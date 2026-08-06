//! Persistent, queryable store for supervised-service output (KTD2).
//!
//! One SQLite database (`logs.db` in the data dir, 0600) with a single
//! `logs` table whose autoincrement id doubles as the tail cursor: every
//! live surface polls `after_id` and gets a bounded chunk plus the new
//! cursor — no streaming transport on top of the one-shot IPC.
//!
//! Lines are truncated at append time (8 KiB + marker) and chunks are
//! additionally byte-budgeted, so a full-size response always fits the
//! 1 MiB IPC frame — an untruncated oversized line would wedge the cursor
//! permanently.
//!
//! Writes flow through a channel into a single drain task that batches
//! whatever is queued into one transaction; all rusqlite calls (blocking)
//! run under `spawn_blocking`, keeping the reactor clean. Reads share the
//! same connection behind a mutex — dev-scale contention, deliberately
//! simple.
//!
//! Retention is per-service line cap plus an age sweep on a timer.
//!
//! Captured child output may itself contain app-printed secrets. The daemon
//! wraps this store's sink in `secret_masker`, so values portman handed a
//! service are replaced with a non-disclosing marker before they are stored.
//! The store and its read routes (the dashboard included) are a weaker trust
//! boundary than the provider a value came from, so an unmasked copy here is
//! a secondary disclosure portman created rather than one the service chose.
//! Masking is exact-value matching and therefore best-effort: it does not
//! catch a value the service transformed before printing.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::Connection;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::supervisor::{LineSink, LogStream};

/// Max stored bytes per line; the tail is replaced by a marker.
const MAX_LINE_BYTES: usize = 8 * 1024;
const TRUNCATION_MARKER: &str = " …[truncated]";

/// Hard cap on `limit` in queries.
pub(crate) const MAX_QUERY_LIMIT: u32 = 500;

/// Byte budget for one chunk's line content — leaves ample headroom inside
/// the 1 MiB IPC frame for JSON framing and metadata.
const CHUNK_BYTE_BUDGET: usize = 700 * 1024;

/// Capacity of the capture channel. Overflow drops lines (counted, warned)
/// rather than blocking the supervisor's pipe readers.
const CHANNEL_CAPACITY: usize = 16 * 1024;

/// How many queued records the drain task folds into one transaction.
const MAX_BATCH: usize = 512;

#[derive(Debug, Clone)]
pub(crate) struct Retention {
    /// Newest lines kept per service.
    pub per_service_lines: u32,
    /// Lines older than this are swept regardless of count.
    pub max_age: Duration,
    /// Sweep cadence.
    pub sweep_interval: Duration,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            per_service_lines: 10_000,
            max_age: Duration::from_secs(7 * 24 * 3600),
            sweep_interval: Duration::from_secs(10 * 60),
        }
    }
}

/// One captured line, as appended.
#[derive(Debug, Clone)]
struct Record {
    service: String,
    stream: LogStream,
    ts_ms: i64,
    line: String,
}

/// One stored line, as queried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogLine {
    pub id: i64,
    pub ts_ms: i64,
    pub stream: String,
    pub line: String,
}

/// A bounded query result. `last_id` is the cursor for the next poll (equal
/// to the previous cursor when nothing new arrived).
#[derive(Debug, Clone, Default)]
pub(crate) struct LogChunk {
    pub lines: Vec<LogLine>,
    pub last_id: i64,
}

#[derive(Clone)]
pub(crate) struct LogStore {
    conn: Arc<Mutex<Connection>>,
    tx: mpsc::Sender<Record>,
    dropped: Arc<AtomicU64>,
    retention: Retention,
}

impl LogStore {
    /// Open (creating if needed) the store at `path`, 0600, and start the
    /// drain task. Must be called within a tokio runtime.
    pub(crate) fn open(path: &Path, retention: Retention) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening log store {}", path.display()))?;
        // WAL keeps readers unblocked by the writer; busy_timeout guards the
        // shared-connection edge.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                ts_ms INTEGER NOT NULL,
                stream TEXT NOT NULL,
                line TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS logs_service_id ON logs(service, id);",
        )?;
        // The db (and its -wal/-shm siblings, which inherit its mode) must
        // not be world-readable: captured output can contain app secrets.
        set_owner_only(path);

        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            retention,
        };
        store.spawn_drain(rx);
        Ok(store)
    }

    /// A cheap capture handle for the supervisor's pipe readers.
    pub(crate) fn sink(&self) -> Arc<dyn LineSink> {
        Arc::new(StoreSink {
            tx: self.tx.clone(),
            dropped: self.dropped.clone(),
        })
    }

    /// Lines for `service` with id greater than `after_id` (0 = from the
    /// start), oldest-first, bounded by `limit` (clamped) and the chunk byte
    /// budget. `last_id` advances to the last returned line, or stays at
    /// `after_id` when nothing matched.
    pub(crate) async fn query_after(
        &self,
        service: &str,
        after_id: i64,
        limit: u32,
    ) -> Result<LogChunk> {
        let conn = self.conn.clone();
        let service = service.to_string();
        let limit = limit.clamp(1, MAX_QUERY_LIMIT);
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().expect("log store lock poisoned");
            let mut stmt = conn.prepare_cached(
                "SELECT id, ts_ms, stream, line FROM logs
                 WHERE service = ?1 AND id > ?2 ORDER BY id ASC LIMIT ?3",
            )?;
            let rows = stmt.query_map(rusqlite::params![service, after_id, limit], row_to_line)?;
            let mut chunk = LogChunk {
                lines: Vec::new(),
                last_id: after_id,
            };
            let mut budget = CHUNK_BYTE_BUDGET;
            for row in rows {
                let line = row?;
                budget = budget.saturating_sub(line.line.len() + line.stream.len() + 48);
                chunk.last_id = line.id;
                chunk.lines.push(line);
                if budget == 0 {
                    break;
                }
            }
            Ok(chunk)
        })
        .await
        .context("log query task")?
    }

    /// The newest `limit` lines for `service`, oldest-first — the initial
    /// view for `portman logs` / the TUI pane; follow-up polls use
    /// [`Self::query_after`] with the returned cursor.
    pub(crate) async fn tail(&self, service: &str, limit: u32) -> Result<LogChunk> {
        let conn = self.conn.clone();
        let service = service.to_string();
        let limit = limit.clamp(1, MAX_QUERY_LIMIT);
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().expect("log store lock poisoned");
            let mut stmt = conn.prepare_cached(
                "SELECT id, ts_ms, stream, line FROM (
                     SELECT id, ts_ms, stream, line FROM logs
                     WHERE service = ?1 ORDER BY id DESC LIMIT ?2
                 ) ORDER BY id ASC",
            )?;
            let rows = stmt.query_map(rusqlite::params![service, limit], row_to_line)?;
            let mut chunk = LogChunk::default();
            let mut budget = CHUNK_BYTE_BUDGET;
            for row in rows {
                let line = row?;
                budget = budget.saturating_sub(line.line.len() + line.stream.len() + 48);
                chunk.last_id = line.id.max(chunk.last_id);
                chunk.lines.push(line);
                if budget == 0 {
                    break;
                }
            }
            Ok(chunk)
        })
        .await
        .context("log tail task")?
    }

    /// Apply retention: keep the newest N lines per service, drop anything
    /// older than `max_age`.
    pub(crate) async fn sweep(&self) -> Result<()> {
        let conn = self.conn.clone();
        let retention = self.retention.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().expect("log store lock poisoned");
            let cutoff_ms = now_ms() - retention.max_age.as_millis() as i64;
            conn.execute("DELETE FROM logs WHERE ts_ms < ?1", [cutoff_ms])?;
            let services: Vec<String> = conn
                .prepare("SELECT DISTINCT service FROM logs")?
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for service in services {
                conn.execute(
                    "DELETE FROM logs WHERE service = ?1 AND id NOT IN (
                         SELECT id FROM logs WHERE service = ?1
                         ORDER BY id DESC LIMIT ?2
                     )",
                    rusqlite::params![service, retention.per_service_lines],
                )?;
            }
            Ok(())
        })
        .await
        .context("log sweep task")?
    }

    /// Run the retention sweep on its timer, forever.
    pub(crate) async fn run_sweeper(self) -> Result<()> {
        loop {
            tokio::time::sleep(self.retention.sweep_interval).await;
            if let Err(err) = self.sweep().await {
                warn!(%err, "log retention sweep failed");
            }
        }
    }

    fn spawn_drain(&self, mut rx: mpsc::Receiver<Record>) {
        let conn = self.conn.clone();
        let dropped = self.dropped.clone();
        tokio::spawn(async move {
            while let Some(first) = rx.recv().await {
                let mut batch = vec![first];
                while batch.len() < MAX_BATCH {
                    match rx.try_recv() {
                        Ok(record) => batch.push(record),
                        Err(_) => break,
                    }
                }
                let conn = conn.clone();
                let result = tokio::task::spawn_blocking(move || append_batch(&conn, &batch)).await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => warn!(%err, "appending service log batch"),
                    Err(err) => warn!(%err, "log append task panicked"),
                }
                let lost = dropped.swap(0, Ordering::Relaxed);
                if lost > 0 {
                    warn!(lost, "service log lines dropped (capture channel full)");
                }
            }
            debug!("log store drain task ended");
        });
    }
}

struct StoreSink {
    tx: mpsc::Sender<Record>,
    dropped: Arc<AtomicU64>,
}

impl LineSink for StoreSink {
    fn line(&self, service: &str, stream: LogStream, line: &str) {
        let record = Record {
            service: service.to_string(),
            stream,
            ts_ms: now_ms(),
            line: truncate_line(line),
        };
        if self.tx.try_send(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn append_batch(conn: &Arc<Mutex<Connection>>, batch: &[Record]) -> Result<()> {
    let mut conn = conn.lock().expect("log store lock poisoned");
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO logs (service, ts_ms, stream, line) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for record in batch {
            stmt.execute(rusqlite::params![
                record.service,
                record.ts_ms,
                record.stream.as_str(),
                record.line
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Truncate to [`MAX_LINE_BYTES`] on a char boundary, appending the marker.
fn truncate_line(line: &str) -> String {
    if line.len() <= MAX_LINE_BYTES {
        return line.to_string();
    }
    let mut cut = MAX_LINE_BYTES;
    while !line.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = line[..cut].to_string();
    out.push_str(TRUNCATION_MARKER);
    out
}

fn row_to_line(row: &rusqlite::Row<'_>) -> rusqlite::Result<LogLine> {
    Ok(LogLine {
        id: row.get(0)?,
        ts_ms: row.get(1)?,
        stream: row.get(2)?,
        line: row.get(3)?,
    })
}

fn now_ms() -> i64 {
    crate::now_unix_ms() as i64
}

fn set_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        warn!(%err, path = %path.display(), "restricting log store permissions");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::tempdir;

    fn append_now(store: &LogStore, service: &str, stream: LogStream, lines: &[&str]) {
        let batch: Vec<Record> = lines
            .iter()
            .map(|l| Record {
                service: service.to_string(),
                stream,
                ts_ms: now_ms(),
                line: truncate_line(l),
            })
            .collect();
        append_batch(&store.conn, &batch).unwrap();
    }

    /// End-to-end: a supervised toy service's stdout lands in the store and
    /// is visible via a direct cursor query (U3 verification).
    /// End-to-end: a value the supervisor handed a service must not reach the
    /// store when the service prints it. Wired exactly as the daemon wires it
    /// (`with_masker` + a wrapped sink), so this covers registration before
    /// spawn, masking through the sink, and what actually lands in SQLite.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_services_own_secret_never_reaches_the_store() {
        use crate::secret_masker::SecretMasker;
        use crate::supervisor::{IdentityPolicy, NoRoutes, NoSecrets, Supervisor, Timings};

        const SECRET: &str = "tok-live-do-not-store-me-42";

        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let env_file = dir.path().join("svc.env");
        std::fs::write(&env_file, format!("SECRET_TOKEN={SECRET}\n")).unwrap();

        let store = LogStore::open(&dir.path().join("logs.db"), Retention::default()).unwrap();
        let masker = SecretMasker::new();
        let sup = Supervisor::with_masker(
            dir.path().join("services.json"),
            crate::env_compose::BaseEnv {
                user: "test".into(),
                home,
            },
            IdentityPolicy::CurrentUser,
            Timings::default(),
            masker.wrap(store.sink()),
            masker,
            std::sync::Arc::new(NoSecrets),
            std::sync::Arc::new(NoRoutes),
        );

        let mut def = toy_def(dir.path());
        def.name = "leaky".into();
        def.run = vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo \"token is $SECRET_TOKEN\"".into(),
        ];
        def.env_files = vec![env_file];
        sup.sync(
            dir.path(),
            vec![def],
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
        sup.up(None).await.unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let line = loop {
            let chunk = store.query_after("leaky", 0, 10).await.unwrap();
            if let Some(hit) = chunk.lines.iter().find(|l| l.line.starts_with("token is ")) {
                break hit.line.clone();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "leaky output never reached the store"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        assert!(!line.contains(SECRET), "secret reached the store: {line}");
        assert!(line.contains("[masked:"), "expected a marker, got: {line}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn supervised_service_output_is_queryable() {
        use crate::supervisor::{IdentityPolicy, NoRoutes, NoSecrets, Supervisor, Timings};

        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let store = LogStore::open(&dir.path().join("logs.db"), Retention::default()).unwrap();
        let sup = Supervisor::new(
            dir.path().join("services.json"),
            crate::env_compose::BaseEnv {
                user: "test".into(),
                home,
            },
            IdentityPolicy::CurrentUser,
            Timings::default(),
            store.sink(),
            std::sync::Arc::new(NoSecrets),
            std::sync::Arc::new(NoRoutes),
        );
        let def = toy_def(dir.path());
        sup.sync(
            dir.path(),
            vec![def],
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
        sup.up(None).await.unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let chunk = store.query_after("toy", 0, 10).await.unwrap();
            if chunk.lines.iter().any(|l| l.line == "toy says hi") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "toy output never reached the store"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// A minimal supervised service definition for the end-to-end tests.
    fn toy_def(dir: &std::path::Path) -> portman_protocol::ServiceDefinition {
        portman_protocol::ServiceDefinition {
            name: "toy".into(),
            run: vec!["/bin/sh".into(), "-c".into(), "echo toy says hi".into()],
            dir: dir.to_path_buf(),
            port: None,
            host: None,
            mode: portman_protocol::Mode::Http,
            ready: portman_protocol::ReadyCheck::None,
            depends: vec![],
            restart: portman_protocol::RestartPolicy::Never,
            stop_grace_ms: 300,
            env_files: vec![],
            env: Default::default(),
            secrets: vec![],
            secrets_optional: false,
            watch: Vec::new(),
            watch_mode: Default::default(),
            watch_debounce_ms: 500,
            groups: Vec::new(),
            project: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cursor_query_returns_only_newer_lines_with_last_id() {
        let dir = tempdir().unwrap();
        let store = LogStore::open(&dir.path().join("logs.db"), Retention::default()).unwrap();

        append_now(&store, "svc", LogStream::Stdout, &["one", "two", "three"]);
        let first = store.query_after("svc", 0, 100).await.unwrap();
        assert_eq!(first.lines.len(), 3);
        assert_eq!(first.last_id, first.lines.last().unwrap().id);

        append_now(&store, "svc", LogStream::Stderr, &["four"]);
        let next = store.query_after("svc", first.last_id, 100).await.unwrap();
        assert_eq!(next.lines.len(), 1);
        assert_eq!(next.lines[0].line, "four");
        assert_eq!(next.lines[0].stream, "stderr");
        assert!(next.last_id > first.last_id);

        // Nothing new → cursor holds still.
        let idle = store.query_after("svc", next.last_id, 100).await.unwrap();
        assert!(idle.lines.is_empty());
        assert_eq!(idle.last_id, next.last_id);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn limit_bounds_the_chunk() {
        let dir = tempdir().unwrap();
        let store = LogStore::open(&dir.path().join("logs.db"), Retention::default()).unwrap();
        let lines: Vec<String> = (0..20).map(|i| format!("line-{i}")).collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        append_now(&store, "svc", LogStream::Stdout, &refs);

        let chunk = store.query_after("svc", 0, 5).await.unwrap();
        assert_eq!(chunk.lines.len(), 5);
        assert_eq!(chunk.lines[0].line, "line-0");

        let next = store.query_after("svc", chunk.last_id, 5).await.unwrap();
        assert_eq!(next.lines[0].line, "line-5");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_line_is_truncated_and_chunks_stay_frameable() {
        let dir = tempdir().unwrap();
        let store = LogStore::open(&dir.path().join("logs.db"), Retention::default()).unwrap();

        let huge = "x".repeat(3 * 1024 * 1024); // 3 MiB single line
        append_now(&store, "svc", LogStream::Stdout, &[huge.as_str()]);
        let chunk = store.query_after("svc", 0, 10).await.unwrap();
        assert_eq!(chunk.lines.len(), 1);
        assert!(chunk.lines[0].line.len() <= MAX_LINE_BYTES + TRUNCATION_MARKER.len());
        assert!(chunk.lines[0].line.ends_with(TRUNCATION_MARKER));

        // A max-limit query over max-size lines still fits the IPC frame.
        let big: Vec<String> = (0..MAX_QUERY_LIMIT).map(|_| "y".repeat(9000)).collect();
        let refs: Vec<&str> = big.iter().map(String::as_str).collect();
        append_now(&store, "bulk", LogStream::Stdout, &refs);
        let chunk = store.query_after("bulk", 0, MAX_QUERY_LIMIT).await.unwrap();
        let serialized: usize = chunk
            .lines
            .iter()
            .map(|l| l.line.len() + l.stream.len() + 64)
            .sum();
        assert!(
            serialized < 1024 * 1024,
            "chunk would overflow the IPC frame: {serialized} bytes"
        );
        assert!(!chunk.lines.is_empty());
        // The cursor lets the next poll pick up where the budget cut off.
        assert!(chunk.last_id < MAX_QUERY_LIMIT as i64 + 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn interleaved_services_do_not_cross_contaminate() {
        let dir = tempdir().unwrap();
        let store = LogStore::open(&dir.path().join("logs.db"), Retention::default()).unwrap();
        append_now(&store, "a", LogStream::Stdout, &["a1"]);
        append_now(&store, "b", LogStream::Stdout, &["b1"]);
        append_now(&store, "a", LogStream::Stdout, &["a2"]);

        let a = store.query_after("a", 0, 100).await.unwrap();
        assert_eq!(
            a.lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>(),
            vec!["a1", "a2"]
        );
        let b = store.query_after("b", 0, 100).await.unwrap();
        assert_eq!(b.lines.len(), 1);
        assert_eq!(b.lines[0].line, "b1");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn retention_cap_drops_oldest_for_one_service_only() {
        let dir = tempdir().unwrap();
        let retention = Retention {
            per_service_lines: 3,
            max_age: Duration::from_secs(3600),
            sweep_interval: Duration::from_secs(3600),
        };
        let store = LogStore::open(&dir.path().join("logs.db"), retention).unwrap();
        let noisy: Vec<String> = (0..10).map(|i| format!("n{i}")).collect();
        let refs: Vec<&str> = noisy.iter().map(String::as_str).collect();
        append_now(&store, "noisy", LogStream::Stdout, &refs);
        append_now(&store, "quiet", LogStream::Stdout, &["q1", "q2"]);

        store.sweep().await.unwrap();

        let noisy = store.query_after("noisy", 0, 100).await.unwrap();
        assert_eq!(
            noisy
                .lines
                .iter()
                .map(|l| l.line.as_str())
                .collect::<Vec<_>>(),
            vec!["n7", "n8", "n9"]
        );
        let quiet = store.query_after("quiet", 0, 100).await.unwrap();
        assert_eq!(quiet.lines.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_store_queries_cleanly() {
        let dir = tempdir().unwrap();
        let store = LogStore::open(&dir.path().join("logs.db"), Retention::default()).unwrap();
        let chunk = store.query_after("ghost", 0, 100).await.unwrap();
        assert!(chunk.lines.is_empty());
        assert_eq!(chunk.last_id, 0);
        let tail = store.tail("ghost", 50).await.unwrap();
        assert!(tail.lines.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tail_returns_newest_lines_oldest_first() {
        let dir = tempdir().unwrap();
        let store = LogStore::open(&dir.path().join("logs.db"), Retention::default()).unwrap();
        let lines: Vec<String> = (0..10).map(|i| format!("l{i}")).collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        append_now(&store, "svc", LogStream::Stdout, &refs);

        let tail = store.tail("svc", 3).await.unwrap();
        assert_eq!(
            tail.lines
                .iter()
                .map(|l| l.line.as_str())
                .collect::<Vec<_>>(),
            vec!["l7", "l8", "l9"]
        );
        // The tail cursor continues seamlessly into query_after.
        append_now(&store, "svc", LogStream::Stdout, &["l10"]);
        let next = store.query_after("svc", tail.last_id, 100).await.unwrap();
        assert_eq!(next.lines.len(), 1);
        assert_eq!(next.lines[0].line, "l10");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sink_capture_lands_in_store() {
        let dir = tempdir().unwrap();
        let store = LogStore::open(&dir.path().join("logs.db"), Retention::default()).unwrap();
        let sink = store.sink();
        sink.line("svc", LogStream::Stdout, "hello from the pipe");

        // The drain task is async; poll briefly.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let chunk = store.query_after("svc", 0, 10).await.unwrap();
            if !chunk.lines.is_empty() {
                assert_eq!(chunk.lines[0].line, "hello from the pipe");
                break;
            }
            assert!(std::time::Instant::now() < deadline, "line never drained");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_append_and_query_do_not_stall() {
        let dir = tempdir().unwrap();
        let store = LogStore::open(&dir.path().join("logs.db"), Retention::default()).unwrap();
        let sink = store.sink();

        let writer = tokio::spawn(async move {
            for i in 0..500 {
                sink.line("busy", LogStream::Stdout, &format!("line {i}"));
                if i % 50 == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        });
        let reader = {
            let store = store.clone();
            tokio::spawn(async move {
                let mut cursor = 0;
                for _ in 0..20 {
                    let chunk = store.query_after("busy", cursor, 100).await.unwrap();
                    cursor = chunk.last_id;
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            writer.await.unwrap();
            reader.await.unwrap();
        })
        .await
        .expect("concurrent append/query stalled");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn store_file_is_owner_only() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("logs.db");
        let _store = LogStore::open(&path, Retention::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
