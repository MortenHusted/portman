//! File watching for services that declare `watch` paths.
//!
//! One task per watched service. It bumps a generation counter on a
//! `tokio::sync::watch` channel every time a declared path changes; the
//! supervisor selects on that channel and respawns the child.
//!
//! A watch hit is an *intentional* respawn, not a crash — the supervisor is
//! what encodes that distinction (no backoff, no restart-policy budget). This
//! module's only job is to decide when something changed.
//!
//! Patterns are globs resolved against the service's `dir`, re-expanded on
//! every batch so a newly created match starts being watched without a
//! restart. Watching the *parent directory* rather than the matched file is
//! deliberate: a rebuild replaces its output by rename, and a watch registered
//! on the old path stops firing the moment the inode changes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{Config, EventKind, PollWatcher, RecommendedWatcher, RecursiveMode};
use notify_debouncer_full::{new_debouncer_opt, DebounceEventResult, Debouncer, RecommendedCache};
use portman_protocol::WatchMode;
use tokio::sync::watch;
use tracing::{debug, warn};

/// How often the poll backend stats its paths. Well under a human's
/// rebuild-then-refresh loop, and cheap for the handful of paths a service
/// declares.
///
/// Note the backend's own resolution limit: notify truncates mtime to whole
/// seconds (`poll.rs`, `system_time_to_seconds`) and only reports a change
/// when the new mtime is strictly greater. Two writes inside one wall-clock
/// second look identical to it, so polling cannot see a rebuild that lands in
/// the same second as the previous one. Real rebuilds are minutes apart, so
/// this is a non-issue in practice — but anything needing sub-second
/// resolution wants `watch_mode = "native"`.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Backends differ in type but not in use, so keep whichever we built alive
/// for the task's lifetime — dropping a debouncer unregisters its watches.
enum Backend {
    Native(Debouncer<RecommendedWatcher, RecommendedCache>),
    Poll(Debouncer<PollWatcher, RecommendedCache>),
}

/// Spawn the watcher for `patterns`. Every debounced change bumps `restart_tx`.
///
/// Returns `None` when there is nothing to watch or the backend can't be
/// built — a service whose watcher failed still runs, it just doesn't respawn
/// on change, which beats refusing to start it.
pub(crate) fn spawn(
    service: String,
    patterns: Vec<PathBuf>,
    mode: WatchMode,
    debounce: Duration,
    restart_tx: watch::Sender<u64>,
) -> Option<tokio::task::JoinHandle<()>> {
    if patterns.is_empty() {
        return None;
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    let handler = move |res: DebounceEventResult| {
        let Ok(events) = res else { return };
        let relevant = events.iter().any(|e| {
            matches!(
                e.kind,
                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
            )
        });
        if relevant {
            // A full channel already means "restart pending" — dropping this
            // one collapses into it rather than queueing a second respawn.
            let _ = tx.try_send(());
        }
    };

    let mut backend = match mode {
        WatchMode::Native => new_debouncer_opt::<_, RecommendedWatcher, RecommendedCache>(
            debounce,
            None,
            handler,
            RecommendedCache::new(),
            Config::default(),
        )
        .map(Backend::Native),
        WatchMode::Poll => new_debouncer_opt::<_, PollWatcher, RecommendedCache>(
            debounce,
            None,
            handler,
            RecommendedCache::new(),
            Config::default().with_poll_interval(POLL_INTERVAL),
        )
        .map(Backend::Poll),
    }
    .map_err(|err| warn!(%service, error = %err, "could not start file watcher"))
    .ok()?;

    let mut watched = BTreeSet::new();
    rewatch(&service, &patterns, &mut backend, &mut watched);

    Some(tokio::spawn(async move {
        // `backend` is moved in and never touched again except to re-register
        // roots; dropping it here would silently stop the watch.
        while rx.recv().await.is_some() {
            rewatch(&service, &patterns, &mut backend, &mut watched);
            debug!(%service, "watched path changed; requesting respawn");
            restart_tx.send_modify(|gen| *gen = gen.wrapping_add(1));
        }
    }))
}

/// Register (and drop) watch roots so the set matches what `patterns`
/// currently resolves to. Idempotent — only the delta is touched.
fn rewatch(
    service: &str,
    patterns: &[PathBuf],
    backend: &mut Backend,
    watched: &mut BTreeSet<PathBuf>,
) {
    let wanted = watch_roots(patterns);
    for root in wanted.difference(watched) {
        if let Err(err) = watch_path(backend, root) {
            debug!(%service, path = %root.display(), error = %err, "could not watch path");
        }
    }
    for root in watched.difference(&wanted) {
        let _ = unwatch_path(backend, root);
    }
    *watched = wanted;
}

/// Directories to hand the backend for a set of patterns.
///
/// A literal directory is watched recursively. Everything else — a literal
/// file, or a glob — resolves to its parent directory, because the interesting
/// events (a build replacing its output, a new file appearing) happen *to* the
/// entry from the directory's point of view. Filtering back down to the
/// pattern isn't worth it: a spurious respawn costs a second, a missed one
/// costs a confusing debugging session.
fn watch_roots(patterns: &[PathBuf]) -> BTreeSet<PathBuf> {
    let mut roots = BTreeSet::new();
    for pattern in patterns {
        if pattern.is_dir() {
            roots.insert(pattern.clone());
            continue;
        }
        let literal_prefix = pattern
            .to_str()
            .map(|s| s.split(['*', '?', '[']).next().unwrap_or(s).to_string())
            .unwrap_or_default();
        let base = Path::new(&literal_prefix);
        let dir = if base.is_dir() {
            base.to_path_buf()
        } else {
            base.parent().unwrap_or(Path::new(".")).to_path_buf()
        };
        if dir.is_dir() {
            roots.insert(dir);
        }
    }
    roots
}

fn watch_path(backend: &mut Backend, path: &Path) -> notify::Result<()> {
    match backend {
        Backend::Native(d) => d.watch(path, RecursiveMode::Recursive),
        Backend::Poll(d) => d.watch(path, RecursiveMode::Recursive),
    }
}

fn unwatch_path(backend: &mut Backend, path: &Path) -> notify::Result<()> {
    match backend {
        Backend::Native(d) => d.unwatch(path),
        Backend::Poll(d) => d.unwatch(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn a_literal_file_is_watched_via_its_parent_directory() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("binary");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(
            watch_roots(&[file]),
            BTreeSet::from([dir.path().to_path_buf()])
        );
    }

    #[test]
    fn a_directory_is_watched_directly() {
        let dir = tempdir().unwrap();
        assert_eq!(
            watch_roots(&[dir.path().to_path_buf()]),
            BTreeSet::from([dir.path().to_path_buf()])
        );
    }

    #[test]
    fn a_glob_resolves_to_its_literal_prefix_directory() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("config");
        std::fs::create_dir(&nested).unwrap();
        assert_eq!(
            watch_roots(&[nested.join("*.toml")]),
            BTreeSet::from([nested])
        );
    }

    #[test]
    fn a_pattern_under_a_missing_directory_is_dropped_not_panicked_on() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("not-built-yet").join("bin");
        assert!(watch_roots(&[missing]).is_empty());
    }
}
