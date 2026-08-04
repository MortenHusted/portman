//! Service supervisor — the daemon owns host service processes.
//!
//! Services declared in a repo's `portman.toml` are spawned directly by the
//! root daemon **as the login user** (KTD1): uid + primary gid (root's
//! supplementary groups are cleared by std's privilege-dropping spawn path;
//! see [`IdentityPolicy::SwitchTo`] for why the user's own list can't be
//! populated on stable Rust), a fresh process group per service so stop can
//! signal the whole tree, the declared cwd, and a hermetically composed
//! environment (see `env_compose`). `sudo -u` is deliberately not used —
//! direct parentage is what gives us exit notifications and pipe-owned log
//! capture.
//!
//! Lifecycle per service: Pending (waiting on `depends`) → Starting →
//! Ready (port/delay gate) → {Backoff → Starting…} on crash, → Stopped on
//! `portman down` / daemon shutdown (TERM to the process group, KILL after
//! the grace period), → Failed when the restart policy is exhausted. The
//! consecutive-failure counter resets after a service has run stably
//! (`Timings::stable_after`), so an occasional crasher restarts forever with
//! fresh backoff while a boot-looper marches to Failed.
//!
//! Desired state persists in `services.json` (atomic rename, 0600). Boot
//! reconciliation is **terminate-and-respawn only**: a process group that
//! survived a daemon crash is identity-checked (pgid + spawn time + argv) and
//! terminated, never adopted — an adopted orphan has no exit notification and
//! its capture pipes died with the old daemon. A marker that fails the
//! identity check is never signaled.
//!
//! mise neutralization (KTD7): supervised children never get the shims dir
//! on PATH — a shim re-execs through mise at exec time, which applies the
//! cwd's mise config (including dotenv env injection) *after* the composer
//! ran. Instead the spawn path asks `mise bin-paths` (as the login user, in
//! the service dir) for the real tool bin dirs and substitutes those.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use portman_protocol::{ReadyCheck, RestartPolicy, SecretsProviderConfig, ServiceDefinition};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::env_compose::{self, BaseEnv};

/// Injectable timings so tests run in milliseconds. Defaults are production
/// values; there is no fake-clock precedent in this repo — tests keep
/// timings real and small.
#[derive(Debug, Clone)]
pub(crate) struct Timings {
    /// First restart delay; doubles per consecutive failure.
    pub backoff_base: Duration,
    /// Backoff ceiling.
    pub backoff_cap: Duration,
    /// How long a readiness check may take before the attempt fails.
    pub ready_timeout: Duration,
    /// Poll cadence for port readiness checks.
    pub ready_poll: Duration,
    /// Uptime after which the consecutive-failure counter resets — a service
    /// that ran stably and then crashed restarts with fresh backoff instead
    /// of marching toward Failed.
    pub stable_after: Duration,
    /// TERM→KILL grace when reclaiming orphaned groups at boot.
    pub reconcile_grace: Duration,
    /// How long a `mise bin-paths` probe may take at spawn.
    pub mise_timeout: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            backoff_base: Duration::from_millis(500),
            backoff_cap: Duration::from_secs(30),
            ready_timeout: Duration::from_secs(60),
            ready_poll: Duration::from_millis(150),
            stable_after: Duration::from_secs(10),
            reconcile_grace: Duration::from_secs(5),
            mise_timeout: Duration::from_secs(10),
        }
    }
}

/// Which pipe a captured line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogStream {
    Stdout,
    Stderr,
}

impl LogStream {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            LogStream::Stdout => "stdout",
            LogStream::Stderr => "stderr",
        }
    }
}

/// Consumer of captured child output. The SQLite log store implements this;
/// the default sink forwards to tracing.
pub(crate) trait LineSink: Send + Sync + 'static {
    fn line(&self, service: &str, stream: LogStream, line: &str);
}

/// A secrets-resolution failure, classified for the R15 policy: transient
/// errors (unreachable instance, timeout) retry under the service's
/// restart/backoff policy; non-transient errors (auth rejection, unknown
/// path) land the service in Failed directly.
#[derive(Debug, Clone)]
pub(crate) struct SecretsError {
    pub transient: bool,
    pub message: String,
}

impl SecretsError {
    pub(crate) fn transient(message: impl Into<String>) -> Self {
        Self {
            transient: true,
            message: message.into(),
        }
    }
    pub(crate) fn fatal(message: impl Into<String>) -> Self {
        Self {
            transient: false,
            message: message.into(),
        }
    }
}

/// Resolves a service's declared secrets into env pairs, inserted between
/// env_files and inline env (R3).
#[async_trait::async_trait]
pub(crate) trait SecretsSource: Send + Sync + 'static {
    async fn resolve(
        &self,
        def: &ServiceDefinition,
        blocks: &BTreeMap<String, SecretsProviderConfig>,
    ) -> Result<Vec<(String, String)>, SecretsError>;

    /// Drop any per-run value caches. Called at the sync point (`portman
    /// up`) so config edits fetch fresh values, while backoff restarts and
    /// `portman start` keep reusing the cache.
    fn invalidate(&self) {}
}

/// Test seam — production wires the provider-backed source.
#[allow(dead_code)]
pub(crate) struct NoSecrets;

#[async_trait::async_trait]
impl SecretsSource for NoSecrets {
    async fn resolve(
        &self,
        _def: &ServiceDefinition,
        _blocks: &BTreeMap<String, SecretsProviderConfig>,
    ) -> Result<Vec<(String, String)>, SecretsError> {
        Ok(Vec::new())
    }
}

/// Routes derived from service records (KTD8). `register` fires on
/// `portman up` (not on ready — the 502 page with its Start button is the
/// correct not-yet-up UX), `deregister` on `portman down` / config removal.
/// Injected as a seam so supervisor tests run without registry plumbing.
pub(crate) trait RouteSink: Send + Sync + 'static {
    fn register(&self, def: &ServiceDefinition);
    fn deregister(&self, def: &ServiceDefinition);
}

/// Test seam — production always wires the [`RouteBinder`].
#[allow(dead_code)]
pub(crate) struct NoRoutes;

impl RouteSink for NoRoutes {
    fn register(&self, _def: &ServiceDefinition) {}
    fn deregister(&self, _def: &ServiceDefinition) {}
}

/// The production [`RouteSink`]: gates on managed TLDs exactly like static
/// rules, upserts `Source::Service` entries the DNS / proxy / TCP-forwarder
/// consume unchanged, and provisions certs for TLS-enabled TLDs.
pub(crate) struct RouteBinder {
    pub registry: portman_core::Registry,
    pub static_store: Arc<portman_core::StaticStore>,
    pub known_tlds: Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
    pub tls_store: Arc<portman_core::TlsStore>,
    pub cert_manager: crate::certs::CertManager,
}

impl RouteSink for RouteBinder {
    fn register(&self, def: &ServiceDefinition) {
        let (Some(host), Some(port)) = (&def.host, def.port) else {
            return;
        };
        let managed = {
            let guard = self.known_tlds.read().expect("known_tlds lock poisoned");
            portman_core::tld::host_has_managed_tld(host, guard.iter())
        };
        if !managed {
            warn!(
                service = %def.name,
                %host,
                "service host is under an unmanaged TLD; no route derived — run `portman tld add <tld>` first"
            );
            return;
        }
        self.registry.upsert(portman_protocol::Entry {
            host: host.clone(),
            target: format!("127.0.0.1:{port}"),
            source: portman_protocol::Source::Service,
            mode: def.mode,
            container_id: None,
            project: def.project.clone(),
        });
        if def.mode == portman_protocol::Mode::Http
            && crate::certs::tls_enabled_for_host(&self.tls_store, host)
        {
            if let Err(err) = self.cert_manager.ensure(host) {
                warn!(%host, error = %err, "failed to provision cert for service route");
            }
        }
        info!(service = %def.name, %host, port, "derived service route");
    }

    fn deregister(&self, def: &ServiceDefinition) {
        let Some(host) = &def.host else {
            return;
        };
        let Some(entry) = self.registry.get(host) else {
            return;
        };
        if entry.source != portman_protocol::Source::Service {
            return;
        }
        // Migration window: the same host may legitimately still carry a
        // static rule — re-seed it instead of silently unrouting the
        // fallback (mirrors main's seed_from_static_store).
        match self.static_store.get(host) {
            Some((target, mode, project)) => {
                self.registry.upsert(portman_protocol::Entry {
                    host: host.clone(),
                    target,
                    source: portman_protocol::Source::Static,
                    mode,
                    container_id: None,
                    project,
                });
                info!(service = %def.name, %host, "service route released; static rule re-seeded");
            }
            None => {
                self.registry.remove(host);
                info!(service = %def.name, %host, "service route removed");
            }
        }
    }
}

/// Service lifecycle states (see the module docs for the transitions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StateKind {
    Pending,
    Starting,
    Ready,
    Backoff,
    Failed,
    Stopped,
}

impl StateKind {
    /// Wire representation for status responses.
    pub(crate) fn wire(self) -> portman_protocol::ServiceState {
        match self {
            StateKind::Pending => portman_protocol::ServiceState::Pending,
            StateKind::Starting => portman_protocol::ServiceState::Starting,
            StateKind::Ready => portman_protocol::ServiceState::Ready,
            StateKind::Backoff => portman_protocol::ServiceState::Backoff,
            StateKind::Failed => portman_protocol::ServiceState::Failed,
            StateKind::Stopped => portman_protocol::ServiceState::Stopped,
        }
    }
}

/// A running service's process group, for resource sampling (KTD5).
#[derive(Debug, Clone)]
pub(crate) struct RunningGroup {
    pub name: String,
    pub host: Option<String>,
    pub pid: u32,
    pub pgid: i32,
}

/// One row of `portman status` — a snapshot of a slot.
#[derive(Debug, Clone)]
pub(crate) struct ServiceStatus {
    pub name: String,
    pub root: PathBuf,
    pub state: StateKind,
    /// Human detail: last error, backoff note, etc. Empty when healthy.
    pub detail: String,
    pub pid: Option<u32>,
    /// Total respawns since the runner task started.
    pub restarts: u32,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub desired_up: bool,
    pub groups: Vec<String>,
    pub project: Option<String>,
}

/// What `sync` did, for CLI display.
#[derive(Debug, Default, Clone)]
pub(crate) struct SyncReport {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: Vec<String>,
}

// ---------------------------------------------------------------------------
// Persistence (`services.json`).

#[derive(Debug, Default, Serialize, Deserialize)]
struct Persisted {
    version: u32,
    #[serde(default)]
    services: BTreeMap<String, PersistedService>,
    #[serde(default)]
    secrets: BTreeMap<String, PersistedSecrets>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedService {
    /// Repo root the definition was synced from — the collision namespace.
    root: PathBuf,
    definition: ServiceDefinition,
    desired_up: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    running: Option<RunningMarker>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedSecrets {
    root: PathBuf,
    config: SecretsProviderConfig,
}

/// Enough identity to recognize (and only then signal) a process group that
/// survived an unclean daemon exit.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunningMarker {
    pid: u32,
    pgid: i32,
    spawn_unix_ms: u64,
    /// The exact argv the child was exec'd with (program resolved).
    argv: Vec<String>,
}

// ---------------------------------------------------------------------------
// Supervisor.

/// How spawned children get their identity.
pub(crate) enum IdentityPolicy {
    /// Root daemon: switch to the login user's uid + primary gid. When
    /// dropping privilege from root, std's spawn path clears the
    /// supplementary group list in the child (`setgroups(0)`), so root's
    /// wheel/admin memberships never leak. The user's *own* supplementary
    /// groups are not populated: `CommandExt::groups` is unstable and nix
    /// exposes no `getgrouplist` on macOS, so there is no safe stable API
    /// for it — the child runs with uid + primary gid (`staff` covers the
    /// dev-service file access that matters) + an empty supplementary list.
    SwitchTo(SpawnIdentity),
    /// Dev mode (non-root daemon): children run as ourselves.
    CurrentUser,
    /// Root without SUDO_USER: refuse to spawn rather than run services as
    /// root. The message becomes the per-service failure detail.
    Refuse(String),
}

pub(crate) struct SpawnIdentity {
    pub uid: u32,
    pub gid: u32,
}

struct StatusCell {
    detail: String,
    pid: Option<u32>,
    restarts: u32,
}

struct Slot {
    root: PathBuf,
    def: ServiceDefinition,
    desired_tx: watch::Sender<bool>,
    state_tx: watch::Sender<StateKind>,
    /// Generation counter bumped by the file watcher. Every increment is one
    /// request to respawn — see [`crate::watch`].
    restart_tx: watch::Sender<u64>,
    cell: Arc<Mutex<StatusCell>>,
    task: Option<tokio::task::JoinHandle<()>>,
    watcher: Option<tokio::task::JoinHandle<()>>,
    running: Option<RunningMarker>,
}

impl Slot {
    fn new(root: PathBuf, def: ServiceDefinition, desired_up: bool) -> Self {
        let (desired_tx, _) = watch::channel(desired_up);
        let (state_tx, _) = watch::channel(StateKind::Stopped);
        let (restart_tx, _) = watch::channel(0);
        Self {
            root,
            def,
            desired_tx,
            state_tx,
            restart_tx,
            cell: Arc::new(Mutex::new(StatusCell {
                detail: String::new(),
                pid: None,
                restarts: 0,
            })),
            task: None,
            watcher: None,
            running: None,
        }
    }
}

struct Inner {
    state_path: PathBuf,
    base: BaseEnv,
    identity: IdentityPolicy,
    timings: Timings,
    sink: Arc<dyn LineSink>,
    secrets_source: Arc<dyn SecretsSource>,
    routes: Arc<dyn RouteSink>,
    slots: Mutex<BTreeMap<String, Slot>>,
    secrets: Mutex<BTreeMap<String, PersistedSecrets>>,
    shutdown_tx: watch::Sender<bool>,
    /// Serializes whole `sync()` calls. Classification and mutation happen
    /// under separate `slots` lock holds (stop_and_join awaits in between),
    /// so without this two concurrent syncs from different roots could both
    /// pass the cross-root name-collision check and one would silently
    /// overwrite the other — the exact invariant sync's own bail! asserts.
    sync_gate: tokio::sync::Mutex<()>,
}

#[derive(Clone)]
pub(crate) struct Supervisor {
    inner: Arc<Inner>,
}

impl Supervisor {
    pub(crate) fn new(
        state_path: PathBuf,
        base: BaseEnv,
        identity: IdentityPolicy,
        timings: Timings,
        sink: Arc<dyn LineSink>,
        secrets_source: Arc<dyn SecretsSource>,
        routes: Arc<dyn RouteSink>,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            inner: Arc::new(Inner {
                state_path,
                base,
                identity,
                timings,
                sink,
                secrets_source,
                routes,
                slots: Mutex::new(BTreeMap::new()),
                secrets: Mutex::new(BTreeMap::new()),
                shutdown_tx,
                sync_gate: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// Production construction: state under the data dir, identity from
    /// SUDO_USER, captured output into `sink`, derived routes through
    /// `routes`, secrets through `secrets_source`.
    pub(crate) fn for_daemon(
        sink: Arc<dyn LineSink>,
        routes: Arc<dyn RouteSink>,
        secrets_source: Arc<dyn SecretsSource>,
    ) -> Result<Self> {
        let state_path = portman_core::paths::services_state_path()?;
        let home = portman_core::paths::user_home().context("resolving login user home")?;
        let user = login_user_name();
        let identity = resolve_identity_policy(&user);
        Ok(Self::new(
            state_path,
            BaseEnv { user, home },
            identity,
            Timings::default(),
            sink,
            secrets_source,
            routes,
        ))
    }

    /// Upsert a repo's service definitions (called by `portman up` with a
    /// freshly parsed config). Per KTD6 this is the sync point: changed
    /// definitions restart their running service, definitions missing from
    /// the new set (same root) are stopped and dropped.
    pub(crate) async fn sync(
        &self,
        root: &Path,
        services: Vec<ServiceDefinition>,
        secrets: BTreeMap<String, SecretsProviderConfig>,
    ) -> Result<SyncReport> {
        // One sync at a time - see Inner::sync_gate.
        let _gate = self.inner.sync_gate.lock().await;
        let mut report = SyncReport::default();
        let mut to_stop: Vec<String> = Vec::new(); // stop before replacing/removing
        let mut restart_after: Vec<String> = Vec::new();

        {
            let slots = self.inner.slots.lock().expect("slots lock poisoned");
            for def in &services {
                match slots.get(&def.name) {
                    Some(slot) if slot.root != root => bail!(
                        "service name `{}` is already defined by {} — service names are global",
                        def.name,
                        slot.root.display()
                    ),
                    Some(slot) if slot.def != *def => {
                        report.updated.push(def.name.clone());
                        to_stop.push(def.name.clone());
                        if *slot.desired_tx.borrow() {
                            restart_after.push(def.name.clone());
                        }
                    }
                    Some(_) => report.unchanged.push(def.name.clone()),
                    None => report.added.push(def.name.clone()),
                }
            }
            let new_names: std::collections::BTreeSet<&str> =
                services.iter().map(|d| d.name.as_str()).collect();
            for (name, slot) in slots.iter() {
                if slot.root == root && !new_names.contains(name.as_str()) {
                    report.removed.push(name.clone());
                    to_stop.push(name.clone());
                }
            }
        }

        for name in &to_stop {
            self.stop_and_join(name).await;
        }

        {
            let mut slots = self.inner.slots.lock().expect("slots lock poisoned");
            for name in &report.removed {
                if let Some(slot) = slots.remove(name) {
                    self.inner.routes.deregister(&slot.def);
                }
            }
            for def in services {
                match slots.get_mut(&def.name) {
                    Some(slot) => {
                        // A replaced definition may have moved or dropped its
                        // host; release the old route (restart re-registers).
                        if slot.def.host != def.host {
                            self.inner.routes.deregister(&slot.def);
                        }
                        slot.def = def;
                    }
                    None => {
                        let name = def.name.clone();
                        slots.insert(name, Slot::new(root.to_path_buf(), def, false));
                    }
                }
            }
        }
        {
            let mut blocks = self.inner.secrets.lock().expect("secrets lock poisoned");
            blocks.retain(|_, b| b.root != root);
            for (name, config) in secrets {
                blocks.insert(
                    name,
                    PersistedSecrets {
                        root: root.to_path_buf(),
                        config,
                    },
                );
            }
        }
        self.persist();
        self.inner.secrets_source.invalidate();

        for name in restart_after {
            self.up(Some(&[name])).await?;
        }
        Ok(report)
    }

    /// Mark services desired-up and ensure their runner tasks exist. `None`
    /// means every known service. Named services pull their transitive
    /// dependencies up with them. Returns the (sorted) set acted on.
    pub(crate) async fn up(&self, names: Option<&[String]>) -> Result<Vec<String>> {
        let targets = self.expand_targets(names, true)?;
        for name in &targets {
            // One lock hold for the whole decide-spawn-record sequence.
            // `expand_targets` validated the name under an *earlier* hold, and
            // the IPC server runs handlers concurrently — a `SyncServices`
            // can remove the slot in between (so no `expect` here: a vanished
            // slot is a skip, not a daemon panic), and splitting the
            // "is a runner needed?" check from the task insert let two
            // concurrent `up()` calls both observe "needed" and spawn two
            // supervisors fighting over one port. `tokio::spawn` doesn't
            // await, so it is safe inside the critical section.
            {
                let mut slots = self.inner.slots.lock().expect("slots lock poisoned");
                let Some(slot) = slots.get_mut(name) else {
                    warn!(service = %name, "service removed while starting; skipping");
                    continue;
                };
                slot.desired_tx.send_replace(true);
                // `Option::is_none_or` is past the workspace MSRV (1.78).
                let spawn_needed = slot.task.as_ref().map_or(true, |t| t.is_finished());
                if spawn_needed {
                    slot.cell.lock().expect("cell lock poisoned").restarts = 0;
                    slot.task = Some(tokio::spawn(run_service(self.inner.clone(), name.clone())));
                    // Watching is tied to the runner task, not to `desired_up`:
                    // an idle watcher on a stopped service would fire into a
                    // channel nobody reads.
                    if slot.watcher.as_ref().map_or(true, |w| w.is_finished()) {
                        slot.watcher = crate::watch::spawn(
                            name.clone(),
                            slot.def.watch.clone(),
                            slot.def.watch_mode,
                            Duration::from_millis(slot.def.watch_debounce_ms),
                            slot.restart_tx.clone(),
                        );
                    }
                }
            }
            let def = {
                let slots = self.inner.slots.lock().expect("slots lock poisoned");
                slots.get(name).map(|slot| slot.def.clone())
            };
            if let Some(def) = def {
                self.inner.routes.register(&def);
            }
        }
        self.persist();
        Ok(targets)
    }

    /// Mark services desired-down and stop them, waiting for a clean exit.
    /// `None` means every known service. Dependencies are left alone.
    pub(crate) async fn down(&self, names: Option<&[String]>) -> Result<Vec<String>> {
        let targets = self.expand_targets(names, false)?;
        for name in &targets {
            self.stop_and_join(name).await;
            let def = {
                let slots = self.inner.slots.lock().expect("slots lock poisoned");
                slots.get(name).map(|slot| slot.def.clone())
            };
            if let Some(def) = def {
                self.inner.routes.deregister(&def);
            }
        }
        self.persist();
        Ok(targets)
    }

    /// Stop every running service without touching desired state, so boot
    /// restore brings them back (R7: clean daemon shutdown/restart).
    pub(crate) async fn shutdown_all(&self) {
        self.inner.shutdown_tx.send_replace(true);
        let tasks: Vec<(String, tokio::task::JoinHandle<()>)> = {
            let mut slots = self.inner.slots.lock().expect("slots lock poisoned");
            slots
                .iter_mut()
                .filter_map(|(name, slot)| slot.task.take().map(|t| (name.clone(), t)))
                .collect()
        };
        for (name, task) in tasks {
            if tokio::time::timeout(Duration::from_secs(30), task)
                .await
                .is_err()
            {
                warn!(service = %name, "service did not stop within 30s at daemon shutdown");
            }
        }
        self.persist();
    }

    /// The service whose definition claims `host`, if any — the native
    /// (first-priority) Starter resolution path.
    pub(crate) fn service_for_host(&self, host: &str) -> Option<String> {
        let slots = self.inner.slots.lock().expect("slots lock poisoned");
        slots
            .iter()
            .find(|(_, slot)| slot.def.host.as_deref() == Some(host))
            .map(|(name, _)| name.clone())
    }

    /// Live process groups for resource sampling.
    pub(crate) fn running_groups(&self) -> Vec<RunningGroup> {
        let slots = self.inner.slots.lock().expect("slots lock poisoned");
        slots
            .iter()
            .filter_map(|(name, slot)| {
                slot.running.as_ref().map(|marker| RunningGroup {
                    name: name.clone(),
                    host: slot.def.host.clone(),
                    pid: marker.pid,
                    pgid: marker.pgid,
                })
            })
            .collect()
    }

    /// Is `name` a known (synced) service?
    pub(crate) fn knows(&self, name: &str) -> bool {
        self.inner
            .slots
            .lock()
            .expect("slots lock poisoned")
            .contains_key(name)
    }

    /// Snapshot of all known services.
    /// Distinct config roots the supervisor currently owns services for.
    /// This is the allowlist for anything that reads or writes config files
    /// on the daemon's behalf — never an arbitrary path from a request.
    pub(crate) fn known_roots(&self) -> Vec<PathBuf> {
        let slots = self.inner.slots.lock().expect("slots lock poisoned");
        let mut roots: Vec<PathBuf> = slots.values().map(|slot| slot.root.clone()).collect();
        roots.sort();
        roots.dedup();
        roots
    }

    pub(crate) fn status(&self) -> Vec<ServiceStatus> {
        let slots = self.inner.slots.lock().expect("slots lock poisoned");
        slots
            .iter()
            .map(|(name, slot)| {
                let cell = slot.cell.lock().expect("cell lock poisoned");
                ServiceStatus {
                    name: name.clone(),
                    root: slot.root.clone(),
                    state: *slot.state_tx.borrow(),
                    detail: cell.detail.clone(),
                    pid: cell.pid,
                    restarts: cell.restarts,
                    host: slot.def.host.clone(),
                    port: slot.def.port,
                    desired_up: *slot.desired_tx.borrow(),
                    groups: slot.def.groups.clone(),
                    project: slot.def.project.clone(),
                }
            })
            .collect()
    }

    /// Load persisted state, reconcile surviving process groups
    /// (terminate-and-respawn, never adopt), then start desired services.
    pub(crate) async fn restore(&self) -> Result<()> {
        let persisted = load_persisted(&self.inner.state_path)?;
        let mut markers: Vec<(String, RunningMarker)> = Vec::new();
        {
            let mut slots = self.inner.slots.lock().expect("slots lock poisoned");
            for (name, ps) in persisted.services {
                if let Some(marker) = &ps.running {
                    markers.push((name.clone(), marker.clone()));
                }
                slots.insert(name, Slot::new(ps.root, ps.definition, ps.desired_up));
            }
        }
        {
            let mut blocks = self.inner.secrets.lock().expect("secrets lock poisoned");
            blocks.extend(persisted.secrets);
        }

        for (name, marker) in &markers {
            self.reconcile_marker(name, marker).await;
        }
        self.persist();

        let desired: Vec<String> = {
            let slots = self.inner.slots.lock().expect("slots lock poisoned");
            slots
                .iter()
                .filter(|(_, s)| *s.desired_tx.borrow())
                .map(|(n, _)| n.clone())
                .collect()
        };
        if !desired.is_empty() {
            info!(services = ?desired, "restoring desired-up services");
            self.up(Some(&desired)).await?;
        }
        Ok(())
    }

    /// Terminate a process group that survived an unclean daemon exit — but
    /// only when the recorded identity still matches what's live. A recycled
    /// pid/pgid is never signaled.
    async fn reconcile_marker(&self, name: &str, marker: &RunningMarker) {
        if !marker_identity_matches(marker) {
            debug!(
                service = name,
                pid = marker.pid,
                "recorded process gone or identity mismatch; clearing marker"
            );
            return;
        }
        info!(
            service = name,
            pid = marker.pid,
            pgid = marker.pgid,
            "terminating service process group surviving a previous daemon run"
        );
        signal_group(marker.pgid, Signal::SIGTERM);
        let deadline = Instant::now() + self.inner.timings.reconcile_grace;
        while Instant::now() < deadline {
            if nix::sys::signal::kill(Pid::from_raw(marker.pid as i32), None).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        signal_group(marker.pgid, Signal::SIGKILL);
    }

    /// Resolve `names` (or all) to existing services; with `expand_deps`,
    /// close the set over transitive `depends`.
    fn expand_targets(&self, names: Option<&[String]>, expand_deps: bool) -> Result<Vec<String>> {
        let slots = self.inner.slots.lock().expect("slots lock poisoned");
        let mut targets: Vec<String> = match names {
            None => slots.keys().cloned().collect(),
            Some(names) => {
                for name in names {
                    if !slots.contains_key(name) {
                        bail!("unknown service `{name}` — run `portman up` from the repo to sync its config");
                    }
                }
                names.to_vec()
            }
        };
        if expand_deps {
            let mut seen: std::collections::BTreeSet<String> = targets.iter().cloned().collect();
            let mut queue = targets.clone();
            while let Some(name) = queue.pop() {
                if let Some(slot) = slots.get(&name) {
                    for dep in &slot.def.depends {
                        if seen.insert(dep.clone()) {
                            targets.push(dep.clone());
                            queue.push(dep.clone());
                        }
                    }
                }
            }
        }
        targets.sort();
        targets.dedup();
        Ok(targets)
    }

    /// Set desired-down and wait for the runner task (which performs the
    /// graceful TERM→KILL stop) to finish.
    async fn stop_and_join(&self, name: &str) {
        let task = {
            let mut slots = self.inner.slots.lock().expect("slots lock poisoned");
            let Some(slot) = slots.get_mut(name) else {
                return;
            };
            slot.desired_tx.send_replace(false);
            if let Some(watcher) = slot.watcher.take() {
                watcher.abort();
            }
            slot.task.take()
        };
        match task {
            Some(task) => {
                if tokio::time::timeout(Duration::from_secs(60), task)
                    .await
                    .is_err()
                {
                    warn!(service = name, "service did not stop within 60s");
                }
            }
            None => {
                // Nothing supervising it — reflect the desired state directly.
                set_state(&self.inner, name, StateKind::Stopped, String::new());
            }
        }
    }

    fn persist(&self) {
        persist(&self.inner);
    }

    /// Test hook: drop all runner tasks *without* stopping children —
    /// simulates an unclean daemon exit for reconciliation tests.
    #[cfg(test)]
    fn abandon_for_test(&self) {
        let mut slots = self.inner.slots.lock().expect("slots lock poisoned");
        for slot in slots.values_mut() {
            if let Some(task) = slot.task.take() {
                task.abort();
            }
        }
    }
}

fn login_user_name() -> String {
    match std::env::var("SUDO_USER") {
        Ok(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()),
    }
}

fn resolve_identity_policy(user: &str) -> IdentityPolicy {
    if !nix::unistd::geteuid().is_root() {
        return IdentityPolicy::CurrentUser;
    }
    if std::env::var("SUDO_USER")
        .map(|u| u.trim().is_empty())
        .unwrap_or(true)
    {
        return IdentityPolicy::Refuse(
            "daemon runs as root but SUDO_USER is unset; refusing to run services as root — \
             re-run `portman install`"
                .to_string(),
        );
    }
    match spawn_identity_for(user) {
        Ok(identity) => IdentityPolicy::SwitchTo(identity),
        Err(err) => IdentityPolicy::Refuse(format!("resolving login user {user}: {err:#}")),
    }
}

fn spawn_identity_for(user: &str) -> Result<SpawnIdentity> {
    let record = nix::unistd::User::from_name(user)
        .with_context(|| format!("looking up user {user}"))?
        .with_context(|| format!("login user {user} not found"))?;
    Ok(SpawnIdentity {
        uid: record.uid.as_raw(),
        gid: record.gid.as_raw(),
    })
}

// ---------------------------------------------------------------------------
// The per-service runner task.

enum Gate {
    Proceed,
    Stop,
}

enum Attempt {
    /// Stop was requested (desired-down or daemon shutdown); child is stopped.
    Stopped,
    /// A watched path changed; the child is stopped and should respawn now.
    /// Deliberately distinct from `Failure`: this is an intentional respawn,
    /// so it spends no restart budget and waits out no backoff.
    Restart,
    /// The attempt ended (spawn error, readiness timeout, or process exit).
    Failure { detail: String, ran: Duration },
    /// A non-retryable failure (e.g. secrets auth rejection): Failed
    /// immediately, regardless of the restart policy (R15).
    Fatal { detail: String },
}

async fn run_service(inner: Arc<Inner>, name: String) {
    let (mut desired_rx, mut shutdown_rx, mut restart_rx, watched) = {
        let slots = inner.slots.lock().expect("slots lock poisoned");
        let Some(slot) = slots.get(&name) else {
            return;
        };
        (
            slot.desired_tx.subscribe(),
            inner.shutdown_tx.subscribe(),
            slot.restart_tx.subscribe(),
            !slot.def.watch.is_empty(),
        )
    };
    let mut consecutive_failures: u32 = 0;

    loop {
        if !*desired_rx.borrow() || *shutdown_rx.borrow() {
            set_state(&inner, &name, StateKind::Stopped, String::new());
            break;
        }

        set_state(&inner, &name, StateKind::Pending, String::new());
        match wait_for_deps(&inner, &name, &mut desired_rx, &mut shutdown_rx).await {
            Gate::Proceed => {}
            Gate::Stop => {
                set_state(&inner, &name, StateKind::Stopped, String::new());
                break;
            }
        }

        set_state(&inner, &name, StateKind::Starting, String::new());
        let attempt = supervise_once(
            &inner,
            &name,
            &mut desired_rx,
            &mut shutdown_rx,
            &mut restart_rx,
        )
        .await;
        clear_running_marker(&inner, &name);
        persist(&inner);

        match attempt {
            Attempt::Stopped => {
                set_state(&inner, &name, StateKind::Stopped, String::new());
                break;
            }
            Attempt::Restart => {
                // Intentional respawn: the failure counter describes crash
                // health, and a file edit says nothing about that.
                consecutive_failures = 0;
                info!(service = %name, "watched path changed; respawning");
            }
            Attempt::Fatal { detail } => {
                warn!(service = %name, %detail, "service failed (non-retryable)");
                set_state(&inner, &name, StateKind::Failed, detail);
                break;
            }
            Attempt::Failure { detail, ran } => {
                if ran >= inner.timings.stable_after {
                    consecutive_failures = 1;
                } else {
                    consecutive_failures += 1;
                }
                let (policy, cell) = {
                    let slots = inner.slots.lock().expect("slots lock poisoned");
                    let Some(slot) = slots.get(&name) else { break };
                    (slot.def.restart, slot.cell.clone())
                };
                let give_up = match policy {
                    RestartPolicy::Never => true,
                    RestartPolicy::Limit(n) => consecutive_failures > n,
                    RestartPolicy::Always => false,
                };
                if give_up {
                    warn!(service = %name, %detail, "service failed; restart policy exhausted");
                    set_state(&inner, &name, StateKind::Failed, detail);
                    if !watched {
                        break;
                    }
                    // Watched services park in Failed instead of ending the
                    // task: rebuilding the binary that was crash-looping is
                    // new information, and should bring the service back
                    // without a manual `portman up`.
                    consecutive_failures = 0;
                    tokio::select! {
                        r = restart_rx.changed() => {
                            if r.is_err() {
                                break;
                            }
                            info!(service = %name, "watched path changed; reviving failed service");
                        }
                        _ = stop_requested(&mut desired_rx, &mut shutdown_rx) => {
                            set_state(&inner, &name, StateKind::Stopped, String::new());
                            break;
                        }
                    }
                    continue;
                }
                cell.lock().expect("cell lock poisoned").restarts += 1;
                let delay = backoff_delay(&inner.timings, consecutive_failures);
                info!(service = %name, %detail, delay_ms = delay.as_millis() as u64, "service attempt failed; backing off");
                set_state(
                    &inner,
                    &name,
                    StateKind::Backoff,
                    format!("{detail}; restarting in {}ms", delay.as_millis()),
                );
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    // A rebuild during backoff takes effect now rather than
                    // serving out a delay earned by the code it replaced.
                    r = restart_rx.changed() => {
                        if r.is_ok() {
                            consecutive_failures = 0;
                            info!(service = %name, "watched path changed; skipping backoff");
                        }
                    }
                    _ = stop_requested(&mut desired_rx, &mut shutdown_rx) => {
                        set_state(&inner, &name, StateKind::Stopped, String::new());
                        break;
                    }
                }
            }
        }
    }
}

fn backoff_delay(t: &Timings, consecutive_failures: u32) -> Duration {
    let exp = consecutive_failures.saturating_sub(1).min(16);
    let delay = t.backoff_base.saturating_mul(2u32.saturating_pow(exp));
    delay.min(t.backoff_cap)
}

/// Wait until every dependency reports Ready. Returns Stop if a stop arrives
/// first (or a dependency slot vanished under us — sync will re-drive).
async fn wait_for_deps(
    inner: &Arc<Inner>,
    name: &str,
    desired_rx: &mut watch::Receiver<bool>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Gate {
    let deps: Vec<(String, watch::Receiver<StateKind>)> = {
        let slots = inner.slots.lock().expect("slots lock poisoned");
        let Some(slot) = slots.get(name) else {
            return Gate::Stop;
        };
        slot.def
            .depends
            .iter()
            .filter_map(|dep| {
                slots
                    .get(dep)
                    .map(|s| (dep.clone(), s.state_tx.subscribe()))
            })
            .collect()
    };
    for (dep, mut rx) in deps {
        loop {
            if *rx.borrow_and_update() == StateKind::Ready {
                break;
            }
            debug!(service = name, waiting_on = %dep, "waiting for dependency");
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() {
                        warn!(service = name, dep = %dep, "dependency removed while waiting");
                        return Gate::Stop;
                    }
                }
                _ = stop_requested(desired_rx, shutdown_rx) => return Gate::Stop,
            }
        }
    }
    Gate::Proceed
}

/// Completes when a stop is requested: desired flips down or the daemon
/// begins shutdown.
async fn stop_requested(
    desired_rx: &mut watch::Receiver<bool>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    loop {
        if !*desired_rx.borrow_and_update() || *shutdown_rx.borrow_and_update() {
            return;
        }
        tokio::select! {
            r = desired_rx.changed() => { if r.is_err() { return; } }
            r = shutdown_rx.changed() => { if r.is_err() { return; } }
        }
    }
}

/// One spawn attempt: compose env, spawn, gate readiness, then supervise
/// until exit or stop.
async fn supervise_once(
    inner: &Arc<Inner>,
    name: &str,
    desired_rx: &mut watch::Receiver<bool>,
    shutdown_rx: &mut watch::Receiver<bool>,
    restart_rx: &mut watch::Receiver<u64>,
) -> Attempt {
    let def = {
        let slots = inner.slots.lock().expect("slots lock poisoned");
        let Some(slot) = slots.get(name) else {
            return Attempt::Stopped;
        };
        slot.def.clone()
    };
    let fail = |detail: String| Attempt::Failure {
        detail,
        ran: Duration::ZERO,
    };

    if let IdentityPolicy::Refuse(reason) = &inner.identity {
        return fail(reason.clone());
    }

    // Secrets → env pairs, per the R15 failure policy.
    let blocks: BTreeMap<String, SecretsProviderConfig> = {
        let secrets = inner.secrets.lock().expect("secrets lock poisoned");
        secrets
            .iter()
            .map(|(k, v)| (k.clone(), v.config.clone()))
            .collect()
    };
    let (provider_values, ready_note) = match inner.secrets_source.resolve(&def, &blocks).await {
        Ok(values) => (values, String::new()),
        Err(err) if def.secrets_optional => {
            // The declared offline fallback: start from env_files only,
            // visibly flagged — never a silently empty env.
            warn!(service = name, error = %err.message, "secrets unavailable; starting env_files-only (secrets_optional)");
            (
                Vec::new(),
                format!(
                    "secrets unavailable ({}); running from env_files only",
                    err.message
                ),
            )
        }
        Err(err) if err.transient => return fail(format!("secrets: {}", err.message)),
        Err(err) => {
            return Attempt::Fatal {
                detail: format!("secrets: {}", err.message),
            }
        }
    };

    // PATH: well-known install dirs plus mise's real tool bin dirs — never
    // the shims dir (KTD7).
    let mise_paths = mise_bin_paths(inner, &def).await;
    let path_value = service_path(&inner.base.home, &mise_paths);
    let env = match env_compose::compose(
        &inner.base,
        &path_value,
        &def.env_files,
        &provider_values,
        &def.env,
    ) {
        Ok(env) => env,
        Err(err) => return fail(format!("{err:#}")),
    };

    let effective_path = env.get("PATH").map(String::as_str).unwrap_or(&path_value);
    let program = match resolve_program(&def.dir, &def.run[0], effective_path) {
        Ok(program) => program,
        Err(err) => return fail(format!("{err:#}")),
    };
    let mut argv: Vec<String> = vec![program.display().to_string()];
    argv.extend(def.run.iter().skip(1).cloned());

    let mut cmd = tokio::process::Command::new(&program);
    cmd.args(&def.run[1..])
        .env_clear()
        .envs(&env)
        .current_dir(&def.dir)
        // Piped, never written to, and deliberately never `take()`n — the
        // write end stays owned by `child` for the process's whole life, so
        // the child sees an open stdin that never reaches EOF. `Stdio::null()`
        // reads EOF immediately, and watchers that treat that as "my terminal
        // went away" exit on the spot: tailwindcss v4's `--watch` quits with
        // status 0 the instant stdin closes, which the supervisor then sees as
        // a crash and restart-loops forever. Foreman/overmind hand children a
        // live stdin; portman replaces them, so it does too.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(false);
    if let IdentityPolicy::SwitchTo(identity) = &inner.identity {
        // std clears the supplementary group list in the child when
        // dropping privilege from root — see IdentityPolicy::SwitchTo.
        cmd.uid(identity.uid).gid(identity.gid);
    }

    let spawned_at = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => return fail(format!("spawning {}: {err}", program.display())),
    };
    // No pid means the child was reaped before we could look — treat it as
    // a failed attempt rather than persisting a `pid 0` marker, which boot
    // reconciliation could misread (`getpgid(0)` is the calling process).
    let Some(pid) = child.id() else {
        return Attempt::Failure {
            detail: "child exited before its pid could be read".to_string(),
            ran: spawned_at.elapsed(),
        };
    };
    let pgid = pid as i32; // process_group(0) → the child leads its own group
    info!(service = name, pid, "service spawned");

    {
        let mut slots = inner.slots.lock().expect("slots lock poisoned");
        if let Some(slot) = slots.get_mut(name) {
            slot.running = Some(RunningMarker {
                pid,
                pgid,
                spawn_unix_ms: crate::now_unix_ms(),
                argv,
            });
            slot.cell.lock().expect("cell lock poisoned").pid = Some(pid);
        }
    }
    persist(inner);

    // `Child::wait()` drops the child's stdin before waiting (tokio does this
    // to avoid deadlocking on a full pipe), so the write end has to live
    // outside the `Child` to stay open. Bound and never used: it drops when
    // this attempt returns, which is after the process has already exited or
    // been stopped.
    let _stdin_keepalive = child.stdin.take();

    let mut readers: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        readers.push(spawn_line_reader(
            inner.sink.clone(),
            name.to_string(),
            LogStream::Stdout,
            stdout,
        ));
    }
    if let Some(stderr) = child.stderr.take() {
        readers.push(spawn_line_reader(
            inner.sink.clone(),
            name.to_string(),
            LogStream::Stderr,
            stderr,
        ));
    }

    // Every exit path below funnels through the reader drain at the bottom —
    // a grandchild that escapes the group KILL while holding stdout would
    // otherwise keep a reader alive indefinitely, appending to the log store
    // under an attempt that ended long ago.
    let attempt = 'attempt: {
        // Readiness gate.
        match wait_ready(&def, &inner.timings, &mut child, desired_rx, shutdown_rx).await {
            ReadyOutcome::Ready => {}
            ReadyOutcome::Stop => {
                stop_child_group(&mut child, pgid, def.stop_grace_ms).await;
                break 'attempt Attempt::Stopped;
            }
            ReadyOutcome::Exited(detail) => {
                signal_group(pgid, Signal::SIGKILL);
                break 'attempt Attempt::Failure {
                    detail,
                    ran: spawned_at.elapsed(),
                };
            }
            ReadyOutcome::Timeout => {
                stop_child_group(&mut child, pgid, def.stop_grace_ms).await;
                break 'attempt Attempt::Failure {
                    detail: format!(
                        "readiness check did not pass within {}ms",
                        inner.timings.ready_timeout.as_millis()
                    ),
                    ran: spawned_at.elapsed(),
                };
            }
        }
        set_state(inner, name, StateKind::Ready, ready_note);

        // Steady state: wait for exit, a stop request, or a watched-path change.
        tokio::select! {
            status = child.wait() => {
                // Sweep group members that outlived the leader so a respawn
                // can't double-bind the port.
                signal_group(pgid, Signal::SIGKILL);
                Attempt::Failure {
                    detail: format!("process {}", describe_exit(status)),
                    ran: spawned_at.elapsed(),
                }
            }
            _ = stop_requested(desired_rx, shutdown_rx) => {
                stop_child_group(&mut child, pgid, def.stop_grace_ms).await;
                Attempt::Stopped
            }
            // Same graceful TERM→KILL as a stop: the child gets its shutdown
            // grace, it just gets spawned again straight after.
            _ = restart_rx.changed() => {
                stop_child_group(&mut child, pgid, def.stop_grace_ms).await;
                Attempt::Restart
            }
        }
    };

    // Give the readers a beat to drain buffered output (they finish
    // instantly on a normal pipe EOF), then cut them off.
    for mut reader in readers {
        if tokio::time::timeout(Duration::from_millis(250), &mut reader)
            .await
            .is_err()
        {
            reader.abort();
        }
    }
    attempt
}

enum ReadyOutcome {
    Ready,
    Exited(String),
    Timeout,
    Stop,
}

async fn wait_ready(
    def: &ServiceDefinition,
    timings: &Timings,
    child: &mut tokio::process::Child,
    desired_rx: &mut watch::Receiver<bool>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> ReadyOutcome {
    match def.ready {
        ReadyCheck::None => ReadyOutcome::Ready,
        ReadyCheck::DelayMs(ms) => {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(ms)) => ReadyOutcome::Ready,
                status = child.wait() => ReadyOutcome::Exited(
                    format!("process {} before its readiness delay", describe_exit(status))
                ),
                _ = stop_requested(desired_rx, shutdown_rx) => ReadyOutcome::Stop,
            }
        }
        ReadyCheck::Port(port) => {
            let deadline = Instant::now() + timings.ready_timeout;
            loop {
                tokio::select! {
                    status = child.wait() => return ReadyOutcome::Exited(
                        format!("process {} before becoming ready", describe_exit(status))
                    ),
                    _ = stop_requested(desired_rx, shutdown_rx) => return ReadyOutcome::Stop,
                    _ = tokio::time::sleep(timings.ready_poll) => {}
                }
                let connect = tokio::net::TcpStream::connect(("127.0.0.1", port));
                if let Ok(Ok(_)) = tokio::time::timeout(timings.ready_poll, connect).await {
                    return ReadyOutcome::Ready;
                }
                if Instant::now() >= deadline {
                    return ReadyOutcome::Timeout;
                }
            }
        }
    }
}

fn describe_exit(status: std::io::Result<std::process::ExitStatus>) -> String {
    match status {
        Ok(status) => format!("exited ({status})"),
        Err(err) => format!("wait failed ({err})"),
    }
}

/// Graceful stop: TERM the whole group, KILL it after the grace period, and
/// always sweep with KILL once the leader is reaped so no group member
/// outlives the stop.
async fn stop_child_group(child: &mut tokio::process::Child, pgid: i32, grace_ms: u64) {
    signal_group(pgid, Signal::SIGTERM);
    if tokio::time::timeout(Duration::from_millis(grace_ms), child.wait())
        .await
        .is_err()
    {
        signal_group(pgid, Signal::SIGKILL);
        let _ = child.wait().await;
    }
    signal_group(pgid, Signal::SIGKILL);
}

/// Signal a process group, refusing pgids that could hit the daemon itself
/// (pgid ≤ 1 or our own group) — corrupt persisted state must never let the
/// daemon shoot its own foot.
fn signal_group(pgid: i32, sig: Signal) {
    if pgid <= 1 {
        return;
    }
    if nix::unistd::getpgrp().as_raw() == pgid {
        warn!(pgid, "refusing to signal the daemon's own process group");
        return;
    }
    let _ = nix::sys::signal::killpg(Pid::from_raw(pgid), sig);
}

fn spawn_line_reader(
    sink: Arc<dyn LineSink>,
    service: String,
    stream: LogStream,
    reader: impl tokio::io::AsyncRead + Unpin + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            sink.line(&service, stream, &line);
        }
    })
}

// ---------------------------------------------------------------------------
// PATH + program resolution (mise-shim neutralization).

/// The fixed PATH supervised children get. Deliberately excludes the mise
/// shims dir: a shim re-execs through mise, which applies the cwd's config
/// (dotenv included) at exec time — after the hermetic composer ran. Real
/// tool dirs from `mise bin-paths` take the shims' place.
fn service_path(home: &Path, mise_paths: &[String]) -> String {
    let h = home.display();
    let mut parts: Vec<String> = mise_paths
        .iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    parts.push(format!("{h}/.local/bin"));
    parts.push(format!("{h}/.cargo/bin"));
    parts.push("/opt/homebrew/bin".to_string());
    parts.push("/usr/local/bin".to_string());
    parts.push("/usr/bin".to_string());
    parts.push("/bin".to_string());
    parts.join(":")
}

/// Ask mise (as the login user, in the service dir, so repo-pinned tool
/// versions apply) for its real tool bin dirs. Any failure degrades to "no
/// mise tools on PATH" with a warning — services running direct binary
/// paths are unaffected.
async fn mise_bin_paths(inner: &Arc<Inner>, def: &ServiceDefinition) -> Vec<String> {
    let shims = inner.base.home.join(".local/share/mise/shims");
    if !shims.is_dir() {
        return Vec::new();
    }
    let candidates = [
        inner.base.home.join(".local/bin/mise"),
        PathBuf::from("/opt/homebrew/bin/mise"),
        PathBuf::from("/usr/local/bin/mise"),
        inner.base.home.join(".cargo/bin/mise"),
    ];
    let Some(mise) = candidates.iter().find(|p| p.is_file()) else {
        debug!("mise shims dir exists but no mise binary found; skipping bin-paths");
        return Vec::new();
    };

    let mut cmd = tokio::process::Command::new(mise);
    cmd.arg("bin-paths")
        .current_dir(&def.dir)
        .env_clear()
        .env("HOME", &inner.base.home)
        .env("USER", &inner.base.user)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let IdentityPolicy::SwitchTo(identity) = &inner.identity {
        cmd.uid(identity.uid).gid(identity.gid);
    }

    match tokio::time::timeout(inner.timings.mise_timeout, cmd.output()).await {
        Ok(Ok(output)) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with('/'))
            .map(str::to_string)
            .collect(),
        Ok(Ok(output)) => {
            let tail = String::from_utf8_lossy(&output.stderr);
            warn!(
                service = %def.name,
                status = ?output.status.code(),
                stderr = %tail.lines().last().unwrap_or(""),
                "mise bin-paths failed; supervised PATH will not include mise tools"
            );
            Vec::new()
        }
        Ok(Err(err)) => {
            warn!(service = %def.name, %err, "running mise bin-paths");
            Vec::new()
        }
        Err(_) => {
            warn!(service = %def.name, "mise bin-paths timed out");
            Vec::new()
        }
    }
}

/// Resolve the run command to a concrete executable. Paths with a `/`
/// resolve against the service dir; bare names search the composed PATH.
/// Because that PATH never contains the shims dir, resolution can't land on
/// a mise shim.
fn resolve_program(dir: &Path, argv0: &str, path_value: &str) -> Result<PathBuf> {
    if argv0.contains('/') {
        let p = if Path::new(argv0).is_absolute() {
            PathBuf::from(argv0)
        } else {
            dir.join(argv0)
        };
        if p.is_file() {
            return Ok(p);
        }
        bail!("run command `{argv0}` not found at {}", p.display());
    }
    for entry in path_value.split(':') {
        if entry.is_empty() {
            continue;
        }
        let candidate = Path::new(entry).join(argv0);
        if candidate.is_file() && is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    bail!("run command `{argv0}` not found in service PATH")
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Shared slot/state helpers.

fn set_state(inner: &Arc<Inner>, name: &str, kind: StateKind, detail: String) {
    let slots = inner.slots.lock().expect("slots lock poisoned");
    if let Some(slot) = slots.get(name) {
        slot.state_tx.send_replace(kind);
        slot.cell.lock().expect("cell lock poisoned").detail = detail;
        debug!(
            service = name,
            state = kind.wire().as_str(),
            "service state"
        );
    }
}

fn clear_running_marker(inner: &Arc<Inner>, name: &str) {
    let mut slots = inner.slots.lock().expect("slots lock poisoned");
    if let Some(slot) = slots.get_mut(name) {
        slot.running = None;
        // The attempt is over in every branch that reaches here, so the pid
        // is stale — leaving it set made `status` and the dashboard show a
        // pid for a Stopped service.
        slot.cell.lock().expect("cell lock poisoned").pid = None;
    }
}

/// Does the recorded marker still describe a live process? pgid, spawn time
/// (±5 s), and argv must all match before we'll signal anything. The argv
/// comparison tolerates a rewritten argv[0]: macOS trampolines (e.g.
/// `/usr/bin/python3`) exec the real binary, so the live process reports a
/// different program path than the one we spawned — the argument tail plus
/// pid/pgid/start-time still pin the identity. Any *argument* mismatch is a
/// veto: a recycled pgid is never signaled.
fn marker_identity_matches(marker: &RunningMarker) -> bool {
    // Every inconclusive leg logs at warn: a false negative here means a
    // survivor keeps its port while the respawn crash-loops on EADDRINUSE,
    // and a debug-level reason is invisible exactly when it matters (CI).
    let pid = Pid::from_raw(marker.pid as i32);
    let Ok(live_pgid) = nix::unistd::getpgid(Some(pid)) else {
        // Process gone — nothing to kill, marker just clears.
        return false;
    };
    if live_pgid.as_raw() != marker.pgid {
        warn!(
            pid = marker.pid,
            marker_pgid = marker.pgid,
            live_pgid = live_pgid.as_raw(),
            "survivor identity mismatch: pgid changed; not signaling"
        );
        return false;
    }

    let sys_pid = sysinfo::Pid::from_u32(marker.pid);
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sys_pid]), true);
    let Some(process) = system.process(sys_pid) else {
        warn!(
            pid = marker.pid,
            "survivor identity inconclusive: process table has no entry; not signaling"
        );
        return false;
    };
    let started_ms = process.start_time().saturating_mul(1000);
    if started_ms.abs_diff(marker.spawn_unix_ms) > 5_000 {
        warn!(
            pid = marker.pid,
            started_ms,
            marker_ms = marker.spawn_unix_ms,
            "survivor identity mismatch: start time drifted; not signaling"
        );
        return false;
    }
    let argv: Vec<String> = process
        .cmd()
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    if argv.is_empty() {
        // Argv is the third, weakest signal — pgid and start-time already
        // matched, and start-time alone defeats pid recycling (a recycled
        // pid can't reproduce the recorded spawn instant). sysinfo has been
        // observed returning empty argv for live processes that `ps` reads
        // fine (Apple's /usr/bin tool stubs re-exec, and KERN_PROCARGS2
        // handling varies), so an unreadable argv must not veto two solid
        // matches and strand the survivor holding its port.
        warn!(
            pid = marker.pid,
            "survivor argv unreadable; accepting identity on pgid + start time"
        );
        return true;
    }
    let matches =
        argv == marker.argv || (argv.len() == marker.argv.len() && argv[1..] == marker.argv[1..]);
    if !matches {
        warn!(
            pid = marker.pid,
            live_argv = ?argv,
            marker_argv = ?marker.argv,
            "survivor identity mismatch: argv differs; not signaling"
        );
    }
    matches
}

// ---------------------------------------------------------------------------
// Persistence.

fn load_persisted(path: &Path) -> Result<Persisted> {
    match std::fs::read(path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Persisted::default()),
        Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
    }
}

fn persist(inner: &Arc<Inner>) {
    let persisted = {
        let slots = inner.slots.lock().expect("slots lock poisoned");
        let secrets = inner.secrets.lock().expect("secrets lock poisoned");
        Persisted {
            version: 1,
            services: slots
                .iter()
                .map(|(name, slot)| {
                    (
                        name.clone(),
                        PersistedService {
                            root: slot.root.clone(),
                            definition: slot.def.clone(),
                            desired_up: *slot.desired_tx.borrow(),
                            running: slot.running.clone(),
                        },
                    )
                })
                .collect(),
            secrets: secrets.clone(),
        }
    };
    if let Err(err) = crate::block_on_reactor(|| write_persisted(&inner.state_path, &persisted)) {
        warn!(%err, "persisting services state");
    }
}

/// Atomic-rename write, 0600 (the inline env of a personal config may carry
/// sensitive values; same trust posture as the credentials store).
fn write_persisted(path: &Path, persisted: &Persisted) -> Result<()> {
    // Through the shared atomic writer: persist() fires on every state
    // change, and this fn's old fixed `services.json.tmp` name meant two
    // concurrent persists clobbered each other's tempfile — one renamed it
    // away, the other's rename ENOENTed (or worse, won with a stale
    // snapshot). The exact bug class 2.2 fixed in the core stores; this
    // copy was missed. 0600: the state embeds service environments.
    portman_core::atomic_json::atomic_write_json_with_mode(path, persisted, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap as Map;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::{tempdir, TempDir};

    struct CollectSink(Mutex<Vec<(String, LogStream, String)>>);

    impl CollectSink {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Vec::new())))
        }
        fn lines(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .map(|(_, _, l)| l.clone())
                .collect()
        }
        fn count_containing(&self, needle: &str) -> usize {
            self.lines().iter().filter(|l| l.contains(needle)).count()
        }
    }

    impl LineSink for CollectSink {
        fn line(&self, service: &str, stream: LogStream, line: &str) {
            self.0
                .lock()
                .unwrap()
                .push((service.to_string(), stream, line.to_string()));
        }
    }

    fn fast_timings() -> Timings {
        Timings {
            backoff_base: Duration::from_millis(40),
            backoff_cap: Duration::from_millis(500),
            ready_timeout: Duration::from_millis(600),
            ready_poll: Duration::from_millis(25),
            stable_after: Duration::from_secs(10),
            reconcile_grace: Duration::from_millis(500),
            mise_timeout: Duration::from_secs(60),
        }
    }

    /// Supervisor with a fake home (so the machine's real mise install never
    /// engages) and current-user identity.
    fn test_supervisor(dir: &TempDir, sink: Arc<dyn LineSink>) -> Supervisor {
        // Route tracing into the test harness's captured output — the
        // supervisor's warn-level diagnostics (survivor identity, persist
        // failures) are exactly what a CI-only failure needs to show.
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        Supervisor::new(
            dir.path().join("services.json"),
            BaseEnv {
                user: std::env::var("USER").unwrap_or_else(|_| "test".into()),
                home,
            },
            IdentityPolicy::CurrentUser,
            fast_timings(),
            sink,
            Arc::new(NoSecrets),
            Arc::new(NoRoutes),
        )
    }

    fn def(name: &str, run: &[&str], dir: &Path) -> ServiceDefinition {
        ServiceDefinition {
            name: name.to_string(),
            run: run.iter().map(|s| s.to_string()).collect(),
            dir: dir.to_path_buf(),
            port: None,
            host: None,
            mode: portman_protocol::Mode::Http,
            ready: ReadyCheck::None,
            depends: Vec::new(),
            restart: RestartPolicy::Never,
            stop_grace_ms: 300,
            env_files: Vec::new(),
            env: Map::new(),
            secrets: Vec::new(),
            secrets_optional: false,
            watch: Vec::new(),
            watch_mode: Default::default(),
            watch_debounce_ms: 500,
            groups: Vec::new(),
            project: None,
        }
    }

    async fn wait_for_state(sup: &Supervisor, name: &str, want: StateKind, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let status = sup.status();
            let row = status.iter().find(|s| s.name == name);
            if let Some(row) = row {
                if row.state == want {
                    return;
                }
            }
            if Instant::now() > deadline {
                panic!(
                    "service {name} never reached {want:?}; status: {:?}",
                    sup.status()
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The pipe readers drain asynchronously — poll until a matching line
    /// lands in the sink (panics after 10s).
    async fn wait_for_line(sink: &CollectSink, pred: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !sink.lines().iter().any(|l| pred(l)) {
            if Instant::now() > deadline {
                panic!("expected line never captured; lines: {:?}", sink.lines());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A port no other test in this binary will hand out.
    ///
    /// Bind-then-release alone is a race: tests run in parallel, and between
    /// releasing here and the service binding it, another test's kernel-chosen
    /// ephemeral port can land on the same number — the service then exits 1
    /// ("address in use") and a reconciliation/readiness test flakes. Marching
    /// a process-wide counter through a range the kernel doesn't allocate from
    /// makes same-binary collisions impossible; the bind check still guards
    /// against ports held by other processes.
    fn free_port() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static NEXT: AtomicU16 = AtomicU16::new(24_000);
        loop {
            let candidate = NEXT.fetch_add(1, Ordering::Relaxed);
            assert!(candidate < 32_000, "test port range exhausted");
            if std::net::TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
                return candidate;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_respects_cwd_own_pgid_and_hermetic_env() {
        std::env::set_var("PORTMAN_SUP_POISON", "leaked");
        let dir = tempdir().unwrap();
        let workdir = dir.path().join("work");
        std::fs::create_dir_all(&workdir).unwrap();
        let sink = CollectSink::new();
        let sup = test_supervisor(&dir, sink.clone());

        let svc = def(
            "probe",
            &[
                "/bin/sh",
                "-c",
                "pwd; /usr/bin/env; echo PID=$$; ps -o pgid= -p $$",
            ],
            &workdir,
        );
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["probe".to_string()])).await.unwrap();
        wait_for_state(&sup, "probe", StateKind::Failed, Duration::from_secs(20)).await;
        wait_for_line(&sink, |l| l.trim().parse::<u32>().is_ok()).await;

        let lines = sink.lines();
        let joined = lines.join("\n");
        // cwd respected (canonicalized — /tmp is a symlink on macOS).
        let canonical = workdir.canonicalize().unwrap();
        assert!(
            joined.contains(&canonical.display().to_string()),
            "pwd not found in output: {joined}"
        );
        // Hermetic env: the poisoned daemon var never reaches the child.
        assert!(!joined.contains("PORTMAN_SUP_POISON"), "{joined}");
        // Own process group: the pgid the child reports is its own pid. Both
        // come from the child itself — the supervisor clears its recorded pid
        // once an attempt ends, and this probe exits immediately.
        let pid: u32 = lines
            .iter()
            .find_map(|l| l.trim().strip_prefix("PID=")?.parse().ok())
            .expect("child pid line");
        let pgid_line = lines
            .iter()
            .rev()
            .find_map(|l| l.trim().parse::<u32>().ok())
            .expect("pgid line");
        assert_eq!(pgid_line, pid, "child should lead its own process group");
        assert_ne!(
            pgid_line,
            nix::unistd::getpgrp().as_raw() as u32,
            "child must not share the daemon's process group"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shim_route_is_neutralized_and_never_falls_back() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let shims = home.join(".local/share/mise/shims");
        let bin = home.join(".local/bin");
        let real_tools = home.join("real-tools");
        for d in [&shims, &bin, &real_tools] {
            std::fs::create_dir_all(d).unwrap();
        }
        // The shim injects a canary before exec'ing env — if the supervisor
        // ever resolves through it, the canary shows up in the child env.
        write_script(
            &shims.join("mytool"),
            "#!/bin/sh\nMISE_CANARY=boom exec /usr/bin/env\n",
        );
        // The real tool (what `mise bin-paths` should route us to) is clean.
        write_script(&real_tools.join("mytool"), "#!/bin/sh\nexec /usr/bin/env\n");
        // Fake mise: answers bin-paths with the real tool dir.
        write_script(
            &bin.join("mise"),
            &format!(
                "#!/bin/sh\n[ \"$1\" = bin-paths ] && echo {}\n",
                real_tools.display()
            ),
        );

        // A mise dotenv fixture in the service dir (what real mise would
        // apply at shim exec time).
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("mise.toml"), "[env]\nMISE_CANARY = \"boom\"\n").unwrap();

        let sink = CollectSink::new();
        let sup = Supervisor::new(
            dir.path().join("services.json"),
            BaseEnv {
                user: "test".into(),
                home: home.clone(),
            },
            IdentityPolicy::CurrentUser,
            fast_timings(),
            sink.clone(),
            Arc::new(NoSecrets),
            Arc::new(NoRoutes),
        );

        let svc = def("shimmy", &["mytool"], &repo);
        sup.sync(&repo, vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["shimmy".to_string()])).await.unwrap();
        wait_for_state(&sup, "shimmy", StateKind::Failed, Duration::from_secs(20)).await;
        wait_for_line(&sink, |l| l.starts_with("PATH=")).await;

        let joined = sink.lines().join("\n");
        assert!(
            !joined.contains("MISE_CANARY"),
            "canary leaked into child env: {joined}"
        );
        let path_line = sink
            .lines()
            .into_iter()
            .find(|l| l.starts_with("PATH="))
            .expect("PATH in child env");
        assert!(path_line.contains("real-tools"), "{path_line}");
        assert!(
            !path_line.contains("shims"),
            "shims dir must never be on a supervised child's PATH: {path_line}"
        );

        // Without mise, the shim is NOT a fallback: resolution fails loudly.
        std::fs::remove_file(bin.join("mise")).unwrap();
        let svc2 = def("shimmy2", &["mytool"], &repo);
        sup.sync(
            &repo,
            vec![def("shimmy", &["mytool"], &repo), svc2],
            Map::new(),
        )
        .await
        .unwrap();
        sup.up(Some(&["shimmy2".to_string()])).await.unwrap();
        wait_for_state(&sup, "shimmy2", StateKind::Failed, Duration::from_secs(20)).await;
        let detail = sup
            .status()
            .into_iter()
            .find(|s| s.name == "shimmy2")
            .unwrap()
            .detail;
        assert!(
            detail.contains("not found in service PATH"),
            "expected loud resolution failure, got: {detail}"
        );
    }

    fn write_script(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Pre-warm: macOS syspolicyd assesses a freshly written unsigned
        // executable on first exec and can stall it for tens of seconds
        // (observed 25s). Absorb that here, outside timed supervisor paths.
        let _ = std::process::Command::new(path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn readiness_port_gates_until_listener_binds() {
        let dir = tempdir().unwrap();
        let sup = test_supervisor(&dir, CollectSink::new());
        let port = free_port();

        let mut svc = def("porty", &["/bin/sleep", "10"], dir.path());
        svc.ready = ReadyCheck::Port(port);
        svc.restart = RestartPolicy::Never;
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["porty".to_string()])).await.unwrap();

        // Not ready while nothing listens.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(sup.status()[0].state, StateKind::Starting);

        // Bind the port → the gate opens.
        let _listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        wait_for_state(&sup, "porty", StateKind::Ready, Duration::from_secs(20)).await;

        sup.down(None).await.unwrap();
    }

    /// Watch tests run against real filesystem notifications, so they need a
    /// debounce long enough to be stable and short enough to keep the suite
    /// quick. Poll interval is 250ms, so give the backend room to see it.
    const TEST_DEBOUNCE_MS: u64 = 150;

    fn watched(mut def: ServiceDefinition, paths: &[&Path]) -> ServiceDefinition {
        def.watch = paths.iter().map(|p| p.to_path_buf()).collect();
        def.watch_debounce_ms = TEST_DEBOUNCE_MS;
        def
    }

    /// Rewrite a file so the poll backend sees a change.
    ///
    /// It truncates mtime to whole seconds and fires only on a strictly
    /// greater value (see `watch::POLL_INTERVAL`), so a rewrite in the same
    /// wall-clock second as the previous one is invisible. Real rebuilds are
    /// minutes apart; tests have to wait for the boundary explicitly or they
    /// flake on roughly half of runs.
    async fn touch_next_second(path: &Path, content: &str) {
        let before = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        loop {
            std::fs::write(path, content).unwrap();
            let now = std::fs::metadata(path).and_then(|m| m.modified()).ok();
            match (before, now) {
                (Some(b), Some(n)) if whole_secs(n) <= whole_secs(b) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                _ => return,
            }
        }
    }

    fn whole_secs(t: std::time::SystemTime) -> u64 {
        t.duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    async fn pid_of(sup: &Supervisor, name: &str) -> Option<u32> {
        sup.status().into_iter().find(|s| s.name == name)?.pid
    }

    /// The pid of a running service, polled rather than read once.
    ///
    /// Reaching `Ready` doesn't guarantee the process is still alive by the
    /// next statement — it can crash in between, and the supervisor clears the
    /// recorded pid the moment an attempt ends. A single `.pid.unwrap()` is a
    /// race; under a loaded parallel test run it loses often enough to matter.
    async fn running_pid(sup: &Supervisor, name: &str) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(pid) = pid_of(sup, name).await {
                return pid;
            }
            assert!(
                Instant::now() < deadline,
                "service {name} never reported a running pid; status: {:?}",
                sup.status()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn watch_change_respawns_a_running_service() {
        let dir = tempdir().unwrap();
        let trigger = dir.path().join("rebuilt.bin");
        std::fs::write(&trigger, "v1").unwrap();

        let sup = test_supervisor(&dir, CollectSink::new());
        let mut svc = watched(
            def("watchy", &["/bin/sleep", "30"], dir.path()),
            &[&trigger],
        );
        svc.ready = ReadyCheck::DelayMs(50);
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["watchy".to_string()])).await.unwrap();
        wait_for_state(&sup, "watchy", StateKind::Ready, Duration::from_secs(20)).await;
        let first = running_pid(&sup, "watchy").await;

        touch_next_second(&trigger, "v2").await;

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let now = pid_of(&sup, "watchy").await;
            if matches!(now, Some(p) if p != first) {
                break;
            }
            assert!(Instant::now() < deadline, "service never respawned");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        wait_for_state(&sup, "watchy", StateKind::Ready, Duration::from_secs(20)).await;
        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn watch_change_does_not_consume_restart_budget() {
        // `retry = false` means one crash is terminal. A watch respawn must
        // not be counted as that crash.
        let dir = tempdir().unwrap();
        let trigger = dir.path().join("rebuilt.bin");
        std::fs::write(&trigger, "v1").unwrap();

        let sup = test_supervisor(&dir, CollectSink::new());
        let mut svc = watched(
            def("budget", &["/bin/sleep", "30"], dir.path()),
            &[&trigger],
        );
        svc.ready = ReadyCheck::DelayMs(50);
        svc.restart = RestartPolicy::Never;
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["budget".to_string()])).await.unwrap();
        wait_for_state(&sup, "budget", StateKind::Ready, Duration::from_secs(20)).await;

        for (i, content) in ["v2", "v3"].iter().enumerate() {
            let before = running_pid(&sup, "budget").await;
            touch_next_second(&trigger, content).await;
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if matches!(pid_of(&sup, "budget").await, Some(p) if p != before) {
                    break;
                }
                assert!(Instant::now() < deadline, "respawn {i} never happened");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            wait_for_state(&sup, "budget", StateKind::Ready, Duration::from_secs(20)).await;
        }

        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn watch_change_revives_a_failed_service() {
        let dir = tempdir().unwrap();
        let built = dir.path().join("built");
        // The script stands in for a binary that only works once its build
        // output exists. Keeping the *script* fixed and watching a separate
        // artifact avoids rewriting an executable mid-test, which would make
        // macOS re-assess it and stall the respawn we're timing.
        let script = dir.path().join("needs-build.sh");
        write_script(
            &script,
            &format!(
                "#!/bin/sh\n[ -f {} ] && exec sleep 30\nexit 1\n",
                built.display()
            ),
        );

        let sup = test_supervisor(&dir, CollectSink::new());
        let mut svc = watched(
            def("revive", &[script.to_str().unwrap()], dir.path()),
            &[&built],
        );
        svc.restart = RestartPolicy::Never;
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["revive".to_string()])).await.unwrap();
        wait_for_state(&sup, "revive", StateKind::Failed, Duration::from_secs(20)).await;

        // The build lands — the service should come back on its own, with no
        // `portman up` and despite `retry = false` having been spent.
        std::fs::write(&built, "artifact").unwrap();
        wait_for_state(&sup, "revive", StateKind::Ready, Duration::from_secs(20)).await;

        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn watch_change_is_ignored_while_stopped() {
        // An explicit `portman down` is sticky: editing a watched file must
        // not resurrect the service.
        let dir = tempdir().unwrap();
        let trigger = dir.path().join("rebuilt.bin");
        std::fs::write(&trigger, "v1").unwrap();

        let sup = test_supervisor(&dir, CollectSink::new());
        let mut svc = watched(
            def("sticky", &["/bin/sleep", "30"], dir.path()),
            &[&trigger],
        );
        svc.ready = ReadyCheck::DelayMs(50);
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["sticky".to_string()])).await.unwrap();
        wait_for_state(&sup, "sticky", StateKind::Ready, Duration::from_secs(20)).await;
        sup.down(None).await.unwrap();
        wait_for_state(&sup, "sticky", StateKind::Stopped, Duration::from_secs(20)).await;

        touch_next_second(&trigger, "v2").await;
        tokio::time::sleep(Duration::from_millis(TEST_DEBOUNCE_MS * 6)).await;

        let row = sup
            .status()
            .into_iter()
            .find(|s| s.name == "sticky")
            .unwrap();
        assert_eq!(row.state, StateKind::Stopped);
        assert_eq!(row.pid, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn watch_picks_up_a_file_created_after_startup() {
        // The watch root is the directory, so a path that doesn't exist yet
        // (a build output before the first build) still triggers a respawn.
        let dir = tempdir().unwrap();
        let build_dir = dir.path().join("dist");
        std::fs::create_dir(&build_dir).unwrap();
        let not_yet_built = build_dir.join("binary");

        let sup = test_supervisor(&dir, CollectSink::new());
        let mut svc = watched(
            def("late", &["/bin/sleep", "30"], dir.path()),
            &[&not_yet_built],
        );
        svc.ready = ReadyCheck::DelayMs(50);
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["late".to_string()])).await.unwrap();
        wait_for_state(&sup, "late", StateKind::Ready, Duration::from_secs(20)).await;
        let first = running_pid(&sup, "late").await;

        std::fs::write(&not_yet_built, "freshly built").unwrap();

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if matches!(pid_of(&sup, "late").await, Some(p) if p != first) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "creation never triggered respawn"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_syncs_cannot_both_claim_one_service_name() {
        // Names are global across roots; sync classifies and mutates under
        // separate lock holds, so without the sync gate two racing syncs
        // could both pass the collision check and one silently won.
        let dir = tempdir().unwrap();
        let sup = test_supervisor(&dir, CollectSink::new());
        let root_a = dir.path().join("a");
        let root_b = dir.path().join("b");
        std::fs::create_dir_all(&root_a).unwrap();
        std::fs::create_dir_all(&root_b).unwrap();

        for i in 0..20 {
            let ta = {
                let sup = sup.clone();
                let root = root_a.clone();
                tokio::spawn(async move {
                    let svc = def("shared-name", &["/bin/sleep", "1"], &root);
                    sup.sync(&root, vec![svc], Map::new()).await
                })
            };
            let tb = {
                let sup = sup.clone();
                let root = root_b.clone();
                tokio::spawn(async move {
                    let svc = def("shared-name", &["/bin/sleep", "1"], &root);
                    sup.sync(&root, vec![svc], Map::new()).await
                })
            };
            let (ra, rb) = (ta.await.unwrap(), tb.await.unwrap());
            let rejected = [&ra, &rb].iter().filter(|r| r.is_err()).count();
            assert_eq!(
                rejected, 1,
                "iteration {i}: exactly one sync must lose the name race, got {ra:?} / {rb:?}"
            );
            // Clean the slate: the winner forgets its claim for the next round.
            let winner_root = if ra.is_ok() { &root_a } else { &root_b };
            sup.sync(winner_root, vec![], Map::new()).await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn up_racing_a_sync_that_removes_the_service_does_not_panic() {
        // `expand_targets` validates under one lock hold; the per-name work
        // happens under later ones. A concurrent SyncServices that removes
        // the name in between used to fire an `expect` — in the root daemon.
        let dir = tempdir().unwrap();
        let sup = test_supervisor(&dir, CollectSink::new());
        for i in 0..25 {
            let svc = def("racer", &["/bin/sleep", "5"], dir.path());
            sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
            let a = {
                let sup = sup.clone();
                tokio::spawn(async move { sup.up(Some(&["racer".to_string()])).await })
            };
            let b = {
                let sup = sup.clone();
                let root = dir.path().to_path_buf();
                tokio::spawn(async move { sup.sync(&root, vec![], Map::new()).await })
            };
            // Either interleaving is a legal outcome; a panicked task is not.
            assert!(a.await.is_ok(), "up panicked on iteration {i}");
            assert!(b.await.is_ok(), "sync panicked on iteration {i}");
        }
        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_up_spawns_exactly_one_child() {
        // The spawn decision and the task insert used to live in separate
        // lock holds; concurrent up() calls (CLI + dashboard + the 502-page
        // Start path) could each observe "runner needed" and both spawn —
        // two children fighting over one port.
        let dir = tempdir().unwrap();
        let counter = dir.path().join("spawns");
        let script = dir.path().join("count-and-sleep.sh");
        // Gated on an env var only the supervised spawn sets, so the
        // syspolicyd pre-warm inside write_script doesn't count as a child.
        write_script(
            &script,
            &format!(
                "#!/bin/sh\n[ -n \"$PORTMAN_TEST_RUN\" ] || exit 0\necho x >> {}\nsleep 30\n",
                counter.display()
            ),
        );

        let sup = test_supervisor(&dir, CollectSink::new());
        let mut svc = def("solo", &[script.to_str().unwrap()], dir.path());
        svc.env.insert("PORTMAN_TEST_RUN".into(), "1".into());
        svc.ready = ReadyCheck::DelayMs(50);
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();

        let ups: Vec<_> = (0..8)
            .map(|_| {
                let sup = sup.clone();
                tokio::spawn(async move { sup.up(Some(&["solo".to_string()])).await })
            })
            .collect();
        for u in ups {
            u.await.unwrap().unwrap();
        }
        wait_for_state(&sup, "solo", StateKind::Ready, Duration::from_secs(20)).await;
        // Ready fires on the delay gate, not on the script's first line —
        // syspolicyd can stall a fresh script's exec well past it. Wait for
        // the first append, then give any illegitimate second runner time.
        let deadline = Instant::now() + Duration::from_secs(15);
        while std::fs::read_to_string(&counter)
            .unwrap_or_default()
            .is_empty()
        {
            assert!(Instant::now() < deadline, "child never wrote the counter");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        let spawns = std::fs::read_to_string(&counter).unwrap_or_default();
        assert_eq!(
            spawns.lines().count(),
            1,
            "exactly one child must have spawned"
        );
        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn child_stdin_stays_open_instead_of_reaching_eof() {
        // `cat` returns the moment stdin hits EOF, so this script exits
        // immediately under `Stdio::null()` and blocks forever on a live
        // stdin. Stands in for watchers that quit when their input closes —
        // tailwindcss v4's `--watch` is the one that surfaced this.
        let dir = tempdir().unwrap();
        let script = dir.path().join("waits-on-stdin.sh");
        write_script(&script, "#!/bin/sh\ncat > /dev/null\n");

        let sup = test_supervisor(&dir, CollectSink::new());
        let mut svc = def("stdin-holder", &[script.to_str().unwrap()], dir.path());
        svc.ready = ReadyCheck::DelayMs(100);
        svc.restart = RestartPolicy::Never;
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["stdin-holder".to_string()])).await.unwrap();

        wait_for_state(
            &sup,
            "stdin-holder",
            StateKind::Ready,
            Duration::from_secs(20),
        )
        .await;
        // Still alive well past the point an EOF'd stdin would have killed it.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(sup.status()[0].state, StateKind::Ready);

        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn readiness_timeout_fails_the_attempt() {
        let dir = tempdir().unwrap();
        let sup = test_supervisor(&dir, CollectSink::new());
        let port = free_port(); // never bound

        let mut svc = def("never-ready", &["/bin/sleep", "10"], dir.path());
        svc.ready = ReadyCheck::Port(port);
        svc.restart = RestartPolicy::Never;
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["never-ready".to_string()])).await.unwrap();

        wait_for_state(
            &sup,
            "never-ready",
            StateKind::Failed,
            Duration::from_secs(5),
        )
        .await;
        let detail = sup.status()[0].detail.clone();
        assert!(detail.contains("readiness"), "{detail}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn crash_restarts_with_growing_backoff_and_honors_max_retries() {
        let dir = tempdir().unwrap();
        let sink = CollectSink::new();
        let sup = test_supervisor(&dir, sink.clone());

        let mut svc = def("crashy", &["/bin/sh", "-c", "echo attempt"], dir.path());
        svc.restart = RestartPolicy::Limit(2);
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();

        let started = Instant::now();
        sup.up(Some(&["crashy".to_string()])).await.unwrap();
        wait_for_state(&sup, "crashy", StateKind::Failed, Duration::from_secs(20)).await;
        let elapsed = started.elapsed();

        // Limit(2) → initial attempt + 2 restarts = 3 spawns.
        assert_eq!(sink.count_containing("attempt"), 3);
        assert_eq!(sup.status()[0].restarts, 2);
        // Backoff grew: 40ms then 80ms between attempts.
        assert!(
            elapsed >= Duration::from_millis(120),
            "backoff too fast: {elapsed:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stop_terms_then_kills_a_term_ignoring_child() {
        let dir = tempdir().unwrap();
        let sink = CollectSink::new();
        let sup = test_supervisor(&dir, sink.clone());

        let mut svc = def(
            "stubborn",
            &[
                "/bin/sh",
                "-c",
                "trap '' TERM; echo up; while :; do sleep 0.05; done",
            ],
            dir.path(),
        );
        svc.stop_grace_ms = 250;
        svc.restart = RestartPolicy::Always;
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(Some(&["stubborn".to_string()])).await.unwrap();
        wait_for_state(&sup, "stubborn", StateKind::Ready, Duration::from_secs(20)).await;
        let deadline = Instant::now() + Duration::from_secs(2);
        while sink.count_containing("up") == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let pid = sup.status()[0].pid.unwrap();

        let stop_started = Instant::now();
        sup.down(Some(&["stubborn".to_string()])).await.unwrap();
        let stop_elapsed = stop_started.elapsed();

        assert_eq!(sup.status()[0].state, StateKind::Stopped);
        // TERM was ignored, so the stop took at least the grace period.
        assert!(
            stop_elapsed >= Duration::from_millis(250),
            "stop returned before the grace period: {stop_elapsed:?}"
        );
        // And the process is really gone.
        assert!(nix::sys::signal::kill(Pid::from_raw(pid as i32), None).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dependency_gates_start_order() {
        let dir = tempdir().unwrap();
        let sup = test_supervisor(&dir, CollectSink::new());

        let mut dep = def("dep", &["/bin/sleep", "10"], dir.path());
        dep.ready = ReadyCheck::DelayMs(250);
        dep.restart = RestartPolicy::Always;
        let mut top = def("top", &["/bin/sleep", "10"], dir.path());
        top.depends = vec!["dep".to_string()];
        top.restart = RestartPolicy::Always;
        sup.sync(dir.path(), vec![dep, top], Map::new())
            .await
            .unwrap();
        sup.up(None).await.unwrap();

        // While dep serves its readiness delay, top must hold in Pending.
        tokio::time::sleep(Duration::from_millis(120)).await;
        let states: Map<String, StateKind> = sup
            .status()
            .into_iter()
            .map(|s| (s.name.clone(), s.state))
            .collect();
        assert_eq!(states["dep"], StateKind::Starting);
        assert_eq!(states["top"], StateKind::Pending);

        wait_for_state(&sup, "top", StateKind::Ready, Duration::from_secs(20)).await;
        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn up_pulls_transitive_dependencies() {
        let dir = tempdir().unwrap();
        let sup = test_supervisor(&dir, CollectSink::new());

        let mut a = def("a", &["/bin/sleep", "10"], dir.path());
        a.restart = RestartPolicy::Always;
        let mut b = def("b", &["/bin/sleep", "10"], dir.path());
        b.depends = vec!["a".to_string()];
        b.restart = RestartPolicy::Always;
        sup.sync(dir.path(), vec![a, b], Map::new()).await.unwrap();

        let started = sup.up(Some(&["b".to_string()])).await.unwrap();
        assert_eq!(started, vec!["a".to_string(), "b".to_string()]);
        wait_for_state(&sup, "b", StateKind::Ready, Duration::from_secs(20)).await;
        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn desired_state_persists_and_reloads() {
        let dir = tempdir().unwrap();
        let sup = test_supervisor(&dir, CollectSink::new());
        let mut svc = def("keeper", &["/bin/sleep", "10"], dir.path());
        svc.restart = RestartPolicy::Always;
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(None).await.unwrap();
        wait_for_state(&sup, "keeper", StateKind::Ready, Duration::from_secs(20)).await;
        sup.down(None).await.unwrap();

        // 0600 on the state file.
        let meta = std::fs::metadata(dir.path().join("services.json")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        // A fresh supervisor sees the definition with desired-down.
        let sup2 = test_supervisor(&dir, CollectSink::new());
        sup2.restore().await.unwrap();
        let status = sup2.status();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].name, "keeper");
        assert!(!status[0].desired_up);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn boot_reconciliation_terminates_survivor_and_respawns_once() {
        let dir = tempdir().unwrap();
        let port = free_port();
        let binder = format!(
            "import socket,time\ns=socket.socket()\ns.bind((\"127.0.0.1\",{port}))\ns.listen()\ntime.sleep(30)"
        );
        let make_def = |root: &Path| {
            let mut svc = def("binder", &["/usr/bin/python3", "-c", &binder], root);
            svc.ready = ReadyCheck::Port(port);
            svc.restart = RestartPolicy::Always;
            svc
        };

        let sup_a = test_supervisor(&dir, CollectSink::new());
        sup_a
            .sync(dir.path(), vec![make_def(dir.path())], Map::new())
            .await
            .unwrap();
        sup_a.up(None).await.unwrap();
        wait_for_state(&sup_a, "binder", StateKind::Ready, Duration::from_secs(60)).await;
        let old_pid = running_pid(&sup_a, "binder").await;

        // Simulate an unclean daemon exit: tasks die, the child survives
        // holding the port.
        sup_a.abandon_for_test();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The respawn below can only work if reconciliation will recognize
        // (and kill) the survivor. Assert that premise directly first: when
        // the identity check goes inconclusive, THIS is the failure to show,
        // with the leg-naming warn! in the captured output — not a 60s
        // EADDRINUSE crash-loop two waits later.
        let persisted = load_persisted(&dir.path().join("services.json")).unwrap();
        let marker = persisted.services["binder"]
            .running
            .clone()
            .expect("abandoned run must leave a running marker");
        assert!(
            marker_identity_matches(&marker),
            "survivor identity check went inconclusive for live pid {} (see warnings above); \
             reconciliation would strand the port",
            marker.pid
        );

        // A new daemon generation must terminate the orphan (identity check
        // passes) and respawn exactly once — the rebind only succeeds if the
        // old group is gone.
        let sup_b = test_supervisor(&dir, CollectSink::new());
        sup_b.restore().await.unwrap();
        wait_for_state(&sup_b, "binder", StateKind::Ready, Duration::from_secs(60)).await;
        let new_pid = running_pid(&sup_b, "binder").await;
        assert_ne!(new_pid, old_pid, "must respawn, not adopt");

        sup_b.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn boot_reconciliation_clears_dead_marker_without_signaling() {
        let dir = tempdir().unwrap();
        // A pid that is certainly dead by the time restore runs.
        let dead = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let dead_pid = dead.id();
        let mut child = dead;
        child.wait().unwrap();

        let svc = def("ghost", &["/bin/sleep", "10"], dir.path());
        let persisted = Persisted {
            version: 1,
            services: Map::from([(
                "ghost".to_string(),
                PersistedService {
                    root: dir.path().to_path_buf(),
                    definition: svc,
                    desired_up: false,
                    running: Some(RunningMarker {
                        pid: dead_pid,
                        pgid: dead_pid as i32,
                        spawn_unix_ms: crate::now_unix_ms(),
                        argv: vec!["/bin/sleep".into(), "10".into()],
                    }),
                },
            )]),
            secrets: Map::new(),
        };
        write_persisted(&dir.path().join("services.json"), &persisted).unwrap();

        let sup = test_supervisor(&dir, CollectSink::new());
        sup.restore().await.unwrap();

        // Marker cleared in the rewritten state file.
        let reloaded = load_persisted(&dir.path().join("services.json")).unwrap();
        assert!(reloaded.services["ghost"].running.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn boot_reconciliation_never_signals_identity_mismatch() {
        let dir = tempdir().unwrap();
        // A live process whose pid/pgid we record but whose argv does NOT
        // match the marker — a "reused pgid" stand-in. It shares the test's
        // process group, so the own-group guard also protects us.
        let mut decoy = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let decoy_pid = decoy.id();
        let decoy_pgid = nix::unistd::getpgid(Some(Pid::from_raw(decoy_pid as i32)))
            .unwrap()
            .as_raw();

        let svc = def("imposter", &["/bin/sleep", "10"], dir.path());
        let persisted = Persisted {
            version: 1,
            services: Map::from([(
                "imposter".to_string(),
                PersistedService {
                    root: dir.path().to_path_buf(),
                    definition: svc,
                    desired_up: false,
                    running: Some(RunningMarker {
                        pid: decoy_pid,
                        pgid: decoy_pgid,
                        spawn_unix_ms: crate::now_unix_ms(),
                        argv: vec!["/bin/sleep".into(), "31".into()], // mismatch
                    }),
                },
            )]),
            secrets: Map::new(),
        };
        write_persisted(&dir.path().join("services.json"), &persisted).unwrap();

        let sup = test_supervisor(&dir, CollectSink::new());
        sup.restore().await.unwrap();

        // The decoy must still be alive — identity mismatch is never signaled.
        assert!(nix::sys::signal::kill(Pid::from_raw(decoy_pid as i32), None).is_ok());
        decoy.kill().unwrap();
        decoy.wait().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sync_restarts_changed_and_stops_removed() {
        let dir = tempdir().unwrap();
        let sink = CollectSink::new();
        let sup = test_supervisor(&dir, sink.clone());

        let mut one = def("one", &["/bin/sh", "-c", "echo v1; sleep 10"], dir.path());
        one.restart = RestartPolicy::Always;
        let mut two = def("two", &["/bin/sleep", "10"], dir.path());
        two.restart = RestartPolicy::Always;
        sup.sync(dir.path(), vec![one.clone(), two], Map::new())
            .await
            .unwrap();
        sup.up(None).await.unwrap();
        wait_for_state(&sup, "one", StateKind::Ready, Duration::from_secs(20)).await;
        wait_for_state(&sup, "two", StateKind::Ready, Duration::from_secs(20)).await;
        let two_pid = sup
            .status()
            .iter()
            .find(|s| s.name == "two")
            .unwrap()
            .pid
            .unwrap();

        // Change `one`, drop `two`.
        let mut one_v2 = one.clone();
        one_v2.run = vec!["/bin/sh".into(), "-c".into(), "echo v2; sleep 10".into()];
        let report = sup
            .sync(dir.path(), vec![one_v2], Map::new())
            .await
            .unwrap();
        assert_eq!(report.updated, vec!["one"]);
        assert_eq!(report.removed, vec!["two"]);

        wait_for_state(&sup, "one", StateKind::Ready, Duration::from_secs(20)).await;
        let deadline = Instant::now() + Duration::from_secs(2);
        while sink.count_containing("v2") == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(sink.count_containing("v2") >= 1, "changed def must restart");
        assert!(sup.status().iter().all(|s| s.name != "two"));
        assert!(
            nix::sys::signal::kill(Pid::from_raw(two_pid as i32), None).is_err(),
            "removed service process must be stopped"
        );

        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_sync_forgets_every_service_owned_by_the_root() {
        let dir = tempdir().unwrap();
        let sup = test_supervisor(&dir, CollectSink::new());
        let root = dir.path().join("repo");
        let other_root = dir.path().join("other-repo");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&other_root).unwrap();
        let mut web = def("web", &["/bin/sleep", "300"], &root);
        web.restart = RestartPolicy::Always;
        let worker = def("worker", &["/bin/sleep", "300"], &other_root);

        sup.sync(&root, vec![web], Map::new()).await.unwrap();
        sup.sync(&other_root, vec![worker], Map::new())
            .await
            .unwrap();
        sup.up(None).await.unwrap();
        wait_for_state(&sup, "web", StateKind::Ready, Duration::from_secs(20)).await;
        wait_for_state(&sup, "worker", StateKind::Ready, Duration::from_secs(20)).await;
        let statuses = sup.status();
        let pid = statuses
            .iter()
            .find(|s| s.name == "web")
            .unwrap()
            .pid
            .unwrap();
        let worker_pid = statuses
            .iter()
            .find(|s| s.name == "worker")
            .unwrap()
            .pid
            .unwrap();
        assert!(
            nix::sys::signal::kill(Pid::from_raw(pid as i32), None).is_ok(),
            "service process must be alive before it is forgotten"
        );

        let report = sup.sync(&root, Vec::new(), Map::new()).await.unwrap();

        assert_eq!(report.removed, vec!["web"]);
        assert_eq!(
            sup.status()
                .iter()
                .map(|status| status.name.as_str())
                .collect::<Vec<_>>(),
            vec!["worker"]
        );
        assert!(
            nix::sys::signal::kill(Pid::from_raw(pid as i32), None).is_err(),
            "forgotten service process must be stopped"
        );
        assert!(
            nix::sys::signal::kill(Pid::from_raw(worker_pid as i32), None).is_ok(),
            "another root's service process must stay running"
        );
        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sync_rejects_cross_root_name_collision() {
        let dir = tempdir().unwrap();
        let sup = test_supervisor(&dir, CollectSink::new());
        let root_a = dir.path().join("a");
        let root_b = dir.path().join("b");
        sup.sync(
            &root_a,
            vec![def("web", &["/bin/sleep", "1"], &root_a)],
            Map::new(),
        )
        .await
        .unwrap();
        let err = sup
            .sync(
                &root_b,
                vec![def("web", &["/bin/sleep", "1"], &root_b)],
                Map::new(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already defined"), "{err}");
    }

    /// A [`RouteBinder`] over real registry/static-store with `.internal`
    /// managed, plus a supervisor wired to it.
    fn route_test_setup(
        dir: &TempDir,
    ) -> (
        Supervisor,
        portman_core::Registry,
        Arc<portman_core::StaticStore>,
    ) {
        let registry = portman_core::Registry::new();
        let static_store =
            Arc::new(portman_core::StaticStore::load(dir.path().join("static.json")).unwrap());
        let binder = Arc::new(RouteBinder {
            registry: registry.clone(),
            static_store: static_store.clone(),
            known_tlds: Arc::new(std::sync::RwLock::new(std::collections::HashSet::from([
                "internal".to_string(),
            ]))),
            tls_store: Arc::new(portman_core::TlsStore::load(dir.path().join("tls.json")).unwrap()),
            cert_manager: crate::certs::CertManager::new(dir.path().join("certs"), None),
        });
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let sup = Supervisor::new(
            dir.path().join("services.json"),
            BaseEnv {
                user: "test".into(),
                home,
            },
            IdentityPolicy::CurrentUser,
            fast_timings(),
            CollectSink::new(),
            Arc::new(NoSecrets),
            binder,
        );
        (sup, registry, static_store)
    }

    fn routed_def(name: &str, host: &str, port: u16, dir: &Path) -> ServiceDefinition {
        let mut svc = def(name, &["/bin/sleep", "10"], dir);
        svc.host = Some(host.to_string());
        svc.port = Some(port);
        svc.ready = ReadyCheck::None;
        svc.restart = RestartPolicy::Always;
        svc
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn route_registers_on_up_and_removes_on_down() {
        let dir = tempdir().unwrap();
        let (sup, registry, _static_store) = route_test_setup(&dir);
        let svc = routed_def("web", "web.internal", 34567, dir.path());
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();

        assert!(
            registry.get("web.internal").is_none(),
            "sync alone must not route"
        );
        sup.up(None).await.unwrap();
        let entry = registry.get("web.internal").expect("route derived on up");
        assert_eq!(entry.source, portman_protocol::Source::Service);
        assert_eq!(entry.target, "127.0.0.1:34567");

        sup.down(None).await.unwrap();
        assert!(
            registry.get("web.internal").is_none(),
            "route removed on down"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn route_wins_over_static_rule_and_down_restores_it() {
        let dir = tempdir().unwrap();
        let (sup, registry, static_store) = route_test_setup(&dir);
        // The migration-window layout: a legacy static rule and the native
        // service claim the same host.
        static_store
            .add(
                "web.internal".into(),
                "127.0.0.1:9080".into(),
                portman_protocol::Mode::Http,
                None,
                None,
            )
            .unwrap();
        registry.upsert(portman_protocol::Entry {
            host: "web.internal".into(),
            target: "127.0.0.1:9080".into(),
            source: portman_protocol::Source::Static,
            mode: portman_protocol::Mode::Http,
            container_id: None,
            project: None,
        });

        let svc = routed_def("web", "web.internal", 34568, dir.path());
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(None).await.unwrap();
        let entry = registry.get("web.internal").unwrap();
        assert_eq!(entry.source, portman_protocol::Source::Service);
        assert_eq!(entry.target, "127.0.0.1:34568");

        // Down does NOT bare-remove: the static fallback is re-seeded.
        sup.down(None).await.unwrap();
        let entry = registry.get("web.internal").expect("static route restored");
        assert_eq!(entry.source, portman_protocol::Source::Static);
        assert_eq!(entry.target, "127.0.0.1:9080");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unmanaged_tld_service_gets_no_route() {
        let dir = tempdir().unwrap();
        let (sup, registry, _static_store) = route_test_setup(&dir);
        let svc = routed_def("web", "web.unmanaged", 34569, dir.path());
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(None).await.unwrap();
        assert!(registry.get("web.unmanaged").is_none());
        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn config_removal_deregisters_route() {
        let dir = tempdir().unwrap();
        let (sup, registry, _static_store) = route_test_setup(&dir);
        let svc = routed_def("web", "web.internal", 34570, dir.path());
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(None).await.unwrap();
        assert!(registry.get("web.internal").is_some());

        // The service disappears from the config → stopped + unrouted.
        sup.sync(dir.path(), vec![], Map::new()).await.unwrap();
        assert!(registry.get("web.internal").is_none());
    }

    /// Stub secrets source with a scripted outcome per resolve call.
    type ScriptedOutcome = Result<Vec<(String, String)>, SecretsError>;

    struct ScriptedSecrets {
        outcomes: Mutex<Vec<ScriptedOutcome>>,
    }

    impl ScriptedSecrets {
        fn new(outcomes: Vec<ScriptedOutcome>) -> Arc<Self> {
            Arc::new(Self {
                outcomes: Mutex::new(outcomes),
            })
        }
    }

    #[async_trait::async_trait]
    impl SecretsSource for ScriptedSecrets {
        async fn resolve(
            &self,
            _def: &ServiceDefinition,
            _blocks: &Map<String, SecretsProviderConfig>,
        ) -> Result<Vec<(String, String)>, SecretsError> {
            let mut outcomes = self.outcomes.lock().unwrap();
            if outcomes.len() > 1 {
                outcomes.remove(0)
            } else {
                outcomes[0].clone()
            }
        }
    }

    fn secrets_supervisor(
        dir: &TempDir,
        source: Arc<dyn SecretsSource>,
        sink: Arc<dyn LineSink>,
    ) -> Supervisor {
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        Supervisor::new(
            dir.path().join("services.json"),
            BaseEnv {
                user: "test".into(),
                home,
            },
            IdentityPolicy::CurrentUser,
            fast_timings(),
            sink,
            source,
            Arc::new(NoRoutes),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn provider_values_reach_child_env_between_files_and_inline() {
        let dir = tempdir().unwrap();
        let env_file = dir.path().join("f.env");
        std::fs::write(
            &env_file,
            "FROM_FILE=file\nSHADOWED=file\nINLINE_WINS=file\n",
        )
        .unwrap();

        let sink = CollectSink::new();
        let source = ScriptedSecrets::new(vec![Ok(vec![
            ("SHADOWED".to_string(), "provider".to_string()),
            ("INLINE_WINS".to_string(), "provider".to_string()),
            ("FROM_PROVIDER".to_string(), "provider".to_string()),
        ])]);
        let sup = secrets_supervisor(&dir, source, sink.clone());

        let mut svc = def("mix", &["/usr/bin/env"], dir.path());
        svc.env_files = vec![env_file];
        svc.env = Map::from([("INLINE_WINS".to_string(), "inline".to_string())]);
        svc.secrets = vec!["stub".to_string()];
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(None).await.unwrap();
        wait_for_state(&sup, "mix", StateKind::Failed, Duration::from_secs(20)).await;
        wait_for_line(&sink, |l| l.starts_with("FROM_PROVIDER=")).await;

        let joined = sink.lines().join("\n");
        assert!(joined.contains("FROM_FILE=file"), "{joined}");
        assert!(joined.contains("SHADOWED=provider"), "{joined}");
        assert!(joined.contains("INLINE_WINS=inline"), "{joined}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transient_secrets_error_retries_via_backoff() {
        let dir = tempdir().unwrap();
        let source = ScriptedSecrets::new(vec![
            Err(SecretsError::transient("instance unreachable")),
            Err(SecretsError::transient("instance unreachable")),
            Ok(vec![]),
        ]);
        let sup = secrets_supervisor(&dir, source, CollectSink::new());

        let mut svc = def("flaky", &["/bin/sleep", "10"], dir.path());
        svc.restart = RestartPolicy::Always;
        svc.secrets = vec!["stub".to_string()];
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(None).await.unwrap();

        // Two transient failures back off, the third attempt comes up.
        wait_for_state(&sup, "flaky", StateKind::Ready, Duration::from_secs(20)).await;
        let status = sup.status().remove(0);
        assert!(status.restarts >= 2, "expected backoff retries: {status:?}");
        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_transient_secrets_error_lands_failed_despite_restart_policy() {
        let dir = tempdir().unwrap();
        let source = ScriptedSecrets::new(vec![Err(SecretsError::fatal("auth rejected"))]);
        let sup = secrets_supervisor(&dir, source, CollectSink::new());

        let mut svc = def("rejected", &["/bin/sleep", "10"], dir.path());
        svc.restart = RestartPolicy::Always; // fatal must short-circuit this
        svc.secrets = vec!["stub".to_string()];
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(None).await.unwrap();

        wait_for_state(&sup, "rejected", StateKind::Failed, Duration::from_secs(20)).await;
        let status = sup.status().remove(0);
        assert!(status.detail.contains("auth rejected"), "{status:?}");
        assert_eq!(status.restarts, 0, "fatal must not loop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn secrets_optional_proceeds_env_files_only_and_flags_status() {
        let dir = tempdir().unwrap();
        let source = ScriptedSecrets::new(vec![Err(SecretsError::fatal("no identity stored"))]);
        let sup = secrets_supervisor(&dir, source, CollectSink::new());

        let mut svc = def("fallback", &["/bin/sleep", "10"], dir.path());
        svc.restart = RestartPolicy::Always;
        svc.secrets = vec!["stub".to_string()];
        svc.secrets_optional = true;
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(None).await.unwrap();

        wait_for_state(&sup, "fallback", StateKind::Ready, Duration::from_secs(20)).await;
        let status = sup.status().remove(0);
        assert!(
            status.detail.contains("env_files only"),
            "status must flag the degraded start: {status:?}"
        );
        sup.down(None).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_preserves_desired_state_for_boot_restore() {
        let dir = tempdir().unwrap();
        let sup = test_supervisor(&dir, CollectSink::new());
        let mut svc = def("boots", &["/bin/sleep", "10"], dir.path());
        svc.restart = RestartPolicy::Always;
        sup.sync(dir.path(), vec![svc], Map::new()).await.unwrap();
        sup.up(None).await.unwrap();
        wait_for_state(&sup, "boots", StateKind::Ready, Duration::from_secs(20)).await;
        let pid = sup.status()[0].pid.unwrap();

        sup.shutdown_all().await;
        assert!(nix::sys::signal::kill(Pid::from_raw(pid as i32), None).is_err());

        let persisted = load_persisted(&dir.path().join("services.json")).unwrap();
        assert!(
            persisted.services["boots"].desired_up,
            "shutdown must not flip desired state"
        );
        assert!(persisted.services["boots"].running.is_none());
    }
}
