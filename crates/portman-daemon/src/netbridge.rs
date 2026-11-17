//! Daemon integration for the v1 portman-netbridge.
//!
//! Long-running task that owns zero or one `Runtime` and converges it on
//! what the user asked for: the on/off flag and the route mode persisted in
//! `~/Library/Application Support/portman/netbridge.json`. The
//! `PORTMAN_NETBRIDGE` env var turns the bridge on for one daemon run. It
//! is never persisted, and a `Disable` ends it.
//!
//! Control flow:
//!
//!   - a `Control` message from the IPC server changes the intent. The
//!     intent is persisted before anything acts on it, so an enable issued
//!     while the engine is unreachable is still an enable after a restart.
//!   - [`plan`] compares the intent and the engine session with the running
//!     bridge and names the next step. The loop applies steps until none is
//!     left, then waits for a control message, a change of engine session,
//!     or a retry timer. Before each step it takes the messages that are in
//!     the channel. A message that arrives later waits for the step to end:
//!     the loop does not cancel a step in flight. The bridge gives the
//!     engine [`runtime::ENGINE_STEP_BUDGET`] for each step and
//!     [`runtime::ENGINE_START_BUDGET`] for a start, so a message waits no
//!     longer than that for an engine that froze. A start that is cut
//!     there fails and is retried, and a cleanup stays owed.
//!   - a bridge is built on one engine session. When no session exists the
//!     loop ends the bridge and asks the engine nothing. When another
//!     session opens, the loop keeps the bridge if that engine says within
//!     [`SETUP_CHECK_BUDGET`] that it still runs the setup container that
//!     the bridge started, because the tunnel then still has both ends.
//!     Otherwise it ends the bridge and builds a new one. It waits for the
//!     tasks of a bridge that it ends, because they hold the UDP port that
//!     the next bridge binds.
//!   - while the bridge is off and none runs, the loop removes the setup
//!     container that an earlier bridge can have left in the engine, once
//!     for each session and again when the user turns the bridge off. Only
//!     a `Disable` makes it also remove the docker network, because a
//!     stopped container of the user can still refer to it. That removal
//!     stays owed until a cleanup has done it: with no session it waits for
//!     one, and a cleanup that was skipped or that failed is tried again on
//!     the next session. The stop of a bridge that the user turned off is
//!     such a cleanup, so no second one follows it on its session. A
//!     network that the engine refuses to remove because it is in use is
//!     not owed. It stays until the next `Disable`, so that no later
//!     session removes it under containers that have stopped. The debt is
//!     not saved, so a daemon restart ends it. Each removal needs the UDP
//!     port that a bridge listens on, so that it cannot take what another
//!     daemon's bridge runs on.
//!   - a failed start is retried with a growing delay. The wait does not
//!     hold up control messages, and a new session starts the delay over.
//!   - a bridge that is up gets the DNS forwarder in the VM: the loop makes
//!     the bridge ensure it once, and again when the managed TLD set
//!     changes. An ensure that does not put the forwarder in place leaves
//!     the bridge up and is repeated a minute later. So is one that started
//!     the forwarder, because a dnsmasq that ends at once shows only then.
//!     The forwarder outlives
//!     the bridge and the daemon. Only the user's `Disable` removes it,
//!     before the docker network. It goes also when the engine then keeps
//!     a network that is in use. A forwarder that could not be removed
//!     beside such a network stays until the next `Disable`.
//!   - [`publish`] tells the rest of the daemon what the bridge is doing:
//!     the [`phase`], the mode, the interface index of the utun, and when a
//!     start that failed runs again.

use std::collections::{BTreeSet, HashSet};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bollard::query_parameters::InspectContainerOptions;
use bollard::Docker;
use portman_core::netbridge_state::{self, NetbridgeState};
use portman_core::NetbridgeMode;
use portman_netbridge::runtime::{
    self, CleanupEnd, DnsForwarder, Leftovers, Runtime, RuntimeOptions,
};
use portman_netbridge::tunnel::{Keypair, HOST_WG_LISTEN_PORT};
use tokio::sync::{mpsc, watch, Notify, RwLock};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::engine::{Engine, Link, Session};

/// Env var override. Useful for the first-run path where the user's
/// `netbridge.json` doesn't exist yet and they want to flip the bridge
/// on from the LaunchDaemon plist before `portman bridge enable`
/// lands. Presence (non-empty, not "0"/"false") turns the bridge on until
/// the daemon exits or a `Disable` arrives.
const ENABLE_ENV: &str = "PORTMAN_NETBRIDGE";

/// How long the engine of a new session has to say whether it runs a
/// bridge's setup container. bollard bounds only the wait for a response
/// head, so a VM that froze with its socket open would never end this
/// check. The budget bounds this check alone. A later step that asks the
/// same engine holds the loop, and with it every control message, for the
/// [`runtime::ENGINE_STEP_BUDGET`] that the bridge gives the engine for a
/// step, or for the [`runtime::ENGINE_START_BUDGET`] of a start.
const SETUP_CHECK_BUDGET: Duration = Duration::from_secs(3);

const RETRY_BASE: Duration = Duration::from_secs(5);
const RETRY_CAP: Duration = Duration::from_secs(60);
/// The wait before the next ensure of a DNS forwarder that is not in place
/// or that was started only now. It is also how soon a setup image that the user built with `portman
/// bridge prepare` is noticed.
const FORWARDER_RETRY: Duration = Duration::from_secs(60);

/// Where the daemon keeps the managed TLD set.
pub(crate) type KnownTlds = Arc<std::sync::RwLock<HashSet<String>>>;

/// Messages the IPC server sends to the netbridge task.
#[derive(Debug)]
pub(crate) enum Control {
    Enable,
    Disable,
    SetMode(NetbridgeMode),
}

/// What the bridge is doing, as the rest of the daemon sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BridgePhase {
    Disabled,
    /// The user wants a bridge and no engine session exists to build it on.
    WaitingForDocker,
    /// A start is in flight or waiting for its retry.
    Starting,
    /// `epoch` increments for every new bridge, so that a reader can tell a
    /// new bridge from the one it last saw up.
    Up {
        epoch: u64,
    },
    /// A bridge still runs and the next step removes it. The phase that
    /// follows is published only when that bridge is gone. `turned_off`
    /// tells a bridge that the user turned off from one that a new bridge
    /// replaces.
    Stopping {
        turned_off: bool,
    },
}

impl BridgePhase {
    pub(crate) fn epoch(self) -> Option<u64> {
        match self {
            BridgePhase::Up { epoch } => Some(epoch),
            _ => None,
        }
    }

    /// What `bridge_enabled` tells a client that predates the phase. Such a
    /// client waits on this flag alone. It stays true while a bridge that
    /// the user turned off is on its way out, so that `disable` returns
    /// when the bridge is gone. It is false while a bridge stops to be
    /// replaced, so that `enable` does not take that bridge for up.
    pub(crate) fn reads_as_enabled(self) -> bool {
        matches!(
            self,
            BridgePhase::Up { .. } | BridgePhase::Stopping { turned_off: true }
        )
    }
}

impl From<BridgePhase> for portman_protocol::BridgePhase {
    fn from(phase: BridgePhase) -> Self {
        match phase {
            BridgePhase::Disabled => Self::Disabled,
            BridgePhase::WaitingForDocker => Self::WaitingForDocker,
            BridgePhase::Starting => Self::Starting,
            BridgePhase::Up { .. } => Self::Up,
            BridgePhase::Stopping { .. } => Self::Stopping,
        }
    }
}

/// Shared handle the IPC server holds to push control messages and read
/// what the netbridge task last published.
#[derive(Clone)]
pub(crate) struct Handle {
    pub tx: mpsc::Sender<Control>,
    pub mode: Arc<RwLock<NetbridgeMode>>,
    pub phase: watch::Receiver<BridgePhase>,
    /// Interface index of the bridge's utun while it is up. The proxy /
    /// forwarder subsystems scope upstream sockets to it so bridge-subnet
    /// traffic survives a VPN/exit-node claiming the default route.
    pub ifindex: crate::upstream::BridgeIfIndex,
    /// Wakes the netbridge task after a change of the managed TLD set, which
    /// the DNS forwarder is built from.
    pub tlds_changed: Arc<Notify>,
    /// When the next start is due, while a start that failed waits for its
    /// retry.
    pub retry_at: Arc<std::sync::RwLock<Option<Instant>>>,
}

impl Handle {
    pub(crate) fn retry_in_secs(&self) -> Option<NonZeroU64> {
        let at = (*self.retry_at.read().expect("retry lock poisoned"))?;
        let left = at.saturating_duration_since(Instant::now());
        NonZeroU64::new(left.as_secs() + u64::from(left.subsec_nanos() > 0))
    }
}

/// Build the handle the daemon shares, and the two ends only the netbridge
/// task holds.
pub(crate) fn handle_pair() -> (Handle, mpsc::Receiver<Control>, watch::Sender<BridgePhase>) {
    let (tx, rx) = mpsc::channel(8);
    let mode = Arc::new(RwLock::new(NetbridgeMode::OptIn));
    let (phase_tx, phase) = watch::channel(BridgePhase::Disabled);
    (
        Handle {
            tx,
            mode,
            phase,
            ifindex: crate::upstream::new_bridge_ifindex(),
            tlds_changed: Arc::new(Notify::new()),
            retry_at: Arc::default(),
        },
        rx,
        phase_tx,
    )
}

/// What a running bridge was built from. `session` is the last one whose
/// engine ran the bridge's setup container. The VM behind any other session
/// may not hold the peer that the bridge talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Built {
    session: Session,
    mode: NetbridgeMode,
    epoch: u64,
}

struct Running<B> {
    bridge: B,
    built: Built,
    /// `None` until the loop has ensured the DNS forwarder for this bridge.
    forwarded: Option<Forwarded>,
}

/// The last ensure of a running bridge's DNS forwarder.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Forwarded {
    tlds: BTreeSet<String>,
    ended: Ensured,
    /// When the next ensure is due. `None` for a forwarder that was found
    /// in place.
    retry_at: Option<Instant>,
}

/// How an ensure of the DNS forwarder ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ensured {
    InPlace,
    /// Created and started now. The next ensure shows whether it stays up.
    Started,
    /// The setup image in the engine cannot run the forwarder.
    ImageWithoutDnsMode,
    /// The engine starts the right container again and again.
    Restarting,
    Failed,
}

/// Whether the loop ensures the forwarder of a running bridge now: for a
/// new bridge, for a new managed TLD set, and when a retry is due.
fn forwarder_due(forwarded: Option<&Forwarded>, tlds: &BTreeSet<String>, now: Instant) -> bool {
    match forwarded {
        None => true,
        Some(last) => last.tlds != *tlds || last.retry_at.is_some_and(|at| at <= now),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Step {
    Keep,
    Start(Session),
    /// End the bridge without a Docker call. Its session is gone, and no
    /// later session's engine said in time that it runs the bridge's setup
    /// container.
    Abandon,
    /// Stop the bridge and keep the docker network, so that attached
    /// containers keep their addresses while the mode changes.
    Shutdown,
    /// Stop the bridge and remove the docker network. The user asked for
    /// the bridge to be off.
    Teardown,
    /// Remove what an earlier bridge can have left in the engine. No bridge
    /// runs and the user wants none.
    Sweep(Session, Leftovers),
    /// Make the running bridge ensure the DNS forwarder in the VM.
    Forward,
}

/// `owed` is what a cleanup on this session is to remove. It is `None` once
/// the session had its cleanup, also when that one left the network owed.
/// `forwarder_due` is [`forwarder_due`] for the running bridge.
fn plan(
    intent: &NetbridgeState,
    session: Option<Session>,
    running: Option<Built>,
    may_start: bool,
    owed: Option<Leftovers>,
    forwarder_due: bool,
) -> Step {
    match (running, session, owed) {
        (Some(built), session, _) if session != Some(built.session) => Step::Abandon,
        (Some(_), _, _) if !intent.enabled => Step::Teardown,
        (Some(built), _, _) if built.mode != intent.mode => Step::Shutdown,
        (Some(_), _, _) if forwarder_due => Step::Forward,
        (None, Some(session), _) if intent.enabled && may_start => Step::Start(session),
        (None, Some(session), Some(leftovers)) if !intent.enabled => {
            Step::Sweep(session, leftovers)
        }
        _ => Step::Keep,
    }
}

/// `Up` only for a bridge that [`plan`] keeps. A bridge that `plan` removes
/// is `Stopping`, so that a reader waiting for the bridge to be off or to be
/// up again does not take the removal for done. `Stopping` also tells the
/// container-facing listeners to let go of the utun. The loop does not wait
/// for them before it removes the bridge.
fn phase(intent: &NetbridgeState, session: Option<Session>, running: Option<Built>) -> BridgePhase {
    match (running, session) {
        (Some(built), Some(session))
            if intent.enabled && built.session == session && built.mode == intent.mode =>
        {
            BridgePhase::Up { epoch: built.epoch }
        }
        (Some(_), _) => BridgePhase::Stopping {
            turned_off: !intent.enabled,
        },
        (None, _) if !intent.enabled => BridgePhase::Disabled,
        (None, None) => BridgePhase::WaitingForDocker,
        (None, Some(_)) => BridgePhase::Starting,
    }
}

/// The mode that status reports beside [`phase`]: the running bridge's mode
/// while one exists, and the wanted mode otherwise. A client that waits for
/// a mode change to finish therefore never sees the new mode beside the
/// bridge that was built for the old one.
fn reported_mode(intent: &NetbridgeState, running: Option<Built>) -> NetbridgeMode {
    running.map_or(intent.mode, |built| built.mode)
}

/// One start sequence: a first attempt and its retries. The doc of
/// `Runtime::start_with_keypair` says why they share one host key.
struct Attempts {
    host_kp: Keypair,
    failures: u32,
    retry_at: Option<Instant>,
}

impl Attempts {
    fn new() -> Self {
        Self {
            host_kp: Keypair::generate(),
            failures: 0,
            retry_at: None,
        }
    }

    /// Records how one attempt ended. A failure schedules the retry. A
    /// success ends the sequence, so that the next start has a new key and
    /// the first delay.
    fn settle<T>(&mut self, started: Result<T>) -> Option<T> {
        match started {
            Ok(bridge) => {
                *self = Self::new();
                Some(bridge)
            }
            Err(err) => {
                self.failures += 1;
                let retry_after = backoff(self.failures);
                warn!(
                    err = %format_args!("{err:#}"),
                    attempt = self.failures,
                    retry_in_secs = retry_after.as_secs(),
                    "netbridge start failed"
                );
                self.retry_at = Some(Instant::now() + retry_after);
                None
            }
        }
    }
}

fn backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(4);
    RETRY_BASE.saturating_mul(1 << doublings).min(RETRY_CAP)
}

/// What the loop has yet to remove from the engine. [`plan`] collects it only
/// while the bridge is off and none runs, so a debt that an enable finds is
/// not collected, and the disable that turns the bridge off again owes the
/// network anew. The debt is not saved: after a daemon restart every session
/// owes the setup container and no network.
#[derive(Default)]
struct Debt {
    /// A `Disable` asked for the DNS forwarder and the docker network to go,
    /// and no cleanup has run to its end since.
    network: bool,
    /// The session that had its cleanup. Every other session is owed one.
    swept: Option<Session>,
}

impl Debt {
    fn owed_on(&self, session: Option<Session>) -> Option<Leftovers> {
        (self.swept != session).then_some(if self.network {
            Leftovers::SetupContainerAndNetwork
        } else {
            Leftovers::SetupContainer
        })
    }

    fn disabled(&mut self) {
        self.network = true;
        self.swept = None;
    }

    /// A cleanup that did not finish is not tried again on its session.
    fn settle(&mut self, session: Session, leftovers: Leftovers, swept: Swept) {
        self.swept = Some(session);
        let complete = swept == Swept::Ended(CleanupEnd::Complete);
        if leftovers == Leftovers::SetupContainerAndNetwork && complete {
            self.network = false;
        }
    }
}

/// How a cleanup that the loop planned ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Swept {
    Ended(CleanupEnd),
    /// The UDP port that a bridge listens on was taken, so the engine was
    /// not asked. Another daemon's bridge holds that port, and so can a
    /// process that is not portman.
    PortTaken,
    /// Another session existed at the call, so the engine was not asked.
    SessionEnded,
}

/// What the bridge should be: the intent the user saved, with the
/// `PORTMAN_NETBRIDGE` override on top. Only `saved` is written to
/// `netbridge.json`.
struct Wanted {
    saved: NetbridgeState,
    forced_on: bool,
}

impl Wanted {
    fn intent(&self) -> NetbridgeState {
        NetbridgeState {
            enabled: self.saved.enabled || self.forced_on,
            mode: self.saved.mode,
        }
    }

    fn apply(&mut self, msg: Control) {
        match msg {
            Control::Enable => self.saved.enabled = true,
            Control::Disable => {
                self.saved.enabled = false;
                self.forced_on = false;
            }
            Control::SetMode(mode) => {
                if self.saved.mode != mode {
                    info!(mode = mode.as_str(), "netbridge mode changed");
                }
                self.saved.mode = mode;
            }
        }
    }
}

/// Long-running task spawned from `main`. It returns only when the control
/// channel closes, and `handle` holds a sender, so it runs for as long as
/// the daemon polls it.
pub(crate) async fn run(
    engine: Engine,
    handle: Handle,
    rx: mpsc::Receiver<Control>,
    phase_tx: watch::Sender<BridgePhase>,
    state_path: PathBuf,
    known_tlds: KnownTlds,
) -> Result<()> {
    let forced_on = env_forces_enabled();
    let engine = LinkedEngine::new(engine.watch());
    converge(
        engine, handle, rx, phase_tx, state_path, forced_on, known_tlds,
    )
    .await
}

async fn converge<E: BridgeEngine>(
    mut engine: E,
    handle: Handle,
    mut rx: mpsc::Receiver<Control>,
    phase_tx: watch::Sender<BridgePhase>,
    state_path: PathBuf,
    forced_on: bool,
    known_tlds: KnownTlds,
) -> Result<()> {
    let mut wanted = Wanted {
        saved: netbridge_state::load(&state_path),
        forced_on,
    };
    info!(
        persisted_enabled = wanted.saved.enabled,
        mode = wanted.saved.mode.as_str(),
        env = forced_on,
        "netbridge subsystem starting"
    );

    let mut session = None;
    let mut running: Option<Running<E::Bridge>> = None;
    let mut attempts = Attempts::new();
    let mut epoch = 0;
    let mut debt = Debt::default();

    loop {
        while let Ok(msg) = rx.try_recv() {
            take(msg, &mut wanted, &mut attempts, &mut debt, &state_path);
        }
        // A start sequence serves one session, as it serves one intent.
        if session != engine.session() {
            session = engine.session();
            attempts = Attempts::new();
            if let (Some(session), Some(running)) = (session, running.as_mut()) {
                let setup_container = running.bridge.setup_container_id();
                if still_runs(&engine, session, setup_container).await {
                    info!(
                        session = session.0,
                        "netbridge kept for a new docker session"
                    );
                    running.built.session = session;
                }
            }
        }
        let intent = wanted.intent();
        let built = running.as_ref().map(|r| r.built);
        publish(
            &handle,
            &phase_tx,
            phase(&intent, session, built),
            reported_mode(&intent, built),
            running.as_ref(),
            attempts.retry_at,
        )
        .await;
        let may_start = attempts.retry_at.is_none();
        let tlds = managed_tlds(&known_tlds);
        let now = Instant::now();
        let forwarded = running.as_ref().map(|r| r.forwarded.as_ref());
        let forwarder_due = forwarded.is_some_and(|last| forwarder_due(last, &tlds, now));
        let owed = debt.owed_on(session);
        match plan(&intent, session, built, may_start, owed, forwarder_due) {
            Step::Keep => {
                // A start waits only while no bridge runs, and a forwarder
                // only while one does, so one timer serves both.
                let forwarder_retry = forwarded.flatten().and_then(|last| last.retry_at);
                let retry_after = attempts
                    .retry_at
                    .or(forwarder_retry)
                    .map(|at| at.saturating_duration_since(now));
                let tlds_changed = &handle.tlds_changed;
                match next_wake(&mut rx, &mut engine, tlds_changed, retry_after).await {
                    Wake::Control(msg) => {
                        take(msg, &mut wanted, &mut attempts, &mut debt, &state_path);
                    }
                    Wake::RetryDue => attempts.retry_at = None,
                    Wake::SessionChanged | Wake::TldsChanged => {}
                    Wake::Closed => return Ok(()),
                }
            }
            Step::Forward => {
                if let Some(running) = running.as_mut() {
                    let last = running.forwarded.take();
                    running.forwarded = Some(forward(&running.bridge, tlds, last).await);
                }
            }
            Step::Start(session) => {
                let started = try_start(&engine, session, intent.mode, &mut attempts).await;
                if let Some(bridge) = started {
                    epoch += 1;
                    running = Some(Running {
                        bridge,
                        built: Built {
                            session,
                            mode: intent.mode,
                            epoch,
                        },
                        forwarded: None,
                    });
                }
            }
            Step::Abandon => {
                if let Some(old) = running.take() {
                    old.bridge.abandon().await;
                }
            }
            Step::Shutdown => {
                if let Some(old) = running.take() {
                    old.bridge.shutdown().await;
                }
            }
            Step::Teardown => {
                if let Some(old) = running.take() {
                    let ended = old.bridge.shutdown_and_remove_network().await;
                    let asked_for = Leftovers::SetupContainerAndNetwork;
                    debt.settle(old.built.session, asked_for, Swept::Ended(ended));
                }
            }
            Step::Sweep(session, leftovers) => {
                let swept = engine.remove_leftovers(session, leftovers).await;
                debt.settle(session, leftovers, swept);
            }
        }
    }
}

/// A message changes what the user wants, so it also ends the start
/// sequence that served the old intent. Only a `Disable` makes the loop
/// remove the docker network.
fn take(
    msg: Control,
    wanted: &mut Wanted,
    attempts: &mut Attempts,
    debt: &mut Debt,
    state_path: &Path,
) {
    if matches!(msg, Control::Disable) {
        debt.disabled();
    }
    wanted.apply(msg);
    persist(state_path, &wanted.saved);
    *attempts = Attempts::new();
}

/// Whether the engine of `session` runs `container`, as far as it says
/// within [`SETUP_CHECK_BUDGET`].
async fn still_runs(engine: &impl BridgeEngine, session: Session, container: &str) -> bool {
    let check = engine.runs_container(session, container);
    tokio::time::timeout(SETUP_CHECK_BUDGET, check)
        .await
        .unwrap_or(false)
}

fn managed_tlds(known_tlds: &KnownTlds) -> BTreeSet<String> {
    let known = known_tlds.read().expect("known_tlds lock poisoned");
    known.iter().cloned().collect()
}

/// Makes `bridge` ensure the DNS forwarder for `tlds`. Nothing here stops
/// or restarts the bridge. An outcome that repeats the last one is logged
/// at debug level, so that a retry every minute does not fill the log.
async fn forward(
    bridge: &impl Bridge,
    tlds: BTreeSet<String>,
    last: Option<Forwarded>,
) -> Forwarded {
    let ensured = bridge.ensure_dns_forwarder(&tlds).await;
    let ended = match &ensured {
        Ok(DnsForwarder::InPlace) => Ensured::InPlace,
        Ok(DnsForwarder::Started) => Ensured::Started,
        Ok(DnsForwarder::ImageWithoutDnsMode) => Ensured::ImageWithoutDnsMode,
        Ok(DnsForwarder::Restarting) => Ensured::Restarting,
        Err(_) => Ensured::Failed,
    };
    let repeats = last.is_some_and(|last| last.ended == ended && last.tlds == tlds);
    let retry_in_secs = FORWARDER_RETRY.as_secs();
    match (&ensured, repeats) {
        (Ok(DnsForwarder::InPlace), false) => {
            info!(?tlds, "dns forwarder in place at 192.168.99.129");
        }
        (Ok(DnsForwarder::Started), false) => info!(
            ?tlds,
            look_again_in_secs = retry_in_secs,
            "dns forwarder started at 192.168.99.129"
        ),
        (Ok(DnsForwarder::ImageWithoutDnsMode), false) => warn!(
            retry_in_secs,
            "dns forwarder unavailable: the netbridge setup image has no dns mode; run `portman bridge prepare`"
        ),
        (Ok(DnsForwarder::Restarting), false) => warn!(
            retry_in_secs,
            "dns forwarder keeps restarting and is left as it is; `docker logs portman-netbridge-dns` shows why"
        ),
        (Err(err), false) => warn!(%err, retry_in_secs, "dns forwarder not in place"),
        (_, true) => debug!(?ended, "dns forwarder: the same as a minute ago"),
    }
    Forwarded {
        tlds,
        ended,
        retry_at: (ended != Ensured::InPlace).then(|| Instant::now() + FORWARDER_RETRY),
    }
}

enum Wake {
    Control(Control),
    SessionChanged,
    TldsChanged,
    RetryDue,
    Closed,
}

/// A message that is ready goes before a retry that is due, so that no
/// start runs ahead of a `Disable` that is already in the channel.
async fn next_wake(
    rx: &mut mpsc::Receiver<Control>,
    engine: &mut impl BridgeEngine,
    tlds_changed: &Notify,
    retry_after: Option<Duration>,
) -> Wake {
    tokio::select! {
        biased;
        msg = rx.recv() => msg.map_or(Wake::Closed, Wake::Control),
        () = engine.session_changed() => Wake::SessionChanged,
        () = tlds_changed.notified() => Wake::TldsChanged,
        () = tokio::time::sleep(retry_after.unwrap_or_default()), if retry_after.is_some() => {
            Wake::RetryDue
        }
    }
}

/// The one place that tells the rest of the daemon what the bridge is
/// doing. The ifindex goes first, so that a reader woken by `Up` finds it
/// set. The mode goes last, so that a reader that takes the mode first and
/// the phase second never gets a new mode with a phase that is older than
/// it.
async fn publish(
    handle: &Handle,
    phase_tx: &watch::Sender<BridgePhase>,
    phase: BridgePhase,
    mode: NetbridgeMode,
    running: Option<&Running<impl Bridge>>,
    retry_at: Option<Instant>,
) {
    let up = running.filter(|_| phase.epoch().is_some());
    publish_ifindex(&handle.ifindex, up.map(|r| &r.bridge));
    *handle.retry_at.write().expect("retry lock poisoned") = retry_at;
    phase_tx.send_replace(phase);
    *handle.mode.write().await = mode;
}

/// Publish the utun's interface index while the bridge is up so upstream
/// connects can scope to it (see [`crate::upstream`]); `None` clears it.
/// Resolution failure downgrades to unscoped connects rather than erroring —
/// the bridge itself is fine, only exit-node immunity is lost.
fn publish_ifindex(slot: &crate::upstream::BridgeIfIndex, bridge: Option<&impl Bridge>) {
    let resolved = bridge.and_then(|bridge| {
        let name = bridge.utun_name();
        match nix::net::if_::if_nametoindex(name) {
            Ok(idx) => Some(idx),
            Err(err) => {
                warn!(utun = %name, %err, "resolving utun ifindex; upstream scoping disabled");
                None
            }
        }
    });
    *slot.write().expect("bridge ifindex lock poisoned") = resolved;
}

/// The container engine as the control loop uses it, so that a test can
/// run the loop with no engine.
pub(crate) trait BridgeEngine {
    type Bridge: Bridge;

    fn session(&self) -> Option<Session>;

    /// Returns when the session may differ from the one last returned. A
    /// caller that drops the wait loses no change.
    async fn session_changed(&mut self);

    /// Fails at once when another session exists at the call. A session
    /// that ends during the start does not stop it.
    async fn start_bridge(
        &self,
        session: Session,
        mode: NetbridgeMode,
        host_kp: &Keypair,
    ) -> Result<Self::Bridge>;

    /// Whether the engine of `session` runs the container with this id.
    /// False when the engine does not say, and when another session exists
    /// at the call.
    async fn runs_container(&self, session: Session, id: &str) -> bool;

    /// Removes `leftovers` that carry portman's label from the engine of
    /// `session`, and says how that ended. Does nothing when another
    /// session exists at the call, or when the UDP port that a bridge
    /// listens on is taken.
    async fn remove_leftovers(&self, session: Session, leftovers: Leftovers) -> Swept;
}

/// A bridge that is up. The control loop holds it only through this, so
/// that a test can hold one without root.
pub(crate) trait Bridge {
    fn utun_name(&self) -> &str;
    /// The engine's id of the setup container that the bridge started.
    fn setup_container_id(&self) -> &str;
    /// Makes the bridge's engine run the DNS forwarder for `tlds`. It
    /// changes the engine only while the forwarder differs from that.
    async fn ensure_dns_forwarder(&self, tlds: &BTreeSet<String>) -> Result<DnsForwarder>;
    /// Ends the bridge and asks its engine nothing. The listen port is free
    /// when this returns, so that the next start can take it.
    async fn abandon(self);
    /// Stops the bridge and keeps the docker network and the DNS forwarder.
    async fn shutdown(self);
    /// Stops the bridge and removes the DNS forwarder and the docker
    /// network, and says how that ended. The bridge holds the listen port,
    /// so its engine is always asked.
    async fn shutdown_and_remove_network(self) -> CleanupEnd;
}

/// The engine behind the daemon's link. Its bridges listen on UDP port
/// `listen_port`, and its cleanups need that port. The port is a field so
/// that a test can name one that it holds or that is free.
struct LinkedEngine {
    link: watch::Receiver<Link>,
    listen_port: u16,
}

impl LinkedEngine {
    /// The engine as the daemon uses it, on the one port that every portman
    /// daemon's bridge listens on. A cleanup that holds any other port has
    /// not shown that no other daemon's bridge is up.
    fn new(link: watch::Receiver<Link>) -> Self {
        Self {
            link,
            listen_port: HOST_WG_LISTEN_PORT,
        }
    }
}

impl BridgeEngine for LinkedEngine {
    type Bridge = Runtime;

    fn session(&self) -> Option<Session> {
        self.link.borrow().session()
    }

    async fn session_changed(&mut self) {
        if self.link.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    async fn start_bridge(
        &self,
        session: Session,
        mode: NetbridgeMode,
        host_kp: &Keypair,
    ) -> Result<Runtime> {
        let docker = docker_of(&self.link, session)?;
        let options = RuntimeOptions {
            mode,
            listen_port: self.listen_port,
        };
        Runtime::start_with_keypair(docker, options, host_kp).await
    }

    async fn runs_container(&self, session: Session, id: &str) -> bool {
        let Ok(docker) = docker_of(&self.link, session) else {
            return false;
        };
        let inspected = docker
            .inspect_container(id, None::<InspectContainerOptions>)
            .await;
        inspected
            .is_ok_and(|container| container.state.and_then(|state| state.running) == Some(true))
    }

    async fn remove_leftovers(&self, session: Session, leftovers: Leftovers) -> Swept {
        let Ok(docker) = docker_of(&self.link, session) else {
            info!(
                session = session.0,
                "netbridge cleanup skipped: the engine session that it was planned on has ended"
            );
            return Swept::SessionEnded;
        };
        let listen_port = self.listen_port;
        match runtime::try_remove_leftovers(&docker, listen_port, leftovers).await {
            Ok(ended) => Swept::Ended(ended),
            Err(err) => {
                info!(
                    listen_port,
                    %err,
                    "netbridge leftovers stay in the engine: the listen port is taken, and its holder may run a bridge on them"
                );
                Swept::PortTaken
            }
        }
    }
}

fn docker_of(link: &watch::Receiver<Link>, wanted: Session) -> Result<Docker> {
    match &*link.borrow() {
        Link::Connected {
            session, docker, ..
        } if *session == wanted => Ok(docker.clone()),
        _ => anyhow::bail!("the engine session that the bridge was planned on has ended"),
    }
}

impl Bridge for Runtime {
    fn utun_name(&self) -> &str {
        Runtime::utun_name(self)
    }

    fn setup_container_id(&self) -> &str {
        Runtime::setup_container_id(self)
    }

    async fn ensure_dns_forwarder(&self, tlds: &BTreeSet<String>) -> Result<DnsForwarder> {
        Runtime::ensure_dns_forwarder(self, tlds).await
    }

    async fn abandon(self) {
        Runtime::abandon(self).await;
    }

    async fn shutdown(self) {
        Runtime::shutdown(self).await;
    }

    async fn shutdown_and_remove_network(self) -> CleanupEnd {
        Runtime::shutdown_and_remove_network(self).await
    }
}

async fn try_start<E: BridgeEngine>(
    engine: &E,
    session: Session,
    mode: NetbridgeMode,
    attempts: &mut Attempts,
) -> Option<E::Bridge> {
    let started = engine.start_bridge(session, mode, &attempts.host_kp).await;
    let bridge = attempts.settle(started)?;
    info!(
        mode = mode.as_str(),
        "netbridge up: docker network `portman`, container pool 192.168.99.130–.253"
    );
    Some(bridge)
}

fn persist(path: &Path, intent: &NetbridgeState) {
    if let Err(err) = netbridge_state::save(path, intent) {
        warn!(%err, "persisting netbridge state");
    }
}

fn env_forces_enabled() -> bool {
    std::env::var(ENABLE_ENV).is_ok_and(|value| forces_enabled(&value))
}

fn forces_enabled(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime::{ENGINE_START_BUDGET, ENGINE_STEP_BUDGET};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tempfile::{tempdir, TempDir};
    use Leftovers::{SetupContainer, SetupContainerAndNetwork};
    use NetbridgeMode::{Docker as DockerMode, OptIn};

    const S1: Option<Session> = Some(Session(1));
    const S2: Option<Session> = Some(Session(2));
    const ON: bool = true;
    const OFF: bool = false;

    fn built(session: Option<Session>, mode: NetbridgeMode) -> Option<Built> {
        session.map(|session| Built {
            session,
            mode,
            epoch: 7,
        })
    }

    fn intent(enabled: bool, mode: NetbridgeMode) -> NetbridgeState {
        NetbridgeState { enabled, mode }
    }

    #[test]
    fn plan_names_the_step_that_closes_the_gap() {
        let on_s1 = built(S1, OptIn);
        let (may, wait) = (true, false);
        // (enabled, wanted mode, session, running, may_start) → step
        let table = [
            (OFF, OptIn, S1, None, may, Step::Keep),
            (OFF, OptIn, None, None, may, Step::Keep),
            (ON, OptIn, None, None, may, Step::Keep),
            (ON, OptIn, S1, None, wait, Step::Keep),
            (ON, OptIn, S1, None, may, Step::Start(Session(1))),
            (ON, DockerMode, S2, None, may, Step::Start(Session(2))),
            (ON, OptIn, S1, on_s1, may, Step::Keep),
            (ON, OptIn, S1, on_s1, wait, Step::Keep),
            (ON, DockerMode, S1, on_s1, may, Step::Shutdown),
            (ON, DockerMode, S1, on_s1, wait, Step::Shutdown),
            (OFF, OptIn, S1, on_s1, may, Step::Teardown),
            (OFF, DockerMode, S1, on_s1, may, Step::Teardown),
            (ON, OptIn, None, on_s1, may, Step::Abandon),
            (ON, OptIn, S2, on_s1, may, Step::Abandon),
            (ON, DockerMode, S2, on_s1, may, Step::Abandon),
            (OFF, OptIn, None, on_s1, may, Step::Abandon),
            (OFF, OptIn, S2, on_s1, may, Step::Abandon),
        ];
        for (enabled, mode, session, running, may_start, want) in table {
            assert_eq!(
                plan(
                    &intent(enabled, mode),
                    session,
                    running,
                    may_start,
                    None,
                    false
                ),
                want,
                "enabled={enabled} mode={mode:?} session={session:?} running={running:?} may_start={may_start}"
            );
        }
    }

    #[test]
    fn plan_sweeps_what_is_owed_while_the_bridge_is_off_and_none_runs() {
        let on_s1 = built(S1, OptIn);
        let (may, wait) = (true, false);
        let (container, network) = (Some(SetupContainer), Some(SetupContainerAndNetwork));
        let sweep = |session, leftovers| Step::Sweep(Session(session), leftovers);
        // (enabled, session, running, may_start, owed) → step
        let table = [
            (OFF, S1, None, may, container, sweep(1, SetupContainer)),
            (OFF, S1, None, wait, container, sweep(1, SetupContainer)),
            (
                OFF,
                S2,
                None,
                may,
                network,
                sweep(2, SetupContainerAndNetwork),
            ),
            (OFF, S1, None, may, None, Step::Keep),
            (OFF, None, None, may, network, Step::Keep),
            (ON, S1, None, wait, network, Step::Keep),
            (ON, S1, None, may, network, Step::Start(Session(1))),
            (OFF, S1, on_s1, may, network, Step::Teardown),
            (OFF, S2, on_s1, may, network, Step::Abandon),
        ];
        for (enabled, session, running, may_start, owed, want) in table {
            assert_eq!(
                plan(
                    &intent(enabled, OptIn),
                    session,
                    running,
                    may_start,
                    owed,
                    false
                ),
                want,
                "enabled={enabled} session={session:?} running={running:?} may_start={may_start} owed={owed:?}"
            );
        }
    }

    #[test]
    fn plan_ensures_the_forwarder_only_for_a_bridge_that_it_keeps() {
        let on_s1 = built(S1, OptIn);
        let container = Some(SetupContainer);
        // (enabled, wanted mode, session, running, owed) → step, with the
        // forwarder due
        let table = [
            (ON, OptIn, S1, on_s1, None, Step::Forward),
            (ON, OptIn, S1, on_s1, container, Step::Forward),
            (ON, DockerMode, S1, on_s1, None, Step::Shutdown),
            (OFF, OptIn, S1, on_s1, None, Step::Teardown),
            (ON, OptIn, S2, on_s1, None, Step::Abandon),
            (ON, OptIn, None, on_s1, None, Step::Abandon),
            (ON, OptIn, S1, None, None, Step::Start(Session(1))),
            (ON, OptIn, None, None, None, Step::Keep),
            (OFF, OptIn, S1, None, None, Step::Keep),
            (
                OFF,
                OptIn,
                S1,
                None,
                container,
                Step::Sweep(Session(1), SetupContainer),
            ),
        ];
        for (enabled, mode, session, running, owed, want) in table {
            assert_eq!(
                plan(&intent(enabled, mode), session, running, true, owed, true),
                want,
                "enabled={enabled} mode={mode:?} session={session:?} running={running:?} owed={owed:?}"
            );
        }
    }

    fn tlds(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn the_forwarder_is_due_for_a_new_bridge_a_new_tld_set_and_a_retry_that_is_due() {
        let last = |names: &[&str], ended, retry_at| {
            Some(Forwarded {
                tlds: tlds(names),
                ended,
                retry_at,
            })
        };
        let earlier = Instant::now();
        let now = earlier + FORWARDER_RETRY;
        let waits = Some(now + Duration::from_millis(1));
        let (due_now, overdue) = (Some(now), Some(earlier));
        use Ensured::{Failed, ImageWithoutDnsMode, InPlace};
        // (the last ensure, the managed TLDs now) → due
        let table = [
            (None, vec!["test"], true),
            (None, vec![], true),
            (last(&["test"], InPlace, None), vec!["test"], false),
            (last(&["test"], InPlace, None), vec!["acme", "test"], true),
            (last(&["test"], InPlace, None), vec![], true),
            (last(&[], InPlace, None), vec![], false),
            (
                last(&["test"], ImageWithoutDnsMode, waits),
                vec!["test"],
                false,
            ),
            (
                last(&["test"], ImageWithoutDnsMode, due_now),
                vec!["test"],
                true,
            ),
            (
                last(&["test"], ImageWithoutDnsMode, waits),
                vec!["acme"],
                true,
            ),
            (last(&["test"], Failed, waits), vec!["test"], false),
            (last(&["test"], Failed, due_now), vec!["test"], true),
            (last(&["test"], Failed, overdue), vec!["test"], true),
        ];
        for (forwarded, managed, want) in table {
            assert_eq!(
                forwarder_due(forwarded.as_ref(), &tlds(&managed), now),
                want,
                "forwarded={forwarded:?} managed={managed:?}"
            );
        }
    }

    #[test]
    fn phase_reports_what_the_daemon_can_rely_on() {
        let on_s1 = built(S1, OptIn);
        let up = BridgePhase::Up { epoch: 7 };
        let turned_off = BridgePhase::Stopping { turned_off: true };
        let replaced = BridgePhase::Stopping { turned_off: false };
        // (enabled, wanted mode, session, running) → phase
        let table = [
            (OFF, OptIn, S1, None, BridgePhase::Disabled),
            (OFF, OptIn, None, None, BridgePhase::Disabled),
            (ON, OptIn, None, None, BridgePhase::WaitingForDocker),
            (ON, OptIn, S1, None, BridgePhase::Starting),
            (ON, OptIn, S1, on_s1, up),
            (ON, DockerMode, S2, built(S2, DockerMode), up),
            (OFF, OptIn, S1, on_s1, turned_off),
            (OFF, DockerMode, S1, on_s1, turned_off),
            (ON, DockerMode, S1, on_s1, replaced),
            (ON, OptIn, None, on_s1, replaced),
            (ON, OptIn, S2, on_s1, replaced),
            (OFF, OptIn, None, on_s1, turned_off),
            (OFF, OptIn, S2, on_s1, turned_off),
        ];
        for (enabled, mode, session, running, want) in table {
            assert_eq!(
                phase(&intent(enabled, mode), session, running),
                want,
                "enabled={enabled} mode={mode:?} session={session:?} running={running:?}"
            );
        }
    }

    #[test]
    fn a_bridge_is_up_while_plan_keeps_it_and_stopping_otherwise() {
        for enabled in [OFF, ON] {
            for mode in [OptIn, DockerMode] {
                for session in [None, S1, S2] {
                    for running in [None, built(S1, OptIn), built(S2, DockerMode)] {
                        let intent = intent(enabled, mode);
                        let kept = plan(&intent, session, running, true, None, false) == Step::Keep;
                        let phase = phase(&intent, session, running);
                        assert_eq!(
                            (
                                phase.epoch().is_some(),
                                matches!(phase, BridgePhase::Stopping { .. })
                            ),
                            (running.is_some() && kept, running.is_some() && !kept),
                            "enabled={enabled} mode={mode:?} session={session:?} running={running:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_new_mode_is_reported_once_the_bridge_built_for_the_old_one_is_gone() {
        let on_s1 = built(S1, OptIn);
        // (wanted mode, running) → reported mode
        let table = [
            (OptIn, None, OptIn),
            (DockerMode, None, DockerMode),
            (OptIn, on_s1, OptIn),
            (DockerMode, on_s1, OptIn),
        ];
        for (mode, running, want) in table {
            assert_eq!(
                reported_mode(&intent(ON, mode), running),
                want,
                "mode={mode:?} running={running:?}"
            );
        }
    }

    #[test]
    fn the_env_override_is_on_for_any_value_but_empty_zero_and_false() {
        for on in ["1", "true", "TRUE", "yes", "on", " 1 ", "2", "00"] {
            assert!(forces_enabled(on), "{on:?}");
        }
        for off in ["", " ", "0", " 0 ", "false", "FALSE", "False", " false\n"] {
            assert!(!forces_enabled(off), "{off:?}");
        }
    }

    #[test]
    fn backoff_grows_to_one_minute_and_stays_there() {
        assert_eq!(backoff(1), Duration::from_secs(5));
        assert_eq!(backoff(2), Duration::from_secs(10));
        assert_eq!(backoff(3), Duration::from_secs(20));
        assert_eq!(backoff(4), Duration::from_secs(40));
        assert_eq!(backoff(5), Duration::from_secs(60));
        assert_eq!(backoff(u32::MAX), Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn a_start_that_succeeds_ends_its_sequence() {
        let failed = || Err::<(), _>(anyhow::anyhow!("no container engine"));
        let now = Instant::now();
        let mut attempts = Attempts::new();
        let first_key = attempts.host_kp.public_base64();
        attempts.settle(failed());
        attempts.settle(failed());
        assert_eq!(attempts.retry_at, Some(now + Duration::from_secs(10)));
        assert_eq!(attempts.host_kp.public_base64(), first_key);

        assert_eq!(attempts.settle(Ok(())), Some(()));

        assert_ne!(attempts.host_kp.public_base64(), first_key);
        attempts.settle(failed());
        assert_eq!(attempts.retry_at, Some(now + RETRY_BASE));
    }

    struct Attempt {
        at: Instant,
        session: Session,
        mode: NetbridgeMode,
        host_key: String,
        /// What `netbridge.json` held while the attempt was in flight.
        saved: NetbridgeState,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Stop {
        KeepsNetwork,
        RemovesNetwork,
    }

    /// What a test sees of the bridges that the loop holds, and its hold on
    /// their stops.
    #[derive(Clone)]
    struct Probe {
        held: Arc<AtomicUsize>,
        phase: watch::Receiver<BridgePhase>,
        phase_at_utun_ask: Arc<Mutex<Vec<BridgePhase>>>,
        /// The setup container that the engine runs. A start replaces it.
        setup_container: Arc<Mutex<Option<String>>>,
        /// Each time the loop asked whether a bridge's setup container
        /// runs: the session it asked on and the phase it had published.
        container_asks: Arc<Mutex<Vec<(Session, BridgePhase)>>>,
        /// An engine that froze with its socket open never ends an ask.
        engine_froze: Arc<AtomicBool>,
        stops: mpsc::UnboundedSender<Stop>,
        stops_may_end: watch::Receiver<bool>,
        /// Each ensure of the DNS forwarder that the loop asked a bridge
        /// for.
        forwards: mpsc::UnboundedSender<Forwarding>,
        /// How the next ensure ends.
        ensure: Arc<Mutex<Ensure>>,
        port_held: Arc<AtomicBool>,
        cleanups_end: Arc<Mutex<CleanupEnd>>,
    }

    struct Forwarding {
        at: Instant,
        tlds: BTreeSet<String>,
        /// The phase that the loop had published when it asked.
        phase: BridgePhase,
    }

    #[derive(Debug, Clone, Copy)]
    enum Ensure {
        PutsItInPlace,
        StartsIt,
        FindsAnImageWithoutTheDnsMode,
        FindsItRestarting,
        Fails,
    }

    impl Probe {
        async fn stop(mut self, stop: Stop) {
            let _ = self.stops.send(stop);
            let _ = self.stops_may_end.wait_for(|may_end| *may_end).await;
        }
    }

    /// Awaits nothing but a session change and a stop that a test holds
    /// open, so that the paused clock moves only when the control loop
    /// waits.
    struct TestEngine {
        sessions: watch::Receiver<Option<Session>>,
        state_path: PathBuf,
        seen: mpsc::UnboundedSender<Attempt>,
        swept: mpsc::UnboundedSender<(Session, Leftovers)>,
        /// How each cleanup ends.
        cleanups_end: Arc<Mutex<CleanupEnd>>,
        /// `None` fails every start.
        probe: Option<Probe>,
    }

    impl BridgeEngine for TestEngine {
        type Bridge = TestBridge;

        fn session(&self) -> Option<Session> {
            *self.sessions.borrow()
        }

        async fn session_changed(&mut self) {
            self.sessions.changed().await.unwrap();
        }

        async fn start_bridge(
            &self,
            session: Session,
            mode: NetbridgeMode,
            host_kp: &Keypair,
        ) -> Result<TestBridge> {
            let _ = self.seen.send(Attempt {
                at: Instant::now(),
                session,
                mode,
                host_key: host_kp.public_base64(),
                saved: netbridge_state::load(&self.state_path),
            });
            match &self.probe {
                Some(probe) => {
                    if probe.port_held.swap(true, Ordering::SeqCst) {
                        anyhow::bail!("an earlier bridge holds the listen port");
                    }
                    probe.held.fetch_add(1, Ordering::SeqCst);
                    let setup_container = format!("the setup container for {session:?}");
                    *probe.setup_container.lock().unwrap() = Some(setup_container.clone());
                    Ok(TestBridge {
                        probe: probe.clone(),
                        setup_container,
                        holds_port: true,
                    })
                }
                None => anyhow::bail!("the start failed"),
            }
        }

        async fn runs_container(&self, session: Session, id: &str) -> bool {
            let Some(probe) = &self.probe else {
                return false;
            };
            let asked = (session, *probe.phase.borrow());
            probe.container_asks.lock().unwrap().push(asked);
            if probe.engine_froze.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            probe.setup_container.lock().unwrap().as_deref() == Some(id)
        }

        async fn remove_leftovers(&self, session: Session, leftovers: Leftovers) -> Swept {
            let _ = self.swept.send((session, leftovers));
            Swept::Ended(*self.cleanups_end.lock().unwrap())
        }
    }

    struct TestBridge {
        probe: Probe,
        setup_container: String,
        holds_port: bool,
    }

    impl TestBridge {
        fn free_port(&mut self) {
            self.holds_port = false;
            self.probe.port_held.store(false, Ordering::SeqCst);
        }
    }

    /// As a `Runtime` that is dropped: its tasks hold the listen port until
    /// the executor has run their abort, which is after the drop returns.
    impl Drop for TestBridge {
        fn drop(&mut self) {
            self.probe.held.fetch_sub(1, Ordering::SeqCst);
            if self.holds_port {
                let port_held = self.probe.port_held.clone();
                if let Ok(executor) = tokio::runtime::Handle::try_current() {
                    executor.spawn(async move { port_held.store(false, Ordering::SeqCst) });
                }
            }
        }
    }

    /// The loopback interface stands in for the utun: its name resolves to
    /// an index on every Mac.
    const TEST_UTUN: &str = "lo0";

    impl Bridge for TestBridge {
        fn utun_name(&self) -> &str {
            let published = *self.probe.phase.borrow();
            self.probe.phase_at_utun_ask.lock().unwrap().push(published);
            TEST_UTUN
        }

        fn setup_container_id(&self) -> &str {
            &self.setup_container
        }

        async fn ensure_dns_forwarder(&self, tlds: &BTreeSet<String>) -> Result<DnsForwarder> {
            let _ = self.probe.forwards.send(Forwarding {
                at: Instant::now(),
                tlds: tlds.clone(),
                phase: *self.probe.phase.borrow(),
            });
            let ensure = *self.probe.ensure.lock().unwrap();
            match ensure {
                Ensure::PutsItInPlace => Ok(DnsForwarder::InPlace),
                Ensure::StartsIt => Ok(DnsForwarder::Started),
                Ensure::FindsAnImageWithoutTheDnsMode => Ok(DnsForwarder::ImageWithoutDnsMode),
                Ensure::FindsItRestarting => Ok(DnsForwarder::Restarting),
                Ensure::Fails => anyhow::bail!("the engine refused the container"),
            }
        }

        async fn abandon(mut self) {
            self.free_port();
        }

        async fn shutdown(mut self) {
            self.probe.clone().stop(Stop::KeepsNetwork).await;
            self.free_port();
        }

        async fn shutdown_and_remove_network(mut self) -> CleanupEnd {
            self.probe.clone().stop(Stop::RemovesNetwork).await;
            self.free_port();
            *self.probe.cleanups_end.lock().unwrap()
        }
    }

    struct Rig {
        handle: Handle,
        sessions: watch::Sender<Option<Session>>,
        bridges_held: Arc<AtomicUsize>,
        state_path: PathBuf,
        attempts: mpsc::UnboundedReceiver<Attempt>,
        sweeps: mpsc::UnboundedReceiver<(Session, Leftovers)>,
        cleanups_end: Arc<Mutex<CleanupEnd>>,
        stops: mpsc::UnboundedReceiver<Stop>,
        stops_may_end: watch::Sender<bool>,
        phase_at_utun_ask: Arc<Mutex<Vec<BridgePhase>>>,
        setup_container: Arc<Mutex<Option<String>>>,
        container_asks: Arc<Mutex<Vec<(Session, BridgePhase)>>>,
        engine_froze: Arc<AtomicBool>,
        forwards: mpsc::UnboundedReceiver<Forwarding>,
        ensure: Arc<Mutex<Ensure>>,
        known_tlds: KnownTlds,
        daemon: tokio::task::JoinHandle<Result<()>>,
        dir: TempDir,
    }

    const LONGEST_WAIT: Duration = Duration::from_secs(3600);

    impl Rig {
        /// A rig whose engine is in its first session and fails every
        /// start.
        fn start() -> Self {
            Self::spawn(S1, false, false)
        }

        fn start_with_env_override(forced_on: bool) -> Self {
            Self::spawn(S1, false, forced_on)
        }

        /// A rig whose engine starts every bridge, with the first one up.
        async fn up() -> Self {
            let mut rig = Self::spawn(S1, true, false);
            rig.send(Control::Enable).await;
            rig.reaches(BridgePhase::Up { epoch: 1 }).await;
            assert_eq!(rig.next_attempt().await.mode, OptIn);
            rig
        }

        fn spawn(session: Option<Session>, engine_starts_bridges: bool, forced_on: bool) -> Self {
            Self::boot(
                tempdir().unwrap(),
                session,
                engine_starts_bridges,
                forced_on,
            )
        }

        /// A daemon that boots on the `netbridge.json` that `saved` holds,
        /// with an engine in its first session that fails every start.
        fn boot_on(saved: Option<&str>) -> Self {
            let dir = tempdir().unwrap();
            if let Some(saved) = saved {
                std::fs::write(dir.path().join("netbridge.json"), saved).unwrap();
            }
            Self::boot(dir, S1, false, false)
        }

        /// Ends this daemon and boots another on what it saved.
        async fn restart(self, session: Option<Session>) -> Self {
            self.daemon.abort();
            let _ = self.daemon.await;
            Self::boot(self.dir, session, false, false)
        }

        fn boot(
            dir: TempDir,
            session: Option<Session>,
            engine_starts_bridges: bool,
            forced_on: bool,
        ) -> Self {
            let (sessions, session_seen) = watch::channel(session);
            let bridges_held = Arc::new(AtomicUsize::new(0));
            let state_path = dir.path().join("netbridge.json");
            let (seen, attempts) = mpsc::unbounded_channel();
            let (swept, sweeps) = mpsc::unbounded_channel();
            let cleanups_end = Arc::new(Mutex::new(CleanupEnd::Complete));
            let (stop_seen, stops) = mpsc::unbounded_channel();
            let (stops_may_end, may_end) = watch::channel(true);
            let phase_at_utun_ask = Arc::new(Mutex::new(Vec::new()));
            let setup_container = Arc::new(Mutex::new(None));
            let container_asks = Arc::new(Mutex::new(Vec::new()));
            let engine_froze = Arc::new(AtomicBool::new(false));
            let (forward_seen, forwards) = mpsc::unbounded_channel();
            let ensure = Arc::new(Mutex::new(Ensure::PutsItInPlace));
            let known_tlds = KnownTlds::default();
            known_tlds.write().unwrap().insert("test".to_string());
            let (handle, rx, phase_tx) = handle_pair();
            let engine = TestEngine {
                sessions: session_seen,
                state_path: state_path.clone(),
                seen,
                swept,
                cleanups_end: cleanups_end.clone(),
                probe: engine_starts_bridges.then(|| Probe {
                    held: bridges_held.clone(),
                    phase: handle.phase.clone(),
                    phase_at_utun_ask: phase_at_utun_ask.clone(),
                    setup_container: setup_container.clone(),
                    container_asks: container_asks.clone(),
                    engine_froze: engine_froze.clone(),
                    stops: stop_seen,
                    stops_may_end: may_end,
                    forwards: forward_seen,
                    ensure: ensure.clone(),
                    port_held: Arc::default(),
                    cleanups_end: cleanups_end.clone(),
                }),
            };
            let daemon = tokio::spawn(converge(
                engine,
                handle.clone(),
                rx,
                phase_tx,
                state_path.clone(),
                forced_on,
                known_tlds.clone(),
            ));
            Rig {
                handle,
                sessions,
                bridges_held,
                state_path,
                attempts,
                sweeps,
                cleanups_end,
                stops,
                stops_may_end,
                phase_at_utun_ask,
                setup_container,
                container_asks,
                engine_froze,
                forwards,
                ensure,
                known_tlds,
                daemon,
                dir,
            }
        }

        /// Changes the managed TLD set as `DaemonState` does.
        fn manage(&self, names: &[&str]) {
            *self.known_tlds.write().unwrap() = names.iter().map(|name| name.to_string()).collect();
            self.handle.tlds_changed.notify_one();
        }

        fn the_next_ensure(&self, ensure: Ensure) {
            *self.ensure.lock().unwrap() = ensure;
        }

        async fn next_forward(&mut self) -> Forwarding {
            tokio::time::timeout(LONGEST_WAIT, self.forwards.recv())
                .await
                .expect("an ensure of the dns forwarder")
                .unwrap()
        }

        async fn no_forward_follows(&mut self) {
            let next = tokio::time::timeout(LONGEST_WAIT, self.forwards.recv()).await;
            assert!(
                next.is_err(),
                "an ensure of the dns forwarder that nothing called for"
            );
        }

        /// The stop that the loop began. With `hold_stops` it stays in
        /// flight until `end_stops`.
        async fn next_stop(&mut self) -> Stop {
            tokio::time::timeout(LONGEST_WAIT, self.stops.recv())
                .await
                .expect("a bridge stop")
                .unwrap()
        }

        fn hold_stops(&self) {
            self.stops_may_end.send_replace(false);
        }

        fn end_stops(&self) {
            self.stops_may_end.send_replace(true);
        }

        fn phase(&self) -> BridgePhase {
            *self.handle.phase.borrow()
        }

        fn engine_session(&self, session: Option<Session>) {
            self.sessions.send_replace(session);
        }

        /// Puts `container` where the engine ran a bridge's setup
        /// container.
        fn engine_runs(&self, container: Option<&str>) {
            *self.setup_container.lock().unwrap() = container.map(String::from);
        }

        fn engine_freezes(&self) {
            self.engine_froze.store(true, Ordering::SeqCst);
        }

        fn container_asks(&self) -> Vec<(Session, BridgePhase)> {
            self.container_asks.lock().unwrap().clone()
        }

        fn cleanups_end(&self, cleanup: CleanupEnd) {
            *self.cleanups_end.lock().unwrap() = cleanup;
        }

        fn bridges_held(&self) -> usize {
            self.bridges_held.load(Ordering::SeqCst)
        }

        fn no_stop_began(&mut self) -> bool {
            self.stops.try_recv().is_err()
        }

        async fn mode(&self) -> NetbridgeMode {
            *self.handle.mode.read().await
        }

        fn ifindex(&self) -> Option<u32> {
            *self.handle.ifindex.read().unwrap()
        }

        async fn send(&self, msg: Control) {
            self.handle.tx.send(msg).await.unwrap();
        }

        async fn next_attempt(&mut self) -> Attempt {
            tokio::time::timeout(LONGEST_WAIT, self.attempts.recv())
                .await
                .expect("a start attempt")
                .unwrap()
        }

        async fn next_sweep(&mut self) -> (Session, Leftovers) {
            tokio::time::timeout(LONGEST_WAIT, self.sweeps.recv())
                .await
                .expect("a sweep")
                .unwrap()
        }

        async fn no_sweep_follows(&mut self) {
            let next = tokio::time::timeout(LONGEST_WAIT, self.sweeps.recv()).await;
            assert!(next.is_err(), "a sweep that nothing called for");
        }

        async fn no_attempt_follows(&mut self) {
            let next = tokio::time::timeout(LONGEST_WAIT, self.attempts.recv()).await;
            assert!(next.is_err(), "a start attempt that nothing called for");
        }

        async fn reaches(&self, want: BridgePhase) {
            let mut phase = self.handle.phase.clone();
            tokio::time::timeout(LONGEST_WAIT, phase.wait_for(|p| *p == want))
                .await
                .unwrap_or_else(|_| panic!("the bridge never reported {want:?}"))
                .unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_start_is_tried_again_after_a_delay_that_grows_to_a_minute() {
        let mut rig = Rig::start();
        rig.send(Control::Enable).await;

        let mut attempts = Vec::new();
        for _ in 0..7 {
            attempts.push(rig.next_attempt().await);
        }

        let gaps: Vec<Duration> = attempts.windows(2).map(|w| w[1].at - w[0].at).collect();
        assert_eq!(gaps, [5, 10, 20, 40, 60, 60].map(Duration::from_secs));
        assert!(
            attempts.iter().all(|a| a.host_key == attempts[0].host_key),
            "a retry used a new host key"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_intent_is_saved_before_the_first_start_and_outlives_a_failed_one() {
        let mut rig = Rig::start();
        rig.send(Control::Enable).await;

        let first = rig.next_attempt().await;
        assert!(first.saved.enabled, "saved before the first start");
        let retry = rig.next_attempt().await;
        assert!(retry.saved.enabled, "still saved after a failed start");
        assert_eq!(*rig.handle.phase.borrow(), BridgePhase::Starting);

        rig.send(Control::SetMode(DockerMode)).await;
        let in_new_mode = rig.next_attempt().await;
        assert!(in_new_mode.saved.enabled);
        assert_eq!(in_new_mode.saved.mode, DockerMode);
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_lands_while_a_failed_start_waits_for_its_retry() {
        let mut rig = Rig::start();
        rig.send(Control::Enable).await;
        rig.next_attempt().await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        let sent = Instant::now();
        rig.send(Control::Disable).await;
        rig.reaches(BridgePhase::Disabled).await;

        assert_eq!(
            sent.elapsed(),
            Duration::ZERO,
            "the disable waited for the retry timer"
        );
        assert!(!netbridge_state::load(&rig.state_path).enabled);
        rig.no_attempt_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_control_message_ends_the_wait_for_a_retry_and_starts_a_new_sequence() {
        let mut rig = Rig::start();
        rig.send(Control::Enable).await;
        rig.next_attempt().await;
        rig.next_attempt().await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        let sent = Instant::now();
        rig.send(Control::SetMode(DockerMode)).await;
        let at_once = rig.next_attempt().await;
        let retry = rig.next_attempt().await;

        assert_eq!(at_once.at - sent, Duration::ZERO);
        assert_eq!(retry.at - at_once.at, RETRY_BASE);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wake_for_another_reason_does_not_put_off_the_retry_of_a_failed_start() {
        let mut rig = Rig::start();
        rig.send(Control::Enable).await;
        let first = rig.next_attempt().await;
        tokio::time::sleep(Duration::from_secs(3)).await;

        rig.manage(&["acme"]);
        let retry = rig.next_attempt().await;

        assert_eq!(retry.at - first.at, RETRY_BASE);
    }

    #[tokio::test(start_paused = true)]
    async fn the_time_of_the_retry_is_published_while_a_failed_start_waits_for_it() {
        let mut rig = Rig::start();
        assert_eq!(rig.handle.retry_in_secs(), None);

        rig.send(Control::Enable).await;
        rig.next_attempt().await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(rig.handle.retry_in_secs(), NonZeroU64::new(4));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(rig.handle.retry_in_secs(), NonZeroU64::new(2));

        rig.next_attempt().await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(rig.handle.retry_in_secs(), NonZeroU64::new(9));

        rig.send(Control::Disable).await;
        rig.reaches(BridgePhase::Disabled).await;
        assert_eq!(rig.handle.retry_in_secs(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_that_has_fallen_due_has_no_time_left_to_report() {
        let (handle, _rx, _phase_tx) = handle_pair();
        let due = Instant::now() + RETRY_BASE;
        *handle.retry_at.write().unwrap() = Some(due);

        tokio::time::advance(RETRY_BASE - Duration::from_nanos(1)).await;
        assert_eq!(handle.retry_in_secs(), NonZeroU64::new(1));
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert_eq!(handle.retry_in_secs(), None, "at the due instant");
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(handle.retry_in_secs(), None, "after the due instant");
    }

    #[tokio::test(start_paused = true)]
    async fn no_retry_time_is_published_for_a_bridge_that_is_up_or_waits_for_docker() {
        let rig = Rig::up().await;
        assert_eq!(rig.handle.retry_in_secs(), None);

        let mut failing = Rig::start();
        failing.send(Control::Enable).await;
        failing.next_attempt().await;
        failing.engine_session(None);
        failing.reaches(BridgePhase::WaitingForDocker).await;
        assert_eq!(failing.handle.retry_in_secs(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn the_utun_index_is_published_before_the_phase_says_up() {
        let rig = Rig::up().await;

        assert_eq!(rig.ifindex(), nix::net::if_::if_nametoindex(TEST_UTUN).ok());
        assert!(rig.ifindex().is_some());
        assert_eq!(
            rig.phase_at_utun_ask.lock().unwrap().first(),
            Some(&BridgePhase::Starting),
            "the phase said up before the loop asked the bridge for its utun"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_mode_change_keeps_the_network_and_reports_the_old_mode_until_the_bridge_is_gone() {
        let mut rig = Rig::up().await;
        rig.hold_stops();
        rig.send(Control::SetMode(DockerMode)).await;

        assert_eq!(rig.next_stop().await, Stop::KeepsNetwork);
        assert_eq!(rig.phase(), BridgePhase::Stopping { turned_off: false });
        assert_eq!(rig.mode().await, OptIn);
        assert_eq!(rig.ifindex(), None);

        rig.end_stops();
        rig.reaches(BridgePhase::Up { epoch: 2 }).await;
        assert_eq!(rig.mode().await, DockerMode);
        assert_eq!(rig.next_attempt().await.mode, DockerMode);
        assert!(rig.ifindex().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn the_phase_moves_on_from_the_old_bridge_before_the_mode_does() {
        let mut rig = Rig::up().await;
        rig.hold_stops();
        rig.send(Control::SetMode(DockerMode)).await;
        rig.next_stop().await;

        // A status read that took the mode and has yet to take the phase.
        let status_read = rig.handle.mode.read().await;
        rig.end_stops();
        rig.reaches(BridgePhase::Starting).await;
        assert_eq!(*status_read, OptIn);

        drop(status_read);
        rig.reaches(BridgePhase::Up { epoch: 2 }).await;
        assert_eq!(rig.mode().await, DockerMode);
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_reports_stopping_until_the_bridge_and_its_network_are_gone() {
        let mut rig = Rig::up().await;
        rig.hold_stops();
        rig.send(Control::Disable).await;

        assert_eq!(rig.next_stop().await, Stop::RemovesNetwork);
        assert_eq!(rig.phase(), BridgePhase::Stopping { turned_off: true });
        assert_eq!(rig.ifindex(), None);

        rig.end_stops();
        rig.reaches(BridgePhase::Disabled).await;
        rig.no_attempt_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_of_a_running_bridge_asks_the_engine_for_the_network_once() {
        let mut rig = Rig::up().await;

        rig.send(Control::Disable).await;

        assert_eq!(rig.next_stop().await, Stop::RemovesNetwork);
        rig.no_sweep_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_that_left_the_network_owed_is_followed_up_at_the_next_session() {
        let mut rig = Rig::up().await;
        rig.cleanups_end(CleanupEnd::Failed);

        rig.send(Control::Disable).await;

        assert_eq!(rig.next_stop().await, Stop::RemovesNetwork);
        rig.no_sweep_follows().await;

        rig.engine_session(S2);
        assert_eq!(
            rig.next_sweep().await,
            (Session(2), SetupContainerAndNetwork)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_during_a_mode_change_ends_it_without_a_new_start() {
        let mut rig = Rig::up().await;
        rig.hold_stops();
        rig.send(Control::SetMode(NetbridgeMode::All)).await;
        assert_eq!(rig.next_stop().await, Stop::KeepsNetwork);

        rig.send(Control::Disable).await;
        rig.end_stops();

        rig.reaches(BridgePhase::Disabled).await;
        rig.no_attempt_follows().await;
        let saved = netbridge_state::load(&rig.state_path);
        assert_eq!((saved.enabled, saved.mode), (false, NetbridgeMode::All));
    }

    #[tokio::test(start_paused = true)]
    async fn mode_changes_that_queue_up_during_a_stop_start_one_bridge_in_the_last_mode() {
        let mut rig = Rig::up().await;
        rig.hold_stops();
        rig.send(Control::SetMode(DockerMode)).await;
        assert_eq!(rig.next_stop().await, Stop::KeepsNetwork);

        rig.send(Control::SetMode(NetbridgeMode::All)).await;
        rig.send(Control::SetMode(DockerMode)).await;
        rig.end_stops();

        assert_eq!(rig.next_attempt().await.mode, DockerMode);
        rig.reaches(BridgePhase::Up { epoch: 2 }).await;
        assert_eq!(rig.mode().await, DockerMode);
    }

    #[tokio::test(start_paused = true)]
    async fn the_env_override_runs_the_bridge_and_is_never_saved() {
        let mut rig = Rig::start_with_env_override(true);
        let unasked = rig.next_attempt().await;
        assert!(!unasked.saved.enabled);

        rig.send(Control::SetMode(DockerMode)).await;
        let in_new_mode = rig.next_attempt().await;
        assert_eq!(in_new_mode.saved.mode, DockerMode);
        assert!(
            !in_new_mode.saved.enabled,
            "a mode change saved the override"
        );

        rig.send(Control::Disable).await;
        rig.reaches(BridgePhase::Disabled).await;
        rig.no_attempt_follows().await;
    }

    /// An engine with no probe, and the sender that changes its session.
    fn bare_engine() -> (TestEngine, watch::Sender<Option<Session>>) {
        let (sessions, session_seen) = watch::channel(S1);
        let (seen, _) = mpsc::unbounded_channel();
        let (swept, _) = mpsc::unbounded_channel();
        let engine = TestEngine {
            sessions: session_seen,
            state_path: PathBuf::new(),
            seen,
            swept,
            cleanups_end: Arc::new(Mutex::new(CleanupEnd::Complete)),
            probe: None,
        };
        (engine, sessions)
    }

    #[tokio::test(start_paused = true)]
    async fn a_control_message_goes_before_a_session_change_and_a_retry_that_are_due() {
        // An unbiased wait picks one of the ready branches at random, so
        // one round would pass a third of the time.
        let (mut engine, sessions) = bare_engine();
        for _ in 0..64 {
            let (tx, mut rx) = mpsc::channel(1);
            tx.send(Control::Disable).await.unwrap();
            sessions.send_replace(S2);
            let quiet = Notify::new();
            let wake = next_wake(&mut rx, &mut engine, &quiet, Some(Duration::ZERO)).await;
            assert!(matches!(wake, Wake::Control(Control::Disable)));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_that_is_due_ends_the_wait_when_nothing_else_is_ready() {
        let (_tx, mut rx) = mpsc::channel(1);
        let (mut engine, _sessions) = bare_engine();
        let quiet = Notify::new();
        let wait = next_wake(&mut rx, &mut engine, &quiet, Some(Duration::ZERO));
        let wake = tokio::time::timeout(LONGEST_WAIT, wait)
            .await
            .expect("the retry timer ends the wait");
        assert!(matches!(wake, Wake::RetryDue));
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_session_drops_the_bridge_without_a_stop_and_waits_for_docker() {
        let mut rig = Rig::up().await;
        assert_eq!(rig.bridges_held(), 1);

        rig.engine_session(None);
        rig.reaches(BridgePhase::WaitingForDocker).await;

        assert_eq!(rig.bridges_held(), 0);
        assert!(rig.no_stop_began(), "a stop asks an engine that is gone");
        assert_eq!(rig.container_asks(), [], "asked an engine that is gone");
        assert_eq!(rig.ifindex(), None);
        assert!(netbridge_state::load(&rig.state_path).enabled);
        rig.no_attempt_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_session_keeps_a_bridge_whose_setup_container_still_runs() {
        let mut rig = Rig::up().await;
        let up = BridgePhase::Up { epoch: 1 };

        rig.engine_session(S2);
        rig.no_attempt_follows().await;

        assert_eq!(
            rig.container_asks(),
            [(Session(2), up)],
            "the listeners follow the phase, and it left `Up` while the loop asked"
        );
        assert_eq!(rig.phase(), up);
        assert_eq!(rig.bridges_held(), 1);
        assert!(rig.no_stop_began());
        assert!(rig.ifindex().is_some());

        rig.send(Control::Disable).await;
        assert_eq!(rig.next_stop().await, Stop::RemovesNetwork);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_session_replaces_a_bridge_whose_setup_container_is_gone_or_is_another() {
        for in_the_engine in [None, Some("the setup container of another bridge")] {
            let mut rig = Rig::spawn(S1, true, false);
            rig.send(Control::Enable).await;
            let first_key = rig.next_attempt().await.host_key;
            rig.reaches(BridgePhase::Up { epoch: 1 }).await;

            rig.engine_runs(in_the_engine);
            rig.engine_session(S2);
            rig.reaches(BridgePhase::Up { epoch: 2 }).await;

            let rebuilt = rig.next_attempt().await;
            assert_eq!(Some(rebuilt.session), S2, "{in_the_engine:?}");
            assert_ne!(rebuilt.host_key, first_key);
            assert_eq!(rig.bridges_held(), 1);
            assert!(rig.no_stop_began(), "a stop of a bridge that is gone");
            assert!(rig.ifindex().is_some());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_runtime_restart_costs_no_failed_start() {
        let mut rig = Rig::up().await;

        rig.engine_session(None);
        rig.reaches(BridgePhase::WaitingForDocker).await;
        rig.engine_runs(None);
        rig.engine_session(S2);
        rig.reaches(BridgePhase::Up { epoch: 2 }).await;
        // The link stays on a session that ended until the next one opens,
        // so the loop sees session 3 follow session 2.
        rig.engine_runs(None);
        let reopened = Instant::now();
        rig.engine_session(Some(Session(3)));
        rig.reaches(BridgePhase::Up { epoch: 3 }).await;

        assert_eq!(
            reopened.elapsed(),
            Duration::ZERO,
            "the start on session 3 failed and waited for its retry"
        );
        let rebuilt = [rig.next_attempt().await, rig.next_attempt().await];
        assert_eq!(rebuilt.map(|a| a.session), [Session(2), Session(3)]);
        rig.no_attempt_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_check_that_never_ends_holds_a_disable_no_longer_than_its_budget() {
        let mut rig = Rig::up().await;
        rig.engine_freezes();
        rig.engine_session(S2);

        let sent = Instant::now();
        rig.send(Control::Disable).await;
        rig.reaches(BridgePhase::Disabled).await;

        assert_eq!(sent.elapsed(), SETUP_CHECK_BUDGET);
        assert_eq!(rig.container_asks().len(), 1);
        assert_eq!(rig.bridges_held(), 0);
        assert!(rig.no_stop_began(), "a stop asks an engine that froze");
    }

    #[tokio::test(start_paused = true)]
    async fn a_check_that_never_ends_replaces_the_bridge_when_its_budget_is_spent() {
        let mut rig = Rig::up().await;
        rig.engine_freezes();

        let opened = Instant::now();
        rig.engine_session(S2);
        rig.reaches(BridgePhase::Up { epoch: 2 }).await;

        let rebuilt = rig.next_attempt().await;
        assert_eq!(Some(rebuilt.session), S2);
        assert_eq!(rebuilt.at - opened, SETUP_CHECK_BUDGET);
        assert_eq!(rig.bridges_held(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_inspect_that_never_ends_is_a_container_that_does_not_run() {
        let (engine, fake) = empty_engine(FREE_PORT);
        let id = "aaaaaaaaaaaa1111";
        fake.hang(&format!("/containers/{id}/json"));

        let asked = Instant::now();
        let runs = tokio::time::timeout(LONGEST_WAIT, still_runs(&engine, Session(1), id))
            .await
            .expect("the check waited for the engine");

        assert!(!runs);
        assert_eq!(asked.elapsed(), SETUP_CHECK_BUDGET);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wanted_bridge_waits_for_docker_and_starts_when_a_session_opens() {
        let mut rig = Rig::spawn(None, true, false);
        rig.send(Control::Enable).await;
        rig.reaches(BridgePhase::WaitingForDocker).await;
        assert!(netbridge_state::load(&rig.state_path).enabled);
        tokio::time::sleep(LONGEST_WAIT).await;
        assert!(rig.attempts.try_recv().is_err(), "a start with no session");

        let opened = Instant::now();
        rig.engine_session(S1);
        rig.reaches(BridgePhase::Up { epoch: 1 }).await;

        let started = rig.next_attempt().await;
        assert_eq!(Some(started.session), S1);
        assert_eq!(started.at - opened, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_session_starts_at_once_with_a_new_key_and_the_first_retry_delay() {
        let mut rig = Rig::start();
        rig.send(Control::Enable).await;
        let first_key = rig.next_attempt().await.host_key;
        rig.next_attempt().await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        let opened = Instant::now();
        rig.engine_session(S2);
        let at_once = rig.next_attempt().await;
        let retry = rig.next_attempt().await;

        assert_eq!(Some(at_once.session), S2);
        assert_eq!(at_once.at - opened, Duration::ZERO);
        assert_ne!(at_once.host_key, first_key);
        assert_eq!(retry.at - at_once.at, RETRY_BASE);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_session_ends_the_retries_of_a_failed_start() {
        let mut rig = Rig::start();
        rig.send(Control::Enable).await;
        rig.next_attempt().await;

        rig.engine_session(None);

        rig.reaches(BridgePhase::WaitingForDocker).await;
        rig.no_attempt_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_bridge_that_comes_up_gets_the_forwarder_for_the_managed_tlds_once() {
        let mut rig = Rig::spawn(S1, true, false);
        rig.manage(&["test", "acme"]);
        let enabled = Instant::now();
        rig.send(Control::Enable).await;

        let forward = rig.next_forward().await;

        assert_eq!(forward.tlds, tlds(&["acme", "test"]));
        assert_eq!(forward.at - enabled, Duration::ZERO);
        assert_eq!(forward.phase, BridgePhase::Up { epoch: 1 });
        rig.no_forward_follows().await;
        assert_eq!(rig.phase(), BridgePhase::Up { epoch: 1 });
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_of_the_managed_tlds_reaches_the_forwarder_while_a_bridge_is_up() {
        let mut rig = Rig::up().await;
        assert_eq!(rig.next_forward().await.tlds, tlds(&["test"]));
        tokio::time::sleep(Duration::from_secs(1)).await;

        for managed in [vec!["acme", "test"], vec!["acme"], vec![]] {
            let changed = Instant::now();
            rig.manage(&managed);
            let forward = rig.next_forward().await;
            assert_eq!(forward.tlds, tlds(&managed));
            assert_eq!(forward.at - changed, Duration::ZERO);
        }

        rig.manage(&[]);
        rig.no_forward_follows().await;
        assert_eq!(rig.phase(), BridgePhase::Up { epoch: 1 });
        assert_eq!(rig.bridges_held(), 1);
        rig.no_attempt_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_forwarder_is_asked_for_only_while_a_bridge_is_up() {
        let mut rig = Rig::spawn(S1, true, false);
        rig.manage(&["acme"]);
        rig.no_forward_follows().await;
        assert_eq!(rig.phase(), BridgePhase::Disabled);

        rig.send(Control::Enable).await;
        assert_eq!(rig.next_forward().await.tlds, tlds(&["acme"]));

        rig.engine_session(None);
        rig.reaches(BridgePhase::WaitingForDocker).await;
        rig.manage(&["acme", "test"]);
        rig.no_forward_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_forwarder_that_is_not_in_place_leaves_the_bridge_up_and_is_tried_each_minute() {
        let not_in_place = [
            Ensure::StartsIt,
            Ensure::FindsAnImageWithoutTheDnsMode,
            Ensure::FindsItRestarting,
            Ensure::Fails,
        ];
        for ensure in not_in_place {
            let mut rig = Rig::spawn(S1, true, false);
            rig.the_next_ensure(ensure);
            rig.send(Control::Enable).await;

            let mut forwards = Vec::new();
            for _ in 0..4 {
                forwards.push(rig.next_forward().await);
            }

            let gaps: Vec<Duration> = forwards.windows(2).map(|w| w[1].at - w[0].at).collect();
            assert_eq!(gaps, [FORWARDER_RETRY; 3], "{ensure:?}");
            assert!(
                forwards
                    .iter()
                    .all(|f| f.phase == BridgePhase::Up { epoch: 1 }),
                "{ensure:?}"
            );
            assert_eq!(rig.bridges_held(), 1);
            assert!(rig.no_stop_began(), "{ensure:?}");
            rig.next_attempt().await;
            assert!(rig.attempts.try_recv().is_err(), "the bridge started again");

            rig.the_next_ensure(Ensure::PutsItInPlace);
            let in_place = rig.next_forward().await;
            assert_eq!(in_place.at - forwards[3].at, FORWARDER_RETRY, "{ensure:?}");
            rig.no_forward_follows().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_forwarder_that_ends_after_its_start_is_seen_a_minute_later_and_reported_once() {
        let (logged, _capture) = Logged::capture();
        let mut rig = Rig::spawn(S1, true, false);
        rig.the_next_ensure(Ensure::StartsIt);
        rig.send(Control::Enable).await;
        let started = rig.next_forward().await;

        rig.the_next_ensure(Ensure::FindsItRestarting);
        let first_look = rig.next_forward().await;
        assert_eq!(first_look.at - started.at, FORWARDER_RETRY);
        for _ in 0..2 {
            rig.next_forward().await;
        }
        rig.the_next_ensure(Ensure::PutsItInPlace);
        rig.next_forward().await;
        rig.no_forward_follows().await;

        let lines = logged.lines();
        let about_the_forwarder: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("dns forwarder"))
            .collect();
        assert_eq!(about_the_forwarder.len(), 3, "{lines:?}");
        let (started, restarting, in_place) = (
            about_the_forwarder[0],
            about_the_forwarder[1],
            about_the_forwarder[2],
        );
        assert!(started.contains("started at"), "{started}");
        assert!(restarting.contains("WARN"), "{restarting}");
        assert!(restarting.contains("keeps restarting"), "{restarting}");
        assert!(
            restarting.contains("docker logs portman-netbridge-dns"),
            "{restarting}"
        );
        assert!(in_place.contains("in place"), "{in_place}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_of_the_managed_tlds_does_not_wait_for_the_forwarders_retry() {
        let mut rig = Rig::spawn(S1, true, false);
        rig.the_next_ensure(Ensure::FindsAnImageWithoutTheDnsMode);
        rig.send(Control::Enable).await;
        rig.next_forward().await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        let changed = Instant::now();
        rig.manage(&["acme"]);
        let at_once = rig.next_forward().await;
        let retry = rig.next_forward().await;

        assert_eq!(at_once.at - changed, Duration::ZERO);
        assert_eq!(at_once.tlds, tlds(&["acme"]));
        assert_eq!(retry.at - at_once.at, FORWARDER_RETRY);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wake_for_another_reason_does_not_put_off_the_forwarders_retry() {
        let mut rig = Rig::spawn(S1, true, false);
        rig.the_next_ensure(Ensure::Fails);
        rig.send(Control::Enable).await;
        let first = rig.next_forward().await;
        tokio::time::sleep(Duration::from_secs(40)).await;

        rig.engine_session(S2);
        let retry = rig.next_forward().await;

        assert_eq!(retry.at - first.at, FORWARDER_RETRY);
        assert_eq!(retry.phase, BridgePhase::Up { epoch: 1 });
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_and_a_lost_session_end_the_forwarders_retries() {
        for ends_it in ["a disable", "a lost session"] {
            let mut rig = Rig::spawn(S1, true, false);
            rig.the_next_ensure(Ensure::Fails);
            rig.send(Control::Enable).await;
            rig.next_forward().await;

            match ends_it {
                "a disable" => {
                    rig.send(Control::Disable).await;
                    assert_eq!(rig.next_stop().await, Stop::RemovesNetwork);
                }
                _ => rig.engine_session(None),
            }

            rig.no_forward_follows().await;
            assert_eq!(rig.bridges_held(), 0, "{ends_it}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn each_new_bridge_gets_the_forwarder_and_a_kept_bridge_is_not_asked_again() {
        let mut rig = Rig::up().await;
        assert_eq!(rig.next_forward().await.phase, BridgePhase::Up { epoch: 1 });

        rig.engine_session(S2);
        rig.no_forward_follows().await;
        assert_eq!(rig.phase(), BridgePhase::Up { epoch: 1 });

        rig.send(Control::SetMode(DockerMode)).await;
        assert_eq!(rig.next_stop().await, Stop::KeepsNetwork);
        assert_eq!(rig.next_forward().await.phase, BridgePhase::Up { epoch: 2 });
        rig.no_forward_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_of_the_managed_tlds_ends_the_wait_when_nothing_else_is_ready() {
        let (_tx, mut rx) = mpsc::channel(1);
        let (mut engine, _sessions) = bare_engine();
        let tlds_changed = Notify::new();
        tlds_changed.notify_one();

        let wait = next_wake(&mut rx, &mut engine, &tlds_changed, None);
        let wake = tokio::time::timeout(LONGEST_WAIT, wait)
            .await
            .expect("the change ends the wait");

        assert!(matches!(wake, Wake::TldsChanged));
    }

    const SETUP_CONTAINER: &str = "/containers/portman-netbridge-setup/json";
    const OWN_SETUP_CONTAINER: &str = r#"{
        "Config": {"Labels": {"dev.portman.managed": "1", "dev.portman.role": "netbridge-setup"}},
        "State": {"Running": true}
    }"#;
    const NETWORK: &str = "/networks/portman";
    const OWN_NETWORK: &str = r#"{"Labels": {"dev.portman.managed": "1"}}"#;
    const FORWARDER: &str = "/containers/portman-netbridge-dns/json";
    const OWN_FORWARDER: &str = r#"{
        "Id": "dddd2222",
        "Config": {"Labels": {"dev.portman.managed": "1", "dev.portman.role": "dns-forwarder"}},
        "State": {"Running": true}
    }"#;
    const FORWARDER_BY_ID: &str = "/containers/dddd2222";

    /// A listen port that nobody holds: a bind to port 0 gets a port that
    /// the system picks. A port that a test binds and frees is not safe,
    /// because the system can hand it to another socket at once.
    const FREE_PORT: u16 = 0;

    /// The engine as the daemon reaches it, with a bridge's leftovers in
    /// it.
    fn engine_with_leftovers(
        listen_port: u16,
    ) -> (LinkedEngine, Arc<crate::engine::tests::FakeEngine>) {
        let (engine, fake) = empty_engine(listen_port);
        fake.hold(SETUP_CONTAINER, OWN_SETUP_CONTAINER);
        fake.hold(NETWORK, OWN_NETWORK);
        fake.hold(FORWARDER, OWN_FORWARDER);
        fake.hold(&format!("{FORWARDER_BY_ID}/json"), OWN_FORWARDER);
        (engine, fake)
    }

    fn empty_engine(listen_port: u16) -> (LinkedEngine, Arc<crate::engine::tests::FakeEngine>) {
        let (engine, fake) = crate::engine::tests::connected();
        let engine = LinkedEngine {
            link: engine.watch(),
            listen_port,
        };
        (engine, fake)
    }

    /// What this thread logs at info and above while a [`Capture`] lives.
    #[derive(Clone, Default)]
    struct Logged(Arc<Mutex<Vec<u8>>>);

    /// While one subscriber exists, tracing takes a callsite's interest
    /// from the thread that reaches it first, and that can be a test that
    /// has no subscriber. With a second subscriber it asks each of them.
    struct Capture {
        _on_this_thread: tracing::subscriber::DefaultGuard,
        _second_subscriber: tracing::Dispatch,
    }

    impl std::io::Write for Logged {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Logged {
        fn capture() -> (Self, Capture) {
            let logged = Self::default();
            let writer = logged.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            let capture = Capture {
                _on_this_thread: tracing::subscriber::set_default(subscriber),
                _second_subscriber: tracing::Dispatch::new(tracing::subscriber::NoSubscriber::new()),
            };
            (logged, capture)
        }

        /// Takes the lines that were logged since the last call.
        fn lines(&self) -> Vec<String> {
            let bytes = std::mem::take(&mut *self.0.lock().unwrap());
            let text = String::from_utf8(bytes).unwrap();
            text.lines().map(String::from).collect()
        }

        /// Takes the lines since the last call and returns the warnings.
        fn take_warnings(&self) -> Vec<String> {
            let mut lines = self.lines();
            lines.retain(|line| line.contains("WARN"));
            lines
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_cleanup_logs_each_removal_once_and_nothing_when_nothing_is_left() {
        let (engine, _fake) = engine_with_leftovers(FREE_PORT);
        let (logged, _capture) = Logged::capture();

        engine
            .remove_leftovers(Session(1), SetupContainerAndNetwork)
            .await;

        let lines = logged.lines();
        let removals = [
            "portman-netbridge-setup",
            "portman-netbridge-dns",
            "network",
        ];
        assert_eq!(lines.len(), removals.len(), "{lines:?}");
        for (line, removed) in lines.iter().zip(removals) {
            assert!(line.contains("INFO"), "{line}");
            assert!(line.contains("removed"), "{line}");
            assert!(line.contains(removed), "{line}");
        }

        engine
            .remove_leftovers(Session(1), SetupContainerAndNetwork)
            .await;

        assert_eq!(logged.lines(), [] as [&str; 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_cleanup_that_is_skipped_logs_the_reason_once() {
        let another_daemons_bridge = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let taken = another_daemons_bridge.local_addr().unwrap().port();
        let (on_a_taken_port, _fake) = engine_with_leftovers(taken);
        let (on_a_free_port, _fake) = engine_with_leftovers(FREE_PORT);
        let (logged, _capture) = Logged::capture();

        on_a_taken_port
            .remove_leftovers(Session(1), SetupContainerAndNetwork)
            .await;
        let lines = logged.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("the listen port is taken"), "{lines:?}");

        on_a_free_port
            .remove_leftovers(Session(2), SetupContainerAndNetwork)
            .await;
        let lines = logged.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("session"), "{lines:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_daemons_engine_is_on_the_port_that_every_portman_bridge_listens_on() {
        let (engine, _fake) = crate::engine::tests::connected();

        let engine = LinkedEngine::new(engine.watch());

        assert_eq!(engine.listen_port, HOST_WG_LISTEN_PORT);
    }

    #[tokio::test(start_paused = true)]
    async fn the_engine_runs_a_container_only_when_an_inspect_by_its_id_says_so() {
        let (engine, fake) = engine_with_leftovers(FREE_PORT);
        let id = "aaaaaaaaaaaa1111";
        let inspect = format!("/containers/{id}/json");

        assert!(!engine.runs_container(Session(1), id).await, "no such id");

        fake.hold(&inspect, r#"{"State": {"Running": false}}"#);
        assert!(!engine.runs_container(Session(1), id).await, "stopped");

        for silent in ["{}", r#"{"State": {}}"#] {
            fake.hold(&inspect, silent);
            assert!(!engine.runs_container(Session(1), id).await, "{silent}");
        }

        fake.hold(&inspect, r#"{"State": {"Running": true}}"#);
        assert!(engine.runs_container(Session(1), id).await);
        assert!(
            !engine.runs_container(Session(2), id).await,
            "asked on a session that is not the open one"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_removal_that_was_planned_on_another_session_asks_the_engine_nothing() {
        let (engine, fake) = engine_with_leftovers(FREE_PORT);

        let cleanup = engine
            .remove_leftovers(Session(2), SetupContainerAndNetwork)
            .await;

        assert_eq!(fake.calls(), [] as [&str; 0]);
        assert_eq!(cleanup, Swept::SessionEnded);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_removed_from_the_engine_while_another_daemon_holds_the_listen_port() {
        let another_daemons_bridge = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let taken = another_daemons_bridge.local_addr().unwrap().port();
        let (engine, fake) = engine_with_leftovers(taken);

        let cleanup = engine
            .remove_leftovers(Session(1), SetupContainerAndNetwork)
            .await;

        assert_eq!(fake.calls(), [] as [&str; 0]);
        assert_eq!(cleanup, Swept::PortTaken);
    }

    #[tokio::test(start_paused = true)]
    async fn a_start_asks_the_engine_nothing_until_it_holds_the_listen_port() {
        let another_daemons_bridge = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let taken = another_daemons_bridge.local_addr().unwrap().port();
        let (engine, fake) = engine_with_leftovers(taken);

        let started = engine
            .start_bridge(Session(1), NetbridgeMode::All, &Keypair::generate())
            .await;

        assert!(started.is_err(), "a bridge started on a port that is taken");
        assert_eq!(fake.calls(), [] as [&str; 0]);
        assert_eq!(
            fake.lists(),
            [],
            "listed containers before it held the port"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_start_logs_the_error_of_the_operating_system() {
        let another_daemons_bridge = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let taken = another_daemons_bridge.local_addr().unwrap().port();
        let (engine, _fake) = engine_with_leftovers(taken);
        let (logged, _capture) = Logged::capture();

        let started = try_start(&engine, Session(1), OptIn, &mut Attempts::new()).await;

        assert!(
            started.is_none(),
            "a bridge started on a port that is taken"
        );
        let lines = logged.lines();
        let warnings: Vec<&String> = lines.iter().filter(|l| l.contains("WARN")).collect();
        assert_eq!(warnings.len(), 1, "{lines:?}");
        let cause = format!("err=binding 0.0.0.0:{taken}: Address already in use");
        assert!(warnings[0].contains(&cause), "{}", warnings[0]);
    }

    fn says_no_answer_within(budget: Duration) -> String {
        let secs = budget.as_secs();
        format!("the container engine gave no answer within {secs} s")
    }

    #[tokio::test(start_paused = true)]
    async fn a_cleanup_on_an_engine_that_froze_ends_owed_when_its_budget_is_spent_and_says_so() {
        for frozen_at in [SETUP_CONTAINER, FORWARDER, NETWORK] {
            let (engine, fake) = engine_with_leftovers(FREE_PORT);
            fake.hang(frozen_at);
            let (logged, _capture) = Logged::capture();

            let asked = Instant::now();
            let cleanup = engine.remove_leftovers(Session(1), SetupContainerAndNetwork);
            let cleanup = tokio::time::timeout(LONGEST_WAIT, cleanup)
                .await
                .unwrap_or_else(|_| panic!("the cleanup waited for the engine at {frozen_at}"));

            assert_eq!(cleanup, Swept::Ended(CleanupEnd::NoAnswer), "{frozen_at}");
            assert_eq!(asked.elapsed(), ENGINE_STEP_BUDGET, "{frozen_at}");
            let warnings = logged.take_warnings();
            assert_eq!(warnings.len(), 1, "{frozen_at} {warnings:?}");
            let no_answer = says_no_answer_within(ENGINE_STEP_BUDGET);
            assert!(warnings[0].contains(&no_answer), "{}", warnings[0]);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_start_on_an_engine_that_froze_fails_when_its_budget_is_spent_and_says_so() {
        let (engine, fake) = engine_with_leftovers(FREE_PORT);
        fake.hang(NETWORK);
        let (logged, _capture) = Logged::capture();

        let asked = Instant::now();
        let mut attempts = Attempts::new();
        let start = try_start(&engine, Session(1), OptIn, &mut attempts);
        let started = tokio::time::timeout(LONGEST_WAIT, start)
            .await
            .expect("the start waited for the engine");

        assert!(started.is_none(), "a bridge started on a frozen engine");
        assert_eq!(asked.elapsed(), ENGINE_START_BUDGET);
        let warnings = logged.take_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let cause = format!("err={}", says_no_answer_within(ENGINE_START_BUDGET));
        assert!(warnings[0].contains(&cause), "{}", warnings[0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_start_that_uses_up_every_wait_inside_it_fails_for_its_own_reason() {
        let (engine, fake) = engine_with_leftovers(FREE_PORT);
        fake.hold_what_it_creates(SETUP_CONTAINER, OWN_SETUP_CONTAINER);
        fake.hold("/containers/portman-netbridge-setup/logs", "");
        fake.be_slow(crate::engine::tests::Slow {
            stop: Duration::from_millis(4_900),
            removal: Duration::from_millis(9_900),
        });
        let (logged, _capture) = Logged::capture();

        let asked = Instant::now();
        let started = try_start(&engine, Session(1), OptIn, &mut Attempts::new()).await;

        assert!(
            started.is_none(),
            "a bridge started with no key from the VM"
        );
        let warnings = logged.take_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let cause = "err=netbridge setup container did not report VM_PUBKEY";
        assert!(warnings[0].contains(cause), "{}", warnings[0]);
        let waited = asked.elapsed();
        assert!(waited > Duration::from_secs(39), "{waited:?}");
        let removals = fake
            .calls()
            .into_iter()
            .filter(|call| call == "DELETE /containers/portman-netbridge-setup");
        assert_eq!(removals.count(), 2, "the old setup container and its own");
    }

    #[tokio::test(start_paused = true)]
    async fn with_the_listen_port_free_the_forwarder_and_the_network_go_only_when_asked_for() {
        let container = "/containers/portman-netbridge-setup";
        let cases = [
            (SetupContainer, vec![container]),
            (
                SetupContainerAndNetwork,
                vec![container, FORWARDER_BY_ID, NETWORK],
            ),
        ];
        for (leftovers, gone) in cases {
            let (engine, fake) = engine_with_leftovers(FREE_PORT);

            let cleanup = engine.remove_leftovers(Session(1), leftovers).await;

            assert_eq!(cleanup, Swept::Ended(CleanupEnd::Complete), "{leftovers:?}");
            let calls = fake.calls();
            let removed: Vec<_> = calls
                .iter()
                .filter_map(|call| call.strip_prefix("DELETE "))
                .collect();
            assert_eq!(removed, gone, "{leftovers:?}");
            for kept_by_a_sweep in [NETWORK, FORWARDER] {
                assert_eq!(
                    calls.iter().any(|call| call.ends_with(kept_by_a_sweep)),
                    leftovers == SetupContainerAndNetwork,
                    "{calls:?}"
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_container_that_has_the_forwarders_name_and_not_its_labels_is_never_removed() {
        let setup_role = OWN_FORWARDER.replace("dns-forwarder", "netbridge-setup");
        let unmanaged = OWN_FORWARDER.replace(r#""dev.portman.managed": "1", "#, "");
        for not_the_forwarder in [
            setup_role.as_str(),
            unmanaged.as_str(),
            r#"{"Id": "dddd2222"}"#,
        ] {
            let (engine, fake) = engine_with_leftovers(FREE_PORT);
            fake.hold(FORWARDER, not_the_forwarder);

            engine
                .remove_leftovers(Session(1), SetupContainerAndNetwork)
                .await;

            let calls = fake.calls();
            assert!(
                !calls.contains(&format!("DELETE {FORWARDER_BY_ID}")),
                "{not_the_forwarder}\n{calls:?}"
            );
            assert!(calls.contains(&format!("DELETE {NETWORK}")), "{calls:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_cleanup_owes_only_what_can_still_be_portmans_in_the_engine() {
        let anothers_container = r#"{"Config": {"Labels": {}}, "State": {"Running": false}}"#;
        let anothers_network = r#"{"Labels": {}}"#;
        let unreadable = "not an answer to an inspect";
        let (both, container_only) = (SetupContainerAndNetwork, SetupContainer);
        let own_container = Some(OWN_SETUP_CONTAINER);
        // (setup container, network, asked for) → how the cleanup ends
        let cases = [
            (None, None, both, CleanupEnd::Complete),
            (
                own_container,
                Some(anothers_network),
                both,
                CleanupEnd::Complete,
            ),
            (
                own_container,
                Some(unreadable),
                container_only,
                CleanupEnd::Complete,
            ),
            (own_container, Some(unreadable), both, CleanupEnd::Failed),
            (
                Some(anothers_container),
                Some(OWN_NETWORK),
                both,
                CleanupEnd::Complete,
            ),
        ];
        for (container, network, leftovers, want) in cases {
            let (engine, fake) = empty_engine(FREE_PORT);
            if let Some(container) = container {
                fake.hold(SETUP_CONTAINER, container);
            }
            if let Some(network) = network {
                fake.hold(NETWORK, network);
            }

            let cleanup = engine.remove_leftovers(Session(1), leftovers).await;

            assert_eq!(
                cleanup,
                Swept::Ended(want),
                "{container:?} {network:?} {leftovers:?}"
            );
            let calls = fake.calls();
            let removed = |path: &str| calls.contains(&format!("DELETE {path}"));
            assert_eq!(
                removed("/containers/portman-netbridge-setup"),
                container == own_container,
                "{calls:?}"
            );
            assert_eq!(removed(NETWORK), network == Some(OWN_NETWORK), "{calls:?}");
        }
    }

    /// How the engine answers the removal of a network that a running
    /// container is attached to.
    const IN_USE: (&str, &str) = (
        "403 Forbidden",
        r#"error while removing network: network portman has active endpoints (name:"demo-web-1" id:"aaaaaaaaaaaa")"#,
    );
    const ENGINE_FAILED: (&str, &str) =
        ("500 Internal Server Error", "the engine is shutting down");

    #[tokio::test(start_paused = true)]
    async fn a_removal_that_failed_stays_owed_and_a_network_in_use_does_not() {
        let container = "/containers/portman-netbridge-setup";
        let connection_cut = None;
        // the removals that fail, and how → how the cleanup ends
        let cases = [
            (vec![(NETWORK, Some(IN_USE))], CleanupEnd::Complete),
            (vec![(NETWORK, Some(ENGINE_FAILED))], CleanupEnd::Failed),
            (vec![(NETWORK, connection_cut)], CleanupEnd::Failed),
            (vec![(container, Some(ENGINE_FAILED))], CleanupEnd::Failed),
            (
                vec![(container, Some(ENGINE_FAILED)), (NETWORK, Some(IN_USE))],
                CleanupEnd::Complete,
            ),
        ];
        for (failures, want) in cases {
            let (engine, fake) = engine_with_leftovers(FREE_PORT);
            for (path, answer) in &failures {
                fake.fail_delete(path, *answer);
            }

            let cleanup = engine
                .remove_leftovers(Session(1), SetupContainerAndNetwork)
                .await;

            assert_eq!(cleanup, Swept::Ended(want), "{failures:?}");
        }
    }

    /// The control loop on the daemon's engine, with the bridge off.
    struct OnFakeEngine {
        handle: Handle,
        engine: Engine,
        fake: Arc<crate::engine::tests::FakeEngine>,
        sessions: watch::Sender<Link>,
        state_path: PathBuf,
        _dir: TempDir,
    }

    impl OnFakeEngine {
        /// Starts the loop on an engine that answers an inspect of each
        /// path in `held`, and returns after the cleanup of the first
        /// session.
        async fn start(held: &[(&str, &str)]) -> Self {
            Self::start_on(FREE_PORT, held).await
        }

        /// As [`OnFakeEngine::start`], with the bridges of this daemon on
        /// UDP port `listen_port`.
        async fn start_on(listen_port: u16, held: &[(&str, &str)]) -> Self {
            let (engine, sessions) = crate::engine::channel();
            let fake = crate::engine::tests::connect(&sessions);
            for (path, json) in held {
                fake.hold(path, json);
            }
            let linked = LinkedEngine {
                link: engine.watch(),
                listen_port,
            };
            let (handle, rx, phase_tx) = handle_pair();
            let dir = tempdir().unwrap();
            let state_path = dir.path().join("netbridge.json");
            tokio::spawn(converge(
                linked,
                handle.clone(),
                rx,
                phase_tx,
                state_path.clone(),
                false,
                KnownTlds::default(),
            ));
            tokio::time::sleep(LONGEST_WAIT).await;
            Self {
                handle,
                engine,
                fake,
                sessions,
                state_path,
                _dir: dir,
            }
        }

        /// Returns when the loop has nothing left to do for the message.
        async fn disable(&self) {
            self.handle.tx.send(Control::Disable).await.unwrap();
            tokio::time::sleep(LONGEST_WAIT).await;
        }

        /// Opens another session on the same engine, and returns when the
        /// loop has nothing left to do for it.
        async fn open_session(&self, session: u64) {
            self.sessions.send_replace(Link::Connected {
                session: Session(session),
                docker: self.engine.docker().unwrap(),
                socket: "/run/demo/docker.sock".into(),
                version: None,
            });
            tokio::time::sleep(LONGEST_WAIT).await;
        }

        /// The requests about the docker network, in order.
        fn network_calls(&self) -> Vec<String> {
            let mut calls = self.fake.calls();
            calls.retain(|call| call.ends_with(NETWORK));
            calls
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_on_an_engine_that_froze_waits_one_step_budget_and_asks_no_second_time() {
        let daemon = OnFakeEngine::start(&[(NETWORK, OWN_NETWORK)]).await;
        daemon.fake.hang(NETWORK);
        let (logged, _capture) = Logged::capture();

        let disabled = Instant::now();
        daemon.handle.tx.send(Control::Disable).await.unwrap();
        let poll = Duration::from_millis(100);
        let mut warnings = logged.take_warnings();
        while warnings.is_empty() && disabled.elapsed() < LONGEST_WAIT {
            tokio::time::sleep(poll).await;
            warnings = logged.take_warnings();
        }

        let waited = disabled.elapsed();
        assert!(
            waited >= ENGINE_STEP_BUDGET && waited <= ENGINE_STEP_BUDGET + poll,
            "{waited:?}"
        );
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let no_answer = says_no_answer_within(ENGINE_STEP_BUDGET);
        assert!(warnings[0].contains(&no_answer), "{}", warnings[0]);

        let asked = daemon.fake.calls();
        tokio::time::sleep(LONGEST_WAIT).await;

        assert_eq!(logged.take_warnings(), [] as [&str; 0]);
        assert_eq!(
            daemon.fake.calls(),
            asked,
            "a second cleanup on the session"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_network_in_use_stays_and_only_the_next_disable_asks_for_it_again() {
        let daemon = OnFakeEngine::start(&[(NETWORK, OWN_NETWORK)]).await;
        daemon.fake.fail_delete(NETWORK, Some(IN_USE));
        let refused = [format!("GET {NETWORK}"), format!("DELETE {NETWORK}")];
        let (logged, _capture) = Logged::capture();

        daemon.disable().await;

        assert_eq!(daemon.network_calls(), refused);
        let lines = logged.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("WARN"), "{lines:?}");
        assert!(lines[0].contains("has active endpoints"), "{lines:?}");

        daemon.open_session(2).await;

        assert_eq!(
            daemon.network_calls(),
            refused,
            "asked again on a session where the user's containers can have stopped"
        );
        assert_eq!(logged.lines(), [] as [&str; 0]);

        daemon.disable().await;

        assert_eq!(daemon.network_calls(), [refused.clone(), refused].concat());
    }

    #[tokio::test(start_paused = true)]
    async fn a_setup_container_that_is_not_portmans_does_not_keep_the_network_owed() {
        let anothers_container = r#"{"Config": {"Labels": {}}, "State": {"Running": false}}"#;
        let held = [
            (SETUP_CONTAINER, anothers_container),
            (NETWORK, OWN_NETWORK),
        ];
        let daemon = OnFakeEngine::start(&held).await;
        let removed = [format!("GET {NETWORK}"), format!("DELETE {NETWORK}")];

        daemon.disable().await;

        assert_eq!(daemon.network_calls(), removed);

        daemon.open_session(2).await;

        assert_eq!(daemon.network_calls(), removed, "the network stayed owed");
        let calls = daemon.fake.calls();
        assert!(
            !calls
                .iter()
                .any(|call| call.starts_with("DELETE /containers")),
            "{calls:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_forwarder_that_was_not_removed_keeps_a_cleanup_owed_unless_the_network_is_in_use() {
        let anothers_container = r#"{"Id": "dddd2222", "Config": {"Labels": {}}}"#;
        let unreadable = "not an answer to an inspect";
        let both = SetupContainerAndNetwork;
        let network_in_use = Some((NETWORK, IN_USE));
        let forwarder_stays = Some((FORWARDER_BY_ID, ENGINE_FAILED));
        let (complete, failed) = (CleanupEnd::Complete, CleanupEnd::Failed);
        // (forwarder, the removal that fails, asked for)
        //     → (how the cleanup ends, the engine was asked to remove the forwarder)
        let cases = [
            (OWN_FORWARDER, None, both, complete, true),
            (OWN_FORWARDER, network_in_use, both, complete, true),
            (OWN_FORWARDER, forwarder_stays, both, failed, true),
            (unreadable, None, both, failed, false),
            (unreadable, network_in_use, both, complete, false),
            (anothers_container, None, both, complete, false),
            (unreadable, None, SetupContainer, complete, false),
        ];
        for (forwarder, fails, leftovers, want, asked) in cases {
            let case = format!("{forwarder} {fails:?} {leftovers:?}");
            let (engine, fake) = engine_with_leftovers(FREE_PORT);
            fake.hold(FORWARDER, forwarder);
            if let Some((path, answer)) = fails {
                fake.fail_delete(path, Some(answer));
            }

            let cleanup = engine.remove_leftovers(Session(1), leftovers).await;

            assert_eq!(cleanup, Swept::Ended(want), "{case}");
            let calls = fake.calls();
            let removal_of = |path: &str| {
                calls
                    .iter()
                    .position(|call| call == &format!("DELETE {path}"))
            };
            assert_eq!(removal_of(FORWARDER_BY_ID).is_some(), asked, "{case}");
            if let (Some(forwarder), Some(network)) =
                (removal_of(FORWARDER_BY_ID), removal_of(NETWORK))
            {
                assert!(forwarder < network, "{case}\n{calls:?}");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_with_no_session_removes_the_forwarder_and_then_the_network_when_one_opens() {
        let (engine, publisher) = crate::engine::channel();
        let engine = LinkedEngine {
            link: engine.watch(),
            listen_port: FREE_PORT,
        };
        let (handle, rx, phase_tx) = handle_pair();
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("netbridge.json");
        let tlds = KnownTlds::default();
        tokio::spawn(converge(
            engine,
            handle.clone(),
            rx,
            phase_tx,
            state_path,
            false,
            tlds,
        ));
        handle.tx.send(Control::Disable).await.unwrap();
        tokio::time::sleep(LONGEST_WAIT).await;

        let fake = crate::engine::tests::connect(&publisher);
        fake.hold(SETUP_CONTAINER, OWN_SETUP_CONTAINER);
        fake.hold(NETWORK, OWN_NETWORK);
        fake.hold(FORWARDER, OWN_FORWARDER);
        tokio::time::sleep(LONGEST_WAIT).await;

        let calls = fake.calls();
        let removed: Vec<_> = calls
            .iter()
            .filter_map(|call| call.strip_prefix("DELETE "))
            .collect();
        assert_eq!(
            removed,
            [
                "/containers/portman-netbridge-setup",
                FORWARDER_BY_ID,
                NETWORK
            ],
            "{calls:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn with_the_bridge_off_a_boot_and_a_new_session_remove_the_setup_container_only() {
        let mut rig = Rig::spawn(S1, true, false);

        assert_eq!(rig.next_sweep().await, (Session(1), SetupContainer));
        rig.no_sweep_follows().await;

        rig.engine_session(None);
        rig.no_sweep_follows().await;

        rig.engine_session(S2);
        assert_eq!(rig.next_sweep().await, (Session(2), SetupContainer));
        rig.no_sweep_follows().await;
        assert_eq!(rig.phase(), BridgePhase::Disabled);
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_with_no_bridge_running_removes_the_network() {
        let mut rig = Rig::start();
        assert_eq!(rig.next_sweep().await, (Session(1), SetupContainer));
        rig.send(Control::SetMode(DockerMode)).await;
        rig.no_sweep_follows().await;

        rig.send(Control::Disable).await;

        assert_eq!(
            rig.next_sweep().await,
            (Session(1), SetupContainerAndNetwork)
        );
        rig.no_sweep_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_with_no_session_removes_the_network_when_a_session_opens() {
        let mut rig = Rig::spawn(None, false, false);
        rig.send(Control::Disable).await;
        rig.no_sweep_follows().await;

        rig.engine_session(S1);

        assert_eq!(
            rig.next_sweep().await,
            (Session(1), SetupContainerAndNetwork)
        );
        rig.no_sweep_follows().await;

        rig.engine_session(S2);
        assert_eq!(rig.next_sweep().await, (Session(2), SetupContainer));
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_that_lands_with_a_session_change_removes_the_network() {
        let mut rig = Rig::start();
        assert_eq!(rig.next_sweep().await, (Session(1), SetupContainer));

        rig.send(Control::Disable).await;
        rig.engine_session(S2);

        assert_eq!(
            rig.next_sweep().await,
            (Session(2), SetupContainerAndNetwork)
        );
        rig.no_sweep_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_cleanup_that_did_not_finish_is_tried_again_at_the_next_session() {
        let mut rig = Rig::start();
        assert_eq!(rig.next_sweep().await, (Session(1), SetupContainer));
        let network_owed = |session| (Session(session), SetupContainerAndNetwork);

        rig.cleanups_end(CleanupEnd::Failed);
        rig.send(Control::Disable).await;
        assert_eq!(rig.next_sweep().await, network_owed(1));
        rig.no_sweep_follows().await;

        rig.engine_session(S2);
        assert_eq!(rig.next_sweep().await, network_owed(2));
        rig.no_sweep_follows().await;

        rig.cleanups_end(CleanupEnd::Complete);
        rig.engine_session(Some(Session(3)));
        assert_eq!(rig.next_sweep().await, network_owed(3));
        rig.no_sweep_follows().await;

        rig.engine_session(Some(Session(4)));
        assert_eq!(rig.next_sweep().await, (Session(4), SetupContainer));
    }

    #[tokio::test(start_paused = true)]
    async fn a_wanted_bridge_is_not_swept_while_its_start_fails() {
        let mut rig = Rig::start();
        rig.send(Control::Enable).await;
        rig.next_attempt().await;
        rig.next_attempt().await;

        rig.no_sweep_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_after_a_failed_start_sweeps_the_session_again() {
        let mut rig = Rig::start();
        assert_eq!(rig.next_sweep().await, (Session(1), SetupContainer));
        rig.send(Control::Enable).await;
        rig.next_attempt().await;

        rig.send(Control::Disable).await;

        assert_eq!(
            rig.next_sweep().await,
            (Session(1), SetupContainerAndNetwork)
        );
        rig.no_sweep_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_during_a_mode_change_sweeps_the_network_that_the_stop_kept() {
        let mut rig = Rig::up().await;
        rig.hold_stops();
        rig.send(Control::SetMode(DockerMode)).await;
        assert_eq!(rig.next_stop().await, Stop::KeepsNetwork);

        rig.send(Control::Disable).await;
        rig.end_stops();

        assert_eq!(
            rig.next_sweep().await,
            (Session(1), SetupContainerAndNetwork)
        );
        assert_eq!(rig.phase(), BridgePhase::Disabled);
        rig.no_attempt_follows().await;
    }

    /// What `netbridge.json` says about a cleanup that a disable left owed.
    fn saved_debt(state_path: &Path) -> serde_json::Value {
        let saved = std::fs::read(state_path).unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&saved).unwrap();
        saved["cleanup_owed"].clone()
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_that_found_no_session_is_paid_after_a_daemon_restart() {
        let mut rig = Rig::spawn(None, false, false);
        rig.send(Control::Disable).await;
        rig.no_sweep_follows().await;
        assert_eq!(saved_debt(&rig.state_path), true);

        let mut rig = rig.restart(None).await;
        rig.no_sweep_follows().await;
        rig.engine_session(S1);

        assert_eq!(
            rig.next_sweep().await,
            (Session(1), SetupContainerAndNetwork)
        );
        rig.no_sweep_follows().await;
        assert_eq!(saved_debt(&rig.state_path), false);

        let mut rig = rig.restart(S1).await;
        assert_eq!(rig.next_sweep().await, (Session(1), SetupContainer));
        rig.no_sweep_follows().await;
    }

    #[tokio::test(start_paused = true)]
    async fn an_enable_ends_the_debt_and_the_next_disable_owes_anew() {
        let mut rig = Rig::spawn(None, false, false);
        rig.send(Control::Disable).await;
        rig.no_sweep_follows().await;
        assert_eq!(saved_debt(&rig.state_path), true);

        rig.send(Control::Enable).await;
        rig.reaches(BridgePhase::WaitingForDocker).await;
        assert_eq!(saved_debt(&rig.state_path), false);

        let mut rig = rig.restart(None).await;
        rig.send(Control::Disable).await;
        rig.no_sweep_follows().await;
        assert_eq!(saved_debt(&rig.state_path), true);
    }

    #[tokio::test(start_paused = true)]
    async fn a_boot_owes_the_network_only_when_the_saved_state_says_so() {
        // what `netbridge.json` holds at boot → what the first session is swept of
        let table = [
            (None, SetupContainer),
            (Some(r#"{"enabled":false}"#), SetupContainer),
            (
                Some(r#"{"enabled":false,"cleanup_owed":false}"#),
                SetupContainer,
            ),
            (
                Some(r#"{"enabled":false,"cleanup_owed":true}"#),
                SetupContainerAndNetwork,
            ),
        ];
        for (saved, swept) in table {
            let mut rig = Rig::boot_on(saved);

            assert_eq!(rig.next_sweep().await, (Session(1), swept), "{saved:?}");
            rig.no_sweep_follows().await;
            rig.daemon.abort();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_debt_is_saved_until_a_cleanup_ends_it() {
        #[derive(Debug)]
        enum Engine {
            RemovesTheNetwork,
            RefusesANetworkInUse,
            FailsTheRemoval,
            GivesNoAnswer,
        }
        // how the engine takes the removal of the network → the debt that is saved
        let table = [
            (Engine::RemovesTheNetwork, false),
            (Engine::RefusesANetworkInUse, false),
            (Engine::FailsTheRemoval, true),
            (Engine::GivesNoAnswer, true),
        ];
        for (engine, owed) in table {
            let daemon = OnFakeEngine::start(&[(NETWORK, OWN_NETWORK)]).await;
            match engine {
                Engine::RemovesTheNetwork => {}
                Engine::RefusesANetworkInUse => daemon.fake.fail_delete(NETWORK, Some(IN_USE)),
                Engine::FailsTheRemoval => daemon.fake.fail_delete(NETWORK, Some(ENGINE_FAILED)),
                Engine::GivesNoAnswer => daemon.fake.hang(NETWORK),
            }

            daemon.disable().await;

            assert_eq!(saved_debt(&daemon.state_path), owed, "{engine:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_listen_port_that_is_taken_ends_the_debt_for_that_disable() {
        let another_daemons_bridge = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let taken = another_daemons_bridge.local_addr().unwrap().port();
        let held = [(NETWORK, OWN_NETWORK), (FORWARDER, OWN_FORWARDER)];
        let daemon = OnFakeEngine::start_on(taken, &held).await;
        let (logged, _capture) = Logged::capture();

        daemon.disable().await;

        assert_eq!(daemon.fake.calls(), [] as [&str; 0]);
        let lines = logged.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        let final_for_this_disable = "the listen port is taken, and its holder may run a bridge \
                                      on them. portman does not ask again until the next \
                                      `portman bridge disable`";
        assert!(lines[0].contains(final_for_this_disable), "{lines:?}");
        assert_eq!(saved_debt(&daemon.state_path), false);

        drop(another_daemons_bridge);
        daemon.open_session(2).await;

        let asked = daemon.fake.calls();
        assert_eq!(
            asked,
            [format!("GET {SETUP_CONTAINER}")],
            "asked for more than the setup container when the port was free again"
        );
    }
}
