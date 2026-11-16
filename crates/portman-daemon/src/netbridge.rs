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
//!     left, then waits for a control message or a retry timer. Before each
//!     step it takes the messages that are in the channel. A message that
//!     arrives later waits for the step to end: the loop does not cancel a
//!     step in flight.
//!   - a failed start is retried with a growing delay. The wait does not
//!     hold up control messages.
//!   - [`publish`] tells the rest of the daemon what the bridge is doing:
//!     the [`phase`], the mode, and the interface index of the utun.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use portman_core::netbridge_state::{self, NetbridgeState};
use portman_core::NetbridgeMode;
use portman_netbridge::runtime::{Runtime, RuntimeOptions};
use portman_netbridge::tunnel::Keypair;
use tokio::sync::{mpsc, watch, RwLock};
use tracing::{info, warn};

/// Env var override. Useful for the first-run path where the user's
/// `netbridge.json` doesn't exist yet and they want to flip the bridge
/// on from the LaunchDaemon plist before `portman bridge enable`
/// lands. Presence (non-empty, not "0"/"false") turns the bridge on until
/// the daemon exits or a `Disable` arrives.
const ENABLE_ENV: &str = "PORTMAN_NETBRIDGE";

const RETRY_BASE: Duration = Duration::from_secs(5);
const RETRY_CAP: Duration = Duration::from_secs(60);

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
        },
        rx,
        phase_tx,
    )
}

/// One connection to the container engine. A bridge is built on a session
/// and is stale once that session is gone, because the VM behind a new
/// session may not hold the peer the old bridge talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Session(u64);

/// What a running bridge was built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Built {
    session: Session,
    mode: NetbridgeMode,
    epoch: u64,
}

struct Running<B> {
    bridge: B,
    built: Built,
}

#[derive(Debug, PartialEq, Eq)]
enum Step {
    Keep,
    Start(Session),
    /// Drop the bridge without a Docker call. Its session is gone, so the
    /// engine that would answer is absent or is a different one.
    Abandon,
    /// Stop the bridge and keep the docker network, so that attached
    /// containers keep their addresses while the mode changes.
    Shutdown,
    /// Stop the bridge and remove the docker network. The user asked for
    /// the bridge to be off.
    Teardown,
}

fn plan(
    intent: &NetbridgeState,
    session: Option<Session>,
    running: Option<Built>,
    may_start: bool,
) -> Step {
    match (running, session) {
        (Some(built), session) if session != Some(built.session) => Step::Abandon,
        (Some(_), _) if !intent.enabled => Step::Teardown,
        (Some(built), _) if built.mode != intent.mode => Step::Shutdown,
        (None, Some(session)) if intent.enabled && may_start => Step::Start(session),
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
    retry_after: Option<Duration>,
}

impl Attempts {
    fn new() -> Self {
        Self {
            host_kp: Keypair::generate(),
            failures: 0,
            retry_after: None,
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
                    %err,
                    attempt = self.failures,
                    retry_in_secs = retry_after.as_secs(),
                    "netbridge start failed"
                );
                self.retry_after = Some(retry_after);
                None
            }
        }
    }
}

fn backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(4);
    RETRY_BASE.saturating_mul(1 << doublings).min(RETRY_CAP)
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
    engine: impl BridgeStarter,
    handle: Handle,
    rx: mpsc::Receiver<Control>,
    phase_tx: watch::Sender<BridgePhase>,
    state_path: PathBuf,
) -> Result<()> {
    let forced_on = env_forces_enabled();
    converge(engine, handle, rx, phase_tx, state_path, forced_on).await
}

async fn converge<E: BridgeStarter>(
    engine: E,
    handle: Handle,
    mut rx: mpsc::Receiver<Control>,
    phase_tx: watch::Sender<BridgePhase>,
    state_path: PathBuf,
    forced_on: bool,
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

    // The boot-time Docker handle is the only engine session there is.
    let session = Some(Session(0));
    let mut running: Option<Running<E::Bridge>> = None;
    let mut attempts = Attempts::new();
    let mut epoch = 0;

    loop {
        while let Ok(msg) = rx.try_recv() {
            take(msg, &mut wanted, &mut attempts, &state_path);
        }
        let intent = wanted.intent();
        let built = running.as_ref().map(|r| r.built);
        publish(
            &handle,
            &phase_tx,
            phase(&intent, session, built),
            reported_mode(&intent, built),
            running.as_ref(),
        )
        .await;
        match plan(&intent, session, built, attempts.retry_after.is_none()) {
            Step::Keep => match next_wake(&mut rx, attempts.retry_after).await {
                Wake::Control(msg) => take(msg, &mut wanted, &mut attempts, &state_path),
                Wake::RetryDue => attempts.retry_after = None,
                Wake::Closed => return Ok(()),
            },
            Step::Start(session) => {
                if let Some(bridge) = try_start(&engine, intent.mode, &mut attempts).await {
                    epoch += 1;
                    running = Some(Running {
                        bridge,
                        built: Built {
                            session,
                            mode: intent.mode,
                            epoch,
                        },
                    });
                }
            }
            Step::Abandon => running = None,
            Step::Shutdown => {
                if let Some(old) = running.take() {
                    old.bridge.shutdown().await;
                }
            }
            Step::Teardown => {
                if let Some(old) = running.take() {
                    old.bridge.shutdown_and_remove_network().await;
                }
            }
        }
    }
}

/// A message changes what the user wants, so it also ends the start
/// sequence that served the old intent.
fn take(msg: Control, wanted: &mut Wanted, attempts: &mut Attempts, state_path: &Path) {
    wanted.apply(msg);
    persist(state_path, &wanted.saved);
    *attempts = Attempts::new();
}

enum Wake {
    Control(Control),
    RetryDue,
    Closed,
}

/// A message that is ready goes before a retry that is due, so that no
/// start runs ahead of a `Disable` that is already in the channel.
async fn next_wake(rx: &mut mpsc::Receiver<Control>, retry_after: Option<Duration>) -> Wake {
    tokio::select! {
        biased;
        msg = rx.recv() => msg.map_or(Wake::Closed, Wake::Control),
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
) {
    let up = running.filter(|_| phase.epoch().is_some());
    publish_ifindex(&handle.ifindex, up.map(|r| &r.bridge));
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

/// The control loop starts a bridge only through this, so that a test can
/// run the loop with no container engine.
pub(crate) trait BridgeStarter {
    type Bridge: Bridge;

    async fn start_bridge(&self, mode: NetbridgeMode, host_kp: &Keypair) -> Result<Self::Bridge>;
}

/// A bridge that is up. The control loop holds it only through this, so
/// that a test can hold one without root.
pub(crate) trait Bridge {
    fn utun_name(&self) -> &str;
    /// Stops the bridge and keeps the docker network.
    async fn shutdown(self);
    async fn shutdown_and_remove_network(self);
}

impl BridgeStarter for crate::engine::Engine {
    type Bridge = Runtime;

    async fn start_bridge(&self, mode: NetbridgeMode, host_kp: &Keypair) -> Result<Runtime> {
        Runtime::start_with_keypair(self.docker()?, RuntimeOptions { mode }, host_kp).await
    }
}

impl Bridge for Runtime {
    fn utun_name(&self) -> &str {
        Runtime::utun_name(self)
    }

    async fn shutdown(self) {
        Runtime::shutdown(self).await;
    }

    async fn shutdown_and_remove_network(self) {
        Runtime::shutdown_and_remove_network(self).await;
    }
}

async fn try_start<E: BridgeStarter>(
    engine: &E,
    mode: NetbridgeMode,
    attempts: &mut Attempts,
) -> Option<E::Bridge> {
    let started = engine.start_bridge(mode, &attempts.host_kp).await;
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
    use std::sync::Mutex;
    use tempfile::{tempdir, TempDir};
    use tokio::time::Instant;
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
                plan(&intent(enabled, mode), session, running, may_start),
                want,
                "enabled={enabled} mode={mode:?} session={session:?} running={running:?} may_start={may_start}"
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
                        let kept = plan(&intent, session, running, true) == Step::Keep;
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

    #[test]
    fn a_start_that_succeeds_ends_its_sequence() {
        let failed = || Err::<(), _>(anyhow::anyhow!("no container engine"));
        let mut attempts = Attempts::new();
        let first_key = attempts.host_kp.public_base64();
        attempts.settle(failed());
        attempts.settle(failed());
        assert_eq!(attempts.retry_after, Some(Duration::from_secs(10)));
        assert_eq!(attempts.host_kp.public_base64(), first_key);

        assert_eq!(attempts.settle(Ok(())), Some(()));

        assert_ne!(attempts.host_kp.public_base64(), first_key);
        attempts.settle(failed());
        assert_eq!(attempts.retry_after, Some(RETRY_BASE));
    }

    struct Attempt {
        at: Instant,
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
        phase: watch::Receiver<BridgePhase>,
        phase_at_utun_ask: Arc<Mutex<Vec<BridgePhase>>>,
        stops: mpsc::UnboundedSender<Stop>,
        stops_may_end: watch::Receiver<bool>,
    }

    impl Probe {
        async fn stop(mut self, stop: Stop) {
            let _ = self.stops.send(stop);
            let _ = self.stops_may_end.wait_for(|may_end| *may_end).await;
        }
    }

    /// Awaits nothing but a stop that a test holds open, so that the paused
    /// clock moves only when the control loop waits.
    struct TestEngine {
        state_path: PathBuf,
        seen: mpsc::UnboundedSender<Attempt>,
        /// `None` fails every start, as an engine that is not there does.
        probe: Option<Probe>,
    }

    impl BridgeStarter for TestEngine {
        type Bridge = TestBridge;

        async fn start_bridge(&self, mode: NetbridgeMode, host_kp: &Keypair) -> Result<TestBridge> {
            let _ = self.seen.send(Attempt {
                at: Instant::now(),
                mode,
                host_key: host_kp.public_base64(),
                saved: netbridge_state::load(&self.state_path),
            });
            match &self.probe {
                Some(probe) => Ok(TestBridge(probe.clone())),
                None => anyhow::bail!("no container engine"),
            }
        }
    }

    struct TestBridge(Probe);

    /// The loopback interface stands in for the utun: its name resolves to
    /// an index on every Mac.
    const TEST_UTUN: &str = "lo0";

    impl Bridge for TestBridge {
        fn utun_name(&self) -> &str {
            let published = *self.0.phase.borrow();
            self.0.phase_at_utun_ask.lock().unwrap().push(published);
            TEST_UTUN
        }

        async fn shutdown(self) {
            self.0.stop(Stop::KeepsNetwork).await;
        }

        async fn shutdown_and_remove_network(self) {
            self.0.stop(Stop::RemovesNetwork).await;
        }
    }

    struct Rig {
        handle: Handle,
        state_path: PathBuf,
        attempts: mpsc::UnboundedReceiver<Attempt>,
        stops: mpsc::UnboundedReceiver<Stop>,
        stops_may_end: watch::Sender<bool>,
        phase_at_utun_ask: Arc<Mutex<Vec<BridgePhase>>>,
        _dir: TempDir,
    }

    const LONGEST_WAIT: Duration = Duration::from_secs(3600);

    impl Rig {
        fn start() -> Self {
            Self::spawn(false, false)
        }

        fn start_with_env_override(forced_on: bool) -> Self {
            Self::spawn(false, forced_on)
        }

        /// A rig whose engine starts every bridge, with the first one up.
        async fn up() -> Self {
            let mut rig = Self::spawn(true, false);
            rig.send(Control::Enable).await;
            rig.reaches(BridgePhase::Up { epoch: 1 }).await;
            assert_eq!(rig.next_attempt().await.mode, OptIn);
            rig
        }

        fn spawn(engine_starts_bridges: bool, forced_on: bool) -> Self {
            let dir = tempdir().unwrap();
            let state_path = dir.path().join("netbridge.json");
            let (seen, attempts) = mpsc::unbounded_channel();
            let (stop_seen, stops) = mpsc::unbounded_channel();
            let (stops_may_end, may_end) = watch::channel(true);
            let phase_at_utun_ask = Arc::new(Mutex::new(Vec::new()));
            let (handle, rx, phase_tx) = handle_pair();
            let engine = TestEngine {
                state_path: state_path.clone(),
                seen,
                probe: engine_starts_bridges.then(|| Probe {
                    phase: handle.phase.clone(),
                    phase_at_utun_ask: phase_at_utun_ask.clone(),
                    stops: stop_seen,
                    stops_may_end: may_end,
                }),
            };
            tokio::spawn(converge(
                engine,
                handle.clone(),
                rx,
                phase_tx,
                state_path.clone(),
                forced_on,
            ));
            Rig {
                handle,
                state_path,
                attempts,
                stops,
                stops_may_end,
                phase_at_utun_ask,
                _dir: dir,
            }
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

        async fn no_attempt_follows(&mut self) {
            let next = tokio::time::timeout(LONGEST_WAIT, self.attempts.recv()).await;
            assert!(next.is_err(), "a start attempt after the bridge was off");
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

    #[tokio::test(start_paused = true)]
    async fn a_control_message_goes_before_a_retry_that_is_due() {
        // An unbiased wait picks one of two ready branches at random, so
        // one round would pass half the time.
        for _ in 0..64 {
            let (tx, mut rx) = mpsc::channel(1);
            tx.send(Control::Disable).await.unwrap();
            let wake = next_wake(&mut rx, Some(Duration::ZERO)).await;
            assert!(matches!(wake, Wake::Control(Control::Disable)));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_that_is_due_ends_the_wait_when_no_message_is_ready() {
        let (_tx, mut rx) = mpsc::channel(1);
        let wake = tokio::time::timeout(LONGEST_WAIT, next_wake(&mut rx, Some(Duration::ZERO)))
            .await
            .expect("the retry timer ends the wait");
        assert!(matches!(wake, Wake::RetryDue));
    }
}
