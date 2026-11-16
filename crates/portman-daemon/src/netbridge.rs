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
//!     left, then waits for a control message or a retry timer.
//!   - a failed start is retried with a growing delay. The wait does not
//!     hold up control messages.
//!   - [`phase`] is the one fact the rest of the daemon reads.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bollard::Docker;
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
    /// `epoch` increments for every new `Runtime`. A listener on the tunnel
    /// address belongs to one utun, so a new epoch means rebind.
    Up {
        epoch: u64,
    },
    /// A bridge still runs and the next step removes it. The phase that
    /// follows is published only when that bridge is gone.
    Stopping,
}

impl BridgePhase {
    pub(crate) fn epoch(self) -> Option<u64> {
        match self {
            BridgePhase::Up { epoch } => Some(epoch),
            _ => None,
        }
    }
}

impl From<BridgePhase> for portman_protocol::BridgePhase {
    fn from(phase: BridgePhase) -> Self {
        match phase {
            BridgePhase::Disabled => Self::Disabled,
            BridgePhase::WaitingForDocker => Self::WaitingForDocker,
            BridgePhase::Starting => Self::Starting,
            BridgePhase::Up { .. } => Self::Up,
            BridgePhase::Stopping => Self::Stopping,
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

struct Running {
    runtime: Runtime,
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

/// `Up` only for a bridge that [`plan`] keeps, so that nothing binds to a
/// utun the next step removes. A bridge that `plan` removes is `Stopping`,
/// so that a reader waiting for the bridge to be off or to be up again does
/// not take the removal for done.
fn phase(intent: &NetbridgeState, session: Option<Session>, running: Option<Built>) -> BridgePhase {
    match (running, session) {
        (Some(built), Some(session))
            if intent.enabled && built.session == session && built.mode == intent.mode =>
        {
            BridgePhase::Up { epoch: built.epoch }
        }
        (Some(_), _) => BridgePhase::Stopping,
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

/// One start sequence: a first attempt and its retries. They share one host
/// identity. A retry with a new key would leave a tunnel from the failed
/// attempt peered to a key the VM has forgotten, with the same name as the
/// live tunnel and no traffic through it.
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
}

fn backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(4);
    RETRY_BASE.saturating_mul(1 << doublings).min(RETRY_CAP)
}

/// Long-running task spawned from `main`. Never returns `Ok` —
/// mirrors the shape of the other daemon subsystems so `select!`
/// handles panics uniformly.
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

async fn converge(
    engine: impl BridgeStarter,
    handle: Handle,
    mut rx: mpsc::Receiver<Control>,
    phase_tx: watch::Sender<BridgePhase>,
    state_path: PathBuf,
    mut forced_on: bool,
) -> Result<()> {
    let mut saved = netbridge_state::load(&state_path);
    info!(
        persisted_enabled = saved.enabled,
        mode = saved.mode.as_str(),
        env = forced_on,
        "netbridge subsystem starting"
    );

    // The boot-time Docker handle is the only engine session there is.
    let session = Some(Session(0));
    let mut running: Option<Running> = None;
    let mut attempts = Attempts::new();
    let mut epoch = 0;

    loop {
        let intent = NetbridgeState {
            enabled: saved.enabled || forced_on,
            mode: saved.mode,
        };
        loop {
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
                Step::Keep => break,
                Step::Start(session) => {
                    if let Some(runtime) = try_start(&engine, intent.mode, &mut attempts).await {
                        epoch += 1;
                        running = Some(Running {
                            runtime,
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
                        old.runtime.shutdown().await;
                    }
                }
                Step::Teardown => {
                    if let Some(old) = running.take() {
                        old.runtime.shutdown_and_remove_network().await;
                    }
                }
            }
        }

        tokio::select! {
            msg = rx.recv() => {
                // `None` means every sender is gone, so the daemon is exiting.
                let Some(msg) = msg else { return Ok(()) };
                match msg {
                    Control::Enable => saved.enabled = true,
                    Control::Disable => {
                        saved.enabled = false;
                        forced_on = false;
                    }
                    Control::SetMode(mode) => {
                        if saved.mode != mode {
                            info!(mode = mode.as_str(), "netbridge mode changed");
                        }
                        saved.mode = mode;
                    }
                }
                persist(&state_path, &saved);
                attempts = Attempts::new();
            }
            () = tokio::time::sleep(attempts.retry_after.unwrap_or_default()),
                if attempts.retry_after.is_some() =>
            {
                attempts.retry_after = None;
            }
        }
    }
}

/// The one place that tells the rest of the daemon what the bridge is
/// doing. The ifindex goes first, so that a reader woken by `Up` finds it
/// set. The mode goes last, so that a reader that takes the mode first and
/// the phase second never pairs a new mode with the phase of the bridge
/// built for the old mode.
async fn publish(
    handle: &Handle,
    phase_tx: &watch::Sender<BridgePhase>,
    phase: BridgePhase,
    mode: NetbridgeMode,
    running: Option<&Running>,
) {
    let up = running.filter(|_| phase.epoch().is_some());
    publish_ifindex(&handle.ifindex, up.map(|r| &r.runtime));
    phase_tx.send_replace(phase);
    *handle.mode.write().await = mode;
}

/// Publish the utun's interface index while the bridge is up so upstream
/// connects can scope to it (see [`crate::upstream`]); `None` clears it.
/// Resolution failure downgrades to unscoped connects rather than erroring —
/// the bridge itself is fine, only exit-node immunity is lost.
fn publish_ifindex(slot: &crate::upstream::BridgeIfIndex, runtime: Option<&Runtime>) {
    let resolved = runtime.and_then(|rt| {
        let name = rt.utun_name();
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

/// Builds a bridge. The control loop starts one only through this, so that
/// a test can run the loop with no container engine.
pub(crate) trait BridgeStarter {
    async fn start_bridge(&self, mode: NetbridgeMode, host_kp: &Keypair) -> Result<Runtime>;
}

impl BridgeStarter for Docker {
    async fn start_bridge(&self, mode: NetbridgeMode, host_kp: &Keypair) -> Result<Runtime> {
        Runtime::start_with_keypair(self.clone(), RuntimeOptions { mode }, host_kp).await
    }
}

/// One start attempt. A failure schedules the retry on `attempts`.
async fn try_start(
    engine: &impl BridgeStarter,
    mode: NetbridgeMode,
    attempts: &mut Attempts,
) -> Option<Runtime> {
    match engine.start_bridge(mode, &attempts.host_kp).await {
        Ok(rt) => {
            info!(
                mode = mode.as_str(),
                "netbridge up: docker network `portman`, container pool 192.168.99.130–.253"
            );
            Some(rt)
        }
        Err(err) => {
            attempts.failures += 1;
            let retry_after = backoff(attempts.failures);
            warn!(
                %err,
                attempt = attempts.failures,
                retry_in_secs = retry_after.as_secs(),
                "netbridge start failed"
            );
            attempts.retry_after = Some(retry_after);
            None
        }
    }
}

fn persist(path: &Path, intent: &NetbridgeState) {
    if let Err(err) = netbridge_state::save(path, intent) {
        warn!(%err, "persisting netbridge state");
    }
}

fn env_forces_enabled() -> bool {
    match std::env::var(ENABLE_ENV) {
        Ok(v) => {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        // (enabled, wanted mode, session, running) → phase
        let table = [
            (OFF, OptIn, S1, None, BridgePhase::Disabled),
            (OFF, OptIn, None, None, BridgePhase::Disabled),
            (ON, OptIn, None, None, BridgePhase::WaitingForDocker),
            (ON, OptIn, S1, None, BridgePhase::Starting),
            (ON, OptIn, S1, on_s1, up),
            (ON, DockerMode, S2, built(S2, DockerMode), up),
            (OFF, OptIn, S1, on_s1, BridgePhase::Stopping),
            (OFF, DockerMode, S1, on_s1, BridgePhase::Stopping),
            (ON, DockerMode, S1, on_s1, BridgePhase::Stopping),
            (ON, OptIn, None, on_s1, BridgePhase::Stopping),
            (ON, OptIn, S2, on_s1, BridgePhase::Stopping),
            (OFF, OptIn, None, on_s1, BridgePhase::Stopping),
            (OFF, OptIn, S2, on_s1, BridgePhase::Stopping),
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
                            (phase.epoch().is_some(), phase == BridgePhase::Stopping),
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
    fn backoff_grows_to_one_minute_and_stays_there() {
        assert_eq!(backoff(1), Duration::from_secs(5));
        assert_eq!(backoff(2), Duration::from_secs(10));
        assert_eq!(backoff(3), Duration::from_secs(20));
        assert_eq!(backoff(4), Duration::from_secs(40));
        assert_eq!(backoff(5), Duration::from_secs(60));
        assert_eq!(backoff(u32::MAX), Duration::from_secs(60));
    }

    /// One start attempt, as the engine saw it.
    struct Attempt {
        at: Instant,
        host_key: String,
        /// What `netbridge.json` held while the attempt was in flight.
        saved: NetbridgeState,
    }

    /// An engine on which no start succeeds. It does no I/O, so the paused
    /// clock moves only when the control loop waits.
    struct NoEngine {
        state_path: PathBuf,
        seen: mpsc::UnboundedSender<Attempt>,
    }

    impl BridgeStarter for NoEngine {
        async fn start_bridge(&self, _mode: NetbridgeMode, host_kp: &Keypair) -> Result<Runtime> {
            let _ = self.seen.send(Attempt {
                at: Instant::now(),
                host_key: host_kp.public_base64(),
                saved: netbridge_state::load(&self.state_path),
            });
            anyhow::bail!("no container engine")
        }
    }

    struct Rig {
        handle: Handle,
        state_path: PathBuf,
        attempts: mpsc::UnboundedReceiver<Attempt>,
        _dir: TempDir,
    }

    const LONGEST_WAIT: Duration = Duration::from_secs(3600);

    impl Rig {
        fn start() -> Self {
            Self::start_with_env_override(false)
        }

        fn start_with_env_override(forced_on: bool) -> Self {
            let dir = tempdir().unwrap();
            let state_path = dir.path().join("netbridge.json");
            let (seen, attempts) = mpsc::unbounded_channel();
            let engine = NoEngine {
                state_path: state_path.clone(),
                seen,
            };
            let (handle, rx, phase_tx) = handle_pair();
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
                _dir: dir,
            }
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
}
