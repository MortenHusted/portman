//! Daemon integration for the v1 portman-netbridge.
//!
//! Long-running task that owns zero or one `Runtime` and converges it on
//! what the user asked for: the on/off flag and the route mode persisted in
//! `~/Library/Application Support/portman/netbridge.json`. The
//! `PORTMAN_NETBRIDGE` env var forces the flag on for one daemon run.
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
/// lands. Presence (non-empty, not "0"/"false") forces enabled=true.
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
    docker: Docker,
    handle: Handle,
    mut rx: mpsc::Receiver<Control>,
    phase_tx: watch::Sender<BridgePhase>,
    state_path: PathBuf,
) -> Result<()> {
    let mut intent = netbridge_state::load(&state_path);
    let env_forces = env_forces_enabled();
    info!(
        persisted_enabled = intent.enabled,
        mode = intent.mode.as_str(),
        env = env_forces,
        "netbridge subsystem starting"
    );
    intent.enabled |= env_forces;

    // The boot-time Docker handle is the only engine session there is.
    let session = Some(Session(0));
    let mut running: Option<Running> = None;
    let mut attempts = Attempts::new();
    let mut epoch = 0;

    loop {
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
                    if let Some(runtime) = try_start(&docker, intent.mode, &mut attempts).await {
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
                    Control::Enable => intent.enabled = true,
                    Control::Disable => intent.enabled = false,
                    Control::SetMode(mode) => {
                        if intent.mode != mode {
                            info!(mode = mode.as_str(), "netbridge mode changed");
                        }
                        intent.mode = mode;
                    }
                }
                persist(&state_path, &intent);
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

/// One start attempt. A failure schedules the retry on `attempts`.
async fn try_start(
    docker: &Docker,
    mode: NetbridgeMode,
    attempts: &mut Attempts,
) -> Option<Runtime> {
    let options = RuntimeOptions { mode };
    match Runtime::start_with_keypair(docker.clone(), options, &attempts.host_kp).await {
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
    use tokio::task::JoinHandle;
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

    /// Runs the task against a Docker socket that refuses every connection,
    /// so a start fails at its first Docker call and touches nothing on the
    /// host.
    fn run_without_engine(dir: &TempDir) -> (Handle, PathBuf, JoinHandle<Result<()>>) {
        let sock = dir.path().join("docker.sock");
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
        let docker =
            Docker::connect_with_socket(sock.to_str().unwrap(), 5, bollard::API_DEFAULT_VERSION)
                .unwrap();
        let state_path = dir.path().join("netbridge.json");
        let (handle, rx, phase_tx) = handle_pair();
        let task = tokio::spawn(run(
            docker,
            handle.clone(),
            rx,
            phase_tx,
            state_path.clone(),
        ));
        (handle, state_path, task)
    }

    #[tokio::test]
    async fn enable_with_no_reachable_engine_persists_the_intent() {
        let dir = tempdir().unwrap();
        let (handle, state_path, task) = run_without_engine(&dir);

        handle.tx.send(Control::Enable).await.unwrap();
        // The task takes the mode change only after the start that the
        // enable asked for has failed.
        handle.tx.send(Control::SetMode(DockerMode)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while *handle.mode.read().await != DockerMode {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the mode change is published");

        let saved = netbridge_state::load(&state_path);
        assert!(saved.enabled);
        assert_eq!(saved.mode, DockerMode);
        assert_eq!(*handle.phase.borrow(), BridgePhase::Starting);
        task.abort();
    }

    #[tokio::test]
    async fn disable_while_a_start_is_retrying_takes_effect() {
        let dir = tempdir().unwrap();
        let (handle, state_path, task) = run_without_engine(&dir);
        let mut phase = handle.phase.clone();

        handle.tx.send(Control::Enable).await.unwrap();
        phase
            .wait_for(|p| *p == BridgePhase::Starting)
            .await
            .unwrap();
        handle.tx.send(Control::Disable).await.unwrap();
        tokio::time::timeout(RETRY_BASE, phase.wait_for(|p| *p == BridgePhase::Disabled))
            .await
            .expect("the disable lands before the first retry is due")
            .unwrap();

        assert!(!netbridge_state::load(&state_path).enabled);
        task.abort();
    }
}
