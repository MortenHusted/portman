//! Daemon integration for the v1 portman-netbridge.
//!
//! Long-running task that owns zero or one `Runtime`. Starts in the
//! persisted state (from `~/Library/Application Support/portman/
//! netbridge.json` or the `PORTMAN_NETBRIDGE` env var as a fallback
//! / override) and listens on an mpsc channel for enable/disable
//! messages from the IPC server.
//!
//! Control flow:
//!
//!   - on startup: load persisted state. If enabled → `Runtime::start`.
//!     If env var is set, treat as enabled regardless of persistence
//!     (lets users who are still flipping the plist also land here).
//!   - on `Control::Enable`: start `Runtime` if none, persist
//!     enabled=true.
//!   - on `Control::Disable`: shutdown the `Runtime` if one, persist
//!     enabled=false.
//!   - persistence is written *after* the bridge state change so a
//!     mid-operation crash doesn't leave stale state.

use std::path::PathBuf;
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

/// Messages the IPC server sends to the netbridge task.
#[derive(Debug)]
pub(crate) enum Control {
    Enable,
    Disable,
    SetMode(NetbridgeMode),
}

/// Shared handle the IPC server holds to push control messages. The
/// `RwLock<bool>` mirrors the current enabled state so `portman
/// status` / future IPC queries can report it synchronously without
/// awaiting the task's internal state. The `watch` channel lets other
/// subsystems (e.g. the host-facing DNS listener) react to bridge
/// state changes without polling.
#[derive(Clone)]
pub(crate) struct Handle {
    pub tx: mpsc::Sender<Control>,
    pub enabled: Arc<RwLock<bool>>,
    pub mode: Arc<RwLock<NetbridgeMode>>,
    pub state_rx: watch::Receiver<bool>,
    /// Interface index of the bridge's utun while it is up. The proxy /
    /// forwarder subsystems scope upstream sockets to it so bridge-subnet
    /// traffic survives a VPN/exit-node claiming the default route.
    pub ifindex: crate::upstream::BridgeIfIndex,
}

/// The netbridge task owns the `watch::Sender`. Wrapping it lets us
/// pass just the sender into `run()` while leaving the Handle shape
/// untouched for the IPC server / status reads.
pub(crate) struct StateTx(pub watch::Sender<bool>);

/// Build a handle pair — one for main.rs to pass into the task,
/// one for the daemon's IPC server to hold.
pub(crate) fn handle_pair() -> (Handle, mpsc::Receiver<Control>, StateTx) {
    let (tx, rx) = mpsc::channel(8);
    let enabled = Arc::new(RwLock::new(false));
    let mode = Arc::new(RwLock::new(NetbridgeMode::OptIn));
    let (state_tx, state_rx) = watch::channel(false);
    (
        Handle {
            tx,
            enabled,
            mode,
            state_rx,
            ifindex: crate::upstream::new_bridge_ifindex(),
        },
        rx,
        StateTx(state_tx),
    )
}

/// Long-running task spawned from `main`. Never returns `Ok` —
/// mirrors the shape of the other daemon subsystems so `select!`
/// handles panics uniformly.
pub(crate) async fn run(
    docker: Docker,
    handle: Handle,
    mut rx: mpsc::Receiver<Control>,
    state_tx: StateTx,
    state_path: PathBuf,
) -> Result<()> {
    let persisted = netbridge_state::load(&state_path);
    let env_forces = env_forces_enabled();
    let initial = persisted.enabled || env_forces;
    let mut mode = persisted.mode;
    *handle.mode.write().await = mode;

    info!(
        persisted_enabled = persisted.enabled,
        mode = mode.as_str(),
        env = env_forces,
        "netbridge subsystem starting"
    );

    let mut runtime: Option<Runtime> = None;

    if initial {
        runtime = try_start(&docker, mode).await;
    }

    // Only reflect `enabled = true` if the Runtime actually came up.
    // Without this the initial-boot path lies to IPC readers when
    // `try_start` fails (e.g. docker unavailable): status would still
    // show `netbridge: enabled` while the bridge is down.
    let up = runtime.is_some();
    *handle.enabled.write().await = up;
    publish_ifindex(&handle.ifindex, runtime.as_ref());
    let _ = state_tx.0.send(up);

    // Loop on control messages. mpsc::Receiver::recv returns None
    // only if all senders are dropped — which would mean the daemon
    // is exiting, so we bail.
    while let Some(msg) = rx.recv().await {
        match msg {
            Control::Enable => {
                if runtime.is_none() {
                    runtime = try_start(&docker, mode).await;
                }
                let up = runtime.is_some();
                *handle.enabled.write().await = up;
                publish_ifindex(&handle.ifindex, runtime.as_ref());
                let _ = state_tx.0.send(up);
                persist(&state_path, up, mode);
            }
            Control::Disable => {
                // Explicit disable is the one case where we also want
                // the docker network gone — the user asked. Daemon
                // restart takes the lighter `shutdown` path so attached
                // containers (osrm, etc.) keep their IPs.
                if let Some(rt) = runtime.take() {
                    rt.shutdown_and_remove_network().await;
                }
                *handle.enabled.write().await = false;
                publish_ifindex(&handle.ifindex, None);
                let _ = state_tx.0.send(false);
                persist(&state_path, false, mode);
            }
            Control::SetMode(new_mode) => {
                if mode != new_mode {
                    let was_enabled = runtime.is_some();
                    if let Some(rt) = runtime.take() {
                        *handle.enabled.write().await = false;
                        publish_ifindex(&handle.ifindex, None);
                        let _ = state_tx.0.send(false);
                        rt.shutdown().await;
                    }
                    mode = new_mode;
                    *handle.mode.write().await = mode;
                    info!(mode = mode.as_str(), "netbridge mode changed");
                    if was_enabled {
                        runtime = try_start(&docker, mode).await;
                    }
                }
                let up = runtime.is_some();
                *handle.enabled.write().await = up;
                publish_ifindex(&handle.ifindex, runtime.as_ref());
                let _ = state_tx.0.send(up);
                persist(&state_path, up, mode);
            }
        }
    }
    Ok(())
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

/// Attempt `Runtime::start` with a short retry — docker might be
/// briefly unavailable on daemon boot (colima still starting). Return
/// `None` after retries fail; the daemon keeps running, the user can
/// re-enable later.
async fn try_start(docker: &Docker, mode: NetbridgeMode) -> Option<Runtime> {
    // One identity for the whole attempt sequence. Regenerating per attempt
    // meant a tunnel left over from a failed attempt was peered to keys the VM
    // had already forgotten — indistinguishable from the live one by name, and
    // silently black-holing whatever routed through it.
    let host_kp = Keypair::generate();
    for attempt in 1..=3 {
        match Runtime::start_with_keypair(docker.clone(), RuntimeOptions { mode }, &host_kp).await {
            Ok(rt) => {
                info!(
                    mode = mode.as_str(),
                    "netbridge up: docker network `portman`, container pool 192.168.99.130–.253"
                );
                return Some(rt);
            }
            Err(err) => {
                warn!(%err, attempt, "netbridge start failed");
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
    None
}

fn persist(path: &std::path::Path, enabled: bool, mode: NetbridgeMode) {
    if let Err(err) = netbridge_state::save(path, &NetbridgeState { enabled, mode }) {
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
