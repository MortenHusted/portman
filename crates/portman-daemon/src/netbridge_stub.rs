//! Linux stub — no VM↔host WireGuard bridge on Linux.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use bollard::Docker;
use portman_core::NetbridgeMode;
use tokio::sync::{mpsc, watch, RwLock};

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum Control {
    Enable,
    Disable,
    SetMode(NetbridgeMode),
}

#[derive(Clone)]
pub(crate) struct Handle {
    #[allow(dead_code)]
    pub tx: mpsc::Sender<Control>,
    pub enabled: Arc<RwLock<bool>>,
    pub mode: Arc<RwLock<NetbridgeMode>>,
    pub state_rx: watch::Receiver<bool>,
    /// Never published on Linux — container IPs are natively routable, so
    /// upstream connects stay unscoped. Present to keep the Handle shape
    /// identical across platforms.
    pub ifindex: crate::upstream::BridgeIfIndex,
}

pub(crate) struct StateTx(pub watch::Sender<bool>);

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

pub(crate) async fn run(
    _docker: Docker,
    handle: Handle,
    mut rx: mpsc::Receiver<Control>,
    state_tx: StateTx,
    _state_path: PathBuf,
) -> Result<()> {
    while let Some(msg) = rx.recv().await {
        match msg {
            Control::Enable => {
                *handle.enabled.write().await = false;
                let _ = state_tx.0.send(false);
            }
            Control::Disable => {
                *handle.enabled.write().await = false;
                let _ = state_tx.0.send(false);
            }
            Control::SetMode(new_mode) => {
                *handle.mode.write().await = new_mode;
            }
        }
    }
    Ok(())
}
