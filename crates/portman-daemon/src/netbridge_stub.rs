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

/// Linux runs no bridge, so the phase has one value and nothing publishes
/// another. The type exists so that the readers compile on both platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BridgePhase {
    Disabled,
}

impl BridgePhase {
    pub(crate) fn reads_as_enabled(self) -> bool {
        false
    }
}

impl From<BridgePhase> for portman_protocol::BridgePhase {
    fn from(phase: BridgePhase) -> Self {
        match phase {
            BridgePhase::Disabled => Self::Disabled,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Handle {
    #[allow(dead_code)]
    pub tx: mpsc::Sender<Control>,
    pub mode: Arc<RwLock<NetbridgeMode>>,
    pub phase: watch::Receiver<BridgePhase>,
    /// Never published on Linux — container IPs are natively routable, so
    /// upstream connects stay unscoped. Present to keep the Handle shape
    /// identical across platforms.
    pub ifindex: crate::upstream::BridgeIfIndex,
}

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

pub(crate) async fn run(
    _docker: Docker,
    handle: Handle,
    mut rx: mpsc::Receiver<Control>,
    _phase_tx: watch::Sender<BridgePhase>,
    _state_path: PathBuf,
) -> Result<()> {
    while let Some(msg) = rx.recv().await {
        match msg {
            Control::Enable | Control::Disable => {}
            Control::SetMode(new_mode) => {
                *handle.mode.write().await = new_mode;
            }
        }
    }
    Ok(())
}
