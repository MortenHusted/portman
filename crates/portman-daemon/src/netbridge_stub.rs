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

/// Mirrors the macOS phase so readers compile on both platforms. Linux
/// only ever publishes `Disabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum BridgePhase {
    Disabled,
    WaitingForDocker,
    Starting,
    Up { epoch: u64 },
}

impl BridgePhase {
    pub(crate) fn epoch(self) -> Option<u64> {
        match self {
            BridgePhase::Up { epoch } => Some(epoch),
            _ => None,
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
