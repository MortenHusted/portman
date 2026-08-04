//! Linux stub — no container-facing tunnel IP on Linux.

use anyhow::Result;
use portman_core::{Registry, TlsStore};
use tokio::sync::watch;

use crate::certs::CertManager;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    _registry: Registry,
    _state_rx: watch::Receiver<bool>,
    _http_port: u16,
    _tls_port: u16,
    _cert_manager: CertManager,
    _tls_store: std::sync::Arc<TlsStore>,
    _bridge: crate::upstream::BridgeIfIndex,
    _starter: std::sync::Arc<dyn crate::runner::Starter>,
) -> Result<()> {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
