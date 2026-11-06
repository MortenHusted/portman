//! Linux stub — container IPs are natively routable; no bridge health check.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bollard::Docker;

use portman_protocol::BridgeAssessment;

pub(crate) type Shared = Arc<RwLock<BridgeAssessment>>;

pub(crate) fn new_shared() -> Shared {
    // Natively routable — the bridge concept doesn't apply, report healthy.
    Arc::new(RwLock::new(BridgeAssessment::Healthy))
}

pub(crate) async fn run(
    _docker: Docker,
    _shared: Shared,
    _bridge_ifindex: crate::upstream::BridgeIfIndex,
) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
