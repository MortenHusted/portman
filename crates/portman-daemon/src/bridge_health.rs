//! Background assessment of "is the host ↔ VM bridge healthy?".
//!
//! Every 5 seconds:
//!   1. Ask Docker for the set of networks that currently have Portman-labelled
//!      containers on them (via `bollard`, reusing the socket the daemon already
//!      opened for the container-events watcher).
//!   2. For each such network, read its subnet(s) and ask the macOS
//!      routing table whether that subnet is routed via any `utun`
//!      interface.
//!   3. Reduce to a single assessment — `healthy` | `routes_missing` |
//!      `offline` | `unknown` — and publish it to a `RwLock<String>` the
//!      IPC Status handler reads.
//!
//! This is the first daemon-side consumer of the Phase-A primitives. It
//! deliberately doesn't depend on the Phase-A example code in
//! `portman-netbridge`; those examples exist to prototype shapes before
//! productionizing them. We'll absorb them into `portman-netbridge`'s
//! `route_observer` and `docker_state` modules in a later phase, and
//! this daemon task will switch from polling to subscribing. For now,
//! a 5-second poll is plenty for a menubar tint update.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bollard::query_parameters::{ListContainersOptionsBuilder, ListNetworksOptionsBuilder};
use bollard::Docker;
use tracing::{debug, warn};

/// How often to re-assess. 5s matches the menubar's own refresh cadence;
/// a bridge flap surfaces in the UI within the next poll cycle.
const ASSESSMENT_PERIOD: Duration = Duration::from_secs(5);
const LABEL_HOST: &str = "dev.portman.host";

use portman_protocol::BridgeAssessment;

/// Shared assessment published by the background task. Uses
/// `std::sync::RwLock` (not tokio's) so the sync IPC `handle_status` can
/// read it without awaiting — the write holds the lock only for a
/// microsecond-scale value replacement, safe to block on briefly from
/// a tokio task.
pub(crate) type Shared = Arc<RwLock<BridgeAssessment>>;

pub(crate) fn new_shared() -> Shared {
    Arc::new(RwLock::new(BridgeAssessment::Unknown))
}

/// Long-running task. Spawned once at daemon startup. Returns `Result`
/// to match the shape of the other daemon tasks the `tokio::select!` in
/// `main` awaits — the loop itself is infinite so the function never
/// actually returns `Ok`.
pub(crate) async fn run(docker: Docker, shared: Shared) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(ASSESSMENT_PERIOD);
    // First tick fires immediately, which is what we want — establish an
    // assessment ASAP after startup rather than leaving the menubar on
    // "unknown" for 5s.
    loop {
        ticker.tick().await;
        let assessment = assess(&docker).await;
        debug!(
            assessment = assessment.as_str(),
            "bridge health assessment updated"
        );
        if let Ok(mut guard) = shared.write() {
            *guard = assessment;
        }
    }
}

async fn assess(docker: &Docker) -> BridgeAssessment {
    // Find docker networks that currently have at least one Portman-labelled
    // container on them. Unrelated compose/default networks are not Portman
    // health inputs.
    let subnets = match subnets_with_portman_containers(docker).await {
        Ok(s) => s,
        Err(err) => {
            warn!(error = %err, "bridge health: docker unreachable");
            return BridgeAssessment::Offline;
        }
    };

    if subnets.is_empty() {
        // No containers → bridge isn't being used right now → we call it
        // healthy. (A reasonable alternative is "unknown"; "healthy" is
        // chosen so the menubar icon stays green when the user's compose
        // stack is down for legitimate reasons.)
        return BridgeAssessment::Healthy;
    }

    // A dead tunnel outranks a missing route in the report: it's the more
    // specific, more confusing failure, and the one that looks fine from the
    // routing table alone.
    let mut missing = false;
    for subnet in &subnets {
        match subnet_routed_via_live_utun(subnet).await {
            RouteState::Live => {}
            RouteState::Dead => return BridgeAssessment::TunnelDead,
            RouteState::Missing => missing = true,
        }
    }
    if missing {
        return BridgeAssessment::RoutesMissing;
    }
    BridgeAssessment::Healthy
}

/// Set of docker network subnets (CIDR strings like "172.18.0.0/16")
/// that have at least one Portman-labelled container attached right now.
async fn subnets_with_portman_containers(docker: &Docker) -> anyhow::Result<BTreeSet<String>> {
    let opts = ListContainersOptionsBuilder::default().all(false).build();
    let containers = docker.list_containers(Some(opts)).await?;

    // Collect the distinct network names in use.
    let mut networks_in_use: BTreeSet<String> = BTreeSet::new();
    for c in &containers {
        if !has_portman_host_label(c.labels.as_ref()) {
            continue;
        }
        if let Some(nets) = c
            .network_settings
            .as_ref()
            .and_then(|s| s.networks.as_ref())
        {
            for name in nets.keys() {
                // Skip virtual networks that don't have routed subnets.
                if matches!(name.as_str(), "host" | "none") {
                    continue;
                }
                networks_in_use.insert(name.clone());
            }
        }
    }
    if networks_in_use.is_empty() {
        return Ok(BTreeSet::new());
    }

    // Fetch network IPAM configs to read the CIDR for each network in use.
    let all_networks = docker
        .list_networks(None::<ListNetworksOptionsBuilder>.map(|b| b.build()))
        .await?;

    let mut out = BTreeSet::new();
    for net in &all_networks {
        let Some(name) = net.name.as_deref() else {
            continue;
        };
        if !networks_in_use.contains(name) {
            continue;
        }
        if let Some(configs) = net.ipam.as_ref().and_then(|i| i.config.as_ref()) {
            for cfg in configs {
                if let Some(subnet) = &cfg.subnet {
                    out.insert(subnet.clone());
                }
            }
        }
    }
    Ok(out)
}

fn has_portman_host_label(labels: Option<&std::collections::HashMap<String, String>>) -> bool {
    labels
        .and_then(|labels| labels.get(LABEL_HOST))
        .is_some_and(|value| !value.trim().is_empty())
}

/// Does the macOS host currently route `subnet` via some `utun*`
/// interface? Uses the system `route -n get` command rather than a
/// PF_ROUTE socket dump — fewer moving parts and zero new unsafe code in
/// the daemon (PF_ROUTE lives in the `portman-netbridge` crate, which is
/// where the deeper observer will land).
async fn route_utun_for_subnet(subnet: &str) -> Option<String> {
    // CIDR → address (strip the "/NN"). `route get` takes a host
    // address; for our purposes passing the subnet's network address
    // works — if the subnet is routed, `route get` reports the matching
    // route.
    let addr = subnet.split('/').next()?;

    let output = tokio::process::Command::new("/sbin/route")
        .args(["-n", "get", addr])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().find_map(parse_route_interface)
}

/// `  interface: utun5` → `Some("utun5")`. Non-utun interfaces don't count:
/// the bridge is the only thing that should be carrying these subnets.
fn parse_route_interface(line: &str) -> Option<String> {
    let iface = line.trim_start().strip_prefix("interface:")?.trim();
    iface.starts_with("utun").then(|| iface.to_string())
}

/// Does the host route `subnet` via a utun that **actually exists**?
///
/// Checking only that a route exists is what let a total outage report
/// `healthy`: a failed bridge start left the subnet pointed at a utun that had
/// since been destroyed, and every packet was black-holed while `route get`
/// kept happily naming the dead interface.
async fn subnet_routed_via_live_utun(subnet: &str) -> RouteState {
    match route_utun_for_subnet(subnet).await {
        None => RouteState::Missing,
        Some(iface) if nix::net::if_::if_nametoindex(iface.as_str()).is_ok() => RouteState::Live,
        Some(_) => RouteState::Dead,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteState {
    Live,
    /// Routed, but at an interface that no longer exists.
    Dead,
    Missing,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn health_scope_requires_portman_host_label() {
        let labels = HashMap::from([(LABEL_HOST.to_string(), "pg.test".to_string())]);
        let empty_label = HashMap::from([(LABEL_HOST.to_string(), " ".to_string())]);

        assert!(has_portman_host_label(Some(&labels)));
        assert!(!has_portman_host_label(Some(&empty_label)));
        assert!(!has_portman_host_label(Some(&HashMap::new())));
        assert!(!has_portman_host_label(None));
    }
}
