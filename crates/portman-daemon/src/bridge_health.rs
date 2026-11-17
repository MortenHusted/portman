//! Background assessment of "is the host ↔ VM bridge healthy?".
//!
//! Every 5 seconds, and when the engine link changes:
//!   1. Ask Docker for the running Portman-labelled containers, and take the
//!      networks that the health needs a route to. A container that the
//!      registry routes to its address on the `portman` network needs that
//!      network only. Any other labelled container needs each of its
//!      networks. With no engine connected the assessment is `offline` and
//!      nothing is asked.
//!   2. For each such network, read its subnet(s) and ask the macOS
//!      routing table whether that subnet is routed via the active bridge
//!      interface (or a live legacy `utun` when the native bridge is disabled).
//!   3. Reduce to a single [`BridgeAssessment`] and publish it to the
//!      [`Shared`] lock that the IPC Status handler reads.
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

use bollard::models::ContainerSummary;
use bollard::query_parameters::{ListContainersOptionsBuilder, ListNetworksOptionsBuilder};
use bollard::Docker;
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::discovery::{self, PORTMAN_NETWORK};
use crate::engine::Engine;
use crate::netbridge::BridgePhase;

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
pub(crate) async fn run(
    engine: Engine,
    shared: Shared,
    bridge_ifindex: crate::upstream::BridgeIfIndex,
    _phase: watch::Receiver<BridgePhase>,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(ASSESSMENT_PERIOD);
    let mut link = engine.watch();
    // First tick fires immediately, which is what we want — establish an
    // assessment ASAP after startup rather than leaving the menubar on
    // "unknown" for 5s. A change of the engine link is assessed at once, so
    // that the assessment does not stay `offline` for a period after the
    // engine connects.
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            Ok(()) = link.changed() => {}
        }
        let assessment = assess(&engine, &bridge_ifindex).await;
        debug!(
            assessment = assessment.as_str(),
            "bridge health assessment updated"
        );
        if let Ok(mut guard) = shared.write() {
            *guard = assessment;
        }
    }
}

async fn assess(
    engine: &Engine,
    bridge_ifindex: &crate::upstream::BridgeIfIndex,
) -> BridgeAssessment {
    let Ok(docker) = engine.docker() else {
        return BridgeAssessment::Offline;
    };
    // Unrelated compose/default networks are not Portman health inputs, and
    // neither is the second network of a container that the registry routes
    // through `portman`.
    let subnets = match subnets_with_portman_containers(&docker).await {
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
    let expected_ifindex = *bridge_ifindex.read().expect("bridge ifindex lock poisoned");
    let mut missing = false;
    for subnet in &subnets {
        match subnet_routed_via_live_utun(subnet, expected_ifindex).await {
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

/// Set of docker network subnets (CIDR strings like "172.18.0.0/16") of the
/// networks that [`networks_in_use`] names for the running containers.
async fn subnets_with_portman_containers(docker: &Docker) -> anyhow::Result<BTreeSet<String>> {
    let opts = ListContainersOptionsBuilder::default().all(false).build();
    let containers = docker.list_containers(Some(opts)).await?;

    let networks_in_use = networks_in_use(&containers);
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

/// A container that the registry routes to its address on the `portman`
/// network counts through that network only, because the bridge routes that
/// network in every mode. Any other labelled container counts through each
/// of its networks.
fn networks_in_use(containers: &[ContainerSummary]) -> BTreeSet<String> {
    let mut networks_in_use: BTreeSet<String> = BTreeSet::new();
    for c in containers {
        if !has_portman_host_label(c.labels.as_ref()) {
            continue;
        }
        if routed_through_portman(c) {
            networks_in_use.insert(PORTMAN_NETWORK.to_string());
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
    networks_in_use
}

/// Asks the registry's own choice of address, so that the health cannot name
/// `portman` for a container that the registry routes elsewhere.
fn routed_through_portman(container: &ContainerSummary) -> bool {
    discovery::observe(container.clone()).is_some_and(|container| {
        discovery::pick(&container.addresses).is_some_and(|(network, _)| network == PORTMAN_NETWORK)
    })
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

/// A route is healthy only when its interface exists and matches the active
/// runtime. With no native runtime, retain support for a live legacy bridge.
async fn subnet_routed_via_live_utun(subnet: &str, expected_ifindex: Option<u32>) -> RouteState {
    classify_route_interface(
        route_utun_for_subnet(subnet).await.as_deref(),
        expected_ifindex,
    )
}

fn classify_route_interface(iface: Option<&str>, expected_ifindex: Option<u32>) -> RouteState {
    let Some(iface) = iface else {
        return RouteState::Missing;
    };
    match nix::net::if_::if_nametoindex(iface) {
        Err(_) => RouteState::Dead,
        Ok(index) if expected_ifindex.is_some_and(|expected| expected != index) => {
            RouteState::Missing
        }
        Ok(_) => RouteState::Live,
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
    fn health_rejects_a_live_interface_that_is_not_the_current_bridge() {
        let iface = "lo0";
        let index = nix::net::if_::if_nametoindex(iface).unwrap();
        assert_eq!(
            classify_route_interface(Some(iface), Some(index)),
            RouteState::Live
        );
        assert_eq!(
            classify_route_interface(Some(iface), None),
            RouteState::Live
        );
        assert_eq!(
            classify_route_interface(None, Some(index)),
            RouteState::Missing
        );
        assert_eq!(
            classify_route_interface(Some("utun-does-not-exist"), Some(index)),
            RouteState::Dead
        );
        assert_eq!(
            classify_route_interface(Some(iface), Some(index + 1)),
            RouteState::Missing,
            "a live VPN interface does not prove Portman's route is healthy"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_engine_that_connects_is_assessed_before_the_next_period() {
        let (engine, publisher) = crate::engine::channel();
        let shared = new_shared();
        let ifindex = crate::upstream::new_bridge_ifindex();
        let (_phase_tx, phase) = watch::channel(BridgePhase::Disabled);
        tokio::spawn(run(engine, shared.clone(), ifindex, phase));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(*shared.read().unwrap(), BridgeAssessment::Offline);

        let _engine = crate::engine::tests::connect(&publisher);
        tokio::time::sleep(Duration::from_millis(1)).await;

        assert_eq!(*shared.read().unwrap(), BridgeAssessment::Healthy);
    }

    #[tokio::test(start_paused = true)]
    async fn a_bridge_that_changes_phase_is_assessed_before_the_next_period() {
        let (engine, fake) = crate::engine::tests::connected();
        let shared = new_shared();
        let ifindex = crate::upstream::new_bridge_ifindex();
        let (phase_tx, phase) = watch::channel(BridgePhase::Starting);
        tokio::spawn(run(engine, shared.clone(), ifindex, phase));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(*shared.read().unwrap(), BridgeAssessment::Healthy);

        fake.fail_lists();
        phase_tx.send_replace(BridgePhase::Up { epoch: 1 });
        tokio::time::sleep(Duration::from_millis(1)).await;

        assert_eq!(
            *shared.read().unwrap(),
            BridgeAssessment::Offline,
            "the assessment is from before the bridge came up"
        );
    }

    #[tokio::test]
    async fn with_no_engine_the_bridge_is_offline() {
        let (engine, _) = crate::engine::channel();
        let ifindex = crate::upstream::new_bridge_ifindex();

        assert_eq!(assess(&engine, &ifindex).await, BridgeAssessment::Offline);
    }

    fn container(host: Option<&str>, networks: &[(&str, &str)]) -> ContainerSummary {
        use bollard::models::{ContainerSummaryNetworkSettings, EndpointSettings};
        let endpoint = |address: &str| EndpointSettings {
            ip_address: Some(address.to_string()),
            ..Default::default()
        };
        ContainerSummary {
            id: Some("0a1b2c3d4e5f".to_string()),
            labels: host.map(|host| HashMap::from([(LABEL_HOST.to_string(), host.to_string())])),
            network_settings: Some(ContainerSummaryNetworkSettings {
                networks: Some(
                    networks
                        .iter()
                        .map(|&(name, address)| (name.to_string(), endpoint(address)))
                        .collect(),
                ),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_labelled_container_counts_through_portman_when_the_registry_routes_it_there_and_through_each_of_its_networks_otherwise(
    ) {
        let web = Some("web.demo.test");
        let compose = ("demo_default", "172.18.0.2");
        let backend = ("acme_backend", "172.19.0.2");
        let portman = ("portman", "192.168.99.130");
        let portman_without_ipv4 = ("portman", "");
        let names = |names: &[&str]| -> BTreeSet<String> {
            names.iter().map(|name| name.to_string()).collect()
        };
        // the containers → the networks whose routes the health needs
        let table = [
            (vec![container(web, &[compose])], names(&["demo_default"])),
            (vec![container(web, &[portman])], names(&["portman"])),
            (
                vec![container(web, &[compose, portman])],
                names(&["portman"]),
            ),
            (
                vec![container(web, &[compose, portman_without_ipv4])],
                names(&["demo_default", "portman"]),
            ),
            (
                vec![container(web, &[backend, compose])],
                names(&["acme_backend", "demo_default"]),
            ),
            (
                vec![
                    container(web, &[compose, portman]),
                    container(Some("api.demo.test"), &[compose]),
                ],
                names(&["demo_default", "portman"]),
            ),
            (vec![container(web, &[("host", "")])], names(&[])),
            (vec![container(None, &[compose])], names(&[])),
        ];
        for (containers, networks) in table {
            assert_eq!(networks_in_use(&containers), networks, "{containers:?}");
        }
    }

    #[test]
    fn health_counts_a_container_through_portman_alone_only_when_the_registry_routes_it_there() {
        let on_portman: std::net::Ipv4Addr = [192, 168, 99, 130].into();
        let portman_alone = BTreeSet::from(["portman".to_string()]);
        let mut routed_through_portman = 0;
        for portman_address in ["192.168.99.130", "", "invalid IP", "fd00:99::2"] {
            let both = container(
                Some("web.demo.test"),
                &[("demo_default", "172.18.0.2"), ("portman", portman_address)],
            );

            let routed_to = crate::discovery::observe(both.clone())
                .and_then(|container| crate::discovery::pick_address(&container.addresses));

            assert_eq!(
                networks_in_use(&[both]) == portman_alone,
                routed_to == Some(on_portman),
                "portman address {portman_address:?}, registry routes to {routed_to:?}"
            );
            routed_through_portman += usize::from(routed_to == Some(on_portman));
        }
        assert_eq!(routed_through_portman, 1);
    }

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
