//! Which container routes the registry should hold, computed from one list
//! of running containers.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use bollard::models::ContainerSummary;
use portman_core::{Entry, Mode, Source};

pub(crate) const LABEL_HOST: &str = "dev.portman.host";
const LABEL_PORT: &str = "dev.portman.port";
const LABEL_MODE: &str = "dev.portman.mode";
const LABEL_PROJECT: &str = "dev.portman.project";

/// The one network whose addresses portman's own bridge always routes.
const PORTMAN_NETWORK: &str = "portman";

/// A running container that carries `dev.portman.host`, parsed once from the
/// Docker list response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Container {
    pub id: String,
    pub created: i64,
    /// The `dev.portman.host` label as written.
    pub host: String,
    pub port: Option<String>,
    pub mode: Mode,
    pub project: Option<String>,
    /// One `(network name, address)` per network that gave the container an
    /// IPv4 address. `host` and `none` never appear.
    pub addresses: Vec<(String, Ipv4Addr)>,
    /// The network mode, when it is one that never gives the container an
    /// address of its own: `host`, `none`, or `container:<id>`.
    pub unaddressable: Option<String>,
}

/// `None` for a container without a `dev.portman.host` label.
pub(crate) fn observe(summary: ContainerSummary) -> Option<Container> {
    let labels = summary.labels?;
    let label = |name: &str| labels.get(name).filter(|value| !value.is_empty()).cloned();
    let host = label(LABEL_HOST)?;
    let addresses = summary
        .network_settings
        .and_then(|settings| settings.networks)
        .into_iter()
        .flatten()
        .filter(|(network, _)| network != "host" && network != "none")
        .filter_map(|(network, endpoint)| Some((network, endpoint.ip_address?.parse().ok()?)))
        .collect();
    let unaddressable = summary
        .host_config
        .and_then(|config| config.network_mode)
        .filter(|mode| mode == "host" || mode == "none" || mode.starts_with("container:"));
    Some(Container {
        id: summary.id?,
        created: summary.created.unwrap_or_default(),
        host,
        port: label(LABEL_PORT),
        mode: Mode::parse_label(label(LABEL_MODE).as_deref()),
        project: label(LABEL_PROJECT),
        addresses,
        unaddressable,
    })
}

#[derive(Debug, Default)]
pub(crate) struct Plan {
    /// At most one entry per host.
    pub entries: Vec<Entry>,
    /// Short ids of containers that get a host once they have an address.
    pub waiting: Vec<String>,
    pub skipped: Vec<Skipped>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Skipped {
    pub id: String,
    pub host: String,
    pub reason: Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Skip {
    InvalidHost(String),
    ReservedHost,
    UnmanagedTld,
    TcpOnLocalhost,
    TcpWithoutPort,
    /// The network mode, which never gives the container an address.
    NoAddress(String),
    /// A newer container, named by its short id, holds the same host.
    HostTakenBy(String),
    /// A route from this source holds the same host. [`plan`] never gives
    /// this reason, because only the registry knows its other routes.
    HostHeldBy(Source),
}

impl fmt::Display for Skip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Skip::InvalidHost(err) => write!(f, "invalid dev.portman.host label: {err}"),
            Skip::ReservedHost => f.write_str("hostname is reserved for portman's dashboard"),
            Skip::UnmanagedTld => {
                f.write_str("TLD is not managed; run `portman tld add <tld>` first")
            }
            Skip::TcpOnLocalhost => f.write_str(
                ".localhost is HTTP-only because the operating system fixes it to loopback",
            ),
            Skip::TcpWithoutPort => f.write_str("dev.portman.mode=tcp requires dev.portman.port"),
            Skip::NoAddress(mode) => write!(
                f,
                "network mode `{mode}` gives the container no address of its own"
            ),
            Skip::HostTakenBy(id) => write!(f, "container {id} is newer and holds the hostname"),
            Skip::HostHeldBy(source) => {
                let route = match source {
                    Source::Static => "a static rule",
                    Source::Service => "a service route",
                    Source::Egress => "an egress route",
                    Source::Builtin | Source::Container | Source::Unknown => "another route",
                };
                write!(f, "{route} holds the hostname")
            }
        }
    }
}

/// The container routes for `containers`. When several containers claim one
/// host, the newest `created` that has an address holds it, and on a tie the
/// lower id. A claimant newer than the holder waits for its address, and an
/// older one is skipped.
pub(crate) fn plan(containers: &[Container], host_is_routable: impl Fn(&str) -> bool) -> Plan {
    let mut newest_first: Vec<&Container> = containers.iter().collect();
    newest_first.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));

    let mut plan = Plan::default();
    let mut claims: BTreeMap<String, Vec<(&Container, String)>> = BTreeMap::new();
    for container in newest_first {
        match claim(container, &host_is_routable) {
            Ok((host, port)) => claims.entry(host).or_default().push((container, port)),
            Err(reason) => plan.skipped.push(Skipped {
                id: short(&container.id).to_string(),
                host: container.host.clone(),
                reason,
            }),
        }
    }

    for (host, claimants) in claims {
        let mut holder: Option<String> = None;
        for (container, port) in claimants {
            let id = short(&container.id).to_string();
            match (&holder, pick_address(&container.addresses)) {
                (Some(holder), _) => plan.skipped.push(Skipped {
                    id,
                    host: container.host.clone(),
                    reason: Skip::HostTakenBy(holder.clone()),
                }),
                (None, Some(ip)) => {
                    plan.entries.push(Entry {
                        host: host.clone(),
                        target: format!("{ip}:{port}"),
                        source: Source::Container,
                        mode: container.mode,
                        container_id: Some(id.clone()),
                        project: container.project.clone(),
                        egress: None,
                    });
                    holder = Some(id);
                }
                (None, None) => plan.waiting.push(id),
            }
        }
    }
    plan
}

/// The normalized host and the port `container` asks for.
fn claim(
    container: &Container,
    host_is_routable: impl Fn(&str) -> bool,
) -> Result<(String, String), Skip> {
    let host = portman_core::static_store::validate_host(&container.host)
        .map_err(|err| Skip::InvalidHost(err.to_string()))?;
    if host == portman_core::registry::DASHBOARD_HOST {
        return Err(Skip::ReservedHost);
    }
    if !host_is_routable(&host) {
        return Err(Skip::UnmanagedTld);
    }
    if container.mode == Mode::Tcp && portman_core::tld::host_is_localhost(&host) {
        return Err(Skip::TcpOnLocalhost);
    }
    let port = match (&container.port, container.mode) {
        (Some(port), _) => port.clone(),
        (None, Mode::Tcp) => return Err(Skip::TcpWithoutPort),
        (None, Mode::Http | Mode::Egress | Mode::Unknown) => "80".to_string(),
    };
    if let Some(mode) = &container.unaddressable {
        return Err(Skip::NoAddress(mode.clone()));
    }
    Ok((host, port))
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// The address on the `portman` network, otherwise the address on the network
/// whose name sorts first.
pub(crate) fn pick_address(addresses: &[(String, Ipv4Addr)]) -> Option<Ipv4Addr> {
    addresses
        .iter()
        .min_by_key(|&(network, _)| (network != PORTMAN_NETWORK, network))
        .map(|&(_, ip)| ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{
        ContainerSummaryHostConfig, ContainerSummaryNetworkSettings, EndpointSettings,
    };
    use std::collections::HashMap;

    const ID_A: &str = "aaaaaaaaaaaa1111";
    const ID_B: &str = "bbbbbbbbbbbb2222";

    fn on(network: &str, ip: [u8; 4]) -> (String, Ipv4Addr) {
        (network.to_string(), Ipv4Addr::from(ip))
    }

    fn container(id: &str, host: &str) -> Container {
        Container {
            id: id.into(),
            created: 100,
            host: host.into(),
            port: None,
            mode: Mode::Http,
            project: None,
            addresses: vec![on("bridge", [172, 17, 0, 2])],
            unaddressable: None,
        }
    }

    fn managed(host: &str) -> bool {
        host.ends_with(".test") || host.ends_with(".localhost")
    }

    #[test]
    fn pick_address_prefers_the_portman_network_then_the_first_name() {
        let portman = [192, 168, 99, 130];
        let bridge = [172, 17, 0, 2];
        let compose = [172, 18, 0, 2];
        let check = |networks: &[(&str, [u8; 4])], expected: Option<[u8; 4]>| {
            let addresses: Vec<_> = networks.iter().map(|&(name, ip)| on(name, ip)).collect();
            assert_eq!(
                pick_address(&addresses),
                expected.map(Ipv4Addr::from),
                "{networks:?}"
            );
        };

        check(&[], None);
        check(&[("bridge", bridge)], Some(bridge));
        check(&[("bridge", bridge), ("portman", portman)], Some(portman));
        check(
            &[("demo_default", compose), ("portman", portman)],
            Some(portman),
        );
        check(
            &[("demo_default", compose), ("bridge", bridge)],
            Some(bridge),
        );
        check(&[("zeta", compose), ("quay", bridge)], Some(bridge));
    }

    #[test]
    fn pick_address_ignores_the_order_networks_arrive_in() {
        let mut addresses = vec![
            on("demo_default", [172, 18, 0, 2]),
            on("bridge", [172, 17, 0, 2]),
            on("acme_backend", [172, 19, 0, 2]),
        ];
        let first = pick_address(&addresses);
        assert_eq!(first, Some(Ipv4Addr::new(172, 19, 0, 2)));
        for _ in 0..addresses.len() {
            addresses.rotate_left(1);
            assert_eq!(pick_address(&addresses), first);
        }
    }

    #[test]
    fn plan_registers_a_container_at_its_picked_address() {
        let web = Container {
            host: "Web.Demo.Test".into(),
            port: Some("3000".into()),
            project: Some("demo".into()),
            addresses: vec![
                on("bridge", [172, 17, 0, 2]),
                on("portman", [192, 168, 99, 130]),
            ],
            ..container(ID_A, "")
        };

        let plan = plan(&[web], managed);

        assert_eq!(
            plan.entries,
            vec![Entry {
                host: "web.demo.test".into(),
                target: "192.168.99.130:3000".into(),
                source: Source::Container,
                mode: Mode::Http,
                container_id: Some("aaaaaaaaaaaa".into()),
                project: Some("demo".into()),
                egress: None,
            }]
        );
        assert!(plan.waiting.is_empty());
        assert!(plan.skipped.is_empty());
    }

    #[test]
    fn plan_defaults_the_port_to_80_except_for_tcp() {
        let http = container(ID_A, "web.demo.test");
        let tcp = Container {
            mode: Mode::Tcp,
            ..container(ID_B, "db.demo.test")
        };
        let tcp_with_port = Container {
            port: Some("5432".into()),
            ..tcp.clone()
        };

        let without_port = plan(&[http.clone(), tcp], managed);
        assert_eq!(without_port.entries.len(), 1);
        assert_eq!(without_port.entries[0].target, "172.17.0.2:80");
        assert_eq!(
            without_port.skipped,
            vec![Skipped {
                id: "bbbbbbbbbbbb".into(),
                host: "db.demo.test".into(),
                reason: Skip::TcpWithoutPort,
            }]
        );

        let with_port = plan(&[http, tcp_with_port], managed);
        let db = with_port
            .entries
            .iter()
            .find(|entry| entry.host == "db.demo.test")
            .expect("tcp container with a port registers");
        assert_eq!(db.target, "172.17.0.2:5432");
        assert_eq!(db.mode, Mode::Tcp);
    }

    #[test]
    fn plan_waits_for_a_container_without_an_address() {
        let starting = Container {
            addresses: vec![],
            ..container(ID_A, "web.demo.test")
        };

        let plan = plan(&[starting, container(ID_B, "api.demo.test")], managed);

        assert_eq!(plan.waiting, vec!["aaaaaaaaaaaa"]);
        let hosts: Vec<&str> = plan.entries.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, vec!["api.demo.test"]);
        assert!(plan.skipped.is_empty());
    }

    #[test]
    fn plan_gives_a_contested_host_to_the_newest_container() {
        let older = Container {
            created: 100,
            addresses: vec![on("bridge", [172, 17, 0, 2])],
            ..container(ID_B, "web.demo.test")
        };
        let newer = Container {
            created: 102,
            addresses: vec![on("bridge", [172, 17, 0, 3])],
            ..container(ID_A, "web.demo.test")
        };
        let loser = Skipped {
            id: "bbbbbbbbbbbb".into(),
            host: "web.demo.test".into(),
            reason: Skip::HostTakenBy("aaaaaaaaaaaa".into()),
        };

        for containers in [[older.clone(), newer.clone()], [newer, older]] {
            let plan = plan(&containers, managed);
            assert_eq!(plan.entries.len(), 1);
            assert_eq!(plan.entries[0].target, "172.17.0.3:80");
            assert_eq!(
                plan.entries[0].container_id.as_deref(),
                Some("aaaaaaaaaaaa")
            );
            assert_eq!(plan.skipped, vec![loser.clone()]);
        }
    }

    #[test]
    fn plan_breaks_a_created_tie_by_id() {
        let low = Container {
            addresses: vec![on("bridge", [172, 17, 0, 2])],
            ..container(ID_A, "web.demo.test")
        };
        let high = Container {
            addresses: vec![on("bridge", [172, 17, 0, 3])],
            ..container(ID_B, "web.demo.test")
        };

        for containers in [[low.clone(), high.clone()], [high, low]] {
            let plan = plan(&containers, managed);
            assert_eq!(plan.entries.len(), 1);
            assert_eq!(
                plan.entries[0].container_id.as_deref(),
                Some("aaaaaaaaaaaa")
            );
        }
    }

    #[test]
    fn plan_skips_with_a_reason() {
        let tcp = |host: &str| Container {
            mode: Mode::Tcp,
            port: Some("5432".into()),
            ..container(ID_A, host)
        };
        let cases = [
            (container(ID_A, "portman.localhost"), Skip::ReservedHost),
            (container(ID_A, "web.acme"), Skip::UnmanagedTld),
            (tcp("db.localhost"), Skip::TcpOnLocalhost),
            (
                Container {
                    port: None,
                    ..tcp("db.demo.test")
                },
                Skip::TcpWithoutPort,
            ),
        ];
        for (container, reason) in cases {
            let host = container.host.clone();
            let plan = plan(&[container], managed);
            assert!(plan.entries.is_empty(), "{host}");
            assert!(plan.waiting.is_empty(), "{host}");
            assert_eq!(
                plan.skipped,
                vec![Skipped {
                    id: "aaaaaaaaaaaa".into(),
                    host,
                    reason,
                }]
            );
        }

        let invalid = plan(&[container(ID_A, "missingdot")], managed);
        assert!(invalid.entries.is_empty());
        assert!(matches!(
            invalid.skipped.as_slice(),
            [Skipped {
                reason: Skip::InvalidHost(_),
                ..
            }]
        ));
    }

    fn summary(labels: &[(&str, &str)], networks: &[(&str, &str)]) -> ContainerSummary {
        ContainerSummary {
            id: Some(ID_A.into()),
            created: Some(1_700_000_000),
            labels: Some(
                labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            network_settings: Some(ContainerSummaryNetworkSettings {
                networks: Some(
                    networks
                        .iter()
                        .map(|(name, ip)| {
                            (
                                name.to_string(),
                                EndpointSettings {
                                    ip_address: Some(ip.to_string()),
                                    ..Default::default()
                                },
                            )
                        })
                        .collect::<HashMap<_, _>>(),
                ),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn observe_reads_labels_and_per_network_addresses() {
        let mut observed = observe(summary(
            &[
                ("dev.portman.host", "db.demo.test"),
                ("dev.portman.port", "5432"),
                ("dev.portman.mode", "tcp"),
                ("dev.portman.project", "demo"),
            ],
            &[("portman", "192.168.99.130"), ("bridge", "172.17.0.2")],
        ))
        .expect("labelled container");
        observed.addresses.sort();

        assert_eq!(
            observed,
            Container {
                id: ID_A.into(),
                created: 1_700_000_000,
                host: "db.demo.test".into(),
                port: Some("5432".into()),
                mode: Mode::Tcp,
                project: Some("demo".into()),
                addresses: vec![
                    on("bridge", [172, 17, 0, 2]),
                    on("portman", [192, 168, 99, 130])
                ],
                unaddressable: None,
            }
        );
    }

    #[test]
    fn observe_marks_a_network_mode_that_never_gives_an_address() {
        let cases = [
            (Some("host"), Some("host")),
            (Some("none"), Some("none")),
            (
                Some("container:cccccccccccc3333"),
                Some("container:cccccccccccc3333"),
            ),
            (Some("bridge"), None),
            (Some("default"), None),
            (Some("demo_default"), None),
            (None, None),
        ];
        for (mode, expected) in cases {
            let mut listed = summary(&[("dev.portman.host", "web.demo.test")], &[]);
            listed.host_config = mode.map(|mode| ContainerSummaryHostConfig {
                network_mode: Some(mode.into()),
                ..Default::default()
            });

            let observed = observe(listed).expect("labelled container");

            assert_eq!(observed.unaddressable.as_deref(), expected, "{mode:?}");
        }
    }

    #[test]
    fn plan_skips_a_container_that_can_never_get_an_address() {
        let host_network = Container {
            created: 200,
            addresses: vec![],
            unaddressable: Some("host".into()),
            ..container(ID_A, "web.demo.test")
        };
        let addressed = container(ID_B, "web.demo.test");

        let plan = plan(&[host_network, addressed], managed);

        assert!(plan.waiting.is_empty());
        assert_eq!(
            plan.skipped,
            vec![Skipped {
                id: "aaaaaaaaaaaa".into(),
                host: "web.demo.test".into(),
                reason: Skip::NoAddress("host".into()),
            }]
        );
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(
            plan.entries[0].container_id.as_deref(),
            Some("bbbbbbbbbbbb")
        );
    }

    #[test]
    fn plan_keeps_a_host_with_the_addressed_container_while_a_newer_one_waits() {
        let addressed = Container {
            created: 100,
            ..container(ID_B, "web.demo.test")
        };
        let starting = Container {
            created: 200,
            addresses: vec![],
            ..container(ID_A, "web.demo.test")
        };

        for containers in [[addressed.clone(), starting.clone()], [starting, addressed]] {
            let plan = plan(&containers, managed);
            assert_eq!(plan.entries.len(), 1);
            assert_eq!(plan.entries[0].target, "172.17.0.2:80");
            assert_eq!(
                plan.entries[0].container_id.as_deref(),
                Some("bbbbbbbbbbbb")
            );
            assert_eq!(plan.waiting, vec!["aaaaaaaaaaaa"]);
            assert!(plan.skipped.is_empty());
        }
    }

    #[test]
    fn plan_waits_for_every_claimant_while_none_has_an_address() {
        let older = Container {
            created: 100,
            addresses: vec![],
            ..container(ID_B, "web.demo.test")
        };
        let newer = Container {
            created: 200,
            addresses: vec![],
            ..container(ID_A, "web.demo.test")
        };

        let plan = plan(&[older, newer], managed);

        assert!(plan.entries.is_empty());
        assert_eq!(plan.waiting, vec!["aaaaaaaaaaaa", "bbbbbbbbbbbb"]);
        assert!(plan.skipped.is_empty());
    }

    #[test]
    fn observe_never_counts_host_none_or_an_empty_address() {
        let observed = observe(summary(
            &[("dev.portman.host", "web.demo.test")],
            &[
                ("host", "192.168.5.15"),
                ("none", "10.0.0.9"),
                ("demo_default", ""),
            ],
        ))
        .expect("labelled container");

        assert_eq!(observed.addresses, vec![]);
        assert_eq!(observed.port, None);
        assert_eq!(observed.mode, Mode::Http);
    }

    #[test]
    fn observe_ignores_a_container_without_a_host_label() {
        assert_eq!(
            observe(summary(
                &[("dev.portman.port", "3000")],
                &[("bridge", "172.17.0.2")]
            )),
            None
        );
        assert_eq!(
            observe(summary(
                &[("dev.portman.host", "")],
                &[("bridge", "172.17.0.2")]
            )),
            None
        );
    }
}
