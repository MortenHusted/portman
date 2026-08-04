use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::Duration;

use portman_protocol::NetbridgeMode;
use serde_json::Value;

pub(crate) const SETUP_IMAGE: &str = "portman-netbridge/setup:local";
const DOCKER_MAC_NET_CONNECT_PLIST: &str =
    "/Library/LaunchDaemons/homebrew.mxcl.docker-mac-net-connect.plist";
const LABEL_HOST: &str = "dev.portman.host";
const CONTAINER_FACING_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 99, 1);
const ENDPOINT_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DaemonSnapshot {
    pub reachable: bool,
    pub version: Option<String>,
    pub bridge_assessment: Option<portman_protocol::BridgeAssessment>,
    pub bridge_enabled: Option<bool>,
    pub bridge_mode: Option<NetbridgeMode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SetupImageStatus {
    Present { id: String, created: String },
    Missing,
    DockerUnavailable { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LegacyBridgeStatus {
    NotDetected,
    Stopped { detail: String },
    Running { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DockerRouteDiagnostic {
    pub network: String,
    pub subnet: String,
    pub hosts: Vec<String>,
    pub route_iface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DockerRouteStatus {
    Routes(Vec<DockerRouteDiagnostic>),
    NoLabelledContainers,
    DockerUnavailable { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerFacingStatus {
    pub dns: bool,
    pub http: bool,
    pub tls: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DoctorReport {
    pub daemon: DaemonSnapshot,
    pub setup_image: SetupImageStatus,
    pub legacy_bridge: LegacyBridgeStatus,
    pub docker_routes: DockerRouteStatus,
    pub container_facing: ContainerFacingStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LabelledContainer {
    pub id: String,
    pub name: String,
    pub host: String,
    pub networks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupImageBuildCommand {
    pub program: String,
    pub args: Vec<String>,
    pub current_dir: PathBuf,
}

pub(crate) fn inspect_setup_image() -> SetupImageStatus {
    let output = match StdCommand::new("docker")
        .args([
            "image",
            "inspect",
            SETUP_IMAGE,
            "--format",
            "{{.Id}}\t{{.Created}}",
        ])
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            return SetupImageStatus::DockerUnavailable {
                message: err.to_string(),
            };
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such image") || stderr.contains("No such object") {
            return SetupImageStatus::Missing;
        }
        return SetupImageStatus::DockerUnavailable {
            message: stderr.trim().to_string(),
        };
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut parts = stdout.trim().split('\t');
    let id = parts.next().unwrap_or("").to_string();
    let created = parts.next().unwrap_or("").to_string();
    if id.is_empty() {
        SetupImageStatus::Missing
    } else {
        SetupImageStatus::Present { id, created }
    }
}

pub(crate) fn detect_legacy_bridge() -> LegacyBridgeStatus {
    if let Some(output) = command_stdout("pgrep", &["-fl", "docker-mac-net-connect|chipmk"]) {
        let detail = output
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .unwrap_or("docker-mac-net-connect process detected")
            .to_string();
        return LegacyBridgeStatus::Running { detail };
    }

    if let Some(output) = command_stdout("brew", &["services", "list"]) {
        for line in output.lines() {
            if !line.contains("docker-mac-net-connect") {
                continue;
            }
            if line.contains("started") {
                return LegacyBridgeStatus::Running {
                    detail: line.trim().to_string(),
                };
            }
            return LegacyBridgeStatus::Stopped {
                detail: line.trim().to_string(),
            };
        }
    }

    if Path::new(DOCKER_MAC_NET_CONNECT_PLIST).exists() {
        return LegacyBridgeStatus::Stopped {
            detail: DOCKER_MAC_NET_CONNECT_PLIST.to_string(),
        };
    }

    LegacyBridgeStatus::NotDetected
}

pub(crate) fn collect_docker_routes() -> DockerRouteStatus {
    let ids_output = match docker_stdout(&["ps", "--filter", "label=dev.portman.host", "-q"]) {
        Ok(output) => output,
        Err(message) => return DockerRouteStatus::DockerUnavailable { message },
    };
    let ids: Vec<&str> = ids_output.split_ascii_whitespace().collect();
    if ids.is_empty() {
        return DockerRouteStatus::NoLabelledContainers;
    }

    let mut inspect_args = vec!["container", "inspect"];
    inspect_args.extend(ids.iter().copied());
    let container_json = match docker_stdout(&inspect_args) {
        Ok(output) => output,
        Err(message) => return DockerRouteStatus::DockerUnavailable { message },
    };
    let containers = parse_labelled_containers(&container_json);
    if containers.is_empty() {
        return DockerRouteStatus::NoLabelledContainers;
    }

    let networks: BTreeSet<&str> = containers
        .iter()
        .flat_map(|container| container.networks.iter().map(String::as_str))
        .filter(|network| *network != "host" && *network != "none")
        .collect();
    if networks.is_empty() {
        return DockerRouteStatus::NoLabelledContainers;
    }

    let mut network_args = vec!["network", "inspect"];
    network_args.extend(networks.iter().copied());
    let network_json = match docker_stdout(&network_args) {
        Ok(output) => output,
        Err(message) => return DockerRouteStatus::DockerUnavailable { message },
    };

    DockerRouteStatus::Routes(route_diagnostics_from_networks_json(
        &network_json,
        &containers,
        route_interface_for_cidr,
    ))
}

pub(crate) fn inspect_container_facing() -> ContainerFacingStatus {
    ContainerFacingStatus {
        dns: tcp_port_open(CONTAINER_FACING_IP, 53),
        http: tcp_port_open(CONTAINER_FACING_IP, 80),
        tls: tcp_port_open(CONTAINER_FACING_IP, 443),
    }
}

/// Every doctor check reduces to this one shape: a classification, the
/// rendered lines, and whether the check gates "replacement: ready".
/// Classification and rendering come from the same function per check, so
/// readiness can never be re-derived out of sync with what's displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckState {
    Ok,
    Warn,
    Fail,
}

struct CheckOutcome {
    state: CheckState,
    lines: Vec<String>,
    /// Informational checks (container-facing endpoints) don't gate
    /// readiness; everything else does.
    gates_ready: bool,
}

impl CheckOutcome {
    fn gating(state: CheckState, line: String) -> Self {
        Self {
            state,
            lines: vec![line],
            gates_ready: true,
        }
    }

    fn informational(state: CheckState, line: String) -> Self {
        Self {
            state,
            lines: vec![line],
            gates_ready: false,
        }
    }
}

fn replacement_ready(outcomes: &[CheckOutcome]) -> bool {
    outcomes
        .iter()
        .filter(|outcome| outcome.gates_ready)
        .all(|outcome| outcome.state == CheckState::Ok)
}

pub(crate) fn render_report(report: &DoctorReport) -> String {
    let legacy = check_legacy_bridge(&report.legacy_bridge);
    let legacy_running = legacy.state != CheckState::Ok;
    let outcomes = [
        check_daemon(&report.daemon),
        check_setup_image(&report.setup_image),
        legacy,
        check_container_facing(&report.container_facing),
        check_docker_routes(&report.docker_routes),
    ];
    let ready = replacement_ready(&outcomes);

    let mut lines = Vec::new();
    lines.push("Portman doctor".to_string());
    lines.push(format!(
        "replacement: {}",
        if ready { "ready" } else { "needs attention" }
    ));
    for outcome in &outcomes {
        lines.extend(outcome.lines.iter().cloned());
    }

    // Guidance is conditional: printing "stop the legacy bridge" on a clean
    // machine hands users alarming instructions for a service they don't
    // have, and the enable hint is noise once the replacement is ready.
    if legacy_running || !ready {
        lines.push("guidance:".to_string());
        if !ready {
            lines.push(
                "  use `portman bridge mode docker` and `portman bridge enable` for labelled Docker bridge replacement"
                    .to_string(),
            );
        }
        if legacy_running {
            lines.push("  Portman did not stop it automatically.".to_string());
            lines.push("  to stop the legacy bridge when you are ready:".to_string());
            lines.push("    sudo brew services stop docker-mac-net-connect".to_string());
            lines.push(format!(
                "    sudo launchctl bootout system {DOCKER_MAC_NET_CONNECT_PLIST}"
            ));
        }
    }

    lines.join("\n") + "\n"
}

fn check_docker_routes(status: &DockerRouteStatus) -> CheckOutcome {
    let state = match status {
        DockerRouteStatus::Routes(routes) => {
            let all_utun = !routes.is_empty()
                && routes.iter().all(|route| {
                    route
                        .route_iface
                        .as_deref()
                        .is_some_and(|iface| iface.starts_with("utun"))
                });
            if all_utun {
                CheckState::Ok
            } else {
                CheckState::Warn
            }
        }
        DockerRouteStatus::NoLabelledContainers => CheckState::Ok,
        DockerRouteStatus::DockerUnavailable { .. } => CheckState::Fail,
    };
    CheckOutcome {
        state,
        lines: render_docker_routes(status),
        gates_ready: true,
    }
}

pub(crate) fn render_docker_routes(status: &DockerRouteStatus) -> Vec<String> {
    match status {
        DockerRouteStatus::Routes(routes) if routes.is_empty() => {
            vec!["labelled docker networks: none".to_string()]
        }
        DockerRouteStatus::Routes(routes) => {
            let mut lines = vec!["labelled docker networks:".to_string()];
            for route in routes {
                let iface = route.route_iface.as_deref().unwrap_or("missing route");
                lines.push(format!(
                    "  {} {} via {} hosts {}",
                    route.network,
                    route.subnet,
                    iface,
                    route.hosts.join(", ")
                ));
            }
            lines
        }
        DockerRouteStatus::NoLabelledContainers => {
            vec!["labelled docker networks: no running dev.portman.host containers".to_string()]
        }
        DockerRouteStatus::DockerUnavailable { message } => {
            vec![format!("labelled docker networks: unavailable ({message})")]
        }
    }
}

pub(crate) fn parse_labelled_containers(inspect_json: &str) -> Vec<LabelledContainer> {
    let Ok(value) = serde_json::from_str::<Value>(inspect_json) else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        return Vec::new();
    };

    let mut containers = Vec::new();
    for item in items {
        let Some(host) = item
            .pointer("/Config/Labels")
            .and_then(Value::as_object)
            .and_then(|labels| labels.get(LABEL_HOST))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|host| !host.is_empty())
        else {
            continue;
        };
        let networks = item
            .pointer("/NetworkSettings/Networks")
            .and_then(Value::as_object)
            .map(|networks| {
                let mut names: Vec<String> = networks.keys().cloned().collect();
                names.sort();
                names
            })
            .unwrap_or_default();
        containers.push(LabelledContainer {
            id: item
                .get("Id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            name: item
                .get("Name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim_start_matches('/')
                .to_string(),
            host: host.to_string(),
            networks,
        });
    }
    containers
}

pub(crate) fn parse_route_get_interface(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix("interface:")
            .map(str::trim)
            .filter(|iface| !iface.is_empty())
            .map(ToString::to_string)
    })
}

pub(crate) fn setup_image_build_command(context_dir: &Path) -> SetupImageBuildCommand {
    SetupImageBuildCommand {
        program: "docker".to_string(),
        args: vec![
            "build".to_string(),
            "-t".to_string(),
            SETUP_IMAGE.to_string(),
            ".".to_string(),
        ],
        current_dir: context_dir.to_path_buf(),
    }
}

fn check_daemon(daemon: &DaemonSnapshot) -> CheckOutcome {
    if !daemon.reachable {
        return CheckOutcome::gating(CheckState::Fail, "daemon: unreachable".to_string());
    }
    // Ready needs the replacement actually routing: bridge enabled, docker mode.
    let state = if daemon.bridge_enabled == Some(true)
        && daemon.bridge_mode == Some(NetbridgeMode::Docker)
    {
        CheckState::Ok
    } else {
        CheckState::Warn
    };
    let line = format!(
        "daemon: ok{} bridge: {} netbridge: {} mode: {}",
        daemon
            .version
            .as_deref()
            .map(|version| format!(" v{version}"))
            .unwrap_or_default(),
        daemon.bridge_assessment.unwrap_or_default().as_str(),
        if daemon.bridge_enabled.unwrap_or(false) {
            "enabled"
        } else {
            "disabled"
        },
        daemon
            .bridge_mode
            .map(NetbridgeMode::display_word)
            .unwrap_or("unknown")
    );
    CheckOutcome::gating(state, line)
}

fn check_setup_image(status: &SetupImageStatus) -> CheckOutcome {
    match status {
        SetupImageStatus::Present { id, created } => {
            let short_id = id
                .strip_prefix("sha256:")
                .unwrap_or(id)
                .chars()
                .take(12)
                .collect::<String>();
            CheckOutcome::gating(
                CheckState::Ok,
                format!("setup image: present {SETUP_IMAGE} {short_id} created {created}"),
            )
        }
        SetupImageStatus::Missing => CheckOutcome::gating(
            CheckState::Warn,
            format!("setup image: missing {SETUP_IMAGE} (run `portman bridge prepare`)"),
        ),
        SetupImageStatus::DockerUnavailable { message } => CheckOutcome::gating(
            CheckState::Fail,
            format!("setup image: unavailable ({message})"),
        ),
    }
}

fn check_legacy_bridge(status: &LegacyBridgeStatus) -> CheckOutcome {
    match status {
        LegacyBridgeStatus::NotDetected => {
            CheckOutcome::gating(CheckState::Ok, "legacy bridge: not detected".to_string())
        }
        LegacyBridgeStatus::Stopped { detail } => {
            CheckOutcome::gating(CheckState::Ok, format!("legacy bridge: stopped ({detail})"))
        }
        LegacyBridgeStatus::Running { detail } => CheckOutcome::gating(
            CheckState::Warn,
            format!("legacy bridge: running ({detail})"),
        ),
    }
}

fn check_container_facing(status: &ContainerFacingStatus) -> CheckOutcome {
    let state = if status.dns && status.http && status.tls {
        CheckState::Ok
    } else {
        CheckState::Warn
    };
    CheckOutcome::informational(
        state,
        format!(
            "container-facing: dns 192.168.99.1:53 {}  http 192.168.99.1:80 {}  tls 192.168.99.1:443 {}",
            endpoint_word(status.dns),
            endpoint_word(status.http),
            endpoint_word(status.tls),
        ),
    )
}

fn endpoint_word(open: bool) -> &'static str {
    if open {
        "open"
    } else {
        "closed"
    }
}

fn route_diagnostics_from_networks_json(
    network_json: &str,
    containers: &[LabelledContainer],
    route_lookup: impl Fn(&str) -> Option<String>,
) -> Vec<DockerRouteDiagnostic> {
    let Ok(value) = serde_json::from_str::<Value>(network_json) else {
        return Vec::new();
    };
    let Some(networks) = value.as_array() else {
        return Vec::new();
    };

    let hosts_by_network = hosts_by_network(containers);
    let mut diagnostics = Vec::new();
    for network in networks {
        if network.get("Driver").and_then(Value::as_str) != Some("bridge") {
            continue;
        }
        let Some(name) = network.get("Name").and_then(Value::as_str) else {
            continue;
        };
        let Some(hosts) = hosts_by_network.get(name) else {
            continue;
        };
        let Some(configs) = network.pointer("/IPAM/Config").and_then(Value::as_array) else {
            continue;
        };
        for config in configs {
            let Some(subnet) = config.get("Subnet").and_then(Value::as_str) else {
                continue;
            };
            diagnostics.push(DockerRouteDiagnostic {
                network: name.to_string(),
                subnet: subnet.to_string(),
                hosts: hosts.clone(),
                route_iface: route_lookup(subnet),
            });
        }
    }
    diagnostics.sort_by(|a, b| a.network.cmp(&b.network).then(a.subnet.cmp(&b.subnet)));
    diagnostics
}

fn hosts_by_network(containers: &[LabelledContainer]) -> BTreeMap<String, Vec<String>> {
    let mut hosts_by_network: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for container in containers {
        for network in &container.networks {
            hosts_by_network
                .entry(network.clone())
                .or_default()
                .insert(container.host.clone());
        }
    }
    hosts_by_network
        .into_iter()
        .map(|(network, hosts)| (network, hosts.into_iter().collect()))
        .collect()
}

fn route_interface_for_cidr(cidr: &str) -> Option<String> {
    let addr = cidr.split('/').next()?;
    let output = StdCommand::new("/sbin/route")
        .args(["-n", "get", addr])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_route_get_interface(&String::from_utf8_lossy(&output.stdout))
}

fn docker_stdout(args: &[&str]) -> Result<String, String> {
    let output = StdCommand::new("docker")
        .args(args)
        .output()
        .map_err(|err| err.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("docker {args:?} exited with {}", output.status)
        } else {
            stderr
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = StdCommand::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn tcp_port_open(ip: Ipv4Addr, port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), ENDPOINT_TIMEOUT).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docker_daemon() -> DaemonSnapshot {
        DaemonSnapshot {
            reachable: true,
            version: Some("0.0.1".to_string()),
            bridge_assessment: Some(portman_protocol::BridgeAssessment::Healthy),
            bridge_enabled: Some(true),
            bridge_mode: Some(NetbridgeMode::Docker),
        }
    }

    fn open_container_facing() -> ContainerFacingStatus {
        ContainerFacingStatus {
            dns: true,
            http: true,
            tls: true,
        }
    }

    #[test]
    fn doctor_report_marks_docker_mode_ready_when_routes_are_owned() {
        let report = DoctorReport {
            daemon: docker_daemon(),
            setup_image: SetupImageStatus::Present {
                id: "sha256:a3884c".to_string(),
                created: "2026-04-24T07:48:00Z".to_string(),
            },
            legacy_bridge: LegacyBridgeStatus::NotDetected,
            docker_routes: DockerRouteStatus::Routes(vec![DockerRouteDiagnostic {
                network: "dev_default".to_string(),
                subnet: "172.18.0.0/16".to_string(),
                hosts: vec![
                    "mysql84.acme.internal".to_string(),
                    "mysql.archival.internal".to_string(),
                ],
                route_iface: Some("utun10".to_string()),
            }]),
            container_facing: open_container_facing(),
        };

        let rendered = render_report(&report);

        assert!(rendered.contains("replacement: ready"));
        assert!(rendered.contains("mode: docker"));
        assert!(rendered.contains("setup image: present"));
        assert!(rendered.contains("container-facing: dns 192.168.99.1:53 open"));
        assert!(rendered.contains("http 192.168.99.1:80 open"));
        assert!(rendered.contains("tls 192.168.99.1:443 open"));
        assert!(rendered.contains("dev_default 172.18.0.0/16 via utun10"));
        assert!(rendered.contains("mysql84.acme.internal, mysql.archival.internal"));
        // Clean machine, replacement ready: no alarming instructions for a
        // legacy service that doesn't exist, no redundant enable hint.
        assert!(!rendered.contains("guidance:"), "{rendered}");
        assert!(!rendered.contains("stop the legacy bridge"), "{rendered}");
        assert!(!rendered.contains("brew services stop"), "{rendered}");
    }

    #[test]
    fn doctor_report_warns_when_legacy_bridge_is_running_without_mutating_it() {
        let report = DoctorReport {
            daemon: docker_daemon(),
            setup_image: SetupImageStatus::Present {
                id: "sha256:a3884c".to_string(),
                created: "2026-04-24T07:48:00Z".to_string(),
            },
            legacy_bridge: LegacyBridgeStatus::Running {
                detail: "docker-mac-net-connect pid 1234".to_string(),
            },
            docker_routes: DockerRouteStatus::Routes(vec![DockerRouteDiagnostic {
                network: "dev_default".to_string(),
                subnet: "172.18.0.0/16".to_string(),
                hosts: vec!["mysql84.acme.internal".to_string()],
                route_iface: Some("utun8".to_string()),
            }]),
            container_facing: open_container_facing(),
        };

        let rendered = render_report(&report);

        assert!(rendered.contains("legacy bridge: running"));
        assert!(rendered.contains("Portman did not stop it automatically"));
        assert!(rendered.contains("sudo brew services stop docker-mac-net-connect"));
        assert!(rendered.contains(
            "sudo launchctl bootout system /Library/LaunchDaemons/homebrew.mxcl.docker-mac-net-connect.plist"
        ));
    }

    #[test]
    fn parses_labelled_containers_from_docker_inspect_json() {
        let containers = parse_labelled_containers(
            r#"
[
  {
    "Id": "abc123",
    "Name": "/mysql84",
    "Config": { "Labels": { "dev.portman.host": "mysql84.acme.internal" } },
    "NetworkSettings": {
      "Networks": {
        "dev_default": {},
        "portman": {}
      }
    }
  },
  {
    "Id": "def456",
    "Name": "/ignored",
    "Config": { "Labels": { "other": "1" } },
    "NetworkSettings": { "Networks": { "dev_default": {} } }
  }
]
"#,
        );

        assert_eq!(
            containers,
            vec![LabelledContainer {
                id: "abc123".to_string(),
                name: "mysql84".to_string(),
                host: "mysql84.acme.internal".to_string(),
                networks: vec!["dev_default".to_string(), "portman".to_string()],
            }]
        );
    }

    #[test]
    fn parses_route_get_interface() {
        let output = "\
   route to: 172.18.0.0
destination: 172.18.0.0
  interface: utun10
";

        assert_eq!(
            parse_route_get_interface(output),
            Some("utun10".to_string())
        );
        assert_eq!(parse_route_get_interface("destination: default\n"), None);
    }

    #[test]
    fn maps_labelled_network_subnets_to_route_interfaces() {
        let containers = vec![
            LabelledContainer {
                id: "abc123".to_string(),
                name: "mysql84".to_string(),
                host: "mysql84.acme.internal".to_string(),
                networks: vec!["dev_default".to_string()],
            },
            LabelledContainer {
                id: "def456".to_string(),
                name: "pg".to_string(),
                host: "pg.acme.internal".to_string(),
                networks: vec!["portman".to_string()],
            },
        ];
        let routes = route_diagnostics_from_networks_json(
            r#"
[
  {
    "Name": "dev_default",
    "Driver": "bridge",
    "IPAM": { "Config": [ { "Subnet": "172.18.0.0/16" } ] }
  },
  {
    "Name": "host",
    "Driver": "host",
    "IPAM": { "Config": [ { "Subnet": "ignored" } ] }
  },
  {
    "Name": "portman",
    "Driver": "bridge",
    "IPAM": { "Config": [ { "Subnet": "192.168.99.128/25" } ] }
  }
]
"#,
            &containers,
            |subnet| match subnet {
                "172.18.0.0/16" => Some("utun10".to_string()),
                _ => None,
            },
        );

        assert_eq!(
            routes,
            vec![
                DockerRouteDiagnostic {
                    network: "dev_default".to_string(),
                    subnet: "172.18.0.0/16".to_string(),
                    hosts: vec!["mysql84.acme.internal".to_string()],
                    route_iface: Some("utun10".to_string()),
                },
                DockerRouteDiagnostic {
                    network: "portman".to_string(),
                    subnet: "192.168.99.128/25".to_string(),
                    hosts: vec!["pg.acme.internal".to_string()],
                    route_iface: None,
                },
            ]
        );
    }

    #[test]
    fn setup_image_build_command_builds_from_the_given_context_dir() {
        let cmd = setup_image_build_command(Path::new("/tmp/portman-setup-image"));
        assert_eq!(cmd.program, "docker");
        assert_eq!(
            cmd.args,
            vec![
                "build".to_string(),
                "-t".to_string(),
                SETUP_IMAGE.to_string(),
                ".".to_string(),
            ]
        );
        assert_eq!(cmd.current_dir, Path::new("/tmp/portman-setup-image"));
    }
}
