use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::Duration;

use portman_protocol::{BridgePhase, DockerState, DockerStatus, NetbridgeMode, Response};
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
    pub bridge_phase: Option<BridgePhase>,
    pub bridge_mode: Option<NetbridgeMode>,
    /// `None` also for a daemon that predates the field.
    pub docker: Option<DockerStatus>,
}

impl DaemonSnapshot {
    /// `None` is a daemon that did not answer.
    pub(crate) fn from_status(status: Option<Response>) -> Self {
        match status {
            Some(Response::Status {
                version,
                bridge_assessment,
                bridge_enabled,
                bridge_phase,
                bridge_mode,
                docker,
                ..
            }) => Self {
                reachable: true,
                version: Some(version),
                bridge_assessment: Some(bridge_assessment),
                bridge_phase: Some(bridge_phase.or_from_enabled(bridge_enabled)),
                bridge_mode: Some(bridge_mode),
                docker,
            },
            _ => Self {
                reachable: false,
                version: None,
                bridge_assessment: None,
                bridge_phase: None,
                bridge_mode: None,
                docker: None,
            },
        }
    }
}

/// Why a `docker` CLI call gave no output to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DockerCliError {
    /// The `docker` program did not start, as when none is installed.
    NotStarted(String),
    /// The CLI reached no engine.
    NoAnswer(String),
    /// Any other failure. An engine that answers with an error, as it does
    /// for a container that is gone, ends here.
    Failed(String),
}

impl std::fmt::Display for DockerCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (DockerCliError::NotStarted(message)
        | DockerCliError::NoAnswer(message)
        | DockerCliError::Failed(message)) = self;
        f.write_str(message)
    }
}

/// What one check learned from the `docker` CLI: that an engine answered,
/// or why the CLI gave nothing.
pub(crate) type CliAnswer<'a> = Result<(), &'a DockerCliError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SetupImageStatus {
    Present { id: String, created: String },
    Missing,
    Unavailable(DockerCliError),
}

impl SetupImageStatus {
    pub(crate) fn cli_answer(&self) -> CliAnswer<'_> {
        match self {
            SetupImageStatus::Unavailable(error) => Err(error),
            _ => Ok(()),
        }
    }
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
    Unavailable(DockerCliError),
}

impl DockerRouteStatus {
    pub(crate) fn cli_answer(&self) -> CliAnswer<'_> {
        match self {
            DockerRouteStatus::Unavailable(error) => Err(error),
            _ => Ok(()),
        }
    }
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
    let format = "{{.Id}}\t{{.Created}}";
    let stdout = match docker_stdout(&["image", "inspect", SETUP_IMAGE, "--format", format]) {
        Ok(stdout) => stdout,
        Err(DockerCliError::Failed(message))
            if message.contains("No such image") || message.contains("No such object") =>
        {
            return SetupImageStatus::Missing;
        }
        Err(error) => return SetupImageStatus::Unavailable(error),
    };

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

    if !Path::new(DOCKER_MAC_NET_CONNECT_PLIST).exists() {
        return LegacyBridgeStatus::NotDetected;
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

    LegacyBridgeStatus::Stopped {
        detail: DOCKER_MAC_NET_CONNECT_PLIST.to_string(),
    }
}

pub(crate) fn collect_docker_routes() -> DockerRouteStatus {
    let ids_output = match docker_stdout(&["ps", "--filter", "label=dev.portman.host", "-q"]) {
        Ok(output) => output,
        Err(error) => return DockerRouteStatus::Unavailable(error),
    };
    let ids: Vec<&str> = ids_output.split_ascii_whitespace().collect();
    if ids.is_empty() {
        return DockerRouteStatus::NoLabelledContainers;
    }

    let mut inspect_args = vec!["container", "inspect"];
    inspect_args.extend(ids.iter().copied());
    let container_json = match docker_stdout(&inspect_args) {
        Ok(output) => output,
        Err(error) => return DockerRouteStatus::Unavailable(error),
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
        Err(error) => return DockerRouteStatus::Unavailable(error),
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
    let cli_answers = [
        report.setup_image.cli_answer(),
        report.docker_routes.cli_answer(),
    ];
    let mut outcomes = vec![check_daemon(&report.daemon)];
    outcomes.extend(check_docker(
        report.daemon.docker.as_ref(),
        &cli_answers,
        "setup image and labelled docker networks lines",
    ));
    outcomes.extend([
        check_setup_image(&report.setup_image),
        legacy,
        check_container_facing(&report.container_facing),
        check_docker_routes(&report.docker_routes),
    ]);
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
            lines.extend(
                bridge_guidance(report.daemon.bridge_phase)
                    .iter()
                    .map(|line| format!("  {line}")),
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

/// `portman bridge enable` helps only a bridge that is off. For a bridge
/// that is enabled and not up, it restarts the retry delay and waits.
fn bridge_guidance(phase: Option<BridgePhase>) -> &'static [&'static str] {
    match phase {
        Some(BridgePhase::Starting) => &[
            "netbridge is enabled and not up yet; if a start fails, the daemon tries again",
            "a failed start is in the daemon log as `netbridge start failed`, with the reason (~/Library/Logs/portman/daemon.log when installed)",
            "check the setup image line above and that Docker is running; `portman bridge disable` turns the bridge off",
        ],
        Some(BridgePhase::WaitingForDocker) => &[
            "netbridge is enabled and waits for Docker; start your container runtime",
            "`portman bridge disable` turns the bridge off",
        ],
        Some(BridgePhase::Stopping) => {
            &["netbridge is stopping; run `portman doctor` again when it has stopped"]
        }
        _ => &[
            "use `portman bridge mode docker` and `portman bridge enable` for labelled Docker bridge replacement",
        ],
    }
}

/// The daemon's own view of the engine. A daemon that reports none gets no
/// line. The setup image check and the docker networks check ask the
/// `docker` CLI.
fn check_docker(
    docker: Option<&DockerStatus>,
    cli_answers: &[CliAnswer<'_>],
    cli_lines: &str,
) -> Option<CheckOutcome> {
    let docker = docker?;
    let state = match docker.state {
        DockerState::Disconnected => CheckState::Fail,
        _ => CheckState::Ok,
    };
    let mut lines = vec![format!("docker: {}", docker.summary())];
    lines.extend(docker_cli_note(Some(docker), cli_answers, cli_lines));
    Some(CheckOutcome {
        state,
        lines,
        gates_ready: true,
    })
}

/// The daemon and the `docker` CLI each choose their socket, so one can
/// have an engine while the other has none. The note says so, and names the
/// lines that show the CLI's result. `cli_answers` holds one answer for each
/// check that ran the CLI. A check that failed in another way than
/// [`DockerCliError::NoAnswer`] shows neither that the CLI has an engine nor
/// that it has none, so it brings no note.
pub(crate) fn docker_cli_note(
    docker: Option<&DockerStatus>,
    cli_answers: &[CliAnswer<'_>],
    cli_lines: &str,
) -> Option<String> {
    let no_answer = |answer: &CliAnswer<'_>| matches!(answer, Err(DockerCliError::NoAnswer(_)));
    let found = match docker?.state {
        DockerState::Connected if cli_answers.iter().any(no_answer) => {
            "a check got no answer from an engine, and the daemon is connected to one"
        }
        DockerState::Disconnected if cli_answers.iter().any(Result::is_ok) => {
            "a check reached an engine, and the daemon is connected to none"
        }
        _ => return None,
    };
    Some(format!(
        "docker CLI: {found}; the {cli_lines} below come from the `docker` CLI"
    ))
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
        DockerRouteStatus::Unavailable(_) => CheckState::Fail,
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
        DockerRouteStatus::Unavailable(error) => {
            vec![format!("labelled docker networks: unavailable ({error})")]
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
    // Ready needs the replacement actually routing: bridge up, docker mode.
    let state = if daemon.bridge_phase == Some(BridgePhase::Up)
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
        daemon.bridge_phase.unwrap_or_default().display_word(),
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
        SetupImageStatus::Unavailable(error) => CheckOutcome::gating(
            CheckState::Fail,
            format!("setup image: unavailable ({error})"),
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

fn docker_stdout(args: &[&str]) -> Result<String, DockerCliError> {
    run_docker("docker", args)
}

/// What the `docker` CLI prints when it reaches no engine. Docker 29 names
/// "the docker API", and the releases before it name "the Docker daemon".
const NO_ENGINE: [&str; 3] = [
    "connect to the docker API",
    "connect to the Docker daemon",
    "error during connect",
];

fn run_docker(program: &str, args: &[&str]) -> Result<String, DockerCliError> {
    let output = StdCommand::new(program)
        .args(args)
        .output()
        .map_err(|err| DockerCliError::NotStarted(err.to_string()))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if stderr.is_empty() {
        DockerCliError::Failed(format!("docker {args:?} exited with {}", output.status))
    } else if NO_ENGINE.iter().any(|phrase| stderr.contains(phrase)) {
        DockerCliError::NoAnswer(stderr)
    } else {
        DockerCliError::Failed(stderr)
    })
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
            bridge_phase: Some(BridgePhase::Up),
            bridge_mode: Some(NetbridgeMode::Docker),
            docker: None,
        }
    }

    fn ready_but_for_the_bridge(phase: BridgePhase) -> DoctorReport {
        DoctorReport {
            daemon: DaemonSnapshot {
                bridge_phase: Some(phase),
                ..docker_daemon()
            },
            setup_image: SetupImageStatus::Present {
                id: "sha256:a3884c".to_string(),
                created: "2026-04-24T07:48:00Z".to_string(),
            },
            legacy_bridge: LegacyBridgeStatus::NotDetected,
            docker_routes: DockerRouteStatus::NoLabelledContainers,
            container_facing: open_container_facing(),
        }
    }

    #[test]
    fn doctor_prints_the_phase_and_is_ready_only_for_a_bridge_that_is_up() {
        // phase → (word on the daemon line, ready)
        let table = [
            (BridgePhase::Disabled, "netbridge: disabled mode", false),
            (
                BridgePhase::WaitingForDocker,
                "netbridge: waiting for docker mode",
                false,
            ),
            (BridgePhase::Starting, "netbridge: starting mode", false),
            (BridgePhase::Up, "netbridge: up mode", true),
            (BridgePhase::Stopping, "netbridge: stopping mode", false),
        ];
        for (phase, word, ready) in table {
            let rendered = render_report(&ready_but_for_the_bridge(phase));
            assert!(rendered.contains(word), "phase={phase:?}\n{rendered}");
            assert_eq!(
                rendered.contains("replacement: ready"),
                ready,
                "phase={phase:?}\n{rendered}"
            );
        }
    }

    #[test]
    fn doctor_advises_enable_only_for_a_bridge_that_is_off() {
        // phase → (advises `portman bridge enable`, the advice names)
        let table = [
            (BridgePhase::Disabled, true, "portman bridge mode docker"),
            (BridgePhase::Starting, false, "daemon log"),
            (BridgePhase::Starting, false, "portman bridge disable"),
            (BridgePhase::WaitingForDocker, false, "container runtime"),
            (BridgePhase::Stopping, false, "stopping"),
        ];
        for (phase, advises_enable, names) in table {
            let rendered = render_report(&ready_but_for_the_bridge(phase));
            let guidance = rendered.split("guidance:").nth(1).unwrap_or_default();
            assert_eq!(
                guidance.contains("portman bridge enable"),
                advises_enable,
                "phase={phase:?}\n{rendered}"
            );
            assert!(guidance.contains(names), "phase={phase:?}\n{rendered}");
        }
    }

    #[test]
    fn doctor_reads_the_phase_of_an_older_daemon_from_bridge_enabled() {
        let status = |bridge_enabled: bool| {
            let json = format!(
                r#"{{"kind":"status","version":"0.1.5","running_since":"5s","dns_port":5335,"bridge_enabled":{bridge_enabled}}}"#
            );
            DaemonSnapshot::from_status(Some(serde_json::from_str(&json).unwrap()))
        };

        assert_eq!(status(true).bridge_phase, Some(BridgePhase::Up));
        assert_eq!(status(false).bridge_phase, Some(BridgePhase::Disabled));
    }

    fn connected_docker() -> DockerStatus {
        DockerStatus {
            state: DockerState::Connected,
            socket: Some("/run/demo/docker.sock".to_string()),
            version: Some("29.2.1".to_string()),
            ..DockerStatus::default()
        }
    }

    fn disconnected_docker() -> DockerStatus {
        DockerStatus {
            state: DockerState::Disconnected,
            socket: Some("/run/demo/docker.sock".to_string()),
            reason: Some("no socket".to_string()),
            ..DockerStatus::default()
        }
    }

    fn with_docker(docker: Option<DockerStatus>) -> DoctorReport {
        let mut report = ready_but_for_the_bridge(BridgePhase::Up);
        report.daemon.docker = docker;
        report
    }

    #[test]
    fn doctor_says_whether_docker_is_connected_and_why_not() {
        let connected = render_report(&with_docker(Some(connected_docker())));
        assert!(
            connected.contains("\ndocker: connected to /run/demo/docker.sock, engine 29.2.1\n"),
            "{connected}"
        );
        assert!(connected.contains("replacement: ready"), "{connected}");

        let disconnected = render_report(&with_docker(Some(disconnected_docker())));
        assert!(
            disconnected.contains("\ndocker: disconnected, no socket at /run/demo/docker.sock\n"),
            "{disconnected}"
        );
        assert!(
            disconnected.contains("replacement: needs attention"),
            "{disconnected}"
        );
    }

    #[test]
    fn doctor_prints_no_docker_line_for_a_daemon_that_does_not_report_the_engine() {
        let json = r#"{"kind":"status","version":"0.1.5","running_since":"5s","dns_port":5335}"#;
        let daemon = DaemonSnapshot::from_status(Some(serde_json::from_str(json).unwrap()));
        assert_eq!(daemon.docker, None);

        let rendered = render_report(&with_docker(None));
        assert!(!rendered.contains("\ndocker"), "{rendered}");
        assert!(rendered.contains("replacement: ready"), "{rendered}");
    }

    #[test]
    fn doctor_reads_the_engine_state_that_the_daemon_reports() {
        let json = r#"{"kind":"status","docker":{"state":"disconnected","socket":"/run/demo/docker.sock","reason":"no socket"}}"#;
        let daemon = DaemonSnapshot::from_status(Some(serde_json::from_str(json).unwrap()));
        assert_eq!(daemon.docker, Some(disconnected_docker()));
    }

    #[test]
    fn a_note_says_when_the_docker_cli_and_the_daemon_see_different_engines() {
        let no_engine = DockerCliError::NoAnswer("failed to connect to the docker API".into());
        let gone = DockerCliError::Failed("No such container: 0a1b2c".into());
        let no_program = DockerCliError::NotStarted("No such file or directory".into());
        let answered = &[Ok(())][..];
        let silent = &[Err(&no_engine)][..];
        let mixed = &[Ok(()), Err(&no_engine)][..];
        let refused = &[Err(&gone)][..];
        let not_run = &[Err(&no_program)][..];
        // (the daemon's engine state, what each `docker` CLI check learned)
        // → the note names
        let table = [
            (Some(connected_docker()), answered, None),
            (Some(connected_docker()), silent, Some("got no answer")),
            (Some(connected_docker()), mixed, Some("got no answer")),
            (Some(connected_docker()), refused, None),
            (Some(connected_docker()), not_run, None),
            (Some(disconnected_docker()), silent, None),
            (Some(disconnected_docker()), refused, None),
            (Some(disconnected_docker()), not_run, None),
            (
                Some(disconnected_docker()),
                answered,
                Some("reached an engine"),
            ),
            (
                Some(disconnected_docker()),
                mixed,
                Some("reached an engine"),
            ),
            (None, answered, None),
            (None, silent, None),
            (Some(DockerStatus::default()), answered, None),
            (Some(DockerStatus::default()), silent, None),
        ];
        for (docker, cli_answers, names) in table {
            let note = docker_cli_note(docker.as_ref(), cli_answers, "labelled docker networks");
            assert_eq!(
                note.is_some(),
                names.is_some(),
                "docker={docker:?} cli_answers={cli_answers:?} note={note:?}"
            );
            if let (Some(note), Some(names)) = (note, names) {
                assert!(note.starts_with("docker CLI: "), "{note}");
                assert!(note.contains(names), "{note}");
                assert!(note.contains("labelled docker networks"), "{note}");
            }
        }
    }

    #[test]
    fn doctor_notes_a_docker_cli_that_disagrees_with_the_daemon() {
        // The `docker` CLI of the report answers both of its checks.
        let agree = render_report(&with_docker(Some(connected_docker())));
        assert!(!agree.contains("docker CLI:"), "{agree}");

        let cli_only = render_report(&with_docker(Some(disconnected_docker())));
        assert!(
            cli_only.contains("docker CLI: a check reached an engine"),
            "{cli_only}"
        );

        let mut report = with_docker(Some(connected_docker()));
        report.docker_routes = DockerRouteStatus::Unavailable(DockerCliError::NoAnswer(
            "Cannot connect to the Docker daemon".to_string(),
        ));
        let daemon_only = render_report(&report);
        assert!(
            daemon_only.contains("docker CLI: a check got no answer"),
            "{daemon_only}"
        );
    }

    #[test]
    fn doctor_prints_no_note_for_an_engine_that_answered_with_an_error_or_a_cli_that_did_not_run() {
        let gone = "Error response from daemon: No such container: 0a1b2c";
        let errors = [
            DockerCliError::Failed(gone.to_string()),
            DockerCliError::NotStarted("No such file or directory (os error 2)".to_string()),
        ];
        for error in errors {
            let mut report = with_docker(Some(connected_docker()));
            report.docker_routes = DockerRouteStatus::Unavailable(error.clone());

            let rendered = render_report(&report);

            assert!(!rendered.contains("docker CLI:"), "{error:?}\n{rendered}");
            assert!(
                rendered.contains(&format!("labelled docker networks: unavailable ({error})")),
                "{error:?}\n{rendered}"
            );
            assert!(
                rendered.contains("replacement: needs attention"),
                "{error:?}\n{rendered}"
            );
        }
    }

    #[test]
    fn a_docker_cli_call_says_whether_an_engine_answered_it() {
        let fails_with = |stderr: &str| format!("echo '{stderr}' >&2; exit 1");
        let no_engine = "failed to connect to the docker API at unix:///run/demo/docker.sock; \
                         check if the path is correct and if the daemon is running";
        let no_engine_before_29 = "Cannot connect to the Docker daemon at \
                                   unix:///run/demo/docker.sock. Is the docker daemon running?";
        let gone = "Error response from daemon: No such container: kafka-connect-1";
        // the script that stands for `docker` → what the call returns
        let table = [
            ("echo 0a1b2c".to_string(), Ok("0a1b2c\n".to_string())),
            (
                fails_with(no_engine),
                Err(DockerCliError::NoAnswer(no_engine.to_string())),
            ),
            (
                fails_with(no_engine_before_29),
                Err(DockerCliError::NoAnswer(no_engine_before_29.to_string())),
            ),
            (
                fails_with(gone),
                Err(DockerCliError::Failed(gone.to_string())),
            ),
        ];
        for (script, want) in table {
            assert_eq!(run_docker("sh", &["-c", &script]), want, "{script}");
        }

        let silent_failure = run_docker("sh", &["-c", "exit 3"]);
        assert!(
            matches!(silent_failure, Err(DockerCliError::Failed(_))),
            "{silent_failure:?}"
        );
        let no_program = run_docker("/run/demo/no-such-docker", &["ps"]);
        assert!(
            matches!(no_program, Err(DockerCliError::NotStarted(_))),
            "{no_program:?}"
        );
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
