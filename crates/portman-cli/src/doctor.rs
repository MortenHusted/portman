use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;

use portman_protocol::{
    BridgeAssessment, BridgePhase, DockerState, DockerStatus, Entry, Mode, NetbridgeMode, Response,
};
use serde_json::Value;

pub(crate) const SETUP_IMAGE: &str = "portman-netbridge/setup:local";
const DOCKER_MAC_NET_CONNECT_PLIST: &str =
    "/Library/LaunchDaemons/homebrew.mxcl.docker-mac-net-connect.plist";
const LABEL_HOST: &str = "dev.portman.host";
const CONTAINER_FACING_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 99, 1);
const DNS_CONTAINER: &str = "portman-netbridge-dns";
/// The gateway address of the `portman` docker network, where the DNS
/// forwarder listens.
pub(crate) const DNS_FORWARDER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 99, 129);
/// The subnet of the `portman` docker network. The netbridge crate names it
/// `DOCKER_BRIDGE_CIDR` and builds on macOS only, so doctor has its own
/// copy, and a test holds the two together.
const PORTMAN_NETWORK_CIDR: &str = "192.168.99.128/25";
/// The label of a setup image that has the `dns` mode, and its value.
const DNS_IMAGE_LABEL: (&str, &str) = ("dev.portman.dns-forwarder", "1");
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

impl DaemonSnapshot {
    /// A bridge that is up beside a health that is not `healthy` can be a
    /// health from before that bridge. A daemon up to 0.1.7 assesses on its
    /// period only, and a later one needs the time of one assessment after
    /// the bridge comes up.
    fn health_can_be_behind_the_bridge(&self) -> bool {
        self.bridge_phase == Some(BridgePhase::Up)
            && self.bridge_assessment != Some(BridgeAssessment::Healthy)
    }
}

/// How long doctor reads the status again while
/// [`DaemonSnapshot::health_can_be_behind_the_bridge`]. One period brings an
/// assessment from after the first read, and the margin is for the time
/// that the assessment takes, which was 6 to 22 ms on a dev rig with one
/// labelled network.
const HEALTH_BOUND: Duration = BridgeAssessment::PERIOD.saturating_add(Duration::from_secs(1));
const HEALTH_PAUSE: Duration = Duration::from_millis(100);

/// The status that doctor gives its verdict on. `read` asks the daemon for
/// its status, and gives `None` for a daemon that did not answer. Doctor
/// reads again while the health can be behind the bridge, for at most
/// [`HEALTH_BOUND`], and takes the last reading. So a bridge whose health
/// stays as it is costs that wait, and doctor's verdict is not from before
/// the bridge.
pub(crate) async fn settled_daemon<F>(mut read: impl FnMut() -> F) -> DaemonSnapshot
where
    F: Future<Output = Option<Response>>,
{
    let first_read = tokio::time::Instant::now();
    loop {
        let daemon = DaemonSnapshot::from_status(read().await);
        if !daemon.health_can_be_behind_the_bridge() || first_read.elapsed() >= HEALTH_BOUND {
            return daemon;
        }
        tokio::time::sleep(HEALTH_PAUSE).await;
    }
}

/// Why a `docker` CLI call gave no output to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DockerCliError {
    /// The `docker` program did not start, as when none is installed.
    NotStarted(String),
    /// The CLI reached no engine, or the call was killed at
    /// [`DOCKER_CLI_BOUND`].
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

/// The DNS forwarder in the VM, as the `docker` CLI shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsForwarderStatus {
    /// The engine has no setup image with the `dns` mode, so the daemon
    /// starts no forwarder.
    ImageWithoutDnsMode,
    /// `state` is docker's word for a container that exists and does not
    /// run. `None` is no container.
    NotRunning {
        state: Option<String>,
    },
    Running(ForwarderQuery),
    DockerUnavailable(DockerCliError),
}

impl DnsForwarderStatus {
    pub(crate) fn cli_answer(&self) -> CliAnswer<'_> {
        match self {
            DnsForwarderStatus::DockerUnavailable(error)
            | DnsForwarderStatus::Running(ForwarderQuery::NotRun { error, .. }) => Err(error),
            _ => Ok(()),
        }
    }
}

/// One lookup of a managed name from a container that has the forwarder as
/// its only resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ForwarderQuery {
    NotSent { why: String },
    Answered { name: String, address: String },
    Unanswered { name: String, detail: String },
    NotRun { name: String, error: DockerCliError },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsForwarderReport {
    pub status: DnsForwarderStatus,
    /// The hostnames of the TCP routes whose target is on the `portman`
    /// docker network.
    pub tcp_routes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DoctorReport {
    pub daemon: DaemonSnapshot,
    pub setup_image: SetupImageStatus,
    pub legacy_bridge: LegacyBridgeStatus,
    pub docker_routes: DockerRouteStatus,
    pub container_facing: ContainerFacingStatus,
    /// `None` on a platform that has no netbridge, and so no forwarder.
    pub dns_forwarder: Option<DnsForwarderReport>,
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

pub(crate) async fn inspect_setup_image() -> SetupImageStatus {
    let format = "{{.Id}}\t{{.Created}}";
    let inspect = ["image", "inspect", SETUP_IMAGE, "--format", format];
    let stdout = match docker_stdout(&inspect).await {
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

pub(crate) async fn collect_docker_routes() -> DockerRouteStatus {
    let labelled = ["ps", "--filter", "label=dev.portman.host", "-q"];
    let ids_output = match docker_stdout(&labelled).await {
        Ok(output) => output,
        Err(error) => return DockerRouteStatus::Unavailable(error),
    };
    let ids: Vec<&str> = ids_output.split_ascii_whitespace().collect();
    if ids.is_empty() {
        return DockerRouteStatus::NoLabelledContainers;
    }

    let mut inspect_args = vec!["container", "inspect"];
    inspect_args.extend(ids.iter().copied());
    let container_json = match docker_stdout(&inspect_args).await {
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
    let network_json = match docker_stdout(&network_args).await {
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

/// `routes` is the registry as the daemon lists it, and empty for a daemon
/// that did not answer. Only macOS has the netbridge that runs a forwarder,
/// so any other platform gets `None` and the `docker` CLI is not asked.
pub(crate) async fn inspect_dns_forwarder(
    phase: Option<BridgePhase>,
    routes: &[Entry],
) -> Option<DnsForwarderReport> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    Some(DnsForwarderReport {
        status: dns_forwarder_status(phase, routes).await,
        tcp_routes: tcp_routes_on_the_portman_network(routes),
    })
}

async fn dns_forwarder_status(phase: Option<BridgePhase>, routes: &[Entry]) -> DnsForwarderStatus {
    let (label, _) = DNS_IMAGE_LABEL;
    let label_of_image = format!("{{{{index .Config.Labels \"{label}\"}}}}");
    let image = ["image", "inspect", SETUP_IMAGE, "--format", &label_of_image];
    let state = "{{.State.Status}}";
    let container = ["container", "inspect", DNS_CONTAINER, "--format", state];
    classify_dns_forwarder(
        docker_stdout(&image).await,
        docker_stdout(&container),
        async {
            match forwarder_query_name(phase, routes) {
                Ok(name) => look_up_through_forwarder(&["docker"], name, LOOKUP_BOUND).await,
                Err(why) => ForwarderQuery::NotSent { why },
            }
        },
    )
    .await
}

/// `image_label` and `container_state` are what the `docker` CLI printed
/// for the setup image's label and for the forwarder container's state, or
/// its error. The container is asked about only for an image that has the
/// `dns` mode, and `look_up` runs only for a container that runs.
async fn classify_dns_forwarder(
    image_label: Result<String, DockerCliError>,
    container_state: impl Future<Output = Result<String, DockerCliError>>,
    look_up: impl Future<Output = ForwarderQuery>,
) -> DnsForwarderStatus {
    let engine_has_no = |what: &str, error: &DockerCliError| {
        let message = error.to_string();
        message.contains(&format!("No such {what}")) || message.contains("No such object")
    };
    match image_label {
        Ok(value) if value.trim() == DNS_IMAGE_LABEL.1 => {}
        Ok(_) => return DnsForwarderStatus::ImageWithoutDnsMode,
        Err(error) if engine_has_no("image", &error) => {
            return DnsForwarderStatus::ImageWithoutDnsMode
        }
        Err(error) => return DnsForwarderStatus::DockerUnavailable(error),
    }
    match container_state.await {
        Ok(state) if state.trim() == "running" => DnsForwarderStatus::Running(look_up.await),
        Ok(state) => DnsForwarderStatus::NotRunning {
            state: Some(state.trim().to_string()),
        },
        Err(error) if engine_has_no("container", &error) => {
            DnsForwarderStatus::NotRunning { state: None }
        }
        Err(error) => DnsForwarderStatus::DockerUnavailable(error),
    }
}

/// The managed name that doctor looks up through the forwarder, or why it
/// looks up none.
fn forwarder_query_name(phase: Option<BridgePhase>, routes: &[Entry]) -> Result<String, String> {
    match phase {
        Some(BridgePhase::Up) => {}
        Some(phase) => {
            return Err(format!(
                "the netbridge is {}, and managed names resolve only while it is up",
                phase.display_word()
            ))
        }
        None => {
            return Err(
                "the daemon is unreachable, and managed names resolve only through it".to_string(),
            )
        }
    }
    routes
        .iter()
        .map(|route| route.host.as_str())
        .filter(|host| !host.starts_with("*.") && !host.ends_with(".localhost"))
        .min()
        .map(String::from)
        .ok_or_else(|| {
            "no registered hostname to look up; a wildcard and a `.localhost` name are not looked up"
                .to_string()
        })
}

/// The TCP routes that a container reaches only from the `portman` network:
/// a name of such a route resolves to its target, a container on that
/// network, and Docker carries no traffic between two bridge networks. A
/// TCP route to any other target is left out, because joining the network
/// is not what a container needs to reach it.
fn tcp_routes_on_the_portman_network(routes: &[Entry]) -> Vec<String> {
    let mut names: Vec<String> = routes
        .iter()
        .filter(|route| route.mode == Mode::Tcp && targets_the_portman_network(&route.target))
        .map(|route| route.host.clone())
        .collect();
    names.sort();
    names
}

fn targets_the_portman_network(target: &str) -> bool {
    let (network, prefix_len) = PORTMAN_NETWORK_CIDR
        .split_once('/')
        .expect("a subnet is an address and a prefix length");
    let network: Ipv4Addr = network.parse().expect("an IPv4 subnet");
    let mask = u32::MAX << (32 - prefix_len.parse::<u32>().expect("a prefix length"));
    match target.parse() {
        Ok(SocketAddr::V4(target)) => u32::from(*target.ip()) & mask == u32::from(network),
        _ => false,
    }
}

/// Looks `name` up from a container on the default bridge network that has
/// the forwarder as its only resolver, as a container started with `--dns
/// 192.168.99.129` has. The container is the setup image's `getent`, and
/// the engine removes it when the lookup ends. `--pull never` keeps the CLI
/// from asking a registry for an image that went away since the inspect.
/// The resolver options set one attempt with a timeout of
/// [`LOOKUP_RESOLVER_SECS`], so that a lookup with no answer ends.
///
/// `docker` is the command that stands for the `docker` CLI. A run that has
/// not ended after `bound` is killed. The engine can then still hold the
/// container, and never removes one that it created and did not start, so
/// the container has a name and is removed by it.
async fn look_up_through_forwarder(
    docker: &[&str],
    name: String,
    bound: Duration,
) -> ForwarderQuery {
    let forwarder = DNS_FORWARDER_IP.to_string();
    let container = format!("portman-doctor-lookup-{}", std::process::id());
    let resolver_wait = format!("timeout:{LOOKUP_RESOLVER_SECS}");
    let (program, first_args) = docker.split_first().expect("a command has a program");
    let run = [
        first_args,
        &["run", "--rm", "--pull", "never", "--name", &container],
        &["--dns", &forwarder],
        &["--dns-opt", &resolver_wait, "--dns-opt", "attempts:1"],
        &["--entrypoint", "getent", SETUP_IMAGE, "hosts", &name],
    ]
    .concat();
    let error = match bounded_output(program, &run, bound).await {
        Ok(ran) => {
            let stderr = String::from_utf8_lossy(&ran.stderr);
            if !ran.status.success() && reached_no_engine(&stderr) {
                DockerCliError::NoAnswer(stderr.trim().to_string())
            } else {
                let stdout = String::from_utf8_lossy(&ran.stdout);
                return forwarder_query(name, ran.status.success(), &stdout, &stderr);
            }
        }
        Err(DockerCliError::NoAnswer(no_answer)) => {
            let remove = [first_args, &["rm", "--force", &container]].concat();
            DockerCliError::NoAnswer(match run_docker(program, &remove, DOCKER_CLI_BOUND).await {
                Ok(_) => no_answer,
                Err(DockerCliError::Failed(gone)) if gone.contains("No such container") => {
                    no_answer
                }
                Err(_) => format!(
                    "{no_answer}; the lookup container can still exist, `docker rm --force {container}` removes it"
                ),
            })
        }
        Err(error) => error,
    };
    ForwarderQuery::NotRun { name, error }
}

/// What the lookup container's exit and output say. `getent` prints nothing
/// when it finds no address, and `docker` prints why a container did not
/// run.
fn forwarder_query(name: String, succeeded: bool, stdout: &str, stderr: &str) -> ForwarderQuery {
    match getent_address(stdout).filter(|_| succeeded) {
        Some(address) => ForwarderQuery::Answered { name, address },
        None => ForwarderQuery::Unanswered {
            name,
            detail: stderr
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .unwrap_or("getent found no address")
                .to_string(),
        },
    }
}

/// The first address in the output of `getent hosts <name>`.
fn getent_address(stdout: &str) -> Option<String> {
    let first = stdout.split_whitespace().next()?;
    first.parse::<IpAddr>().ok().map(|_| first.to_string())
}

fn check_dns_forwarder(report: &DnsForwarderReport) -> CheckOutcome {
    let at = format!("dns forwarder: running at {DNS_FORWARDER_IP}");
    let (state, line) = match &report.status {
        DnsForwarderStatus::Running(ForwarderQuery::Answered { name, address }) => (
            CheckState::Ok,
            format!("{at}, {name} resolves to {address}"),
        ),
        DnsForwarderStatus::Running(ForwarderQuery::Unanswered { name, detail }) => (
            CheckState::Warn,
            format!("{at}, {name} does not resolve through it ({detail})"),
        ),
        DnsForwarderStatus::Running(ForwarderQuery::NotRun { name, error }) => (
            CheckState::Warn,
            format!("{at}, {name} does not resolve through it ({error})"),
        ),
        DnsForwarderStatus::Running(ForwarderQuery::NotSent { why }) => {
            (CheckState::Ok, format!("{at}, not queried ({why})"))
        }
        DnsForwarderStatus::NotRunning { state: None } => (
            CheckState::Warn,
            "dns forwarder: absent; the netbridge starts it when it comes up, and a failed start is in the daemon log as `dns forwarder`".to_string(),
        ),
        DnsForwarderStatus::NotRunning { state: Some(state) } => (
            CheckState::Warn,
            format!("dns forwarder: {state}, not running; `docker logs {DNS_CONTAINER}` shows why"),
        ),
        DnsForwarderStatus::ImageWithoutDnsMode => (
            CheckState::Warn,
            "dns forwarder: unavailable, the setup image has no dns mode (run `portman bridge prepare`; a bridge that is up then gets the forwarder within a minute)".to_string(),
        ),
        DnsForwarderStatus::DockerUnavailable(error) => (
            CheckState::Warn,
            format!("dns forwarder: unavailable ({error})"),
        ),
    };
    let mut lines = vec![line];
    let running = matches!(report.status, DnsForwarderStatus::Running(_));
    if running && !report.tcp_routes.is_empty() {
        lines.push(format!(
            "  tcp routes to the `portman` network ({}): a container resolves them through the forwarder and connects only when it also joins that network",
            report.tcp_routes.join(", ")
        ));
    }
    CheckOutcome {
        state,
        lines,
        gates_ready: false,
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
    let mut cli_answers = vec![
        report.setup_image.cli_answer(),
        report.docker_routes.cli_answer(),
    ];
    let mut cli_lines = "setup image and labelled docker networks lines";
    if let Some(forwarder) = &report.dns_forwarder {
        cli_answers.push(forwarder.status.cli_answer());
        cli_lines = "setup image, dns forwarder and labelled docker networks lines";
    }
    let mut outcomes = vec![check_daemon(&report.daemon)];
    outcomes.extend(check_docker(
        report.daemon.docker.as_ref(),
        &cli_answers,
        cli_lines,
    ));
    outcomes.extend([
        check_setup_image(&report.setup_image),
        legacy,
        check_container_facing(&report.container_facing),
    ]);
    outcomes.extend(report.dns_forwarder.as_ref().map(check_dns_forwarder));
    outcomes.push(check_docker_routes(
        &report.docker_routes,
        report.daemon.bridge_assessment,
    ));
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
    let mut guidance = Vec::new();
    if !ready {
        guidance.extend(
            bridge_guidance(&report.daemon)
                .iter()
                .map(|line| format!("  {line}")),
        );
    }
    if legacy_running {
        guidance.push("  Portman did not stop it automatically.".to_string());
        guidance.push("  to stop the legacy bridge when you are ready:".to_string());
        guidance.push("    sudo brew services stop docker-mac-net-connect".to_string());
        guidance.push(format!(
            "    sudo launchctl bootout system {DOCKER_MAC_NET_CONNECT_PLIST}"
        ));
    }
    if !guidance.is_empty() {
        lines.push("guidance:".to_string());
        lines.extend(guidance);
    }

    lines.join("\n") + "\n"
}

/// `portman bridge enable` helps only a bridge that is off. For a bridge
/// that is enabled and not up, it restarts the retry delay and waits. A
/// bridge that is up in `docker` mode is where both commands lead, so the
/// advice for it is what the health found.
fn bridge_guidance(daemon: &DaemonSnapshot) -> &'static [&'static str] {
    match (daemon.bridge_phase, daemon.bridge_mode) {
        (Some(BridgePhase::Up), Some(NetbridgeMode::Docker)) => {
            health_guidance(daemon.bridge_assessment.unwrap_or_default())
        }
        (phase, _) => phase_guidance(phase),
    }
}

/// For a bridge that is up in `docker` mode. That bridge adds a missing
/// route within seconds and leaves one that another live `utun` holds, so a
/// route that stays missing is one that the bridge does not own or does not
/// make.
fn health_guidance(health: BridgeAssessment) -> &'static [&'static str] {
    const LOOK_AT: &str =
        "`portman bridge status` names each labelled network and the interface of its route";
    match health {
        BridgeAssessment::Healthy => &[],
        BridgeAssessment::RoutesMissing => &[
            "netbridge is up in docker mode, and a labelled Docker network has no route through the bridge",
            LOOK_AT,
            "the bridge leaves a route in place that another live `utun` holds, such as the one of a VPN",
        ],
        BridgeAssessment::TunnelDead => &[
            "netbridge is up in docker mode, and the route to a labelled Docker network names an interface that no longer exists",
            LOOK_AT,
        ],
        BridgeAssessment::Offline => &[
            "netbridge is up in docker mode, and the daemon's health check got no answer from Docker; check that your container runtime is running",
        ],
        BridgeAssessment::Unknown => &[
            "netbridge is up in docker mode, and the daemon reports no health for it that this `portman` can read",
        ],
    }
}

fn phase_guidance(phase: Option<BridgePhase>) -> &'static [&'static str] {
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
/// line. The setup image check, the DNS forwarder check and the docker
/// networks check ask the `docker` CLI.
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
/// check that ran the CLI. Only a call that an engine answered counts as an
/// engine for the CLI, and only [`DockerCliError::NoAnswer`] counts as none.
/// Any other failure brings no note.
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

/// The verdict on the routes is the daemon's health, which knows the network
/// that the registry routes each container through and the interface of the
/// bridge. The lines show what the `docker` CLI and the routing table say.
fn check_docker_routes(
    status: &DockerRouteStatus,
    health: Option<BridgeAssessment>,
) -> CheckOutcome {
    let state = match status {
        DockerRouteStatus::Unavailable(_) => CheckState::Fail,
        _ if health == Some(BridgeAssessment::Healthy) => CheckState::Ok,
        _ => CheckState::Warn,
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

/// How long one `docker` CLI call has to end, process start included. A
/// socket that accepts and never answers would otherwise hold the command
/// for minutes. An engine that is alive and slower than this reads as one
/// that gave no answer.
const DOCKER_CLI_BOUND: Duration = Duration::from_secs(3);

async fn docker_stdout(args: &[&str]) -> Result<String, DockerCliError> {
    run_docker("docker", args, DOCKER_CLI_BOUND).await
}

/// What the `docker` CLI prints when it reaches no engine. The words differ
/// between releases: some name "the docker API", and others name "the
/// Docker daemon".
const NO_ENGINE: [&str; 3] = [
    "connect to the docker API",
    "connect to the Docker daemon",
    "error during connect",
];

/// How long the resolver of the lookup container waits for the forwarder in
/// one lookup.
const LOOKUP_RESOLVER_SECS: u64 = 2;

/// How long the lookup container has to end. `docker run` makes the engine
/// create and start the container, `getent hosts` in it makes two lookups in
/// turn that each wait for up to [`LOOKUP_RESOLVER_SECS`], and the engine
/// then removes the container. That leaves the engine 4 s of the bound.
/// Measured on colima with Docker Engine 29, a forwarder that never answers
/// holds the run for 4.8 to 5.6 s, so the run ends at least 2.4 s inside the
/// bound.
const LOOKUP_BOUND: Duration =
    Duration::from_secs(2 * DOCKER_CLI_BOUND.as_secs() + LOOKUP_RESOLVER_SECS);

/// Runs `program`, and kills it when it has not ended after `bound`. The
/// `docker` CLI itself waits for minutes on a socket that accepts a
/// connection and never answers.
async fn bounded_output(
    program: &str,
    args: &[&str],
    bound: Duration,
) -> Result<std::process::Output, DockerCliError> {
    let child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| {
            DockerCliError::NotStarted(match err.kind() {
                std::io::ErrorKind::NotFound => format!("`{program}` not found"),
                _ => err.to_string(),
            })
        })?;
    match tokio::time::timeout(bound, child.wait_with_output()).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(err)) => Err(DockerCliError::Failed(err.to_string())),
        Err(_) => {
            let waited = bound.as_secs_f32();
            Err(DockerCliError::NoAnswer(format!("no answer in {waited} s")))
        }
    }
}

/// [`bounded_output`], with a call that failed sorted by whether an engine
/// answered it.
async fn run_docker(
    program: &str,
    args: &[&str],
    bound: Duration,
) -> Result<String, DockerCliError> {
    let output = bounded_output(program, args, bound).await?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if stderr.is_empty() {
        DockerCliError::Failed(format!("docker {args:?} exited with {}", output.status))
    } else if reached_no_engine(&stderr) {
        DockerCliError::NoAnswer(stderr)
    } else {
        DockerCliError::Failed(stderr)
    })
}

fn reached_no_engine(stderr: &str) -> bool {
    NO_ENGINE.iter().any(|phrase| stderr.contains(phrase))
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
            dns_forwarder: Some(forwarder(running(answered()))),
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
    fn doctor_names_what_the_health_found_for_a_bridge_that_is_up_in_docker_mode() {
        use BridgeAssessment::{Offline, RoutesMissing, TunnelDead, Unknown};
        let status = "`portman bridge status` names each labelled network";
        // health → what the guidance names
        let table = [
            (RoutesMissing, "has no route through the bridge"),
            (RoutesMissing, status),
            (TunnelDead, "an interface that no longer exists"),
            (TunnelDead, status),
            (Offline, "container runtime"),
            (Unknown, "no health"),
        ];
        for (health, names) in table {
            let mut report = ready_but_for_the_bridge(BridgePhase::Up);
            report.daemon.bridge_assessment = Some(health);

            let rendered = render_report(&report);

            let guidance = rendered.split("guidance:").nth(1).unwrap_or_default();
            assert!(
                guidance.contains("netbridge is up in docker mode"),
                "{rendered}"
            );
            assert!(guidance.contains(names), "{health}: {names}\n{rendered}");
            for done in ["portman bridge enable", "portman bridge mode docker"] {
                assert!(!guidance.contains(done), "{health}: {done}\n{rendered}");
            }
        }
    }

    #[test]
    fn doctor_gives_no_bridge_advice_for_a_healthy_bridge_in_docker_mode() {
        let mut no_image = ready_but_for_the_bridge(BridgePhase::Up);
        no_image.setup_image = SetupImageStatus::Missing;
        let rendered = render_report(&no_image);
        assert!(
            rendered.contains("replacement: needs attention"),
            "{rendered}"
        );
        assert!(
            rendered.contains("run `portman bridge prepare`"),
            "{rendered}"
        );
        assert!(!rendered.contains("guidance:"), "{rendered}");

        let mut legacy = ready_but_for_the_bridge(BridgePhase::Up);
        legacy.legacy_bridge = LegacyBridgeStatus::Running {
            detail: "docker-mac-net-connect pid 1234".to_string(),
        };
        let rendered = render_report(&legacy);
        assert!(
            rendered.contains("guidance:\n  Portman did not stop it automatically."),
            "{rendered}"
        );
    }

    #[test]
    fn doctor_advises_docker_mode_for_a_bridge_that_is_up_in_another_mode() {
        for mode in [NetbridgeMode::OptIn, NetbridgeMode::All] {
            let mut report = ready_but_for_the_bridge(BridgePhase::Up);
            report.daemon.bridge_mode = Some(mode);

            let rendered = render_report(&report);

            let guidance = rendered.split("guidance:").nth(1).unwrap_or_default();
            assert!(
                guidance.contains("portman bridge mode docker"),
                "{mode:?}\n{rendered}"
            );
        }
    }

    /// Answers each status read with the next of `healths`, and with the
    /// last one from then on. `None` is a daemon that does not answer.
    fn daemon_that_reports(
        phase: &'static str,
        healths: &[Option<&'static str>],
    ) -> (
        impl FnMut() -> std::future::Ready<Option<Response>>,
        std::rc::Rc<std::cell::Cell<usize>>,
    ) {
        let healths = healths.to_vec();
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let counted = reads.clone();
        let read = move || {
            let health = healths[counted.get().min(healths.len() - 1)];
            counted.set(counted.get() + 1);
            std::future::ready(health.map(|health| {
                let json = format!(
                    r#"{{"kind":"status","version":"0.1.7","bridge_enabled":true,"bridge_phase":"{phase}","bridge_mode":"docker","bridge_assessment":"{health}"}}"#
                );
                serde_json::from_str(&json).unwrap()
            }))
        };
        (read, reads)
    }

    fn rendered_with(daemon: DaemonSnapshot) -> String {
        let mut report = ready_but_for_the_bridge(BridgePhase::Up);
        report.daemon = daemon;
        render_report(&report)
    }

    #[tokio::test(start_paused = true)]
    async fn doctor_reads_the_status_again_for_an_up_bridge_until_its_health_is_healthy() {
        let (read, reads) = daemon_that_reports("up", &[Some("routes_missing"), Some("healthy")]);
        let asked_at = tokio::time::Instant::now();

        let rendered = rendered_with(settled_daemon(read).await);

        let daemon_line = "daemon: ok v0.1.7 bridge: healthy netbridge: up mode: docker";
        assert!(
            rendered.contains(&format!("replacement: ready\n{daemon_line}\n")),
            "{rendered}"
        );
        assert_eq!(reads.get(), 2);
        assert!(asked_at.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn doctor_waits_a_little_more_than_one_health_period_for_a_health_that_stays_behind() {
        let period = BridgeAssessment::PERIOD;
        for health in ["routes_missing", "tunnel_dead", "offline", "unknown"] {
            let (read, _) = daemon_that_reports("up", &[Some(health)]);
            let asked_at = tokio::time::Instant::now();

            let rendered = rendered_with(settled_daemon(read).await);

            let waited = asked_at.elapsed();
            assert!(
                waited > period && waited <= period + period / 4,
                "{health}: waited {waited:?}"
            );
            let daemon_line =
                format!("daemon: ok v0.1.7 bridge: {health} netbridge: up mode: docker");
            assert!(
                rendered.contains(&format!("replacement: needs attention\n{daemon_line}\n")),
                "{rendered}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn doctor_reads_the_status_once_where_the_health_is_not_behind_an_up_bridge() {
        use BridgeAssessment::{Healthy, RoutesMissing};
        let turns_healthy = [Some("routes_missing"), Some("healthy")];
        // (the phase, the healths that the daemon reports in turn) → the health doctor takes
        let table = [
            (
                "up",
                &[Some("healthy"), Some("routes_missing")][..],
                Some(Healthy),
            ),
            ("disabled", &turns_healthy[..], Some(RoutesMissing)),
            (
                "waiting_for_docker",
                &turns_healthy[..],
                Some(RoutesMissing),
            ),
            ("starting", &turns_healthy[..], Some(RoutesMissing)),
            ("stopping", &turns_healthy[..], Some(RoutesMissing)),
            ("up", &[None][..], None),
        ];
        for (phase, healths, taken) in table {
            let (read, reads) = daemon_that_reports(phase, healths);
            let asked_at = tokio::time::Instant::now();

            let daemon = settled_daemon(read).await;

            assert_eq!(daemon.bridge_assessment, taken, "{phase} {healths:?}");
            assert_eq!(reads.get(), 1, "{phase} {healths:?}");
            assert_eq!(asked_at.elapsed(), Duration::ZERO, "{phase} {healths:?}");
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
        let no_program = DockerCliError::NotStarted("`docker` not found".into());
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
    fn doctor_reads_the_setup_image_check_as_one_of_those_that_ask_the_docker_cli() {
        let no_answer = || DockerCliError::NoAnswer("no answer in 3 s".to_string());
        let lines = "the setup image, dns forwarder and labelled docker networks lines below";

        let mut image_got_no_answer = with_docker(Some(connected_docker()));
        image_got_no_answer.setup_image = SetupImageStatus::Unavailable(no_answer());
        let rendered = render_report(&image_got_no_answer);
        assert!(
            rendered.contains("docker CLI: a check got no answer"),
            "{rendered}"
        );
        assert!(rendered.contains(lines), "{rendered}");
        assert!(
            rendered.contains("\nsetup image: unavailable (no answer in 3 s)\n"),
            "{rendered}"
        );

        let mut only_the_image_answered = with_docker(Some(disconnected_docker()));
        only_the_image_answered.docker_routes = DockerRouteStatus::Unavailable(no_answer());
        let rendered = render_report(&only_the_image_answered);
        assert!(
            rendered.contains("docker CLI: a check reached an engine"),
            "{rendered}"
        );
    }

    #[test]
    fn doctor_prints_no_note_for_an_engine_that_answered_with_an_error_or_a_cli_that_did_not_run() {
        let gone = "Error response from daemon: No such container: 0a1b2c";
        let errors = [
            DockerCliError::Failed(gone.to_string()),
            DockerCliError::NotStarted("`docker` not found".to_string()),
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

    #[tokio::test]
    async fn a_docker_cli_call_says_whether_an_engine_answered_it() {
        let run = |program: &'static str, script: String| async move {
            run_docker(program, &["-c", &script], Duration::from_secs(10)).await
        };
        let fails_with = |stderr: &str| format!("echo '{stderr}' >&2; exit 1");
        let no_engine = "failed to connect to the docker API at unix:///run/demo/docker.sock; \
                         check if the path is correct and if the daemon is running";
        let no_engine_other_wording = "Cannot connect to the Docker daemon at \
                                   unix:///run/demo/docker.sock. Is the docker daemon running?";
        let gone = "Error response from daemon: No such container: demo-web-1";
        // the script that stands for `docker` → what the call returns
        let table = [
            ("echo 0a1b2c".to_string(), Ok("0a1b2c\n".to_string())),
            (
                fails_with(no_engine),
                Err(DockerCliError::NoAnswer(no_engine.to_string())),
            ),
            (
                fails_with(no_engine_other_wording),
                Err(DockerCliError::NoAnswer(
                    no_engine_other_wording.to_string(),
                )),
            ),
            (
                fails_with(gone),
                Err(DockerCliError::Failed(gone.to_string())),
            ),
        ];
        for (script, want) in table {
            assert_eq!(run("sh", script.clone()).await, want, "{script}");
        }

        let silent_failure = run("sh", "exit 3".to_string()).await;
        assert!(
            matches!(silent_failure, Err(DockerCliError::Failed(_))),
            "{silent_failure:?}"
        );
        let no_program = run("/run/demo/no-such-docker", "exit 0".to_string()).await;
        assert!(
            matches!(no_program, Err(DockerCliError::NotStarted(_))),
            "{no_program:?}"
        );
    }

    #[tokio::test]
    async fn a_docker_cli_that_is_not_there_is_named_as_not_found() {
        let no_program = "/run/demo/no-such-docker";

        let result = run_docker(no_program, &["ps"], Duration::from_secs(10)).await;

        let not_found = format!("`{no_program}` not found");
        assert_eq!(result, Err(DockerCliError::NotStarted(not_found)));
    }

    #[test]
    fn doctor_counts_a_forwarder_check_that_got_no_answer_toward_the_docker_cli_note() {
        let no_answer = |waited: &str| DockerCliError::NoAnswer(format!("no answer in {waited}"));
        let name = || "web.demo.test".to_string();
        let lookup_killed = ForwarderQuery::NotRun {
            name: name(),
            error: no_answer("8 s"),
        };
        let no_address = ForwarderQuery::Unanswered {
            name: name(),
            detail: "getent found no address".to_string(),
        };
        let refused = DockerCliError::Failed("permission denied".to_string());
        let note = "\ndocker CLI: a check got no answer from an engine, and the daemon is \
                    connected to one; the setup image, dns forwarder and labelled docker \
                    networks lines below come from the `docker` CLI\n";
        // the forwarder check → (its line, the note shows)
        let table = [
            (
                DnsForwarderStatus::DockerUnavailable(no_answer("3 s")),
                "dns forwarder: unavailable (no answer in 3 s)",
                true,
            ),
            (
                running(lookup_killed),
                "dns forwarder: running at 192.168.99.129, web.demo.test does not resolve through it (no answer in 8 s)",
                true,
            ),
            (
                DnsForwarderStatus::DockerUnavailable(refused),
                "dns forwarder: unavailable (permission denied)",
                false,
            ),
            (
                running(no_address),
                "dns forwarder: running at 192.168.99.129, web.demo.test does not resolve through it (getent found no address)",
                false,
            ),
        ];
        for (status, line, noted) in table {
            let mut report = with_docker(Some(connected_docker()));
            report.dns_forwarder = Some(forwarder(status.clone()));

            let rendered = render_report(&report);

            assert_eq!(rendered.contains(note), noted, "{status:?}\n{rendered}");
            assert_eq!(rendered.contains("docker CLI:"), noted, "{rendered}");
            assert!(rendered.contains(&format!("\n{line}\n")), "{rendered}");
        }
    }

    #[test]
    fn the_docker_cli_note_names_the_forwarder_line_only_where_doctor_prints_one() {
        let mut report = with_docker(Some(connected_docker()));
        report.dns_forwarder = None;
        report.setup_image =
            SetupImageStatus::Unavailable(DockerCliError::NoAnswer("no answer in 3 s".into()));

        let rendered = render_report(&report);

        assert!(
            rendered.contains("the setup image and labelled docker networks lines below"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn a_docker_cli_call_that_does_not_end_is_killed_at_its_bound() {
        let dir = tempfile::tempdir().unwrap();
        let outlived = dir.path().join("outlived");
        let script = format!("sleep 0.3; touch '{}'", outlived.display());

        let result = run_docker("sh", &["-c", &script], Duration::from_millis(50)).await;

        assert_eq!(
            result,
            Err(DockerCliError::NoAnswer("no answer in 0.05 s".to_string()))
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(!outlived.exists(), "the call ran on after its bound");
    }

    fn open_container_facing() -> ContainerFacingStatus {
        ContainerFacingStatus {
            dns: true,
            http: true,
            tls: true,
        }
    }

    fn forwarder(status: DnsForwarderStatus) -> DnsForwarderReport {
        DnsForwarderReport {
            status,
            tcp_routes: Vec::new(),
        }
    }

    fn running(query: ForwarderQuery) -> DnsForwarderStatus {
        DnsForwarderStatus::Running(query)
    }

    fn answered() -> ForwarderQuery {
        ForwarderQuery::Answered {
            name: "web.demo.test".to_string(),
            address: "192.168.99.1".to_string(),
        }
    }

    fn with_forwarder(dns_forwarder: DnsForwarderReport) -> DoctorReport {
        DoctorReport {
            dns_forwarder: Some(dns_forwarder),
            ..ready_but_for_the_bridge(BridgePhase::Up)
        }
    }

    #[test]
    fn doctor_prints_no_forwarder_line_where_no_forwarder_can_run() {
        let report = DoctorReport {
            dns_forwarder: None,
            ..ready_but_for_the_bridge(BridgePhase::Up)
        };

        let rendered = render_report(&report);

        assert!(!rendered.contains("dns forwarder"), "{rendered}");
        assert!(rendered.contains("container-facing:"), "{rendered}");
        assert!(rendered.contains("labelled docker networks"), "{rendered}");
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn only_macos_has_a_forwarder_for_doctor_to_look_at() {
        let routes = [route("web.demo.test", Mode::Http)];

        assert_eq!(
            inspect_dns_forwarder(Some(BridgePhase::Up), &routes).await,
            None
        );
    }

    fn route(host: &str, mode: Mode) -> Entry {
        Entry {
            host: host.to_string(),
            target: "192.168.99.130:5432".to_string(),
            source: portman_protocol::Source::Static,
            mode,
            container_id: None,
            project: None,
            egress: None,
        }
    }

    #[test]
    fn doctor_prints_one_line_for_each_state_of_the_dns_forwarder() {
        let not_sent = ForwarderQuery::NotSent {
            why: "no registered hostname to look up; a wildcard and a `.localhost` name are not looked up".to_string(),
        };
        let unanswered = ForwarderQuery::Unanswered {
            name: "web.demo.test".to_string(),
            detail: "getent found no address".to_string(),
        };
        let absent = DnsForwarderStatus::NotRunning { state: None };
        let restarting = DnsForwarderStatus::NotRunning {
            state: Some("restarting".to_string()),
        };
        let no_engine = DnsForwarderStatus::DockerUnavailable(DockerCliError::NoAnswer(
            "Cannot connect to the Docker daemon".to_string(),
        ));
        // status → the line
        let table = [
            (
                running(answered()),
                "dns forwarder: running at 192.168.99.129, web.demo.test resolves to 192.168.99.1",
            ),
            (
                running(unanswered),
                "dns forwarder: running at 192.168.99.129, web.demo.test does not resolve through it (getent found no address)",
            ),
            (
                running(not_sent),
                "dns forwarder: running at 192.168.99.129, not queried (no registered hostname to look up; a wildcard and a `.localhost` name are not looked up)",
            ),
            (
                absent,
                "dns forwarder: absent; the netbridge starts it when it comes up, and a failed start is in the daemon log as `dns forwarder`",
            ),
            (
                restarting,
                "dns forwarder: restarting, not running; `docker logs portman-netbridge-dns` shows why",
            ),
            (
                DnsForwarderStatus::ImageWithoutDnsMode,
                "dns forwarder: unavailable, the setup image has no dns mode (run `portman bridge prepare`; a bridge that is up then gets the forwarder within a minute)",
            ),
            (
                no_engine,
                "dns forwarder: unavailable (Cannot connect to the Docker daemon)",
            ),
        ];
        for (status, line) in table {
            let rendered = render_report(&with_forwarder(forwarder(status.clone())));
            let printed: Vec<&str> = rendered
                .lines()
                .filter(|line| line.contains("dns forwarder"))
                .collect();
            assert_eq!(printed, [line], "{status:?}");
            assert!(!rendered.contains("portman` network"), "{rendered}");
            assert!(
                rendered.contains("replacement: ready"),
                "the forwarder line changed the verdict\n{rendered}"
            );
        }
    }

    #[test]
    fn doctor_names_the_portman_network_when_a_tcp_route_exists() {
        let note = "  tcp routes to the `portman` network (db.demo.test, mq.demo.test): a container resolves them through the forwarder and connects only when it also joins that network";
        let with_tcp_routes = |status| DnsForwarderReport {
            status,
            tcp_routes: vec!["db.demo.test".to_string(), "mq.demo.test".to_string()],
        };

        let rendered = render_report(&with_forwarder(with_tcp_routes(running(answered()))));
        let lines: Vec<&str> = rendered.lines().collect();
        let forwarder_line = lines
            .iter()
            .position(|line| line.starts_with("dns forwarder: running"))
            .expect("the forwarder line");
        assert_eq!(lines[forwarder_line + 1], note, "{rendered}");

        let unavailable = with_tcp_routes(DnsForwarderStatus::ImageWithoutDnsMode);
        let rendered = render_report(&with_forwarder(unavailable));
        assert!(!rendered.contains("tcp routes"), "{rendered}");
    }

    #[test]
    fn doctor_looks_up_the_first_registered_name_only_while_the_bridge_is_up() {
        let routes = [
            route("*.demo.test", Mode::Http),
            route("web.demo.test", Mode::Http),
            route("portman.localhost", Mode::Http),
            route("db.demo.test", Mode::Tcp),
        ];
        let up = Some(BridgePhase::Up);
        let name = |name: &str| Ok(name.to_string());
        let why = |why: &str| Err(why.to_string());
        // (bridge phase, routes) → the name, or why none
        let table = [
            (up, &routes[..], name("db.demo.test")),
            (up, &routes[..3], name("web.demo.test")),
            (up, &routes[..1], why("no registered hostname to look up; a wildcard and a `.localhost` name are not looked up")),
            (up, &routes[2..3], why("no registered hostname to look up; a wildcard and a `.localhost` name are not looked up")),
            (up, &[][..], why("no registered hostname to look up; a wildcard and a `.localhost` name are not looked up")),
            (
                Some(BridgePhase::Disabled),
                &routes[..],
                why("the netbridge is disabled, and managed names resolve only while it is up"),
            ),
            (
                Some(BridgePhase::Starting),
                &routes[..],
                why("the netbridge is starting, and managed names resolve only while it is up"),
            ),
            (
                None,
                &routes[..],
                why("the daemon is unreachable, and managed names resolve only through it"),
            ),
        ];
        for (phase, routes, want) in table {
            assert_eq!(forwarder_query_name(phase, routes), want, "phase={phase:?}");
        }
    }

    #[tokio::test]
    async fn the_forwarder_is_looked_at_in_order_and_asked_only_when_it_runs() {
        let ok = |printed: &str| Ok(printed.to_string());
        let failed = |message: &str| DockerCliError::Failed(message.to_string());
        let no_image =
            failed("Error response from daemon: No such image: portman-netbridge/setup:local");
        let no_container =
            failed("Error response from daemon: No such container: portman-netbridge-dns");
        let no_object = failed("Error: No such object: portman-netbridge-dns");
        let no_engine = DockerCliError::NoAnswer("Cannot connect to the Docker daemon".into());
        let no_cli = DockerCliError::NotStarted("`docker` not found".into());
        let err = |error: &DockerCliError| Err(error.clone());
        let unavailable =
            |error: &DockerCliError| DnsForwarderStatus::DockerUnavailable(error.clone());
        let not_running = |state: Option<&str>| DnsForwarderStatus::NotRunning {
            state: state.map(String::from),
        };
        use DnsForwarderStatus::ImageWithoutDnsMode;
        // (the image's label, the container's state) → status
        let table = [
            (ok("1\n"), Some(ok("running\n")), running(answered())),
            (ok("1\n"), Some(ok("exited\n")), not_running(Some("exited"))),
            (
                ok("1\n"),
                Some(ok("restarting\n")),
                not_running(Some("restarting")),
            ),
            (ok("1\n"), Some(err(&no_container)), not_running(None)),
            (ok("1\n"), Some(err(&no_object)), not_running(None)),
            (ok("1\n"), Some(err(&no_image)), unavailable(&no_image)),
            (ok("1\n"), Some(err(&no_engine)), unavailable(&no_engine)),
            (ok("\n"), None, ImageWithoutDnsMode),
            (ok("2\n"), None, ImageWithoutDnsMode),
            (err(&no_image), None, ImageWithoutDnsMode),
            (err(&no_object), None, ImageWithoutDnsMode),
            (err(&no_container), None, unavailable(&no_container)),
            (err(&no_engine), None, unavailable(&no_engine)),
            (err(&no_cli), None, unavailable(&no_cli)),
        ];
        for (image_label, container_state, want) in table {
            let case = format!("{image_label:?} {container_state:?}");
            let looked_up = std::cell::Cell::new(false);
            let status = classify_dns_forwarder(
                image_label,
                async { container_state.expect("the container was asked about") },
                async {
                    looked_up.set(true);
                    answered()
                },
            )
            .await;
            assert_eq!(looked_up.get(), want == running(answered()), "{case}");
            assert_eq!(status, want, "{case}");
        }
    }

    #[test]
    fn a_lookup_is_answered_only_by_a_run_that_succeeds_and_prints_an_address() {
        let name = || "web.demo.test".to_string();
        let unanswered = |detail: &str| ForwarderQuery::Unanswered {
            name: name(),
            detail: detail.to_string(),
        };
        let found = "192.168.99.1  web.demo.test\n";
        // (the run succeeded, stdout, stderr) → the query
        let table = [
            (true, found, "", answered()),
            (false, found, "", unanswered("getent found no address")),
            (false, "", "", unanswered("getent found no address")),
            (true, "", "", unanswered("getent found no address")),
            (
                false,
                "",
                "\ndocker: Error response from daemon: no such image.\nSee 'docker run --help'.\n",
                unanswered("docker: Error response from daemon: no such image."),
            ),
        ];
        for (succeeded, stdout, stderr, want) in table {
            assert_eq!(
                forwarder_query(name(), succeeded, stdout, stderr),
                want,
                "succeeded={succeeded} stdout={stdout:?} stderr={stderr:?}"
            );
        }
    }

    /// Runs the lookup against a script that stands for `docker`. The script
    /// gets the CLI's arguments as `$@`. Returns the query and the argument
    /// line of each call that the script got.
    async fn look_up_with(script: &str, bound: Duration) -> (ForwarderQuery, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let calls = dir.path().join("calls");
        let script = format!("echo \"$*\" >> '{}'\n{script}", calls.display());
        let docker = ["sh", "-c", &script, "docker"];

        let query = look_up_through_forwarder(&docker, "web.demo.test".to_string(), bound).await;

        let calls = std::fs::read_to_string(calls).unwrap();
        (query, calls.lines().map(String::from).collect())
    }

    #[tokio::test]
    async fn a_lookup_that_does_not_end_is_killed_and_its_container_is_removed() {
        let container = format!("portman-doctor-lookup-{}", std::process::id());
        let hangs_then = |rm: &str| format!("case $1 in run) exec sleep 2;; rm) {rm};; esac");
        let no_engine = "echo 'Cannot connect to the Docker daemon' >&2; exit 1";
        let gone = "echo 'Error response from daemon: No such container' >&2; exit 1";
        let left = format!(
            "no answer in 0.1 s; the lookup container can still exist, `docker rm --force {container}` removes it"
        );
        // how `docker rm` ends → what doctor says about the lookup
        let table = [
            ("exit 0", "no answer in 0.1 s"),
            (gone, "no answer in 0.1 s"),
            (no_engine, left.as_str()),
        ];
        for (rm, detail) in table {
            let (query, calls) = look_up_with(&hangs_then(rm), Duration::from_millis(100)).await;

            let not_run = ForwarderQuery::NotRun {
                name: "web.demo.test".to_string(),
                error: DockerCliError::NoAnswer(detail.to_string()),
            };
            assert_eq!(query, not_run, "{rm}");
            assert_eq!(calls.len(), 2, "{calls:?}");
            let named = format!("run --rm --pull never --name {container} --dns 192.168.99.129 ");
            assert!(calls[0].starts_with(&named), "{calls:?}");
            assert_eq!(calls[1], format!("rm --force {container}"), "{rm}");
        }
    }

    #[tokio::test]
    async fn a_lookup_whose_docker_call_reaches_no_engine_reads_as_a_call_with_no_answer() {
        let no_engine = "Cannot connect to the Docker daemon at unix:///run/demo/docker.sock";
        let run = format!("echo '{no_engine}' >&2; exit 1");

        let (query, calls) = look_up_with(&run, Duration::from_secs(60)).await;

        let not_run = ForwarderQuery::NotRun {
            name: "web.demo.test".to_string(),
            error: DockerCliError::NoAnswer(no_engine.to_string()),
        };
        assert_eq!(query, not_run);
        assert_eq!(calls.len(), 1, "{calls:?}");
    }

    #[tokio::test]
    async fn a_lookup_that_ends_in_time_removes_nothing() {
        let found = "echo '192.168.99.1  web.demo.test'";
        let unanswered = ForwarderQuery::Unanswered {
            name: "web.demo.test".to_string(),
            detail: "getent found no address".to_string(),
        };
        // how `docker run` ends → the query
        let table = [(found, answered()), ("exit 2", unanswered)];
        for (run, want) in table {
            let (query, calls) = look_up_with(run, Duration::from_secs(60)).await;

            assert_eq!(query, want, "{run}");
            assert_eq!(calls.len(), 1, "{calls:?}");
            assert!(
                calls[0].ends_with(
                    "--dns-opt timeout:2 --dns-opt attempts:1 --entrypoint getent portman-netbridge/setup:local hosts web.demo.test"
                ),
                "{calls:?}"
            );
        }
    }

    #[test]
    fn the_note_lists_only_the_tcp_routes_whose_target_is_on_the_portman_network() {
        let to = |host: &str, target: &str, mode| Entry {
            target: target.to_string(),
            ..route(host, mode)
        };
        let routes = [
            to("web.demo.test", "192.168.99.131:80", Mode::Http),
            to("mq.demo.test", "192.168.99.255:5672", Mode::Tcp),
            to("db.demo.test", "192.168.99.128:5432", Mode::Tcp),
            to("api.acme.test", "192.168.99.132:443", Mode::Egress),
            to("below.demo.test", "192.168.99.127:5432", Mode::Tcp),
            to("above.demo.test", "192.168.100.0:5432", Mode::Tcp),
            to("bridge.demo.test", "172.17.0.2:5432", Mode::Tcp),
            to("host.demo.test", "127.0.0.1:5432", Mode::Tcp),
            to("named.demo.test", "db.acme.test:5432", Mode::Tcp),
            to("v6.demo.test", "[fd00::1]:5432", Mode::Tcp),
        ];

        assert_eq!(
            tcp_routes_on_the_portman_network(&routes),
            ["db.demo.test", "mq.demo.test"]
        );
        assert_eq!(
            tcp_routes_on_the_portman_network(&routes[..1]),
            [] as [&str; 0]
        );
    }

    #[test]
    fn doctor_and_the_netbridge_name_one_subnet_for_the_portman_network() {
        let tunnel = include_str!("../../portman-netbridge/src/tunnel.rs");
        let netbridge_names =
            format!("pub const DOCKER_BRIDGE_CIDR: &str = \"{PORTMAN_NETWORK_CIDR}\";");

        assert!(
            tunnel.lines().any(|line| line == netbridge_names),
            "{netbridge_names}"
        );
    }

    #[test]
    fn the_answer_is_the_first_address_that_getent_prints() {
        // stdout of `getent hosts <name>` → the address
        let table = [
            (
                "192.168.99.1     web.demo.test  web.demo.test\n",
                Some("192.168.99.1"),
            ),
            (
                "192.168.99.130  db.demo.test\n192.168.99.131  db.demo.test\n",
                Some("192.168.99.130"),
            ),
            ("fd00::1  web.demo.test\n", Some("fd00::1")),
            ("", None),
            ("\n", None),
            ("web.demo.test\n", None),
        ];
        for (stdout, address) in table {
            assert_eq!(
                getent_address(stdout),
                address.map(String::from),
                "{stdout:?}"
            );
        }
    }

    #[test]
    fn the_embedded_setup_image_carries_the_label_that_doctor_reads() {
        let dockerfile = include_str!("../../portman-netbridge/setup-image/Dockerfile");
        let (key, value) = DNS_IMAGE_LABEL;
        let label = format!("LABEL {key}=\"{value}\"");

        assert!(dockerfile.lines().any(|line| line == label), "{label}");
    }

    #[test]
    fn doctor_takes_its_verdict_on_the_routes_from_the_health_that_the_daemon_reports() {
        use portman_protocol::BridgeAssessment::{
            Healthy, Offline, RoutesMissing, TunnelDead, Unknown,
        };
        let route = |network: &str, subnet: &str, iface: &str| DockerRouteDiagnostic {
            network: network.to_string(),
            subnet: subnet.to_string(),
            hosts: vec!["web.demo.test".to_string()],
            route_iface: Some(iface.to_string()),
        };
        let on_portman_and_a_second_network = DockerRouteStatus::Routes(vec![
            route("demo_default", "172.18.0.0/16", "en0"),
            route("portman", "192.168.99.128/25", "utun9"),
        ]);
        let through_the_utun_of_a_vpn =
            DockerRouteStatus::Routes(vec![route("demo_default", "172.18.0.0/16", "utun4")]);
        let none = DockerRouteStatus::NoLabelledContainers;
        // (the health, what the docker CLI and the routing table show) → ready
        let table = [
            (Healthy, &on_portman_and_a_second_network, true),
            (Healthy, &through_the_utun_of_a_vpn, true),
            (Healthy, &none, true),
            (RoutesMissing, &on_portman_and_a_second_network, false),
            (RoutesMissing, &through_the_utun_of_a_vpn, false),
            (RoutesMissing, &none, false),
            (TunnelDead, &through_the_utun_of_a_vpn, false),
            (Offline, &none, false),
            (Unknown, &none, false),
        ];
        for (health, routes, ready) in table {
            let mut report = ready_but_for_the_bridge(BridgePhase::Up);
            report.daemon.bridge_assessment = Some(health);
            report.docker_routes = routes.clone();

            let rendered = render_report(&report);

            assert!(
                rendered.contains(&format!("bridge: {health} netbridge: up")),
                "{rendered}"
            );
            assert_eq!(
                rendered.contains("replacement: ready"),
                ready,
                "health={health} routes={routes:?}\n{rendered}"
            );
            for line in render_docker_routes(routes) {
                assert!(rendered.contains(&line), "{line}\n{rendered}");
            }
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
            dns_forwarder: Some(forwarder(running(answered()))),
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
            dns_forwarder: Some(forwarder(running(answered()))),
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
