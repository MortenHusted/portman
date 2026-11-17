//! Service-runner commands: status, up, down, logs.

use std::future::Future;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use portman_protocol::{ServiceState, ServiceStatusInfo};
use tokio::time::{sleep, timeout, timeout_at, Duration, Instant};

use crate::client::request;
use portman_protocol::{Request, Response};

pub(crate) async fn cmd_status(repo: bool) -> Result<()> {
    let repo_root = if repo {
        Some(load_repo_services()?.root)
    } else {
        None
    };
    let resp = request(Request::Status).await?;
    match resp {
        Response::Status {
            version,
            running_since,
            dns_port,
            proxy_port,
            tls_port,
            socket_path,
            data_dir,
            cert_dir,
            bridge_assessment: _bridge_assessment,
            bridge_enabled: _bridge_enabled,
            bridge_phase: _bridge_phase,
            bridge_retry_in_secs: _bridge_retry_in_secs,
            bridge_cleanup: _bridge_cleanup,
            bridge_mode: _bridge_mode,
            dashboard_port: _,
            managed_broker,
            egress_grants_version,
            inference_provisioning_version,
            docker,
        } => {
            println!("daemon version:  {version}");
            println!("managed broker:  {managed_broker} (egress grants v{egress_grants_version}, inference provisioning v{inference_provisioning_version})");
            println!("running for:     {running_since}");
            println!("dns port:        {dns_port} (127.0.0.1)");
            println!("http proxy:      {proxy_port} (127.0.0.1)");
            println!("tls proxy:       {tls_port} (127.0.0.1)");
            if proxy_port == 80 {
                println!(
                    "dashboard:       http://{}",
                    portman_core::registry::DASHBOARD_HOST
                );
            } else {
                println!(
                    "dashboard:       http://{}:{proxy_port}",
                    portman_core::registry::DASHBOARD_HOST
                );
            }
            println!("socket:          {socket_path}");
            println!("data dir:        {data_dir}");
            println!("cert dir:        {cert_dir}");
            if let Some(line) = docker_line(docker.as_ref()) {
                println!("{line}");
            }
            #[cfg(target_os = "macos")]
            {
                println!("bridge:          {_bridge_assessment}");
                println!(
                    "{}",
                    netbridge_line(
                        _bridge_phase.or_from_enabled(_bridge_enabled),
                        _bridge_retry_in_secs
                    )
                );
                if let Some(line) = bridge_cleanup_line(_bridge_cleanup) {
                    println!("{line}");
                }
                println!(
                    "netbridge mode:  {}",
                    portman_protocol::NetbridgeMode::display_word(_bridge_mode)
                );
            }
        }
        other => return other.unexpected(),
    }
    // Supervised services, when any are synced. Older daemons answer Err
    // for the unknown request — quietly skip the section.
    if let Ok(Response::ServiceStatuses { mut services }) = request(Request::ServiceStatus).await {
        if let Some(root) = repo_root {
            let missing_ownership = services.iter().any(|service| service.root.is_none());
            services.retain(|service| service.root.as_ref() == Some(&root));
            if missing_ownership {
                eprintln!("warning: older daemon omitted service ownership; upgrade it for repo-scoped status");
            }
        }
        print_service_statuses(&services);
    }
    Ok(())
}

/// The `docker` line of `portman status`. A daemon that predates the field
/// reports no engine state, and status then prints no line.
fn docker_line(docker: Option<&portman_protocol::DockerStatus>) -> Option<String> {
    docker.map(|docker| format!("docker:          {}", docker.summary()))
}

#[cfg(any(target_os = "macos", test))]
fn netbridge_line(phase: portman_protocol::BridgePhase, retry_in_secs: Option<u64>) -> String {
    format!("netbridge:       {}", phase.status_words(retry_in_secs))
}

/// The `bridge cleanup` line of `portman status`. A daemon that reports no
/// cleanup state gets no line.
#[cfg(any(target_os = "macos", test))]
fn bridge_cleanup_line(cleanup: Option<portman_protocol::BridgeCleanup>) -> Option<String> {
    cleanup.map(|held| format!("bridge cleanup:  {}", held.in_words()))
}

/// Load and validate this repo's service config (walking up from the cwd).
pub(crate) fn load_repo_services() -> Result<portman_core::service_config::ServiceConfig> {
    let cwd = std::env::current_dir().context("resolving current directory")?;
    let root = portman_core::service_config::discover_root(&cwd).with_context(|| {
        format!(
            "no {} or {} found in {} or any parent directory",
            portman_core::service_config::CONFIG_FILE,
            portman_core::service_config::LOCAL_CONFIG_FILE,
            cwd.display()
        )
    })?;
    portman_core::service_config::load(&root)
}

pub(crate) async fn cmd_up(names: Vec<String>) -> Result<()> {
    let config = load_repo_services()?;
    if config.services.is_empty() && config.egress.is_empty() {
        bail!(
            "no [service.<name>] or [egress.<name>] blocks defined in {}",
            config.root.display()
        );
    }
    for name in &names {
        if !config.services.contains_key(name) {
            bail!(
                "service `{name}` is not defined in this repo's config (available: {})",
                config
                    .services
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    // Sync the freshly parsed config — this is the KTD6 sync point where
    // config edits take effect.
    let resp = request(Request::SyncServices {
        root: config.root.clone(),
        services: config.services.values().cloned().collect(),
        secrets: config.secrets.clone(),
        egress: config.egress.clone(),
    })
    .await?;
    match resp {
        Response::SyncReport {
            added,
            updated,
            removed,
            ..
        } => {
            for name in &added {
                println!("+ {name}");
            }
            for name in &updated {
                println!("~ {name} (definition changed, restarting)");
            }
            for name in &removed {
                println!("- {name} (removed from config, stopped)");
            }
        }
        other => return other.unexpected(),
    }

    let targets: Vec<String> = if names.is_empty() {
        config.services.keys().cloned().collect()
    } else {
        names
    };
    // An egress-only config is fully applied by the sync. The daemon refuses
    // an empty `ServiceUp`; older daemons started every service with it.
    if targets.is_empty() {
        return Ok(());
    }
    let resp = request(Request::ServiceUp {
        names: targets.clone(),
    })
    .await?;
    match resp {
        Response::ServiceStatuses { .. } => {}
        other => return other.unexpected(),
    }

    wait_and_print_outcome(&targets).await
}

/// Poll service status until every target settles (ready / failed /
/// stopped), printing state transitions as they happen.
pub(crate) async fn wait_and_print_outcome(targets: &[String]) -> Result<()> {
    use std::collections::HashMap;
    let mut last_seen: HashMap<String, ServiceState> = HashMap::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let resp = request(Request::ServiceStatus).await?;
        let services = match resp {
            Response::ServiceStatuses { services } => services,
            other => return other.unexpected(),
        };
        let mut all_settled = true;
        let mut any_failed = false;
        for status in services.iter().filter(|s| targets.contains(&s.name)) {
            let prev = last_seen.get(&status.name);
            if prev.copied() != Some(status.state) {
                if status.detail.is_empty() {
                    println!("{:<24} {}", status.name, status.state);
                } else {
                    println!("{:<24} {}  ({})", status.name, status.state, status.detail);
                }
                last_seen.insert(status.name.clone(), status.state);
            }
            match status.state {
                ServiceState::Ready | ServiceState::Stopped => {}
                ServiceState::Failed => any_failed = true,
                _ => all_settled = false,
            }
        }
        if all_settled {
            if any_failed {
                bail!("one or more services failed — see `portman logs <service>`");
            }
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            bail!(readiness_timeout_message(targets, &last_seen));
        }
        sleep(Duration::from_millis(300)).await;
    }
}

pub(crate) fn readiness_timeout_message(
    targets: &[String],
    last_seen: &std::collections::HashMap<String, ServiceState>,
) -> String {
    let unresolved = targets
        .iter()
        .filter(|name| {
            !matches!(
                last_seen.get(*name),
                Some(ServiceState::Ready | ServiceState::Stopped | ServiceState::Failed)
            )
        })
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "services did not settle within 120s: {unresolved} — check `portman status` / `portman logs`"
    )
}

const RECORD_LIMIT: Duration = Duration::from_secs(3);
const NEW_DAEMON_LIMIT: Duration = Duration::from_secs(30);
const READY_LIMIT: Duration = Duration::from_secs(120);
const POLL_PAUSE: Duration = Duration::from_millis(300);
const FAILED_ATTEMPTS_THAT_END_THE_WAIT: u32 = 2;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InterruptedServices(Vec<UpService>);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Recorded {
    Services(InterruptedServices),
    NoAnswerInTime,
}

enum LastPoll {
    Answered(Vec<ServiceStatusInfo>),
    Unanswered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpService {
    name: String,
    root: Option<PathBuf>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RestartReport {
    started: Vec<String>,
    dependencies: Vec<String>,
    in_backoff: Vec<NotStarted>,
    not_started: Vec<NotStarted>,
    unconfirmed: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct NotStarted {
    service: UpService,
    why: String,
}

impl UpService {
    fn place(&self) -> String {
        match &self.root {
            Some(root) => root.display().to_string(),
            None => "its repository".to_string(),
        }
    }
}

impl InterruptedServices {
    pub(crate) async fn record() -> Recorded {
        Self::record_from(request).await
    }

    async fn record_from<F, Fut>(mut send: F) -> Recorded
    where
        F: FnMut(Request) -> Fut,
        Fut: Future<Output = Result<Response>>,
    {
        let Ok(answer) = timeout(RECORD_LIMIT, send(Request::ServiceStatus)).await else {
            return Recorded::NoAnswerInTime;
        };
        let Ok(Response::ServiceStatuses { services }) = answer else {
            return Recorded::Services(Self(Vec::new()));
        };
        Recorded::Services(Self(
            services
                .into_iter()
                .filter(is_up)
                .map(|status| UpService {
                    name: status.name,
                    root: status.root,
                })
                .collect(),
        ))
    }

    pub(crate) async fn restore(self) {
        if !self.0.is_empty() {
            eprintln!("starting them again on the new daemon…");
        }
        for line in self.restore_through(request).await.lines() {
            eprintln!("{line}");
        }
    }

    async fn restore_through<F, Fut>(self, mut send: F) -> RestartReport
    where
        F: FnMut(Request) -> Fut,
        Fut: Future<Output = Result<Response>>,
    {
        let mut report = RestartReport::default();
        if self.0.is_empty() {
            return report;
        }
        let names = self.names();
        let listed = poll_services(&mut send, NEW_DAEMON_LIMIT, |rows| {
            names
                .iter()
                .all(|name| rows.iter().any(|row| row.name == *name))
        })
        .await;
        let LastPoll::Answered(listed) = listed else {
            report.fail(self.0, "the new daemon did not answer within 30s");
            return report;
        };
        let (known, unknown): (Vec<_>, Vec<_>) = self
            .0
            .into_iter()
            .partition(|service| listed.iter().any(|row| row.name == service.name));
        report.fail(unknown, "the new daemon has no definition for it");
        if known.is_empty() {
            return report;
        }

        let names: Vec<String> = known.iter().map(|service| service.name.clone()).collect();
        let start = send(Request::ServiceUp {
            names: names.clone(),
        });
        let Ok(asked) = timeout(NEW_DAEMON_LIMIT, start).await else {
            report.unconfirmed = names;
            return report;
        };
        let asked = asked.and_then(|response| match response {
            Response::ServiceStatuses { services } => Ok(services),
            other => other.unexpected(),
        });
        let wanted_up = match asked {
            Ok(rows) => rows.into_iter().filter(|row| row.desired_up),
            Err(err) => {
                report.fail(known, &format!("{err:#}"));
                return report;
            }
        };
        let was_down = |name: &String| {
            listed
                .iter()
                .any(|row| row.name == *name && !row.desired_up)
        };
        let dependencies: Vec<String> = wanted_up
            .map(|row| row.name)
            .filter(|name| !names.contains(name) && was_down(name))
            .collect();

        let rows = poll_services(&mut send, READY_LIMIT, |rows| {
            rows.iter()
                .filter(|row| names.contains(&row.name))
                .all(start_ended)
        })
        .await;
        let LastPoll::Answered(rows) = rows else {
            report.unconfirmed = names;
            return report;
        };
        for service in known {
            match rows.iter().find(|row| row.name == service.name) {
                Some(row) if row.state == ServiceState::Ready => report.started.push(service.name),
                Some(row) => {
                    let why = why_not_ready(row);
                    let outcome = match row.state {
                        ServiceState::Backoff => &mut report.in_backoff,
                        _ => &mut report.not_started,
                    };
                    outcome.push(NotStarted { service, why });
                }
                None => report.fail(vec![service], "the new daemon no longer lists it"),
            }
        }
        let ready = |name: &String| {
            rows.iter()
                .any(|row| row.name == *name && row.state == ServiceState::Ready)
        };
        report.dependencies = dependencies.into_iter().filter(ready).collect();
        report
    }

    pub(crate) fn say_how_to_start(&self) {
        for line in self.start_lines() {
            eprintln!("{line}");
        }
    }

    fn start_lines(&self) -> Vec<String> {
        if self.0.is_empty() {
            return Vec::new();
        }
        let head = "the daemon did not start, so these services stay down. \
                    When the daemon runs again, start each one:";
        let commands = self.0.iter().map(|service| {
            let (name, place) = (&service.name, service.place());
            format!("  `portman up {name}` in {place}")
        });
        std::iter::once(head.to_string()).chain(commands).collect()
    }

    fn names(&self) -> Vec<String> {
        self.0.iter().map(|service| service.name.clone()).collect()
    }
}

impl Recorded {
    pub(crate) fn say_what_stops(self) -> InterruptedServices {
        for line in self.lines() {
            eprintln!("{line}");
        }
        match self {
            Self::Services(up) => up,
            Self::NoAnswerInTime => InterruptedServices(Vec::new()),
        }
    }

    fn lines(&self) -> Vec<String> {
        match self {
            Self::NoAnswerInTime => vec![
                "the daemon gave no answer within 3s, so the install cannot name the services \
                 that are up. They stop with the daemon. Start each one again with `portman up` \
                 in its repository."
                    .to_string(),
            ],
            Self::Services(up) if up.0.is_empty() => Vec::new(),
            Self::Services(up) => vec![format!(
                "the restart of the daemon stops these services: {}",
                up.names().join(", ")
            )],
        }
    }
}

impl RestartReport {
    fn fail(&mut self, services: Vec<UpService>, why: &str) {
        self.not_started
            .extend(services.into_iter().map(|service| NotStarted {
                service,
                why: why.to_string(),
            }));
    }

    fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.started.is_empty() {
            lines.push(format!("started again: {}", self.started.join(", ")));
        }
        if !self.dependencies.is_empty() {
            lines.push(format!(
                "started as a dependency: {}",
                self.dependencies.join(", ")
            ));
        }
        for NotStarted { service, why } in &self.in_backoff {
            lines.push(format!(
                "could not start {name} again yet: {why}. The daemon tries again as its restart \
                 policy allows. See `portman logs {name}`. If the service ends as failed, run \
                 `portman up {name}` in {place}.",
                name = service.name,
                place = service.place()
            ));
        }
        for NotStarted { service, why } in &self.not_started {
            lines.push(format!(
                "could not start {name} again: {why}. Run `portman up {name}` in {place}.",
                name = service.name,
                place = service.place()
            ));
        }
        if !self.unconfirmed.is_empty() {
            lines.push(format!(
                "the new daemon stopped answering, so the install cannot tell whether these \
                 services started: {}. Run `portman status` when the daemon answers again.",
                self.unconfirmed.join(", ")
            ));
        }
        lines
    }
}

fn is_up(status: &ServiceStatusInfo) -> bool {
    status.desired_up
        && matches!(
            status.state,
            ServiceState::Pending
                | ServiceState::Starting
                | ServiceState::Ready
                | ServiceState::Backoff
        )
}

fn start_ended(row: &ServiceStatusInfo) -> bool {
    match row.state {
        ServiceState::Ready | ServiceState::Failed => true,
        ServiceState::Backoff => row.restarts >= FAILED_ATTEMPTS_THAT_END_THE_WAIT,
        ServiceState::Stopped => !row.desired_up,
        _ => false,
    }
}

fn why_not_ready(row: &ServiceStatusInfo) -> String {
    let state = if start_ended(row) {
        row.state.to_string()
    } else {
        format!("still {} after 120s", row.state)
    };
    if row.detail.is_empty() {
        state
    } else {
        format!("{state} ({})", row.detail)
    }
}

async fn poll_services<F, Fut>(
    send: &mut F,
    limit: Duration,
    done: impl Fn(&[ServiceStatusInfo]) -> bool,
) -> LastPoll
where
    F: FnMut(Request) -> Fut,
    Fut: Future<Output = Result<Response>>,
{
    let deadline = Instant::now() + limit;
    loop {
        let answer = timeout_at(deadline, send(Request::ServiceStatus)).await;
        let last = match answer {
            Ok(Ok(Response::ServiceStatuses { services })) => LastPoll::Answered(services),
            _ => LastPoll::Unanswered,
        };
        let finished = matches!(&last, LastPoll::Answered(rows) if done(rows));
        let next_request_starts = Instant::now() + POLL_PAUSE;
        let next_request_can_be_answered = next_request_starts + POLL_PAUSE <= deadline;
        if finished || !next_request_can_be_answered {
            return last;
        }
        sleep(POLL_PAUSE).await;
    }
}

pub(crate) async fn cmd_down(
    names: Vec<String>,
    forget: bool,
    explicit_root: Option<std::path::PathBuf>,
) -> Result<()> {
    if forget {
        let root = match explicit_root {
            Some(root) if root.is_absolute() => root,
            Some(_) => bail!("--root must be an absolute path"),
            None => load_repo_services()?.root,
        };
        let resp = request(Request::SyncServices {
            root: root.clone(),
            services: Vec::new(),
            secrets: std::collections::BTreeMap::new(),
            egress: std::collections::BTreeMap::new(),
        })
        .await?;
        return match resp {
            Response::SyncReport { removed, .. } => {
                println!("forgot service definitions owned by {}", root.display());
                for name in removed {
                    println!("- {name} (forgotten)");
                }
                Ok(())
            }
            other => return other.unexpected(),
        };
    }

    // With no explicit names, stop the services this repo declares *and*
    // owns. Service names are global, so a declared name can belong to
    // another root that synced it first; the daemon stops by name alone.
    // Outside a repo there is no scope, so names are required.
    let names = if names.is_empty() {
        let cwd = std::env::current_dir().context("resolving current directory")?;
        let Some(root) = portman_core::service_config::discover_root(&cwd) else {
            bail!(
                "no portman.toml or portman.local.toml here — pass service names \
                 explicitly to stop services from outside their repo"
            );
        };
        // A config that exists but doesn't parse is its own error. Blanketing
        // it as "outside a repo" sent a user with a one-character TOML typo
        // looking in entirely the wrong place.
        let config = portman_core::service_config::load(&root)?;
        if config.services.is_empty() {
            bail!(
                "no [service.<name>] blocks in this repo — only egress routes, which \
                 follow the config (remove the block, `portman up`); nothing to stop"
            );
        }
        let services = match request(Request::ServiceStatus).await? {
            Response::ServiceStatuses { services } => services,
            other => return other.unexpected(),
        };
        let mut owned = Vec::new();
        for status in services
            .iter()
            .filter(|s| config.services.contains_key(&s.name))
        {
            match &status.root {
                Some(owner) if *owner == root => owned.push(status.name.clone()),
                Some(owner) => eprintln!(
                    "skipping `{}`: owned by {}, not this repo (name it to stop it anyway)",
                    status.name,
                    owner.display()
                ),
                None => eprintln!(
                    "skipping `{}`: the daemon did not report its owner (upgrade it, or name the service)",
                    status.name
                ),
            }
        }
        if owned.is_empty() {
            println!("nothing to stop: no services owned by {}", root.display());
            return Ok(());
        }
        owned
    } else {
        names
    };
    let resp = request(Request::ServiceDown {
        names: names.clone(),
    })
    .await?;
    match resp {
        Response::ServiceStatuses { services } => {
            for status in services.iter().filter(|s| names.contains(&s.name)) {
                println!("{:<24} {}", status.name, status.state);
            }
            Ok(())
        }
        other => other.unexpected(),
    }
}

pub(crate) async fn cmd_logs(service: String, follow: bool, lines: u32) -> Result<()> {
    let mut cursor = match request(Request::LogsQuery {
        service: service.clone(),
        after_id: None,
        limit: lines,
    })
    .await?
    {
        Response::Logs { lines, last_id } => {
            print_log_lines(&lines);
            last_id
        }
        other => return other.unexpected(),
    };
    if !follow {
        return Ok(());
    }
    loop {
        sleep(Duration::from_millis(250)).await;
        match request(Request::LogsQuery {
            service: service.clone(),
            after_id: Some(cursor),
            limit: 200,
        })
        .await?
        {
            Response::Logs { lines, last_id } => {
                print_log_lines(&lines);
                cursor = last_id;
            }
            other => return other.unexpected(),
        }
    }
}

/// stdout lines go to stdout, stderr lines to stderr — composable, like
/// `docker logs`.
pub(crate) fn print_log_lines(lines: &[portman_protocol::LogLineInfo]) {
    for line in lines {
        if line.stream == "stderr" {
            eprintln!("{}", line.line);
        } else {
            println!("{}", line.line);
        }
    }
}

pub(crate) fn print_service_statuses(services: &[portman_protocol::ServiceStatusInfo]) {
    if services.is_empty() {
        return;
    }
    let name_w = services
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(0)
        .max("SERVICE".len());
    println!(
        "\n{:<name_w$}  {:<8}  {:<7}  {:<8}  {:<24}  DETAIL",
        "SERVICE",
        "STATE",
        "PID",
        "RESTARTS",
        "HOST",
        name_w = name_w
    );
    for s in services {
        let pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
        let host = s.host.as_deref().unwrap_or("-");
        println!(
            "{:<name_w$}  {:<8}  {:<7}  {:<8}  {:<24}  {}",
            s.name,
            s.state,
            pid,
            s.restarts,
            host,
            s.detail,
            name_w = name_w
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_prints_a_docker_line_only_when_the_daemon_reports_the_engine() {
        let line = |json: &str| match serde_json::from_str(json).unwrap() {
            Response::Status { docker, .. } => docker_line(docker.as_ref()),
            other => panic!("expected status response, got {other:?}"),
        };

        assert_eq!(line(r#"{"kind":"status","version":"0.1.5"}"#), None);
        assert_eq!(
            line(
                r#"{"kind":"status","docker":{"state":"disconnected","socket":"/run/demo/docker.sock","reason":"no socket"}}"#
            )
            .as_deref(),
            Some("docker:          disconnected, no socket at /run/demo/docker.sock")
        );
        assert_eq!(
            line(r#"{"kind":"status","docker":{"state":"paused"}}"#).as_deref(),
            Some("docker:          unknown")
        );
    }

    fn service(name: &str, state: ServiceState, desired_up: bool) -> ServiceStatusInfo {
        ServiceStatusInfo {
            name: name.into(),
            root: Some(format!("/Users/dev/acme/{name}").into()),
            repo: None,
            config_missing: false,
            state,
            detail: String::new(),
            pid: None,
            restarts: 0,
            host: None,
            port: None,
            desired_up,
            groups: Vec::new(),
            project: None,
        }
    }

    fn up(name: &str) -> UpService {
        UpService {
            name: name.into(),
            root: Some(format!("/Users/dev/acme/{name}").into()),
        }
    }

    #[derive(Default)]
    struct NewDaemon {
        refused_connections: usize,
        services: Vec<ServiceStatusInfo>,
        ends: std::collections::HashMap<String, (ServiceState, String)>,
        depends: std::collections::HashMap<String, Vec<String>>,
        courses: std::collections::HashMap<String, std::collections::VecDeque<Step>>,
        start_requests: Vec<Vec<String>>,
    }

    type Step = (ServiceState, u32, &'static str);

    impl NewDaemon {
        fn holding(names: &[&str]) -> Self {
            Self {
                services: names
                    .iter()
                    .map(|name| service(name, ServiceState::Stopped, false))
                    .collect(),
                ..Self::default()
            }
        }

        fn after_the_start_request<const N: usize>(&mut self, name: &str, steps: [Step; N]) {
            self.courses.insert(name.into(), steps.into());
        }

        fn take_one_step(&mut self) {
            for row in &mut self.services {
                let Some(course) = self.courses.get_mut(&row.name) else {
                    continue;
                };
                let last_step_stays = course.len() == 1;
                let step = if last_step_stays {
                    course.front().copied()
                } else {
                    course.pop_front()
                };
                if let Some((state, restarts, detail)) = step {
                    row.state = state;
                    row.restarts = restarts;
                    row.detail = detail.into();
                }
            }
        }

        fn answer(&mut self, request: Request) -> Result<Response> {
            if self.refused_connections > 0 {
                self.refused_connections -= 1;
                bail!("connection refused");
            }
            if matches!(request, Request::ServiceStatus) && !self.start_requests.is_empty() {
                self.take_one_step();
            }
            if let Request::ServiceUp { names } = request {
                let dependencies = names.iter().filter_map(|name| self.depends.get(name));
                let targets: Vec<&String> = dependencies.flatten().chain(&names).collect();
                for row in self
                    .services
                    .iter_mut()
                    .filter(|row| targets.contains(&&row.name))
                {
                    let (state, detail) = self
                        .ends
                        .get(&row.name)
                        .cloned()
                        .unwrap_or((ServiceState::Ready, String::new()));
                    row.desired_up = true;
                    row.state = state;
                    row.detail = detail;
                }
                self.start_requests.push(names);
            }
            Ok(Response::ServiceStatuses {
                services: self.services.clone(),
            })
        }
    }

    async fn restore(interrupted: InterruptedServices, daemon: &mut NewDaemon) -> RestartReport {
        interrupted
            .restore_through(|request| std::future::ready(daemon.answer(request)))
            .await
    }

    #[tokio::test]
    async fn the_install_records_only_the_services_that_are_up() {
        let old_daemon = vec![
            service("web", ServiceState::Ready, true),
            service("jobs", ServiceState::Backoff, true),
            service("idle", ServiceState::Stopped, false),
            service("broken", ServiceState::Failed, true),
        ];

        let recorded = InterruptedServices::record_from(|_| {
            std::future::ready(Ok(Response::ServiceStatuses {
                services: old_daemon.clone(),
            }))
        })
        .await;

        assert_eq!(
            recorded,
            Recorded::Services(InterruptedServices(vec![up("web"), up("jobs")]))
        );
        assert_eq!(
            recorded.lines(),
            ["the restart of the daemon stops these services: web, jobs"]
        );
    }

    #[tokio::test]
    async fn a_first_install_records_nothing_and_asks_the_new_daemon_nothing() {
        let recorded = InterruptedServices::record_from(|_| {
            std::future::ready(Err(anyhow::anyhow!("no daemon socket")))
        })
        .await;
        assert_eq!(recorded.lines(), Vec::<String>::new());
        let Recorded::Services(recorded) = recorded else {
            panic!("a refused connection is an answer");
        };
        assert_eq!(recorded, InterruptedServices(Vec::new()));

        let report = recorded
            .restore_through(|request| -> std::future::Ready<Result<Response>> {
                panic!("a first install sent {request:?}")
            })
            .await;

        assert_eq!(report.lines(), Vec::<String>::new());
    }

    #[tokio::test(start_paused = true)]
    async fn the_install_starts_what_was_up_once_the_new_daemon_answers() {
        let mut daemon = NewDaemon {
            refused_connections: 3,
            ..NewDaemon::holding(&["idle", "jobs", "web"])
        };

        let report = restore(
            InterruptedServices(vec![up("web"), up("jobs")]),
            &mut daemon,
        )
        .await;

        assert_eq!(daemon.start_requests, [["web", "jobs"]]);
        assert_eq!(report.lines(), ["started again: web, jobs"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_service_that_fails_to_start_again_is_named_with_its_command() {
        let mut daemon = NewDaemon::holding(&["jobs", "web"]);
        daemon.ends.insert(
            "jobs".into(),
            (ServiceState::Failed, "exited with status 3".into()),
        );

        let report = restore(
            InterruptedServices(vec![up("web"), up("jobs")]),
            &mut daemon,
        )
        .await;

        assert_eq!(
            report.lines(),
            [
                "started again: web",
                "could not start jobs again: failed (exited with status 3). \
                 Run `portman up jobs` in /Users/dev/acme/jobs.",
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_service_that_is_ready_on_its_second_attempt_is_started_again() {
        let mut daemon = NewDaemon::holding(&["jobs", "web"]);
        daemon.after_the_start_request(
            "web",
            [
                (
                    ServiceState::Backoff,
                    1,
                    "port 3000 is taken; restarting in 500ms",
                ),
                (ServiceState::Starting, 1, ""),
                (ServiceState::Ready, 1, ""),
            ],
        );

        let report = restore(
            InterruptedServices(vec![up("web"), up("jobs")]),
            &mut daemon,
        )
        .await;

        assert_eq!(report.lines(), ["started again: web, jobs"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_service_that_fails_for_good_on_its_second_attempt_is_named_as_failed() {
        let mut daemon = NewDaemon::holding(&["web"]);
        daemon.after_the_start_request(
            "web",
            [
                (
                    ServiceState::Backoff,
                    1,
                    "exited with status 1; restarting in 500ms",
                ),
                (ServiceState::Starting, 1, ""),
                (ServiceState::Failed, 1, "exited with status 1"),
            ],
        );

        let report = restore(InterruptedServices(vec![up("web")]), &mut daemon).await;

        assert_eq!(
            report.lines(),
            ["could not start web again: failed (exited with status 1). \
              Run `portman up web` in /Users/dev/acme/web."]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_service_that_fails_twice_is_named_while_the_daemon_tries_again() {
        let mut daemon = NewDaemon::holding(&["jobs", "web"]);
        daemon.after_the_start_request(
            "web",
            [
                (
                    ServiceState::Backoff,
                    1,
                    "port 3000 is taken; restarting in 500ms",
                ),
                (ServiceState::Starting, 1, ""),
                (
                    ServiceState::Backoff,
                    2,
                    "port 3000 is taken; restarting in 1000ms",
                ),
            ],
        );
        let began = Instant::now();

        let report = restore(
            InterruptedServices(vec![up("web"), up("jobs")]),
            &mut daemon,
        )
        .await;

        assert_eq!(
            report.lines(),
            [
                "started again: jobs",
                "could not start web again yet: backoff (port 3000 is taken; restarting in \
                 1000ms). The daemon tries again as its restart policy allows. See `portman \
                 logs web`. If the service ends as failed, run `portman up web` in \
                 /Users/dev/acme/web.",
            ]
        );
        assert!(began.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_started_service_that_still_reads_stopped_is_waited_for() {
        let mut daemon = NewDaemon::holding(&["web"]);
        daemon
            .ends
            .insert("web".into(), (ServiceState::Stopped, String::new()));
        let mut reads_after_start = 0;

        let report = InterruptedServices(vec![up("web")])
            .restore_through(|request| {
                if !daemon.start_requests.is_empty() && matches!(request, Request::ServiceStatus) {
                    reads_after_start += 1;
                    if reads_after_start == 2 {
                        daemon.services[0].state = ServiceState::Ready;
                    }
                }
                std::future::ready(daemon.answer(request))
            })
            .await;

        assert_eq!(report.lines(), ["started again: web"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_service_that_the_new_daemon_does_not_hold_is_named() {
        let mut daemon = NewDaemon::holding(&["web"]);

        let report = restore(
            InterruptedServices(vec![up("web"), up("jobs")]),
            &mut daemon,
        )
        .await;

        assert_eq!(daemon.start_requests, [["web"]]);
        assert_eq!(
            report.lines(),
            [
                "started again: web",
                "could not start jobs again: the new daemon has no definition for it. \
                 Run `portman up jobs` in /Users/dev/acme/jobs.",
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn every_service_is_named_when_the_new_daemon_never_answers() {
        let mut daemon = NewDaemon {
            refused_connections: usize::MAX,
            ..NewDaemon::default()
        };

        let report = restore(
            InterruptedServices(vec![up("web"), up("jobs")]),
            &mut daemon,
        )
        .await;

        assert_eq!(
            report.lines(),
            [
                "could not start web again: the new daemon did not answer within 30s. \
                 Run `portman up web` in /Users/dev/acme/web.",
                "could not start jobs again: the new daemon did not answer within 30s. \
                 Run `portman up jobs` in /Users/dev/acme/jobs.",
            ]
        );
    }

    fn no_answer(_: Request) -> std::future::Pending<Result<Response>> {
        std::future::pending()
    }

    async fn returned<T>(call: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(3600), call)
            .await
            .expect("the call did not return within an hour")
    }

    fn assert_took(began: Instant, limit: Duration) {
        let took = began.elapsed();
        assert!(
            took >= limit && took < limit + Duration::from_secs(1),
            "took {took:?}, the limit is {limit:?}"
        );
    }

    async fn restore_with_requests_unanswered(
        interrupted: InterruptedServices,
        daemon: &mut NewDaemon,
        unanswered: impl Fn(&Request, &NewDaemon) -> bool,
    ) -> RestartReport {
        returned(interrupted.restore_through(|request| {
            let answer = (!unanswered(&request, daemon)).then(|| daemon.answer(request));
            async move {
                match answer {
                    Some(answer) => answer,
                    None => std::future::pending().await,
                }
            }
        }))
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn the_install_records_nothing_when_the_daemon_accepts_and_does_not_answer() {
        let began = Instant::now();

        let recorded = returned(InterruptedServices::record_from(no_answer)).await;

        assert_eq!(recorded, Recorded::NoAnswerInTime);
        assert_took(began, Duration::from_secs(3));
        assert_eq!(
            recorded.lines(),
            [
                "the daemon gave no answer within 3s, so the install cannot name the services \
                 that are up. They stop with the daemon. Start each one again with `portman up` \
                 in its repository."
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_for_the_new_daemon_ends_after_30s_when_it_accepts_and_does_not_answer() {
        let began = Instant::now();

        let report =
            returned(InterruptedServices(vec![up("web")]).restore_through(no_answer)).await;

        assert_took(began, Duration::from_secs(30));
        assert_eq!(
            report.lines(),
            [
                "could not start web again: the new daemon did not answer within 30s. \
                 Run `portman up web` in /Users/dev/acme/web."
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_install_gives_up_on_a_start_request_that_gets_no_answer() {
        let mut daemon = NewDaemon::holding(&["web"]);
        let began = Instant::now();

        let report = restore_with_requests_unanswered(
            InterruptedServices(vec![up("web")]),
            &mut daemon,
            |request, _| matches!(request, Request::ServiceUp { .. }),
        )
        .await;

        assert_took(began, Duration::from_secs(30));
        assert_eq!(
            report.lines(),
            [
                "the new daemon stopped answering, so the install cannot tell whether these \
                 services started: web. Run `portman status` when the daemon answers again."
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_for_readiness_ends_after_120s_when_the_daemon_stops_answering() {
        let mut daemon = NewDaemon::holding(&["web"]);
        let began = Instant::now();

        restore_with_requests_unanswered(
            InterruptedServices(vec![up("web")]),
            &mut daemon,
            |_, daemon| !daemon.start_requests.is_empty(),
        )
        .await;

        assert_took(began, Duration::from_secs(120));
    }

    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_stops_answering_after_the_start_request_is_named() {
        let mut daemon = NewDaemon::holding(&["web"]);

        let report = InterruptedServices(vec![up("web")])
            .restore_through(|request| {
                if !daemon.start_requests.is_empty() {
                    daemon.refused_connections = usize::MAX;
                }
                std::future::ready(daemon.answer(request))
            })
            .await;

        assert_eq!(
            report.lines(),
            [
                "the new daemon stopped answering, so the install cannot tell whether these \
                 services started: web. Run `portman status` when the daemon answers again."
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dependency_that_the_start_request_brings_up_is_named() {
        let mut daemon = NewDaemon::holding(&["api", "cron", "db"]);
        daemon.depends.insert("api".into(), vec!["db".into()]);
        let started_by_the_daemon_itself = &mut daemon.services[1];
        started_by_the_daemon_itself.desired_up = true;
        started_by_the_daemon_itself.state = ServiceState::Ready;

        let report = restore(InterruptedServices(vec![up("api")]), &mut daemon).await;

        assert_eq!(daemon.start_requests, [["api"]]);
        assert_eq!(
            report.lines(),
            ["started again: api", "started as a dependency: db"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dependency_that_does_not_get_ready_is_not_named_as_started() {
        let mut daemon = NewDaemon::holding(&["api", "db"]);
        daemon.depends.insert("api".into(), vec!["db".into()]);
        daemon.ends.insert(
            "db".into(),
            (ServiceState::Failed, "exited with status 1".into()),
        );
        daemon.ends.insert(
            "api".into(),
            (
                ServiceState::Failed,
                "dependency `db` failed: exited with status 1".into(),
            ),
        );

        let report = restore(InterruptedServices(vec![up("api")]), &mut daemon).await;

        assert_eq!(
            report.lines(),
            [
                "could not start api again: failed (dependency `db` failed: exited with status \
                 1). Run `portman up api` in /Users/dev/acme/api."
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_service_is_not_reported_from_an_answer_that_came_before_the_daemon_stopped() {
        let mut daemon = NewDaemon::holding(&["web"]);
        daemon
            .ends
            .insert("web".into(), (ServiceState::Starting, String::new()));
        let mut reads_after_start = 0;

        let report = InterruptedServices(vec![up("web")])
            .restore_through(|request| {
                if !daemon.start_requests.is_empty() && matches!(request, Request::ServiceStatus) {
                    reads_after_start += 1;
                    if reads_after_start == 3 {
                        daemon.refused_connections = usize::MAX;
                    }
                }
                std::future::ready(daemon.answer(request))
            })
            .await;

        assert_eq!(
            report.lines(),
            [
                "the new daemon stopped answering, so the install cannot tell whether these \
                 services started: web. Run `portman status` when the daemon answers again."
            ]
        );
    }

    #[test]
    fn status_says_when_a_failed_bridge_start_runs_again() {
        let line = |json: &str| match serde_json::from_str(json).unwrap() {
            Response::Status {
                bridge_phase,
                bridge_enabled,
                bridge_retry_in_secs,
                ..
            } => netbridge_line(
                bridge_phase.or_from_enabled(bridge_enabled),
                bridge_retry_in_secs,
            ),
            other => panic!("expected status response, got {other:?}"),
        };

        assert_eq!(
            line(r#"{"kind":"status","bridge_phase":"starting","bridge_retry_in_secs":12}"#),
            "netbridge:       starting, the last start failed, tries again in 12s"
        );
        assert_eq!(
            line(r#"{"kind":"status","bridge_phase":"starting"}"#),
            "netbridge:       starting"
        );
        assert_eq!(
            line(r#"{"kind":"status","version":"0.1.5","bridge_enabled":true}"#),
            "netbridge:       up"
        );
    }

    #[test]
    fn an_install_that_cannot_start_the_daemon_gives_the_command_for_each_service() {
        let no_root = UpService {
            name: "jobs".into(),
            root: None,
        };

        assert_eq!(
            InterruptedServices(vec![up("web"), no_root]).start_lines(),
            [
                "the daemon did not start, so these services stay down. \
                 When the daemon runs again, start each one:",
                "  `portman up web` in /Users/dev/acme/web",
                "  `portman up jobs` in its repository",
            ]
        );
        assert_eq!(
            InterruptedServices(Vec::new()).start_lines(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn status_says_what_holds_up_the_cleanup_of_a_disable_only_while_something_does() {
        let line = |json: &str| match serde_json::from_str(json).unwrap() {
            Response::Status { bridge_cleanup, .. } => bridge_cleanup_line(bridge_cleanup),
            other => panic!("expected status response, got {other:?}"),
        };

        assert_eq!(line(r#"{"kind":"status","bridge_phase":"disabled"}"#), None);
        assert_eq!(
            line(
                r#"{"kind":"status","bridge_phase":"disabled","bridge_cleanup":{"state":"port_taken"}}"#
            )
            .as_deref(),
            Some(
                "bridge cleanup:  portman has not removed the dns forwarder and the `portman` \
                 network: another program holds the UDP port of the bridge and can run a \
                 bridge on them. It does not try again until the next `portman bridge disable`"
            )
        );
    }

    #[test]
    fn readiness_timeout_names_unsettled_services() {
        let targets = vec!["web".to_string(), "jobs".to_string()];
        let last_seen = std::collections::HashMap::from([
            ("web".to_string(), ServiceState::Ready),
            ("jobs".to_string(), ServiceState::Starting),
        ]);

        let message = readiness_timeout_message(&targets, &last_seen);

        assert_eq!(
            message,
            "services did not settle within 120s: jobs — check `portman status` / `portman logs`"
        );
    }
}
