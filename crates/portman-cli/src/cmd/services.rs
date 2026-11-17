//! Service-runner commands: status, up, down, logs.

use std::future::Future;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use portman_protocol::{ServiceState, ServiceStatusInfo};
use tokio::time::{sleep, Duration, Instant};

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

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InterruptedServices(Vec<UpService>);

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpService {
    name: String,
    root: Option<PathBuf>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RestartReport {
    started: Vec<String>,
    not_started: Vec<NotStarted>,
}

#[derive(Debug, PartialEq, Eq)]
struct NotStarted {
    service: UpService,
    why: String,
}

impl InterruptedServices {
    pub(crate) async fn record() -> Self {
        let recorded = Self::record_from(request).await;
        if !recorded.0.is_empty() {
            eprintln!(
                "the restart of the daemon stops these services: {}",
                recorded.names().join(", ")
            );
        }
        recorded
    }

    async fn record_from<F, Fut>(_send: F) -> Self
    where
        F: FnMut(Request) -> Fut,
        Fut: Future<Output = Result<Response>>,
    {
        Self(Vec::new())
    }

    pub(crate) async fn restore(self) {
        if !self.0.is_empty() {
            eprintln!("starting them again on the new daemon…");
        }
        for line in self.restore_through(request).await.lines() {
            eprintln!("{line}");
        }
    }

    async fn restore_through<F, Fut>(self, _send: F) -> RestartReport
    where
        F: FnMut(Request) -> Fut,
        Fut: Future<Output = Result<Response>>,
    {
        drop(self);
        RestartReport::default()
    }

    fn names(&self) -> Vec<String> {
        self.0.iter().map(|service| service.name.clone()).collect()
    }
}

impl RestartReport {
    fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.started.is_empty() {
            lines.push(format!("started again: {}", self.started.join(", ")));
        }
        for NotStarted { service, why } in &self.not_started {
            let place = match &service.root {
                Some(root) => root.display().to_string(),
                None => "its repository".to_string(),
            };
            lines.push(format!(
                "could not start {name} again: {why}. Run `portman up {name}` in {place}.",
                name = service.name
            ));
        }
        lines
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
        start_requests: Vec<Vec<String>>,
    }

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

        fn answer(&mut self, request: Request) -> Result<Response> {
            if self.refused_connections > 0 {
                self.refused_connections -= 1;
                bail!("connection refused");
            }
            if let Request::ServiceUp { names } = request {
                for row in self
                    .services
                    .iter_mut()
                    .filter(|row| names.contains(&row.name))
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

        assert_eq!(recorded, InterruptedServices(vec![up("web"), up("jobs")]));
    }

    #[tokio::test]
    async fn a_first_install_records_nothing_and_asks_the_new_daemon_nothing() {
        let recorded = InterruptedServices::record_from(|_| {
            std::future::ready(Err(anyhow::anyhow!("no daemon socket")))
        })
        .await;
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
    async fn a_service_that_stays_in_backoff_is_named_after_the_wait() {
        let mut daemon = NewDaemon::holding(&["web"]);
        daemon.ends.insert(
            "web".into(),
            (ServiceState::Backoff, "port 3000 is taken".into()),
        );

        let report = restore(InterruptedServices(vec![up("web")]), &mut daemon).await;

        assert_eq!(
            report.lines(),
            [
                "could not start web again: still backoff after 120s (port 3000 is taken). \
              Run `portman up web` in /Users/dev/acme/web."
            ]
        );
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
