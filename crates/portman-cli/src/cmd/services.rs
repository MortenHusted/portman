//! Service-runner commands: status, up, down, logs.

use anyhow::{bail, Context, Result};
use portman_protocol::ServiceState;
use tokio::time::{sleep, Duration};

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
            bridge_mode: _bridge_mode,
            dashboard_port,
        } => {
            println!("daemon version:  {version}");
            println!("running for:     {running_since}");
            println!("dns port:        {dns_port} (127.0.0.1)");
            println!("http proxy:      {proxy_port} (127.0.0.1)");
            println!("tls proxy:       {tls_port} (127.0.0.1)");
            println!("dashboard:       http://127.0.0.1:{dashboard_port}");
            println!("socket:          {socket_path}");
            println!("data dir:        {data_dir}");
            println!("cert dir:        {cert_dir}");
            #[cfg(target_os = "macos")]
            {
                println!("bridge:          {_bridge_assessment}");
                println!(
                    "netbridge:       {}",
                    if _bridge_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
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

    // With no explicit names, scope the stop to this repo's stack when
    // inside one; outside a repo, empty names mean "everything the daemon
    // knows" — confirm that intent by requiring the repo context.
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
        config.services.keys().cloned().collect()
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
