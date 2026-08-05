//! Shared request handlers for IPC and HTTP dashboard.

use portman_core::paths::{cert_dir as cert_dir_path, socket_path};
use portman_core::{Mode, NetbridgeMode, Request, Response, VERSION};
use portman_protocol::TldInfo;

use crate::DaemonState;

pub(crate) async fn dispatch(request: Request, state: &DaemonState) -> Response {
    match request {
        Request::ListEntries => Response::Entries {
            entries: state.registry.list(),
        },
        Request::Status => handle_status(state).await,
        Request::AddStatic {
            host,
            target,
            mode,
            service,
            project,
        } => handle_add(state, host, target, mode, service, project),
        Request::RemoveStatic { host } => handle_remove(state, host),
        Request::StartService { host } => handle_start_service(state, host).await,
        Request::TldList => Response::Tlds {
            tlds: build_tld_infos(state),
        },
        Request::TldAdd { tld, tls_mode } => handle_tld_add(state, tld, tls_mode).await,
        Request::TldRemove { tld } => handle_tld_remove(state, tld),
        Request::CertHealth => handle_cert_health(state),
        Request::ResourceUsage => handle_resource_usage(state),
        Request::ResourceHistory => handle_resource_history(state),
        Request::BridgeEnable => handle_bridge_control(state, true).await,
        Request::BridgeDisable => handle_bridge_control(state, false).await,
        Request::BridgeSetMode { mode } => handle_bridge_mode(state, mode).await,
        Request::SyncServices {
            root,
            services,
            secrets,
        } => handle_sync_services(state, root, services, secrets).await,
        Request::ServiceUp { names } => handle_service_up(state, names).await,
        Request::ServiceDown { names } => handle_service_down(state, names).await,
        Request::ServiceStatus => handle_service_status(state),
        Request::LogsQuery {
            service,
            after_id,
            limit,
        } => handle_logs_query(state, service, after_id, limit).await,
        Request::SetSecretsCredentials {
            provider,
            client_id,
            client_secret,
            token,
        } => handle_set_secrets_credentials(state, provider, client_id, client_secret, token),
    }
}

fn handle_set_secrets_credentials(
    state: &DaemonState,
    provider: String,
    client_id: Option<String>,
    client_secret: Option<portman_protocol::Redacted>,
    token: Option<portman_protocol::Redacted>,
) -> Response {
    let result = match provider.as_str() {
        "infisical" => match (client_id, client_secret) {
            (Some(id), Some(secret)) if !id.trim().is_empty() && !secret.0.trim().is_empty() => {
                state
                    .credentials
                    .set_infisical(id.trim().to_string(), secret.0.trim().to_string())
            }
            _ => return err("infisical credentials need both client_id and client_secret"),
        },
        "1password" => match token {
            Some(token) if !token.0.trim().is_empty() => state
                .credentials
                .set_onepassword(token.0.trim().to_string()),
            _ => return err("1password credentials need a service-account token"),
        },
        other => return err(format!("unknown secrets provider `{other}`")),
    };
    match result {
        Ok(()) => Response::Ok,
        Err(e) => err(format!("persisting credentials: {e:#}")),
    }
}

async fn handle_sync_services(
    state: &DaemonState,
    root: std::path::PathBuf,
    services: Vec<portman_protocol::ServiceDefinition>,
    secrets: std::collections::BTreeMap<String, portman_protocol::SecretsProviderConfig>,
) -> Response {
    // Definitions arrive pre-validated by the CLI's config parser, but the
    // socket is open to any local client — re-check the basics.
    for def in &services {
        if def.name.is_empty() || def.run.is_empty() || def.run[0].trim().is_empty() {
            return err(format!(
                "invalid service definition `{}`: empty name or run command",
                def.name
            ));
        }
    }
    match state.supervisor.sync(&root, services, secrets).await {
        Ok(report) => Response::SyncReport {
            added: report.added,
            updated: report.updated,
            removed: report.removed,
            unchanged: report.unchanged,
        },
        Err(e) => err(format!("{e:#}")),
    }
}

async fn handle_service_up(state: &DaemonState, names: Vec<String>) -> Response {
    let names = if names.is_empty() { None } else { Some(names) };
    match state.supervisor.up(names.as_deref()).await {
        Ok(_) => handle_service_status(state),
        Err(e) => err(format!("{e:#}")),
    }
}

async fn handle_service_down(state: &DaemonState, names: Vec<String>) -> Response {
    let names = if names.is_empty() { None } else { Some(names) };
    match state.supervisor.down(names.as_deref()).await {
        Ok(_) => handle_service_status(state),
        Err(e) => err(format!("{e:#}")),
    }
}

fn handle_service_status(state: &DaemonState) -> Response {
    let services = state
        .supervisor
        .status()
        .into_iter()
        .map(|s| portman_protocol::ServiceStatusInfo {
            name: s.name,
            root: Some(s.root),
            state: s.state.wire(),
            detail: s.detail,
            pid: s.pid,
            restarts: s.restarts,
            host: s.host,
            port: s.port,
            desired_up: s.desired_up,
            groups: s.groups,
            project: s.project,
        })
        .collect();
    Response::ServiceStatuses { services }
}

async fn handle_logs_query(
    state: &DaemonState,
    service: String,
    after_id: Option<i64>,
    limit: u32,
) -> Response {
    if !state.supervisor.knows(&service) {
        return err(format!(
            "unknown service `{service}` — run `portman up` from its repo first"
        ));
    }
    let result = match after_id {
        Some(cursor) => state.logs.query_after(&service, cursor, limit).await,
        None => state.logs.tail(&service, limit).await,
    };
    match result {
        Ok(chunk) => Response::Logs {
            last_id: chunk.last_id,
            lines: chunk
                .lines
                .into_iter()
                .map(|l| portman_protocol::LogLineInfo {
                    id: l.id,
                    ts_ms: l.ts_ms,
                    stream: l.stream,
                    line: l.line,
                })
                .collect(),
        },
        Err(e) => err(format!("querying logs: {e:#}")),
    }
}

fn handle_resource_usage(state: &DaemonState) -> Response {
    // The background sampler is the only thing that samples; requests read
    // what it retained. Sampling here too would steal its delta baselines and
    // produce CPU percentages over near-zero windows.
    Response::ResourceUsage {
        snapshot: crate::resources::latest_snapshot(&state.resource_history),
    }
}

fn handle_resource_history(state: &DaemonState) -> Response {
    Response::ResourceHistory {
        series: crate::resources::history_series(&state.resource_history),
    }
}

async fn handle_bridge_control(_state: &DaemonState, enable: bool) -> Response {
    #[cfg(target_os = "macos")]
    {
        use crate::netbridge::Control;
        use tracing::info;
        let msg = if enable {
            Control::Enable
        } else {
            Control::Disable
        };
        if let Err(send_err) = _state.netbridge.tx.send(msg).await {
            return err(format!("netbridge task not reachable: {send_err}"));
        }
        info!(enable, "bridge control message sent");
        Response::Ok
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = enable;
        err("netbridge is not available on this platform")
    }
}

async fn handle_bridge_mode(_state: &DaemonState, mode: NetbridgeMode) -> Response {
    #[cfg(target_os = "macos")]
    {
        use crate::netbridge::Control;
        use tracing::info;
        if let Err(send_err) = _state.netbridge.tx.send(Control::SetMode(mode)).await {
            return err(format!("netbridge task not reachable: {send_err}"));
        }
        info!(mode = mode.as_str(), "bridge mode control message sent");
        Response::Ok
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = mode;
        err("netbridge is not available on this platform")
    }
}

pub(crate) async fn handle_status(state: &DaemonState) -> Response {
    let socket = socket_path()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let data_dir = cert_dir_path()
        .ok()
        .and_then(|p| p.parent().map(|q| q.display().to_string()))
        .unwrap_or_default();
    let certs = cert_dir_path()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let bridge_assessment = state
        .bridge_health
        .read()
        .map(|g| *g)
        .unwrap_or(portman_protocol::BridgeAssessment::Unknown);
    let bridge_enabled = *state.netbridge.enabled.read().await;
    let bridge_mode = *state.netbridge.mode.read().await;
    Response::Status {
        version: VERSION.to_string(),
        running_since: format_duration(state.started.elapsed()),
        dns_port: state.dns_port,
        proxy_port: state.proxy_port,
        tls_port: state.tls_port,
        socket_path: socket,
        data_dir,
        cert_dir: certs,
        bridge_assessment,
        bridge_enabled,
        bridge_mode,
        dashboard_port: state.dashboard_port,
    }
}

fn build_tld_infos(state: &DaemonState) -> Vec<TldInfo> {
    use portman_core::tld::host_has_managed_tld;

    let tlds = state.tld_list();
    let entries = state.registry.list();
    tlds.iter()
        .map(|tld| {
            let count = entries
                .iter()
                .filter(|e| host_has_managed_tld(&e.host, std::iter::once(tld.as_str())))
                .count() as u32;
            TldInfo {
                name: tld.clone(),
                tls_mode: state.tls_store.mode_for(tld),
                entry_count: count,
            }
        })
        .collect()
}

fn handle_cert_health(state: &DaemonState) -> Response {
    let dir = match cert_dir_path() {
        Ok(p) => p,
        Err(_) => {
            return Response::CertHealth {
                mkcert_available: false,
                caroot_path: None,
                caroot_valid: false,
                issued_count: 0,
            };
        }
    };
    let issued = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    e.path()
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.eq_ignore_ascii_case("pem"))
                        .unwrap_or(false)
                })
                .count() as u32
        })
        .unwrap_or(0);

    // Probed once per daemon lifetime: this handler runs on every dashboard
    // poll, and `mkcert -version` is a blocking shell-out on the reactor.
    static MKCERT_AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let mkcert_available = *MKCERT_AVAILABLE.get_or_init(|| {
        crate::block_on_reactor(|| {
            std::process::Command::new("mkcert")
                .arg("-version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
    });

    let caroot = state.cert_manager.caroot();
    let caroot_valid = caroot
        .as_deref()
        .map(|p| p.join("rootCA.pem").exists())
        .unwrap_or(false);

    Response::CertHealth {
        mkcert_available,
        caroot_path: caroot.map(|p| p.display().to_string()),
        caroot_valid,
        issued_count: issued,
    }
}

fn handle_add(
    state: &DaemonState,
    host: String,
    target: String,
    mode: Mode,
    service: Option<String>,
    project: Option<String>,
) -> Response {
    use portman_core::static_store::{validate_host, validate_service, validate_target};
    use portman_core::{Entry, Source};
    use tracing::{info, warn};

    let host = match validate_host(&host) {
        Ok(h) => h,
        Err(e) => return err(e.to_string()),
    };
    let target = match validate_target(&target) {
        Ok(t) => t,
        Err(e) => return err(e.to_string()),
    };
    let service = match service.as_deref().map(validate_service).transpose() {
        Ok(s) => s,
        Err(e) => return err(e.to_string()),
    };

    if !state.host_tld_is_managed(&host) {
        return err(format!(
            "host `{host}` is under an unmanaged TLD; run `portman tld add <tld>` first"
        ));
    }

    // A wildcard resolves per queried name, but the TCP forwarder binds one
    // loopback front per registry *entry* — so the listener would sit on the
    // pattern's address while queries answer with per-name addresses nothing is
    // bound to. HTTP has no such split: every name lands on the same proxy and
    // is routed by the Host header it arrived with.
    if portman_core::static_store::is_wildcard_host(&host) && mode == Mode::Tcp {
        return err(format!(
            "`{host}` is a wildcard, which portman only supports in HTTP mode — \
             TCP entries need a dedicated loopback front per hostname. \
             Register the concrete names instead."
        ));
    }

    if let Err(e) =
        state
            .static_store
            .add(host.clone(), target.clone(), mode, service, project.clone())
    {
        return err(format!("persisting static rule: {e:#}"));
    }
    state.registry.upsert(Entry {
        host: host.clone(),
        target,
        source: Source::Static,
        mode,
        container_id: None,
        project,
    });
    if mode == Mode::Http && state.host_tls_enabled(&host) {
        if let Err(err) = state.cert_manager.ensure(&host) {
            warn!(%host, error = %err, "failed to provision cert on add");
        }
    }
    info!(host = %host, mode = mode.as_str(), "added static rule");
    Response::Ok
}

async fn handle_start_service(state: &DaemonState, host: String) -> Response {
    use crate::runner::Starter;
    use portman_core::static_store::validate_host;

    let host = match validate_host(&host) {
        Ok(h) => h,
        Err(e) => return err(e.to_string()),
    };
    match state.runner.start(&host).await {
        Ok(detail) => Response::Started { detail },
        Err(e) => err(format!("{e:#}")),
    }
}

fn handle_remove(state: &DaemonState, host: String) -> Response {
    use portman_core::static_store::validate_host;
    use tracing::info;

    let host = match validate_host(&host) {
        Ok(h) => h,
        Err(e) => return err(e.to_string()),
    };

    let removed = match state.static_store.remove(&host) {
        Ok(r) => r,
        Err(e) => return err(format!("removing static rule: {e:#}")),
    };
    if removed.is_none() {
        return err(format!("no static rule for {host}"));
    }

    if let Some(existing) = state.registry.get(&host) {
        if existing.source == portman_core::Source::Static {
            state.registry.remove(&host);
        }
    }
    info!(host = %host, "removed static rule");
    Response::Ok
}

async fn handle_tld_add(
    state: &DaemonState,
    tld: String,
    tls_mode: Option<portman_core::TlsMode>,
) -> Response {
    use portman_core::tld::validate_tld;
    use tracing::info;

    let tld = match validate_tld(&tld) {
        Ok(t) => t,
        Err(e) => return err(e.to_string()),
    };

    // Typed on the wire now, but `le` stays non-actionable until it ships —
    // the same rejection `parse_mode` used to give the stringly request.
    if tls_mode == Some(portman_core::TlsMode::Le) {
        return err("Let's Encrypt mode is not implemented yet (post-v0)".to_string());
    }

    if let Some(mode) = tls_mode {
        if let Err(e) = state.tls_store.set_mode(tld.clone(), mode) {
            return err(format!("persisting TLS mode: {e:#}"));
        }
    }

    state.tld_add(tld.clone());
    crate::rehydrate_registry_for_managed_tlds(state).await;

    if state.tls_store.mode_for(&tld).requires_tls() {
        provision_certs_under(state, &tld);
    }

    info!(%tld, "registered TLD");
    Response::Ok
}

fn provision_certs_under(state: &DaemonState, tld: &str) {
    use tracing::warn;
    let suffix = format!(".{tld}");
    for entry in state.registry.list() {
        let host = entry.host.to_ascii_lowercase();
        if host == tld || host.ends_with(&suffix) {
            if let Err(err) = state.cert_manager.ensure(&host) {
                warn!(%host, error = %err, "failed to provision cert");
            }
        }
    }
}

fn handle_tld_remove(state: &DaemonState, tld: String) -> Response {
    use portman_core::tld::validate_tld;
    use tracing::info;

    let tld = match validate_tld(&tld) {
        Ok(t) => t,
        Err(e) => return err(e.to_string()),
    };
    state.tld_remove(&tld);
    let orphans: Vec<String> = state
        .registry
        .list()
        .into_iter()
        .filter(|e| !state.host_tld_is_managed(&e.host))
        .map(|e| e.host)
        .collect();
    for host in &orphans {
        state.registry.remove(host);
    }
    if !orphans.is_empty() {
        info!(count = orphans.len(), %tld, "dropped orphaned entries after TLD removal");
    }
    info!(%tld, "unregistered TLD");
    Response::Ok
}

fn err(message: impl Into<String>) -> Response {
    Response::Err {
        message: message.into(),
    }
}

fn format_duration(d: std::time::Duration) -> String {
    let total = d.as_secs();
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// A DaemonState over temp stores and a lazy (never-connected) Docker
    /// handle — enough to exercise dispatch arms that don't touch Docker.
    fn test_state(dir: &TempDir) -> DaemonState {
        let docker = {
            // bollard checks the socket path exists at construction; give it
            // a real (never-accepting) socket.
            let sock = dir.path().join("docker.sock");
            let _listener = Box::leak(Box::new(
                std::os::unix::net::UnixListener::bind(&sock).unwrap(),
            ));
            bollard::Docker::connect_with_socket(
                sock.to_str().unwrap(),
                5,
                bollard::API_DEFAULT_VERSION,
            )
            .expect("lazy docker handle")
        };
        let registry = portman_core::Registry::new();
        let static_store =
            Arc::new(portman_core::StaticStore::load(dir.path().join("static.json")).unwrap());
        let tls_store =
            Arc::new(portman_core::TlsStore::load(dir.path().join("tls.json")).unwrap());
        let logs = crate::log_store::LogStore::open(
            &dir.path().join("logs.db"),
            crate::log_store::Retention::default(),
        )
        .unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let supervisor = crate::supervisor::Supervisor::new(
            dir.path().join("services.json"),
            crate::env_compose::BaseEnv {
                user: "test".into(),
                home,
            },
            crate::supervisor::IdentityPolicy::CurrentUser,
            crate::supervisor::Timings::default(),
            logs.sink(),
            Arc::new(crate::supervisor::NoSecrets),
            Arc::new(crate::supervisor::NoRoutes),
        );
        let runner = crate::runner::Runner::new(
            docker.clone(),
            static_store.clone(),
            registry.clone(),
            supervisor.clone(),
        );
        let (netbridge_handle, _rx, _state_tx) = crate::netbridge::handle_pair();
        DaemonState {
            docker,
            registry,
            static_store,
            tls_store,
            cert_manager: crate::certs::CertManager::new(dir.path().join("certs"), None),
            known_tlds: Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
            bridge_health: crate::bridge_health::new_shared(),
            netbridge: netbridge_handle,
            resource_samples: crate::resources::new_shared_samples(),
            resource_history: crate::resources::new_shared_history(),
            service_sampler: crate::resources::new_shared_system(),
            runner,
            supervisor,
            logs,
            credentials: crate::secrets::CredentialsStore::load(
                dir.path().join("credentials.json"),
            )
            .unwrap(),
            dns_port: 5335,
            proxy_port: 80,
            tls_port: 443,
            dashboard_port: 7341,
            // These tests drive `handlers::dispatch` directly, below the HTTP
            // layer that checks the token.
            dashboard_token: None,
            started: std::time::Instant::now(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wildcard_hosts_route_in_http_mode() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        state.known_tlds.write().unwrap().insert("test".to_string());

        let response = dispatch(
            Request::AddStatic {
                host: "*.demo.test".into(),
                target: "127.0.0.1:3070".into(),
                mode: Mode::Http,
                service: None,
                project: None,
            },
            &state,
        )
        .await;
        assert!(matches!(response, Response::Ok), "{response:?}");

        // A name nobody registered resolves through the pattern.
        let (key, entry) = state.registry.lookup("7.demo.test").expect("wildcard hit");
        assert_eq!(key, "*.demo.test");
        assert_eq!(entry.target, "127.0.0.1:3070");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wildcard_hosts_are_refused_in_tcp_mode() {
        // TCP entries get a dedicated loopback front per hostname, which a
        // pattern can't provide — better to say so than half-work.
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        state.known_tlds.write().unwrap().insert("test".to_string());

        let response = dispatch(
            Request::AddStatic {
                host: "*.db.test".into(),
                target: "127.0.0.1:5432".into(),
                mode: Mode::Tcp,
                service: None,
                project: None,
            },
            &state,
        )
        .await;
        match response {
            Response::Err { message } => {
                assert!(message.contains("HTTP mode"), "{message}");
            }
            other => panic!("expected err, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn service_up_unknown_name_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let response = dispatch(
            Request::ServiceUp {
                names: vec!["ghost".into()],
            },
            &state,
        )
        .await;
        match response {
            Response::Err { message } => assert!(message.contains("ghost"), "{message}"),
            other => panic!("expected err, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn service_down_unknown_name_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let response = dispatch(
            Request::ServiceDown {
                names: vec!["ghost".into()],
            },
            &state,
        )
        .await;
        assert!(matches!(response, Response::Err { .. }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn logs_query_unknown_service_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let response = dispatch(
            Request::LogsQuery {
                service: "ghost".into(),
                after_id: None,
                limit: 10,
            },
            &state,
        )
        .await;
        match response {
            Response::Err { message } => assert!(message.contains("ghost"), "{message}"),
            other => panic!("expected err, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sync_then_up_then_status_and_logs_flow() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);

        let def = portman_protocol::ServiceDefinition {
            name: "echoer".into(),
            run: vec!["/bin/sh".into(), "-c".into(), "echo hello-ipc".into()],
            dir: dir.path().to_path_buf(),
            port: None,
            host: None,
            mode: Mode::Http,
            ready: portman_protocol::ReadyCheck::None,
            depends: vec![],
            restart: portman_protocol::RestartPolicy::Never,
            stop_grace_ms: 300,
            env_files: vec![],
            env: Default::default(),
            secrets: vec![],
            secrets_optional: false,
            watch: Vec::new(),
            watch_mode: Default::default(),
            watch_debounce_ms: 500,
            groups: Vec::new(),
            project: None,
        };
        let response = dispatch(
            Request::SyncServices {
                root: dir.path().to_path_buf(),
                services: vec![def],
                secrets: Default::default(),
            },
            &state,
        )
        .await;
        match response {
            Response::SyncReport { added, .. } => assert_eq!(added, vec!["echoer"]),
            other => panic!("expected sync report, got {other:?}"),
        }

        let response = dispatch(
            Request::ServiceUp {
                names: vec!["echoer".into()],
            },
            &state,
        )
        .await;
        match response {
            Response::ServiceStatuses { services } => {
                assert_eq!(services.len(), 1);
                assert_eq!(services[0].name, "echoer");
                assert!(services[0].desired_up);
            }
            other => panic!("expected statuses, got {other:?}"),
        }

        // The echo line reaches the log store and pages by cursor.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let response = dispatch(
                Request::LogsQuery {
                    service: "echoer".into(),
                    after_id: Some(0),
                    limit: 10,
                },
                &state,
            )
            .await;
            let Response::Logs { lines, last_id } = response else {
                panic!("expected logs response");
            };
            if lines.iter().any(|l| l.line == "hello-ipc") {
                // Cursor semantics across two consecutive requests: nothing
                // newer than last_id.
                let response = dispatch(
                    Request::LogsQuery {
                        service: "echoer".into(),
                        after_id: Some(last_id),
                        limit: 10,
                    },
                    &state,
                )
                .await;
                match response {
                    Response::Logs {
                        lines,
                        last_id: id2,
                    } => {
                        assert!(lines.is_empty());
                        assert_eq!(id2, last_id);
                    }
                    other => panic!("expected logs, got {other:?}"),
                }
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "echo output never reached the store"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }
}
