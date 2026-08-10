//! Service runner — "start this service" for hosts whose backend is down.
//!
//! Three backends, resolved per host in priority order:
//!
//!   1. **native** — a supervised service (from a repo's `portman.toml`)
//!      declaring this host. portman's own supervisor spawns it. During
//!      migration a host may exist both here and as a pitchfork-mapped
//!      static rule: native wins — that's the intended cutover mechanism.
//!   2. **pitchfork** (attrition bridge) — a static rule can carry a service
//!      id (`portman add crm.acme 127.0.0.1:3070 --service acme/web`).
//!      Starting shells out to `pitchfork start <id>` as the login user;
//!      pitchfork owns spawn, readiness, and logs.
//!   3. **docker** — container-sourced hosts start/restart their labelled
//!      container via the Docker API. A *stopped* container has no registry
//!      entry (DNS drops on container stop by design), so resolution falls
//!      back to scanning all containers for the `dev.portman.host` label.
//!
//! Reachable from the IPC `StartService` request, the dashboard, and the
//! HTTP proxy's 502 page (`POST /.portman/start`).

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bollard::query_parameters::{RestartContainerOptions, StartContainerOptions};
use bollard::Docker;
use portman_core::static_store::validate_service;
use portman_core::{Registry, StaticStore};
use tracing::{info, warn};

/// How long a `pitchfork start` may take before we stop waiting. pitchfork
/// blocks on readiness checks, so slow Rails boots are the normal case.
const PITCHFORK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Narrow seam the HTTP proxy sees, so proxy tests can stub the runner
/// without a Docker handle or an on-disk store.
#[async_trait::async_trait]
pub(crate) trait Starter: Send + Sync {
    /// Is there a plausible start path for `host`? Drives whether the 502
    /// page offers a Start button. Cheap and synchronous — no Docker calls.
    fn can_start(&self, host: &str, container_id: Option<&str>) -> bool;

    /// Start whatever is behind `host`. Returns a human-readable detail line.
    async fn start(&self, host: &str) -> Result<String>;
}

#[derive(Clone)]
pub(crate) struct Runner {
    docker: Docker,
    static_store: Arc<StaticStore>,
    registry: Registry,
    supervisor: crate::supervisor::Supervisor,
}

impl Runner {
    pub(crate) fn new(
        docker: Docker,
        static_store: Arc<StaticStore>,
        registry: Registry,
        supervisor: crate::supervisor::Supervisor,
    ) -> Self {
        Self {
            docker,
            static_store,
            registry,
            supervisor,
        }
    }

    async fn start_container(&self, id: &str, running: bool) -> Result<String> {
        if running {
            // Registry entry exists → container is up but its app refused the
            // connection. Restart is the actionable remedy.
            self.docker
                .restart_container(id, None::<RestartContainerOptions>)
                .await
                .with_context(|| format!("restarting container {id}"))?;
            info!(container = id, "restarted container");
            Ok(format!("restarted container {id}"))
        } else {
            self.docker
                .start_container(id, None::<StartContainerOptions>)
                .await
                .with_context(|| format!("starting container {id}"))?;
            info!(container = id, "started container");
            Ok(format!("started container {id}"))
        }
    }

    /// Scan all containers (including stopped ones) for the labelled host.
    async fn find_labelled_container(&self, host: &str) -> Result<Option<String>> {
        use bollard::query_parameters::ListContainersOptionsBuilder;
        let opts = ListContainersOptionsBuilder::default().all(true).build();
        let summaries = self
            .docker
            .list_containers(Some(opts))
            .await
            .context("listing containers")?;
        Ok(summaries.into_iter().find_map(|s| {
            let labels = s.labels.as_ref()?;
            (labels.get("dev.portman.host").map(String::as_str) == Some(host))
                .then_some(s.id)
                .flatten()
        }))
    }
}

#[async_trait::async_trait]
impl Starter for Runner {
    fn can_start(&self, host: &str, container_id: Option<&str>) -> bool {
        self.supervisor.service_for_host(host).is_some()
            || container_id.is_some()
            || self.static_store.service_for(host).is_some()
    }

    async fn start(&self, host: &str) -> Result<String> {
        // Native service first: during migration the same host can also
        // carry a pitchfork mapping — native winning is the cutover.
        if let Some(service) = self.supervisor.service_for_host(host) {
            self.supervisor
                .up(Some(std::slice::from_ref(&service)))
                .await?;
            info!(%service, %host, "starting native service");
            return Ok(format!("starting service {service}"));
        }
        if let Some(service) = self.static_store.service_for(host) {
            return start_pitchfork_service(&service).await;
        }
        if let Some(entry) = self.registry.get(host) {
            if let Some(id) = entry.container_id.as_deref() {
                return self.start_container(id, true).await;
            }
        }
        if let Some(id) = self.find_labelled_container(host).await? {
            return self.start_container(&id, false).await;
        }
        bail!(
            "nothing knows how to start {host}: no --service mapping on a static rule \
             and no container labelled dev.portman.host={host}"
        )
    }
}

/// Run `pitchfork start <id>` as the login user.
///
/// The daemon runs as root under launchd, but pitchfork's supervisor, state,
/// and config are per-user — running it as root would talk to root's (empty)
/// supervisor. `sudo -u <user> -H` gets the user's supervisor socket; a login
/// shell would NOT reliably get their PATH (mise activates in `.zshrc`, which
/// `zsh -lc` never sources), so instead `/usr/bin/env` resolves `pitchfork`
/// against the well-known install dirs (mise shims, homebrew, ~/.local/bin,
/// cargo). Everything is discrete argv — no shell, nothing interpolated.
async fn start_pitchfork_service(service: &str) -> Result<String> {
    let service = validate_service(service)?;
    let user = login_user()?;
    let home = portman_core::paths::user_home().context("resolving login user home")?;
    let path_env = format!(
        "PATH={h}/.local/share/mise/shims:{h}/.local/bin:{h}/.cargo/bin:\
         /opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        h = home.display()
    );

    let output = tokio::time::timeout(
        PITCHFORK_TIMEOUT,
        tokio::process::Command::new("/usr/bin/sudo")
            .args(["-u", &user, "-H", "/usr/bin/env"])
            .arg(&path_env)
            .args(["pitchfork", "start", &service])
            .output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("pitchfork start {service} timed out after 60s"))?
    .with_context(|| format!("spawning pitchfork start {service}"))?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        info!(%service, %user, "pitchfork service started");
        // pitchfork exits 0 even for a soft no-op ("daemon not found" is
        // only a WARN), so relay its last log line rather than a bare ok.
        let last = stderr.lines().last().unwrap_or("").trim();
        return Ok(if last.is_empty() {
            format!("pitchfork start {service}: ok")
        } else {
            format!("pitchfork start {service}: {last}")
        });
    }
    let tail: String = stderr.lines().rev().take(4).collect::<Vec<_>>().join(" | ");
    warn!(%service, status = ?output.status.code(), %tail, "pitchfork start failed");
    bail!(
        "pitchfork start {service} failed ({}): {tail}",
        output.status
    )
}

/// The login user the daemon acts on behalf of. The install path bakes
/// `SUDO_USER` into the LaunchDaemon environment (the same variable the
/// data-dir resolution in `portman_core::paths::user_home` keys on).
fn login_user() -> Result<String> {
    match std::env::var("SUDO_USER") {
        Ok(u) if !u.trim().is_empty() => Ok(u.trim().to_string()),
        _ => bail!(
            "cannot determine the login user (SUDO_USER is unset); \
             pitchfork services can only be started when the daemon knows whose \
             supervisor to talk to — re-run `portman install` or run the daemon \
             via `sudo -E`"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_user_requires_sudo_user() {
        // The test runner itself may or may not have SUDO_USER; assert only
        // the deterministic branch by inspecting the error message shape.
        if std::env::var("SUDO_USER").is_err() {
            let err = login_user().unwrap_err().to_string();
            assert!(err.contains("SUDO_USER"));
        }
    }

    /// Migration cutover: a host carrying BOTH a native service and a
    /// pitchfork-mapped static rule starts natively.
    #[tokio::test(flavor = "multi_thread")]
    async fn native_service_wins_over_pitchfork_mapping() {
        let dir = tempfile::tempdir().unwrap();
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
            std::sync::Arc::new(DiscardSink),
            std::sync::Arc::new(crate::supervisor::NoSecrets),
            std::sync::Arc::new(crate::supervisor::NoRoutes),
        );
        let def = portman_protocol::ServiceDefinition {
            name: "native-web".into(),
            run: vec!["/bin/sleep".into(), "5".into()],
            dir: dir.path().to_path_buf(),
            port: Some(39997),
            host: Some("both.test".into()),
            mode: portman_protocol::Mode::Http,
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
        supervisor
            .sync(
                dir.path(),
                vec![def],
                Default::default(),
                Default::default(),
            )
            .await
            .unwrap();

        let static_store =
            Arc::new(portman_core::StaticStore::load(dir.path().join("static.json")).unwrap());
        // The legacy mapping that native must shadow: if the pitchfork path
        // ran, it would shell out (and fail loudly / time out) — instead the
        // native path returns immediately.
        static_store
            .add(
                "both.test".into(),
                "127.0.0.1:39997".into(),
                portman_core::Mode::Http,
                Some("legacy/web".into()),
                None,
            )
            .unwrap();

        let sock = dir.path().join("docker.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let docker =
            Docker::connect_with_socket(sock.to_str().unwrap(), 5, bollard::API_DEFAULT_VERSION)
                .unwrap();
        let runner = Runner::new(
            docker,
            static_store,
            portman_core::Registry::new(),
            supervisor.clone(),
        );

        assert!(runner.can_start("both.test", None));
        let detail = runner.start("both.test").await.unwrap();
        assert!(
            detail.contains("native-web"),
            "expected the native backend, got: {detail}"
        );

        supervisor.down(None).await.unwrap();
    }

    struct DiscardSink;
    impl crate::supervisor::LineSink for DiscardSink {
        fn line(&self, _: &str, _: crate::supervisor::LogStream, _: &str) {}
    }
}
