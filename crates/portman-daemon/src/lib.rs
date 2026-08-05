//! portman daemon entry point.
//!
//! Phase 3: in-memory registry fed by (1) docker events, (2) a one-shot scan
//! of already-running containers at boot, and (3) persisted static rules.
//! IPC server answers list/status/add/remove.

mod certs;
mod dashboard;
mod dns;
mod docker_events;
mod env_compose;
mod handlers;
mod ipc_server;
mod log_store;
mod proxy;
mod resources;
mod runner;
mod secret_masker;
mod secrets;
mod supervisor;
mod tcp_forward;
mod tls_proxy;
mod upstream;
mod watch;

#[cfg(target_os = "macos")]
mod bridge_health;
#[cfg(not(target_os = "macos"))]
#[path = "bridge_health_stub.rs"]
mod bridge_health;

#[cfg(target_os = "macos")]
mod host_facing;
#[cfg(not(target_os = "macos"))]
#[path = "host_facing_stub.rs"]
mod host_facing;

#[cfg(target_os = "macos")]
mod netbridge;
#[cfg(not(target_os = "macos"))]
#[path = "netbridge_stub.rs"]
mod netbridge;

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use bollard::Docker;
use clap::Parser;
use portman_core::paths::{cert_dir, static_rules_path, tls_settings_path, user_home};
use portman_core::tld::{host_has_managed_tld, scan_managed_tlds};
use portman_core::{Entry, LoopbackAllocator, Mode, Registry, Source, StaticStore, TlsStore};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::certs::CertManager;

/// Run possibly-blocking work (shell-outs, fsync-heavy writes) without
/// starving the async reactor. Inside the multi-thread runtime this is
/// `block_in_place`; in plain sync contexts (unit tests) it just runs.
/// Milliseconds since the Unix epoch. The one clock helper — supervisor
/// markers, resource samples, and log rows must agree on the epoch.
pub(crate) fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

pub(crate) fn block_on_reactor<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "portman-daemon",
    version,
    about = "portman daemon — Docker watcher, DNS, HTTP proxy"
)]
struct Args {
    /// Path to the docker socket. Examples:
    ///   colima (legacy home): /Users/<you>/.colima/default/docker.sock
    ///   colima (XDG):         /Users/<you>/.config/colima/default/docker.sock
    ///   Docker.app:           /var/run/docker.sock
    ///
    /// If not set, tries $DOCKER_HOST, then ~/.colima, then ~/.config/colima,
    /// then ~/.orbstack, then ~/.docker, then /var/run/docker.sock.
    #[arg(long, env = "PORTMAN_DOCKER_SOCKET")]
    docker_socket: Option<String>,

    /// UDP + TCP port the embedded DNS server binds to on 127.0.0.1.
    /// Default is 5335. 5353 is a frequent conflict on macOS (mDNSResponder
    /// and some apps like Spotify bind to wildcard :5353 for local device
    /// discovery, which also blocks 127.0.0.1:5353).
    #[arg(long, env = "PORTMAN_DNS_PORT", default_value_t = 5335)]
    dns_port: u16,

    /// TCP port the HTTP proxy binds to on 127.0.0.1. Default 80 (privileged
    /// — requires root). Use a high port for development without sudo.
    #[arg(long, env = "PORTMAN_PROXY_PORT", default_value_t = 80)]
    proxy_port: u16,

    /// TCP port the HTTPS/TLS proxy binds to on 127.0.0.1. Default 443
    /// (privileged — requires root). Only listens if at least one TLD has
    /// TLS enabled.
    #[arg(long, env = "PORTMAN_TLS_PORT", default_value_t = 443)]
    tls_port: u16,

    /// TCP port for the embedded web dashboard on 127.0.0.1.
    #[arg(long, env = "PORTMAN_DASHBOARD_PORT", default_value_t = portman_core::paths::DEFAULT_DASHBOARD_PORT)]
    dashboard_port: u16,
}

/// Snapshot of daemon-level state useful for introspection (e.g. the IPC
/// `Status` response). Cheap to clone.
#[derive(Clone)]
pub(crate) struct DaemonState {
    pub docker: Docker,
    pub registry: Registry,
    pub static_store: Arc<StaticStore>,
    pub tls_store: Arc<TlsStore>,
    pub cert_manager: CertManager,
    /// Set of TLDs portman currently manages in `/etc/resolver/`. Used both
    /// to answer `TldList` and to gate registration (hosts with unregistered
    /// TLDs are rejected with a warning).
    pub known_tlds: Arc<RwLock<HashSet<String>>>,
    /// Current host↔VM bridge health assessment, updated every 5s by the
    /// `bridge_health` task. Surfaced via IPC `Status` so the menubar can
    /// tint the sailboat icon green/yellow/red.
    pub bridge_health: bridge_health::Shared,
    /// Handle the IPC server uses to send Enable/Disable to the
    /// netbridge task. Also carries a shared `enabled` flag for
    /// synchronous status reads.
    pub netbridge: netbridge::Handle,
    /// Previous Docker CPU samples, keyed by full container id. Docker stats
    /// reports monotonic counters; this lets IPC snapshots compute a delta
    /// without keeping long-lived Docker stats streams open.
    pub resource_samples: resources::SharedSamples,
    /// Persistent sysinfo handle for supervised-service sampling; keeping it
    /// across collect() calls makes cpu_usage() a poll-cadence delta.
    pub service_sampler: resources::SharedSystem,
    /// Retained snapshot + per-series history, fed by the background sampler.
    /// IPC and the dashboard read this; nothing samples on demand any more.
    pub resource_history: resources::SharedHistory,
    /// Starts the service behind a host: native supervised services first,
    /// then pitchfork for mapped static rules, then Docker for labelled
    /// containers. Shared by IPC, the dashboard, and the HTTP proxy's
    /// 502-page Start button.
    pub runner: runner::Runner,
    /// The native service supervisor (repo `portman.toml` stacks).
    pub supervisor: supervisor::Supervisor,
    /// Captured service output, cursor-queryable.
    pub logs: log_store::LogStore,
    /// Machine credentials for secrets providers (0600 store).
    pub credentials: secrets::CredentialsStore,
    pub dns_port: u16,
    pub proxy_port: u16,
    pub tls_port: u16,
    pub dashboard_port: u16,
    pub started: Instant,
}

impl DaemonState {
    pub(crate) fn host_tld_is_managed(&self, host: &str) -> bool {
        let guard = self.known_tlds.read().expect("known_tlds lock poisoned");
        host_has_managed_tld(host, guard.iter())
    }

    /// Does `host` fall under a TLD whose TLS mode is not `off`?
    pub(crate) fn host_tls_enabled(&self, host: &str) -> bool {
        certs::tls_enabled_for_host(&self.tls_store, host)
    }

    pub(crate) fn tld_list(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .known_tlds
            .read()
            .expect("known_tlds lock poisoned")
            .iter()
            .cloned()
            .collect();
        v.sort();
        v
    }

    pub(crate) fn tld_add(&self, tld: String) {
        self.known_tlds
            .write()
            .expect("known_tlds lock poisoned")
            .insert(tld);
    }

    pub(crate) fn tld_remove(&self, tld: &str) {
        self.known_tlds
            .write()
            .expect("known_tlds lock poisoned")
            .remove(tld);
    }
}

/// The daemon's whole entry point. Lives in this lib crate so the single
/// distributable `portman` package can carry the `portman-daemon` bin as a
/// thin shim (one brew formula, two binaries).
pub async fn daemon_main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let docker = connect_docker(&args).context("connecting to docker")?;
    let version = docker.version().await.context("docker ping/version")?;
    info!(
        api_version = version.api_version.as_deref().unwrap_or("?"),
        server_version = version.version.as_deref().unwrap_or("?"),
        "connected to docker"
    );

    ensure_data_dir_owned_by_login_user().context("preparing data dir")?;

    let registry = Registry::new();
    // Shared host → loopback-address map: the DNS server answers TCP hosts with
    // their front, and the forwarder binds a listener there. Same handle, so
    // they always agree on the address.
    let loopback = LoopbackAllocator::new();
    let static_store =
        Arc::new(StaticStore::load(static_rules_path()?).context("loading static-rule store")?);
    let tls_store =
        Arc::new(TlsStore::load(tls_settings_path()?).context("loading TLS settings store")?);
    let initial_tlds = scan_managed_tlds().unwrap_or_else(|err| {
        warn!(error = %err, "initial resolver scan failed; starting with empty TLD set");
        Vec::new()
    });
    if !initial_tlds.is_empty() {
        info!(tlds = ?initial_tlds, "discovered portman-managed resolvers");
    }
    let known_tlds = Arc::new(RwLock::new(
        initial_tlds.into_iter().collect::<HashSet<_>>(),
    ));

    let caroot = user_home().ok().map(|h| CertManager::default_caroot(&h));
    let cert_manager = CertManager::new(cert_dir()?, caroot);

    let bridge_health_shared = bridge_health::new_shared();
    let (netbridge_handle, netbridge_rx, netbridge_state_tx) = netbridge::handle_pair();
    let resource_samples = resources::new_shared_samples();
    let service_sampler = resources::new_shared_system();
    let resource_history = resources::new_shared_history();

    // Native service runner: captured output lands in the SQLite log store.
    let logs = log_store::LogStore::open(
        &portman_core::paths::log_store_path()?,
        log_store::Retention::default(),
    )
    .context("opening service log store")?;
    let log_sweeper = tokio::spawn(logs.clone().run_sweeper());
    let credentials =
        secrets::CredentialsStore::load(portman_core::paths::secrets_credentials_path()?)
            .context("loading secrets credentials store")?;
    let secrets_source = Arc::new(secrets::ProviderSecretsSource::new(credentials.clone()));
    let route_binder = Arc::new(supervisor::RouteBinder {
        registry: registry.clone(),
        static_store: static_store.clone(),
        known_tlds: known_tlds.clone(),
        tls_store: tls_store.clone(),
        cert_manager: cert_manager.clone(),
    });
    let supervisor = supervisor::Supervisor::for_daemon(logs.sink(), route_binder, secrets_source)
        .context("initializing supervisor")?;

    let runner = runner::Runner::new(
        docker.clone(),
        static_store.clone(),
        registry.clone(),
        supervisor.clone(),
    );

    let state = DaemonState {
        docker: docker.clone(),
        registry: registry.clone(),
        static_store: static_store.clone(),
        runner,
        supervisor: supervisor.clone(),
        logs,
        credentials,
        tls_store: tls_store.clone(),
        cert_manager: cert_manager.clone(),
        known_tlds: known_tlds.clone(),
        bridge_health: bridge_health_shared.clone(),
        netbridge: netbridge_handle.clone(),
        resource_samples,
        service_sampler,
        resource_history: resource_history.clone(),
        dns_port: args.dns_port,
        proxy_port: args.proxy_port,
        tls_port: args.tls_port,
        dashboard_port: args.dashboard_port,
        started: Instant::now(),
    };

    seed_from_static_store(&state);
    seed_from_running_containers(&docker, &state).await;

    // Provision certs for any already-registered entries under TLS-enabled TLDs.
    provision_certs_for_existing(&state);

    // Restore persisted desired service state (terminating any process
    // groups that survived an unclean daemon exit, never adopting them) and
    // start desired-up services.
    {
        let supervisor = supervisor.clone();
        tokio::spawn(async move {
            if let Err(err) = supervisor.restore().await {
                warn!(%err, "restoring supervised services");
            }
        });
    }

    let sampler = tokio::spawn(resources::run_sampler(state.clone(), resource_history));
    let ipc = tokio::spawn(ipc_server::run(state.clone()));
    let dashboard = tokio::spawn(dashboard::run(state.clone(), args.dashboard_port));
    // Hand bridge_health a clone of the Docker handle before docker_events
    // takes ownership; bollard::Docker is a cheap Arc internally.
    let bridge_health_task = tokio::spawn(bridge_health::run(docker.clone(), bridge_health_shared));
    // v1 Rust bridge. Starts in whatever state the user last left it
    // (persisted in netbridge.json) or overridden on by
    // `PORTMAN_NETBRIDGE=1`. The IPC server can flip it on/off
    // runtime via `Request::BridgeEnable` / `BridgeDisable`, which
    // forward through `netbridge_handle` as `Control` messages.
    let netbridge_state_path = portman_core::paths::netbridge_state_path()?;
    // Subscribe a state receiver *before* spawning the netbridge task
    // so the very first state publish isn't missed.
    let host_facing_rx = netbridge_handle.state_rx.clone();
    let netbridge_task = tokio::spawn(netbridge::run(
        docker.clone(),
        netbridge_handle,
        netbridge_rx,
        netbridge_state_tx,
        netbridge_state_path,
    ));
    let events = tokio::spawn(docker_events::run(docker, state.clone()));
    let dns = tokio::spawn(dns::run(
        state.registry.clone(),
        args.dns_port,
        loopback.clone(),
    ));
    // Bridge utun interface index, published by the netbridge task while the
    // bridge is up. Every subsystem that opens upstream connections scopes
    // bridge-subnet sockets to it so an exit-node can't capture them.
    let bridge_ifindex = state.netbridge.ifindex.clone();
    let starter: Arc<dyn runner::Starter> = Arc::new(state.runner.clone());
    let http = tokio::spawn(proxy::run(
        state.registry.clone(),
        args.proxy_port,
        bridge_ifindex.clone(),
        starter.clone(),
    ));
    // Loopback front for TCP-mode entries (databases etc.): keeps them
    // reachable even when a VPN/exit-node captures the target's real subnet.
    let tcp_forward = tokio::spawn(tcp_forward::run(
        state.registry.clone(),
        loopback.clone(),
        bridge_ifindex.clone(),
    ));
    let tls = tokio::spawn(tls_proxy::run(
        state.registry.clone(),
        args.tls_port,
        state.cert_manager.clone(),
        state.tls_store.clone(),
        bridge_ifindex.clone(),
    ));
    // Container-facing listeners on 192.168.99.1 — only bind when the
    // netbridge says the address exists.
    let host_facing_task = tokio::spawn(host_facing::run(
        state.registry.clone(),
        host_facing_rx,
        args.proxy_port,
        args.tls_port,
        state.cert_manager.clone(),
        state.tls_store.clone(),
        bridge_ifindex,
        starter,
    ));

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    let outcome = tokio::select! {
        result = events => result.context("docker events task panicked").and_then(|r| r),
        result = ipc => result.context("ipc server task panicked").and_then(|r| r),
        result = dashboard => result.context("dashboard task panicked").and_then(|r| r),
        result = dns => result.context("dns task panicked").and_then(|r| r),
        result = http => result.context("http proxy task panicked").and_then(|r| r),
        result = tcp_forward => result.context("tcp_forward task panicked").and_then(|r| r),
        result = tls => result.context("tls proxy task panicked").and_then(|r| r),
        result = bridge_health_task => result.context("bridge_health task panicked").and_then(|r| r),
        result = netbridge_task => result.context("netbridge task panicked").and_then(|r| r),
        result = host_facing_task => result.context("host_facing task panicked").and_then(|r| r),
        result = log_sweeper => result.context("log sweeper task panicked").and_then(|r| r),
        result = sampler => result.context("resource sampler task panicked").and_then(|r| r),
        _ = tokio::signal::ctrl_c() => {
            info!("ctrl-c received, shutting down");
            Ok(())
        }
        _ = sigterm.recv() => {
            info!("SIGTERM received, shutting down");
            Ok(())
        }
    };

    // Whatever ended the daemon, stop supervised services cleanly (R7);
    // desired state is preserved so the next boot restores them.
    supervisor.shutdown_all().await;
    outcome
}

fn provision_certs_for_existing(state: &DaemonState) {
    for entry in state.registry.list() {
        if state.host_tls_enabled(&entry.host) {
            if let Err(err) = state.cert_manager.ensure(&entry.host) {
                warn!(host = %entry.host, error = %err, "failed to provision startup cert");
            }
        }
    }
}

pub(crate) async fn rehydrate_registry_for_managed_tlds(state: &DaemonState) {
    seed_from_static_store(state);
    seed_from_running_containers(&state.docker, state).await;
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn connect_docker(args: &Args) -> Result<Docker> {
    if let Some(path) = args.docker_socket.as_deref() {
        info!(socket = path, "using configured docker socket");
        return Ok(Docker::connect_with_socket(
            path,
            120,
            bollard::API_DEFAULT_VERSION,
        )?);
    }

    // Auto-detect: honor DOCKER_HOST first, then try common macOS runtime
    // socket locations relative to the invoking user's home (SUDO_USER-aware
    // so this works under `sudo -E` where $HOME is rewritten to /var/root).
    // Candidate list is defined in portman_core so the netbridge crate and
    // any future auxiliary binaries use exactly the same resolution order.
    for path in portman_core::paths::docker_socket_candidates() {
        if path.exists() {
            info!(socket = %path.display(), "auto-detected docker socket");
            let Some(s) = path.to_str() else {
                continue;
            };
            return Ok(Docker::connect_with_socket(
                s,
                120,
                bollard::API_DEFAULT_VERSION,
            )?);
        }
    }

    anyhow::bail!(
        "no docker socket found. Tried DOCKER_HOST, ~/.colima/default/docker.sock, \
         ~/.config/colima/default/docker.sock, ~/.orbstack/run/docker.sock, \
         ~/.docker/run/docker.sock, /var/run/docker.sock. \
         Set PORTMAN_DOCKER_SOCKET or start a runtime (e.g. `colima start`)."
    )
}

/// The daemon runs as root under launchd/systemd, but the data dir must be
/// owned by the login user: the IPC socket's group and the peer-credential
/// gate both derive from this directory's ownership. On a fresh box the
/// root daemon is the first thing to touch the path — left root-owned,
/// everything ownership-derived collapses to root-only and the CLI gets
/// EACCES on the socket (found by the linux-e2e job on its first run).
/// Only the directory itself is chowned; root-written contents (logs.db,
/// credentials.json) stay root's.
fn ensure_data_dir_owned_by_login_user() -> Result<()> {
    let dir = portman_core::paths::data_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    if !nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    let Ok(sudo_user) = std::env::var("SUDO_USER") else {
        return Ok(());
    };
    let name = sudo_user.trim();
    if name.is_empty() {
        return Ok(());
    }
    let Some(user) = nix::unistd::User::from_name(name)
        .with_context(|| format!("looking up login user {name}"))?
    else {
        warn!(
            user = name,
            "SUDO_USER does not resolve; data dir stays root-owned"
        );
        return Ok(());
    };
    std::os::unix::fs::chown(&dir, Some(user.uid.as_raw()), Some(user.gid.as_raw()))
        .with_context(|| format!("chowning {} to {name}", dir.display()))?;
    Ok(())
}

fn seed_from_static_store(state: &DaemonState) {
    let rules = state.static_store.list();
    let mut seeded = 0usize;
    let mut skipped = 0usize;
    for (host, target, mode, project) in rules {
        if !state.host_tld_is_managed(&host) {
            warn!(%host, "skipping static rule: TLD is not managed; run `portman tld add <tld>` first");
            skipped += 1;
            continue;
        }
        state.registry.upsert(Entry {
            host,
            target,
            source: Source::Static,
            mode,
            container_id: None,
            project,
        });
        seeded += 1;
    }
    if seeded > 0 {
        info!(count = seeded, "seeded registry with static rules");
    }
    if skipped > 0 {
        warn!(count = skipped, "static rules skipped (unmanaged TLD)");
    }
}

async fn seed_from_running_containers(docker: &Docker, state: &DaemonState) {
    use bollard::query_parameters::{InspectContainerOptions, ListContainersOptionsBuilder};

    let opts = ListContainersOptionsBuilder::default().build();
    let summaries = match docker.list_containers(Some(opts)).await {
        Ok(list) => list,
        Err(err) => {
            warn!(error = %err, "initial container scan failed");
            return;
        }
    };

    let mut seeded = 0_usize;
    let mut skipped = 0_usize;
    for summary in summaries {
        let Some(labels) = summary.labels.as_ref() else {
            continue;
        };
        let Some(raw_host) = labels.get("dev.portman.host").filter(|v| !v.is_empty()) else {
            continue;
        };
        let host = match docker_events::normalize_host_label(raw_host) {
            Ok(host) => host,
            Err(err) => {
                warn!(
                    host = %raw_host,
                    error = %err,
                    "skipping container: invalid dev.portman.host label"
                );
                skipped += 1;
                continue;
            }
        };
        if !state.host_tld_is_managed(&host) {
            warn!(%host, "skipping container: TLD is not managed; run `portman tld add <tld>` first");
            skipped += 1;
            continue;
        }
        let mode = Mode::parse_label(labels.get("dev.portman.mode").map(String::as_str));
        let Some(port) = labels
            .get("dev.portman.port")
            .cloned()
            .filter(|v| !v.is_empty())
            .or_else(|| match mode {
                Mode::Http => Some("80".into()),
                Mode::Tcp => None,
            })
        else {
            warn!(
                %host,
                "skipping container: dev.portman.mode=tcp requires dev.portman.port"
            );
            skipped += 1;
            continue;
        };
        let Some(id) = summary.id.as_deref() else {
            continue;
        };

        match docker
            .inspect_container(id, None::<InspectContainerOptions>)
            .await
        {
            Ok(inspect) => {
                if let Some(target) = pick_ip(&inspect).map(|ip| format!("{ip}:{port}")) {
                    state.registry.upsert(Entry {
                        host: host.clone(),
                        target,
                        source: Source::Container,
                        mode,
                        container_id: Some(short(id).to_string()),
                        project: inspect
                            .config
                            .as_ref()
                            .and_then(|c| c.labels.as_ref())
                            .and_then(|l| l.get("dev.portman.project"))
                            .cloned(),
                    });
                    seeded += 1;
                }
            }
            Err(err) => warn!(error = %err, id = short(id), "initial scan: inspect failed"),
        }
    }
    if seeded > 0 {
        info!(
            count = seeded,
            "seeded registry with already-running containers"
        );
    }
    if skipped > 0 {
        warn!(count = skipped, "containers skipped (unmanaged TLD)");
    }
}

fn pick_ip(inspect: &bollard::models::ContainerInspectResponse) -> Option<String> {
    let settings = inspect.network_settings.as_ref()?;
    if let Some(ip) = settings.ip_address.as_deref() {
        if !ip.is_empty() {
            return Some(ip.to_string());
        }
    }
    if let Some(networks) = settings.networks.as_ref() {
        for net in networks.values() {
            if let Some(ip) = net.ip_address.as_deref() {
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}
