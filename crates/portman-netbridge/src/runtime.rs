//! Long-running portman-netbridge: the thing the daemon wires in (Phase
//! B.5) and the thing `examples/tunnel_docker` runs for manual
//! validation. All the production-grade wiring lives here; the
//! example becomes a thin `fn main` around [`Runtime::start`] +
//! signal-await + [`Runtime::shutdown`].
//!
//! The runtime owns:
//!   - a macOS `utun` device configured as `HOST_TUNNEL_IP/24`,
//!   - a host route `192.168.99.0/24 → <utun>`,
//!   - a UDP socket on `HOST_WG_LISTEN_PORT`,
//!   - a VM-side setup container (spawned inside colima),
//!   - a docker bridge network `portman` on the `/25` upper half,
//!   - a `Peer` state machine plus tokio tasks that pump encrypt/
//!     decrypt in both directions,
//!   - a 1-second timer task that nudges `Peer::encapsulate` so the
//!     handshake fires promptly after the VM peer starts.
//!
//! It is **only** the v1 host-side bridge; it knows nothing about
//! portman's DNS/proxy/registry. The daemon keeps those separate.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bollard::container::LogOutput;
use bollard::errors::Error as DockerError;
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, InspectContainerOptions, InspectNetworkOptions,
    ListContainersOptionsBuilder, ListNetworksOptionsBuilder, LogsOptionsBuilder,
    RemoveContainerOptionsBuilder, StartContainerOptions, StopContainerOptionsBuilder,
};
use bollard::secret::{ContainerCreateBody, HostConfig, Ipam, IpamConfig, NetworkCreateRequest};
use bollard::Docker;
use boringtun::noise::TunnResult;
use futures_util::TryStreamExt;
use portman_core::NetbridgeMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use tun::Device;

use crate::tunnel::{
    public_key_from_base64, Keypair, Peer, DOCKER_BRIDGE_CIDR, DOCKER_BRIDGE_GATEWAY,
    HOST_TUNNEL_IP, HOST_WG_LISTEN_PORT, PORTMAN_SUBNET_CIDR, TUNNEL_MTU, VM_TUNNEL_IP,
};

/// Name of the docker network the runtime creates.
pub const PORTMAN_NETWORK: &str = "portman";
/// Name of the VM-side setup container. Stable — the runtime reuses
/// the name across restarts and idempotently removes a stale one.
pub const SETUP_CONTAINER: &str = "portman-netbridge-setup";
/// Image the setup container runs. Must be present in the colima VM.
/// Daemon integration should build or pull this before starting the
/// runtime; the runtime itself fails fast if missing.
pub const SETUP_IMAGE: &str = "portman-netbridge/setup:local";
const MANAGED_LABEL: &str = "dev.portman.managed";
const MANAGED_LABEL_VALUE: &str = "1";
const ROLE_LABEL: &str = "dev.portman.role";
const SETUP_ROLE_LABEL_VALUE: &str = "netbridge-setup";
const SETUP_STOP_TIMEOUT_SECS: i32 = 5;
/// How long to wait for docker to finish removing the setup container before
/// giving up and saying so.
const SETUP_REMOVE_TIMEOUT: Duration = Duration::from_secs(10);
const LABEL_HOST: &str = "dev.portman.host";
const ROUTE_RECONCILE_PERIOD: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
pub struct RuntimeOptions {
    pub mode: NetbridgeMode,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            mode: NetbridgeMode::OptIn,
        }
    }
}

/// A started portman-netbridge. Hold it as long as you want the
/// bridge up; drop it or call [`Runtime::shutdown`] to tear down.
pub struct Runtime {
    utun_name: String,
    docker: Docker,
    /// Handles of the three pump tasks so we can abort them on
    /// shutdown. Not awaited — they loop forever by design.
    tasks: Vec<JoinHandle<()>>,
}

impl Runtime {
    /// Bring up the full stack. Requires root (utun + route).
    ///
    /// Returns after the utun + route + UDP + setup container +
    /// docker network are all live and the pump tasks are spawned.
    /// The tunnel may still be mid-handshake at this point; the VM
    /// side fires keepalives every second from the moment chip0
    /// comes up, so a first packet from the host will session up
    /// within ~100 ms.
    pub async fn start(docker: Docker) -> Result<Self> {
        Self::start_with_options(docker, RuntimeOptions::default()).await
    }

    pub async fn start_with_options(docker: Docker, options: RuntimeOptions) -> Result<Self> {
        Self::start_with_keypair(docker, options, &Keypair::generate()).await
    }

    /// As [`Runtime::start_with_options`], but with the host keypair supplied by
    /// the caller so a retry reuses the same identity instead of minting a new
    /// one. A retry that regenerates keys leaves any tunnel the failed attempt
    /// created peered to a VM that no longer knows it.
    pub async fn start_with_keypair(
        docker: Docker,
        options: RuntimeOptions,
        host_kp: &Keypair,
    ) -> Result<Self> {
        info!(
            host_pub = %host_kp.public_base64(),
            mode = options.mode.as_str(),
            "netbridge host key generated"
        );

        // Ordering is load-bearing: everything that can realistically fail —
        // docker network, route discovery, the setup container — happens before
        // any host-level resource exists. A failure here used to unwind past an
        // already-created utun and its installed routes, orphaning both; the
        // routes then pinned the subnet to a dead interface and the reconciler
        // treated them as fine, so the bridge stayed silently broken.

        // ── Portman-owned docker network
        //
        // Preflight this before touching host routes or setup containers. A
        // network called "portman" is not enough ownership proof; another
        // user/tool may already own that name.
        ensure_portman_network(&docker).await?;
        let extra_route_cidrs = docker_route_cidrs(&docker, options.mode).await?;

        // ── UDP
        let udp = Arc::new(
            UdpSocket::bind(("0.0.0.0", HOST_WG_LISTEN_PORT))
                .await
                .with_context(|| format!("binding 0.0.0.0:{HOST_WG_LISTEN_PORT}"))?,
        );

        // ── VM-side peer + docker network
        //
        // Setup container is always replaced — its wg config references
        // the host's keys, which are fresh on every start (though stable
        // across the retries of one start).
        //
        // The docker network is reused when present: attached user
        // containers (e.g. osrm on the portman network) keep their IP
        // and stay reachable across daemon restarts. Removing the
        // network while endpoints are attached fails anyway, so
        // blunt remove-then-create is both wrong and not robust.
        remove_existing_setup_container(&docker).await?;
        let vm_pubkey = spawn_setup_container(&docker, host_kp).await?;
        info!(container = SETUP_CONTAINER, "VM setup container running");

        // ── utun + routes, last, and rolled back together on failure
        let mut cfg = tun::Configuration::default();
        cfg.address(HOST_TUNNEL_IP)
            .netmask((255, 255, 255, 0))
            .destination(VM_TUNNEL_IP)
            .mtu(i32::from(TUNNEL_MTU))
            .up();
        let device = tun::create_as_async(&cfg).context("creating utun")?;
        let utun_name = device.get_ref().name().context("utun name")?;
        info!(utun = %utun_name, "utun up");
        remember_own_utun(&utun_name);

        let mut installed = InstalledRoutes::new(utun_name.clone());
        for cmd in startup_route_plan(&utun_name, &extra_route_cidrs) {
            if let Err(err) = ensure_route_command(&cmd) {
                // The device drops with this error; stop claiming its name
                // (same reasoning as shutdown — names are recycled).
                forget_own_utun(&utun_name);
                return Err(err);
            }
            installed.record(cmd.cidr);
        }
        // Past the last fallible step — these routes belong to a live runtime
        // now, so the guard must not undo them.
        installed.keep();

        // ── Peer + shared state
        let peer = Arc::new(Mutex::new(Peer::new(host_kp, &vm_pubkey, Some(25))));
        let vm_endpoint: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let (dev_read, dev_write) = tokio::io::split(device);

        let rx = spawn_rx(udp.clone(), peer.clone(), vm_endpoint.clone(), dev_write);
        let tx = spawn_tx(udp.clone(), peer.clone(), vm_endpoint.clone(), dev_read);
        let timer = spawn_timer(udp.clone(), peer.clone(), vm_endpoint.clone());
        let routes = spawn_route_reconciler(docker.clone(), options.mode, utun_name.clone());

        Ok(Self {
            utun_name,
            docker,
            tasks: vec![rx, tx, timer, routes],
        })
    }

    /// Name of the utun interface this bridge owns (e.g. `utun10`).
    /// Stable for the lifetime of the `Runtime`. The daemon uses it to
    /// interface-scope upstream sockets so bridge-subnet traffic survives
    /// a VPN/exit-node claiming the default route.
    pub fn utun_name(&self) -> &str {
        &self.utun_name
    }

    /// Cleanly tear down the bridge. Aborts the pump tasks and removes
    /// the setup container. The `portman` docker network is left in
    /// place — if user containers are attached, they keep their IPs
    /// and become reachable again as soon as the daemon comes back up.
    /// `portman bridge disable` (user intent) still wants the network
    /// gone; call [`Runtime::shutdown_and_remove_network`] for that.
    pub async fn shutdown(mut self) {
        for t in self.tasks.drain(..) {
            t.abort();
        }
        // The kernel recycles utun names. Keep claiming this one after the
        // device is gone and route repair would treat a *recycled* utun —
        // somebody else's VPN — as ours to repoint.
        forget_own_utun(&self.utun_name);
        best_effort_remove_setup_container(&self.docker).await;
        info!(utun = %self.utun_name, "netbridge shut down (network retained)");
    }

    /// Shutdown + best-effort remove the docker network. Used when the
    /// user explicitly disables the bridge (`portman bridge disable`),
    /// not on daemon restart. If user containers are attached, the
    /// network removal will fail silently — docker refuses to remove a
    /// network with endpoints. The user disconnects them first.
    pub async fn shutdown_and_remove_network(self) {
        let docker = self.docker.clone();
        self.shutdown().await;
        remove_portman_network_if_owned(&docker).await;
    }
}

// ── Task spawners ──────────────────────────────────────────────────

fn spawn_rx<W>(
    udp: Arc<UdpSocket>,
    peer: Arc<Mutex<Peer>>,
    endpoint: Arc<Mutex<Option<SocketAddr>>>,
    mut dev_write: W,
) -> JoinHandle<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        // Sized so no UDP datagram can arrive truncated — a clipped frame
        // would feed decapsulate garbage that looks like an auth failure.
        let mut buf = vec![0u8; usize::from(u16::MAX)];
        let mut out = vec![0u8; (TUNNEL_MTU as usize) + 128];
        let mut send_warned = false;
        loop {
            let (n, src) = match udp.recv_from(&mut buf).await {
                Ok(pair) => pair,
                Err(err) => {
                    // The bridge looks healthy from the routing table alone —
                    // a silent pump death is exactly how it stays broken.
                    warn!(%err, "netbridge rx pump died; bridge will stop passing traffic");
                    return;
                }
            };
            // The source address is only trusted once boringtun has
            // authenticated the datagram. Recording it up front meant any
            // LAN host could spray garbage at the listen socket and
            // redirect every outbound tunnel frame to itself until the
            // real peer's next packet — a silent bridge DoS.
            let mut authenticated = false;
            let mut inbound: Option<Vec<u8>> = Some(buf[..n].to_vec());
            loop {
                let first_pass = inbound.is_some();
                let input: &[u8] = match &inbound {
                    Some(v) => v.as_slice(),
                    None => &[],
                };
                let r = {
                    let mut p = peer.lock().await;
                    p.decapsulate(input, &mut out)
                };
                match r {
                    TunnResult::Err(_) => break,
                    TunnResult::WriteToNetwork(frame) => {
                        if first_pass {
                            authenticated = true;
                        }
                        // Handshake replies go to the datagram's own source,
                        // so a first contact works before the endpoint is
                        // recorded below.
                        if let Err(err) = udp.send_to(frame, src).await {
                            if !send_warned {
                                warn!(%err, "netbridge rx pump failed to send; further failures muted");
                                send_warned = true;
                            }
                        }
                        inbound = None;
                    }
                    TunnResult::WriteToTunnelV4(pkt, _) => {
                        if first_pass {
                            authenticated = true;
                        }
                        // AF_INET = 2 in big-endian; macOS utun writes
                        // need this 4-byte prefix or the kernel drops.
                        let mut framed = Vec::with_capacity(pkt.len() + 4);
                        framed.extend_from_slice(&[0, 0, 0, 2]);
                        framed.extend_from_slice(pkt);
                        if let Err(err) = dev_write.write_all(&framed).await {
                            if !send_warned {
                                warn!(%err, "netbridge rx pump failed to write utun; further failures muted");
                                send_warned = true;
                            }
                        }
                        break;
                    }
                    _ => {
                        // Done / v6: consumed and valid (keepalives land
                        // here), just nothing to forward.
                        if first_pass {
                            authenticated = true;
                        }
                        break;
                    }
                }
            }
            if authenticated {
                *endpoint.lock().await = Some(src);
            }
        }
    })
}

fn spawn_tx(
    udp: Arc<UdpSocket>,
    peer: Arc<Mutex<Peer>>,
    endpoint: Arc<Mutex<Option<SocketAddr>>>,
    mut dev_read: tokio::io::ReadHalf<tun::AsyncDevice>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut pkt = vec![0u8; (TUNNEL_MTU as usize) + 64];
        let mut out = vec![0u8; (TUNNEL_MTU as usize) + 128];
        let mut send_warned = false;
        loop {
            let n = match dev_read.read(&mut pkt).await {
                Ok(n) => n,
                Err(err) => {
                    warn!(%err, "netbridge tx pump died; bridge will stop passing traffic");
                    return;
                }
            };
            let ip = strip_utun_prefix(&pkt[..n]);
            let r = {
                let mut p = peer.lock().await;
                p.encapsulate(ip, &mut out)
            };
            if let TunnResult::WriteToNetwork(frame) = r {
                if let Some(dest) = *endpoint.lock().await {
                    if let Err(err) = udp.send_to(frame, dest).await {
                        if !send_warned {
                            warn!(%err, "netbridge tx pump failed to send; further failures muted");
                            send_warned = true;
                        }
                    }
                }
            }
        }
    })
}

/// WireGuard timer driver. Ticks every second to give boringtun a
/// chance to re-initiate the handshake (every `REKEY_AFTER_TIME` =
/// 120s), send keepalives (every 25s when configured), and retry
/// stuck handshakes (every `REKEY_TIMEOUT` = 5s). Without this task
/// the tunnel works initially but falls silent 2 minutes after the
/// first handshake because the session expires and never rekeys.
///
/// Earlier versions called `encapsulate(&[])` here — that's the
/// wrong API (it encrypts an empty data packet, it doesn't touch
/// the timer state). We now use `update_timers` which is exactly
/// what wg-go's `RoutineTimer` does.
fn spawn_timer(
    udp: Arc<UdpSocket>,
    peer: Arc<Mutex<Peer>>,
    endpoint: Arc<Mutex<Option<SocketAddr>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.tick().await;
        let mut out = vec![0u8; 256];
        loop {
            tick.tick().await;
            let r = {
                let mut p = peer.lock().await;
                p.update_timers(&mut out)
            };
            match r {
                TunnResult::WriteToNetwork(frame) => {
                    if let Some(dest) = *endpoint.lock().await {
                        let _ = udp.send_to(frame, dest).await;
                    }
                }
                TunnResult::Err(err) => {
                    warn!(?err, "wireguard timers returned error");
                }
                _ => {}
            }
        }
    })
}

fn spawn_route_reconciler(docker: Docker, mode: NetbridgeMode, iface: String) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(ROUTE_RECONCILE_PERIOD);
        loop {
            tick.tick().await;
            let extra_route_cidrs = match docker_route_cidrs(&docker, mode).await {
                Ok(cidr) => cidr,
                Err(err) => {
                    warn!(%err, "netbridge route discovery failed");
                    BTreeSet::new()
                }
            };
            for cmd in startup_route_plan(&iface, &extra_route_cidrs) {
                if let Err(err) = ensure_route_command(&cmd) {
                    warn!(cidr = %cmd.cidr, iface = %cmd.iface, %err, "netbridge route reconcile failed");
                }
            }
        }
    })
}

// ── Docker helpers ─────────────────────────────────────────────────

async fn spawn_setup_container(
    docker: &Docker,
    host: &Keypair,
) -> Result<boringtun::x25519::PublicKey> {
    let env = setup_container_env(host);
    let body = ContainerCreateBody {
        image: Some(SETUP_IMAGE.to_string()),
        env: Some(env),
        host_config: Some(HostConfig {
            network_mode: Some("host".to_string()),
            cap_add: Some(vec!["NET_ADMIN".to_string()]),
            auto_remove: Some(true),
            ..Default::default()
        }),
        labels: Some(HashMap::from([
            (MANAGED_LABEL.into(), MANAGED_LABEL_VALUE.into()),
            (ROLE_LABEL.into(), SETUP_ROLE_LABEL_VALUE.into()),
        ])),
        ..Default::default()
    };
    let opts = CreateContainerOptionsBuilder::default()
        .name(SETUP_CONTAINER)
        .build();
    docker
        .create_container(Some(opts), body)
        .await
        .context("creating netbridge setup container")?;
    if let Err(err) = docker
        .start_container(SETUP_CONTAINER, None::<StartContainerOptions>)
        .await
    {
        best_effort_remove_setup_container(docker).await;
        return Err(err).context("starting netbridge setup container");
    }
    // Brief wait so chip0 is up and the VM peer has fired its first
    // keepalive by the time the host pump starts issuing handshakes.
    tokio::time::sleep(Duration::from_secs(2)).await;
    if let Err(err) = ensure_setup_container_running(docker).await {
        best_effort_remove_setup_container(docker).await;
        return Err(err);
    }
    match read_setup_vm_public_key(docker).await {
        Ok(key) => Ok(key),
        Err(err) => {
            best_effort_remove_setup_container(docker).await;
            Err(err)
        }
    }
}

fn setup_container_env(host: &Keypair) -> Vec<String> {
    vec![
        format!("HOST_PUBKEY={}", host.public_base64()),
        format!("HOST_ENDPOINT=host.docker.internal:{HOST_WG_LISTEN_PORT}"),
        format!("PEER_CIDR={VM_TUNNEL_IP}/25"),
        format!("ALLOWED_IPS={PORTMAN_SUBNET_CIDR}"),
    ]
}

async fn read_setup_vm_public_key(docker: &Docker) -> Result<boringtun::x25519::PublicKey> {
    let opts = LogsOptionsBuilder::default()
        .stdout(true)
        .stderr(true)
        .tail("50")
        .build();
    let mut stream = docker.logs(SETUP_CONTAINER, Some(opts));
    let mut logs = String::new();
    while let Some(chunk) = stream
        .try_next()
        .await
        .context("reading netbridge setup container logs")?
    {
        logs.push_str(&log_output_to_string(chunk));
    }
    parse_vm_public_key_from_logs(&logs)
}

fn log_output_to_string(output: LogOutput) -> String {
    match output {
        LogOutput::StdErr { message }
        | LogOutput::StdOut { message }
        | LogOutput::StdIn { message }
        | LogOutput::Console { message } => String::from_utf8_lossy(&message).into_owned(),
    }
}

fn parse_vm_public_key_from_logs(logs: &str) -> Result<boringtun::x25519::PublicKey> {
    for line in logs.lines() {
        if let Some(raw) = line.trim().strip_prefix("VM_PUBKEY=") {
            return public_key_from_base64(raw).context("parsing VM public key from setup logs");
        }
    }
    anyhow::bail!("netbridge setup container did not report VM_PUBKEY");
}

/// Reuse the existing `portman` network if present, otherwise create
/// it. Idempotent across daemon restarts where user containers are
/// still attached — removing a network with endpoints fails anyway,
/// so reuse is the only correct path.
async fn ensure_portman_network(docker: &Docker) -> Result<()> {
    match docker
        .inspect_network(PORTMAN_NETWORK, None::<InspectNetworkOptions>)
        .await
    {
        Ok(net) => {
            if !network_is_portman_managed(net.labels.as_ref()) {
                return Err(anyhow!(
                    "docker network `{PORTMAN_NETWORK}` already exists but is not managed by portman"
                ));
            }
            info!(
                network = PORTMAN_NETWORK,
                cidr = DOCKER_BRIDGE_CIDR,
                "docker network reused"
            );
            Ok(())
        }
        Err(_) => {
            create_portman_network(docker).await?;
            info!(
                network = PORTMAN_NETWORK,
                cidr = DOCKER_BRIDGE_CIDR,
                "docker network created"
            );
            Ok(())
        }
    }
}

async fn create_portman_network(docker: &Docker) -> Result<()> {
    let req = NetworkCreateRequest {
        name: PORTMAN_NETWORK.to_string(),
        driver: Some("bridge".to_string()),
        internal: Some(false),
        attachable: Some(true),
        ingress: Some(false),
        enable_ipv6: Some(false),
        ipam: Some(Ipam {
            driver: Some("default".to_string()),
            config: Some(vec![IpamConfig {
                subnet: Some(DOCKER_BRIDGE_CIDR.to_string()),
                gateway: Some(DOCKER_BRIDGE_GATEWAY.to_string()),
                ip_range: None,
                auxiliary_addresses: None,
            }]),
            options: None,
        }),
        options: Some(HashMap::from([(
            "com.docker.network.driver.mtu".to_string(),
            TUNNEL_MTU.to_string(),
        )])),
        labels: Some(HashMap::from([(
            MANAGED_LABEL.to_string(),
            MANAGED_LABEL_VALUE.to_string(),
        )])),
        ..Default::default()
    };
    docker.create_network(req).await?;
    Ok(())
}

async fn remove_existing_setup_container(docker: &Docker) -> Result<()> {
    let Some((labels, running)) = setup_container_snapshot(docker).await? else {
        return Ok(());
    };
    if !setup_container_is_portman_managed(Some(&labels)) {
        anyhow::bail!(
            "docker container `{SETUP_CONTAINER}` already exists but is not managed by portman"
        );
    }
    if running {
        let opts = StopContainerOptionsBuilder::default()
            .signal("SIGTERM")
            .t(setup_stop_timeout_secs())
            .build();
        if let Err(err) = docker.stop_container(SETUP_CONTAINER, Some(opts)).await {
            if docker_not_found(&err) {
                return Ok(());
            }
            warn!(
                container = SETUP_CONTAINER,
                error = %err,
                "graceful setup container stop failed; removing anyway"
            );
        }
    }
    let opts = RemoveContainerOptionsBuilder::default().force(true).build();
    match docker.remove_container(SETUP_CONTAINER, Some(opts)).await {
        Ok(()) => {}
        Err(err) if docker_not_found(&err) => {}
        Err(err) if docker_removal_already_underway(&err) => {
            debug!(container = SETUP_CONTAINER, "auto-remove already in flight");
        }
        Err(err) => return Err(err).context("removing existing netbridge setup container"),
    }
    // Don't return until it's actually gone. `remove_container` is
    // asynchronous on docker's side, and auto_remove means it may already have
    // been in flight — either way, creating the replacement while the old one
    // still exists just moves the race one step later.
    wait_for_setup_container_gone(docker).await
}

/// Poll until the setup container no longer exists. Bounded: if docker is wedged
/// we want a named error, not a hung daemon start.
async fn wait_for_setup_container_gone(docker: &Docker) -> Result<()> {
    let deadline = std::time::Instant::now() + SETUP_REMOVE_TIMEOUT;
    loop {
        if setup_container_snapshot(docker).await?.is_none() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "netbridge setup container `{SETUP_CONTAINER}` still present {}s after removal",
                SETUP_REMOVE_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn best_effort_remove_setup_container(docker: &Docker) {
    if let Err(err) = remove_existing_setup_container(docker).await {
        warn!(
            container = SETUP_CONTAINER,
            error = %err,
            "could not remove netbridge setup container"
        );
    }
}

async fn setup_container_snapshot(
    docker: &Docker,
) -> Result<Option<(HashMap<String, String>, bool)>> {
    match docker
        .inspect_container(SETUP_CONTAINER, None::<InspectContainerOptions>)
        .await
    {
        Ok(info) => {
            let labels = info
                .config
                .and_then(|config| config.labels)
                .unwrap_or_default();
            let running = info
                .state
                .as_ref()
                .and_then(|state| state.running)
                .unwrap_or(false);
            Ok(Some((labels, running)))
        }
        Err(DockerError::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(None),
        Err(err) => Err(err).context("inspecting netbridge setup container"),
    }
}

async fn ensure_setup_container_running(docker: &Docker) -> Result<()> {
    let info = match docker
        .inspect_container(SETUP_CONTAINER, None::<InspectContainerOptions>)
        .await
    {
        Ok(info) => info,
        Err(DockerError::DockerResponseServerError {
            status_code: 404, ..
        }) => {
            anyhow::bail!("netbridge setup container exited during startup");
        }
        Err(err) => return Err(err).context("inspecting netbridge setup container after startup"),
    };

    let labels = info
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref());
    if !setup_container_is_portman_managed(labels) {
        anyhow::bail!("docker container `{SETUP_CONTAINER}` exists but is not managed by portman");
    }

    let running = info
        .state
        .as_ref()
        .and_then(|state| state.running)
        .unwrap_or(false);
    if !running {
        let status = info
            .state
            .as_ref()
            .and_then(|state| state.status)
            .map(|status| format!("{status:?}"))
            .unwrap_or_else(|| "unknown".to_string());
        let exit_code = info.state.as_ref().and_then(|state| state.exit_code);
        anyhow::bail!(
            "netbridge setup container is not running after startup (status={status}, exit_code={exit_code:?})"
        );
    }

    Ok(())
}

fn docker_not_found(err: &DockerError) -> bool {
    matches!(
        err,
        DockerError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

/// Is this docker error "the container is already going away"?
///
/// The setup container runs with `auto_remove`, so stopping it makes docker
/// start removing it on its own. Our explicit force-remove then races that and
/// comes back 409 `removal of container … is already in progress`. That is
/// docker doing exactly what we asked, not a failure — and treating it as one
/// is what made every daemon restart fall into the retry path.
fn docker_removal_already_underway(err: &DockerError) -> bool {
    match err {
        DockerError::DockerResponseServerError {
            status_code: 409,
            message,
        } => message.contains("removal") && message.contains("in progress"),
        _ => false,
    }
}

async fn remove_portman_network_if_owned(docker: &Docker) {
    match docker
        .inspect_network(PORTMAN_NETWORK, None::<InspectNetworkOptions>)
        .await
    {
        Ok(net) if network_is_portman_managed(net.labels.as_ref()) => {
            if let Err(err) = docker.remove_network(PORTMAN_NETWORK).await {
                warn!(
                    network = PORTMAN_NETWORK,
                    error = %err,
                    "could not remove docker network (likely has attached containers)"
                );
            }
        }
        Ok(_) => warn!(
            network = PORTMAN_NETWORK,
            "skipping docker network removal because it is not marked as portman-managed"
        ),
        Err(err) => warn!(
            network = PORTMAN_NETWORK,
            error = %err,
            "could not inspect docker network before removal"
        ),
    }
}

fn network_is_portman_managed(labels: Option<&HashMap<String, String>>) -> bool {
    labels
        .and_then(|labels| labels.get(MANAGED_LABEL))
        .is_some_and(|value| value == MANAGED_LABEL_VALUE)
}

fn setup_container_is_portman_managed(labels: Option<&HashMap<String, String>>) -> bool {
    let Some(labels) = labels else {
        return false;
    };
    labels
        .get(MANAGED_LABEL)
        .is_some_and(|value| value == MANAGED_LABEL_VALUE)
        && labels
            .get(ROLE_LABEL)
            .is_some_and(|value| value == SETUP_ROLE_LABEL_VALUE)
}

fn setup_stop_timeout_secs() -> i32 {
    SETUP_STOP_TIMEOUT_SECS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DockerRouteScope {
    PortmanLabeled,
    AllContainers,
}

async fn docker_route_cidrs(docker: &Docker, mode: NetbridgeMode) -> Result<BTreeSet<String>> {
    match mode {
        NetbridgeMode::OptIn => Ok(BTreeSet::new()),
        NetbridgeMode::Docker => docker_bridge_subnets(docker, DockerRouteScope::PortmanLabeled)
            .await
            .context("discovering docker-mode bridge subnets"),
        NetbridgeMode::All => docker_bridge_subnets(docker, DockerRouteScope::AllContainers)
            .await
            .context("discovering all docker bridge subnets"),
    }
}

async fn docker_bridge_subnets(
    docker: &Docker,
    scope: DockerRouteScope,
) -> Result<BTreeSet<String>> {
    let opts = ListContainersOptionsBuilder::default().all(false).build();
    let containers = docker.list_containers(Some(opts)).await?;
    let mut networks_in_scope = BTreeSet::new();

    for container in &containers {
        if scope == DockerRouteScope::PortmanLabeled
            && !container_has_portman_host_label(container.labels.as_ref())
        {
            continue;
        }
        let Some(networks) = container
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
        else {
            continue;
        };
        for name in networks.keys() {
            if routable_docker_network_name(name) {
                networks_in_scope.insert(name.clone());
            }
        }
    }

    if networks_in_scope.is_empty() {
        return Ok(BTreeSet::new());
    }

    let networks = docker
        .list_networks(None::<ListNetworksOptionsBuilder>.map(|builder| builder.build()))
        .await?;
    let mut subnets = BTreeSet::new();
    for network in &networks {
        let Some(name) = network.name.as_deref() else {
            continue;
        };
        if !networks_in_scope.contains(name) {
            continue;
        }
        if network.driver.as_deref() != Some("bridge") {
            continue;
        }
        if let Some(configs) = network.ipam.as_ref().and_then(|ipam| ipam.config.as_ref()) {
            for config in configs {
                let Some(subnet) = config.subnet.as_deref() else {
                    continue;
                };
                if routable_docker_subnet(subnet) {
                    subnets.insert(subnet.to_string());
                }
            }
        }
    }
    Ok(subnets)
}

fn container_has_portman_host_label(labels: Option<&HashMap<String, String>>) -> bool {
    labels
        .and_then(|labels| labels.get(LABEL_HOST))
        .is_some_and(|value| !value.trim().is_empty())
}

fn routable_docker_network_name(name: &str) -> bool {
    !matches!(name, "host" | "none" | PORTMAN_NETWORK)
}

fn routable_docker_subnet(subnet: &str) -> bool {
    subnet != PORTMAN_SUBNET_CIDR && subnet != DOCKER_BRIDGE_CIDR
}

/// Deprecated-name helper retained for potential external
/// reach-through; users should prefer [`Runtime::start`].
pub async fn inspect_container_ip(docker: &Docker, name: &str) -> Result<String> {
    let info = docker
        .inspect_container(name, None::<InspectContainerOptions>)
        .await?;
    info.network_settings
        .as_ref()
        .and_then(|s| s.networks.as_ref())
        .and_then(|n| n.get(PORTMAN_NETWORK))
        .and_then(|net| net.ip_address.clone())
        .ok_or_else(|| anyhow!("no IP on {PORTMAN_NETWORK}"))
}

// ── Routing helpers ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteCommand {
    verb: &'static str,
    cidr: String,
    iface: String,
}

impl RouteCommand {
    fn add(cidr: impl Into<String>, iface: impl Into<String>) -> Self {
        Self {
            verb: "add",
            cidr: cidr.into(),
            iface: iface.into(),
        }
    }
}

/// utun names this process has created. A route pointing at one of these is
/// portman's to repair; a route pointing at any other live utun belongs to
/// something else (chipmk's bridge, a VPN) and is left strictly alone.
static OWN_UTUNS: std::sync::Mutex<BTreeSet<String>> = std::sync::Mutex::new(BTreeSet::new());

fn remember_own_utun(name: &str) {
    OWN_UTUNS
        .lock()
        .expect("own-utun lock poisoned")
        .insert(name.to_string());
}

fn forget_own_utun(name: &str) {
    OWN_UTUNS
        .lock()
        .expect("own-utun lock poisoned")
        .remove(name);
}

fn is_own_utun(name: &str) -> bool {
    OWN_UTUNS
        .lock()
        .expect("own-utun lock poisoned")
        .contains(name)
}

/// Does `iface` still exist on the host?
fn interface_is_alive(iface: &str) -> bool {
    nix::net::if_::if_nametoindex(iface).is_ok()
}

/// Routes installed by an in-progress start, removed again if that start
/// fails. Without this a half-built runtime leaves the subnet pointed at a
/// tunnel that is about to disappear.
struct InstalledRoutes {
    iface: String,
    cidrs: Vec<String>,
    committed: bool,
}

impl InstalledRoutes {
    fn new(iface: String) -> Self {
        Self {
            iface,
            cidrs: Vec::new(),
            committed: false,
        }
    }

    fn record(&mut self, cidr: String) {
        self.cidrs.push(cidr);
    }

    /// The runtime is live; stop treating these as rollback-able.
    fn keep(&mut self) {
        self.committed = true;
    }
}

impl Drop for InstalledRoutes {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for cidr in &self.cidrs {
            if let Err(err) = run_route("delete", cidr, &self.iface) {
                warn!(%cidr, iface = %self.iface, %err, "rolling back netbridge route");
            }
        }
    }
}

fn startup_route_plan(iface: &str, extra_cidrs: &BTreeSet<String>) -> Vec<RouteCommand> {
    let mut plan = vec![RouteCommand::add(PORTMAN_SUBNET_CIDR, iface)];
    for cidr in extra_cidrs {
        if routable_docker_subnet(cidr) {
            plan.push(RouteCommand::add(cidr, iface));
        }
    }
    plan
}

/// What to do about a route that already exists for a CIDR we want.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingRoute {
    /// Already points where we want it.
    Correct,
    /// Points at a utun that is dead, or is one of ours — repair it.
    Repair,
    /// Points at a live utun somebody else owns. Not ours to touch.
    Foreign,
}

fn classify_existing_route(existing_iface: &str, wanted_iface: &str) -> ExistingRoute {
    if existing_iface == wanted_iface {
        ExistingRoute::Correct
    } else if !interface_is_alive(existing_iface) || is_own_utun(existing_iface) {
        ExistingRoute::Repair
    } else {
        ExistingRoute::Foreign
    }
}

fn ensure_route_command(cmd: &RouteCommand) -> Result<()> {
    if cmd.verb == "add" {
        if let Some(existing) = specific_route_utun_interface(&cmd.cidr) {
            match classify_existing_route(&existing, &cmd.iface) {
                ExistingRoute::Correct => return Ok(()),
                // A route left behind by a previous start — dead interface, or
                // a tunnel of ours that isn't the live one — is why the bridge
                // used to stay broken until someone ran `route change` by hand.
                // Repair it rather than accepting it forever.
                ExistingRoute::Repair => {
                    info!(
                        cidr = %cmd.cidr,
                        stale_iface = %existing,
                        iface = %cmd.iface,
                        alive = interface_is_alive(&existing),
                        "repointing stale netbridge route"
                    );
                    if run_route("change", &cmd.cidr, &cmd.iface).is_ok() {
                        return Ok(());
                    }
                    // `change` can fail if the route vanished under us; fall
                    // through and let `add` handle it.
                }
                ExistingRoute::Foreign => {
                    debug!(
                        cidr = %cmd.cidr,
                        requested_iface = %cmd.iface,
                        existing_iface = %existing,
                        "route owned by another live utun; leaving it in place"
                    );
                    return Ok(());
                }
            }
        }
    }

    match run_route(cmd.verb, &cmd.cidr, &cmd.iface) {
        Ok(()) => Ok(()),
        Err(err) if cmd.verb == "add" => match specific_route_utun_interface(&cmd.cidr) {
            Some(existing)
                if classify_existing_route(&existing, &cmd.iface) != ExistingRoute::Repair =>
            {
                debug!(cidr = %cmd.cidr, %existing, "route already present; leaving it in place");
                Ok(())
            }
            _ => Err(err),
        },
        Err(err) => Err(err),
    }
}

fn run_route(verb: &str, cidr: &str, iface: &str) -> Result<()> {
    let output = StdCommand::new("/sbin/route")
        .args(["-n", verb, "-net", cidr, "-interface", iface])
        .output()
        .with_context(|| format!("spawning /sbin/route {verb}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        let detail = if stderr.is_empty() {
            String::new()
        } else {
            format!(": {stderr}")
        };
        return Err(anyhow!(
            "/sbin/route {verb} exited with {}{detail}",
            output.status
        ));
    }
    Ok(())
}

fn specific_route_utun_interface(cidr: &str) -> Option<String> {
    let addr = cidr.split('/').next()?;
    let Ok(output) = StdCommand::new("/sbin/route")
        .args(["-n", "get", addr])
        .output()
    else {
        return None;
    };
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    route_get_specific_utun_interface(&stdout, addr)
}

fn route_get_specific_utun_interface(stdout: &str, addr: &str) -> Option<String> {
    let mut destination_matches = false;
    let mut interface = None;
    for line in stdout.lines() {
        let trimmed = line.trim_start();
        if let Some(destination) = trimmed.strip_prefix("destination:") {
            destination_matches = destination.trim() == addr;
        }
        if let Some(raw_interface) = trimmed.strip_prefix("interface:") {
            let raw_interface = raw_interface.trim();
            if raw_interface.starts_with("utun") {
                interface = Some(raw_interface.to_string());
            }
        }
    }
    if destination_matches {
        interface
    } else {
        None
    }
}

/// macOS utun frames optionally carry a 4-byte protocol-family
/// prefix. Strip it for consumers that expect raw IP packets.
fn strip_utun_prefix(pkt: &[u8]) -> &[u8] {
    if pkt.len() > 4 && pkt[0] == 0 && pkt[1] == 0 && (pkt[3] == 2 || pkt[3] == 30) {
        &pkt[4..]
    } else {
        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_route_plan_defaults_to_portman_owned_subnet() {
        let plan = startup_route_plan("utun42", &BTreeSet::new());

        assert_eq!(plan, vec![RouteCommand::add(PORTMAN_SUBNET_CIDR, "utun42")]);
        assert!(!plan.iter().any(|cmd| cmd.cidr == DOCKER_BRIDGE_CIDR));
    }

    #[test]
    fn startup_route_plan_includes_discovered_docker_subnets() {
        let extra = BTreeSet::from([
            "172.18.0.0/16".to_string(),
            DOCKER_BRIDGE_CIDR.to_string(),
            PORTMAN_SUBNET_CIDR.to_string(),
        ]);
        let plan = startup_route_plan("utun42", &extra);

        assert_eq!(
            plan,
            vec![
                RouteCommand::add(PORTMAN_SUBNET_CIDR, "utun42"),
                RouteCommand::add("172.18.0.0/16", "utun42"),
            ]
        );
    }

    #[test]
    fn route_scope_requires_portman_host_label_for_docker_mode() {
        let labels = HashMap::from([(LABEL_HOST.to_string(), "pg.test".to_string())]);
        let empty_label = HashMap::from([(LABEL_HOST.to_string(), " ".to_string())]);

        assert!(container_has_portman_host_label(Some(&labels)));
        assert!(!container_has_portman_host_label(Some(&empty_label)));
        assert!(!container_has_portman_host_label(None));
        assert!(!container_has_portman_host_label(Some(&HashMap::new())));
    }

    #[test]
    fn docker_route_discovery_skips_virtual_and_portman_networks() {
        assert!(routable_docker_network_name("dev_default"));
        assert!(routable_docker_network_name("bridge"));
        assert!(!routable_docker_network_name("host"));
        assert!(!routable_docker_network_name("none"));
        assert!(!routable_docker_network_name(PORTMAN_NETWORK));
    }

    #[test]
    fn existing_route_skip_requires_specific_utun_destination() {
        let routed = "\
   route to: 172.18.0.0
destination: 172.18.0.0
  interface: utun0
";
        let default_route = "\
   route to: 172.19.0.0
destination: default
  interface: en0
";
        let utun_default = "\
   route to: 172.19.0.0
destination: default
  interface: utun8
";

        assert_eq!(
            route_get_specific_utun_interface(routed, "172.18.0.0"),
            Some("utun0".to_string())
        );
        assert_eq!(
            route_get_specific_utun_interface(default_route, "172.19.0.0"),
            None
        );
        assert_eq!(
            route_get_specific_utun_interface(utun_default, "172.19.0.0"),
            None
        );
    }

    #[test]
    fn existing_route_skip_rejects_non_utun_interfaces() {
        let routed = "\
   route to: 172.18.0.0
destination: 172.18.0.0
       mask: 255.255.0.0
  interface: en0
";

        assert_eq!(
            route_get_specific_utun_interface(routed, "172.18.0.0"),
            None
        );
    }

    #[test]
    fn docker_network_must_have_portman_ownership_label() {
        let labels = HashMap::from([("dev.portman.managed".to_string(), "1".to_string())]);

        assert!(network_is_portman_managed(Some(&labels)));
        assert!(!network_is_portman_managed(None));
        assert!(!network_is_portman_managed(Some(&HashMap::new())));
        assert!(!network_is_portman_managed(Some(&HashMap::from([(
            "dev.portman.managed".to_string(),
            "0".to_string(),
        )]))));
    }

    #[test]
    fn setup_container_must_have_portman_ownership_and_role_labels() {
        let labels = HashMap::from([
            (MANAGED_LABEL.to_string(), MANAGED_LABEL_VALUE.to_string()),
            (ROLE_LABEL.to_string(), SETUP_ROLE_LABEL_VALUE.to_string()),
        ]);

        assert!(setup_container_is_portman_managed(Some(&labels)));
        assert!(!setup_container_is_portman_managed(None));
        assert!(!setup_container_is_portman_managed(Some(&HashMap::from([
            (MANAGED_LABEL.to_string(), MANAGED_LABEL_VALUE.to_string(),)
        ]))));
        assert!(!setup_container_is_portman_managed(Some(&HashMap::from([
            (MANAGED_LABEL.to_string(), MANAGED_LABEL_VALUE.to_string()),
            (ROLE_LABEL.to_string(), "other".to_string()),
        ]))));
    }

    #[test]
    fn setup_container_stop_timeout_allows_graceful_cleanup() {
        assert_eq!(setup_stop_timeout_secs(), 5);
    }

    #[test]
    fn setup_container_env_does_not_expose_vm_private_key() {
        let host = Keypair::generate();
        let env = setup_container_env(&host);

        assert!(env.iter().any(|value| value.starts_with("HOST_PUBKEY=")));
        assert!(env.iter().any(|value| value == "PEER_CIDR=192.168.99.2/25"));
        assert!(!env.iter().any(|value| value.starts_with("PEER_PRIVKEY=")));
    }

    fn server_err(status_code: u16, message: &str) -> DockerError {
        DockerError::DockerResponseServerError {
            status_code,
            message: message.to_string(),
        }
    }

    #[test]
    fn auto_remove_race_is_not_treated_as_a_failure() {
        // The exact shape docker returns when `auto_remove` already started
        // reaping the container we asked it to remove. Classifying this as an
        // error is what pushed every daemon restart into the retry path.
        assert!(docker_removal_already_underway(&server_err(
            409,
            "removal of container portman-netbridge-setup is already in progress"
        )));
    }

    #[test]
    fn other_conflicts_still_fail() {
        assert!(!docker_removal_already_underway(&server_err(
            409,
            "container portman-netbridge-setup is paused"
        )));
        assert!(!docker_removal_already_underway(&server_err(500, "boom")));
        assert!(!docker_removal_already_underway(&server_err(
            404, "no such"
        )));
    }

    #[test]
    fn a_route_already_pointing_at_us_is_left_alone() {
        assert_eq!(
            classify_existing_route("utun9", "utun9"),
            ExistingRoute::Correct
        );
    }

    #[test]
    fn a_route_via_a_destroyed_interface_is_repaired() {
        // Nothing can be reached through an interface that doesn't exist, so
        // repairing it can't disrupt anyone — this is the case that kept the
        // bridge silently broken.
        assert_eq!(
            classify_existing_route("utun-does-not-exist", "utun9"),
            ExistingRoute::Repair
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unauthenticated_datagrams_do_not_move_the_peer_endpoint() {
        // The rx socket is bound wide (host.docker.internal must reach it),
        // so any LAN host can hit it. Only boringtun-authenticated traffic
        // may steer where outbound tunnel frames go.
        let host_kp = Keypair::generate();
        let vm_kp = Keypair::generate();
        let rx_peer = Arc::new(Mutex::new(Peer::new(&host_kp, vm_kp.public(), None)));
        let endpoint: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        let rx_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rx_addr = rx_sock.local_addr().unwrap();
        let _task = spawn_rx(
            rx_sock.clone(),
            rx_peer.clone(),
            endpoint.clone(),
            tokio::io::sink(),
        );

        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..5 {
            attacker
                .send_to(b"not wireguard at all", rx_addr)
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            *endpoint.lock().await,
            None,
            "garbage datagrams must not set the endpoint"
        );

        // A genuine handshake initiation from the real peer DOES set it.
        let mut vm = Peer::new(&vm_kp, host_kp.public(), None);
        let mut out = [0u8; 2048];
        let TunnResult::WriteToNetwork(init) = vm.encapsulate(&[], &mut out) else {
            panic!("expected handshake initiation");
        };
        let vm_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        vm_sock.send_to(init, rx_addr).await.unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if endpoint.lock().await.is_some() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "authenticated handshake never set the endpoint"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            endpoint.lock().await.unwrap(),
            vm_sock.local_addr().unwrap()
        );
    }

    #[test]
    fn own_utun_claims_last_exactly_as_long_as_the_runtime() {
        // One test rather than two: OWN_UTUNS is a process-wide static, and
        // parallel tests sharing the same loopback name would race each
        // other. The interface must be live and not ours by default —
        // lo0 on macOS, lo on Linux CI.
        let name = ["lo0", "lo"]
            .into_iter()
            .find(|i| interface_is_alive(i))
            .expect("a loopback interface exists")
            .to_string();
        // While claimed (a live tunnel of ours): ours to repair.
        remember_own_utun(&name);
        assert_eq!(
            classify_existing_route(&name, "utun9"),
            ExistingRoute::Repair
        );
        // After shutdown forgets it, the kernel may recycle the name for a
        // VPN — a live foreign interface must never be repointed.
        forget_own_utun(&name);
        assert_eq!(
            classify_existing_route(&name, "utun9"),
            ExistingRoute::Foreign
        );
    }

    #[test]
    fn a_route_via_someone_elses_live_interface_is_never_touched() {
        // chipmk's bridge, a VPN — not ours to repoint, whatever we'd prefer.
        // Loopback is the one interface guaranteed alive on every platform
        // this test runs on (en0 exists on Macs but not Linux CI runners).
        #[cfg(target_os = "macos")]
        let live_foreign = "lo0";
        #[cfg(not(target_os = "macos"))]
        let live_foreign = "lo";
        assert_eq!(
            classify_existing_route(live_foreign, "utun9"),
            ExistingRoute::Foreign
        );
    }

    #[test]
    fn vm_public_key_is_parsed_from_setup_logs() {
        let key = Keypair::generate();
        let logs = format!(
            "portman-netbridge-setup: chip0 up\nVM_PUBKEY={}\ninterface: chip0\n",
            key.public_base64()
        );

        let parsed = parse_vm_public_key_from_logs(&logs).unwrap();

        assert_eq!(parsed.as_bytes(), key.public().as_bytes());
        assert!(parse_vm_public_key_from_logs("no key here").is_err());
    }
}
