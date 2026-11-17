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
//! On request it also makes the engine run a DNS forwarder container on
//! the VM host network ([`Runtime::ensure_dns_forwarder`]).
//! [`Runtime::shutdown`] leaves that container running, and
//! [`Runtime::shutdown_and_remove_network`] removes it.
//!
//! It is **only** the v1 host-side bridge; it knows nothing about
//! portman's proxy or registry, and of its DNS only the address that the
//! forwarder asks. The daemon keeps those separate.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Command as StdCommand, Output, Stdio};
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
use bollard::secret::{
    ContainerCreateBody, ContainerState, HostConfig, Ipam, IpamConfig, NetworkCreateRequest,
    RestartPolicy, RestartPolicyNameEnum,
};
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
/// Name of the container that runs the DNS forwarder in the VM.
pub const DNS_CONTAINER: &str = "portman-netbridge-dns";
const DNS_ROLE_LABEL_VALUE: &str = "dns-forwarder";
/// On the forwarder container: the id of the setup image it was created
/// from, so that a rebuilt image replaces it.
const DNS_FROM_IMAGE_LABEL: &str = "dev.portman.setup-image";
/// A setup image carries this label when its entrypoint has the `dns` mode
/// that [`dns_forwarder_args`] is written for.
const DNS_IMAGE_LABEL: &str = "dev.portman.dns-forwarder";
const DNS_IMAGE_LABEL_VALUE: &str = "1";
/// Stands for the VM's resolver in [`dns_forwarder_args`]. The address is in
/// the VM, so the entrypoint of the setup image puts it in.
const VM_RESOLVER: &str = "@vm-resolver@";
/// Docker and its VMs give this name to the host. It can fall under a
/// managed TLD, and it has to resolve while portman is down.
const HOST_DOCKER_INTERNAL: &str = "host.docker.internal";
const SETUP_STOP_TIMEOUT_SECS: i32 = 5;
/// How long to wait for docker to finish removing the setup container before
/// giving up and saying so.
const SETUP_REMOVE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a new setup container has to print the VM's public key.
const SETUP_KEY_TIMEOUT: Duration = Duration::from_secs(10);
const LABEL_HOST: &str = "dev.portman.host";
const ROUTE_RECONCILE_PERIOD: Duration = Duration::from_secs(5);
/// A `route` command takes milliseconds. A bridge that ends waits for the
/// command that runs at that moment, so one that takes longer is ended.
const ROUTE_LIMIT: Duration = Duration::from_secs(3);
/// How long a command that was killed gets to go away.
const KILL_GRACE: Duration = Duration::from_millis(500);
/// The waits inside one removal of the setup container: the engine's stop
/// of it, and the wait until the engine has let go of it.
const SETUP_REMOVAL_WAITS_SECS: u64 =
    SETUP_STOP_TIMEOUT_SECS as u64 + SETUP_REMOVE_TIMEOUT.as_secs();
/// What the requests of one step get on top of the waits inside it. On an
/// engine that answers they take under a second together.
const REQUESTS_MARGIN_SECS: u64 = 5;

/// How long the engine has to answer all that a stop, a cleanup of
/// leftovers or an ensure of the DNS forwarder asks it. The limit of the
/// caller's client is for one request and ends at the head of the response,
/// so a VM that froze with its socket open held a step for a multiple of
/// that limit, or without end once a head was in. Each of these steps
/// removes the setup container at most once, and the budget is the waits of
/// that removal and `REQUESTS_MARGIN_SECS`, so that it cuts no step on an
/// engine that answers.
pub const ENGINE_STEP_BUDGET: Duration =
    Duration::from_secs(SETUP_REMOVAL_WAITS_SECS + REQUESTS_MARGIN_SECS);

/// As [`ENGINE_STEP_BUDGET`], for a start. A start removes the setup
/// container of an earlier bridge, waits `SETUP_KEY_TIMEOUT` for the key
/// of the new one, and removes that one when no key came. The budget is
/// those waits and `REQUESTS_MARGIN_SECS`, so that a start that uses up
/// every wait still ends with its own error and with its setup container
/// gone.
pub const ENGINE_START_BUDGET: Duration = Duration::from_secs(
    2 * SETUP_REMOVAL_WAITS_SECS + SETUP_KEY_TIMEOUT.as_secs() + REQUESTS_MARGIN_SECS,
);

/// A step that is cut leaves in the engine what it had done by then.
async fn within<T>(budget: Duration, step: impl Future<Output = T>) -> Result<T> {
    let cut = tokio::time::timeout(budget, step).await;
    cut.map_err(|_| {
        anyhow!(
            "the container engine gave no answer within {} s",
            budget.as_secs()
        )
    })
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeOptions {
    pub mode: NetbridgeMode,
    /// The UDP port that the bridge listens on and that the VM peer dials.
    pub listen_port: u16,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            mode: NetbridgeMode::OptIn,
            listen_port: HOST_WG_LISTEN_PORT,
        }
    }
}

/// A started portman-netbridge. Hold it as long as you want the
/// bridge up; drop it or call [`Runtime::shutdown`] to tear down.
pub struct Runtime {
    utun_name: String,
    setup_container_id: String,
    docker: Docker,
    /// Held until the runtime is dropped, so that a shutdown removes the
    /// setup container before another daemon can bind the port.
    listen_port: ListenPort,
    /// Pump and route tasks, cancelled and joined on shutdown.
    tasks: Vec<JoinHandle<()>>,
}

/// A UDP port, bound. Every removal from the engine takes one. Two sockets
/// cannot bind one port, and a bridge holds its port from before it asks the
/// engine anything until a shutdown has removed its setup container or the
/// bridge is dropped. A claim therefore shows that no other daemon's bridge
/// is up, but only when the port is the one that every bridge listens on,
/// [`HOST_WG_LISTEN_PORT`]. The caller of [`remove_leftovers`] names the
/// port, so that is the caller's to get right.
struct ListenPort(Arc<UdpSocket>);

impl ListenPort {
    async fn claim(port: u16) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(("0.0.0.0", port)).await?;
        Ok(Self(Arc::new(socket)))
    }
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

    /// As [`Runtime::start_with_options`], with the host keypair supplied by
    /// the caller. A caller that retries a failed start passes the same
    /// keypair, and the key is then logged once and not for every retry.
    /// A start that the engine does not answer fails when
    /// [`ENGINE_START_BUDGET`] is spent. It can leave a setup container,
    /// which the next start or cleanup removes.
    pub async fn start_with_keypair(
        docker: Docker,
        options: RuntimeOptions,
        host_kp: &Keypair,
    ) -> Result<Self> {
        within(
            ENGINE_START_BUDGET,
            Self::bring_up(docker, options, host_kp),
        )
        .await?
    }

    async fn bring_up(docker: Docker, options: RuntimeOptions, host_kp: &Keypair) -> Result<Self> {
        let host_pub = host_kp.public_base64();
        if is_new_host_key(&host_pub) {
            info!(
                %host_pub,
                mode = options.mode.as_str(),
                "netbridge host key generated"
            );
        }

        // Ordering is load-bearing: everything that can realistically fail —
        // the listen port, docker network, route discovery, the setup
        // container — happens before the utun and its routes exist. A failure
        // here used to unwind past an already-created utun and its installed
        // routes, orphaning both; the routes then pinned the subnet to a dead
        // interface and the reconciler treated them as fine, so the bridge
        // stayed silently broken.

        // ── UDP
        //
        // First, before the engine is asked anything. A cleanup removes the
        // docker network only while it holds this port, so a start that holds
        // it cannot lose the network it is about to rely on.
        let listen_port = ListenPort::claim(options.listen_port)
            .await
            .with_context(|| format!("binding 0.0.0.0:{}", options.listen_port))?;
        let udp = &listen_port.0;

        // ── Portman-owned docker network
        //
        // Preflight this before touching host routes or setup containers. A
        // network called "portman" is not enough ownership proof; another
        // user/tool may already own that name.
        ensure_portman_network(&docker, &listen_port).await?;
        let extra_route_cidrs = docker_route_cidrs(&docker, options.mode).await?;

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
        remove_existing_setup_container(&docker, &listen_port).await?;
        let (setup_container_id, vm_pubkey) =
            spawn_setup_container(&docker, host_kp, options.listen_port, &listen_port).await?;
        info!(container = SETUP_CONTAINER, "VM setup container running");

        // ── utun + routes, last, and rolled back together on failure
        let (device, utun_name) = match open_utun(&extra_route_cidrs) {
            Ok(opened) => opened,
            Err(err) => {
                best_effort_remove_setup_container(&docker, &listen_port).await;
                return Err(err);
            }
        };

        // ── Peer + shared state
        let peer = Arc::new(Mutex::new(Peer::new(host_kp, &vm_pubkey, Some(25))));
        let vm_endpoint: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let (dev_read, dev_write) = tokio::io::split(device);

        let rx = spawn_rx(
            udp.clone(),
            peer.clone(),
            vm_endpoint.clone(),
            &utun_name,
            dev_write,
        );
        let tx = spawn_tx(
            udp.clone(),
            peer.clone(),
            vm_endpoint.clone(),
            &utun_name,
            dev_read,
        );
        let timer = spawn_timer(udp.clone(), peer.clone(), vm_endpoint.clone());
        let routes =
            spawn_route_reconciler(docker.clone(), options.mode, utun_name.clone(), sbin_route);

        Ok(Self {
            utun_name,
            setup_container_id,
            docker,
            listen_port,
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

    /// The engine's id of the setup container that this bridge started. The
    /// VM end of the tunnel exists for as long as that container runs.
    pub fn setup_container_id(&self) -> &str {
        &self.setup_container_id
    }

    /// Makes the engine run one DNS forwarder for `managed_tlds`. It creates
    /// the container when the engine has none, and replaces it only when it
    /// does not run, runs another command, or comes from another build of
    /// the setup image. One that has the wanted command from the current
    /// image and that the engine starts again and again stays as it is,
    /// because a new one would end the same way. A container of that name
    /// without portman's labels is an error and stays as it is. The bridge
    /// holds the listen port, so no other daemon has a bridge up whose
    /// forwarder this could replace. An ensure that the engine does not
    /// answer fails when [`ENGINE_STEP_BUDGET`] is spent.
    pub async fn ensure_dns_forwarder(
        &self,
        managed_tlds: &BTreeSet<String>,
    ) -> Result<DnsForwarder> {
        within(ENGINE_STEP_BUDGET, self.ensure_forwarder(managed_tlds)).await?
    }

    async fn ensure_forwarder(&self, managed_tlds: &BTreeSet<String>) -> Result<DnsForwarder> {
        let Some(image) = setup_image_with_dns_mode(&self.docker).await? else {
            return Ok(DnsForwarder::ImageWithoutDnsMode);
        };
        ensure_portman_network(&self.docker, &self.listen_port).await?;
        let cmd = dns_forwarder_args(managed_tlds);
        let found = dns_forwarder_snapshot(&self.docker).await?;
        match forwarder_step(found.as_ref(), &image, &cmd) {
            ForwarderStep::Keep => return Ok(DnsForwarder::InPlace),
            ForwarderStep::LeaveRestarting => return Ok(DnsForwarder::Restarting),
            ForwarderStep::Foreign => anyhow::bail!(
                "docker container `{DNS_CONTAINER}` already exists but is not managed by portman"
            ),
            ForwarderStep::Replace => remove_dns_forwarder(&self.docker, &self.listen_port).await?,
            ForwarderStep::Create => {}
        }
        create_dns_forwarder(&self.docker, &image, cmd).await?;
        Ok(DnsForwarder::Started)
    }

    /// Cleanly tear down the bridge. Aborts the pump tasks and removes
    /// the setup container. The `portman` docker network is left in
    /// place — if user containers are attached, they keep their IPs
    /// and become reachable again as soon as the daemon comes back up.
    /// The DNS forwarder also stays, so that containers that use it keep
    /// resolving every name that is not portman's.
    /// `portman bridge disable` (user intent) still wants the network
    /// gone; call [`Runtime::shutdown_and_remove_network`] for that.
    /// The engine has [`ENGINE_STEP_BUDGET`] to remove the setup container.
    /// On an engine that does not answer in that time the bridge is still
    /// down when this returns, and the container can still be there.
    pub async fn shutdown(mut self) {
        self.end_tasks().await;
        let container = Leftovers::SetupContainer;
        remove_with_port_held(&self.docker, &self.listen_port, container).await;
        info!(utun = %self.utun_name, "netbridge shut down (network retained)");
    }

    /// Shutdown + best-effort remove the DNS forwarder and then the docker
    /// network, whose gateway address the forwarder listens on. Used when
    /// the user explicitly disables the bridge (`portman bridge disable`),
    /// not on daemon restart. Docker refuses the removal of the network
    /// only while a running container is attached, and that is logged. A
    /// stopped container that refers to the network fails to start
    /// afterwards. The return value says whether a later cleanup has
    /// anything left to try, as [`try_remove_leftovers`] does. The engine
    /// has [`ENGINE_STEP_BUDGET`] for all of it.
    pub async fn shutdown_and_remove_network(mut self) -> CleanupEnd {
        self.end_tasks().await;
        let everything = Leftovers::SetupContainerAndNetwork;
        let cleanup = remove_with_port_held(&self.docker, &self.listen_port, everything).await;
        info!(utun = %self.utun_name, "netbridge shut down");
        cleanup
    }

    /// Ends the bridge and asks the engine nothing, for a bridge whose
    /// engine is gone. The pump tasks hold the listen port and the utun, and
    /// they have ended when this returns. So a start that follows at once
    /// finds the port free, which it does not after a drop.
    pub async fn abandon(mut self) {
        self.end_tasks().await;
    }

    async fn end_tasks(&mut self) {
        self.abort_tasks();
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
    }

    fn abort_tasks(&self) {
        // The kernel recycles utun names. Keep claiming this one after the
        // device is gone and route repair would treat a *recycled* utun —
        // somebody else's VPN — as ours to repoint. So the claim goes
        // first, and the tasks that hold the device go after it.
        forget_own_utun(&self.utun_name);
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.abort_tasks();
    }
}

/// The host key of the last start. The retries of one start share its key.
static LAST_HOST_KEY: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Whether `host_pub` differs from the key of the start before this one.
fn is_new_host_key(host_pub: &str) -> bool {
    let mut last = LAST_HOST_KEY.lock().expect("host key lock poisoned");
    if last.as_deref() == Some(host_pub) {
        return false;
    }
    *last = Some(host_pub.to_string());
    true
}

/// Creates the utun and installs its routes. On a failure it drops the
/// device and rolls back the routes it installed.
fn open_utun(extra_route_cidrs: &BTreeSet<String>) -> Result<(tun::AsyncDevice, String)> {
    let mut cfg = tun::Configuration::default();
    cfg.address(HOST_TUNNEL_IP)
        .netmask((255, 255, 255, 0))
        .destination(VM_TUNNEL_IP)
        .mtu(i32::from(TUNNEL_MTU))
        .up();
    let device = tun::create_as_async(&cfg).context("creating utun")?;
    prevent_child_inheritance(device.get_ref().as_raw_fd())?;
    let utun_name = device.get_ref().name().context("utun name")?;
    info!(utun = %utun_name, "utun up");
    remember_own_utun(&utun_name);

    let mut installed = InstalledRoutes::new(utun_name.clone());
    for cmd in startup_route_plan(&utun_name, extra_route_cidrs) {
        if let Err(err) = ensure_route_command(&sbin_route, &cmd) {
            // The device drops with this error; stop claiming its name
            // (same reasoning as shutdown — names are recycled).
            forget_own_utun(&utun_name);
            return Err(err.into());
        }
        installed.record(cmd.cidr);
    }
    // Past the last fallible step — these routes belong to a live runtime
    // now, so the guard must not undo them.
    installed.keep();
    Ok((device, utun_name))
}

fn prevent_child_inheritance(fd: RawFd) -> Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};

    let flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD)?);
    fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))
        .context("preventing tunnel descriptor inheritance")?;
    Ok(())
}

// ── Task spawners ──────────────────────────────────────────────────

/// A pump that ends drops its half of the utun device, whatever ended it,
/// and the device closes when both halves have dropped. The kernel can then
/// give the utun's name to the next utun, so the bridge lets go of the name
/// before the half drops. No change to a pump can turn that order around,
/// because Rust runs the `drop` of a value before it drops the value's
/// fields, and it moves no field out of a type that has a `drop`.
struct OwnHalf<D> {
    utun: String,
    half: D,
}

impl<D> Drop for OwnHalf<D> {
    fn drop(&mut self) {
        forget_own_utun(&self.utun);
    }
}

fn spawn_rx<W>(
    udp: Arc<UdpSocket>,
    peer: Arc<Mutex<Peer>>,
    endpoint: Arc<Mutex<Option<SocketAddr>>>,
    utun: &str,
    dev_write: W,
) -> JoinHandle<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut dev_write = OwnHalf {
        utun: utun.to_string(),
        half: dev_write,
    };
    tokio::spawn(async move {
        // Sized so no UDP datagram or 1500-MTU container packet can arrive
        // truncated — a clipped frame would feed decapsulate garbage that
        // looks like an auth failure. First 4 bytes of `out` hold the
        // big-endian AF_INET = 2 prefix required by macOS utun so writing to
        // `dev_write` needs zero per-packet allocations or copies.
        let mut buf = vec![0u8; usize::from(u16::MAX)];
        let mut out = vec![0u8; 4 + usize::from(u16::MAX)];
        out[..4].copy_from_slice(&[0, 0, 0, 2]);
        let mut last_authenticated_src: Option<SocketAddr> = None;
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
            let mut first_pass = true;
            loop {
                let is_first = std::mem::take(&mut first_pass);
                let input: &[u8] = if is_first { &buf[..n] } else { &[] };
                let r = {
                    let mut p = peer.lock().await;
                    p.decapsulate(input, &mut out[4..])
                };
                match r {
                    TunnResult::Err(_) => break,
                    TunnResult::WriteToNetwork(frame) => {
                        if is_first {
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
                    }
                    TunnResult::WriteToTunnelV4(pkt, _) => {
                        if is_first {
                            authenticated = true;
                        }
                        let pkt_len = pkt.len();
                        if let Err(err) = dev_write.half.write_all(&out[..4 + pkt_len]).await {
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
                        if is_first {
                            authenticated = true;
                        }
                        break;
                    }
                }
            }
            if authenticated && last_authenticated_src != Some(src) {
                *endpoint.lock().await = Some(src);
                last_authenticated_src = Some(src);
            }
        }
    })
}

fn spawn_tx<R>(
    udp: Arc<UdpSocket>,
    peer: Arc<Mutex<Peer>>,
    endpoint: Arc<Mutex<Option<SocketAddr>>>,
    utun: &str,
    dev_read: R,
) -> JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let mut dev_read = OwnHalf {
        utun: utun.to_string(),
        half: dev_read,
    };
    tokio::spawn(async move {
        let mut pkt = vec![0u8; usize::from(u16::MAX)];
        let mut out = vec![0u8; usize::from(u16::MAX)];
        let mut send_warned = false;
        loop {
            let n = match dev_read.half.read(&mut pkt).await {
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

fn spawn_route_reconciler(
    docker: Docker,
    mode: NetbridgeMode,
    iface: String,
    route: fn(&[&str]) -> std::io::Result<Output>,
) -> JoinHandle<()> {
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
            let cmds = startup_route_plan(&iface, &extra_route_cidrs);
            let pass = tokio::task::spawn_blocking(move || reconcile_routes(&route, &cmds));
            let bridge_holds_utun = pass.await.unwrap_or(true);
            if !bridge_holds_utun {
                return;
            }
        }
    })
}

/// One pass of the route reconciler. It runs on a blocking thread, and the
/// abort of the reconciler task does not end it. A bridge lets go of its
/// utun before the interface goes, and the routes go with the interface.
/// Returns whether the bridge still holds its utun. A bridge never takes a
/// utun back, so a pass that returns `false` is the last one.
fn reconcile_routes(route: &RunRoute, cmds: &[RouteCommand]) -> bool {
    for cmd in cmds {
        match ensure_route_command(route, cmd) {
            Ok(()) => {}
            Err(RouteError::LetGo) => {
                info!(iface = %cmd.iface, "netbridge route pass ended with its bridge");
                return false;
            }
            Err(RouteError::Failed(err)) => {
                warn!(cidr = %cmd.cidr, iface = %cmd.iface, %err, "netbridge route reconcile failed");
            }
        }
    }
    true
}

// ── Docker helpers ─────────────────────────────────────────────────

/// Returns the engine's id of the container and the VM's public key.
async fn spawn_setup_container(
    docker: &Docker,
    host: &Keypair,
    listen_port: u16,
    held: &ListenPort,
) -> Result<(String, boringtun::x25519::PublicKey)> {
    let env = setup_container_env(host, listen_port);
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
    let created = docker
        .create_container(Some(opts), body)
        .await
        .context("creating netbridge setup container")?;
    if let Err(err) = docker
        .start_container(SETUP_CONTAINER, None::<StartContainerOptions>)
        .await
    {
        best_effort_remove_setup_container(docker, held).await;
        return Err(err).context("starting netbridge setup container");
    }
    // Poll until the setup container is running and has printed `VM_PUBKEY=`,
    // instead of a fixed 2s sleep that slows normal starts and fails under load.
    let deadline = tokio::time::Instant::now() + SETUP_KEY_TIMEOUT;
    loop {
        if let Err(err) = ensure_setup_container_running(docker).await {
            best_effort_remove_setup_container(docker, held).await;
            return Err(err);
        }
        match read_setup_vm_public_key(docker).await {
            Ok(key) => return Ok((created.id, key)),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                best_effort_remove_setup_container(docker, held).await;
                return Err(err);
            }
        }
    }
}

fn setup_container_env(host: &Keypair, listen_port: u16) -> Vec<String> {
    vec![
        format!("HOST_PUBKEY={}", host.public_base64()),
        format!("HOST_ENDPOINT=host.docker.internal:{listen_port}"),
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
async fn ensure_portman_network(docker: &Docker, _held: &ListenPort) -> Result<()> {
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

async fn remove_existing_setup_container(docker: &Docker, _held: &ListenPort) -> Result<()> {
    let Some((labels, running)) = setup_container_snapshot(docker).await? else {
        return Ok(());
    };
    if !setup_container_is_portman_managed(Some(&labels)) {
        return Err(ForeignSetupContainer.into());
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
    wait_for_setup_container_gone(docker).await?;
    info!(
        container = SETUP_CONTAINER,
        "netbridge setup container removed"
    );
    Ok(())
}

/// Poll until the setup container no longer exists. Bounded: if docker is wedged
/// we want a named error, not a hung daemon start.
async fn wait_for_setup_container_gone(docker: &Docker) -> Result<()> {
    let deadline = tokio::time::Instant::now() + SETUP_REMOVE_TIMEOUT;
    loop {
        if setup_container_snapshot(docker).await?.is_none() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "netbridge setup container `{SETUP_CONTAINER}` still present {}s after removal",
                SETUP_REMOVE_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A container has the setup container's name and not portman's labels.
#[derive(Debug)]
struct ForeignSetupContainer;

impl std::fmt::Display for ForeignSetupContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "docker container `{SETUP_CONTAINER}` already exists but is not managed by portman"
        )
    }
}

impl std::error::Error for ForeignSetupContainer {}

/// Whether the engine is left with no setup container of portman's. A
/// container of that name that something else owns is not portman's to
/// remove.
async fn best_effort_remove_setup_container(docker: &Docker, held: &ListenPort) -> bool {
    match remove_existing_setup_container(docker, held).await {
        Ok(()) => true,
        Err(err) if err.is::<ForeignSetupContainer>() => {
            warn!(
                container = SETUP_CONTAINER,
                "skipping netbridge setup container removal because it is not marked as portman-managed"
            );
            true
        }
        Err(err) => {
            warn!(
                container = SETUP_CONTAINER,
                error = %format_args!("{err:#}"),
                "could not remove netbridge setup container"
            );
            false
        }
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

/// Is this the engine's refusal to remove a network that is in use?
///
/// The engine answers a removal of a network that has active endpoints
/// with 403, and a running container is what holds an endpoint. Its other
/// 403 answers to a removal are for kinds of network that portman does not
/// create: one that the engine predefines, an ingress network, and a
/// configuration network that another network uses.
fn docker_network_in_use(err: &DockerError) -> bool {
    matches!(
        err,
        DockerError::DockerResponseServerError {
            status_code: 403,
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

/// The command of the forwarder container: the `dns` mode of the setup
/// image, then the arguments of dnsmasq.
///
/// dnsmasq listens on the gateway address of the `portman` network only. In
/// strict order it asks portman first and the VM's resolver second for a
/// name under a managed TLD, so a name that portman refuses still resolves.
/// Every other name goes to the resolvers in the VM's `/etc/resolv.conf`,
/// which dnsmasq reads itself. It keeps no answer: portman can register a
/// moment later the name that the VM's resolver just answered or denied,
/// and a cached answer would hide the registration for as long as that
/// resolver's TTL says.
/// It logs to stderr, where `docker logs` finds what it wrote.
pub fn dns_forwarder_args(managed_tlds: &BTreeSet<String>) -> Vec<String> {
    let mut args = vec![
        "dns".to_string(),
        "--keep-in-foreground".to_string(),
        "--no-hosts".to_string(),
        format!("--listen-address={DOCKER_BRIDGE_GATEWAY}"),
        "--bind-interfaces".to_string(),
        "--strict-order".to_string(),
        "--cache-size=0".to_string(),
        "--log-facility=-".to_string(),
    ];
    let forwarded = managed_tlds
        .iter()
        .filter(|tld| !matches!(tld.as_str(), "localhost" | HOST_DOCKER_INTERNAL));
    for tld in forwarded {
        args.push(format!("--server=/{tld}/{HOST_TUNNEL_IP}"));
        args.push(format!("--server=/{tld}/{VM_RESOLVER}"));
    }
    args.push(format!("--server=/{HOST_DOCKER_INTERNAL}/#"));
    args
}

/// How [`Runtime::ensure_dns_forwarder`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsForwarder {
    /// The engine holds the forwarder container with the wanted command,
    /// from the current setup image, and it ran before this ensure.
    InPlace,
    /// The engine created that container now and started it. A dnsmasq
    /// that ends at once shows only at a later ensure, as `Restarting`.
    Started,
    /// The engine has no setup image whose entrypoint has the `dns` mode.
    /// `portman bridge prepare` builds one. Nothing was created or removed.
    ImageWithoutDnsMode,
    /// The engine holds the forwarder container with the wanted command,
    /// from the current setup image, and starts it again and again. Nothing
    /// was created or removed. `docker logs` of [`DNS_CONTAINER`] shows why
    /// dnsmasq ends.
    Restarting,
}

/// The id of the setup image, when the engine has one with the `dns` mode.
/// The answer comes from the image's labels, so no container runs for it.
async fn setup_image_with_dns_mode(docker: &Docker) -> Result<Option<String>> {
    let image = match docker.inspect_image(SETUP_IMAGE).await {
        Ok(image) => image,
        Err(err) if docker_not_found(&err) => return Ok(None),
        Err(err) => return Err(err).context("inspecting the netbridge setup image"),
    };
    let labels = image.config.and_then(|config| config.labels);
    if !image_has_dns_mode(labels.as_ref()) {
        return Ok(None);
    }
    let id = image
        .id
        .ok_or_else(|| anyhow!("the engine gave no id for the netbridge setup image"))?;
    Ok(Some(id))
}

fn image_has_dns_mode(labels: Option<&HashMap<String, String>>) -> bool {
    labels
        .and_then(|labels| labels.get(DNS_IMAGE_LABEL))
        .is_some_and(|value| value == DNS_IMAGE_LABEL_VALUE)
}

/// The container named [`DNS_CONTAINER`] as the engine holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwarderSnapshot {
    id: String,
    labels: HashMap<String, String>,
    cmd: Vec<String>,
    state: ForwarderState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwarderState {
    Running,
    /// The process ended and the restart policy starts it again.
    Restarting,
    Stopped,
}

/// The engine reports a container that it restarts as running too, so
/// `Restarting` is asked about first.
fn forwarder_state(state: Option<ContainerState>) -> ForwarderState {
    let state = state.unwrap_or_default();
    if state.restarting == Some(true) {
        ForwarderState::Restarting
    } else if state.running == Some(true) {
        ForwarderState::Running
    } else {
        ForwarderState::Stopped
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ForwarderStep {
    Keep,
    /// The container is the one to run, and it does not stay up. A new one
    /// from the same image with the same command would end the same way.
    LeaveRestarting,
    Create,
    Replace,
    /// Something else owns the name. It is not portman's to remove.
    Foreign,
}

/// `image` is the id of the current setup image and `cmd` the command the
/// forwarder should run.
fn forwarder_step(found: Option<&ForwarderSnapshot>, image: &str, cmd: &[String]) -> ForwarderStep {
    let Some(found) = found else {
        return ForwarderStep::Create;
    };
    if !carries_portman_role(Some(&found.labels), DNS_ROLE_LABEL_VALUE) {
        return ForwarderStep::Foreign;
    }
    let from_this_image = found.labels.get(DNS_FROM_IMAGE_LABEL).map(String::as_str) == Some(image);
    let is_the_one_to_run = from_this_image && found.cmd == cmd;
    match found.state {
        ForwarderState::Running if is_the_one_to_run => ForwarderStep::Keep,
        ForwarderState::Restarting if is_the_one_to_run => ForwarderStep::LeaveRestarting,
        _ => ForwarderStep::Replace,
    }
}

async fn dns_forwarder_snapshot(docker: &Docker) -> Result<Option<ForwarderSnapshot>> {
    let info = match docker
        .inspect_container(DNS_CONTAINER, None::<InspectContainerOptions>)
        .await
    {
        Ok(info) => info,
        Err(err) if docker_not_found(&err) => return Ok(None),
        Err(err) => return Err(err).context("inspecting the dns forwarder container"),
    };
    let config = info.config.unwrap_or_default();
    Ok(Some(ForwarderSnapshot {
        id: info.id.unwrap_or_else(|| DNS_CONTAINER.to_string()),
        labels: config.labels.unwrap_or_default(),
        cmd: config.cmd.unwrap_or_default(),
        state: forwarder_state(info.state),
    }))
}

/// The restart policy is `always`, so that the engine starts the forwarder
/// again with the VM, with no daemon and no bridge. The container gets no
/// capability beyond the engine's default set.
async fn create_dns_forwarder(docker: &Docker, image: &str, cmd: Vec<String>) -> Result<()> {
    let body = ContainerCreateBody {
        image: Some(SETUP_IMAGE.to_string()),
        cmd: Some(cmd),
        host_config: Some(HostConfig {
            network_mode: Some("host".to_string()),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::ALWAYS),
                maximum_retry_count: None,
            }),
            ..Default::default()
        }),
        labels: Some(HashMap::from([
            (MANAGED_LABEL.into(), MANAGED_LABEL_VALUE.into()),
            (ROLE_LABEL.into(), DNS_ROLE_LABEL_VALUE.into()),
            (DNS_FROM_IMAGE_LABEL.into(), image.into()),
        ])),
        ..Default::default()
    };
    let opts = CreateContainerOptionsBuilder::default()
        .name(DNS_CONTAINER)
        .build();
    docker
        .create_container(Some(opts), body)
        .await
        .context("creating the dns forwarder container")?;
    docker
        .start_container(DNS_CONTAINER, None::<StartContainerOptions>)
        .await
        .context("starting the dns forwarder container")
}

/// Removes the forwarder container when it carries portman's labels, by the
/// id that carried them. One that is absent is passed over, and so is a
/// container of that name that something else owns.
async fn remove_dns_forwarder(docker: &Docker, _held: &ListenPort) -> Result<()> {
    let Some(found) = dns_forwarder_snapshot(docker).await? else {
        return Ok(());
    };
    if !carries_portman_role(Some(&found.labels), DNS_ROLE_LABEL_VALUE) {
        warn!(
            container = DNS_CONTAINER,
            "skipping dns forwarder removal because it is not marked as portman-managed"
        );
        return Ok(());
    }
    let opts = RemoveContainerOptionsBuilder::default().force(true).build();
    match docker.remove_container(&found.id, Some(opts)).await {
        Ok(()) => {
            info!(container = DNS_CONTAINER, "dns forwarder container removed");
            Ok(())
        }
        Err(err) if docker_not_found(&err) => Ok(()),
        Err(err) => Err(err).context("removing the dns forwarder container"),
    }
}

/// Whether the engine is left with no forwarder of portman's.
async fn best_effort_remove_dns_forwarder(docker: &Docker, held: &ListenPort) -> bool {
    match remove_dns_forwarder(docker, held).await {
        Ok(()) => true,
        Err(err) => {
            warn!(
                container = DNS_CONTAINER,
                error = %format_args!("{err:#}"),
                "could not remove the dns forwarder container"
            );
            false
        }
    }
}

/// What a bridge can leave in the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leftovers {
    SetupContainer,
    /// Also the DNS forwarder, which listens on the network's gateway
    /// address and goes before the network does. The engine removes a
    /// network that a stopped container refers to, and that container then
    /// fails to start. Only a user's request calls for this: to turn the
    /// bridge off, or to uninstall portman.
    SetupContainerAndNetwork,
}

/// How a cleanup of [`Leftovers`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cleanup {
    /// Nothing is left for a later cleanup to try. What was asked for is
    /// gone or is not portman's, or the engine refused to remove the network
    /// because it is in use, and that network stays. A cleanup that asked
    /// again would take it from under containers that have stopped since,
    /// so this also holds when the DNS forwarder could not be removed. That
    /// forwarder stays until the next request to turn the bridge off.
    Complete,
    /// The cleanup was skipped, or a removal failed for a reason that says
    /// nothing about what it was to remove. What was asked for can still be
    /// in the engine.
    Owed,
}

/// How a cleanup of [`Leftovers`] ended, for a caller that acts on why one
/// did not finish. [`Cleanup`] folds the two reasons into `Owed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupEnd {
    /// As [`Cleanup::Complete`].
    Complete,
    /// A removal failed for a reason that says nothing about what it was to
    /// remove. What was asked for can still be in the engine.
    Failed,
    /// The engine gave no answer within [`ENGINE_STEP_BUDGET`]. What was
    /// asked for can still be in the engine.
    NoAnswer,
}

impl From<CleanupEnd> for Cleanup {
    fn from(end: CleanupEnd) -> Self {
        match end {
            CleanupEnd::Complete => Cleanup::Complete,
            CleanupEnd::Failed | CleanupEnd::NoAnswer => Cleanup::Owed,
        }
    }
}

/// Removes `leftovers` from the engine. Each is removed only when it carries
/// portman's labels, and one that is absent is passed over. The engine
/// refuses to remove the network only while a running container is attached
/// to it.
///
/// The labels name portman and not one daemon, so the removal also needs
/// UDP port `listen_port`. Pass [`HOST_WG_LISTEN_PORT`], the one that every
/// bridge listens on: holding any other port shows nothing about a running
/// bridge. When the claim on the port fails, nothing is removed and the
/// engine is not asked.
///
/// The engine has [`ENGINE_STEP_BUDGET`] for all the removals. A cleanup
/// that is cut there ends owed.
pub async fn remove_leftovers(docker: &Docker, listen_port: u16, leftovers: Leftovers) -> Cleanup {
    match try_remove_leftovers(docker, listen_port, leftovers).await {
        Ok(end) => end.into(),
        Err(err) => {
            say_why_leftovers_stay(listen_port, &err);
            Cleanup::Owed
        }
    }
}

/// Only an address in use says that the port has a holder.
fn say_why_leftovers_stay(listen_port: u16, err: &std::io::Error) {
    if err.kind() == std::io::ErrorKind::AddrInUse {
        info!(
            listen_port,
            %err,
            "netbridge leftovers stay in the engine: the listen port is taken, and its holder may run a bridge on them"
        );
    } else {
        warn!(
            listen_port,
            %err,
            "netbridge leftovers stay in the engine: the claim on the listen port failed"
        );
    }
}

/// As [`remove_leftovers`], for a caller that acts on why a cleanup did not
/// finish. The error is that of the claim on `listen_port`: nothing was
/// removed and the engine was not asked. Only an address in use says that
/// the port is taken. This function does not log the error.
pub async fn try_remove_leftovers(
    docker: &Docker,
    listen_port: u16,
    leftovers: Leftovers,
) -> std::io::Result<CleanupEnd> {
    let held = ListenPort::claim(listen_port).await?;
    Ok(remove_with_port_held(docker, &held, leftovers).await)
}

async fn remove_with_port_held(
    docker: &Docker,
    held: &ListenPort,
    leftovers: Leftovers,
) -> CleanupEnd {
    let removals = remove_each(docker, held, leftovers);
    within(ENGINE_STEP_BUDGET, removals).await.unwrap_or_else(|error| {
        warn!(
            %error,
            "netbridge cleanup ended early, and what it was to remove can still be in the engine"
        );
        CleanupEnd::NoAnswer
    })
}

async fn remove_each(docker: &Docker, held: &ListenPort, leftovers: Leftovers) -> CleanupEnd {
    let container_gone = best_effort_remove_setup_container(docker, held).await;
    let (forwarder_gone, network) = match leftovers {
        Leftovers::SetupContainer => (true, None),
        Leftovers::SetupContainerAndNetwork => {
            let forwarder_gone = best_effort_remove_dns_forwarder(docker, held).await;
            let network = remove_portman_network_if_owned(docker, held).await;
            (forwarder_gone, Some(network))
        }
    };
    match network {
        Some(NetworkCleanup::InUse) => CleanupEnd::Complete,
        _ if !forwarder_gone => CleanupEnd::Failed,
        None | Some(NetworkCleanup::NoneLeft) if container_gone => CleanupEnd::Complete,
        None | Some(NetworkCleanup::NoneLeft | NetworkCleanup::Owed) => CleanupEnd::Failed,
    }
}

/// How a removal of the network named `portman` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkCleanup {
    /// The engine holds no network of portman's. A network of that name
    /// that something else owns is not portman's to remove.
    NoneLeft,
    /// The engine refused the removal because the network is in use. A
    /// removal that is asked for again later can take the network from
    /// under containers that have stopped since.
    InUse,
    /// The removal was not tried, or it failed for a reason that says
    /// nothing about the network.
    Owed,
}

async fn remove_portman_network_if_owned(docker: &Docker, _held: &ListenPort) -> NetworkCleanup {
    let inspected = docker
        .inspect_network(PORTMAN_NETWORK, None::<InspectNetworkOptions>)
        .await;
    match network_removal(inspected.as_ref().map(|net| net.labels.as_ref())) {
        NetworkRemoval::Remove => match docker.remove_network(PORTMAN_NETWORK).await {
            Ok(()) => {
                info!(network = PORTMAN_NETWORK, "docker network removed");
                NetworkCleanup::NoneLeft
            }
            Err(err) if docker_network_in_use(&err) => {
                warn!(
                    network = PORTMAN_NETWORK,
                    error = %err,
                    "docker network stays: the engine refused to remove it while it is in use. The next `portman bridge disable` asks again"
                );
                NetworkCleanup::InUse
            }
            Err(err) => {
                warn!(
                    network = PORTMAN_NETWORK,
                    error = %err,
                    "could not remove docker network"
                );
                NetworkCleanup::Owed
            }
        },
        NetworkRemoval::Foreign => {
            warn!(
                network = PORTMAN_NETWORK,
                "skipping docker network removal because it is not marked as portman-managed"
            );
            NetworkCleanup::NoneLeft
        }
        NetworkRemoval::Absent => NetworkCleanup::NoneLeft,
        NetworkRemoval::Unknown(err) => {
            warn!(
                network = PORTMAN_NETWORK,
                error = %err,
                "could not inspect docker network before removal"
            );
            NetworkCleanup::Owed
        }
    }
}

/// What to do with the network named `portman`, given the answer to an
/// inspect of it.
#[derive(Debug)]
enum NetworkRemoval<'a> {
    Remove,
    /// Something else owns the name.
    Foreign,
    Absent,
    Unknown(&'a DockerError),
}

fn network_removal<'a>(
    inspected: Result<Option<&HashMap<String, String>>, &'a DockerError>,
) -> NetworkRemoval<'a> {
    match inspected {
        Ok(labels) if network_is_portman_managed(labels) => NetworkRemoval::Remove,
        Ok(_) => NetworkRemoval::Foreign,
        Err(err) if docker_not_found(err) => NetworkRemoval::Absent,
        Err(err) => NetworkRemoval::Unknown(err),
    }
}

fn network_is_portman_managed(labels: Option<&HashMap<String, String>>) -> bool {
    labels
        .and_then(|labels| labels.get(MANAGED_LABEL))
        .is_some_and(|value| value == MANAGED_LABEL_VALUE)
}

fn setup_container_is_portman_managed(labels: Option<&HashMap<String, String>>) -> bool {
    carries_portman_role(labels, SETUP_ROLE_LABEL_VALUE)
}

/// Whether a container is portman's and has this role. The role keeps the
/// setup container and the DNS forwarder from being taken for each other.
fn carries_portman_role(labels: Option<&HashMap<String, String>>, role: &str) -> bool {
    let Some(labels) = labels else {
        return false;
    };
    labels
        .get(MANAGED_LABEL)
        .is_some_and(|value| value == MANAGED_LABEL_VALUE)
        && labels.get(ROLE_LABEL).is_some_and(|value| value == role)
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
/// portman's to repair. Outside our dedicated subnet, routes pointing at any
/// other live utun belong to something else and are left alone.
static OWN_UTUNS: std::sync::Mutex<BTreeSet<String>> = std::sync::Mutex::new(BTreeSet::new());

/// Held while a `route` command of a bridge runs.
static ROUTE_IN_FLIGHT: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn route_in_flight() -> std::sync::MutexGuard<'static, ()> {
    ROUTE_IN_FLIGHT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The let-go of a utun runs in the `drop` of [`OwnHalf`], also while a pump
/// unwinds from a panic, and a second panic there would abort the daemon. So
/// a poisoned lock is read as it is.
fn own_utuns() -> std::sync::MutexGuard<'static, BTreeSet<String>> {
    OWN_UTUNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn remember_own_utun(name: &str) {
    own_utuns().insert(name.to_string());
}

/// Ends the claim on `name` and waits for the `route` command that runs at
/// this moment. No later command runs for the name. With one bridge in the
/// process the wait is for that one command: at most [`ROUTE_LIMIT`], and
/// [`KILL_GRACE`] after it for a command that was killed. The daemon has one
/// bridge, because it ends a bridge before it starts the next, and two
/// bridges cannot hold the one listen port. The lock is one for the process
/// and it is not fair. So among several bridges the commands of the others
/// can go ahead of the let-go, and the wait is then for more than one.
fn forget_own_utun(name: &str) {
    own_utuns().remove(name);
    drop(route_in_flight());
}

fn is_own_utun(name: &str) -> bool {
    own_utuns().contains(name)
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
            let args = ["-n", "delete", "-net", cidr, "-interface", &self.iface];
            if let Err(err) = route_result("delete", sbin_route(&args)) {
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
    /// Our dedicated subnet, or a utun that is dead or one of ours — repair it.
    Repair,
    /// Another subnet via a live utun somebody else owns. Not ours to touch.
    Foreign,
}

fn classify_existing_route(cidr: &str, existing_iface: &str, wanted_iface: &str) -> ExistingRoute {
    if existing_iface == wanted_iface {
        ExistingRoute::Correct
    } else if cidr == PORTMAN_SUBNET_CIDR
        || !interface_is_alive(existing_iface)
        || is_own_utun(existing_iface)
    {
        ExistingRoute::Repair
    } else {
        ExistingRoute::Foreign
    }
}

/// How a `route` command of a bridge ends without its work done.
#[derive(Debug)]
enum RouteError {
    /// The bridge let go of the utun, so the command did not run.
    LetGo,
    Failed(anyhow::Error),
}

impl From<RouteError> for anyhow::Error {
    fn from(err: RouteError) -> Self {
        match err {
            RouteError::LetGo => anyhow!("the bridge let go of its utun"),
            RouteError::Failed(err) => err,
        }
    }
}

/// Runs `command` while the bridge holds `utun`. `route` takes an interface
/// by its name, and the kernel gives the name of a utun that is gone to the
/// next one, which can belong to a VPN.
fn while_bridge_holds<T>(utun: &str, command: impl FnOnce() -> T) -> Result<T, RouteError> {
    let _in_flight = route_in_flight();
    if !is_own_utun(utun) {
        return Err(RouteError::LetGo);
    }
    Ok(command())
}

fn ensure_route_command(route: &RunRoute, cmd: &RouteCommand) -> Result<(), RouteError> {
    if cmd.verb == "add" {
        if let Some(existing) = exact_route_utun_interface(route, &cmd.iface, &cmd.cidr)? {
            match classify_existing_route(&cmd.cidr, &existing, &cmd.iface) {
                ExistingRoute::Correct => return Ok(()),
                // The dedicated subnet belongs to this runtime even if its
                // previous utun name has since been recycled for a VPN.
                ExistingRoute::Repair => {
                    info!(
                        cidr = %cmd.cidr,
                        stale_iface = %existing,
                        iface = %cmd.iface,
                        alive = interface_is_alive(&existing),
                        "repointing stale netbridge route"
                    );
                    match run_route(route, "change", &cmd.cidr, &cmd.iface) {
                        // `change` can fail if the route vanished under us;
                        // fall through and let `add` handle it.
                        Err(RouteError::Failed(_)) => {}
                        ended => return ended,
                    }
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

    match run_route(route, cmd.verb, &cmd.cidr, &cmd.iface) {
        Err(RouteError::Failed(err)) if cmd.verb == "add" => {
            match exact_route_utun_interface(route, &cmd.iface, &cmd.cidr)? {
                Some(existing)
                    if classify_existing_route(&cmd.cidr, &existing, &cmd.iface)
                        != ExistingRoute::Repair =>
                {
                    debug!(cidr = %cmd.cidr, %existing, "route already present; leaving it in place");
                    Ok(())
                }
                _ => Err(RouteError::Failed(err)),
            }
        }
        ended => ended,
    }
}

type RunRoute<'a> = dyn Fn(&[&str]) -> std::io::Result<Output> + 'a;

fn sbin_route(args: &[&str]) -> std::io::Result<Output> {
    output_within(StdCommand::new("/sbin/route").args(args), ROUTE_LIMIT)
}

/// Runs `command` to its end and returns what it printed. A command that
/// runs longer than `limit` is killed and gets [`KILL_GRACE`] to go away.
/// One that is still there after the grace is left behind with a warning,
/// because a wait without a bound would hold a bridge that ends. So a
/// bridge that has let go of its utun promises this much: no `route`
/// command runs for the utun, provided that a killed `route` goes away
/// within the grace.
///
/// This is for a program like `route`, which starts no program of its own
/// and prints less than a pipe holds. A program that leaves a child with
/// its output open holds this call past the limit. A program that prints
/// more than a pipe holds waits for a reader, which comes only after the
/// program has ended, so it is killed at the limit.
fn output_within(command: &mut StdCommand, limit: Duration) -> std::io::Result<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if exits_within(&mut child, limit)? {
        return child.wait_with_output();
    }
    child.kill()?;
    if !exits_within(&mut child, KILL_GRACE)? {
        warn!(
            pid = child.id(),
            "a command that was killed at its limit is still there; it is left behind"
        );
    }
    let timed_out = format!("the command did not end within {limit:?}");
    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, timed_out))
}

fn exits_within(child: &mut std::process::Child, limit: Duration) -> std::io::Result<bool> {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Runs one `route` command for `iface`, while the bridge holds it.
fn run_route(route: &RunRoute, verb: &str, cidr: &str, iface: &str) -> Result<(), RouteError> {
    let args = ["-n", verb, "-net", cidr, "-interface", iface];
    let output = while_bridge_holds(iface, || route(&args))?;
    route_result(verb, output).map_err(RouteError::Failed)
}

fn route_result(verb: &str, output: std::io::Result<Output>) -> Result<()> {
    let output = output.with_context(|| format!("spawning /sbin/route {verb}"))?;
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

/// Asks while the bridge holds `iface`. `-net` with the prefix length makes
/// the kernel look for that prefix alone. A route to a wider prefix that
/// covers the subnet, such as the one of a VPN, does not answer for it. The
/// kernel answers with the default route when the subnet has no route of
/// its own, and the `destination:` line tells the two answers apart.
fn exact_route_utun_interface(
    route: &RunRoute,
    iface: &str,
    cidr: &str,
) -> Result<Option<String>, RouteError> {
    let Some(addr) = cidr.split('/').next() else {
        return Ok(None);
    };
    let Ok(output) = while_bridge_holds(iface, || route(&["-n", "get", "-net", cidr]))? else {
        return Ok(None);
    };
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(route_get_exact_utun_interface(&stdout, addr))
}

fn route_get_exact_utun_interface(stdout: &str, addr: &str) -> Option<String> {
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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::*;

    #[test]
    fn tunnel_descriptor_is_not_inherited_by_a_child() {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        use std::os::unix::net::UnixStream;

        let (socket, _peer) = UnixStream::pair().unwrap();
        let fd = socket.as_raw_fd();
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
        prevent_child_inheritance(fd).unwrap();

        let output = StdCommand::new("/bin/sh")
            .args(["-c", &format!("test ! -e /dev/fd/{fd}")])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child inherited the tunnel descriptor"
        );
    }

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
            route_get_exact_utun_interface(routed, "172.18.0.0"),
            Some("utun0".to_string())
        );
        assert_eq!(
            route_get_exact_utun_interface(default_route, "172.19.0.0"),
            None
        );
        assert_eq!(
            route_get_exact_utun_interface(utun_default, "172.19.0.0"),
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

        assert_eq!(route_get_exact_utun_interface(routed, "172.18.0.0"), None);
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
        let env = setup_container_env(&host, HOST_WG_LISTEN_PORT);

        assert!(env.iter().any(|value| value.starts_with("HOST_PUBKEY=")));
        assert!(env.iter().any(|value| value == "PEER_CIDR=192.168.99.2/25"));
        assert!(!env.iter().any(|value| value.starts_with("PEER_PRIVKEY=")));
    }

    #[test]
    fn the_cleanup_removes_the_network_only_when_it_carries_portmans_label() {
        let ours = HashMap::from([(MANAGED_LABEL.to_string(), MANAGED_LABEL_VALUE.to_string())]);
        let other_value = HashMap::from([(MANAGED_LABEL.to_string(), "0".to_string())]);
        let other_label =
            HashMap::from([("com.docker.compose.network".to_string(), "1".to_string())]);

        assert!(matches!(
            network_removal(Ok(Some(&ours))),
            NetworkRemoval::Remove
        ));
        for foreign in [None, Some(&other_value), Some(&other_label)] {
            assert!(
                matches!(network_removal(Ok(foreign)), NetworkRemoval::Foreign),
                "{foreign:?}"
            );
        }
        assert!(matches!(
            network_removal(Err(&server_err(404, "network portman not found"))),
            NetworkRemoval::Absent
        ));
        assert!(matches!(
            network_removal(Err(&server_err(500, "boom"))),
            NetworkRemoval::Unknown(_)
        ));
    }

    #[tokio::test]
    async fn the_listen_port_has_one_holder_at_a_time() {
        let first = ListenPort::claim(0).await.unwrap();
        let port = first.0.local_addr().unwrap().port();

        let second = ListenPort::claim(port).await;

        assert_eq!(
            second.err().map(|err| err.kind()),
            Some(std::io::ErrorKind::AddrInUse)
        );
    }

    #[test]
    fn a_host_key_is_new_once_and_a_retry_with_it_is_not() {
        let (first, second) = (Keypair::generate(), Keypair::generate());

        assert!(is_new_host_key(&first.public_base64()));
        assert!(!is_new_host_key(&first.public_base64()));
        assert!(!is_new_host_key(&first.public_base64()));
        assert!(is_new_host_key(&second.public_base64()));
        assert!(!is_new_host_key(&second.public_base64()));
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
            classify_existing_route(PORTMAN_SUBNET_CIDR, "utun9", "utun9"),
            ExistingRoute::Correct
        );
    }

    #[test]
    fn a_route_via_a_destroyed_interface_is_repaired() {
        // Nothing can be reached through an interface that doesn't exist, so
        // repairing it can't disrupt anyone — this is the case that kept the
        // bridge silently broken.
        assert_eq!(
            classify_existing_route("172.18.0.0/16", "utun-does-not-exist", "utun9"),
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
            "no-utun",
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
            classify_existing_route("172.18.0.0/16", &name, "utun9"),
            ExistingRoute::Repair
        );
        // After shutdown forgets it, the kernel may recycle the name for a
        // VPN (chipmk's bridge, someone else's tunnel) — a live foreign
        // interface must never be repointed. This assertion is the one home
        // of that guarantee: a separate test using the same loopback name
        // would race the claimed window above.
        forget_own_utun(&name);
        assert_eq!(
            classify_existing_route("172.18.0.0/16", &name, "utun9"),
            ExistingRoute::Foreign
        );
        assert_eq!(
            classify_existing_route(PORTMAN_SUBNET_CIDR, &name, "utun9"),
            ExistingRoute::Repair,
            "Portman's dedicated subnet must recover even when its old interface is reused"
        );
    }

    fn tlds(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    const DNSMASQ_BASE: [&str; 7] = [
        "--keep-in-foreground",
        "--no-hosts",
        "--listen-address=192.168.99.129",
        "--bind-interfaces",
        "--strict-order",
        "--cache-size=0",
        "--log-facility=-",
    ];
    const TO_THE_VM: &str = "--server=/host.docker.internal/#";

    #[test]
    fn the_forwarder_asks_portman_first_and_the_vm_second_for_each_managed_tld() {
        let test = [
            "--server=/test/192.168.99.1",
            "--server=/test/@vm-resolver@",
        ];
        let acme = [
            "--server=/acme/192.168.99.1",
            "--server=/acme/@vm-resolver@",
        ];
        let internal = [
            "--server=/internal/192.168.99.1",
            "--server=/internal/@vm-resolver@",
        ];
        // managed TLDs → the server lines, in the order dnsmasq gets them
        let table = [
            (vec![], vec![]),
            (vec!["test"], test.to_vec()),
            (vec!["test", "acme"], [acme, test].concat()),
            (vec!["internal"], internal.to_vec()),
            (vec!["localhost", "test"], test.to_vec()),
            (vec!["host.docker.internal", "test"], test.to_vec()),
        ];
        for (managed, server_lines) in table {
            let want = [
                vec!["dns"],
                DNSMASQ_BASE.to_vec(),
                server_lines,
                vec![TO_THE_VM],
            ]
            .concat();
            assert_eq!(dns_forwarder_args(&tlds(&managed)), want, "{managed:?}");
        }
    }

    /// Runs the entrypoint of the setup image with a `dnsmasq` that prints
    /// its arguments, one on each line, and a VM that has `resolv_conf`.
    fn run_dns_mode(args: &[String], resolv_conf: &str) -> std::process::Output {
        let prints_its_arguments = "#!/bin/sh\nprintf '%s\\n' \"$@\"\n";
        run_dns_mode_with(prints_its_arguments, args, resolv_conf).1
    }

    /// Runs the entrypoint in its `dns` mode with `dnsmasq` as the program
    /// of that name. Returns the process id of the entrypoint and what it
    /// printed.
    fn run_dns_mode_with(
        dnsmasq: &str,
        args: &[String],
        resolv_conf: &str,
    ) -> (u32, std::process::Output) {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Stdio;

        static RUNS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let run = RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("portman-dns-mode-{}-{run}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("dnsmasq");
        std::fs::write(&program, dnsmasq).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(dir.join("resolv.conf"), resolv_conf).unwrap();

        let entrypoint = StdCommand::new("sh")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/setup-image/entrypoint.sh"
            ))
            .args(args)
            .env(
                "PATH",
                format!("{}:{}", dir.display(), std::env::var("PATH").unwrap()),
            )
            .env("RESOLV_CONF", dir.join("resolv.conf"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = entrypoint.id();
        let output = entrypoint.wait_with_output().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        (pid, output)
    }

    #[test]
    fn the_dns_mode_runs_dnsmasq_as_the_process_that_the_engine_started() {
        let prints_its_process_id = "#!/bin/sh\necho $$\n";
        let args = dns_forwarder_args(&tlds(&["test"]));

        let (entrypoint, output) =
            run_dns_mode_with(prints_its_process_id, &args, "nameserver 192.168.5.2\n");

        assert!(output.status.success(), "{output:?}");
        let dnsmasq = String::from_utf8_lossy(&output.stdout);
        assert_eq!(dnsmasq.trim(), entrypoint.to_string());
    }

    #[test]
    fn the_entrypoint_gives_dnsmasq_each_nameserver_of_the_vm_in_place_of_the_token() {
        let resolv_conf =
            "# the VM\nsearch demo.test\nnameserver 192.168.5.2\nnameserver 192.168.5.3\n";

        let output = run_dns_mode(&dns_forwarder_args(&tlds(&["test"])), resolv_conf);

        assert!(output.status.success(), "{output:?}");
        let ran_with: Vec<&str> = std::str::from_utf8(&output.stdout)
            .unwrap()
            .lines()
            .collect();
        let want = [
            DNSMASQ_BASE.to_vec(),
            vec![
                "--server=/test/192.168.99.1",
                "--server=/test/192.168.5.2",
                "--server=/test/192.168.5.3",
                TO_THE_VM,
            ],
        ]
        .concat();
        assert_eq!(ran_with, want);
    }

    #[test]
    fn the_entrypoint_fails_and_says_why_when_the_vm_names_no_nameserver() {
        let output = run_dns_mode(&dns_forwarder_args(&tlds(&["test"])), "search demo.test\n");

        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert_eq!(output.stdout, b"", "dnsmasq ran");
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(said.contains("names no nameserver"), "{said}");
    }

    #[test]
    fn the_dns_mode_fails_and_says_why_when_no_dnsmasq_argument_follows() {
        let output = run_dns_mode(&["dns".to_string()], "nameserver 192.168.5.2\n");

        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert_eq!(output.stdout, b"", "dnsmasq ran");
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(said.contains("needs dnsmasq arguments"), "{said}");
    }

    fn forwarder(
        labels: &[(&str, &str)],
        cmd: &[&str],
        state: ForwarderState,
    ) -> ForwarderSnapshot {
        ForwarderSnapshot {
            id: "dddd2222".to_string(),
            labels: labels
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            cmd: cmd.iter().map(|arg| arg.to_string()).collect(),
            state,
        }
    }

    #[test]
    fn a_container_that_the_engine_restarts_is_not_taken_for_one_that_runs() {
        use ForwarderState::{Restarting, Running, Stopped};
        // (State.Running, State.Restarting) of an inspect → the state
        let table = [
            (Some(true), Some(false), Running),
            (Some(true), None, Running),
            (Some(true), Some(true), Restarting),
            (Some(false), Some(true), Restarting),
            (Some(false), Some(false), Stopped),
            (None, None, Stopped),
        ];
        for (running, restarting, want) in table {
            let state = ContainerState {
                running,
                restarting,
                ..Default::default()
            };
            assert_eq!(
                forwarder_state(Some(state)),
                want,
                "running={running:?} restarting={restarting:?}"
            );
        }
        assert_eq!(forwarder_state(None), Stopped);
    }

    #[test]
    fn the_forwarder_is_replaced_only_when_it_differs_from_what_it_should_run() {
        const OURS: [(&str, &str); 3] = [
            (MANAGED_LABEL, MANAGED_LABEL_VALUE),
            (ROLE_LABEL, DNS_ROLE_LABEL_VALUE),
            (DNS_FROM_IMAGE_LABEL, "sha256:aaaa"),
        ];
        let from_an_older_image = [OURS[0], OURS[1], (DNS_FROM_IMAGE_LABEL, "sha256:0000")];
        let setup_container = [OURS[0], (ROLE_LABEL, SETUP_ROLE_LABEL_VALUE), OURS[2]];
        let wanted = ["dns", "--server=/test/192.168.99.1"];
        use ForwarderState::{Restarting as restarting, Running as up, Stopped as stopped};
        use ForwarderStep::{Create, Foreign, Keep, LeaveRestarting, Replace};
        // the container the engine holds → the step
        let table = [
            (None, Create),
            (Some(forwarder(&OURS, &wanted, up)), Keep),
            (Some(forwarder(&OURS, &wanted, stopped)), Replace),
            (Some(forwarder(&OURS, &wanted, restarting)), LeaveRestarting),
            (Some(forwarder(&OURS, &["dns"], restarting)), Replace),
            (
                Some(forwarder(&from_an_older_image, &wanted, restarting)),
                Replace,
            ),
            (Some(forwarder(&[], &wanted, restarting)), Foreign),
            (Some(forwarder(&OURS, &["dns"], up)), Replace),
            (Some(forwarder(&from_an_older_image, &wanted, up)), Replace),
            (Some(forwarder(&OURS[..2], &wanted, up)), Replace),
            (Some(forwarder(&[], &wanted, up)), Foreign),
            (Some(forwarder(&OURS[1..], &wanted, up)), Foreign),
            (Some(forwarder(&setup_container, &wanted, up)), Foreign),
            (
                Some(forwarder(&setup_container, &["dns"], stopped)),
                Foreign,
            ),
        ];
        let wanted: Vec<String> = wanted.iter().map(|arg| arg.to_string()).collect();
        for (found, want) in table {
            assert_eq!(
                forwarder_step(found.as_ref(), "sha256:aaaa", &wanted),
                want,
                "{found:?}"
            );
        }
    }

    #[test]
    fn the_forwarder_and_the_setup_container_are_not_taken_for_each_other() {
        let with_role = |role: &str| {
            HashMap::from([
                (MANAGED_LABEL.to_string(), MANAGED_LABEL_VALUE.to_string()),
                (ROLE_LABEL.to_string(), role.to_string()),
            ])
        };
        let (setup, dns) = (with_role("netbridge-setup"), with_role("dns-forwarder"));

        assert!(setup_container_is_portman_managed(Some(&setup)));
        assert!(!setup_container_is_portman_managed(Some(&dns)));
        assert!(carries_portman_role(Some(&dns), DNS_ROLE_LABEL_VALUE));
        assert!(!carries_portman_role(Some(&setup), DNS_ROLE_LABEL_VALUE));
        assert!(!carries_portman_role(None, DNS_ROLE_LABEL_VALUE));
    }

    #[test]
    fn only_a_setup_image_with_the_dns_label_can_run_the_forwarder() {
        let labelled =
            |value: &str| HashMap::from([(DNS_IMAGE_LABEL.to_string(), value.to_string())]);

        assert!(image_has_dns_mode(Some(&labelled("1"))));
        assert!(!image_has_dns_mode(Some(&labelled("0"))));
        assert!(!image_has_dns_mode(Some(&HashMap::new())));
        assert!(!image_has_dns_mode(None));
    }

    type Shared<T> = Arc<std::sync::Mutex<T>>;

    /// A Docker engine inside the test, on a loopback port. It answers an
    /// inspect with what it holds at the path and with 404 otherwise, drops
    /// what a delete names, and takes any other request as done.
    struct FakeEngine {
        docker: Docker,
        holds: Shared<HashMap<String, String>>,
        /// The method and path of each request that is not an inspect, and
        /// its body.
        requests: Shared<Vec<(String, String)>>,
        refusals: Shared<HashMap<String, Refusal>>,
        /// While true, the engine takes each connection and answers
        /// nothing on it, as a VM does that froze with its socket open.
        frozen: Shared<bool>,
    }

    type Refusal = (&'static str, &'static str);

    /// How the engine answers the removal of a network that a running
    /// container is attached to.
    const IN_USE: Refusal = (
        "403 Forbidden",
        "error while removing network: network portman has active endpoints",
    );
    const ENGINE_FAILED: Refusal = ("500 Internal Server Error", "the engine is shutting down");

    const IMAGE_INSPECT: &str = "/images/portman-netbridge/setup:local/json";
    const IMAGE_WITH_DNS_MODE: &str = r#"{
        "Id": "sha256:aaaa",
        "Config": {"Labels": {"dev.portman.dns-forwarder": "1"}}
    }"#;
    const NETWORK_INSPECT: &str = "/networks/portman";
    const OWN_NETWORK: &str = r#"{"Labels": {"dev.portman.managed": "1"}}"#;
    const SETUP_INSPECT: &str = "/containers/portman-netbridge-setup/json";
    const OWN_SETUP_CONTAINER: &str = r#"{
        "Config": {"Labels": {"dev.portman.managed": "1", "dev.portman.role": "netbridge-setup"}},
        "State": {"Running": true}
    }"#;
    const FORWARDER_INSPECT: &str = "/containers/portman-netbridge-dns/json";

    impl FakeEngine {
        /// An engine that holds the `portman` network and a setup image
        /// with the `dns` mode.
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let holds = Shared::<HashMap<String, String>>::default();
            let requests = Shared::<Vec<(String, String)>>::default();
            let refusals = Shared::<HashMap<String, Refusal>>::default();
            let frozen = Shared::<bool>::default();
            let (held, asked, refused) = (holds.clone(), requests.clone(), refusals.clone());
            let silent = frozen.clone();
            tokio::spawn(async move {
                let mut unanswered = Vec::new();
                while let Ok((stream, _)) = listener.accept().await {
                    if *silent.lock().unwrap() {
                        unanswered.push(stream);
                        continue;
                    }
                    let (held, asked, refused) = (held.clone(), asked.clone(), refused.clone());
                    tokio::spawn(Self::answer(stream, held, asked, refused));
                }
            });
            let engine = Self {
                docker: Docker::connect_with_http(&address, 5, bollard::API_DEFAULT_VERSION)
                    .unwrap(),
                holds,
                requests,
                refusals,
                frozen,
            };
            engine.hold(IMAGE_INSPECT, IMAGE_WITH_DNS_MODE);
            engine.hold(NETWORK_INSPECT, OWN_NETWORK);
            engine
        }

        fn hold(&self, path: &str, json: &str) {
            self.holds.lock().unwrap().insert(path.into(), json.into());
        }

        fn refuse_delete(&self, path: &str, refusal: Refusal) {
            self.refusals.lock().unwrap().insert(path.into(), refusal);
        }

        fn freeze(&self) {
            *self.frozen.lock().unwrap() = true;
        }

        fn requests(&self) -> Vec<(String, String)> {
            self.requests.lock().unwrap().clone()
        }

        fn asked_for(&self) -> Vec<String> {
            let requests = self.requests();
            requests.into_iter().map(|(asked, _)| asked).collect()
        }

        /// A bridge on this engine, as far as the engine is concerned: it
        /// holds a listen port and has no tunnel.
        async fn bridge(&self) -> Runtime {
            Runtime {
                utun_name: "no-utun".to_string(),
                setup_container_id: "aaaa1111".to_string(),
                docker: self.docker.clone(),
                listen_port: ListenPort::claim(0).await.unwrap(),
                tasks: Vec::new(),
            }
        }

        async fn bridge_with_pumps(&self) -> Runtime {
            let mut bridge = self.bridge().await;
            let udp = &bridge.listen_port.0;
            let (host, vm) = (Keypair::generate(), Keypair::generate());
            let peer = Arc::new(Mutex::new(Peer::new(&host, vm.public(), None)));
            let endpoint = Arc::new(Mutex::new(None));
            bridge.tasks = vec![
                spawn_rx(
                    udp.clone(),
                    peer.clone(),
                    endpoint.clone(),
                    &bridge.utun_name,
                    tokio::io::sink(),
                ),
                spawn_timer(udp.clone(), peer, endpoint),
            ];
            bridge
        }

        async fn answer(
            mut stream: tokio::net::TcpStream,
            holds: Shared<HashMap<String, String>>,
            requests: Shared<Vec<(String, String)>>,
            refusals: Shared<HashMap<String, Refusal>>,
        ) {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let Ok(byte) = stream.read_u8().await else {
                    return;
                };
                head.push(byte);
            }
            let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map_or(0, |length| length.trim().parse().unwrap());
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();

            let mut words = head.split(' ');
            let (method, url) = (words.next().unwrap(), words.next().unwrap());
            let path = url.split('?').next().unwrap();
            let path = path
                .strip_prefix("/v")
                .map_or(path, |versioned| &versioned[versioned.find('/').unwrap()..]);
            let (status, json) = match method {
                "get" => match holds.lock().unwrap().get(path) {
                    Some(json) => ("200 OK", json.clone()),
                    None => ("404 Not Found", r#"{"message":"no such thing"}"#.into()),
                },
                _ => {
                    let asked = format!("{} {path}", method.to_ascii_uppercase());
                    let body = String::from_utf8(body).unwrap();
                    requests.lock().unwrap().push((asked, body));
                    let refusal = refusals.lock().unwrap().get(path).copied();
                    match (method, path, refusal) {
                        ("delete", _, Some((status, message))) => {
                            (status, format!(r#"{{"message":"{message}"}}"#))
                        }
                        ("delete", _, None) => {
                            let mut holds = holds.lock().unwrap();
                            holds.remove(&format!("{path}/json"));
                            holds.remove(path);
                            ("204 No Content", String::new())
                        }
                        ("post", "/containers/create", _) => {
                            ("201 Created", r#"{"Id":"eeee3333","Warnings":[]}"#.into())
                        }
                        _ => ("204 No Content", String::new()),
                    }
                }
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{json}",
                json.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    }

    /// The inspect of a forwarder container of portman's, from the image
    /// that the fake engine holds.
    fn held_forwarder(cmd: &[String], state: &str) -> String {
        let cmd: Vec<String> = cmd.iter().map(|arg| format!("\"{arg}\"")).collect();
        format!(
            r#"{{
                "Id": "dddd2222",
                "Config": {{
                    "Cmd": [{}],
                    "Labels": {{
                        "dev.portman.managed": "1",
                        "dev.portman.role": "dns-forwarder",
                        "dev.portman.setup-image": "sha256:aaaa"
                    }}
                }},
                "State": {state}
            }}"#,
            cmd.join(", ")
        )
    }

    const RUNNING: &str = r#"{"Running": true, "Restarting": false}"#;
    const RESTARTING: &str = r#"{"Running": true, "Restarting": true}"#;

    #[tokio::test]
    async fn the_forwarder_is_created_on_the_host_network_and_restarts_with_the_vm() {
        let engine = FakeEngine::start().await;
        let managed = tlds(&["test"]);

        let ensured = engine.bridge().await.ensure_dns_forwarder(&managed).await;

        assert_eq!(ensured.unwrap(), DnsForwarder::Started);
        let requests = engine.requests();
        let asked: Vec<&str> = requests.iter().map(|(asked, _)| asked.as_str()).collect();
        assert_eq!(
            asked,
            [
                "POST /containers/create",
                "POST /containers/portman-netbridge-dns/start"
            ]
        );
        let created = &requests[0].1;
        let cmd: Vec<String> = dns_forwarder_args(&managed)
            .iter()
            .map(|arg| format!("\"{arg}\""))
            .collect();
        for part in [
            r#""Image":"portman-netbridge/setup:local""#.to_string(),
            format!(r#""Cmd":[{}]"#, cmd.join(",")),
            r#""NetworkMode":"host""#.to_string(),
            r#""RestartPolicy":{"Name":"always"}"#.to_string(),
            r#""dev.portman.managed":"1""#.to_string(),
            r#""dev.portman.role":"dns-forwarder""#.to_string(),
            r#""dev.portman.setup-image":"sha256:aaaa""#.to_string(),
        ] {
            assert!(created.contains(&part), "{part}\n{created}");
        }
        assert!(!created.contains("CapAdd"), "{created}");
    }

    #[tokio::test]
    async fn the_forwarder_is_removed_before_its_replacement_and_only_when_one_is_needed() {
        let wanted = dns_forwarder_args(&tlds(&["test"]));
        let for_another_tld_set = dns_forwarder_args(&tlds(&["acme"]));
        let replaced = vec![
            "DELETE /containers/dddd2222",
            "POST /containers/create",
            "POST /containers/portman-netbridge-dns/start",
        ];
        // the forwarder that the engine holds → (how the ensure ends, the requests)
        let table = [
            (
                held_forwarder(&wanted, RUNNING),
                Some(DnsForwarder::InPlace),
                vec![],
            ),
            (
                held_forwarder(&wanted, RESTARTING),
                Some(DnsForwarder::Restarting),
                vec![],
            ),
            (
                held_forwarder(&for_another_tld_set, RUNNING),
                Some(DnsForwarder::Started),
                replaced.clone(),
            ),
            (
                held_forwarder(&for_another_tld_set, RESTARTING),
                Some(DnsForwarder::Started),
                replaced.clone(),
            ),
            (
                held_forwarder(&wanted, r#"{"Running": false}"#),
                Some(DnsForwarder::Started),
                replaced,
            ),
            (r#"{"Id": "dddd2222"}"#.to_string(), None, vec![]),
        ];
        for (forwarder, want, requests) in table {
            let engine = FakeEngine::start().await;
            engine.hold(FORWARDER_INSPECT, &forwarder);
            let bridge = engine.bridge().await;

            let ensured = bridge.ensure_dns_forwarder(&tlds(&["test"])).await;

            assert_eq!(ensured.ok(), want, "{forwarder}");
            assert_eq!(engine.asked_for(), requests, "{forwarder}");
        }
    }

    #[tokio::test]
    async fn a_forwarder_from_0_1_7_is_replaced_by_one_that_keeps_no_answer() {
        let from_0_1_7 = [
            "dns",
            "--keep-in-foreground",
            "--no-hosts",
            "--listen-address=192.168.99.129",
            "--bind-interfaces",
            "--strict-order",
            "--no-negcache",
            "--log-facility=-",
            "--server=/test/192.168.99.1",
            "--server=/test/@vm-resolver@",
            "--server=/host.docker.internal/#",
        ]
        .map(String::from);
        let engine = FakeEngine::start().await;
        engine.hold(FORWARDER_INSPECT, &held_forwarder(&from_0_1_7, RUNNING));

        let ensured = engine
            .bridge()
            .await
            .ensure_dns_forwarder(&tlds(&["test"]))
            .await;

        assert_eq!(ensured.unwrap(), DnsForwarder::Started);
        assert_eq!(
            engine.asked_for(),
            [
                "DELETE /containers/dddd2222",
                "POST /containers/create",
                "POST /containers/portman-netbridge-dns/start",
            ]
        );
        let created = &engine.requests()[1].1;
        assert!(created.contains(r#""--cache-size=0""#), "{created}");
    }

    #[tokio::test]
    async fn an_image_without_the_dns_label_gets_no_forwarder() {
        let engine = FakeEngine::start().await;
        engine.hold(IMAGE_INSPECT, r#"{"Id": "sha256:aaaa", "Config": {}}"#);

        let ensured = engine
            .bridge()
            .await
            .ensure_dns_forwarder(&tlds(&["test"]))
            .await;

        assert_eq!(ensured.unwrap(), DnsForwarder::ImageWithoutDnsMode);
        assert_eq!(engine.asked_for(), [] as [&str; 0]);
    }

    #[tokio::test]
    async fn only_a_shutdown_for_a_disable_removes_the_forwarder_and_then_the_network() {
        let wanted = dns_forwarder_args(&tlds(&["test"]));
        let setup_container = [
            "POST /containers/portman-netbridge-setup/stop",
            "DELETE /containers/portman-netbridge-setup",
        ];
        let forwarder_then_network = ["DELETE /containers/dddd2222", "DELETE /networks/portman"];
        // a disable → the requests of the shutdown
        let table = [
            (false, setup_container.to_vec()),
            (true, [setup_container, forwarder_then_network].concat()),
        ];
        for (disable, requests) in table {
            let engine = FakeEngine::start().await;
            engine.hold(SETUP_INSPECT, OWN_SETUP_CONTAINER);
            engine.hold(FORWARDER_INSPECT, &held_forwarder(&wanted, RUNNING));
            let bridge = engine.bridge().await;

            if disable {
                bridge.shutdown_and_remove_network().await;
            } else {
                bridge.shutdown().await;
            }

            assert_eq!(engine.asked_for(), requests, "disable={disable}");
        }
    }

    #[tokio::test]
    async fn a_bridge_that_is_dropped_still_holds_the_listen_port_when_the_drop_returns() {
        let engine = FakeEngine::start().await;
        let bridge = engine.bridge_with_pumps().await;
        let port = bridge.listen_port.0.local_addr().unwrap().port();

        drop(bridge);
        let next_start = ListenPort::claim(port).await;

        assert_eq!(
            next_start.err().map(|err| err.kind()),
            Some(std::io::ErrorKind::AddrInUse)
        );
    }

    #[tokio::test]
    async fn an_abandoned_bridge_has_freed_the_listen_port_and_asked_the_engine_nothing() {
        let engine = FakeEngine::start().await;
        engine.hold(SETUP_INSPECT, OWN_SETUP_CONTAINER);
        let bridge = engine.bridge_with_pumps().await;
        let socket = Arc::downgrade(&bridge.listen_port.0);

        bridge.abandon().await;

        assert_eq!(socket.strong_count(), 0, "the listen port has a holder");
        assert_eq!(engine.asked_for(), [] as [&str; 0]);
    }

    struct Device {
        utun: &'static str,
        claimed_at_close: Shared<Option<bool>>,
    }

    impl Drop for Device {
        fn drop(&mut self) {
            *self.claimed_at_close.lock().unwrap() = Some(is_own_utun(self.utun));
        }
    }

    #[tokio::test]
    async fn a_bridge_that_ends_lets_go_of_its_utun_before_it_closes_the_device() {
        let utun = "utun-of-a-bridge-that-ends";
        let claimed_at_close = Shared::<Option<bool>>::default();
        let device = Device {
            utun,
            claimed_at_close: claimed_at_close.clone(),
        };
        let engine = FakeEngine::start().await;
        let mut bridge = engine.bridge().await;
        bridge.utun_name = utun.to_string();
        remember_own_utun(utun);
        bridge.tasks = vec![tokio::spawn(async move {
            let _device = device;
            std::future::pending::<()>().await
        })];

        bridge.abandon().await;

        assert_eq!(
            *claimed_at_close.lock().unwrap(),
            Some(false),
            "the bridge claimed the utun when its device closed"
        );
    }

    #[derive(Clone, Copy)]
    enum Ends {
        Never,
        ByAnError,
        ByAPanic,
    }

    #[derive(Clone)]
    struct Seen {
        utun: &'static str,
        claimed_at_drop: Shared<Vec<bool>>,
        a_half_dropped: Arc<AtomicBool>,
    }

    impl Seen {
        fn claim(utun: &'static str) -> Self {
            remember_own_utun(utun);
            Self {
                utun,
                claimed_at_drop: Shared::default(),
                a_half_dropped: Arc::default(),
            }
        }

        fn half(&self, ends: Ends) -> Half {
            Half {
                ends,
                seen: self.clone(),
            }
        }

        fn claimed_at_drop(&self) -> Vec<bool> {
            self.claimed_at_drop.lock().unwrap().clone()
        }
    }

    struct Half {
        ends: Ends,
        seen: Seen,
    }

    impl Half {
        fn used(&self) -> std::task::Poll<std::io::Result<()>> {
            match self.ends {
                Ends::Never => std::task::Poll::Pending,
                Ends::ByAnError => {
                    std::task::Poll::Ready(Err(std::io::Error::other("the device is gone")))
                }
                Ends::ByAPanic => panic!("the pump panics"),
            }
        }
    }

    impl Drop for Half {
        fn drop(&mut self) {
            let claimed = is_own_utun(self.seen.utun);
            self.seen.claimed_at_drop.lock().unwrap().push(claimed);
            self.seen.a_half_dropped.store(true, Ordering::SeqCst);
        }
    }

    impl tokio::io::AsyncRead for Half {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.used()
        }
    }

    impl tokio::io::AsyncWrite for Half {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.used().map_ok(|()| bytes.len())
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct Passes {
        stop: Arc<AtomicBool>,
        ended: Arc<AtomicU64>,
        after_a_drop: Arc<AtomicU64>,
        thread: std::thread::JoinHandle<()>,
    }

    impl Passes {
        fn start(seen: &Seen) -> Self {
            let stop = Arc::<AtomicBool>::default();
            let ended = Arc::<AtomicU64>::default();
            let after_a_drop = Arc::<AtomicU64>::default();
            let ran = Arc::<AtomicU64>::default();
            let thread = {
                let (seen, stop, ended) = (seen.clone(), stop.clone(), ended.clone());
                let (after_a_drop, ran) = (after_a_drop.clone(), ran.clone());
                std::thread::spawn(move || {
                    let dropped = || seen.a_half_dropped.load(Ordering::SeqCst);
                    let route = |_: &[&str]| {
                        let started_late = dropped();
                        ran.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_micros(200));
                        if started_late || dropped() {
                            after_a_drop.fetch_add(1, Ordering::SeqCst);
                        }
                        route_ended(0, "")
                    };
                    let cmds = [RouteCommand::add("192.0.2.0/24", seen.utun)];
                    while !stop.load(Ordering::SeqCst) {
                        reconcile_routes(&route, &cmds);
                        ended.fetch_add(1, Ordering::SeqCst);
                        std::thread::yield_now();
                    }
                })
            };
            while ran.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
            Self {
                stop,
                ended,
                after_a_drop,
                thread,
            }
        }

        fn end(self) -> u64 {
            let ended = self.ended.load(Ordering::SeqCst);
            while self.ended.load(Ordering::SeqCst) < ended + 2 {
                std::thread::sleep(Duration::from_millis(1));
            }
            self.stop.store(true, Ordering::SeqCst);
            self.thread.join().unwrap();
            self.after_a_drop.load(Ordering::SeqCst)
        }
    }

    async fn tx_pump(half: Half) -> JoinHandle<()> {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (host, vm) = (Keypair::generate(), Keypair::generate());
        let peer = Arc::new(Mutex::new(Peer::new(&host, vm.public(), None)));
        spawn_tx(udp, peer, Arc::default(), half.seen.utun, half)
    }

    const ECHO_FROM_THE_VM: &[u8] = &[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 99, 2,
        192, 168, 99, 1, b'e', b'c', b'h', b'o', b'!', b'!', b'!', b'!',
    ];

    async fn rx_pump_that_gets_a_packet(half: Half) -> JoinHandle<()> {
        let (host, vm) = (Keypair::generate(), Keypair::generate());
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let to_host = udp.local_addr().unwrap();
        let peer = Arc::new(Mutex::new(Peer::new(&host, vm.public(), None)));
        let pump = spawn_rx(udp, peer, Arc::default(), half.seen.utun, half);

        let mut vm = Peer::new(&vm, host.public(), None);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut frame, mut answer) = ([0u8; 2048], [0u8; 2048]);
        let TunnResult::WriteToNetwork(initiation) = vm.encapsulate(ECHO_FROM_THE_VM, &mut frame)
        else {
            panic!("no handshake initiation");
        };
        socket.send_to(initiation, to_host).await.unwrap();
        let answered = tokio::time::timeout(Duration::from_secs(60), socket.recv_from(&mut answer));
        let (n, _) = answered
            .await
            .expect("the pump answers the handshake")
            .unwrap();
        if let TunnResult::WriteToNetwork(keepalive) = vm.decapsulate(&answer[..n], &mut frame) {
            socket.send_to(keepalive, to_host).await.unwrap();
        }
        let TunnResult::WriteToNetwork(data) = vm.encapsulate(ECHO_FROM_THE_VM, &mut frame) else {
            panic!("no data frame");
        };
        socket.send_to(data, to_host).await.unwrap();
        pump
    }

    async fn ended(pump: JoinHandle<()>) -> Result<(), tokio::task::JoinError> {
        tokio::time::timeout(Duration::from_secs(60), pump)
            .await
            .expect("the pump ends by itself")
    }

    #[tokio::test]
    async fn a_pump_that_fails_lets_go_of_the_utun_before_its_half_of_the_device_drops() {
        let seen = Seen::claim("utun-of-a-pump-that-fails");
        let passes = Passes::start(&seen);

        let pump = tx_pump(seen.half(Ends::ByAnError)).await;
        assert!(ended(pump).await.is_ok());

        assert_eq!(passes.end(), 0, "route commands after the half dropped");
        assert_eq!(seen.claimed_at_drop(), [false]);
    }

    #[tokio::test]
    async fn a_pump_that_panics_lets_go_of_the_utun_before_its_half_of_the_device_drops() {
        let tx = Seen::claim("utun-of-a-tx-pump-that-panics");
        let passes = Passes::start(&tx);
        let pump = tx_pump(tx.half(Ends::ByAPanic)).await;
        assert!(ended(pump).await.unwrap_err().is_panic());
        assert_eq!(passes.end(), 0, "route commands after the tx half dropped");
        assert_eq!(tx.claimed_at_drop(), [false]);

        let rx = Seen::claim("utun-of-an-rx-pump-that-panics");
        let passes = Passes::start(&rx);
        let pump = rx_pump_that_gets_a_packet(rx.half(Ends::ByAPanic)).await;
        assert!(ended(pump).await.unwrap_err().is_panic());
        assert_eq!(passes.end(), 0, "route commands after the rx half dropped");
        assert_eq!(rx.claimed_at_drop(), [false]);
    }

    #[tokio::test]
    async fn when_both_pumps_end_the_bridge_has_let_go_of_the_utun_before_the_device_closes() {
        let seen = Seen::claim("utun-of-two-pumps-that-end");
        let passes = Passes::start(&seen);

        let tx = tx_pump(seen.half(Ends::ByAnError)).await;
        let rx = rx_pump_that_gets_a_packet(seen.half(Ends::ByAPanic)).await;
        assert!(ended(tx).await.is_ok());
        assert!(ended(rx).await.unwrap_err().is_panic());

        assert_eq!(passes.end(), 0, "route commands after a half dropped");
        assert_eq!(seen.claimed_at_drop(), [false, false]);
    }

    /// At its end the daemon drops its tokio runtime, and the runtime drops
    /// the task that holds the bridge and the pump tasks in an order of its
    /// own. The order follows the ids of the tasks, which count up across
    /// the process and fall into four lists. So the test puts 0 to 7 tasks
    /// between the pump and the holder of the bridge.
    #[test]
    fn a_tokio_runtime_that_shuts_down_drops_no_half_of_a_device_under_the_claim_on_its_utun() {
        for tasks_between in 0..8 {
            let utun = format!("utun-at-a-shutdown-{tasks_between}");
            let utun: &'static str = Box::leak(utun.into_boxed_str());
            let seen = Seen::claim(utun);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let engine = FakeEngine::start().await;
                let mut bridge = engine.bridge().await;
                bridge.utun_name = utun.to_string();
                bridge.tasks = vec![tx_pump(seen.half(Ends::Never)).await];
                for _ in 0..tasks_between {
                    tokio::spawn(std::future::pending::<()>());
                }
                let (holds, held) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    let _bridge = bridge;
                    let _ = holds.send(());
                    std::future::pending::<()>().await
                });
                held.await.unwrap();
                assert!(
                    is_own_utun(utun),
                    "the bridge let go of the utun under a pump that runs"
                );
            });

            drop(runtime);

            assert_eq!(
                seen.claimed_at_drop(),
                [false],
                "tasks_between={tasks_between}"
            );
        }
    }

    #[test]
    fn a_pump_that_ends_lets_go_of_the_utun_through_a_poisoned_lock() {
        let utun = "utun-under-a-poisoned-lock";
        let poisons = std::thread::spawn(|| {
            let _held = OWN_UTUNS.lock();
            panic!("a panic under the lock of the utun names");
        });
        assert!(poisons.join().is_err());
        assert!(OWN_UTUNS.is_poisoned());

        remember_own_utun(utun);
        assert!(is_own_utun(utun));
        drop(OwnHalf {
            utun: utun.to_string(),
            half: (),
        });
        assert!(!is_own_utun(utun));

        OWN_UTUNS.clear_poison();
    }

    #[tokio::test]
    async fn the_route_reconciler_ends_with_the_pass_that_finds_the_utun_let_go() {
        static RAN: AtomicU64 = AtomicU64::new(0);
        let route = |_: &[&str]| {
            RAN.fetch_add(1, Ordering::SeqCst);
            route_ended(0, "")
        };
        let engine = FakeEngine::start().await;
        let reconciler = |utun: &str| {
            let docker = engine.docker.clone();
            spawn_route_reconciler(docker, NetbridgeMode::OptIn, utun.to_string(), route)
        };

        let let_go = reconciler("utun-let-go-before-the-reconciler");
        tokio::time::timeout(Duration::from_secs(30), let_go)
            .await
            .expect("the reconciler ends")
            .unwrap();
        assert_eq!(RAN.load(Ordering::SeqCst), 0);

        let utun = "utun-held-under-the-reconciler";
        remember_own_utun(utun);
        let held = reconciler(utun);
        while RAN.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!held.is_finished(), "the reconciler ended under its bridge");
        forget_own_utun(utun);
        held.abort();
    }

    #[tokio::test]
    async fn a_route_pass_that_panics_does_not_end_the_reconciler_of_a_bridge_that_holds_its_utun()
    {
        static COMMANDS: AtomicU64 = AtomicU64::new(0);
        let route = |_: &[&str]| {
            if COMMANDS.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("the first route pass panics");
            }
            route_ended(0, "")
        };
        let utun = "utun-of-a-route-pass-that-panics";
        remember_own_utun(utun);
        let docker = FakeEngine::start().await.docker.clone();
        let reconciler =
            spawn_route_reconciler(docker, NetbridgeMode::OptIn, utun.to_string(), route);

        let began = std::time::Instant::now();
        while COMMANDS.load(Ordering::SeqCst) < 2 {
            assert!(
                !reconciler.is_finished(),
                "the reconciler ended with the pass that panicked"
            );
            assert!(
                began.elapsed() < ROUTE_RECONCILE_PERIOD + Duration::from_secs(60),
                "no pass followed the one that panicked"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        forget_own_utun(utun);
        reconciler.abort();
    }

    #[derive(Clone, Default)]
    struct Logged(Shared<Vec<u8>>);

    /// While one subscriber exists, tracing takes a callsite's interest
    /// from the thread that reaches it first, and that can be a test that
    /// has no subscriber. With a second subscriber it asks each of them.
    struct Capture {
        _on_this_thread: tracing::subscriber::DefaultGuard,
        _second_subscriber: tracing::Dispatch,
    }

    impl std::io::Write for Logged {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Logged {
        fn capture() -> (Self, Capture) {
            let logged = Self::default();
            let writer = logged.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            let capture = Capture {
                _on_this_thread: tracing::subscriber::set_default(subscriber),
                _second_subscriber: tracing::Dispatch::new(tracing::subscriber::NoSubscriber::new()),
            };
            (logged, capture)
        }

        fn take_lines(&self) -> Vec<String> {
            let bytes = std::mem::take(&mut *self.0.lock().unwrap());
            let text = String::from_utf8(bytes).unwrap();
            text.lines().map(String::from).collect()
        }

        fn take_warnings(&self) -> Vec<String> {
            let mut lines = self.take_lines();
            lines.retain(|line| line.contains(" WARN "));
            lines
        }
    }

    fn route_ended(code: i32, stderr: &str) -> std::io::Result<std::process::Output> {
        use std::os::unix::process::ExitStatusExt;

        Ok(std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: stderr.into(),
        })
    }

    fn no_such_interface(_: &[&str]) -> std::io::Result<std::process::Output> {
        route_ended(1, "route: bad address: utun-of-no-bridge")
    }

    #[test]
    fn a_route_that_fails_is_a_warning_only_while_the_bridge_holds_its_utun() {
        let utun = "utun-of-no-bridge";
        let pass = [RouteCommand::add("192.0.2.0/24", utun)];
        let (logged, _capture) = Logged::capture();

        remember_own_utun(utun);
        reconcile_routes(&no_such_interface, &pass);
        let warnings = logged.take_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("route reconcile failed"),
            "{warnings:?}"
        );
        assert!(warnings[0].contains("bad address"), "{warnings:?}");

        forget_own_utun(utun);
        reconcile_routes(&no_such_interface, &pass);
        assert_eq!(logged.take_warnings(), [] as [&str; 0]);
    }

    #[test]
    fn a_route_pass_runs_no_command_for_a_utun_that_its_bridge_let_go_of() {
        let utun = "utun-let-go-before-the-pass";
        let pass = [
            RouteCommand::add("192.0.2.0/24", utun),
            RouteCommand::add("198.51.100.0/24", utun),
        ];
        let ran = std::cell::RefCell::new(Vec::new());
        let route = |args: &[&str]| {
            ran.borrow_mut().push(args.join(" "));
            route_ended(0, "")
        };
        let (logged, _capture) = Logged::capture();

        remember_own_utun(utun);
        reconcile_routes(&route, &pass);
        assert_eq!(logged.take_lines(), [] as [&str; 0]);
        assert_eq!(
            ran.take(),
            [
                "-n get -net 192.0.2.0/24",
                "-n add -net 192.0.2.0/24 -interface utun-let-go-before-the-pass",
                "-n get -net 198.51.100.0/24",
                "-n add -net 198.51.100.0/24 -interface utun-let-go-before-the-pass",
            ]
        );

        forget_own_utun(utun);
        reconcile_routes(&route, &pass);
        assert_eq!(ran.take(), [] as [&str; 0]);
        let said = logged.take_lines();
        assert_eq!(said.len(), 1, "{said:?}");
        let ended = "netbridge route pass ended with its bridge iface=utun-let-go-before-the-pass";
        assert!(
            said[0].contains(" INFO ") && said[0].ends_with(ended),
            "{said:?}"
        );
    }

    fn route_printed(stdout: &str) -> std::io::Result<std::process::Output> {
        let mut printed = route_ended(0, "")?;
        printed.stdout = stdout.into();
        Ok(printed)
    }

    #[test]
    fn a_route_pass_adds_a_route_only_to_a_subnet_that_has_none_of_its_own() {
        let utun = "utun-with-a-route-to-a-slash-20";
        let its_own_route = format!(
            "\
   route to: 192.168.16.0
destination: 192.168.16.0
       mask: 255.255.240.0
  interface: {utun}
"
        );
        let default_route = "\
   route to: 192.168.32.0
destination: default
       mask: default
    gateway: 192.0.2.1
  interface: en0
";
        let ran = std::cell::RefCell::new(Vec::new());
        let table_with_the_slash_20_route_and_a_default_route = |args: &[&str]| {
            ran.borrow_mut().push(args.join(" "));
            match args {
                ["-n", "get", "-net", "192.168.16.0/20"] => route_printed(&its_own_route),
                ["-n", "get", ..] => route_printed(default_route),
                _ => route_ended(0, ""),
            }
        };
        let pass = [
            RouteCommand::add("192.168.16.0/20", utun),
            RouteCommand::add("192.168.32.0/20", utun),
        ];

        remember_own_utun(utun);
        reconcile_routes(&table_with_the_slash_20_route_and_a_default_route, &pass);
        forget_own_utun(utun);

        assert_eq!(
            ran.take(),
            [
                "-n get -net 192.168.16.0/20",
                "-n get -net 192.168.32.0/20",
                "-n add -net 192.168.32.0/20 -interface utun-with-a-route-to-a-slash-20",
            ]
        );
    }

    #[test]
    fn a_bridge_lets_go_of_its_utun_only_after_the_route_command_that_runs_for_it() {
        use std::sync::mpsc;

        let utun = "utun-let-go-during-a-command";
        remember_own_utun(utun);
        let (started, command_runs) = mpsc::channel();
        let (may_end, ends) = mpsc::channel::<()>();
        let pass = std::thread::spawn(move || {
            let route = |_: &[&str]| {
                let _ = started.send(());
                let _ = ends.recv();
                route_ended(0, "")
            };
            reconcile_routes(&route, &[RouteCommand::add("192.0.2.0/24", utun)]);
        });
        command_runs.recv().unwrap();

        let (let_go, lets_go) = mpsc::channel();
        let bridge = std::thread::spawn(move || {
            forget_own_utun(utun);
            let_go.send(()).unwrap();
        });

        let claim_ended = (0..3000).any(|_| {
            std::thread::sleep(Duration::from_millis(10));
            !is_own_utun(utun)
        });
        assert!(
            claim_ended,
            "the claim stands while the command runs, so the pass could go on after it"
        );
        assert!(
            lets_go.recv_timeout(Duration::from_millis(200)).is_err(),
            "the bridge let go of its utun while a route command for it ran"
        );
        drop(may_end);
        lets_go
            .recv_timeout(Duration::from_secs(30))
            .expect("the bridge lets go once the command has ended");
        pass.join().unwrap();
        bridge.join().unwrap();
    }

    #[test]
    fn a_command_that_outlives_its_limit_is_ended_and_one_that_does_not_gives_its_output() {
        let prints = "echo out; echo err >&2; exit 3";
        let within = Duration::from_secs(60);
        let ended = output_within(StdCommand::new("sh").args(["-c", prints]), within).unwrap();
        assert_eq!(ended.status.code(), Some(3));
        assert_eq!(
            (ended.stdout, ended.stderr),
            (b"out\n".into(), b"err\n".into())
        );

        let pid_file = std::env::temp_dir().join(format!("portman-hangs-{}", std::process::id()));
        let hangs = format!("echo $$ > '{}'; exec sleep 60", pid_file.display());
        let mut limit = Duration::from_millis(100);
        let pid = loop {
            let _ = std::fs::remove_file(&pid_file);
            let began = std::time::Instant::now();
            let hung = output_within(StdCommand::new("sh").args(["-c", &hangs]), limit);
            assert_eq!(hung.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
            let took = began.elapsed();
            assert!(took < limit + Duration::from_secs(10), "it took {took:?}");
            match std::fs::read_to_string(&pid_file) {
                Ok(pid) if pid.ends_with('\n') => break pid.trim().to_string(),
                _killed_before_it_wrote_its_id => limit *= 2,
            }
        };
        std::fs::remove_file(&pid_file).unwrap();
        assert!(
            !exists(&pid),
            "the program that hangs (pid {pid}) is there after its limit"
        );
    }

    /// A process that has ended exists until its parent has waited for it.
    fn exists(pid: &str) -> bool {
        let signal_none = StdCommand::new("kill").args(["-0", pid]).output().unwrap();
        signal_none.status.success()
    }

    #[test]
    fn a_route_program_that_hangs_holds_a_bridge_that_ends_no_longer_than_its_limit() {
        let utun = "utun-of-a-route-that-hangs";
        remember_own_utun(utun);
        let (started, command_runs) = std::sync::mpsc::channel();
        let pass = std::thread::spawn(move || {
            let hangs = |_: &[&str]| {
                let _ = started.send(());
                output_within(
                    StdCommand::new("sleep").arg("60"),
                    Duration::from_millis(200),
                )
            };
            let cmds: Vec<RouteCommand> = (0..40)
                .map(|n| RouteCommand::add(format!("10.{n}.0.0/16"), utun))
                .collect();
            reconcile_routes(&hangs, &cmds);
        });
        command_runs.recv().unwrap();

        let began = std::time::Instant::now();
        forget_own_utun(utun);
        let waited = began.elapsed();
        pass.join().unwrap();

        assert!(
            waited < Duration::from_secs(5),
            "the bridge waited {waited:?} for a route program that hangs"
        );
    }

    #[tokio::test]
    async fn a_shutdown_for_a_disable_asks_for_a_network_in_use_once_and_warns_once() {
        let engine = FakeEngine::start().await;
        engine.hold(SETUP_INSPECT, OWN_SETUP_CONTAINER);
        engine.refuse_delete(NETWORK_INSPECT, IN_USE);
        let bridge = engine.bridge().await;
        let (logged, _capture) = Logged::capture();

        let cleanup = bridge.shutdown_and_remove_network().await;

        assert_eq!(cleanup, CleanupEnd::Complete);
        let mut asked = engine.asked_for();
        asked.retain(|asked| asked.ends_with(NETWORK_INSPECT));
        assert_eq!(asked, ["DELETE /networks/portman"]);
        let warnings = logged.take_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("has active endpoints"), "{warnings:?}");
    }

    #[tokio::test]
    async fn a_shutdown_for_a_disable_says_whether_a_later_cleanup_has_anything_left_to_try() {
        let forwarder = dns_forwarder_args(&tlds(&["test"]));
        // the removal that fails, and how → how the shutdown ends
        let cases = [
            (None, CleanupEnd::Complete),
            (Some((NETWORK_INSPECT, IN_USE)), CleanupEnd::Complete),
            (Some((NETWORK_INSPECT, ENGINE_FAILED)), CleanupEnd::Failed),
            (
                Some(("/containers/dddd2222", ENGINE_FAILED)),
                CleanupEnd::Failed,
            ),
        ];
        for (fails, want) in cases {
            let engine = FakeEngine::start().await;
            engine.hold(SETUP_INSPECT, OWN_SETUP_CONTAINER);
            engine.hold(FORWARDER_INSPECT, &held_forwarder(&forwarder, RUNNING));
            if let Some((path, refusal)) = fails {
                engine.refuse_delete(path, refusal);
            }

            let cleanup = engine.bridge().await.shutdown_and_remove_network().await;

            assert_eq!(cleanup, want, "{fails:?}");
        }
    }

    #[tokio::test]
    async fn a_cleanup_on_a_taken_port_stays_owed_and_asks_the_engine_nothing() {
        let engine = FakeEngine::start().await;
        engine.hold(SETUP_INSPECT, OWN_SETUP_CONTAINER);
        let another_daemons_bridge = ListenPort::claim(0).await.unwrap();
        let taken = another_daemons_bridge.0.local_addr().unwrap().port();
        let everything = Leftovers::SetupContainerAndNetwork;

        let cleanup = remove_leftovers(&engine.docker, taken, everything).await;
        assert_eq!(cleanup, Cleanup::Owed);
        let claim = try_remove_leftovers(&engine.docker, taken, everything).await;
        assert_eq!(claim.unwrap_err().kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(engine.asked_for(), [] as [&str; 0]);

        let cleanup = remove_leftovers(&engine.docker, 0, everything).await;
        assert_eq!(cleanup, Cleanup::Complete);
    }

    #[test]
    fn a_cleanup_that_did_not_get_the_port_blames_a_holder_only_for_an_address_in_use() {
        let (logged, _capture) = Logged::capture();

        let taken = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        say_why_leftovers_stay(HOST_WG_LISTEN_PORT, &taken);

        let lines = logged.take_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("the listen port is taken"), "{lines:?}");

        let out_of_descriptors = std::io::Error::from_raw_os_error(libc::EMFILE);
        say_why_leftovers_stay(HOST_WG_LISTEN_PORT, &out_of_descriptors);

        let warnings = logged.take_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("Too many open files"), "{warnings:?}");
        assert!(!warnings[0].contains("is taken"), "{warnings:?}");
    }

    /// How long the daemon's client waits for the head of an answer.
    const DAEMONS_CLIENT_LIMIT: Duration = Duration::from_secs(120);

    #[derive(Debug, Clone, Copy)]
    enum Step {
        Stop,
        StopForADisable,
        EnsureTheForwarder,
    }

    #[tokio::test(start_paused = true)]
    async fn each_step_of_a_bridge_on_an_engine_that_froze_ends_when_its_budget_is_spent() {
        for step in [Step::Stop, Step::StopForADisable, Step::EnsureTheForwarder] {
            let engine = FakeEngine::start().await;
            let mut bridge = engine.bridge().await;
            bridge.docker = bridge.docker.clone().with_timeout(DAEMONS_CLIENT_LIMIT);
            engine.freeze();

            let asked = tokio::time::Instant::now();
            match step {
                Step::Stop => bridge.shutdown().await,
                Step::StopForADisable => {
                    let cleanup = bridge.shutdown_and_remove_network().await;
                    assert_eq!(cleanup, CleanupEnd::NoAnswer);
                }
                Step::EnsureTheForwarder => {
                    let ensured = bridge.ensure_dns_forwarder(&tlds(&["test"])).await;
                    let said = format!("{:#}", ensured.unwrap_err());
                    let no_answer = "the container engine gave no answer within 20 s";
                    assert!(said.contains(no_answer), "{said}");
                }
            }

            assert_eq!(asked.elapsed(), ENGINE_STEP_BUDGET, "{step:?}");
        }
    }

    #[test]
    fn the_readme_states_the_budgets_that_a_bridge_gives_the_engine() {
        let readme = include_str!("../../../README.md");
        let (step, start) = (ENGINE_STEP_BUDGET.as_secs(), ENGINE_START_BUDGET.as_secs());
        let stated = [
            format!("waits {step} s for the engine in each step of the bridge, and {start} s in a start"),
            format!("`the container engine gave no answer within {step} s`"),
        ];
        for sentence in stated {
            assert!(readme.contains(&sentence), "the README lacks: {sentence}");
        }
    }

    #[test]
    fn the_setup_image_carries_the_label_that_says_it_has_the_dns_mode() {
        let dockerfile = include_str!("../setup-image/Dockerfile");
        let label = format!("LABEL {DNS_IMAGE_LABEL}=\"{DNS_IMAGE_LABEL_VALUE}\"");

        assert!(dockerfile.lines().any(|line| line == label), "{label}");
    }

    #[test]
    fn the_setup_image_ships_a_dnsmasq_that_falls_through_for_a_query_with_edns_options() {
        let dockerfile = include_str!("../setup-image/Dockerfile");
        let base = dockerfile
            .lines()
            .find_map(|line| line.strip_prefix("FROM alpine:"))
            .expect("the setup image is built on alpine");
        let mut numbers = base.split('.').map(|number| number.parse::<u32>().unwrap());
        let release = (numbers.next().unwrap(), numbers.next().unwrap());

        assert!(
            release >= (3, 22),
            "alpine {base} ships dnsmasq 2.90 or older, which answers REFUSED to a query \
             with EDNS options and does not ask the VM's resolver"
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
