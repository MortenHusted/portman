//! Phase B.3 — full stack: host tunnel + docker network + container.
//!
//! Builds on B.2b (host ↔ VM tunnel) by creating an actual docker
//! bridge network attached to the WireGuard side, spawning a test
//! container on it, and pinging the container's IP from the macOS
//! host through the tunnel.
//!
//! ```sh
//! # from repo root, with the setup image already built per B.2a:
//! cargo build -p portman-netbridge --example tunnel_docker
//! sudo -E target/debug/examples/tunnel_docker
//! ```
//!
//! Expected on a live machine: first ping to the test container
//! completes in ~50-150ms (handshake), subsequent pings <3ms. A
//! manual `docker ps --filter network=portman` in another terminal
//! will show the test container with an IP like 192.168.99.130 while
//! the example is running.
//!
//! Subnet layout (also documented in `src/tunnel.rs`):
//!
//! ```text
//! 192.168.99.0/24                (full "portman" address space)
//! ├── .0/25 (lower half)          WG tunnel endpoints
//! │   ├── .1   host utun (macOS)
//! │   ├── .2   chip0     (VM)
//! │   └── .3–.127   reserved/unused
//! └── .128/25 (upper half)        docker bridge subnet
//!     ├── .129  bridge gateway
//!     ├── .130–.253  container pool
//!     ├── .254  reserved host-facing IP (Phase E hook)
//!     └── .255  broadcast
//! ```
//!
//! Requires root (utun + route) and a running colima with the B.2a
//! `portman-netbridge/setup:local` image present.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, InspectContainerOptions, RemoveContainerOptionsBuilder,
    StartContainerOptions,
};
use bollard::secret::{ContainerCreateBody, HostConfig, Ipam, IpamConfig, NetworkCreateRequest};
use bollard::Docker;
use boringtun::noise::TunnResult;
use portman_core::paths::docker_socket_candidates;
use portman_netbridge::tunnel::{
    Keypair, Peer, CONTAINER_IP_POOL_START, DOCKER_BRIDGE_CIDR, DOCKER_BRIDGE_GATEWAY,
    HOST_TUNNEL_IP, HOST_WG_LISTEN_PORT, PORTMAN_SUBNET_CIDR, TUNNEL_MTU, VM_TUNNEL_IP,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tun::Device;

const SETUP_IMAGE: &str = "portman-netbridge/setup:local";
const SETUP_CONTAINER: &str = "portman-netbridge-setup";
const PORTMAN_NETWORK: &str = "portman";
const TEST_CONTAINER: &str = "portman-netbridge-test";
const TEST_IMAGE: &str = "alpine:latest";

#[tokio::main]
async fn main() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("must run as root (utun + route)"));
    }

    eprintln!("portman-netbridge — Phase B.3 full stack (tunnel + docker network)\n");

    let host_kp = Keypair::generate();
    let vm_kp = Keypair::generate();
    eprintln!("host pubkey : {}", host_kp.public_base64());
    eprintln!("vm   pubkey : {}", vm_kp.public_base64());

    // ── utun + host route covers BOTH halves of the /24 (endpoints
    //    AND the docker bridge subnet) so kernel routes container
    //    traffic into utun too.
    let mut cfg = tun::Configuration::default();
    cfg.address(HOST_TUNNEL_IP)
        .netmask((255, 255, 255, 0))
        .destination(VM_TUNNEL_IP)
        .mtu(i32::from(TUNNEL_MTU))
        .up();
    let device = tun::create_as_async(&cfg).context("creating utun")?;
    let utun_name = device.get_ref().name().context("utun name")?;
    eprintln!("✓ utun        → {utun_name}");

    run_route("add", PORTMAN_SUBNET_CIDR, &utun_name)?;
    eprintln!("✓ route       → {PORTMAN_SUBNET_CIDR} dev {utun_name}");

    let udp = Arc::new(
        UdpSocket::bind(("0.0.0.0", HOST_WG_LISTEN_PORT))
            .await
            .with_context(|| format!("binding 0.0.0.0:{HOST_WG_LISTEN_PORT}"))?,
    );
    eprintln!("✓ UDP bound   → 0.0.0.0:{HOST_WG_LISTEN_PORT}");

    let docker = connect_docker()?;

    // Stale cleanups so re-runs are idempotent.
    best_effort_remove_container(&docker, TEST_CONTAINER).await;
    best_effort_remove_container(&docker, SETUP_CONTAINER).await;
    best_effort_remove_network(&docker, PORTMAN_NETWORK).await;

    spawn_setup_container(&docker, &host_kp, &vm_kp).await?;
    eprintln!("✓ setup       → {SETUP_CONTAINER} in colima VM");

    create_portman_network(&docker).await?;
    eprintln!(
        "✓ network     → {PORTMAN_NETWORK} ({DOCKER_BRIDGE_CIDR}, gw {DOCKER_BRIDGE_GATEWAY})"
    );

    // Chipmk (`docker-mac-net-connect`) watches docker-network events
    // and automatically installs a host route `<bridge_subnet> → utun0`
    // on every new network — which is great for its own bridge but
    // *shadows* our /24 → utun<N> route for this specific subnet,
    // because a /25 beats a /24. Beat chipmk at its own specificity:
    // give colima a moment to react, delete whatever /25 chipmk put in,
    // then install our /25 via our utun. Last writer wins at equal
    // specificity.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = run_route_quiet("delete", DOCKER_BRIDGE_CIDR);
    run_route("add", DOCKER_BRIDGE_CIDR, &utun_name)?;
    eprintln!("✓ route       → {DOCKER_BRIDGE_CIDR} dev {utun_name} (overrides chipmk's)");

    spawn_test_container(&docker).await?;
    let test_ip = inspect_container_ip(&docker, TEST_CONTAINER).await?;
    eprintln!("✓ test ctnr   → {TEST_CONTAINER} at {test_ip}\n");

    // ── Packet pump (identical to B.2b) ───────────────────────────
    let peer = Arc::new(Mutex::new(Peer::new(&host_kp, vm_kp.public(), Some(25))));
    let vm_endpoint: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let (mut dev_read, mut dev_write) = tokio::io::split(device);

    let rx_task = {
        let peer = peer.clone();
        let endpoint = vm_endpoint.clone();
        let udp = udp.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut out = vec![0u8; (TUNNEL_MTU as usize) + 128];
            loop {
                let Ok((n, src)) = udp.recv_from(&mut buf).await else {
                    return;
                };
                *endpoint.lock().await = Some(src);
                let datagram = buf[..n].to_vec();
                let mut inbound: Option<Vec<u8>> = Some(datagram);
                loop {
                    let input: &[u8] = match &inbound {
                        Some(v) => v.as_slice(),
                        None => &[],
                    };
                    let r = {
                        let mut p = peer.lock().await;
                        p.decapsulate(input, &mut out)
                    };
                    match r {
                        TunnResult::WriteToNetwork(frame) => {
                            let _ = udp.send_to(frame, src).await;
                            inbound = None;
                        }
                        TunnResult::WriteToTunnelV4(pkt, _) => {
                            let mut framed = Vec::with_capacity(pkt.len() + 4);
                            framed.extend_from_slice(&[0, 0, 0, 2]); // AF_INET
                            framed.extend_from_slice(pkt);
                            let _ = dev_write.write_all(&framed).await;
                            log_ip("utun ←", pkt);
                            break;
                        }
                        _ => break,
                    }
                }
            }
        })
    };

    let tx_task = {
        let peer = peer.clone();
        let endpoint = vm_endpoint.clone();
        let udp = udp.clone();
        tokio::spawn(async move {
            let mut pkt = vec![0u8; (TUNNEL_MTU as usize) + 64];
            let mut out = vec![0u8; (TUNNEL_MTU as usize) + 128];
            loop {
                let Ok(n) = dev_read.read(&mut pkt).await else {
                    return;
                };
                let ip = strip_utun_prefix(&pkt[..n]);
                log_ip("utun →", ip);
                let r = {
                    let mut p = peer.lock().await;
                    p.encapsulate(ip, &mut out)
                };
                if let TunnResult::WriteToNetwork(frame) = r {
                    if let Some(dest) = *endpoint.lock().await {
                        let _ = udp.send_to(frame, dest).await;
                    }
                }
            }
        })
    };

    let timer_task = {
        let peer = peer.clone();
        let endpoint = vm_endpoint.clone();
        let udp = udp.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.tick().await;
            let mut out = vec![0u8; 256];
            loop {
                tick.tick().await;
                let r = {
                    let mut p = peer.lock().await;
                    p.encapsulate(&[], &mut out)
                };
                if let TunnResult::WriteToNetwork(frame) = r {
                    if let Some(dest) = *endpoint.lock().await {
                        let _ = udp.send_to(frame, dest).await;
                    }
                }
            }
        })
    };

    eprintln!(
        "tunnel running — exercise with:\n  \
         ping {test_ip}\n  \
         docker ps --filter network={PORTMAN_NETWORK}\n  \
         docker run --rm --network {PORTMAN_NETWORK} alpine sh -c 'ip addr; ping -c3 192.168.99.1'\n\n\
         Ctrl-C to shut down cleanly."
    );

    // Run until the user hits Ctrl-C (or the daemon sends SIGTERM).
    // tokio::signal catches both gracefully on macOS/Linux, letting us
    // tear down the docker bits before exiting so the next run starts
    // clean.
    let ctrl_c = tokio::signal::ctrl_c();
    let sigterm = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut s) = signal(SignalKind::terminate()) {
                s.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        _ = ctrl_c => eprintln!("\n↓ SIGINT — shutting down"),
        _ = sigterm => eprintln!("\n↓ SIGTERM — shutting down"),
    }

    tx_task.abort();
    rx_task.abort();
    timer_task.abort();

    eprintln!("\ncleaning up…");
    best_effort_remove_container(&docker, TEST_CONTAINER).await;
    best_effort_remove_container(&docker, SETUP_CONTAINER).await;
    best_effort_remove_network(&docker, PORTMAN_NETWORK).await;
    eprintln!("✓ full-stack teardown done");
    Ok(())
}

// ── Docker helpers ─────────────────────────────────────────────────

fn connect_docker() -> Result<Docker> {
    for path in docker_socket_candidates() {
        if path.exists() {
            if let Some(s) = path.to_str() {
                return Ok(Docker::connect_with_socket(
                    s,
                    120,
                    bollard::API_DEFAULT_VERSION,
                )?);
            }
        }
    }
    anyhow::bail!("no docker socket found")
}

async fn spawn_setup_container(docker: &Docker, host: &Keypair, vm: &Keypair) -> Result<()> {
    let env = vec![
        format!("HOST_PUBKEY={}", host.public_base64()),
        format!("HOST_ENDPOINT=host.docker.internal:{HOST_WG_LISTEN_PORT}"),
        format!("PEER_PRIVKEY={}", vm.secret_base64()),
        format!("PEER_CIDR={VM_TUNNEL_IP}/24"),
        format!("ALLOWED_IPS={PORTMAN_SUBNET_CIDR}"),
    ];
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
            ("dev.portman.managed".into(), "1".into()),
            ("dev.portman.role".into(), "netbridge-setup".into()),
        ])),
        ..Default::default()
    };
    let opts = CreateContainerOptionsBuilder::default()
        .name(SETUP_CONTAINER)
        .build();
    docker.create_container(Some(opts), body).await?;
    docker
        .start_container(SETUP_CONTAINER, None::<StartContainerOptions>)
        .await?;
    // Give chip0 a moment to come up + fire its first keepalive so the
    // tunnel's ready before we attach a test container.
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}

async fn create_portman_network(docker: &Docker) -> Result<()> {
    // Use the non-deprecated `NetworkCreateRequest` (OpenAPI-generated
    // model) rather than `bollard::network::CreateNetworkOptions`
    // (convenience wrapper that bollard 0.19 deprecated).
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
        // 1420 = WG MTU. Docker propagates to container NIC so TCP MSS
        // negotiates against the real tunnel capacity.
        options: Some(HashMap::from([(
            "com.docker.network.driver.mtu".to_string(),
            TUNNEL_MTU.to_string(),
        )])),
        labels: Some(HashMap::from([(
            "dev.portman.managed".to_string(),
            "1".to_string(),
        )])),
        ..Default::default()
    };
    docker.create_network(req).await?;
    Ok(())
}

async fn spawn_test_container(docker: &Docker) -> Result<()> {
    // Request a specific IP so the ping target is predictable.
    let endpoint = bollard::secret::EndpointSettings {
        ipam_config: Some(bollard::secret::EndpointIpamConfig {
            ipv4_address: Some(CONTAINER_IP_POOL_START.to_string()),
            ipv6_address: None,
            link_local_ips: None,
        }),
        ..Default::default()
    };
    let networking_config = bollard::secret::NetworkingConfig {
        endpoints_config: Some(HashMap::from([(PORTMAN_NETWORK.to_string(), endpoint)])),
    };

    let body = ContainerCreateBody {
        image: Some(TEST_IMAGE.to_string()),
        // `sleep` with a large timeout — container persists long
        // enough to be pinged many times, auto-exits if we crash.
        cmd: Some(vec!["sleep".to_string(), "120".to_string()]),
        labels: Some(HashMap::from([
            ("dev.portman.managed".into(), "1".into()),
            ("dev.portman.role".into(), "netbridge-test".into()),
        ])),
        networking_config: Some(networking_config),
        host_config: Some(HostConfig {
            auto_remove: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    let opts = CreateContainerOptionsBuilder::default()
        .name(TEST_CONTAINER)
        .build();
    docker.create_container(Some(opts), body).await?;
    docker
        .start_container(TEST_CONTAINER, None::<StartContainerOptions>)
        .await?;
    Ok(())
}

async fn inspect_container_ip(docker: &Docker, name: &str) -> Result<String> {
    let info = docker
        .inspect_container(name, None::<InspectContainerOptions>)
        .await?;
    info.network_settings
        .as_ref()
        .and_then(|s| s.networks.as_ref())
        .and_then(|n| n.get(PORTMAN_NETWORK))
        .and_then(|net| net.ip_address.clone())
        .ok_or_else(|| anyhow!("test container has no IP on {PORTMAN_NETWORK}"))
}

async fn best_effort_remove_container(docker: &Docker, name: &str) {
    let opts = RemoveContainerOptionsBuilder::default().force(true).build();
    let _ = docker.remove_container(name, Some(opts)).await;
}

async fn best_effort_remove_network(docker: &Docker, name: &str) {
    let _ = docker.remove_network(name).await;
}

// ── Packet parse + route helpers (same shape as earlier examples) ──

fn strip_utun_prefix(pkt: &[u8]) -> &[u8] {
    if pkt.len() > 4 && pkt[0] == 0 && pkt[1] == 0 && (pkt[3] == 2 || pkt[3] == 30) {
        &pkt[4..]
    } else {
        pkt
    }
}

fn log_ip(tag: &str, ip: &[u8]) {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return;
    }
    let proto = match ip[9] {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "?",
    };
    let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    eprintln!(
        "{tag}  {proto:<5}  {src:>15} → {dst:<15}  {} bytes",
        ip.len()
    );
}

fn run_route(verb: &str, cidr: &str, iface: &str) -> Result<()> {
    let status = StdCommand::new("/sbin/route")
        .args(["-n", verb, "-net", cidr, "-interface", iface])
        .status()?;
    if !status.success() {
        return Err(anyhow!("/sbin/route {verb} exited with {status}"));
    }
    Ok(())
}

/// Swallow errors + silence stderr — used when deleting a route that
/// might not exist yet (chipmk-override path; first run won't have
/// anything to delete, subsequent runs might).
fn run_route_quiet(verb: &str, cidr: &str) -> std::process::ExitStatus {
    StdCommand::new("/sbin/route")
        .args(["-n", verb, "-net", cidr])
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .ok()
        .unwrap_or_default()
}
