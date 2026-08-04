//! Phase B.2b — end-to-end host ↔ VM WireGuard tunnel via bollard.
//!
//! Spawns the setup container (B.2a) inside colima's VM, wires it to
//! the host-side `Peer` from B.1c, runs the bidirectional packet
//! pump, and tears everything down cleanly on exit.
//!
//! ```sh
//! cargo build -p portman-netbridge --example tunnel_e2e
//! sudo -E target/debug/examples/tunnel_e2e
//! # in another terminal:
//! ping 192.168.99.2
//! ```
//!
//! Expected: first ping might time out (handshake in flight), next
//! pings complete with ~1-10ms round-trip — the full WireGuard path
//! via host utun → UDP → colima VM → chip0 → kernel → echo reply →
//! chip0 → UDP → host utun → ping process.
//!
//! The VM-side container drives the handshake via its
//! `persistent-keepalive = 25`, which also immediately fires a
//! handshake-init as soon as the WG interface comes up. Within ~1
//! second of the container starting, the host's UDP socket sees an
//! incoming frame from colima's VM, records the source address, and
//! the Peer state machine replies. Session-up usually < 100 ms from
//! that point.
//!
//! Requires root on the host (utun + route) and a running colima
//! with the `portman-netbridge/setup:local` image already built
//! (`docker build -t portman-netbridge/setup:local
//! crates/portman-netbridge/setup-image`).

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, RemoveContainerOptionsBuilder, StartContainerOptions,
};
use bollard::secret::{ContainerCreateBody, HostConfig};
use bollard::Docker;
use boringtun::noise::TunnResult;
use portman_core::paths::docker_socket_candidates;
use portman_netbridge::tunnel::{
    Keypair, Peer, HOST_TUNNEL_IP, HOST_WG_LISTEN_PORT, PORTMAN_SUBNET_CIDR, TUNNEL_MTU,
    VM_TUNNEL_IP,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tun::Device;

const SETUP_IMAGE: &str = "portman-netbridge/setup:local";
const SETUP_CONTAINER: &str = "portman-netbridge-setup";
const HOLD_SECS: u64 = 60;

#[tokio::main]
async fn main() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("must run as root (utun + route)"));
    }

    eprintln!("portman-netbridge — Phase B.2b end-to-end tunnel\n");

    // ── Keys ──────────────────────────────────────────────────────
    let host_kp = Keypair::generate();
    let vm_kp = Keypair::generate();
    eprintln!("host pubkey : {}", host_kp.public_base64());
    eprintln!("vm   pubkey : {}", vm_kp.public_base64());

    // ── Host utun + UDP ───────────────────────────────────────────
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
    eprintln!("✓ UDP bound   → 0.0.0.0:{HOST_WG_LISTEN_PORT}\n");

    // ── Docker connection + spawn VM-side peer ────────────────────
    let docker = connect_docker().context("connecting to docker")?;
    let _cleanup = remove_stale_setup(&docker).await;

    spawn_setup_container(&docker, &host_kp, &vm_kp).await?;
    eprintln!("✓ setup       → {SETUP_CONTAINER} spawned in colima VM\n");

    // Cleanup happens explicitly at the end of main (see below) —
    // using a Drop guard here would force us to spin a new tokio
    // runtime inside the drop path, which panics if main's runtime
    // is still active. Explicit is simpler and always works.

    // ── Peer state machine + shared VM endpoint cell ──────────────
    // The VM's outbound endpoint (as seen from the host) isn't known
    // until its first UDP packet arrives — colima NATs the container
    // and the source port is dynamic. We record it on first receive
    // and use it for all subsequent encapsulate-driven sends.
    let peer = Arc::new(Mutex::new(Peer::new(&host_kp, vm_kp.public(), Some(25))));
    let vm_endpoint: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let (mut dev_read, mut dev_write) = tokio::io::split(device);

    // ── UDP receive / decapsulate → utun write ────────────────────
    let peer_rx = peer.clone();
    let endpoint_rx = vm_endpoint.clone();
    let udp_rx = udp.clone();
    let rx_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut out = vec![0u8; (TUNNEL_MTU as usize) + 128];
        loop {
            match udp_rx.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    *endpoint_rx.lock().await = Some(src);
                    let datagram = buf[..n].to_vec();
                    // Loop decapsulate-with-empty until Done, per
                    // boringtun docs: on a WriteToNetwork response,
                    // we're supposed to re-call with an empty
                    // datagram to flush queued traffic.
                    let mut inbound: Option<Vec<u8>> = Some(datagram);
                    loop {
                        let input: &[u8] = match &inbound {
                            Some(v) => v.as_slice(),
                            None => &[],
                        };
                        let r = {
                            let mut p = peer_rx.lock().await;
                            p.decapsulate(input, &mut out)
                        };
                        match r {
                            TunnResult::WriteToNetwork(frame) => {
                                let bytes = frame.to_vec();
                                let kind = classify_wg_frame(&bytes);
                                let _ = udp_rx.send_to(&bytes, src).await;
                                eprintln!("WG out →  {kind:<16} {} bytes → {src}", bytes.len());
                                inbound = None; // empty-datagram recall
                            }
                            TunnResult::WriteToTunnelV4(pkt, _addr) => {
                                // Write plaintext IP packet into the
                                // utun so the kernel receives it.
                                // macOS utun expects a 4-byte protocol
                                // family prefix on writes (same frame
                                // shape it emits on reads): AF_INET =
                                // 2, big-endian. Without this the
                                // kernel drops the frame silently and
                                // ping times out even though the data
                                // arrived through WireGuard correctly.
                                let mut framed = Vec::with_capacity(pkt.len() + 4);
                                framed.extend_from_slice(&[0, 0, 0, 2]); // AF_INET
                                framed.extend_from_slice(pkt);
                                if let Err(err) = dev_write.write_all(&framed).await {
                                    eprintln!("utun write error: {err}");
                                }
                                log_ip_packet("utun ←", pkt);
                                break;
                            }
                            TunnResult::WriteToTunnelV6(_, _) => break,
                            TunnResult::Done => break,
                            TunnResult::Err(e) => {
                                eprintln!("decap error: {e:?}");
                                break;
                            }
                        }
                    }
                }
                Err(err) => {
                    eprintln!("udp recv error: {err}");
                    return;
                }
            }
        }
    });

    // ── utun read → encapsulate → UDP send ────────────────────────
    let peer_tx = peer.clone();
    let endpoint_tx = vm_endpoint.clone();
    let udp_tx = udp.clone();
    let tx_task = tokio::spawn(async move {
        let mut pkt = vec![0u8; (TUNNEL_MTU as usize) + 64];
        let mut out = vec![0u8; (TUNNEL_MTU as usize) + 128];
        loop {
            let n = match dev_read.read(&mut pkt).await {
                Ok(n) => n,
                Err(err) => {
                    eprintln!("utun read error: {err}");
                    return;
                }
            };
            let ip = strip_utun_prefix(&pkt[..n]);
            log_ip_packet("utun →", ip);

            let r = {
                let mut p = peer_tx.lock().await;
                p.encapsulate(ip, &mut out)
            };
            match r {
                TunnResult::WriteToNetwork(frame) => {
                    let Some(dest) = *endpoint_tx.lock().await else {
                        eprintln!("WG out ⨯  no VM endpoint yet; dropping frame");
                        continue;
                    };
                    let bytes = frame.to_vec();
                    let kind = classify_wg_frame(&bytes);
                    let _ = udp_tx.send_to(&bytes, dest).await;
                    eprintln!("WG out →  {kind:<16} {} bytes → {dest}", bytes.len());
                }
                TunnResult::Done => {}
                TunnResult::Err(e) => eprintln!("encap error: {e:?}"),
                _ => {}
            }
        }
    });

    // ── Periodic handshake-nudge: poke encapsulate with an empty
    //    slice every second so boringtun's handshake retries fire
    //    even before the user pings anything. 1s cadence is cheap
    //    and means the demo reaches session-up quickly after the
    //    VM spawns its peer.
    let peer_timer = peer.clone();
    let endpoint_timer = vm_endpoint.clone();
    let udp_timer = udp.clone();
    let timer_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.tick().await; // immediate-fire; consume
        let mut out = vec![0u8; 256];
        loop {
            tick.tick().await;
            let r = {
                let mut p = peer_timer.lock().await;
                p.encapsulate(&[], &mut out)
            };
            if let TunnResult::WriteToNetwork(frame) = r {
                if let Some(dest) = *endpoint_timer.lock().await {
                    let _ = udp_timer.send_to(frame, dest).await;
                } else {
                    // No VM endpoint yet — fine, the VM's own
                    // keepalive will reach us first.
                }
            }
        }
    });

    eprintln!("pumping for {HOLD_SECS}s — exercise with `ping {VM_TUNNEL_IP}`\n");

    tokio::time::sleep(Duration::from_secs(HOLD_SECS)).await;

    tx_task.abort();
    rx_task.abort();
    timer_task.abort();
    let _ = remove_setup_container(&docker).await;
    eprintln!("\n✓ shutdown complete");
    Ok(())
}

// ── Docker + container helpers ─────────────────────────────────────

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
    anyhow::bail!("no docker socket found — is colima running?")
}

async fn spawn_setup_container(docker: &Docker, host: &Keypair, vm: &Keypair) -> Result<()> {
    let env = vec![
        format!("HOST_PUBKEY={}", host.public_base64()),
        format!("HOST_ENDPOINT=host.docker.internal:{HOST_WG_LISTEN_PORT}"),
        format!("PEER_PRIVKEY={}", vm.secret_base64()),
        format!("PEER_CIDR={VM_TUNNEL_IP}/24"),
        format!("ALLOWED_IPS={PORTMAN_SUBNET_CIDR}"),
    ];

    // HostConfig equivalent of:
    //   --network host --cap-add NET_ADMIN --rm
    let host_config = HostConfig {
        network_mode: Some("host".to_string()),
        cap_add: Some(vec!["NET_ADMIN".to_string()]),
        auto_remove: Some(true),
        ..Default::default()
    };

    let body = ContainerCreateBody {
        image: Some(SETUP_IMAGE.to_string()),
        env: Some(env),
        host_config: Some(host_config),
        // Labels make this container trivially identifiable from
        // `docker ps` filters when a future cleanup sweeper needs
        // them. Phase C will lean on this.
        labels: Some(HashMap::from([
            ("dev.portman.managed".into(), "1".into()),
            ("dev.portman.role".into(), "netbridge-setup".into()),
        ])),
        ..Default::default()
    };

    let opts = CreateContainerOptionsBuilder::default()
        .name(SETUP_CONTAINER)
        .build();
    docker
        .create_container(Some(opts), body)
        .await
        .context("docker create_container")?;
    docker
        .start_container(SETUP_CONTAINER, None::<StartContainerOptions>)
        .await
        .context("docker start_container")?;
    Ok(())
}

async fn remove_setup_container(docker: &Docker) -> Result<()> {
    let opts = RemoveContainerOptionsBuilder::default().force(true).build();
    docker
        .remove_container(SETUP_CONTAINER, Some(opts))
        .await
        .context("docker remove_container")?;
    eprintln!("✓ setup container removed");
    Ok(())
}

async fn remove_stale_setup(docker: &Docker) -> Option<()> {
    // Best-effort: if a previous run left one lying around, clean up.
    let opts = RemoveContainerOptionsBuilder::default().force(true).build();
    let _ = docker.remove_container(SETUP_CONTAINER, Some(opts)).await;
    Some(())
}

// ── Packet utilities (mirrors of tunnel_pump / tunnel_encrypt) ─────

fn strip_utun_prefix(pkt: &[u8]) -> &[u8] {
    if pkt.len() > 4 && pkt[0] == 0 && pkt[1] == 0 && (pkt[3] == 2 || pkt[3] == 30) {
        &pkt[4..]
    } else {
        pkt
    }
}

fn log_ip_packet(tag: &str, ip: &[u8]) {
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

fn classify_wg_frame(buf: &[u8]) -> &'static str {
    match buf.first().copied() {
        Some(1) => "handshake-init",
        Some(2) => "handshake-resp",
        Some(3) => "cookie-reply",
        Some(4) => "data",
        Some(_) => "unknown",
        None => "empty",
    }
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
