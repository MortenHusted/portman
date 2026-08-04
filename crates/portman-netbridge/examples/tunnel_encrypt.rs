//! Phase B.1d — wire `Peer` into the packet pump and observe
//! handshake-init UDP frames emitted by boringtun.
//!
//! Same utun + UDP scaffolding as `tunnel_pump` (B.1b), now with the
//! `Peer` state machine (B.1c) fused in. Flow:
//!
//!   1. Allocate utun, install route, bind UDP socket.
//!   2. Generate a real host keypair + a dummy "VM" keypair whose
//!      private half we throw away (we never need to decrypt its
//!      reply because there is no reply). The `Peer` is initialized
//!      with the VM's public key so boringtun will try to hand-shake
//!      toward it.
//!   3. When the host kernel routes an ICMP packet to the utun, our
//!      pump reads it → `Peer::encapsulate` → first call returns a
//!      WriteToNetwork handshake-init frame. Log + send via UDP to
//!      127.0.0.1:51821 (an unused port; no one listens).
//!   4. No response ever arrives, so no session gets established and
//!      all subsequent encapsulations also return handshake-init.
//!      That's fine — this example proves the OUTBOUND path works.
//!      The real VM peer lands in B.2.
//!
//! Run (needs root):
//!
//! ```sh
//! cargo build -p portman-netbridge --example tunnel_encrypt
//! sudo -E target/debug/examples/tunnel_encrypt
//! # in another terminal:
//! ping 192.168.99.2
//! ```
//!
//! Expected output: each ping produces a "utun →" log AND a
//! "WG out →" log showing a ~148-byte handshake-init frame sent
//! toward the would-be peer.

#![allow(unsafe_code)]

use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use boringtun::noise::TunnResult;
use portman_netbridge::tunnel::{
    Keypair, Peer, HOST_TUNNEL_IP, HOST_WG_LISTEN_PORT, PORTMAN_SUBNET_CIDR, TUNNEL_MTU,
    VM_TUNNEL_IP,
};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tun::Device;

/// Pretend-VM UDP port. Nothing binds here — we send handshake-inits
/// into the void to prove the outbound path fires. Different from
/// [`HOST_WG_LISTEN_PORT`] so the kernel doesn't loop our own traffic.
const PRETEND_VM_UDP_PORT: u16 = 51821;

const TIMEOUT_SECS: u64 = 30;

#[tokio::main]
async fn main() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("must run as root (utun + route)"));
    }

    eprintln!("portman-netbridge — Phase B.1d Peer-wired packet pump");

    // Keypairs. host = us; "vm" pubkey is handed to Peer so boringtun
    // generates a proper handshake-init targeted at it. We never need
    // the vm secret because no one will ever reply — just a pubkey
    // target is enough for encapsulation to generate a real frame.
    let host_kp = Keypair::generate();
    let vm_kp = Keypair::generate();
    eprintln!("  host pubkey  : {}", host_kp.public_base64());
    eprintln!("  (pretend) vm : {}", vm_kp.public_base64());
    eprintln!("  host IP      : {HOST_TUNNEL_IP}");
    eprintln!("  peer IP      : {VM_TUNNEL_IP}");
    eprintln!("  subnet       : {PORTMAN_SUBNET_CIDR}");
    eprintln!("  UDP in       : 0.0.0.0:{HOST_WG_LISTEN_PORT}");
    eprintln!("  UDP out      : 127.0.0.1:{PRETEND_VM_UDP_PORT}  (nothing listens — by design)");
    eprintln!("  MTU          : {TUNNEL_MTU}\n");

    // utun + route.
    let mut config = tun::Configuration::default();
    config
        .address(HOST_TUNNEL_IP)
        .netmask((255, 255, 255, 0))
        .destination(VM_TUNNEL_IP)
        .mtu(i32::from(TUNNEL_MTU))
        .up();
    let device = tun::create_as_async(&config).context("creating async utun")?;
    let name = device.get_ref().name().context("reading utun name")?;
    eprintln!("✓ utun up        → {name}");
    run_route("add", PORTMAN_SUBNET_CIDR, &name)?;
    eprintln!("✓ route installed → {PORTMAN_SUBNET_CIDR} dev {name}");

    // UDP sockets. Inbound one would receive replies from a real VM
    // peer; in B.1d it just sits there. Outbound uses the same socket
    // (WireGuard convention: peers reply to the source address of the
    // last frame we sent, so listen + send share the fd).
    let udp = UdpSocket::bind(("0.0.0.0", HOST_WG_LISTEN_PORT))
        .await
        .with_context(|| format!("binding UDP 0.0.0.0:{HOST_WG_LISTEN_PORT}"))?;
    let udp = Arc::new(udp);
    eprintln!(
        "✓ UDP bound      → {}",
        udp.local_addr().map(|a| a.to_string()).unwrap_or_default()
    );

    // Peer instance. Shared between the utun-read task (encrypts) and
    // the UDP-read task (decrypts handshake responses if they ever
    // came). Mutex is fine — handshake frames are small and
    // infrequent; the MTU-bound data path won't hit this until B.2
    // gives us a counterparty to session with.
    let peer = Arc::new(Mutex::new(Peer::new(&host_kp, vm_kp.public(), Some(25))));

    eprintln!(
        "\npump running for {TIMEOUT_SECS}s — trigger handshake-init frames with:\n  \
         ping {VM_TUNNEL_IP}\n"
    );

    // Split the device so we can own read + write halves in separate
    // tasks without juggling a Mutex around the whole thing.
    let (mut dev_read, _dev_write) = tokio::io::split(device);

    let udp_for_utun = udp.clone();
    let peer_for_utun = peer.clone();
    let utun_task = tokio::spawn(async move {
        let mut pkt_buf = vec![0u8; (TUNNEL_MTU as usize) + 64];
        // Encapsulation adds ~32 bytes overhead; give boringtun headroom.
        let mut out_buf = vec![0u8; (TUNNEL_MTU as usize) + 128];
        loop {
            let n = match dev_read.read(&mut pkt_buf).await {
                Ok(n) => n,
                Err(err) => {
                    eprintln!("utun read error: {err}");
                    return;
                }
            };
            let pkt = strip_utun_prefix(&pkt_buf[..n]);
            log_ip_packet("utun →", pkt);

            let mut p = peer_for_utun.lock().await;
            match p.encapsulate(pkt, &mut out_buf) {
                TunnResult::WriteToNetwork(frame) => {
                    let len = frame.len();
                    let kind = classify_wg_frame(frame);
                    // Clone frame out of the guarded buffer so we can
                    // drop the Peer lock before the async send.
                    let bytes = frame.to_vec();
                    drop(p);
                    let dest = format!("127.0.0.1:{PRETEND_VM_UDP_PORT}");
                    match udp_for_utun.send_to(&bytes, &dest).await {
                        Ok(_) => eprintln!("WG out →  {kind}  {len} bytes → {dest}"),
                        Err(err) => eprintln!("WG send error: {err}"),
                    }
                }
                TunnResult::Done => {}
                TunnResult::Err(e) => eprintln!("encapsulate error: {e:?}"),
                other => eprintln!("unexpected encapsulate result: {other:?}"),
            }
        }
    });

    let udp_for_recv = udp.clone();
    let _peer_for_recv = peer.clone();
    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match udp_for_recv.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    eprintln!("WG in  ←  {src}  {n} bytes");
                    // B.1d doesn't have a counterparty; any arriving
                    // datagram is unexpected. Log + drop.
                }
                Err(err) => {
                    eprintln!("UDP recv error: {err}");
                    return;
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_secs(TIMEOUT_SECS)).await;
    utun_task.abort();
    udp_task.abort();
    eprintln!("\n✓ pump stopped   → utun {name} + UDP :{HOST_WG_LISTEN_PORT} closed");
    Ok(())
}

/// Strip macOS's optional 4-byte protocol-family prefix on utun
/// frames. See `tunnel_pump` for the same detection logic.
fn strip_utun_prefix(pkt: &[u8]) -> &[u8] {
    if pkt.len() > 4 && pkt[0] == 0 && pkt[1] == 0 && (pkt[3] == 2 || pkt[3] == 30) {
        &pkt[4..]
    } else {
        pkt
    }
}

fn log_ip_packet(tag: &str, ip: &[u8]) {
    if ip.len() < 20 {
        return;
    }
    if ip[0] >> 4 != 4 {
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

/// WireGuard frames carry their message type in the first byte of
/// the datagram (the other 3 bytes of the type are reserved / zero).
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
    let status = Command::new("/sbin/route")
        .args(["-n", verb, "-net", cidr, "-interface", iface])
        .status()
        .with_context(|| format!("spawning /sbin/route {verb}"))?;
    if !status.success() {
        return Err(anyhow!("/sbin/route {verb} exited with {status}"));
    }
    Ok(())
}
