//! Phase B.1b — async packet pump over utun + UDP.
//!
//! Builds on B.1a (`tunnel_up`) by adding tokio read loops on both
//! halves of the tunnel:
//!
//!   - utun side (`AsyncDevice`): reads IP packets arriving at the
//!     tunnel from macOS's routing layer. We expect at least one
//!     packet per incoming ping because the kernel sends an IP packet
//!     to the tunnel once the route says to.
//!
//!   - UDP side (`tokio::net::UdpSocket` on 51820): reads any bytes
//!     WireGuard peers would send to our host endpoint. With no peer
//!     configured yet this socket will mostly be silent; the point is
//!     to prove the socket binds cleanly alongside the utun.
//!
//! Together, these two reads are the primitives B.1c will fuse via
//! `boringtun::noise::Tunn`: utun-bound packet → encapsulate → UDP
//! out; UDP-bound packet → decapsulate → utun out. This commit
//! validates each half in isolation.
//!
//! Requires root (utun + route). Run:
//!
//! ```sh
//! cargo build -p portman-netbridge --example tunnel_pump
//! sudo -E target/debug/examples/tunnel_pump
//! ```
//!
//! In another terminal:
//!
//! ```sh
//! ping 192.168.99.2       # should appear as ICMP packets on the utun
//! # and see the UDP socket ready on 51820:
//! lsof -nP -iUDP:51820
//! ```

#![allow(unsafe_code)]

use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use portman_netbridge::tunnel::{
    HOST_TUNNEL_IP, HOST_WG_LISTEN_PORT, PORTMAN_SUBNET_CIDR, TUNNEL_MTU, VM_TUNNEL_IP,
};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tun::Device;

const TIMEOUT_SECS: u64 = 30;

#[tokio::main]
async fn main() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!(
            "must run as root. Try:\n  \
             sudo -E target/debug/examples/tunnel_pump"
        ));
    }

    eprintln!("portman-netbridge — Phase B.1b async packet pump");
    eprintln!("  host IP      : {HOST_TUNNEL_IP}");
    eprintln!("  peer IP      : {VM_TUNNEL_IP}  (not reachable yet; B.1c wires WG)");
    eprintln!("  subnet       : {PORTMAN_SUBNET_CIDR}");
    eprintln!("  UDP endpoint : 0.0.0.0:{HOST_WG_LISTEN_PORT}");
    eprintln!("  MTU          : {TUNNEL_MTU}\n");

    // utun setup, same as B.1a.
    let mut config = tun::Configuration::default();
    config
        .address(HOST_TUNNEL_IP)
        .netmask((255, 255, 255, 0))
        .destination(VM_TUNNEL_IP)
        .mtu(i32::from(TUNNEL_MTU))
        .up();

    let device = tun::create_as_async(&config).context("creating async utun")?;
    // get_ref exposes the underlying sync Device for name lookup.
    let name = device.get_ref().name().context("reading utun name")?;
    eprintln!("✓ utun up        → {name}");

    run_route("add", PORTMAN_SUBNET_CIDR, &name)?;
    eprintln!("✓ route installed → {PORTMAN_SUBNET_CIDR} dev {name}");

    let udp = UdpSocket::bind(("0.0.0.0", HOST_WG_LISTEN_PORT))
        .await
        .with_context(|| format!("binding UDP 0.0.0.0:{HOST_WG_LISTEN_PORT}"))?;
    eprintln!(
        "✓ UDP bound      → {}",
        udp.local_addr().map(|a| a.to_string()).unwrap_or_default()
    );

    eprintln!(
        "\npump running for {TIMEOUT_SECS}s — exercise with:\n  \
         ping {VM_TUNNEL_IP}\n  \
         lsof -nP -iUDP:{HOST_WG_LISTEN_PORT}\n"
    );

    // Spawn the two read loops. They log whatever they see; no reply.
    let utun_task = tokio::spawn(pump_utun(device));
    let udp_task = tokio::spawn(pump_udp(udp));

    // Hold for TIMEOUT_SECS, then stop.
    tokio::time::sleep(Duration::from_secs(TIMEOUT_SECS)).await;

    // Abort the pumps. Dropping their handles closes the fd's which in
    // turn makes the kernel tear down the utun. On macOS an interface
    // route is removed *by the kernel* when the interface goes away, so
    // we don't call `route delete` — doing so races the kernel and
    // exits non-zero when the interface is already gone.
    utun_task.abort();
    udp_task.abort();

    eprintln!("\n✓ pump stopped   → utun {name} + UDP :{HOST_WG_LISTEN_PORT} closed");
    eprintln!("   (macOS removes the interface route automatically on utun teardown)");
    Ok(())
}

/// Read IP packets arriving at the utun (i.e. anything macOS routes to
/// this tunnel) and log a summary. Per-packet: first two nibbles tell
/// us IP version, destination IP, and ICMP vs TCP vs UDP lets us spot
/// pings quickly.
async fn pump_utun(mut device: tun::AsyncDevice) {
    let mut buf = vec![0u8; (TUNNEL_MTU as usize) + 64];
    loop {
        match device.read(&mut buf).await {
            Ok(n) => {
                log_packet("utun →", &buf[..n]);
            }
            Err(err) => {
                eprintln!("utun read error: {err}");
                return;
            }
        }
    }
}

/// Read any UDP datagrams arriving on the WireGuard port and log
/// source + first few bytes. In B.1b there's no peer, so this is
/// mostly silent unless you manually send something with `nc -u` etc.
async fn pump_udp(udp: UdpSocket) {
    let mut buf = vec![0u8; 2048];
    loop {
        match udp.recv_from(&mut buf).await {
            Ok((n, src)) => {
                eprintln!(
                    "UDP ← {src:<21}  {n:>4} bytes  first8={}",
                    hex_prefix(&buf[..n])
                );
            }
            Err(err) => {
                eprintln!("UDP recv error: {err}");
                return;
            }
        }
    }
}

/// Log a one-line summary of an IPv4 packet: protocol, src→dst, size.
/// IPv6 / malformed packets get a raw hex preview instead.
fn log_packet(tag: &str, pkt: &[u8]) {
    if pkt.is_empty() {
        return;
    }
    // Some macOS utun flavours prepend a 4-byte protocol family word
    // (the "packet information" header) — byte 0..4 is AF_INET/AF_INET6
    // in native byte order. Detect and skip it.
    let ip = if pkt.len() > 4 && pkt[0] == 0 && pkt[1] == 0 && (pkt[3] == 2 || pkt[3] == 30) {
        &pkt[4..]
    } else {
        pkt
    };
    if ip.is_empty() {
        return;
    }
    let version = ip[0] >> 4;
    if version == 4 && ip.len() >= 20 {
        let proto = ip[9];
        let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
        let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
        let proto_name = match proto {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            58 => "ICMPv6",
            _ => "?",
        };
        eprintln!(
            "{tag}  {proto_name:<5}  {src:>15} → {dst:<15}  {} bytes",
            ip.len()
        );
    } else {
        eprintln!(
            "{tag}  v{version}/?      raw={}  ({} bytes)",
            hex_prefix(ip),
            ip.len()
        );
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn run_route(verb: &str, cidr: &str, iface: &str) -> Result<()> {
    let status = Command::new("/sbin/route")
        .args(["-n", verb, "-net", cidr, "-interface", iface])
        .status()
        .with_context(|| format!("spawning /sbin/route {verb}"))?;
    if !status.success() {
        return Err(anyhow!(
            "/sbin/route {verb} {cidr} dev {iface} exited with {status}"
        ));
    }
    Ok(())
}
