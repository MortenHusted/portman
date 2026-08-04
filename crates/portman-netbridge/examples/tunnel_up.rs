//! Phase B.1 — host-side utun + route install.
//!
//! Brings up a macOS `utun` at the portman host tunnel IP, installs a
//! host route for the portman docker subnet pointing at it, holds for
//! `TIMEOUT_SECS` seconds so the user can verify with `ifconfig` /
//! `netstat`, then tears down cleanly.
//!
//! No WireGuard yet — that's B.1b. This example validates the
//! platform primitives (utun allocation, interface bring-up, route
//! install) in isolation.
//!
//! ```sh
//! sudo -E target/debug/examples/tunnel_up
//! ```
//!
//! (requires root because macOS `utun` creation and routing-table
//! writes go through privileged socket/ioctl calls. A production
//! portman install already runs the daemon as a system LaunchDaemon
//! under root, so when B.1b folds this into the daemon the sudo
//! ceremony goes away.)
//!
//! Verify in a second terminal:
//!
//! ```sh
//! ifconfig | awk '/utun/,/^$/'              # look for 192.168.99.1
//! netstat -rn -f inet | grep 192.168.99     # look for the route
//! ```

use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use portman_netbridge::tunnel::{HOST_TUNNEL_IP, PORTMAN_SUBNET_CIDR, TUNNEL_MTU, VM_TUNNEL_IP};
use tun::Device;

const TIMEOUT_SECS: u64 = 30;

fn main() -> Result<()> {
    let uid = users_effective_uid();
    if uid != 0 {
        return Err(anyhow!(
            "this example must run as root (utun + route). Try:\n  \
             sudo -E $CARGO_TARGET_DIR/debug/examples/tunnel_up\n\
             or:\n  \
             sudo -A -E cargo run -p portman-netbridge --example tunnel_up"
        ));
    }

    eprintln!("portman-netbridge — Phase B.1 utun bring-up");
    eprintln!("  host IP  : {HOST_TUNNEL_IP}");
    eprintln!("  peer IP  : {VM_TUNNEL_IP}  (not yet reachable — B.1b wires WireGuard)");
    eprintln!("  subnet   : {PORTMAN_SUBNET_CIDR}");
    eprintln!("  MTU      : {TUNNEL_MTU}\n");

    // Allocate a utun. `tun` crate asks the kernel for a free unit;
    // the resulting device name (e.g. utun42) is kernel-assigned, so
    // there's no way we can collide with the live chipmk bridge's
    // utun0 or any other existing utun.
    let mut config = tun::Configuration::default();
    config
        .address(HOST_TUNNEL_IP)
        .netmask((255, 255, 255, 0))
        .destination(VM_TUNNEL_IP)
        .mtu(i32::from(TUNNEL_MTU))
        .up();

    let device = tun::create(&config).context("creating utun device")?;
    let name = device.name().context("reading utun device name")?;
    eprintln!("✓ utun up          → {name} (IP {HOST_TUNNEL_IP}, MTU {TUNNEL_MTU})");

    // Install the route. On macOS `route add -net CIDR -interface utunN`
    // creates an interface route: any packet whose destination falls
    // in CIDR goes out that utun. Exactly what B.1b's WireGuard
    // userspace will pick up once we're pumping packets.
    run_route("add", PORTMAN_SUBNET_CIDR, &name)?;
    eprintln!("✓ route installed  → {PORTMAN_SUBNET_CIDR} dev {name}");

    // We register cleanup now so even a panic in the middle of the
    // hold loop unwinds to remove the route. (The utun goes away on
    // drop; the route outlives the interface unless we delete it.)
    let cleanup = OnDrop::new({
        let cidr = PORTMAN_SUBNET_CIDR.to_string();
        let name = name.clone();
        move || {
            if let Err(err) = run_route("delete", &cidr, &name) {
                eprintln!("route cleanup: {err}");
            } else {
                eprintln!("✓ route removed    → {cidr} dev {name}");
            }
        }
    });

    eprintln!(
        "\nholding for {TIMEOUT_SECS}s — verify alongside:\n  \
         ifconfig {name}\n  \
         netstat -rn -f inet | grep 192.168.99\n"
    );

    // Hold. A sleep is fine here — no packet pump yet; that's B.1b.
    std::thread::sleep(Duration::from_secs(TIMEOUT_SECS));

    drop(cleanup); // runs the route delete
    drop(device); // closes the utun fd; kernel destroys the interface

    eprintln!("\n✓ utun torn down   → {name} closed");
    Ok(())
}

fn users_effective_uid() -> u32 {
    // geteuid is safe and unconditionally present on Unix. Avoids
    // shelling out to `id -u`.
    //
    // We call it from an example binary where `libc::geteuid()` is
    // safe in the strict sense (no pre-conditions), so we whitelist
    // the one call.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
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

/// Run a closure when dropped. Used so route cleanup runs even on a
/// panic-induced unwind from within the hold period.
struct OnDrop<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> OnDrop<F> {
    fn new(f: F) -> Self {
        Self(Some(f))
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}
