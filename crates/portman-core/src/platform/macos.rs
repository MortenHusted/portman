use std::net::Ipv4Addr;
use std::process::Command;

use super::PlatformApi;

/// macOS implementation of [`PlatformApi`].
///
/// Resolver integration and routing remain CLI/netbridge concerns; the
/// loopback-alias methods below are what the daemon uses to front TCP-mode
/// entries on dedicated `127.0.0.0/8` addresses.
#[derive(Debug, Default)]
pub struct MacOs;

impl PlatformApi for MacOs {
    fn install_resolver(&self, _tld: &str, _nameserver: &str, _port: u16) -> anyhow::Result<()> {
        anyhow::bail!("install_resolver: not implemented (Phase 5)")
    }

    fn uninstall_resolver(&self, _tld: &str) -> anyhow::Result<()> {
        anyhow::bail!("uninstall_resolver: not implemented (Phase 5)")
    }

    fn add_route(&self, _subnet: &str, _iface: &str) -> anyhow::Result<()> {
        anyhow::bail!("add_route: not implemented (v1+)")
    }

    fn ensure_loopback_alias(&self, ip: Ipv4Addr) -> anyhow::Result<()> {
        // 127.0.0.1 is always up — never touch the primary loopback address.
        if ip == Ipv4Addr::LOCALHOST {
            return Ok(());
        }
        ifconfig(&["lo0", "alias", &ip.to_string(), "up"])
    }

    fn remove_loopback_alias(&self, ip: Ipv4Addr) -> anyhow::Result<()> {
        if ip == Ipv4Addr::LOCALHOST {
            return Ok(());
        }
        ifconfig(&["lo0", "-alias", &ip.to_string()])
    }
}

/// Run `ifconfig` with `args`. The daemon runs as root (system LaunchDaemon),
/// so no `sudo` is needed. Callers that run the daemon unprivileged in dev
/// will see this fail; they should use `mise run daemon-root`.
fn ifconfig(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("ifconfig")
        .args(args)
        .status()
        .map_err(|err| anyhow::anyhow!("spawning `ifconfig {}`: {err}", args.join(" ")))?;
    if !status.success() {
        anyhow::bail!("`ifconfig {}` failed with {status}", args.join(" "));
    }
    Ok(())
}
