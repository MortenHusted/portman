use std::process::Command;

use super::PlatformApi;

/// Linux implementation of [`PlatformApi`].
///
/// DNS integration uses systemd-resolved drop-in configs under
/// `/etc/systemd/resolved.conf.d/`. Routing is a no-op — container IPs
/// are natively reachable on Linux.
#[derive(Debug, Default)]
pub struct Linux;

impl PlatformApi for Linux {
    fn install_resolver(&self, tld: &str, _nameserver: &str, port: u16) -> anyhow::Result<()> {
        crate::tld::write_resolver(tld, port)?;
        reload_systemd_resolved()
    }

    fn uninstall_resolver(&self, tld: &str) -> anyhow::Result<()> {
        crate::tld::remove_resolver(tld)?;
        reload_systemd_resolved()
    }

    fn add_route(&self, _subnet: &str, _iface: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn ensure_loopback_alias(&self, _ip: std::net::Ipv4Addr) -> anyhow::Result<()> {
        // All of 127.0.0.0/8 is already loopback on Linux — nothing to alias.
        Ok(())
    }

    fn remove_loopback_alias(&self, _ip: std::net::Ipv4Addr) -> anyhow::Result<()> {
        Ok(())
    }
}

fn reload_systemd_resolved() -> anyhow::Result<()> {
    let status = Command::new("systemctl")
        .args(["reload", "systemd-resolved"])
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => anyhow::bail!("systemctl reload systemd-resolved failed with {s}"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Distro without systemd-resolved — drop-in is written; user may need dnsmasq.
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}
