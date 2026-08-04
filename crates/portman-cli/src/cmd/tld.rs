//! Managed-TLD commands: list, add (sudo resolver write + TLS mode), remove.

use crate::cmd::sudo_write;
use anyhow::{bail, Context, Result};
use portman_core::tld::{
    peek_resolver, resolver_file_contents, resolver_path, scan_managed_tlds, validate_tld,
    warnings_for_tld, ResolverFileState, PORTMAN_MARKER,
};
use portman_core::tls_store::{parse_mode, TlsMode};
use std::process::Command as StdCommand;

use crate::client::request;
use portman_protocol::{Request, Response};

pub(crate) async fn cmd_tld_list() -> Result<()> {
    // The daemon response carries richer info (TLS mode + entry count); fall
    // back to the raw /etc/resolver/ scan if the daemon isn't reachable.
    match request(Request::TldList).await {
        Ok(Response::Tlds { tlds }) => {
            if tlds.is_empty() {
                println!("(no managed TLDs)");
                return Ok(());
            }
            for t in &tlds {
                let tls = if t.tls_mode == TlsMode::Off {
                    String::new()
                } else {
                    format!("  tls:{}", t.tls_mode)
                };
                println!(".{:<20} entries:{}{tls}", t.name, t.entry_count);
            }
            Ok(())
        }
        Ok(Response::Err { message }) => bail!(message),
        Ok(other) => bail!("unexpected response: {other:?}"),
        Err(_) => {
            let on_disk = scan_managed_tlds().context("scanning resolver configs")?;
            if on_disk.is_empty() {
                println!("(no managed TLDs)");
            } else {
                for t in &on_disk {
                    println!(".{t}");
                }
            }
            Ok(())
        }
    }
}

pub(crate) async fn cmd_tld_add(raw: String, tls: Option<String>) -> Result<()> {
    let tld = validate_tld(&raw).context("invalid tld")?;
    let tls = normalize_tls_mode_arg(tls).context("invalid TLS mode")?;

    for warning in warnings_for_tld(&tld) {
        eprintln!("warning: {warning}");
    }

    match peek_resolver(&tld)? {
        ResolverFileState::Absent => {}
        ResolverFileState::ManagedByPortman => {
            eprintln!(
                "re-writing {} (already portman-managed)",
                resolver_path(&tld).display()
            );
        }
        ResolverFileState::ManagedByOther => {
            bail!(
                "{} exists but is NOT managed by portman. \
                 Refusing to overwrite. Inspect the file and, if safe, remove it manually first.",
                resolver_path(&tld).display()
            );
        }
    }

    let dns_port = daemon_dns_port()
        .await
        .context("fetching daemon dns port")?;
    let contents = resolver_file_contents(&tld, dns_port);
    let path = resolver_path(&tld);

    eprintln!("writing {} (sudo required)", path.display());
    sudo_write(&path, &contents)?;

    #[cfg(target_os = "linux")]
    restart_resolved();

    match request(Request::TldAdd {
        tld: tld.clone(),
        tls_mode: tls,
    })
    .await?
    {
        Response::Ok => {}
        other => return other.unexpected(),
    }

    let tls_note = match tls {
        Some(m) if m != TlsMode::Off => format!(" [TLS: {m}]"),
        _ => String::new(),
    };
    println!("added .{tld}{tls_note} -> {}", path.display());
    #[cfg(target_os = "macos")]
    println!("verify with: scutil --dns | grep -B1 {tld}");
    #[cfg(target_os = "linux")]
    println!("verify with: resolvectl query foo.{tld}");
    Ok(())
}

/// Apply a resolver drop-in change. `reload` looks gentler but resolved
/// does not re-read config drop-ins on reload (verified on Ubuntu 24.04 by
/// the linux-e2e job: Global DNS stayed on DHCP after a clean reload) — a
/// restart is momentary and deterministic. Loudly non-fatal: DNS keeps
/// working via the old config until the user restarts resolved themselves.
#[cfg(target_os = "linux")]
fn restart_resolved() {
    let status = StdCommand::new("sudo")
        .args(["systemctl", "restart", "systemd-resolved"])
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "warning: systemctl restart systemd-resolved exited {s}; \
             the resolver change is written but not yet applied"
        ),
        Err(err) => eprintln!("warning: could not restart systemd-resolved: {err}"),
    }
}

pub(crate) fn normalize_tls_mode_arg(tls: Option<String>) -> Result<Option<TlsMode>> {
    tls.map(|raw| parse_mode(&raw)).transpose()
}

pub(crate) async fn cmd_tld_remove(raw: String) -> Result<()> {
    let tld = validate_tld(&raw).context("invalid tld")?;

    match peek_resolver(&tld)? {
        ResolverFileState::Absent => bail!("{} does not exist", resolver_path(&tld).display()),
        ResolverFileState::ManagedByOther => bail!(
            "{} is not managed by portman (missing marker `{PORTMAN_MARKER}`). \
             Refusing to remove.",
            resolver_path(&tld).display()
        ),
        ResolverFileState::ManagedByPortman => {}
    }

    let path = resolver_path(&tld);
    eprintln!("removing {} (sudo required)", path.display());
    let status = StdCommand::new("sudo").arg("rm").arg(&path).status()?;
    if !status.success() {
        bail!("sudo rm failed with status {status}");
    }

    #[cfg(target_os = "linux")]
    restart_resolved();

    request(Request::TldRemove { tld: tld.clone() })
        .await?
        .into_ok()?;
    println!("removed .{tld}");
    Ok(())
}

pub(crate) async fn daemon_dns_port() -> Result<u16> {
    match request(Request::Status).await? {
        Response::Status { dns_port, .. } => Ok(dns_port),
        other => other.unexpected(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_mode_arg_is_validated_and_normalized_before_resolver_write() {
        assert_eq!(
            normalize_tls_mode_arg(Some("MKCERT".to_string())).unwrap(),
            Some(TlsMode::Mkcert)
        );
        assert_eq!(
            normalize_tls_mode_arg(Some("http".to_string())).unwrap(),
            Some(TlsMode::Off)
        );
        assert_eq!(normalize_tls_mode_arg(None).unwrap(), None);
        assert!(normalize_tls_mode_arg(Some("bogus".to_string())).is_err());
        assert!(normalize_tls_mode_arg(Some("le".to_string())).is_err());
    }
}
