//! TLD management helpers.
//!
//! portman identifies its own resolver configuration via a first-line marker
//! `# managed by portman`. On macOS this is `/etc/resolver/<tld>`; on Linux
//! it is a systemd-resolved drop-in under `/etc/systemd/resolved.conf.d/`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// First line of every resolver file portman writes. Presence of this exact
/// line is how we know the file is ours.
pub const PORTMAN_MARKER: &str = "# managed by portman";

/// Resolver directory on macOS.
#[cfg(target_os = "macos")]
pub const RESOLVER_DIR: &str = "/etc/resolver";

/// systemd-resolved drop-in directory on Linux.
#[cfg(target_os = "linux")]
pub const RESOLVER_DIR: &str = "/etc/systemd/resolved.conf.d";

/// Absolute path to the platform resolver config for `tld`.
pub fn resolver_path(tld: &str) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        Path::new(RESOLVER_DIR).join(tld)
    }
    #[cfg(target_os = "linux")]
    {
        Path::new(RESOLVER_DIR).join(format!("portman-{tld}.conf"))
    }
}

/// Rendered contents of a portman-managed resolver file for `port` (macOS).
#[cfg(target_os = "macos")]
pub fn resolver_contents(port: u16) -> String {
    format!("{PORTMAN_MARKER}\nnameserver 127.0.0.1\nport {port}\n")
}

/// Platform-specific resolver file contents for `tld` on `port`.
pub fn resolver_file_contents(tld: &str, port: u16) -> String {
    #[cfg(target_os = "macos")]
    {
        let _ = tld;
        resolver_contents(port)
    }
    #[cfg(target_os = "linux")]
    {
        resolver_contents_for_tld(tld, port)
    }
}

#[cfg(target_os = "linux")]
fn resolver_contents_for_tld(tld: &str, port: u16) -> String {
    format!("{PORTMAN_MARKER}\n[Resolve]\nDNS=127.0.0.1:{port}\nDomains=~{tld}\n")
}

/// Write a portman-managed resolver config. Caller must have root (sudo).
pub fn write_resolver(tld: &str, port: u16) -> Result<()> {
    let path = resolver_path(tld);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    #[cfg(target_os = "macos")]
    let contents = resolver_contents(port);
    #[cfg(target_os = "linux")]
    let contents = resolver_contents_for_tld(tld, port);
    fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))
}

/// Remove a portman-managed resolver config if it exists.
pub fn remove_resolver(tld: &str) -> Result<()> {
    let path = resolver_path(tld);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("removing {}", path.display())),
    }
}

/// Normalize and validate a TLD string. Lowercase, no whitespace, no leading
/// or trailing dots, no slashes. Multi-label TLDs are permitted
/// (e.g. `dev.acme.example.com`).
///
/// Returns an `Err` with a user-facing message for the rejection reasons
/// portman always refuses. Some values (`internal`, `dev`, etc.) are
/// problematic but handled via a separate warnings path rather than hard-blocked.
pub fn validate_tld(tld: &str) -> Result<String> {
    let t = tld.trim().to_ascii_lowercase();
    if t.is_empty() {
        bail!("tld cannot be empty");
    }
    if t.chars().any(char::is_whitespace) {
        bail!("tld cannot contain whitespace");
    }
    if t.starts_with('.') || t.ends_with('.') {
        bail!("tld cannot start or end with a dot");
    }
    if t.contains('/') {
        bail!("tld cannot contain slashes");
    }
    if t == "local" {
        bail!("`.local` is intercepted by macOS mDNSResponder — do not manage it");
    }
    Ok(t)
}

/// Advisory warnings for TLDs that are technically valid but known-risky on
/// macOS. Returned as a list of human-readable strings; caller decides how to
/// surface them.
pub fn warnings_for_tld(tld: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = tld.to_ascii_lowercase();
    if lower == "internal" {
        out.push(
            "Apple's mDNSResponder has begun intercepting `.internal` in recent macOS versions; \
             resolver files for this TLD often don't reliably take effect."
                .into(),
        );
    }
    if lower == "dev" || lower.ends_with(".dev") {
        out.push(
            "`.dev` is HSTS-preloaded in Chromium-based browsers — plain HTTP will be refused."
                .into(),
        );
    }
    out
}

/// Status of an existing resolver file at `resolver_path(tld)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverFileState {
    /// No file at the path.
    Absent,
    /// File exists and starts with the portman marker.
    ManagedByPortman,
    /// File exists but does not start with the portman marker. Probably
    /// Tailscale split-DNS, dnsmasq, or something else.
    ManagedByOther,
}

/// Inspect an existing resolver file.
pub fn peek_resolver(tld: &str) -> Result<ResolverFileState> {
    let path = resolver_path(tld);
    match fs::read_to_string(&path) {
        Ok(contents) => {
            if contents.starts_with(PORTMAN_MARKER) {
                Ok(ResolverFileState::ManagedByPortman)
            } else {
                Ok(ResolverFileState::ManagedByOther)
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(ResolverFileState::Absent),
        Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
    }
}

/// Scan the resolver directory and return TLD names for every portman-managed
/// config file.
pub fn scan_managed_tlds() -> Result<Vec<String>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(RESOLVER_DIR) {
        Ok(e) => e,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(err) => {
            return Err(err).with_context(|| format!("reading {RESOLVER_DIR}"));
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        #[cfg(target_os = "linux")]
        {
            let Some(tld) = name
                .strip_prefix("portman-")
                .and_then(|s| s.strip_suffix(".conf"))
            else {
                continue;
            };
            match fs::read_to_string(&path) {
                Ok(contents) if contents.starts_with(PORTMAN_MARKER) => out.push(tld.to_string()),
                _ => {}
            }
            continue;
        }
        #[cfg(target_os = "macos")]
        {
            match fs::read_to_string(&path) {
                Ok(contents) if contents.starts_with(PORTMAN_MARKER) => out.push(name.to_string()),
                _ => {}
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Does `host` (e.g. `crm.acme`) fall under any TLD in the managed set?
/// Longest-suffix match, case-insensitive.
pub fn host_has_managed_tld<I>(host: &str, tlds: I) -> bool
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let host_lower = host.to_ascii_lowercase();
    tlds.into_iter().any(|tld| {
        let tld = tld.as_ref().to_ascii_lowercase();
        if host_lower == tld {
            return true;
        }
        if let Some(rest) = host_lower.strip_suffix(&tld) {
            rest.ends_with('.')
        } else {
            false
        }
    })
}

/// Whether `host` uses the RFC 6761 loopback namespace. These names need no
/// resolver integration: operating systems resolve `localhost` and every
/// name below it to loopback themselves.
pub fn host_is_localhost(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost")
}

/// Whether portman may route `host` without asking the user to install a
/// resolver. Managed TLDs use portman's DNS server; `.localhost` uses the
/// operating system's built-in loopback resolution.
pub fn host_is_routable<I>(host: &str, tlds: I) -> bool
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    host_is_localhost(host) || host_has_managed_tld(host, tlds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_tld_rejects_obvious_bad() {
        assert!(validate_tld("").is_err());
        assert!(validate_tld("  ").is_err());
        assert!(validate_tld("has space").is_err());
        assert!(validate_tld(".leading").is_err());
        assert!(validate_tld("trailing.").is_err());
        assert!(validate_tld("with/slash").is_err());
        assert!(validate_tld("local").is_err());
        assert_eq!(validate_tld("TEST").unwrap(), "test");
        assert_eq!(
            validate_tld("dev.acme.example.com").unwrap(),
            "dev.acme.example.com"
        );
    }

    #[test]
    fn warnings_for_tld_flags_internal_and_dev() {
        assert!(warnings_for_tld("test").is_empty());
        assert!(!warnings_for_tld("internal").is_empty());
        assert!(!warnings_for_tld("dev").is_empty());
        assert!(!warnings_for_tld("app.dev").is_empty());
    }

    #[test]
    fn host_has_managed_tld_matches_suffix() {
        let tlds = ["test", "acme"];
        assert!(host_has_managed_tld("crm.test", tlds));
        assert!(host_has_managed_tld("a.b.test", tlds));
        assert!(host_has_managed_tld("crm.acme", tlds));
        assert!(!host_has_managed_tld("crm.example.com", tlds));
        assert!(!host_has_managed_tld("crmtest", tlds)); // no dot boundary
                                                         // exact match (weird but valid — someone dig-ing the TLD itself)
        assert!(host_has_managed_tld("test", tlds));
    }

    #[test]
    fn host_has_managed_tld_multi_label_tld() {
        let tlds = ["dev.acme.example.com"];
        assert!(host_has_managed_tld("crm.dev.acme.example.com", tlds));
        assert!(!host_has_managed_tld("crm.example.com", tlds));
        assert!(!host_has_managed_tld("crm.staging.acme.example.com", tlds));
    }

    #[test]
    fn localhost_names_route_without_a_managed_tld() {
        assert!(host_is_routable(
            "app.localhost",
            std::iter::empty::<&str>()
        ));
        assert!(host_is_routable(
            "API.DEMO.LOCALHOST",
            std::iter::empty::<&str>()
        ));
        assert!(!host_is_routable(
            "localhost.example.com",
            std::iter::empty::<&str>()
        ));
        assert!(!host_is_routable("app.test", std::iter::empty::<&str>()));
    }

    #[test]
    fn resolver_contents_has_marker_first() {
        #[cfg(target_os = "macos")]
        {
            let c = resolver_contents(5335);
            assert!(c.starts_with(PORTMAN_MARKER));
            assert!(c.contains("nameserver 127.0.0.1"));
            assert!(c.contains("port 5335"));
        }
        #[cfg(target_os = "linux")]
        {
            let c = resolver_file_contents("test", 5335);
            assert!(c.starts_with(PORTMAN_MARKER));
            assert!(c.contains("DNS=127.0.0.1:5335"));
            assert!(c.contains("Domains=~test"));
        }
    }
}
