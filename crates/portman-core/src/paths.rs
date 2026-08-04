//! Filesystem locations shared by daemon and client.
//!
//! Everything portman persists lives under the platform data directory
//! (`~/Library/Application Support/portman` on macOS, `$XDG_DATA_HOME/portman`
//! on Linux). The IPC *framing* over the socket at [`socket_path`] lives in
//! `portman_protocol::transport`.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Absolute path to the portman Unix socket. Does not create the parent dir.
pub fn socket_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("portman.sock"))
}

/// Absolute path to the persisted static-rule store.
pub fn static_rules_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("static.json"))
}

/// Absolute path to the per-TLD TLS settings store.
pub fn tls_settings_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("tls.json"))
}

/// Absolute path to the directory portman keeps generated TLS certs in.
pub fn cert_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("certs"))
}

/// Persisted-across-restarts on/off flag for the v1 Rust netbridge.
/// JSON document: `{"enabled": true|false}`. Missing file ≡ false.
pub fn netbridge_state_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("netbridge.json"))
}

/// Persisted supervisor state: synced service definitions, desired
/// run-state, and live process markers for boot reconciliation.
pub fn services_state_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("services.json"))
}

/// SQLite store for captured service stdout/stderr.
pub fn log_store_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("logs.db"))
}

/// Machine credentials for secrets providers (0600, root-owned under the
/// installed daemon). Written by `portman secrets set-*`.
pub fn secrets_credentials_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("credentials.json"))
}

/// Default TCP port for the embedded web dashboard.
pub const DEFAULT_DASHBOARD_PORT: u16 = 7341;

/// Where `portman install` places the daemon binary. Also baked into the
/// launchd/systemd unit templates — change here, change everywhere.
pub const INSTALLED_DAEMON_BIN: &str = "/usr/local/bin/portman-daemon";

/// Where `portman install` places the CLI binary.
pub const INSTALLED_CLI_BIN: &str = "/usr/local/bin/portman";

/// PATH injected into the installed daemon's unit. Homebrew dirs matter on
/// macOS (mkcert lives there); sbin matters everywhere (route, ifconfig).
#[cfg(target_os = "macos")]
pub const DAEMON_RUNTIME_PATH: &str =
    "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
#[cfg(not(target_os = "macos"))]
pub const DAEMON_RUNTIME_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// Environment both unit templates (launchd plist, systemd unit) inject,
/// in one place so the platforms can't drift apart.
pub fn daemon_env(sudo_user: &str) -> [(&'static str, String); 3] {
    [
        ("RUST_LOG", "info".to_string()),
        ("SUDO_USER", sudo_user.to_string()),
        ("PATH", DAEMON_RUNTIME_PATH.to_string()),
    ]
}

/// Process-name fragment for straggler sweeps (`pgrep -f`). Kept adjacent to
/// [`INSTALLED_DAEMON_BIN`] so a rename can't miss one of them; the test
/// at the bottom of this file pins that they agree.
pub const DAEMON_BIN_NAME: &str = "portman-daemon";

/// Absolute path to portman's data directory.
pub fn data_dir() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        Ok(user_home()?.join("Library/Application Support/portman"))
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
            if !dir.is_empty() {
                return Ok(PathBuf::from(dir).join("portman"));
            }
        }
        Ok(user_home()?.join(".local/share/portman"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!("data_dir: unsupported platform")
    }
}

/// Candidate docker-socket paths, in the order portman tries to connect.
///
/// Shared by the daemon's docker-events watcher and by any auxiliary binary
/// (examples, future `portman-netbridge` modules) that needs to talk to the
/// same Docker the daemon talks to. Keeping the list in one place means that
/// when colima (or any other runtime) adds a new path, a single edit covers
/// everything.
///
/// Order:
/// 1. `DOCKER_HOST` if set (only if it's a `unix://` URL).
/// 2. `~/.colima/default/docker.sock` — colima's legacy home; takes precedence
///    whenever `~/.colima` exists, per colima's own "found ~/.colima,
///    ignoring $XDG_CONFIG_HOME" resolution rule.
/// 3. `~/.config/colima/default/docker.sock` — colima's XDG home.
/// 4. `~/.orbstack/run/docker.sock` — OrbStack (rare now, included for
///    compatibility with a partially-migrated install).
/// 5. `~/.docker/run/docker.sock` — Docker Desktop on macOS.
/// 6. `/var/run/docker.sock` — classical default, useful as Linux fallback.
pub fn docker_socket_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(host) = std::env::var("DOCKER_HOST") {
        if let Some(rest) = host.strip_prefix("unix://") {
            out.push(PathBuf::from(rest));
        }
    }
    if let Ok(home) = user_home() {
        out.push(home.join(".colima/default/docker.sock"));
        out.push(home.join(".config/colima/default/docker.sock"));
        out.push(home.join(".orbstack/run/docker.sock"));
        out.push(home.join(".docker/run/docker.sock"));
    }
    out.push(PathBuf::from("/var/run/docker.sock"));
    out
}

/// The invoking user's home directory, even when running under `sudo` (where
/// `HOME` is rewritten to `/var/root`). This way the root-run daemon and the
/// user-run CLI agree on the data directory.
pub fn user_home() -> Result<PathBuf> {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() {
            #[cfg(target_os = "macos")]
            {
                let candidate = PathBuf::from(format!("/Users/{sudo_user}"));
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
            #[cfg(target_os = "linux")]
            {
                let candidate = PathBuf::from(format!("/home/{sudo_user}"));
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
        }
    }
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_bin_constants_agree() {
        assert!(INSTALLED_DAEMON_BIN.ends_with(DAEMON_BIN_NAME));
        assert!(INSTALLED_CLI_BIN.ends_with("portman"));
    }
}
