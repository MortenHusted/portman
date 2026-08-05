//! Bearer-token auth for the dashboard's HTTP API.
//!
//! The dashboard is a control API: it reads captured service logs, and
//! `POST /api/config` writes repo config and triggers a supervisor sync. It
//! binds loopback, which stops the network but not the machine — every local
//! process, including any AI coding agent with shell access, could call it.
//! The rebinding and CSRF guards it already had address browsers reaching in;
//! they do nothing about a local `curl`.
//!
//! So `/api/*` requires a bearer token held in a 0600 file next to the other
//! daemon state. The token is owned by the login user, not root: the CLI runs
//! unprivileged and has to read it to open the browser.
//!
//! Static assets stay open. They carry no data, and requiring a token for the
//! top-level document would mean the browser could never load the page that
//! knows how to send one.

use std::path::Path;

use anyhow::{Context, Result};
use rand::RngCore;
use subtle::ConstantTimeEq;

/// Hex-encoded 256-bit token.
const TOKEN_BYTES: usize = 32;

/// Read the dashboard token, generating and persisting one on first use.
pub(crate) fn load_or_create(path: &Path) -> Result<String> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let existing = existing.trim().to_string();
        if !existing.is_empty() {
            return Ok(existing);
        }
    }
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    write_private(path, &token).with_context(|| format!("writing {}", path.display()))?;
    Ok(token)
}

/// Atomic-rename write, 0600 on both the temp and final file, then chowned to
/// the login user so the unprivileged CLI can read it under a root daemon.
fn write_private(path: &Path, token: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating temp file {}", tmp.display()))?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    chown_to_login_user(path);
    Ok(())
}

/// Best-effort: a root daemon hands the file to the login user. Failure only
/// means the CLI cannot auto-open the browser, so it warns rather than fails.
fn chown_to_login_user(path: &Path) {
    if !nix::unistd::geteuid().is_root() {
        return;
    }
    let Ok(name) = std::env::var("SUDO_USER") else {
        return;
    };
    match nix::unistd::User::from_name(name.trim()) {
        Ok(Some(user)) => {
            if let Err(err) =
                std::os::unix::fs::chown(path, Some(user.uid.as_raw()), Some(user.gid.as_raw()))
            {
                tracing::warn!(%err, "dashboard token stays root-owned; `portman dashboard` may not open it");
            }
        }
        _ => tracing::warn!("SUDO_USER does not resolve; dashboard token stays root-owned"),
    }
}

/// Whether a request may proceed.
///
/// Static assets are open; everything under `/api/` needs the token, supplied
/// either as `Authorization: Bearer <token>` (curl, scripts) or `?token=`
/// (the browser's first load, which cannot set a header). Comparison is
/// constant-time so a wrong token leaks nothing through timing.
pub(crate) fn authorize(path: &str, authorization: Option<&str>, token: &str) -> bool {
    if !path.starts_with("/api/") {
        return true;
    }
    let presented = authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .or_else(|| token_from_query(path));
    let Some(presented) = presented else {
        return false;
    };
    presented.as_bytes().ct_eq(token.as_bytes()).into()
}

/// `?token=…` or `&token=…` from a request target.
fn token_from_query(path: &str) -> Option<&str> {
    let (_, query) = path.split_once('?')?;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("token="))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "8f14e45fceea167a5a36dedd4bea2543";

    #[test]
    fn static_assets_need_no_token() {
        for path in ["/", "/index.html", "/app.js", "/style.css"] {
            assert!(authorize(path, None, TOKEN), "{path} must stay open");
        }
    }

    #[test]
    fn api_requires_a_matching_token() {
        assert!(!authorize("/api/services", None, TOKEN), "no credential");
        assert!(
            !authorize("/api/services", Some("Bearer wrong"), TOKEN),
            "wrong token"
        );
        assert!(
            !authorize("/api/services", Some(TOKEN), TOKEN),
            "bare token without the Bearer scheme is not accepted"
        );
        assert!(authorize(
            "/api/services",
            Some(&format!("Bearer {TOKEN}")),
            TOKEN
        ));
    }

    #[test]
    fn the_query_parameter_works_for_the_browsers_first_load() {
        assert!(authorize(
            &format!("/api/status?token={TOKEN}"),
            None,
            TOKEN
        ));
        assert!(authorize(
            &format!("/api/status?since=1&token={TOKEN}"),
            None,
            TOKEN
        ));
        assert!(!authorize("/api/status?token=wrong", None, TOKEN));
        // A token-shaped value in some other parameter is not a credential.
        assert!(!authorize(
            &format!("/api/status?nottoken={TOKEN}"),
            None,
            TOKEN
        ));
    }

    #[test]
    fn a_generated_token_persists_and_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dashboard-token");
        let first = load_or_create(&path).unwrap();
        assert_eq!(first.len(), TOKEN_BYTES * 2, "256-bit hex token");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(load_or_create(&path).unwrap(), first, "stable across reads");
    }

    #[test]
    fn an_empty_token_file_is_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dashboard-token");
        std::fs::write(&path, "   \n").unwrap();
        assert!(!load_or_create(&path).unwrap().is_empty());
    }
}
