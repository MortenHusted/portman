//! Per-TLD TLS mode + generated-cert registry.
//!
//! Persisted at `~/Library/Application Support/portman/tls.json`. Shape:
//!
//! ```json
//! { "version": 1, "tlds": { "test": {"mode": "mkcert"} } }
//! ```
//!
//! Modes:
//!   * `off`    — explicit "no TLS" (default; equivalent to TLD absent here)
//!   * `mkcert` — portman generates per-host certs via the `mkcert` CLI
//!     signed by the user's local mkcert root CA
//!   * `le`     — reserved for Let's Encrypt (post-v0; not implemented and
//!     deliberately non-actionable until that implementation ships)

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

// The enum lives in the protocol crate (it's a wire type too); this is its
// canonical home for persistence users.
pub use portman_protocol::TlsMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Persisted {
    version: u32,
    /// TLD → mode.
    tlds: BTreeMap<String, TlsSettings>,
}

impl Default for Persisted {
    fn default() -> Self {
        Self {
            version: 1,
            tlds: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    #[serde(default)]
    pub mode: TlsMode,
}

#[derive(Debug)]
pub struct TlsStore {
    path: PathBuf,
    state: RwLock<Persisted>,
}

impl TlsStore {
    pub fn load(path: PathBuf) -> Result<Self> {
        let state = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Persisted>(&bytes)
                .with_context(|| format!("parsing {}", path.display()))?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Persisted::default(),
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self {
            path,
            state: RwLock::new(state),
        })
    }

    pub fn mode_for(&self, tld: &str) -> TlsMode {
        self.state
            .read()
            .expect("tls store lock poisoned")
            .tlds
            .get(tld)
            .map(|s| s.mode)
            .unwrap_or(TlsMode::Off)
    }

    /// Set (or clear) the TLS mode for a TLD. `Off` removes the entry.
    pub fn set_mode(&self, tld: String, mode: TlsMode) -> Result<()> {
        // Clone-mutate-persist-swap: a failed write must not leave memory
        // ahead of disk (see static_store::add for the full rationale).
        let mut guard = self.state.write().expect("tls store lock poisoned");
        let mut next = guard.clone();
        if matches!(mode, TlsMode::Off) {
            next.tlds.remove(&tld);
        } else {
            next.tlds.insert(tld, TlsSettings { mode });
        }
        crate::atomic_json::atomic_write_json(&self.path, &next)?;
        *guard = next;
        Ok(())
    }

    /// All TLDs whose mode requires TLS.
    pub fn tls_tlds(&self) -> Vec<(String, TlsMode)> {
        self.state
            .read()
            .expect("tls store lock poisoned")
            .tlds
            .iter()
            .filter(|(_, s)| s.mode.requires_tls())
            .map(|(k, v)| (k.clone(), v.mode))
            .collect()
    }
}

/// Parse a user-facing TLS mode string.
pub fn parse_mode(s: &str) -> Result<TlsMode> {
    match s.to_ascii_lowercase().as_str() {
        "off" | "none" | "http" => Ok(TlsMode::Off),
        "mkcert" => Ok(TlsMode::Mkcert),
        "le" | "letsencrypt" | "lets-encrypt" => {
            bail!("Let's Encrypt mode is not implemented yet (post-v0)")
        }
        other => bail!("unknown TLS mode `{other}`. Expected: off | mkcert"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_mode_is_off() {
        let dir = tempdir().unwrap();
        let store = TlsStore::load(dir.path().join("tls.json")).unwrap();
        assert_eq!(store.mode_for("test"), TlsMode::Off);
    }

    #[test]
    fn set_and_reload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tls.json");
        let store = TlsStore::load(path.clone()).unwrap();
        store.set_mode("test".into(), TlsMode::Mkcert).unwrap();
        drop(store);
        let store2 = TlsStore::load(path).unwrap();
        assert_eq!(store2.mode_for("test"), TlsMode::Mkcert);
        assert_eq!(store2.mode_for("acme"), TlsMode::Off);
    }

    #[test]
    fn set_off_removes() {
        let dir = tempdir().unwrap();
        let store = TlsStore::load(dir.path().join("tls.json")).unwrap();
        store.set_mode("test".into(), TlsMode::Mkcert).unwrap();
        store.set_mode("test".into(), TlsMode::Off).unwrap();
        assert_eq!(store.mode_for("test"), TlsMode::Off);
        assert!(store.tls_tlds().is_empty());
    }

    #[test]
    fn parse_mode_cases() {
        assert_eq!(parse_mode("mkcert").unwrap(), TlsMode::Mkcert);
        assert_eq!(parse_mode("MKCERT").unwrap(), TlsMode::Mkcert);
        assert_eq!(parse_mode("off").unwrap(), TlsMode::Off);
        assert_eq!(parse_mode("http").unwrap(), TlsMode::Off);
        assert!(parse_mode("le").is_err());
        assert!(parse_mode("bogus").is_err());
    }

    #[test]
    fn missing_persisted_mode_defaults_to_off() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tls.json");
        std::fs::write(&path, r#"{"version":1,"tlds":{"test":{}}}"#).unwrap();

        let store = TlsStore::load(path).unwrap();

        assert_eq!(store.mode_for("test"), TlsMode::Off);
        assert!(store.tls_tlds().is_empty());
    }

    #[test]
    fn reserved_le_mode_is_not_actionable_until_implemented() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tls.json");
        std::fs::write(&path, r#"{"version":1,"tlds":{"future":{"mode":"le"}}}"#).unwrap();

        let store = TlsStore::load(path).unwrap();

        assert_eq!(store.mode_for("future"), TlsMode::Le);
        assert!(!store.mode_for("future").requires_tls());
        assert!(store.tls_tlds().is_empty());
    }
}
