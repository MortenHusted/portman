//! Tiny persisted-state module for the v1 netbridge on/off flag.
//!
//! One JSON file at [`crate::paths::netbridge_state_path`], one boolean.
//! Intentionally separate from `static_store` / `tls_store` — those
//! hold richer user-authored config. This is a single daemon-managed
//! flag, deliberately trivial so the load path on startup is
//! fire-and-forget.

use std::fs;
use std::path::Path;

use anyhow::Result;
use portman_protocol::NetbridgeMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetbridgeState {
    /// User-requested on/off. Missing file / parse error treated as
    /// `false` (off) — the netbridge is opt-in.
    #[serde(default)]
    pub enabled: bool,
    /// Route ownership mode. Missing field from older configs is the safe
    /// current behavior: only the dedicated `portman` network is routed.
    #[serde(default)]
    pub mode: NetbridgeMode,
}

/// Load persisted state from `path`. A missing file returns the
/// default (disabled) rather than erroring — this is the common
/// first-run case and shouldn't block daemon startup.
pub fn load(path: &Path) -> NetbridgeState {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => NetbridgeState::default(),
        Err(_) => NetbridgeState::default(),
    }
}

/// Save state atomically. Delegates to the shared writer — this file used to
/// skip the fsync, so a crash could commit the rename over empty content
/// despite the "atomic" claim.
pub fn save(path: &Path, state: &NetbridgeState) -> Result<()> {
    crate::atomic_json::atomic_write_json(path, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_missing_yields_default() {
        let dir = tempdir().unwrap();
        let s = load(&dir.path().join("nope.json"));
        assert!(!s.enabled);
        assert_eq!(s.mode, NetbridgeMode::OptIn);
    }

    #[test]
    fn round_trip_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("netbridge.json");
        save(
            &path,
            &NetbridgeState {
                enabled: true,
                mode: NetbridgeMode::Docker,
            },
        )
        .unwrap();
        let loaded = load(&path);
        assert!(loaded.enabled);
        assert_eq!(loaded.mode, NetbridgeMode::Docker);
    }

    #[test]
    fn corrupt_file_falls_back_to_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("netbridge.json");
        fs::write(&path, b"not valid json").unwrap();
        let loaded = load(&path);
        assert!(!loaded.enabled);
        assert_eq!(loaded.mode, NetbridgeMode::OptIn);
    }

    #[test]
    fn legacy_enabled_only_shape_defaults_to_opt_in_mode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("netbridge.json");
        fs::write(&path, br#"{"enabled":true}"#).unwrap();
        let loaded = load(&path);

        assert!(loaded.enabled);
        assert_eq!(loaded.mode, NetbridgeMode::OptIn);
    }
}
