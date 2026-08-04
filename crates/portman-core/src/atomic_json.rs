//! One atomic-JSON writer for every file-backed store.
//!
//! Three stores (static rules, TLS settings, netbridge state) each grew their
//! own tempfile-and-rename with inconsistent durability: one skipped the file
//! fsync entirely (a crash could commit the rename over empty content despite
//! the "atomic" doc claim), and all three shared a fixed `<name>.json.tmp`
//! path, so two writers in one process could clobber each other's tempfile.
//!
//! This helper is the single implementation: unique temp name per write →
//! file fsync → rename → best-effort directory fsync (macOS APFS mostly
//! doesn't need it, but it costs nothing and matters on other filesystems).

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use serde::Serialize;

/// Serialize `value` as pretty JSON and atomically replace `path` with it.
pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    atomic_write_json_impl(path, value, None)
}

/// Same, but the file is created with `mode` (e.g. 0o600 for state that
/// embeds service environments).
pub fn atomic_write_json_with_mode<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<()> {
    atomic_write_json_impl(path, value, Some(mode))
}

fn atomic_write_json_impl<T: Serialize>(path: &Path, value: &T, mode: Option<u32>) -> Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let parent = path.parent().context("target path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("target path has no file name")?;
    let tmp = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));

    let bytes = serde_json::to_vec_pretty(value)?;
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        if let Some(mode) = mode {
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("creating temp file {}", tmp.display()))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        // Persist the rename itself. Failure here is not worth failing the
        // write over — the data file is already synced and in place.
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_land_and_leave_no_temp_litter() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write_json(&path, &serde_json::json!({ "v": 1 })).unwrap();
        atomic_write_json(&path, &serde_json::json!({ "v": 2 })).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"v\": 2"));
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries.len(), 1, "{entries:?}");
    }

    #[test]
    fn concurrent_writers_never_share_a_temp_name() {
        // The old fixed `<name>.json.tmp` meant two writers could clobber
        // each other's tempfile mid-write. Hammer from two threads; the
        // final file must always be one of the two valid payloads.
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::thread::scope(|scope| {
            for payload in [1_u64, 2] {
                let path = path.clone();
                scope.spawn(move || {
                    for _ in 0..50 {
                        atomic_write_json(&path, &serde_json::json!({ "v": payload })).unwrap();
                    }
                });
            }
        });
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(matches!(parsed["v"].as_u64(), Some(1 | 2)));
    }

    #[test]
    fn with_mode_sets_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write_json_with_mode(&path, &serde_json::json!({"k": 1}), 0o600).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
