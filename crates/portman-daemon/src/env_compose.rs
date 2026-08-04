//! Hermetic environment composition for supervised services.
//!
//! A service's environment is built from declared sources only — nothing
//! leaks in from the daemon's own environment, the shell that installed it,
//! mise, or whatever `.env` the cwd happens to hold. Composition order is
//! deterministic and documented (R3): base allowlist, then `env_files` in
//! declared order, then secrets-provider values, then inline `env` — later
//! wins, including over the base.
//!
//! The base is an *allowlist*, not an inheritance filter (KTD7):
//!
//!   - `PATH` — a fixed list the supervisor computes per spawn (well-known
//!     install dirs plus mise's real tool bin dirs; never the shims dir, so
//!     mise's exec-time dotenv injection can't engage).
//!   - `HOME`, `USER` — the login user's.
//!   - `TMPDIR` — `/tmp`. The per-user darwin temp dir is only resolvable
//!     from inside the user's own session; `/tmp` is always writable and
//!     predictable.
//!
//! A missing or unreadable `env_file` **fails the composition** (and thus the
//! service start). A declared source that silently vanishes would make the
//! env depend on filesystem state in a way the config no longer describes —
//! the same reasoning the predecessor tooling used ("local env file
//! missing … run: mise run local:setup"). Secrets-provider failure policy is
//! looser by design (R15) and lives with the provider seam, not here.
//!
//! This module is pure: no process spawning, no reads beyond the declared
//! files. Secrets providers plug in as a plain key/value list (U8 fills it).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Identity half of the base allowlist — who the service runs as.
#[derive(Debug, Clone)]
pub(crate) struct BaseEnv {
    /// Login user name (from `SUDO_USER`).
    pub user: String,
    /// The login user's home directory.
    pub home: PathBuf,
}

/// Compose a service environment from declared sources only. Later sources
/// win: base < env_files (in order) < provider values < inline env.
///
/// `path` is the fixed PATH the caller computed for this spawn — the
/// supervisor derives it per service (well-known install dirs plus mise's
/// real tool bin dirs, never the shims dir; see `supervisor::service_path`).
pub(crate) fn compose(
    base: &BaseEnv,
    path: &str,
    env_files: &[PathBuf],
    provider_values: &[(String, String)],
    inline: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), path.to_string());
    env.insert("HOME".to_string(), base.home.display().to_string());
    env.insert("USER".to_string(), base.user.clone());
    env.insert("TMPDIR".to_string(), "/tmp".to_string());

    for file in env_files {
        apply_env_file(&mut env, file).with_context(|| format!("env_file {}", file.display()))?;
    }
    for (key, value) in provider_values {
        env.insert(key.clone(), value.clone());
    }
    for (key, value) in inline {
        env.insert(key.clone(), value.clone());
    }
    Ok(env)
}

fn apply_env_file(env: &mut BTreeMap<String, String>, file: &Path) -> Result<()> {
    for item in dotenvy::from_path_iter(file)? {
        let (key, value) = item?;
        env.insert(key, value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_PATH: &str = "/test/bin:/usr/bin:/bin";

    fn base() -> BaseEnv {
        BaseEnv {
            user: "dev".into(),
            home: PathBuf::from("/Users/dev"),
        }
    }

    #[test]
    fn base_allowlist_only_and_daemon_env_never_leaks() {
        // Poison the daemon's own environment; the composer must not see it.
        // (Composition is pure — this proves the property holds end-to-end.)
        std::env::set_var("PORTMAN_TEST_POISON", "leaked");

        let env = compose(&base(), TEST_PATH, &[], &[], &BTreeMap::new()).unwrap();

        assert_eq!(
            env.keys().collect::<Vec<_>>(),
            vec!["HOME", "PATH", "TMPDIR", "USER"]
        );
        assert_eq!(env["HOME"], "/Users/dev");
        assert_eq!(env["USER"], "dev");
        assert_eq!(env["TMPDIR"], "/tmp");
        assert_eq!(env["PATH"], TEST_PATH);
        assert!(!env.contains_key("PORTMAN_TEST_POISON"));
    }

    #[test]
    fn env_files_apply_in_declared_order_later_wins() {
        let dir = tempdir().unwrap();
        let first = dir.path().join("base.env");
        let second = dir.path().join("local.env");
        std::fs::write(&first, "SHARED=from-base\nBASE_ONLY=1\n").unwrap();
        std::fs::write(&second, "SHARED=from-local\nLOCAL_ONLY=1\n").unwrap();

        let env = compose(&base(), TEST_PATH, &[first, second], &[], &BTreeMap::new()).unwrap();

        assert_eq!(env["SHARED"], "from-local");
        assert_eq!(env["BASE_ONLY"], "1");
        assert_eq!(env["LOCAL_ONLY"], "1");
    }

    #[test]
    fn provider_values_override_env_files_and_lose_to_inline() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("f.env");
        std::fs::write(&file, "A=file\nB=file\nC=file\n").unwrap();

        let providers = vec![
            ("A".to_string(), "provider".to_string()),
            ("B".to_string(), "provider".to_string()),
        ];
        let inline = BTreeMap::from([("A".to_string(), "inline".to_string())]);

        let env = compose(&base(), TEST_PATH, &[file], &providers, &inline).unwrap();

        assert_eq!(env["A"], "inline");
        assert_eq!(env["B"], "provider");
        assert_eq!(env["C"], "file");
    }

    #[test]
    fn declared_sources_may_override_base() {
        let inline = BTreeMap::from([("PATH".to_string(), "/custom/bin".to_string())]);
        let env = compose(&base(), TEST_PATH, &[], &[], &inline).unwrap();
        assert_eq!(env["PATH"], "/custom/bin");
    }

    #[test]
    fn missing_env_file_fails_the_composition() {
        let err = compose(
            &base(),
            TEST_PATH,
            &[PathBuf::from("/nope/definitely-missing.env")],
            &[],
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(format!("{err:?}").contains("definitely-missing.env"));
    }

    /// A real-world `deploy/base.env` + `local/.env` layering: local wins on the
    /// shared Infisical defaults, exactly like the sourcing order in the
    /// retired `bin/local-env-exec`.
    #[test]
    fn base_plus_local_layering_reproduces_precedence() {
        let dir = tempdir().unwrap();
        let base_env = dir.path().join("base.env");
        let local_env = dir.path().join("local.env");
        std::fs::write(
            &base_env,
            "APP_INFISICAL_PROJECT_ID=00000000\nINFISICAL_API_URL=https://secrets.example.com\nAPP_INTERNAL_AUTH=base-fallback\n",
        )
        .unwrap();
        std::fs::write(&local_env, "APP_INTERNAL_AUTH=local-dev-bearer\n").unwrap();

        let env = compose(
            &base(),
            TEST_PATH,
            &[base_env, local_env],
            &[],
            &BTreeMap::new(),
        )
        .unwrap();

        assert_eq!(env["APP_INFISICAL_PROJECT_ID"], "00000000");
        assert_eq!(env["APP_INTERNAL_AUTH"], "local-dev-bearer");
    }
}
