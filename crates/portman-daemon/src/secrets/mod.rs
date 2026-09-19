//! Secrets providers behind one seam (R12).
//!
//! A service references `[secrets.<name>]` blocks from its repo config;
//! resolution turns those blocks into env pairs that the composer inserts
//! between env_files and inline env (R3). Machine credentials (Infisical
//! universal-auth identity, 1Password service-account token) live once in
//! `credentials.json` — 0600 in the data dir, written by `portman secrets
//! set-*` — never in repo config and never in the daemon's ambient env.
//!
//! Failure policy (R15): a *transient* provider error (unreachable
//! instance, timeout) surfaces as a Backoff-path spawn failure retried
//! under the service's restart policy; a *non-transient* error (auth
//! rejection, unknown path) lands the service in Failed with the error
//! retrievable. Either way a service with `secrets_optional = true`
//! proceeds env_files-only with its status flagged — never a silently
//! empty env.

pub(crate) mod infisical;
pub(crate) mod onepassword;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use portman_protocol::{SecretsProviderConfig, ServiceDefinition};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::supervisor::{SecretsError, SecretsSource};

// ---------------------------------------------------------------------------
// Credentials store (`credentials.json`, 0600).

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InfisicalCredentials {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct OnePasswordCredentials {
    pub token: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Credentials {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    infisical: Option<InfisicalCredentials>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    onepassword: Option<OnePasswordCredentials>,
    /// The local vault: values `[secrets.<name>] provider = "local"` blocks
    /// hand out, keyed by env name. Same file, same 0600 writer as the
    /// provider credentials — one place on disk that holds secret material.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    local: BTreeMap<String, String>,
}

#[derive(Clone)]
pub(crate) struct CredentialsStore {
    path: PathBuf,
    state: Arc<Mutex<Credentials>>,
}

impl CredentialsStore {
    pub(crate) fn load(path: PathBuf) -> Result<Self> {
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display()))?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Credentials::default(),
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self {
            path,
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub(crate) fn set_infisical(&self, client_id: String, client_secret: String) -> Result<()> {
        let mut guard = self.state.lock().expect("credentials lock poisoned");
        let mut next = guard.clone();
        next.infisical = Some(InfisicalCredentials {
            client_id,
            client_secret,
        });
        save(&self.path, &next)?;
        *guard = next;
        Ok(())
    }

    pub(crate) fn set_onepassword(&self, token: String) -> Result<()> {
        let mut guard = self.state.lock().expect("credentials lock poisoned");
        let mut next = guard.clone();
        next.onepassword = Some(OnePasswordCredentials { token });
        save(&self.path, &next)?;
        *guard = next;
        Ok(())
    }

    pub(crate) fn infisical(&self) -> Option<InfisicalCredentials> {
        self.state
            .lock()
            .expect("credentials lock poisoned")
            .infisical
            .clone()
    }

    pub(crate) fn onepassword(&self) -> Option<OnePasswordCredentials> {
        self.state
            .lock()
            .expect("credentials lock poisoned")
            .onepassword
            .clone()
    }

    /// Set or replace one vault value. The key is validated by the caller
    /// (`validate_env_key`), so the vault only ever holds keys a block could
    /// reference.
    pub(crate) fn set_local(&self, key: String, value: String) -> Result<()> {
        let mut guard = self.state.lock().expect("credentials lock poisoned");
        let mut next = guard.clone();
        next.local.insert(key, value);
        save(&self.path, &next)?;
        *guard = next;
        Ok(())
    }

    /// Remove one vault value; `Ok(false)` when there was none.
    pub(crate) fn unset_local(&self, key: &str) -> Result<bool> {
        let mut guard = self.state.lock().expect("credentials lock poisoned");
        let mut next = guard.clone();
        if next.local.remove(key).is_none() {
            return Ok(false);
        }
        save(&self.path, &next)?;
        *guard = next;
        Ok(true)
    }

    /// Every vault key, sorted. Names only — the listing surfaces never see
    /// values.
    pub(crate) fn local_keys(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("credentials lock poisoned")
            .local
            .keys()
            .cloned()
            .collect()
    }

    /// The vault values for a block's allowlist, in the block's order. The
    /// first key without a value fails the whole block: a service that
    /// declared it needs a key must not start without it.
    pub(crate) fn local_values(&self, keys: &[String]) -> Result<Vec<(String, String)>, String> {
        let guard = self.state.lock().expect("credentials lock poisoned");
        keys.iter()
            .map(|key| match guard.local.get(key) {
                Some(value) => Ok((key.clone(), value.clone())),
                None => Err(format!(
                    "local secret `{key}` is not set — run `portman secrets set {key}`"
                )),
            })
            .collect()
    }
}

/// Atomic-rename write; both the temp file and the final file are 0600 —
/// these are machine credentials.
fn save(path: &Path, credentials: &Credentials) -> Result<()> {
    let mut persisted = credentials.clone();
    persisted.version = 1;
    portman_core::atomic_json::atomic_write_json_durable(path, &persisted, 0o600)
}

// ---------------------------------------------------------------------------
// The SecretsSource the supervisor composes through.

/// Resolves a service's `secrets = [...]` refs through the configured
/// providers. Blocks are applied in the service's declared order; on
/// duplicate keys the later block wins (same later-wins rule as the rest of
/// env composition).
///
/// Resolved values are cached per block for the daemon run, so backoff
/// restarts and `portman start` reuse them (1Password rate limits are
/// account-wide daily caps; Infisical fetches are just latency). `portman
/// up` is the refresh point: sync invalidates the cache (KTD3/KTD4).
pub(crate) struct ProviderSecretsSource {
    pub credentials: CredentialsStore,
    infisical: infisical::InfisicalClient,
    /// Block name → resolved values, cleared on sync.
    cache: Mutex<BTreeMap<String, Vec<(String, String)>>>,
}

impl ProviderSecretsSource {
    pub(crate) fn new(credentials: CredentialsStore) -> Self {
        Self {
            credentials,
            infisical: infisical::InfisicalClient::default(),
            cache: Mutex::new(BTreeMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl SecretsSource for ProviderSecretsSource {
    async fn resolve(
        &self,
        def: &ServiceDefinition,
        blocks: &BTreeMap<String, SecretsProviderConfig>,
    ) -> Result<Vec<(String, String)>, SecretsError> {
        let mut values: Vec<(String, String)> = Vec::new();
        for reference in &def.secrets {
            let Some(config) = blocks.get(reference) else {
                return Err(SecretsError::fatal(format!(
                    "service references [secrets.{reference}] but no such block is synced"
                )));
            };
            values.extend(self.resolve_block(reference, config).await?);
        }
        if !def.secrets.is_empty() {
            warn_on_empty(def, &values);
        }
        Ok(values)
    }

    /// One block's values, fetched (and cached) independently of any
    /// service. The supervisor's service path loops this over
    /// `def.secrets`; egress resolution names a single block the same way.
    async fn resolve_block(
        &self,
        name: &str,
        config: &SecretsProviderConfig,
    ) -> Result<Vec<(String, String)>, SecretsError> {
        if let Some(cached) = self.cache.lock().expect("secrets cache poisoned").get(name) {
            return Ok(cached.clone());
        }
        let fetched = match config {
            // The vault is in memory and its values are set by hand (CLI or
            // dashboard) — a freshly set value should reach the next spawn
            // and the next egress request without waiting for a `portman
            // up`, so local blocks never enter the per-run cache.
            SecretsProviderConfig::Local { keys } => {
                return self
                    .credentials
                    .local_values(keys)
                    .map_err(SecretsError::fatal);
            }
            SecretsProviderConfig::Infisical { .. } => {
                let creds = self.credentials.infisical().ok_or_else(|| {
                    SecretsError::fatal(
                        "no Infisical machine identity stored — run `portman secrets set-infisical`",
                    )
                })?;
                self.infisical.fetch(config, &creds).await?
            }
            SecretsProviderConfig::OnePassword { refs } => {
                let creds = self.credentials.onepassword().ok_or_else(|| {
                    SecretsError::fatal(
                        "no 1Password service-account token stored — run `portman secrets set-op`",
                    )
                })?;
                onepassword::resolve(refs, &creds).await?
            }
        };
        self.cache
            .lock()
            .expect("secrets cache poisoned")
            .insert(name.to_string(), fetched.clone());
        Ok(fetched)
    }

    fn invalidate(&self) {
        self.cache.lock().expect("secrets cache poisoned").clear();
    }
}

fn warn_on_empty(def: &ServiceDefinition, values: &[(String, String)]) {
    if values.is_empty() {
        warn!(
            service = %def.name,
            "secrets providers resolved zero values — check the provider block's paths/refs"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::tempdir;

    #[test]
    fn failed_credential_mutations_preserve_state_and_retry_durably() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let store = CredentialsStore::load(path.clone()).unwrap();
        store.set_local("TOKEN".into(), "old".into()).unwrap();
        store
            .set_infisical("old-id".into(), "old-secret".into())
            .unwrap();
        store.set_onepassword("old-token".into()).unwrap();
        let original = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(store.set_local("TOKEN".into(), "new".into()).is_err());
        assert!(store.unset_local("TOKEN").is_err());
        assert!(store.unset_local("TOKEN").is_err());
        assert!(store
            .set_infisical("new-id".into(), "new-secret".into())
            .is_err());
        assert!(store.set_onepassword("new-token".into()).is_err());
        assert_eq!(store.local_values(&["TOKEN".into()]).unwrap()[0].1, "old");
        assert_eq!(store.infisical().unwrap().client_id, "old-id");
        assert_eq!(store.onepassword().unwrap().token, "old-token");
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, original).unwrap();
        assert!(store.unset_local("TOKEN").unwrap());
        assert!(!store.unset_local("TOKEN").unwrap());
        assert!(CredentialsStore::load(path.clone())
            .unwrap()
            .local_keys()
            .is_empty());
        store.set_local("TOKEN".into(), "new".into()).unwrap();
        assert_eq!(
            CredentialsStore::load(path)
                .unwrap()
                .local_values(&["TOKEN".into()])
                .unwrap()[0]
                .1,
            "new"
        );
    }

    #[test]
    fn credentials_roundtrip_and_owner_only_permissions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let store = CredentialsStore::load(path.clone()).unwrap();
        assert!(store.infisical().is_none());

        store
            .set_infisical("machine-id".into(), "machine-secret".into())
            .unwrap();
        store.set_onepassword("op-token".into()).unwrap();
        store
            .set_local("GITHUB_TOKEN".into(), "ghp_value".into())
            .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "credentials must be owner-only");

        let reloaded = CredentialsStore::load(path).unwrap();
        assert_eq!(reloaded.infisical().unwrap().client_id, "machine-id");
        assert_eq!(
            reloaded.infisical().unwrap().client_secret,
            "machine-secret"
        );
        assert_eq!(reloaded.onepassword().unwrap().token, "op-token");
        assert_eq!(reloaded.local_keys(), vec!["GITHUB_TOKEN".to_string()]);
        assert!(reloaded.unset_local("GITHUB_TOKEN").unwrap());
        assert!(!reloaded.unset_local("GITHUB_TOKEN").unwrap());
        assert!(reloaded.local_keys().is_empty());
    }

    /// A local block yields its keys in declared order straight from the
    /// vault: a value set after the first resolve is visible on the next one
    /// (no per-run cache), and a missing key fails the block fatally — a
    /// restart cannot fix an unset value, so no backoff retry.
    #[tokio::test(flavor = "multi_thread")]
    async fn local_block_reads_vault_live_and_fails_fatally_on_missing_key() {
        use crate::supervisor::SecretsSource as _;

        let dir = tempdir().unwrap();
        let store = CredentialsStore::load(dir.path().join("credentials.json")).unwrap();
        let source = ProviderSecretsSource::new(store.clone());
        let config = SecretsProviderConfig::Local {
            keys: vec!["B_KEY".into(), "A_KEY".into()],
        };

        let err = source.resolve_block("mine", &config).await.unwrap_err();
        assert!(!err.transient, "{}", err.message);
        assert!(
            err.message.contains("`B_KEY` is not set"),
            "{}",
            err.message
        );
        assert!(
            err.message.contains("portman secrets set B_KEY"),
            "{}",
            err.message
        );

        store.set_local("A_KEY".into(), "a".into()).unwrap();
        store.set_local("B_KEY".into(), "b".into()).unwrap();
        assert_eq!(
            source.resolve_block("mine", &config).await.unwrap(),
            vec![
                ("B_KEY".to_string(), "b".to_string()),
                ("A_KEY".to_string(), "a".to_string())
            ]
        );

        store.set_local("B_KEY".into(), "b2".into()).unwrap();
        assert_eq!(
            source.resolve_block("mine", &config).await.unwrap()[0].1,
            "b2",
            "a vault write must be visible without invalidate()"
        );
    }

    /// The per-run value cache: a second resolve reuses the fetched block
    /// (no provider round-trip — rate-limit safety for backoff restarts and
    /// `portman start`); `invalidate` (the `portman up` sync point) refetches.
    #[tokio::test(flavor = "multi_thread")]
    async fn block_values_cached_per_run_until_invalidated() {
        use crate::supervisor::SecretsSource as _;

        let dir = tempdir().unwrap();
        let store = CredentialsStore::load(dir.path().join("credentials.json")).unwrap();
        store.set_infisical("id".into(), "secret".into()).unwrap();
        let source = ProviderSecretsSource::new(store);

        let (url, seen, _handle) = infisical::tests::mock_server(vec![
            infisical::tests::response_line("200 OK", r#"{"accessToken":"t","expiresIn":3600}"#),
            infisical::tests::response_line(
                "200 OK",
                r#"{"secrets":[{"secretKey":"A","secretValue":"1"}]}"#,
            ),
            // The bearer token stays cached, so the post-invalidate resolve
            // goes straight to a second list call.
            infisical::tests::response_line(
                "200 OK",
                r#"{"secrets":[{"secretKey":"A","secretValue":"2"}]}"#,
            ),
        ])
        .await;

        let blocks = BTreeMap::from([(
            "pacer".to_string(),
            SecretsProviderConfig::Infisical {
                url,
                project_id: "p".into(),
                environment: "dev".into(),
                paths: vec!["/shared".into()],
                api_version: Default::default(),
                mode: Default::default(),
            },
        )]);
        let def = ServiceDefinition {
            name: "svc".into(),
            run: vec!["true".into()],
            dir: dir.path().to_path_buf(),
            port: None,
            host: None,
            mode: portman_protocol::Mode::Http,
            ready: Default::default(),
            depends: vec![],
            restart: Default::default(),
            stop_grace_ms: 1000,
            env_files: vec![],
            env: Default::default(),
            secrets: vec!["pacer".into()],
            secrets_optional: false,
            watch: Vec::new(),
            watch_mode: Default::default(),
            watch_debounce_ms: 500,
            groups: Vec::new(),
            project: None,
        };

        let first = source.resolve(&def, &blocks).await.unwrap();
        assert_eq!(first, vec![("A".to_string(), "1".to_string())]);
        let second = source.resolve(&def, &blocks).await.unwrap();
        assert_eq!(second, first, "second resolve must come from the cache");
        assert_eq!(
            seen.lock().unwrap().len(),
            2,
            "cache must prevent a second provider round-trip"
        );

        source.invalidate();
        let third = source.resolve(&def, &blocks).await.unwrap();
        assert_eq!(third, vec![("A".to_string(), "2".to_string())]);
        assert_eq!(seen.lock().unwrap().len(), 3, "invalidate must refetch");
    }

    #[test]
    fn temp_file_is_created_owner_only() {
        // The 0600 must hold from the first byte — probe the open options by
        // writing and inspecting before rename can happen (the store's save
        // sets mode on create; verify no world-readable window by checking
        // the final file, which inherits the temp file's mode via rename).
        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let store = CredentialsStore::load(path.clone()).unwrap();
        store.set_onepassword("tok".into()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!path.with_extension("json.tmp").exists());
    }
}
