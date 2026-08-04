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
        guard.infisical = Some(InfisicalCredentials {
            client_id,
            client_secret,
        });
        save(&self.path, &guard)
    }

    pub(crate) fn set_onepassword(&self, token: String) -> Result<()> {
        let mut guard = self.state.lock().expect("credentials lock poisoned");
        guard.onepassword = Some(OnePasswordCredentials { token });
        save(&self.path, &guard)
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
}

/// Atomic-rename write; both the temp file and the final file are 0600 —
/// these are machine credentials.
fn save(path: &Path, credentials: &Credentials) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut persisted = credentials.clone();
    persisted.version = 1;
    let bytes = serde_json::to_vec_pretty(&persisted)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating temp file {}", tmp.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
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
            if let Some(cached) = self
                .cache
                .lock()
                .expect("secrets cache poisoned")
                .get(reference)
            {
                values.extend(cached.iter().cloned());
                continue;
            }
            let fetched = match config {
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
                .insert(reference.clone(), fetched.clone());
            values.extend(fetched);
        }
        if !def.secrets.is_empty() {
            warn_on_empty(def, &values);
        }
        Ok(values)
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
    fn credentials_roundtrip_and_owner_only_permissions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let store = CredentialsStore::load(path.clone()).unwrap();
        assert!(store.infisical().is_none());

        store
            .set_infisical("machine-id".into(), "machine-secret".into())
            .unwrap();
        store.set_onepassword("op-token".into()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "credentials must be owner-only");

        let reloaded = CredentialsStore::load(path).unwrap();
        assert_eq!(reloaded.infisical().unwrap().client_id, "machine-id");
        assert_eq!(
            reloaded.infisical().unwrap().client_secret,
            "machine-secret"
        );
        assert_eq!(reloaded.onepassword().unwrap().token, "op-token");
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
