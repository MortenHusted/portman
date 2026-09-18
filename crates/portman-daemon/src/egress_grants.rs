//! Host-controller grants. The store contains digests, never bearer tokens.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Grant {
    host: String,
    route_identity: String,
    revoked: bool,
    token_sha256: String,
    expires_at: u64,
}

// None is a terminal tombstone, including revoke-before-issue.
type Records = BTreeMap<String, Option<Grant>>;

pub(crate) struct GrantStore {
    path: PathBuf,
    gate: Mutex<()>,
}

impl GrantStore {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            gate: Mutex::new(()),
        }
    }

    fn read(&self) -> Result<Records> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("invalid egress grant store"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(err) => Err(err).context("reading egress grant store"),
        }
    }

    fn write(&self, records: &Records) -> Result<()> {
        portman_core::atomic_json::atomic_write_json_with_mode(&self.path, records, 0o600)
    }

    pub(crate) fn issue(
        &self,
        id: String,
        host: String,
        digest: String,
        expires_at: u64,
        route_identity: String,
    ) -> Result<()> {
        validate_id(&id)?;
        let host = portman_core::static_store::validate_host(&host)?;
        if host.contains('*') {
            bail!("grants require an exact route host");
        }
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            bail!("token_sha256 must be a lowercase SHA-256 hex digest");
        }
        let _guard = self.gate.lock().expect("grant lock poisoned");
        let mut records = self.read()?;
        let grant = Grant {
            host,
            token_sha256: digest,
            expires_at,
            route_identity,
            revoked: false,
        };
        if let Some(existing) = records.get(&id) {
            if existing.as_ref() == Some(&grant) {
                return Ok(());
            }
            bail!("grant ID already exists or was revoked");
        }
        if expires_at <= crate::now_unix_ms() / 1000 {
            bail!("grant expiry must be in the future");
        }
        // Reusing a bearer across hosts would silently broaden its authority.
        if records
            .values()
            .flatten()
            .any(|g| g.token_sha256 == grant.token_sha256)
        {
            bail!("bearer digest is already assigned to a grant");
        }
        records.insert(id, Some(grant));
        self.write(&records)
    }

    pub(crate) fn revoke(&self, id: String) -> Result<()> {
        validate_id(&id)?;
        let _guard = self.gate.lock().expect("grant lock poisoned");
        let mut records = self.read()?;
        match records.get_mut(&id) {
            Some(Some(grant)) => grant.revoked = true,
            _ => {
                records.insert(id, None);
            }
        }
        self.write(&records)
    }

    pub(crate) fn permits(
        &self,
        host: &str,
        route: &str,
        headers: &[(String, String)],
        now: u64,
    ) -> bool {
        if headers.iter().any(|(name, _)| {
            ["proxy-authorization", "x-api-key", "api-key"]
                .iter()
                .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
        }) {
            return false;
        }
        let mut auth = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"));
        let Some((_, value)) = auth.next() else {
            return false;
        };
        if auth.next().is_some() {
            return false;
        }
        let Some(token) = value.strip_prefix("Bearer ") else {
            return false;
        };
        if !(32..=512).contains(&token.len())
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        {
            return false;
        }
        let digest = hex::encode(Sha256::digest(token.as_bytes()));
        let _guard = self.gate.lock().expect("grant lock poisoned");
        let Ok(records) = self.read() else {
            return false;
        };
        records.values().flatten().any(|g| {
            !g.revoked
                && g.route_identity == route
                && g.host == host
                && now < g.expires_at
                && bool::from(g.token_sha256.as_bytes().ct_eq(digest.as_bytes()))
        })
    }
}

pub(crate) fn route_identity(target: &str, spec: &portman_protocol::EgressSpec) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&(target, spec)).expect("serializing route identity"),
    ))
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        bail!("grant ID must contain 1–128 letters, digits, hyphens or underscores");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const TOKEN: &str = "synthetic-token-0123456789abcdef0123456789";
    fn headers() -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Bearer {TOKEN}"))]
    }
    fn issue(store: &GrantStore, id: &str, expires: u64) -> Result<()> {
        store.issue(
            id.into(),
            "qwen.localhost".into(),
            hex::encode(Sha256::digest(TOKEN)),
            expires,
            "route-v1".into(),
        )
    }
    #[test]
    fn scoped_expiring_idempotent_and_terminal_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let store = GrantStore::new(path.clone());
        let now = crate::now_unix_ms() / 1000;
        issue(&store, "run-1", now + 60).unwrap();
        issue(&store, "run-1", now + 60).unwrap();
        assert!(store.permits("qwen.localhost", "route-v1", &headers(), now));
        assert!(!store.permits("qwen.localhost", "changed-route", &headers(), now));
        assert!(!store.permits("other.localhost", "route-v1", &headers(), now));
        assert!(!store.permits("qwen.localhost", "route-v1", &headers(), now + 60));
        assert!(!store.permits("qwen.localhost", "route-v1", &[], now));
        let mut duplicate = headers();
        duplicate.extend(headers());
        assert!(!store.permits("qwen.localhost", "route-v1", &duplicate, now));
        assert!(issue(&store, "run-1", now + 90).is_err());
        assert!(!std::fs::read_to_string(&path).unwrap().contains(TOKEN));
        store.revoke("run-1".into()).unwrap();
        let reloaded = GrantStore::new(path);
        assert!(!reloaded.permits("qwen.localhost", "route-v1", &headers(), now));
        assert!(issue(&reloaded, "run-1", now + 60).is_err());
        reloaded.revoke("run-2".into()).unwrap();
        assert!(issue(&reloaded, "run-2", now + 60).is_err());
    }
    #[test]
    fn corrupt_store_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        std::fs::write(&path, "broken").unwrap();
        let store = GrantStore::new(path);
        assert!(!store.permits("qwen.localhost", "route-v1", &headers(), 0));
        assert!(store.revoke("run-1".into()).is_err());
    }
}
