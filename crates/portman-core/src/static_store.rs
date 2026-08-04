//! Persistent store for user-managed static host rules.
//!
//! Written to `~/Library/Application Support/portman/static.json` as a
//! versioned JSON document. Mutations hold an internal lock and perform an
//! atomic rename write so a crashed daemon never leaves a half-written file.
//!
//! Container-sourced entries never touch this store; they live only in the
//! in-memory registry and come back from the docker socket on demand.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use portman_protocol::Mode;
use serde::{Deserialize, Serialize};

/// Per-rule persisted payload. Kept as a struct (not a bare string) so we can
/// grow new fields — `mode` first, `service` second — without another schema
/// bump.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Rule {
    target: String,
    #[serde(default)]
    mode: Mode,
    /// Service-runner mapping (e.g. a pitchfork daemon id). Drives
    /// `StartService` for hosts whose process isn't a Docker container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    /// Project tag for UI grouping/filtering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project: Option<String>,
}

/// On-disk schema. `version` lets us migrate without breaking reads — the
/// v1 format (a `BTreeMap<String, String>`) is accepted transparently.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Persisted {
    version: u32,
    entries: BTreeMap<String, Rule>,
}

impl Default for Persisted {
    fn default() -> Self {
        Self {
            version: 2,
            entries: BTreeMap::new(),
        }
    }
}

/// v1 on-disk shape — pre-mode. Read-compat only; we write v2.
#[derive(Debug, Clone, Deserialize)]
struct PersistedV1 {
    #[allow(dead_code)]
    version: u32,
    entries: BTreeMap<String, String>,
}

/// Static host rule store. Thread-safe via an internal mutex; clone the `Arc`
/// the caller holds to share it.
#[derive(Debug)]
pub struct StaticStore {
    path: PathBuf,
    state: Mutex<Persisted>,
}

impl StaticStore {
    /// Load from `path`, creating an empty store if the file does not exist.
    /// Accepts both v1 (`{host: "ip:port"}`) and v2 (`{host: {target, mode}}`)
    /// on-disk shapes. v1 loads are written back as v2 on the next `add` /
    /// `remove` — we don't force a migration-on-read.
    pub fn load(path: PathBuf) -> Result<Self> {
        let state = match fs::read(&path) {
            Ok(bytes) => {
                parse_persisted(&bytes).with_context(|| format!("parsing {}", path.display()))?
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Persisted::default(),
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    /// Current rules as `(host, target, mode)` tuples, host-sorted.
    pub fn list(&self) -> Vec<(String, String, Mode, Option<String>)> {
        self.state
            .lock()
            .expect("static store lock poisoned")
            .entries
            .iter()
            .map(|(h, r)| (h.clone(), r.target.clone(), r.mode, r.project.clone()))
            .collect()
    }

    /// Insert or replace the rule. Returns the previous (target, mode) if any.
    /// A replace takes `service` as given — re-adding without one clears any
    /// existing mapping (plain upsert semantics, no field-level merging).
    pub fn add(
        &self,
        host: String,
        target: String,
        mode: Mode,
        service: Option<String>,
        project: Option<String>,
    ) -> Result<Option<(String, Mode)>> {
        // Mutate a clone, persist it, then swap — if the disk write fails,
        // memory keeps matching disk instead of silently diverging until the
        // next successful save commits the earlier failed change.
        let mut guard = self.state.lock().expect("static store lock poisoned");
        let mut next = guard.clone();
        let prev = next
            .entries
            .insert(
                host,
                Rule {
                    target,
                    mode,
                    service,
                    project,
                },
            )
            .map(|r| (r.target, r.mode));
        crate::atomic_json::atomic_write_json(&self.path, &next)?;
        *guard = next;
        Ok(prev)
    }

    /// The rule for `host`, if any, as `(target, mode, project)`.
    pub fn get(&self, host: &str) -> Option<(String, Mode, Option<String>)> {
        self.state
            .lock()
            .expect("static store lock poisoned")
            .entries
            .get(host)
            .map(|r| (r.target.clone(), r.mode, r.project.clone()))
    }

    /// The service-runner mapping for `host`, if its rule has one.
    pub fn service_for(&self, host: &str) -> Option<String> {
        self.state
            .lock()
            .expect("static store lock poisoned")
            .entries
            .get(host)
            .and_then(|r| r.service.clone())
    }

    /// Remove and return the rule, if present.
    pub fn remove(&self, host: &str) -> Result<Option<(String, Mode)>> {
        let mut guard = self.state.lock().expect("static store lock poisoned");
        let mut next = guard.clone();
        let removed = next.entries.remove(host).map(|r| (r.target, r.mode));
        if removed.is_some() {
            crate::atomic_json::atomic_write_json(&self.path, &next)?;
            *guard = next;
        }
        Ok(removed)
    }
}

/// Accept either v2 (`Persisted`) or v1 (`PersistedV1`) on-disk shape.
/// v1 rules get `Mode::Http` by default.
fn parse_persisted(bytes: &[u8]) -> Result<Persisted> {
    if let Ok(v2) = serde_json::from_slice::<Persisted>(bytes) {
        return Ok(v2);
    }
    let v1: PersistedV1 = serde_json::from_slice(bytes)?;
    Ok(Persisted {
        version: 2,
        entries: v1
            .entries
            .into_iter()
            .map(|(h, t)| {
                (
                    h,
                    Rule {
                        target: t,
                        mode: Mode::Http,
                        service: None,
                        project: None,
                    },
                )
            })
            .collect(),
    })
}

/// Parse and validate a `host` string (CLI-facing). Accepts DNS-style names,
/// lowercase, no whitespace, with at least one dot. Returns the normalized
/// form or a descriptive error.
pub fn validate_host(host: &str) -> Result<String> {
    let h = host.trim();
    if h.is_empty() {
        bail!("host cannot be empty");
    }
    if h.chars().any(char::is_whitespace) {
        bail!("host cannot contain whitespace");
    }
    if !h.contains('.') {
        bail!("host must contain at least one dot (e.g. crm.test)");
    }
    if h.starts_with('.') || h.ends_with('.') {
        bail!("host cannot start or end with a dot");
    }
    // Wildcards follow DNS/RFC 6125: a single `*` as the whole leftmost label
    // and nowhere else. Anything looser would make routing and TLS disagree,
    // since a cert can only ever cover the one-label form.
    if h.contains('*') {
        let rest = h.strip_prefix("*.").ok_or_else(|| {
            anyhow::anyhow!(
                "`*` is only valid as the whole leftmost label (e.g. *.demo.test), got `{h}`"
            )
        })?;
        if rest.contains('*') {
            bail!("only one `*` label is allowed, got `{h}`");
        }
        if !rest.contains('.') {
            bail!("wildcard needs a domain under it (e.g. *.demo.test), got `{h}`");
        }
    }
    Ok(h.to_ascii_lowercase())
}

/// Is `host` a wildcard pattern rather than a concrete name?
pub fn is_wildcard_host(host: &str) -> bool {
    host.starts_with("*.")
}

/// Does `name` fall under wildcard `pattern`?
///
/// One label, exactly — `*.demo.test` covers `1.demo.test` but neither the
/// apex `demo.test` nor a deeper `a.b.demo.test`. Same rule browsers apply
/// to a wildcard cert, so a name that routes is a name the cert covers.
pub fn wildcard_matches(pattern: &str, name: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix('*') else {
        return false;
    };
    // `suffix` keeps its leading dot, so the label boundary is built in.
    let Some(label) = name.strip_suffix(suffix) else {
        return false;
    };
    !label.is_empty() && !label.contains('.')
}

/// Validate a service-runner id (e.g. a pitchfork daemon id like
/// `acme/web`). Deliberately strict — the id is later handed to a process
/// spawn, so the character set stays boring even though the spawn path also
/// passes it as a discrete argv element.
pub fn validate_service(service: &str) -> Result<String> {
    let s = service.trim();
    if s.is_empty() {
        bail!("service cannot be empty");
    }
    if s.len() > 128 {
        bail!("service id is too long (max 128 chars)");
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | ':'))
    {
        bail!("service may only contain letters, digits, and . _ / - :");
    }
    Ok(s.to_string())
}

/// Parse and validate a `target` as `host-or-ip:port`. Returns the normalized form.
pub fn validate_target(target: &str) -> Result<String> {
    let t = target.trim();
    let (host, port) = t
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("target must be host:port (e.g. 127.0.0.1:3000)"))?;
    if host.is_empty() {
        bail!("target host cannot be empty");
    }
    if host.chars().any(char::is_whitespace) {
        bail!("target host cannot contain whitespace");
    }
    port.parse::<u16>()
        .with_context(|| format!("target port `{port}` is not a valid u16"))?;
    Ok(t.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn add_remove_roundtrip_persisted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("static.json");
        let store = StaticStore::load(path.clone()).unwrap();
        assert!(store.list().is_empty());

        store
            .add(
                "crm.acme".into(),
                "127.0.0.1:3070".into(),
                Mode::Http,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            store.list(),
            vec![("crm.acme".into(), "127.0.0.1:3070".into(), Mode::Http, None)]
        );

        // Reload and confirm persistence.
        let store2 = StaticStore::load(path.clone()).unwrap();
        assert_eq!(
            store2.list(),
            vec![("crm.acme".into(), "127.0.0.1:3070".into(), Mode::Http, None)]
        );

        let removed = store2.remove("crm.acme").unwrap();
        assert_eq!(removed, Some(("127.0.0.1:3070".into(), Mode::Http)));
        assert!(store2.list().is_empty());
    }

    #[test]
    fn add_replaces_existing_returns_previous() {
        let dir = tempdir().unwrap();
        let store = StaticStore::load(dir.path().join("static.json")).unwrap();
        store
            .add(
                "a.test".into(),
                "10.0.0.1:80".into(),
                Mode::Http,
                None,
                None,
            )
            .unwrap();
        let prev = store
            .add(
                "a.test".into(),
                "10.0.0.2:80".into(),
                Mode::Http,
                None,
                None,
            )
            .unwrap();
        assert_eq!(prev, Some(("10.0.0.1:80".into(), Mode::Http)));
        assert_eq!(
            store.list(),
            vec![("a.test".into(), "10.0.0.2:80".into(), Mode::Http, None)]
        );
    }

    #[test]
    fn remove_missing_returns_none() {
        let dir = tempdir().unwrap();
        let store = StaticStore::load(dir.path().join("static.json")).unwrap();
        assert!(store.remove("nope.test").unwrap().is_none());
    }

    #[test]
    fn tcp_mode_roundtrips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("static.json");
        let store = StaticStore::load(path.clone()).unwrap();
        store
            .add(
                "db.acme".into(),
                "172.17.0.2:5432".into(),
                Mode::Tcp,
                None,
                None,
            )
            .unwrap();

        let store2 = StaticStore::load(path).unwrap();
        assert_eq!(
            store2.list(),
            vec![("db.acme".into(), "172.17.0.2:5432".into(), Mode::Tcp, None)]
        );
    }

    #[test]
    fn service_mapping_roundtrips_and_clears_on_plain_readd() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("static.json");
        let store = StaticStore::load(path.clone()).unwrap();
        store
            .add(
                "crm.acme".into(),
                "127.0.0.1:3070".into(),
                Mode::Http,
                Some("acme/web".into()),
                None,
            )
            .unwrap();

        let store2 = StaticStore::load(path).unwrap();
        assert_eq!(store2.service_for("crm.acme"), Some("acme/web".into()));
        assert_eq!(store2.service_for("other.acme"), None);

        store2
            .add(
                "crm.acme".into(),
                "127.0.0.1:3070".into(),
                Mode::Http,
                None,
                None,
            )
            .unwrap();
        assert_eq!(store2.service_for("crm.acme"), None);
    }

    #[test]
    fn validate_service_accepts_ids_and_rejects_shell_noise() {
        assert_eq!(validate_service("acme/web").unwrap(), "acme/web");
        assert_eq!(validate_service(" api-2.main ").unwrap(), "api-2.main");
        assert!(validate_service("").is_err());
        assert!(validate_service("a b").is_err());
        assert!(validate_service("x;rm -rf").is_err());
        assert!(validate_service(&"x".repeat(129)).is_err());
    }

    #[test]
    fn v1_on_disk_shape_loads_as_http() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("static.json");
        let legacy = r#"{"version":1,"entries":{"old.test":"127.0.0.1:3000"}}"#;
        std::fs::write(&path, legacy).unwrap();
        let store = StaticStore::load(path).unwrap();
        assert_eq!(
            store.list(),
            vec![("old.test".into(), "127.0.0.1:3000".into(), Mode::Http, None)]
        );
    }

    #[test]
    fn validate_host_rejects_empty_and_whitespace() {
        assert!(validate_host("").is_err());
        assert!(validate_host("foo bar.test").is_err());
        assert!(validate_host("nodot").is_err());
        assert!(validate_host(".leading.test").is_err());
        assert!(validate_host("trailing.test.").is_err());
        assert_eq!(validate_host("Crm.Test").unwrap(), "crm.test");
    }

    #[test]
    fn validate_host_accepts_a_leftmost_wildcard_label_only() {
        assert_eq!(
            validate_host("*.demo.test").unwrap(),
            "*.demo.test".to_string()
        );
        // Anything a wildcard cert couldn't express is refused up front, so
        // routing never promises a name TLS can't serve.
        assert!(validate_host("*").is_err());
        assert!(validate_host("*.test").is_err());
        assert!(validate_host("*foo.test").is_err());
        assert!(validate_host("a.*.test").is_err());
        assert!(validate_host("*.*.test").is_err());
    }

    #[test]
    fn wildcard_matching_consumes_exactly_one_label() {
        assert!(wildcard_matches("*.demo.test", "1.demo.test"));
        assert!(!wildcard_matches("*.demo.test", "demo.test"));
        assert!(!wildcard_matches("*.demo.test", "a.b.demo.test"));
        assert!(!wildcard_matches("*.demo.test", "1.other.test"));
        // A concrete pattern never matches anything but itself, and that is
        // `get`'s job rather than this one's.
        assert!(!wildcard_matches("1.demo.test", "1.demo.test"));
    }

    #[test]
    fn wildcard_hosts_are_recognisable() {
        assert!(is_wildcard_host("*.demo.test"));
        assert!(!is_wildcard_host("1.demo.test"));
    }

    #[test]
    fn validate_target_requires_port() {
        assert!(validate_target("127.0.0.1").is_err());
        assert!(validate_target("127.0.0.1:").is_err());
        assert!(validate_target("127.0.0.1:notaport").is_err());
        assert!(validate_target("127.0.0.1:70000").is_err());
        assert_eq!(
            validate_target("  127.0.0.1:3000  ").unwrap(),
            "127.0.0.1:3000"
        );
    }
}
