//! In-memory registry of hostname → target entries.
//!
//! Both Docker-label-driven and static-rule entries land here. The DNS and
//! HTTP proxy layers (phases 4 and 6) read from the same registry, so they
//! don't know or care which source produced a given entry.
//!
//! Thread-safety: wrapped in an `Arc<RwLock<...>>` under the hood. Readers
//! take a shared lock, writers an exclusive one. Keyed by hostname.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use portman_protocol::Entry;

/// Cloneable handle to the shared registry — all clones point at the same data.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    inner: Arc<RwLock<HashMap<String, Entry>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the entry for `entry.host`. Returns the previous entry, if any.
    pub fn upsert(&self, entry: Entry) -> Option<Entry> {
        self.inner
            .write()
            .expect("registry lock poisoned")
            .insert(entry.host.clone(), entry)
    }

    /// Remove and return the entry for `host`, if present.
    pub fn remove(&self, host: &str) -> Option<Entry> {
        self.inner
            .write()
            .expect("registry lock poisoned")
            .remove(host)
    }

    /// Remove any entries whose `container_id` matches. Used on container
    /// stop/die events where we know the id but not the host the user mapped.
    /// Returns the removed entries.
    pub fn remove_by_container_id(&self, id: &str) -> Vec<Entry> {
        let mut guard = self.inner.write().expect("registry lock poisoned");
        let victims: Vec<String> = guard
            .iter()
            .filter(|(_, e)| e.container_id.as_deref() == Some(id))
            .map(|(k, _)| k.clone())
            .collect();
        victims
            .into_iter()
            .filter_map(|k| guard.remove(&k))
            .collect()
    }

    /// Snapshot of all entries as a `Vec`. The order is not stable across calls.
    pub fn list(&self) -> Vec<Entry> {
        self.inner
            .read()
            .expect("registry lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Look up a single entry by exact hostname. Wildcard entries are only
    /// found by their literal pattern — see [`Registry::lookup`] for resolution.
    pub fn get(&self, host: &str) -> Option<Entry> {
        self.inner
            .read()
            .expect("registry lock poisoned")
            .get(host)
            .cloned()
    }

    /// Resolve `host` the way DNS would, returning the matched key alongside
    /// the entry.
    ///
    /// The key is the registered name — either `host` itself or the wildcard
    /// pattern that covered it. Callers that mint per-name resources (TLS certs
    /// above all) key off *that*, so one `*.demo.test` cert serves every box
    /// instead of one cert per name appearing on first handshake.
    ///
    /// Exact match wins; otherwise the longest matching wildcard, so
    /// `*.demo.acme.internal` beats `*.acme.internal` for a name both
    /// could serve.
    pub fn lookup(&self, host: &str) -> Option<(String, Entry)> {
        let guard = self.inner.read().expect("registry lock poisoned");
        if let Some(entry) = guard.get(host) {
            return Some((host.to_string(), entry.clone()));
        }
        guard
            .iter()
            .filter(|(pattern, _)| crate::static_store::wildcard_matches(pattern, host))
            .max_by_key(|(pattern, _)| pattern.len())
            .map(|(pattern, entry)| (pattern.clone(), entry.clone()))
    }

    /// Number of entries currently tracked.
    pub fn len(&self) -> usize {
        self.inner.read().expect("registry lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Targets claimed by more than one hostname, as `(target, hosts)` sorted by
/// target with hosts sorted within each group.
///
/// The registry is keyed by hostname, so nothing on the write path ever
/// compares targets — two rules pointing at the same `ip:port` are accepted
/// silently. Sometimes that's deliberate (one app, two names). Just as often
/// it's two different apps racing for one port: only one process can bind it,
/// so the loser's hostname quietly serves the winner's app. We report the
/// ambiguity and let the user decide; we never reject an alias.
pub fn target_collisions(entries: &[Entry]) -> Vec<(String, Vec<String>)> {
    let mut by_target: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
    for e in entries {
        by_target
            .entry(e.target.as_str())
            .or_default()
            .push(e.host.as_str());
    }
    by_target
        .into_iter()
        .filter(|(_, hosts)| hosts.len() > 1)
        .map(|(target, mut hosts)| {
            hosts.sort_unstable();
            (
                target.to_string(),
                hosts.into_iter().map(str::to_string).collect(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use portman_protocol::Source;

    fn container(host: &str, id: &str) -> Entry {
        Entry {
            host: host.into(),
            target: "10.0.0.5:80".into(),
            source: Source::Container,
            mode: portman_protocol::Mode::Http,
            container_id: Some(id.into()),
            project: None,
            egress: None,
        }
    }

    #[test]
    fn upsert_and_list() {
        let r = Registry::new();
        r.upsert(container("a.test", "aaa"));
        r.upsert(container("b.test", "bbb"));
        let mut hosts: Vec<String> = r.list().into_iter().map(|e| e.host).collect();
        hosts.sort();
        assert_eq!(hosts, vec!["a.test", "b.test"]);
    }

    #[test]
    fn upsert_replaces_same_host() {
        let r = Registry::new();
        r.upsert(container("a.test", "old"));
        r.upsert(container("a.test", "new"));
        assert_eq!(r.len(), 1);
        assert_eq!(r.get("a.test").unwrap().container_id.unwrap(), "new");
    }

    #[test]
    fn remove_by_container_id_removes_all_matching() {
        let r = Registry::new();
        r.upsert(container("a.test", "abc"));
        r.upsert(container("b.test", "xyz"));
        r.upsert(container("c.test", "abc")); // edge: same id, two hosts
        let removed = r.remove_by_container_id("abc");
        assert_eq!(removed.len(), 2);
        assert_eq!(r.len(), 1);
        assert!(r.get("b.test").is_some());
    }

    #[test]
    fn remove_by_host_returns_entry() {
        let r = Registry::new();
        r.upsert(container("a.test", "abc"));
        assert!(r.remove("a.test").is_some());
        assert!(r.remove("a.test").is_none());
    }

    fn at(host: &str, target: &str) -> Entry {
        Entry {
            host: host.into(),
            target: target.into(),
            source: Source::Static,
            mode: portman_protocol::Mode::Http,
            container_id: None,
            project: None,
            egress: None,
        }
    }

    #[test]
    fn wildcard_covers_one_label_only() {
        let r = Registry::new();
        r.upsert(at("*.demo.test", "127.0.0.1:3070"));

        assert_eq!(
            r.lookup("1.demo.test").map(|(k, _)| k),
            Some("*.demo.test".to_string())
        );
        // The apex is a different name, and a wildcard cert wouldn't cover it.
        assert!(r.lookup("demo.test").is_none());
        // Two labels deep is likewise out of scope for one `*`.
        assert!(r.lookup("a.b.demo.test").is_none());
    }

    #[test]
    fn exact_entry_beats_a_wildcard_that_would_also_match() {
        let r = Registry::new();
        r.upsert(at("*.demo.test", "127.0.0.1:3070"));
        r.upsert(at("1.demo.test", "127.0.0.1:9999"));

        let (key, entry) = r.lookup("1.demo.test").unwrap();
        assert_eq!(key, "1.demo.test");
        assert_eq!(entry.target, "127.0.0.1:9999");
    }

    #[test]
    fn longest_matching_wildcard_wins() {
        let r = Registry::new();
        r.upsert(at("*.test", "127.0.0.1:1111"));
        r.upsert(at("*.demo.test", "127.0.0.1:3070"));

        let (key, entry) = r.lookup("1.demo.test").unwrap();
        assert_eq!(key, "*.demo.test");
        assert_eq!(entry.target, "127.0.0.1:3070");
    }

    #[test]
    fn get_stays_an_exact_lookup() {
        // `get` is how callers address the pattern itself (removal, cert
        // bookkeeping); only `lookup` resolves names through it.
        let r = Registry::new();
        r.upsert(at("*.demo.test", "127.0.0.1:3070"));

        assert!(r.get("1.demo.test").is_none());
        assert!(r.get("*.demo.test").is_some());
    }

    #[test]
    fn target_collisions_groups_hosts_sharing_a_target() {
        let entries = vec![
            at("crm.acme", "127.0.0.1:3070"),
            at("app.acme", "127.0.0.1:3050"),
            at("1.demo.acme", "127.0.0.1:3070"),
            at("b.test", "127.0.0.1:3080"),
            at("a.test", "127.0.0.1:3080"),
        ];
        assert_eq!(
            target_collisions(&entries),
            vec![
                (
                    "127.0.0.1:3070".to_string(),
                    vec!["1.demo.acme".to_string(), "crm.acme".to_string()]
                ),
                (
                    "127.0.0.1:3080".to_string(),
                    vec!["a.test".to_string(), "b.test".to_string()]
                ),
            ]
        );
    }

    #[test]
    fn target_collisions_ignores_distinct_targets() {
        let entries = vec![
            at("a.test", "127.0.0.1:3000"),
            at("b.test", "127.0.0.1:3001"),
        ];
        assert!(target_collisions(&entries).is_empty());
    }

    #[test]
    fn target_collisions_treats_different_ips_on_one_port_as_distinct() {
        // Same port on two container IPs is not a collision — each container
        // binds its own stack.
        let entries = vec![at("a.test", "10.0.0.5:3000"), at("b.test", "10.0.0.6:3000")];
        assert!(target_collisions(&entries).is_empty());
    }
}
