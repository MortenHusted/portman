//! Host-controller grants. The store contains digests, never bearer tokens.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

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
#[derive(Default, Serialize, Deserialize)]
struct Records {
    observed_unix: u64,
    grants: BTreeMap<String, Option<Grant>>,
}

trait Clock: Send + Sync {
    fn unix_secs(&self) -> u64;
    fn monotonic(&self) -> Instant;
}

struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        crate::now_unix_ms() / 1000
    }
    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}

pub(crate) struct GrantStore {
    path: PathBuf,
    gate: Mutex<()>,
    clock: Arc<dyn Clock>,
    started_at: (u64, Instant),
}

impl GrantStore {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self::with_clock(path, Arc::new(SystemClock))
    }

    fn with_clock(path: PathBuf, clock: Arc<dyn Clock>) -> Self {
        Self {
            path,
            gate: Mutex::new(()),
            started_at: (clock.unix_secs(), clock.monotonic()),
            clock,
        }
    }

    fn read(&self) -> Result<Records> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("invalid egress grant store"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Records::default()),
            Err(err) => Err(err).context("reading egress grant store"),
        }
    }

    fn write(&self, records: &Records) -> Result<()> {
        portman_core::atomic_json::atomic_write_json_durable(&self.path, records, 0o600)
    }

    fn observe(&self, _gate: &MutexGuard<'_, ()>, records: &mut Records) -> Result<u64> {
        // Monotonic before wall, the reverse of `started_at`. In this order
        // the floor cannot pass `now` unless the wall clock went back.
        let since_start = self.clock.monotonic().duration_since(self.started_at.1);
        let now = self.clock.unix_secs();
        let monotonic_floor = self.started_at.0.saturating_add(since_start.as_secs());
        let floor = records.observed_unix.max(monotonic_floor);
        if now < floor {
            bail!("clock rollback: egress grants unavailable until time recovers");
        }
        if now > records.observed_unix {
            records.observed_unix = now;
            self.write(records)?;
        }
        Ok(now)
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
        let gate = self.gate.lock().expect("grant lock poisoned");
        let mut records = self.read()?;
        let now = self.observe(&gate, &mut records)?;
        let grant = Grant {
            host,
            token_sha256: digest,
            expires_at,
            route_identity,
            revoked: false,
        };
        if let Some(existing) = records.grants.get(&id) {
            if existing.as_ref() == Some(&grant) {
                return Ok(());
            }
            bail!("grant ID already exists or was revoked");
        }
        if expires_at <= now {
            bail!("grant expiry must be in the future");
        }
        // Reusing a bearer across hosts would silently broaden its authority.
        if records
            .grants
            .values()
            .flatten()
            .any(|g| g.token_sha256 == grant.token_sha256)
        {
            bail!("bearer digest is already assigned to a grant");
        }
        records.grants.insert(id, Some(grant));
        self.write(&records)
    }

    pub(crate) fn revoke(&self, id: String) -> Result<()> {
        validate_id(&id)?;
        let _guard = self.gate.lock().expect("grant lock poisoned");
        let mut records = self.read()?;
        match records.grants.get_mut(&id) {
            Some(Some(grant)) => grant.revoked = true,
            _ => {
                records.grants.insert(id, None);
            }
        }
        self.write(&records)
    }

    pub(crate) fn permits(&self, host: &str, route: &str, headers: &[(String, String)]) -> bool {
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
        let gate = self.gate.lock().expect("grant lock poisoned");
        let Ok(mut records) = self.read() else {
            return false;
        };
        let Ok(now) = self.observe(&gate, &mut records) else {
            return false;
        };
        records.grants.values().flatten().any(|g| {
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
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;
    const TOKEN: &str = "synthetic-token-0123456789abcdef0123456789";
    fn headers() -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Bearer {TOKEN}"))]
    }
    const OTHER_TOKEN: &str = "synthetic-other-0123456789abcdef0123456789";
    fn issue(store: &GrantStore, id: &str, expires: u64) -> Result<()> {
        issue_token(store, id, TOKEN, expires)
    }
    fn issue_token(store: &GrantStore, id: &str, token: &str, expires: u64) -> Result<()> {
        store.issue(
            id.into(),
            "qwen.localhost".into(),
            hex::encode(Sha256::digest(token)),
            expires,
            "route-v1".into(),
        )
    }
    const START: u64 = 1_800_000_000;
    struct TestClock {
        started: Instant,
        wall: AtomicU64,
        monotonic_secs: AtomicU64,
    }
    impl TestClock {
        fn at(wall: u64) -> Arc<Self> {
            Arc::new(Self {
                started: Instant::now(),
                wall: AtomicU64::new(wall),
                monotonic_secs: AtomicU64::new(0),
            })
        }
        fn advance(&self, secs: u64) {
            self.wall.fetch_add(secs, Ordering::Relaxed);
            self.monotonic_secs.fetch_add(secs, Ordering::Relaxed);
        }
        fn roll_wall_back_to(&self, wall: u64) {
            self.wall.store(wall, Ordering::Relaxed);
        }
    }
    impl Clock for TestClock {
        fn unix_secs(&self) -> u64 {
            self.wall.load(Ordering::Relaxed)
        }
        fn monotonic(&self) -> Instant {
            self.started + Duration::from_secs(self.monotonic_secs.load(Ordering::Relaxed))
        }
    }
    #[test]
    fn scoped_expiring_idempotent_and_terminal_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let clock = TestClock::at(START);
        let store = GrantStore::with_clock(path.clone(), clock.clone());
        issue(&store, "run-1", START + 60).unwrap();
        issue(&store, "run-1", START + 60).unwrap();
        assert!(store.permits("qwen.localhost", "route-v1", &headers()));
        assert!(!store.permits("qwen.localhost", "changed-route", &headers()));
        assert!(!store.permits("other.localhost", "route-v1", &headers()));
        assert!(!store.permits("qwen.localhost", "route-v1", &[]));
        let mut duplicate = headers();
        duplicate.extend(headers());
        assert!(!store.permits("qwen.localhost", "route-v1", &duplicate));
        assert!(issue(&store, "run-1", START + 90).is_err());
        assert!(!std::fs::read_to_string(&path).unwrap().contains(TOKEN));
        clock.advance(59);
        assert!(store.permits("qwen.localhost", "route-v1", &headers()));
        clock.advance(1);
        assert!(!store.permits("qwen.localhost", "route-v1", &headers()));
        store.revoke("run-2".into()).unwrap();
        let reloaded = GrantStore::with_clock(path, clock);
        assert!(issue_token(&reloaded, "run-2", OTHER_TOKEN, START + 120).is_err());
    }
    #[test]
    fn revoked_grant_is_denied_and_cannot_be_issued_again_before_it_expires() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let clock = TestClock::at(START);
        let store = GrantStore::with_clock(path.clone(), clock.clone());
        issue(&store, "run-1", START + 3600).unwrap();
        assert!(store.permits("qwen.localhost", "route-v1", &headers()));
        store.revoke("run-1".into()).unwrap();
        assert!(!store.permits("qwen.localhost", "route-v1", &headers()));
        assert!(issue(&store, "run-1", START + 3600).is_err());
        let reloaded = GrantStore::with_clock(path, clock);
        assert!(!reloaded.permits("qwen.localhost", "route-v1", &headers()));
        assert!(issue(&reloaded, "run-1", START + 3600).is_err());
    }
    #[test]
    fn concurrent_callers_keep_a_valid_grant_while_the_clock_advances() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::at(START);
        let store = Arc::new(GrantStore::with_clock(
            dir.path().join("grants.json"),
            clock.clone(),
        ));
        issue(&store, "run-1", START + 3600).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let denied = Arc::new(AtomicUsize::new(0));
        let callers: Vec<_> = (0..8)
            .map(|_| {
                let (store, done, denied) = (store.clone(), done.clone(), denied.clone());
                std::thread::spawn(move || {
                    while !done.load(Ordering::Relaxed) {
                        if !store.permits("qwen.localhost", "route-v1", &headers()) {
                            denied.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(2));
            clock.advance(1);
        }
        done.store(true, Ordering::Relaxed);
        for caller in callers {
            caller.join().unwrap();
        }
        assert_eq!(denied.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn corrupt_store_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        std::fs::write(&path, "broken").unwrap();
        let store = GrantStore::new(path);
        assert!(!store.permits("qwen.localhost", "route-v1", &headers()));
        assert!(store.revoke("run-1".into()).is_err());
    }
    #[test]
    fn clock_rollback_cannot_reactivate_expired_grants_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let clock = TestClock::at(START);
        let store = GrantStore::with_clock(path.clone(), clock.clone());
        issue(&store, "clock-test", START + 60).unwrap();
        assert!(store.permits("qwen.localhost", "route-v1", &headers()));
        clock.advance(60);
        assert!(!store.permits("qwen.localhost", "route-v1", &headers()));
        clock.roll_wall_back_to(START);
        assert!(!store.permits("qwen.localhost", "route-v1", &headers()));
        let reloaded = GrantStore::with_clock(path, TestClock::at(START));
        assert!(!reloaded.permits("qwen.localhost", "route-v1", &headers()));
        assert!(issue(&reloaded, "new-run", START + 120).is_err());
        reloaded.revoke("clock-test".into()).unwrap();
    }
    #[test]
    fn wall_clock_set_back_while_running_denies_a_live_grant_until_time_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::at(START);
        let store = GrantStore::with_clock(dir.path().join("grants.json"), clock.clone());
        issue(&store, "run-1", START + 7200).unwrap();
        clock.advance(3600);
        clock.roll_wall_back_to(START + 1);
        assert!(!store.permits("qwen.localhost", "route-v1", &headers()));
        assert!(issue_token(&store, "run-2", OTHER_TOKEN, START + 7200).is_err());
        clock.roll_wall_back_to(START + 3599);
        assert!(!store.permits("qwen.localhost", "route-v1", &headers()));
        clock.roll_wall_back_to(START + 3600);
        assert!(store.permits("qwen.localhost", "route-v1", &headers()));
        issue_token(&store, "run-2", OTHER_TOKEN, START + 7200).unwrap();
    }
    #[test]
    fn wall_clock_set_back_while_running_cannot_revive_a_grant_that_expired_unseen() {
        let dir = tempfile::tempdir().unwrap();
        let clock = TestClock::at(START);
        let store = GrantStore::with_clock(dir.path().join("grants.json"), clock.clone());
        issue(&store, "run-1", START + 60).unwrap();
        clock.advance(3600);
        clock.roll_wall_back_to(START + 10);
        assert!(!store.permits("qwen.localhost", "route-v1", &headers()));
    }
    struct ClockThatTicksAfterEachWallReading {
        started: Instant,
        secs: AtomicU64,
        ticking: AtomicBool,
    }
    impl Clock for ClockThatTicksAfterEachWallReading {
        fn unix_secs(&self) -> u64 {
            let tick = u64::from(self.ticking.load(Ordering::Relaxed));
            START + self.secs.fetch_add(tick, Ordering::Relaxed)
        }
        fn monotonic(&self) -> Instant {
            self.started + Duration::from_secs(self.secs.load(Ordering::Relaxed))
        }
    }
    #[test]
    fn second_that_passes_between_the_two_clock_readings_is_not_a_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ClockThatTicksAfterEachWallReading {
            started: Instant::now(),
            secs: AtomicU64::new(0),
            ticking: AtomicBool::new(false),
        });
        let store = GrantStore::with_clock(dir.path().join("grants.json"), clock.clone());
        clock.ticking.store(true, Ordering::Relaxed);
        issue(&store, "run-1", START + 3600).unwrap();
        assert!(store.permits("qwen.localhost", "route-v1", &headers()));
    }
}
