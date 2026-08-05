//! Masking of secret values in captured service output.
//!
//! portman resolves provider secrets and `env_files` into a service's
//! environment, and it also captures that service's stdout/stderr. Anything
//! the service prints — a startup banner echoing its config, a crash dump, a
//! debug `env` — lands in the log store verbatim and is served back over the
//! dashboard. That makes the log store a secondary copy of every secret the
//! service was given, in a place with a much weaker trust boundary than the
//! provider it came from.
//!
//! So the supervisor registers the values it hands a service, and every
//! captured line is scanned for them before it is stored. This is exact-value
//! matching, not pattern detection: portman already knows the values, so it
//! needs no rules and misses no vendor format.
//!
//! What is registered (see `supervisor::supervise_once`): provider values and
//! `env_files` contents — everything a service was given except the base
//! allowlist (`PATH`/`HOME`/`USER`/`TMPDIR`, which `env_compose` injects) and
//! inline `env` from `portman.toml`, which is committed config rather than
//! secret material.
//!
//! Masking is best-effort by nature. A service that base64s a token, splits it
//! across lines, or prints it a character at a time defeats exact matching.
//! It removes the accidental disclosure that actually happens; it is not a
//! guarantee against a service determined to leak.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};

use crate::supervisor::{LineSink, LogStream};

/// Below this length a value is too likely to be ordinary text (`true`, a
/// port, a short name) for exact matching to be safe.
const MIN_MASKABLE_LEN: usize = 8;

/// Registered secret values, keyed by service.
///
/// Lines are masked against every registered service's values, not just the
/// emitting one: services share a machine and routinely print each other's
/// configuration.
pub(crate) struct SecretMasker {
    by_service: RwLock<BTreeMap<String, Vec<Secret>>>,
}

struct Secret {
    value: String,
    marker: String,
}

impl SecretMasker {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            by_service: RwLock::new(BTreeMap::new()),
        })
    }

    /// Replace this service's registered values. Called per spawn attempt, so
    /// a re-resolve that changes a value cannot leave the old one masked and
    /// the new one exposed.
    pub(crate) fn register<'a, I>(&self, service: &str, values: I)
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut secrets: Vec<Secret> = values
            .into_iter()
            .filter(|value| is_maskable(value))
            .map(|value| Secret {
                value: value.to_string(),
                marker: marker_for(value),
            })
            .collect();
        // Longest first: a short secret that is a substring of a longer one
        // must not mask the prefix and leave the remainder exposed.
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.value.len()));
        secrets.dedup_by(|a, b| a.value == b.value);
        self.write().insert(service.to_string(), secrets);
    }

    pub(crate) fn unregister(&self, service: &str) {
        self.write().remove(service);
    }

    /// Replace every registered value found in `line` with its marker.
    pub(crate) fn mask<'a>(&self, line: &'a str) -> Cow<'a, str> {
        let by_service = self.read();
        let mut out = Cow::Borrowed(line);
        for secret in by_service.values().flatten() {
            if out.contains(secret.value.as_str()) {
                out = Cow::Owned(out.replace(secret.value.as_str(), &secret.marker));
            }
        }
        out
    }

    /// Wrap a sink so everything written through it is masked first.
    pub(crate) fn wrap(self: &Arc<Self>, inner: Arc<dyn LineSink>) -> Arc<dyn LineSink> {
        Arc::new(MaskingSink {
            inner,
            masker: Arc::clone(self),
        })
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, Vec<Secret>>> {
        self.by_service
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<String, Vec<Secret>>> {
        self.by_service
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A value worth masking: long enough to be distinctive, not a filesystem
/// path, not a number or boolean, and not prose. Masking `/Users/me` or `true`
/// out of every log line would destroy far more than it protects.
fn is_maskable(value: &str) -> bool {
    value.len() >= MIN_MASKABLE_LEN
        && !value.starts_with('/')
        && !value.chars().any(char::is_whitespace)
        && value.parse::<f64>().is_err()
        && !matches!(value.to_ascii_lowercase().as_str(), "true" | "false")
}

/// `[masked:<sha256-prefix8>]` — stable across lines and services, so repeated
/// occurrences of one secret are correlatable, and usable as a taint handle
/// elsewhere. It discloses nothing about the value.
fn marker_for(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("[masked:{}]", hex::encode(&digest[..4]))
}

struct MaskingSink {
    inner: Arc<dyn LineSink>,
    masker: Arc<SecretMasker>,
}

impl LineSink for MaskingSink {
    fn line(&self, service: &str, stream: LogStream, line: &str) {
        self.inner.line(service, stream, &self.masker.mask(line));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Collect(Mutex<Vec<String>>);

    impl LineSink for Collect {
        fn line(&self, _service: &str, _stream: LogStream, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }
    }

    const SECRET: &str = "s3cret-value-long-enough";

    #[test]
    fn masks_a_registered_value_anywhere_in_the_line() {
        let masker = SecretMasker::new();
        masker.register("svc", [SECRET]);
        let line = format!("TOKEN={SECRET} trailing");
        let masked = masker.mask(&line);
        assert!(!masked.contains(SECRET), "{masked}");
        assert!(masked.starts_with("TOKEN=[masked:"), "{masked}");
        assert!(masked.ends_with("] trailing"), "{masked}");
    }

    #[test]
    fn unregistered_and_unknown_values_pass_through_untouched() {
        let masker = SecretMasker::new();
        masker.register("svc", [SECRET]);
        let line = "nothing sensitive here";
        assert!(matches!(masker.mask(line), Cow::Borrowed(_)), "no copy");

        masker.unregister("svc");
        assert_eq!(masker.mask(SECRET), SECRET, "unregister stops masking");
    }

    #[test]
    fn short_path_numeric_and_prose_values_are_never_masked() {
        for value in ["short", "/Users/someone/project", "8080", "1.25", "true"] {
            assert!(!is_maskable(value), "{value} must not be maskable");
        }
        // Multi-word values are configuration prose, not credentials.
        assert!(!is_maskable("postgres connection string"));
        assert!(is_maskable(SECRET));
    }

    #[test]
    fn a_secret_containing_another_masks_completely() {
        let masker = SecretMasker::new();
        let short = "abcdefgh12";
        let long = format!("{short}-and-more-tail");
        masker.register("svc", [short, long.as_str()]);
        let line = format!("A={long} B={short}");
        let masked = masker.mask(&line);
        assert!(!masked.contains(short), "{masked}");
        assert!(!masked.contains(long.as_str()), "{masked}");
    }

    #[test]
    fn one_services_secret_is_masked_in_anothers_output() {
        let masker = SecretMasker::new();
        masker.register("owner", [SECRET]);
        let line = format!("other service printed {SECRET}");
        let masked = masker.mask(&line);
        assert!(!masked.contains(SECRET), "{masked}");
    }

    #[test]
    fn the_wrapped_sink_stores_masked_lines() {
        let masker = SecretMasker::new();
        masker.register("svc", [SECRET]);
        let collect = Arc::new(Collect(Mutex::new(Vec::new())));
        let sink = masker.wrap(collect.clone());
        sink.line("svc", LogStream::Stdout, &format!("KEY={SECRET}"));
        let lines = collect.0.lock().unwrap().clone();
        assert_eq!(lines.len(), 1);
        assert!(!lines[0].contains(SECRET), "{}", lines[0]);
    }

    #[test]
    fn the_marker_is_stable_and_discloses_nothing() {
        assert_eq!(marker_for(SECRET), marker_for(SECRET));
        assert_ne!(marker_for(SECRET), marker_for("another-long-secret"));
        assert!(!marker_for(SECRET).contains(&SECRET[..6]));
    }
}
