//! Per-hostname TLS cert management, backed by `mkcert`.
//!
//! Lifecycle:
//!   1. CLI enables TLS on a TLD via `portman tld add test --tls mkcert`.
//!   2. When an entry lands in the registry under a TLS-enabled TLD — either
//!      from a container event or a static rule add — the daemon calls
//!      [`CertManager::ensure`] to materialize a cert for that hostname.
//!   3. The TLS proxy's SNI resolver looks up the hostname in this cache on
//!      each `ClientHello`.
//!
//! The daemon runs as root under launchd but mkcert's root CA files live in
//! the user's home. We pass `CAROOT=/Users/<SUDO_USER>/Library/Application
//! Support/mkcert` so mkcert finds and reuses the user's already-installed
//! local CA. (Root is allowed to read user-owned files.)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, RwLock};

use anyhow::{bail, Context, Result};
use portman_core::{Mode, Registry, TlsStore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use tracing::{info, warn};

#[derive(Clone)]
pub(crate) struct CertManager {
    cert_dir: PathBuf,
    /// `$CAROOT` to pass to `mkcert` — the user's local mkcert root.
    caroot: Option<PathBuf>,
    /// Loaded, rustls-ready certs keyed by lowercase hostname.
    cache: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl CertManager {
    pub(crate) fn new(cert_dir: PathBuf, caroot: Option<PathBuf>) -> Self {
        Self {
            cert_dir,
            caroot,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Standard `CAROOT` location under a user's home, matching mkcert's
    /// default on macOS.
    pub(crate) fn default_caroot(home: &Path) -> PathBuf {
        home.join("Library/Application Support/mkcert")
    }

    /// The `$CAROOT` this manager will pass to `mkcert`, if known.
    pub(crate) fn caroot(&self) -> Option<PathBuf> {
        self.caroot.clone()
    }

    /// Ensure a cert exists and is loaded for `host`. Idempotent; cheap if
    /// already cached.
    pub(crate) fn ensure(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let key = host.to_ascii_lowercase();
        if let Some(ck) = self.cache.read().expect("cache lock poisoned").get(&key) {
            return Ok(ck.clone());
        }

        std::fs::create_dir_all(&self.cert_dir)
            .with_context(|| format!("creating {}", self.cert_dir.display()))?;
        let stem = cert_file_stem(&key);
        let cert_path = self.cert_dir.join(format!("{stem}.pem"));
        let key_path = self.cert_dir.join(format!("{stem}.key"));

        if !cert_path.exists() || !key_path.exists() {
            self.mkcert(&key, &cert_path, &key_path)
                .with_context(|| format!("generating cert for {key}"))?;
        }

        let ck = load_certified_key(&cert_path, &key_path)
            .with_context(|| format!("loading cert for {key}"))?;
        let arc = Arc::new(ck);
        self.cache
            .write()
            .expect("cache lock poisoned")
            .insert(key.clone(), arc.clone());
        info!(host = %key, cert = %cert_path.display(), "TLS cert ready");
        Ok(arc)
    }

    fn mkcert(&self, host: &str, cert_path: &Path, key_path: &Path) -> Result<()> {
        let Some(ref caroot) = self.caroot else {
            bail!("TLS requested but mkcert CAROOT is not known; cannot generate cert");
        };
        if !caroot.exists() {
            bail!(
                "mkcert CAROOT `{}` does not exist. Run `mkcert -install` as your user first.",
                caroot.display()
            );
        }
        info!(host = %host, caroot = %caroot.display(), "running mkcert");
        // mkcert takes hundreds of ms; callers sit on the async reactor
        // (route registration, the TLS SNI resolver, dashboard handlers).
        // block_in_place hands this worker's slot back to the scheduler so a
        // cert issue can't stall every other task on the thread.
        let status = crate::block_on_reactor(|| {
            Command::new("mkcert")
                .env("CAROOT", caroot)
                .arg("-cert-file")
                .arg(cert_path)
                .arg("-key-file")
                .arg(key_path)
                .arg(host)
                .status()
        })
        .context("spawning mkcert — is it installed? `brew install mkcert`")?;
        if !status.success() {
            bail!("mkcert exited with {status}");
        }
        Ok(())
    }
}

/// On-disk filename stem for a cert. Wildcard patterns can't carry their `*`
/// into a path, so they use mkcert's own convention: `*.demo.test` becomes
/// `_wildcard.demo.test`.
fn cert_file_stem(key: &str) -> String {
    match key.strip_prefix("*.") {
        Some(rest) => format!("_wildcard.{rest}"),
        None => key.to_string(),
    }
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let cert_bytes = std::fs::read(cert_path)?;
    let key_bytes = std::fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_bytes.as_slice()).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        bail!("no certs found in {}", cert_path.display());
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_bytes.as_slice())?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", key_path.display()))?;
    let signing_key =
        rustls::crypto::ring::sign::any_supported_type(&key).context("parsing private key")?;

    Ok(CertifiedKey::new(certs, signing_key))
}

// SNI cert resolver: implements rustls' ResolvesServerCert by looking up the
// requested hostname in the CertManager's cache.
#[derive(Clone)]
pub(crate) struct SniResolver {
    manager: CertManager,
    registry: Registry,
    tls_store: Arc<TlsStore>,
}

impl SniResolver {
    pub(crate) fn new(manager: CertManager, registry: Registry, tls_store: Arc<TlsStore>) -> Self {
        Self {
            manager,
            registry,
            tls_store,
        }
    }

    /// The cert key to serve for an SNI name, or `None` to reject the handshake.
    ///
    /// Returns the *registered* name — for a wildcard entry that's the pattern,
    /// not the concrete SNI. One `*.demo.test` cert then covers every box,
    /// instead of each new name shelling out to mkcert on its first handshake.
    fn cert_key_for_sni(&self, host: &str) -> Option<String> {
        let sni = host.to_ascii_lowercase();
        let (key, entry) = self.registry.lookup(&sni)?;
        // TLS is a per-TLD setting, so ask about the concrete name: a wildcard
        // pattern and the names under it share a TLD either way.
        (entry.mode == Mode::Http && tls_enabled_for_host(&self.tls_store, &sni)).then_some(key)
    }
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SniResolver")
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;
        let Some(key) = self.cert_key_for_sni(sni) else {
            warn!(sni, "rejecting TLS SNI for unregistered or non-TLS host");
            return None;
        };
        // Try exact cached lookup first — avoids shelling out for every
        // handshake when nothing changed.
        if let Some(ck) = self
            .manager
            .cache
            .read()
            .ok()
            .and_then(|c| c.get(&key).cloned())
        {
            return Some(ck);
        }
        match self.manager.ensure(&key) {
            Ok(ck) => Some(ck),
            Err(err) => {
                warn!(sni, error = %err, "cert resolve failed");
                None
            }
        }
    }
}

pub(crate) fn tls_enabled_for_host(tls_store: &TlsStore, host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    for (tld, _) in tls_store.tls_tlds() {
        if h == tld || h.ends_with(&format!(".{tld}")) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use portman_core::{Entry, Source, TlsMode};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "portman-daemon-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn entry(host: &str, mode: Mode) -> Entry {
        Entry {
            host: host.into(),
            target: "127.0.0.1:3000".into(),
            source: Source::Static,
            mode,
            container_id: None,
            project: None,
        }
    }

    #[test]
    fn sni_allow_list_requires_registered_http_tls_host() {
        let registry = Registry::new();
        registry.upsert(entry("app.test", Mode::Http));
        registry.upsert(entry("db.test", Mode::Tcp));
        registry.upsert(entry("plain.example", Mode::Http));

        let tls_path = unique_path("tls-store").join("tls.json");
        let tls_store = Arc::new(TlsStore::load(tls_path).unwrap());
        tls_store.set_mode("test".into(), TlsMode::Mkcert).unwrap();

        let manager = CertManager::new(unique_path("certs"), None);
        let resolver = SniResolver::new(manager, registry, tls_store);

        assert_eq!(
            resolver.cert_key_for_sni("APP.TEST"),
            Some("app.test".to_string())
        );
        assert!(resolver.cert_key_for_sni("missing.test").is_none());
        assert!(resolver.cert_key_for_sni("db.test").is_none());
        assert!(resolver.cert_key_for_sni("plain.example").is_none());
    }

    #[test]
    fn a_name_under_a_wildcard_serves_the_wildcard_cert() {
        // Not a per-name cert: otherwise every new box would shell out to
        // mkcert on its first handshake, for a cert the wildcard already covers.
        let registry = Registry::new();
        registry.upsert(entry("*.demo.test", Mode::Http));

        let tls_path = unique_path("tls-store-wildcard").join("tls.json");
        let tls_store = Arc::new(TlsStore::load(tls_path).unwrap());
        tls_store.set_mode("test".into(), TlsMode::Mkcert).unwrap();

        let manager = CertManager::new(unique_path("certs-wildcard"), None);
        let resolver = SniResolver::new(manager, registry, tls_store);

        assert_eq!(
            resolver.cert_key_for_sni("1.demo.test"),
            Some("*.demo.test".to_string())
        );
        assert_eq!(
            resolver.cert_key_for_sni("7.demo.test"),
            Some("*.demo.test".to_string())
        );
        // The apex isn't covered by the wildcard, so it isn't served either.
        assert!(resolver.cert_key_for_sni("demo.test").is_none());
    }

    #[test]
    fn wildcard_certs_do_not_put_a_star_in_a_filename() {
        assert_eq!(cert_file_stem("*.demo.test"), "_wildcard.demo.test");
        assert_eq!(cert_file_stem("app.test"), "app.test");
    }
}
