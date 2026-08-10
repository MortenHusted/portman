//! TLS origination for egress hops.
//!
//! portman's other proxy paths TERMINATE TLS: `tls_proxy` presents its own
//! certificates to callers and speaks plaintext upstream. Egress is the
//! first path that ORIGINATES it — the caller speaks plaintext to portman,
//! and portman opens a verified TLS session to the external upstream. Same
//! one-way shape as the credential itself: portman sits at the trust
//! boundary on both sides.
//!
//! Trust anchors are the compiled-in Mozilla set (`webpki-roots`), the same
//! ones the secrets providers' reqwest client already uses — no new supply
//! chain, no trust-store plumbing for the user.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use portman_protocol::EgressSpec;

use crate::upstream::{self, BridgeIfIndex};

/// Which trust anchors the upstream handshake verifies against.
#[derive(Clone, Copy)]
pub(crate) enum Roots {
    /// The compiled-in Mozilla set — production default.
    System,
    /// Test seam: the system set plus one extra anchor (PEM), so a
    /// self-signed test upstream can be verified without touching global
    /// state.
    #[cfg(test)]
    CustomPem(&'static [u8]),
}

/// A connected egress upstream: plain TCP for local/test targets, TLS for
/// `tls = true` routes. Both satisfy AsyncRead/AsyncWrite, so the proxy's
/// head-splice is byte-identical either way.
pub(crate) enum UpstreamStream {
    Plain(TcpStream),
    /// Boxed: `TlsStream` is ~1KiB of handshake state, and an enum sized to
    /// its largest variant would stack that on every plaintext hop too.
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_flush(cx),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Connect to an egress `target` (`host:port`), speaking TLS first when
/// `spec.tls` says so. The TCP leg goes through [`upstream::connect`] so
/// bridge-subnet scoping still applies; the TLS leg verifies the upstream
/// against `spec.upstream_host` — the same name the rewritten request
/// presents, so SNI, certificate checks, and the `Host` header all agree.
pub(crate) async fn connect(
    target: &str,
    spec: &EgressSpec,
    bridge: &BridgeIfIndex,
    roots: Roots,
) -> io::Result<UpstreamStream> {
    let tcp = upstream::connect(target, bridge).await?;
    if !spec.tls {
        return Ok(UpstreamStream::Plain(tcp));
    }
    let name = ServerName::try_from(spec.upstream_host.clone()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "egress upstream_host `{}` is not a valid TLS name",
                spec.upstream_host
            ),
        )
    })?;
    let config = match roots {
        Roots::System => Arc::clone(system_config()),
        #[cfg(test)]
        Roots::CustomPem(pem) => {
            let mut store = system_roots();
            let mut pem_bytes = std::io::Cursor::new(pem);
            let certs: Vec<_> = rustls_pemfile::certs(&mut pem_bytes)
                .collect::<Result<_, _>>()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            if store.add_parsable_certificates(certs).0 == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test trust anchor did not parse as a certificate",
                ));
            }
            Arc::new(build_client_config(store))
        }
    };
    let tls = TlsConnector::from(config).connect(name, tcp).await?;
    Ok(UpstreamStream::Tls(Box::new(tls)))
}

/// The production client config: Mozilla roots, HTTP/1.1 ALPN. Built once —
/// the root table is large and never changes within a daemon run.
/// `OnceLock` rather than `LazyLock`: the latter stabilised in 1.80, past
/// the workspace MSRV (1.78).
static SYSTEM_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

fn system_config() -> &'static Arc<ClientConfig> {
    SYSTEM_CONFIG.get_or_init(|| Arc::new(build_client_config(system_roots())))
}

fn system_roots() -> RootCertStore {
    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

fn build_client_config(roots: RootCertStore) -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // HTTP/1.1 only — the egress splice parses one head per connection.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}
