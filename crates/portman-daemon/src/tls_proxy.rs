//! TLS proxy on `:443`. Does SNI-based cert selection via [`CertManager`],
//! then terminates TLS and runs the same Host-header routing logic as the
//! plain HTTP proxy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use portman_core::{Mode, Registry, TlsStore};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::certs::{CertManager, SniResolver};
use crate::upstream::{self, BridgeIfIndex};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn run(
    registry: Registry,
    port: u16,
    cert_manager: CertManager,
    tls_store: Arc<TlsStore>,
    bridge: BridgeIfIndex,
) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    run_on(registry, addr, cert_manager, tls_store, bridge).await
}

pub(crate) async fn run_on(
    registry: Registry,
    addr: SocketAddr,
    cert_manager: CertManager,
    tls_store: Arc<TlsStore>,
    bridge: BridgeIfIndex,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await.with_context(|| {
        if addr.port() < 1024 {
            format!(
                "binding TLS proxy {addr} — privileged port requires root. \
                 Run under sudo or override --tls-port."
            )
        } else {
            format!("binding TLS proxy {addr}")
        }
    })?;
    info!(%addr, "tls proxy listening");

    let resolver = Arc::new(SniResolver::new(cert_manager, registry.clone(), tls_store));
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // ALPN advertise http/1.1 — our proxy path is HTTP/1.1 only for v0.
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    loop {
        match listener.accept().await {
            Ok((client, peer)) => {
                let acceptor = acceptor.clone();
                let registry = registry.clone();
                let bridge = bridge.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle(client, acceptor, registry, bridge).await {
                        debug!(%peer, error = %err, "tls connection ended");
                    }
                });
            }
            Err(err) => error!(error = %err, "tls accept failed"),
        }
    }
}

async fn handle(
    client: TcpStream,
    acceptor: TlsAcceptor,
    registry: Registry,
    bridge: BridgeIfIndex,
) -> Result<()> {
    // Apply a short handshake timeout so a slow or misbehaving client can't
    // hang a task forever.
    let mut tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(client))
        .await
        .context("tls handshake timed out")??;

    let mut buf = Vec::with_capacity(4096);
    let host = match tokio::time::timeout(HEADER_READ_TIMEOUT, read_host(&mut tls, &mut buf)).await
    {
        Ok(result) => match result? {
            Some(h) => h,
            None => return Ok(()),
        },
        Err(_) => {
            warn!("TLS request header read timed out");
            write_status(&mut tls, 408, "request timed out").await.ok();
            return Ok(());
        }
    };

    let Some((_, entry)) = registry.lookup(&host) else {
        warn!(%host, "no registry entry for TLS Host");
        write_status(
            &mut tls,
            404,
            &format!("no portman entry for host `{host}`"),
        )
        .await
        .ok();
        return Ok(());
    };

    if entry.mode == Mode::Tcp {
        warn!(%host, target = %entry.target, "rejecting HTTPS request to TCP-mode host");
        write_status(
            &mut tls,
            502,
            &format!(
                "`{host}` is a TCP-mode entry (target {}); connect directly with your raw-protocol client.",
                entry.target
            ),
        )
        .await
        .ok();
        return Ok(());
    }

    let target = entry.target.clone();
    debug!(%host, %target, "tls proxying");

    let mut upstream = match tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        upstream::connect(&target, &bridge),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            warn!(%host, %target, error = %err, "cannot reach target");
            write_status(&mut tls, 502, &format!("cannot reach {target}: {err}"))
                .await
                .ok();
            return Ok(());
        }
        Err(_) => {
            warn!(%host, %target, "target connect timed out");
            write_status(&mut tls, 504, &format!("timed out connecting to {target}"))
                .await
                .ok();
            return Ok(());
        }
    };

    upstream.write_all(&buf).await?;
    match tokio::io::copy_bidirectional(&mut tls, &mut upstream).await {
        Ok((c, u)) => debug!(%host, client_bytes = c, upstream_bytes = u, "tls proxied"),
        Err(err) => debug!(%host, %err, "tls proxy io ended"),
    }
    Ok(())
}

async fn read_host<S>(stream: &mut S, buf: &mut Vec<u8>) -> Result<Option<String>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .context("reading request bytes")?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(buf)? {
            httparse::Status::Complete(_) => {
                let host = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .map(|s| s.split(':').next().unwrap_or(s).to_ascii_lowercase())
                    .unwrap_or_default();
                if host.is_empty() {
                    write_status(stream, 400, "missing Host header").await.ok();
                    return Ok(None);
                }
                return Ok(Some(host));
            }
            httparse::Status::Partial => {
                if buf.len() >= MAX_HEADER_BYTES {
                    write_status(stream, 431, "request headers too large")
                        .await
                        .ok();
                    return Ok(None);
                }
            }
        }
    }
}

async fn write_status<W>(w: &mut W, code: u16, message: &str) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let body = format!("portman: {message}\n");
    let head = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(code),
        body.len()
    );
    w.write_all(head.as_bytes()).await?;
    w.write_all(body.as_bytes()).await?;
    w.flush().await.ok();
    Ok(())
}

fn reason_phrase(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        408 => "Request Timeout",
        404 => "Not Found",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}
