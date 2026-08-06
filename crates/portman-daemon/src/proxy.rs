//! HTTP proxy on `:80` — Host-header routing to registry targets.
//!
//! Flow per connection: read request headers, extract the Host header, look
//! up the registry, open a TCP connection to the target, then
//! `tokio::io::copy_bidirectional` back and forth. The initial bytes we had
//! to read to find the Host line get prepended to the upstream stream.
//!
//! WebSocket upgrades, HTTP/1.1 keep-alive within a single connection, and
//! long-lived streaming responses all work because we're byte-level
//! transparent after the Host lookup.
//!
//! **Privilege:** binding `:80` needs root on macOS. The daemon therefore
//! must run under `sudo`. On `EACCES` the error includes the `sudo -E`
//! command to use.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use portman_core::{Mode, Registry};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::egress::{rewrite_head, Credentials, EgressAudit};
use crate::egress_client::{self, Roots};
use crate::runner::Starter;
use crate::upstream::{self, BridgeIfIndex};

/// Reserved path on every proxied host. The 502 page's Start button posts
/// here; the proxy only ever interprets it after the upstream connect has
/// failed, so a healthy app keeps full ownership of its path space.
const START_PATH: &str = "/.portman/start";

/// Max bytes we'll accumulate while searching for the end of the HTTP headers.
/// 16 KiB is more than any reasonable request line + headers will need.
const MAX_HEADER_BYTES: usize = 16 * 1024;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn run(
    registry: Registry,
    port: u16,
    bridge: BridgeIfIndex,
    starter: Arc<dyn Starter>,
    credentials: Credentials,
    roots: Roots,
) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    run_on(registry, addr, bridge, starter, credentials, roots).await
}

pub(crate) async fn run_on(
    registry: Registry,
    addr: SocketAddr,
    bridge: BridgeIfIndex,
    starter: Arc<dyn Starter>,
    credentials: Credentials,
    roots: Roots,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await.with_context(|| {
        if addr.port() < 1024 {
            format!(
                "binding HTTP proxy {addr} — privileged port requires root. \
                 Run with `sudo -E cargo run -p portman-daemon` or `mise run daemon-root`, \
                 or override via --proxy-port / PORTMAN_PROXY_PORT."
            )
        } else {
            format!("binding HTTP proxy {addr}")
        }
    })?;
    info!(%addr, "http proxy listening");

    loop {
        match listener.accept().await {
            Ok((client, peer)) => {
                let registry = registry.clone();
                let bridge = bridge.clone();
                let starter = starter.clone();
                let credentials = credentials.clone();
                tokio::spawn(async move {
                    if let Err(err) =
                        handle_connection(client, registry, bridge, starter, credentials, roots)
                            .await
                    {
                        debug!(%peer, error = %err, "proxy connection ended");
                    }
                });
            }
            Err(err) => error!(error = %err, "proxy accept failed"),
        }
    }
}

async fn handle_connection(
    mut client: TcpStream,
    registry: Registry,
    bridge: BridgeIfIndex,
    starter: Arc<dyn Starter>,
    credentials: Credentials,
    roots: Roots,
) -> Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let head = match tokio::time::timeout(
        HEADER_READ_TIMEOUT,
        read_request_head(&mut client, &mut buf),
    )
    .await
    {
        Ok(result) => match result? {
            Some(v) => v,
            None => return Ok(()),
        },
        Err(_) => {
            warn!("request header read timed out");
            write_status(&mut client, 408, "request timed out")
                .await
                .ok();
            return Ok(());
        }
    };
    let headers_end = head.headers_end;
    let host = head.host.clone();
    let wants_html = head.wants_html;

    let Some((_, entry)) = registry.lookup(&host) else {
        warn!(%host, "no registry entry for Host header");
        write_error(
            &mut client,
            404,
            &host,
            &format!("No route for {host}."),
            "This hostname isn't registered with portman. Add it with `portman add`, \
             or check the container's `dev.portman.host` label.",
            "",
            wants_html,
        )
        .await
        .ok();
        return Ok(());
    };

    // TCP-mode entries are intentionally out of the HTTP data path. Refuse
    // rather than blindly forwarding HTTP bytes into a Postgres/MySQL socket.
    if entry.mode == Mode::Tcp {
        warn!(%host, target = %entry.target, "rejecting HTTP request to TCP-mode host");
        write_error(
            &mut client,
            502,
            &host,
            &format!("{host} is a TCP-mode route, not an HTTP service."),
            "Connect to it with a raw-protocol client (psql, mysql, redis-cli, …) on the \
             same hostname — it isn't reachable over HTTP.",
            "",
            wants_html,
        )
        .await
        .ok();
        return Ok(());
    }

    // Authenticated egress: resolve the credential and connect to the
    // external upstream (plain or TLS). Separate path from the local
    // backend hop below — different connect, different head rewrite, no
    // start-button semantics (the upstream is never one of our services).
    if entry.mode == Mode::Egress {
        return handle_egress(client, &head, &host, entry, bridge, credentials, buf, roots).await;
    }

    let target = entry.target.clone();
    debug!(%host, %target, headers_end, "proxying");

    let mut upstream = match tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        upstream::connect(&target, &bridge),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            warn!(%host, %target, error = %err, "cannot reach target");
            // The backend is down — this is the one moment the reserved
            // start path is interpreted instead of proxied.
            if head.method == "POST" && head.path == START_PATH {
                return handle_start_request(&mut client, &head, starter.as_ref()).await;
            }
            let startable = starter.can_start(&host, entry.container_id.as_deref());
            write_error(
                &mut client,
                502,
                &host,
                &format!("Can't reach the service behind {host}."),
                &format!(
                    "portman routes {host} to {target}, but the connection failed ({err}). \
                         The container or process behind it is probably not running."
                ),
                if startable { START_FORM_HTML } else { "" },
                wants_html,
            )
            .await
            .ok();
            return Ok(());
        }
        Err(_) => {
            warn!(%host, %target, "target connect timed out");
            write_error(
                &mut client,
                504,
                &host,
                &format!("Timed out reaching {host}."),
                &format!(
                    "portman routes {host} to {target}, but it didn't respond in time. \
                         It may still be starting up or be overloaded."
                ),
                "",
                wants_html,
            )
            .await
            .ok();
            return Ok(());
        }
    };

    // The bytes we read to find the Host header belong to the client's
    // request. Forward them to upstream before we start byte-splicing.
    upstream.write_all(&buf).await?;

    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((c, u)) => debug!(%host, client_bytes = c, upstream_bytes = u, "proxied"),
        Err(err) => debug!(%host, %err, "proxy io ended"),
    }
    Ok(())
}

/// An authenticated egress hop: resolve the named credential, connect to the
/// external upstream (originating TLS when the route says so), rewrite the
/// request head, and splice.
///
/// Resolution failures refuse BEFORE opening a connection: forwarding
/// unauthenticated would look like a working route while quietly dropping
/// the guarantee the route exists to provide.
#[allow(clippy::too_many_arguments)]
async fn handle_egress(
    mut client: TcpStream,
    head: &RequestHead,
    host: &str,
    entry: portman_protocol::Entry,
    bridge: BridgeIfIndex,
    credentials: Credentials,
    buf: Vec<u8>,
    roots: Roots,
) -> Result<()> {
    let wants_html = head.wants_html;
    let headers_end = head.headers_end;
    let target = entry.target.clone();
    let Some(spec) = entry.egress.clone() else {
        warn!(%host, "egress route has no credential spec; refusing rather than forwarding unauthenticated");
        write_error(
            &mut client,
            502,
            host,
            &format!("{host} is an egress route with no credential configured."),
            "Add the `secrets` and `key` fields to its config and re-run `portman up`.",
            "",
            wants_html,
        )
        .await
        .ok();
        return Ok(());
    };
    let audit = EgressAudit::from_spec(host, &target, &spec);
    let Some(value) = credentials.resolve(&spec).await else {
        warn!(
            host = audit.host,
            upstream = audit.upstream,
            secrets = audit.secrets_block,
            key = audit.key,
            "egress credential unavailable; refusing rather than forwarding unauthenticated"
        );
        write_error(
            &mut client,
            502,
            host,
            &format!("{host} could not resolve its credential."),
            "Check the referenced secrets block and that `portman secrets set-*` has run.",
            "",
            wants_html,
        )
        .await
        .ok();
        return Ok(());
    };
    info!(
        host = audit.host,
        upstream = audit.upstream,
        secrets = audit.secrets_block,
        key = audit.key,
        tls = spec.tls,
        "egress request authenticated"
    );

    let mut upstream = match tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        egress_client::connect(&target, &spec, &bridge, roots),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            warn!(%host, %target, error = %err, "cannot reach egress upstream");
            write_error(
                &mut client,
                502,
                host,
                &format!("Can't reach the upstream behind {host}."),
                &format!("portman routes {host} to {target}, but the connection failed ({err})."),
                "",
                wants_html,
            )
            .await
            .ok();
            return Ok(());
        }
        Err(_) => {
            warn!(%host, %target, "egress upstream connect timed out");
            write_error(
                &mut client,
                504,
                host,
                &format!("Timed out reaching the upstream behind {host}."),
                &format!("portman routes {host} to {target}, but it didn't respond in time."),
                "",
                wants_html,
            )
            .await
            .ok();
            return Ok(());
        }
    };

    // `rewrite_head` forces `Connection: close`, so the splice below ends
    // after this one request rather than carrying an unparsed — and
    // therefore unauthenticated — second request through.
    let buf = rewrite_head(&buf, headers_end, &spec, &value);
    upstream.write_all(&buf).await?;

    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((c, u)) => debug!(%host, client_bytes = c, upstream_bytes = u, "egress proxied"),
        Err(err) => debug!(%host, %err, "egress io ended"),
    }
    Ok(())
}

/// Everything the router needs from the request head. `method`/`path`/
/// `origin` exist for the reserved start path — routing itself stays
/// Host-only.
struct RequestHead {
    headers_end: usize,
    host: String,
    wants_html: bool,
    method: String,
    path: String,
    origin: Option<String>,
}

/// Read from `client` until we've seen the end of the HTTP request headers,
/// parse them, and extract the head fields (Host without port suffix,
/// lowercased). Returns `Ok(None)` if we wrote an error response to the
/// client and there's nothing further to do.
async fn read_request_head(
    client: &mut TcpStream,
    buf: &mut Vec<u8>,
) -> Result<Option<RequestHead>> {
    let mut chunk = [0u8; 4096];
    loop {
        let n = client
            .read(&mut chunk)
            .await
            .context("reading request header bytes")?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(buf)? {
            httparse::Status::Complete(end) => {
                let header = |name: &str| {
                    req.headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case(name))
                        .and_then(|h| std::str::from_utf8(h.value).ok())
                };
                let host = header("host")
                    .map(|s| s.split(':').next().unwrap_or(s).to_ascii_lowercase())
                    .unwrap_or_default();
                if host.is_empty() {
                    warn!("request missing Host header");
                    write_status(client, 400, "missing Host header").await.ok();
                    return Ok(None);
                }
                // Browsers send `Accept: text/html`; curl/DB clients don't.
                // Drives whether errors render as a page or a plain line.
                let wants_html = header("accept")
                    .map(|accept| accept.contains("text/html"))
                    .unwrap_or(false);
                return Ok(Some(RequestHead {
                    headers_end: end,
                    host,
                    wants_html,
                    method: req.method.unwrap_or("GET").to_string(),
                    path: req.path.unwrap_or("/").to_string(),
                    origin: header("origin").map(str::to_string),
                }));
            }
            httparse::Status::Partial => {
                if buf.len() >= MAX_HEADER_BYTES {
                    warn!(len = buf.len(), "request headers exceed limit");
                    write_status(client, 431, "request headers too large")
                        .await
                        .ok();
                    return Ok(None);
                }
            }
        }
    }
}

/// Plain-text status line. Used for pre-Host errors (timeout, missing/oversize
/// headers) where we don't yet know the client or the route.
async fn write_status<W>(w: &mut W, code: u16, message: &str) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let body = format!("portman: {message}\n");
    write_http(w, code, "text/plain; charset=utf-8", body.as_bytes()).await
}

/// The Start button block injected into the 502 page when the runner has a
/// plausible way to start the host's backend. Static markup — nothing
/// client-supplied lands in it.
const START_FORM_HTML: &str = r#"<form method="post" action="/.portman/start">
  <button type="submit">Start this service</button>
</form>
<p class="fine">portman knows how to start this service and will report back here.</p>"#;

/// Route-level error. Browsers (`wants_html`) get a small styled page naming
/// the host, what went wrong, and the likely cause; everyone else keeps the
/// plain `portman:` lines curl/DB clients already parsed. `extra_html` is
/// trusted static markup (e.g. the start form) rendered after the hint.
#[allow(clippy::too_many_arguments)]
async fn write_error<W>(
    w: &mut W,
    code: u16,
    host: &str,
    message: &str,
    hint: &str,
    extra_html: &str,
    wants_html: bool,
) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    if wants_html {
        let body = error_page(code, host, message, hint, extra_html);
        write_http(w, code, "text/html; charset=utf-8", body.as_bytes()).await
    } else {
        let mut body = format!("portman: {message}\n");
        if !hint.is_empty() {
            body.push_str("portman: ");
            body.push_str(hint);
            body.push('\n');
        }
        write_http(w, code, "text/plain; charset=utf-8", body.as_bytes()).await
    }
}

/// `POST /.portman/start` while the backend is down: same-origin form posts
/// only (a cross-site page must not be able to poke services awake), then
/// hand the host to the runner and report what happened. Success renders a
/// holding page that retries `/` once the backend has had a moment to bind.
async fn handle_start_request(
    client: &mut TcpStream,
    head: &RequestHead,
    starter: &dyn Starter,
) -> Result<()> {
    if let Some(origin) = head.origin.as_deref() {
        let origin_host = origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
            .map(|rest| rest.split(':').next().unwrap_or(rest).to_ascii_lowercase());
        if origin_host.as_deref() != Some(head.host.as_str()) {
            warn!(host = %head.host, ?origin, "rejecting cross-origin start request");
            write_status(client, 403, "cross-origin start request rejected")
                .await
                .ok();
            return Ok(());
        }
    }

    match starter.start(&head.host).await {
        Ok(detail) => {
            info!(host = %head.host, %detail, "started service from proxy");
            if head.wants_html {
                let body = starting_page(&head.host, &detail);
                write_http(client, 200, "text/html; charset=utf-8", body.as_bytes()).await
            } else {
                write_status(client, 200, &detail).await
            }
        }
        Err(err) => {
            warn!(host = %head.host, error = %err, "start request failed");
            write_error(
                client,
                502,
                &head.host,
                &format!("Couldn't start the service behind {}.", head.host),
                &format!("{err:#}"),
                "",
                head.wants_html,
            )
            .await
        }
    }
}

/// Holding page after a successful start: reports the runner's detail line
/// and retries the app root once it has had a moment to come up.
fn starting_page(host: &str, detail: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="3;url=/">
<title>portman · starting {host}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
    font: 15px/1.55 ui-sans-serif, -apple-system, system-ui, sans-serif;
    background: #f7f7f8; color: #1c1c1e; }}
  @media (prefers-color-scheme: dark) {{ body {{ background: #17171a; color: #ececf1; }} }}
  main {{ max-width: 32rem; padding: 2rem 2.25rem; }}
  h1 {{ font-size: 1.35rem; margin: .4rem 0 .75rem; font-weight: 600; }}
  p {{ margin: 0; opacity: .8; }}
  .brand {{ margin-top: 1.75rem; font-size: .8rem; opacity: .4; }}
</style>
</head>
<body>
<main>
  <h1>Starting {host}…</h1>
  <p>{detail}. Reloading in a moment.</p>
  <div class="brand">portman</div>
</main>
</body>
</html>
"#,
        host = html_escape(host),
        detail = html_escape(detail),
    )
}

async fn write_http<W>(w: &mut W, code: u16, content_type: &str, body: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let head = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(code),
        body.len()
    );
    w.write_all(head.as_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await.ok();
    Ok(())
}

/// A small self-contained error page. Calm and monochrome, no external assets.
/// `host`, `message`, and `hint` are escaped — the Host header is client-supplied.
/// `extra_html` is trusted static markup and rendered verbatim.
fn error_page(code: u16, host: &str, message: &str, hint: &str, extra_html: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>portman · {host}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
    font: 15px/1.55 ui-sans-serif, -apple-system, system-ui, sans-serif;
    background: #f7f7f8; color: #1c1c1e; }}
  @media (prefers-color-scheme: dark) {{ body {{ background: #17171a; color: #ececf1; }} }}
  main {{ max-width: 32rem; padding: 2rem 2.25rem; }}
  .code {{ font-size: .8rem; letter-spacing: .08em; text-transform: uppercase; opacity: .5; }}
  h1 {{ font-size: 1.35rem; margin: .4rem 0 .75rem; font-weight: 600; }}
  p {{ margin: 0; opacity: .8; }}
  form {{ margin: 1.25rem 0 0; }}
  button {{ font: inherit; padding: .5rem 1.1rem; border-radius: .5rem; cursor: pointer;
    border: 1px solid currentColor; background: transparent; color: inherit; }}
  .fine {{ margin-top: .5rem; font-size: .8rem; opacity: .55; }}
  .brand {{ margin-top: 1.75rem; font-size: .8rem; opacity: .4; }}
</style>
</head>
<body>
<main>
  <div class="code">{code} {reason}</div>
  <h1>{message}</h1>
  <p>{hint}</p>
  {extra_html}
  <div class="brand">portman</div>
</main>
</body>
</html>
"#,
        code = code,
        reason = reason_phrase(code),
        host = html_escape(host),
        message = html_escape(message),
        hint = html_escape(hint),
        extra_html = extra_html,
    )
}

/// Minimal HTML entity escaping for text interpolated into the error page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn reason_phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        408 => "Request Timeout",
        404 => "Not Found",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portman_protocol::{Entry, Source};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    fn entry(host: &str, target: String, mode: Mode) -> Entry {
        Entry {
            host: host.into(),
            target,
            source: Source::Static,
            mode,
            container_id: None,
            project: None,
            egress: None,
        }
    }

    /// Stub runner: `can_start` is fixed, `start` counts invocations.
    struct StubStarter {
        startable: bool,
        starts: AtomicUsize,
        outcome: std::result::Result<&'static str, &'static str>,
    }

    impl StubStarter {
        fn inert() -> Arc<Self> {
            Arc::new(Self {
                startable: false,
                starts: AtomicUsize::new(0),
                outcome: Err("nothing to start"),
            })
        }

        fn ready(outcome: std::result::Result<&'static str, &'static str>) -> Arc<Self> {
            Arc::new(Self {
                startable: true,
                starts: AtomicUsize::new(0),
                outcome,
            })
        }
    }

    #[async_trait::async_trait]
    impl Starter for StubStarter {
        fn can_start(&self, _host: &str, _container_id: Option<&str>) -> bool {
            self.startable
        }

        async fn start(&self, _host: &str) -> Result<String> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            match self.outcome {
                Ok(detail) => Ok(detail.to_string()),
                Err(msg) => anyhow::bail!(msg),
            }
        }
    }

    async fn proxy_once(registry: Registry, starter: Arc<dyn Starter>) -> SocketAddr {
        proxy_once_with(
            registry,
            starter,
            Arc::new(crate::egress::NoCredentials),
            Roots::System,
        )
        .await
    }

    async fn proxy_once_with(
        registry: Registry,
        starter: Arc<dyn Starter>,
        credentials: Credentials,
        roots: Roots,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            handle_connection(
                client,
                registry,
                upstream::new_bridge_ifindex(),
                starter,
                credentials,
                roots,
            )
            .await
            .unwrap();
        });
        addr
    }

    /// Hands out one fixed value, standing in for a resolved secrets block.
    struct StubCredentials(&'static str);

    #[async_trait::async_trait]
    impl crate::egress::CredentialSource for StubCredentials {
        async fn resolve(&self, _spec: &portman_protocol::EgressSpec) -> Option<String> {
            Some(self.0.to_string())
        }
    }

    struct NoSuchCredential;

    #[async_trait::async_trait]
    impl crate::egress::CredentialSource for NoSuchCredential {
        async fn resolve(&self, _spec: &portman_protocol::EgressSpec) -> Option<String> {
            None
        }
    }

    fn egress_entry(host: &str, target: String) -> Entry {
        let mut e = entry(host, target, Mode::Egress);
        e.egress = Some(portman_protocol::EgressSpec {
            secrets: "gh".into(),
            key: "GITHUB_TOKEN".into(),
            header: "Authorization".into(),
            format: "Bearer {value}".into(),
            upstream_host: "api.github.com".into(),
            tls: false,
        });
        e
    }

    async fn upstream_once(
        response: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream.write_all(response).await.unwrap();
            buf
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn http_proxy_routes_by_normalized_host_and_forwards_initial_request() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (upstream_addr, upstream) = upstream_once(response).await;
        let registry = Registry::new();
        registry.upsert(entry("app.test", upstream_addr.to_string(), Mode::Http));
        let proxy_addr = proxy_once(registry, StubStarter::inert()).await;

        let request = b"GET /path HTTP/1.1\r\nHost: App.Test:80\r\nConnection: close\r\n\r\n";
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert!(std::str::from_utf8(&received)
            .unwrap()
            .starts_with("HTTP/1.1 200 OK"));
        assert_eq!(upstream.await.unwrap(), request);
    }

    /// The tracer bullet: a caller that holds no credential reaches an
    /// upstream that receives an authenticated request. Also pins the three
    /// rewrites that make that safe — the caller's own auth header is gone,
    /// the upstream sees its own `Host`, and the connection is closed so no
    /// unparsed second request can follow.
    #[tokio::test]
    async fn egress_route_injects_the_credential_the_caller_never_held() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (upstream_addr, upstream) = upstream_once(response).await;
        let registry = Registry::new();
        registry.upsert(egress_entry("github.api.test", upstream_addr.to_string()));
        let proxy_addr = proxy_once_with(
            registry,
            StubStarter::inert(),
            Arc::new(StubCredentials("s3cret-token")),
            Roots::System,
        )
        .await;

        // The caller sends its own Authorization header; it must not survive.
        let request = b"GET /user HTTP/1.1\r\nHost: github.api.test\r\nAuthorization: Bearer caller-supplied\r\nConnection: keep-alive\r\n\r\n";
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert!(std::str::from_utf8(&received)
            .unwrap()
            .starts_with("HTTP/1.1 200 OK"));

        let seen = upstream.await.unwrap();
        let seen = std::str::from_utf8(&seen).unwrap();
        assert!(
            seen.contains("Authorization: Bearer s3cret-token\r\n"),
            "upstream must receive the injected credential: {seen:?}"
        );
        assert!(
            !seen.contains("caller-supplied"),
            "caller's own credential must be stripped: {seen:?}"
        );
        assert!(
            seen.contains("Host: api.github.com\r\n") && !seen.contains("github.api.test"),
            "upstream must see its own host: {seen:?}"
        );
        assert!(
            seen.contains("Connection: close\r\n") && !seen.contains("keep-alive"),
            "keep-alive must be forced closed: {seen:?}"
        );
    }

    /// An egress route with no resolvable credential refuses. Forwarding
    /// unauthenticated would look like a working route while quietly
    /// dropping the guarantee the route exists to provide.
    #[tokio::test]
    async fn egress_route_refuses_rather_than_forwarding_unauthenticated() {
        let (upstream_addr, upstream) = upstream_once(b"HTTP/1.1 200 OK\r\n\r\n").await;
        let registry = Registry::new();
        registry.upsert(egress_entry("github.api.test", upstream_addr.to_string()));
        let proxy_addr = proxy_once_with(
            registry,
            StubStarter::inert(),
            Arc::new(NoSuchCredential),
            Roots::System,
        )
        .await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: github.api.test\r\n\r\n")
            .await
            .unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert!(
            std::str::from_utf8(&received)
                .unwrap()
                .starts_with("HTTP/1.1 502"),
            "expected a refusal: {:?}",
            std::str::from_utf8(&received).unwrap()
        );
        upstream.abort();
    }

    /// A service-derived route (`Source::Service`, as the supervisor's
    /// RouteBinder registers it) proxies exactly like any other entry — the
    /// proxy never branches on source.
    #[tokio::test]
    async fn http_proxy_routes_service_derived_entries() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (upstream_addr, _upstream) = upstream_once(response).await;
        let registry = Registry::new();
        registry.upsert(Entry {
            host: "svc.internal".into(),
            target: upstream_addr.to_string(),
            source: Source::Service,
            mode: Mode::Http,
            container_id: None,
            project: None,
            egress: None,
        });
        let proxy_addr = proxy_once(registry, StubStarter::inert()).await;

        let request = b"GET / HTTP/1.1\r\nHost: svc.internal\r\nConnection: close\r\n\r\n";
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert!(std::str::from_utf8(&received)
            .unwrap()
            .starts_with("HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn http_proxy_rejects_tcp_mode_entries_before_connecting_upstream() {
        let registry = Registry::new();
        registry.upsert(entry("db.test", "127.0.0.1:5432".into(), Mode::Tcp));
        let proxy_addr = proxy_once(registry, StubStarter::inert()).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: db.test\r\n\r\n")
            .await
            .unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        let response = std::str::from_utf8(&received).unwrap();
        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway"));
        assert!(response.contains("TCP-mode"));
    }

    #[tokio::test]
    async fn browser_gets_html_error_page_when_upstream_is_down() {
        // Bind then drop a listener so the address is guaranteed refused.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let registry = Registry::new();
        registry.upsert(entry("app.test", dead_addr.to_string(), Mode::Http));
        let proxy_addr = proxy_once(registry, StubStarter::inert()).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        let response = std::str::from_utf8(&received).unwrap();
        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway"));
        assert!(response.contains("Content-Type: text/html"));
        assert!(response.contains("app.test"));
        assert!(response.contains("probably not running"));
    }

    #[tokio::test]
    async fn dead_upstream_502_offers_start_form_when_runner_can_start() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let registry = Registry::new();
        registry.upsert(entry("app.test", dead_addr.to_string(), Mode::Http));
        let proxy_addr = proxy_once(registry, StubStarter::ready(Ok("started"))).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        let response = std::str::from_utf8(&received).unwrap();
        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway"));
        assert!(response.contains("/.portman/start"));
        assert!(response.contains("Start this service"));
    }

    #[tokio::test]
    async fn start_post_triggers_runner_and_renders_holding_page() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let registry = Registry::new();
        registry.upsert(entry("app.test", dead_addr.to_string(), Mode::Http));
        let starter = StubStarter::ready(Ok("restarted container abc123"));
        let proxy_addr = proxy_once(registry, starter.clone()).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                b"POST /.portman/start HTTP/1.1\r\nHost: app.test\r\n\
                  Origin: http://app.test\r\nAccept: text/html\r\n\
                  Content-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        let response = std::str::from_utf8(&received).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("Starting app.test"));
        assert!(response.contains("restarted container abc123"));
        assert_eq!(starter.starts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cross_origin_start_post_is_rejected_without_invoking_runner() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let registry = Registry::new();
        registry.upsert(entry("app.test", dead_addr.to_string(), Mode::Http));
        let starter = StubStarter::ready(Ok("started"));
        let proxy_addr = proxy_once(registry, starter.clone()).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                b"POST /.portman/start HTTP/1.1\r\nHost: app.test\r\n\
                  Origin: http://evil.example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        let response = std::str::from_utf8(&received).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
        assert_eq!(starter.starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn non_browser_client_gets_plain_text_error() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let registry = Registry::new();
        registry.upsert(entry("app.test", dead_addr.to_string(), Mode::Http));
        let proxy_addr = proxy_once(registry, StubStarter::inert()).await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        let response = std::str::from_utf8(&received).unwrap();
        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway"));
        assert!(response.contains("Content-Type: text/plain"));
        assert!(response.contains("portman:"));
    }

    // ------------------------------------------------------------------
    // TLS origination: the hop that makes egress usable against real APIs.
    // The upstream below terminates TLS with a self-signed cert (SAN
    // DNS:upstream.test, IP:127.0.0.1 — valid to 2046). CA:FALSE + serverAuth
    // EKU: webpki rejects a CA-flagged cert presented as an end entity, so
    // a self-signed TEST anchor must look like a leaf to be accepted.

    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBxjCCAWygAwIBAgIURAEmBpmle9mg9tnqTE8tzEbSgUkwCgYIKoZIzj0EAwIw\nGDEWMBQGA1UEAwwNdXBzdHJlYW0udGVzdDAeFw0yNjA4MDUyMTM2MDhaFw00NjA3\nMzEyMTM2MDhaMBgxFjAUBgNVBAMMDXVwc3RyZWFtLnRlc3QwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAAT1iGWNv417mKF30LS9yPfySy3M9VLyXAvxvFmPWXdyfC6x\np3YDLAo1mQdqh5XonlL7lV0GGrBv1vRAqXuEI/6Ro4GTMIGQMB0GA1UdDgQWBBR3\nrtZpJbAxWWKEVYbem+S2jRLd8DAfBgNVHSMEGDAWgBR3rtZpJbAxWWKEVYbem+S2\njRLd8DAeBgNVHREEFzAVhwR/AAABgg11cHN0cmVhbS50ZXN0MAwGA1UdEwEB/wQC\nMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqGSM49BAMC\nA0gAMEUCID8kwpEfexKb4x1V+W0eiaVKgYkDR3MBdMb1zqZmKglXAiEAxRdb2u0z\nXNaeAActuCmdfWufobUZaT30vCYXxZTxKi4=\n-----END CERTIFICATE-----\n";

    // Private key of the throwaway self-signed cert above — committed on
    // purpose (it signs nothing real), hence the gitleaks allow.
    const TEST_KEY_PEM: &str = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIMEn2ioqeQH6W6uk6RUs3JJ2t8ScaVkFkvRh8euRycRsoAoGCCqGSM49\nAwEHoUQDQgAE9Yhljb+Ne5ihd9C0vcj38kstzPVS8lwL8bxZj1l3cnwusad2AywK\nNZkHaoeV6J5S+5VdBhqwb9b0QKl7hCP+kQ==\n-----END EC PRIVATE KEY-----\n"; // gitleaks:allow

    /// A TLS-terminating fake upstream: accepts one connection, performs the
    /// handshake with the self-signed cert, captures the request head, and
    /// answers with `response` — same capture contract as [`upstream_once`],
    /// so the assertions below see the bytes AFTER decryption.
    async fn tls_upstream_once(
        response: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut key_bytes = TEST_KEY_PEM.as_bytes();
        let key = rustls_pemfile::private_key(&mut key_bytes)
            .unwrap()
            .expect("test key parses");
        let certs: Vec<_> = rustls_pemfile::certs(&mut TEST_CERT_PEM.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("test cert/key pair valid");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = tls.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            tls.write_all(response).await.unwrap();
            buf
        });
        (addr, handle)
    }

    /// The tracer bullet's final bit: the caller speaks PLAINTEXT to the
    /// proxy, and the upstream — which only speaks TLS — still receives the
    /// authenticated request. This is what turns egress from a test-bench
    /// toy into something you'd point at a real API.
    #[tokio::test]
    async fn egress_route_originates_tls_so_the_credential_reaches_https_upstreams() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (upstream_addr, upstream) = tls_upstream_once(response).await;
        let registry = Registry::new();
        let mut entry = egress_entry("github.api.test", upstream_addr.to_string());
        let spec = entry.egress.as_mut().unwrap();
        spec.tls = true;
        spec.upstream_host = "upstream.test".into();
        registry.upsert(entry);
        let proxy_addr = proxy_once_with(
            registry,
            StubStarter::inert(),
            Arc::new(StubCredentials("s3cret-token")),
            Roots::CustomPem(TEST_CERT_PEM.as_bytes()),
        )
        .await;

        // Caller -> proxy is plaintext; the TLS work happens inside portman.
        let request = b"GET /user HTTP/1.1\r\nHost: github.api.test\r\n\r\n";
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert!(
            std::str::from_utf8(&received)
                .unwrap()
                .starts_with("HTTP/1.1 200 OK"),
            "caller must receive the TLS upstream's response: {:?}",
            String::from_utf8_lossy(&received)
        );

        // What the upstream saw — after decryption, so this is the real
        // end-to-end content, not a transcript of the wire.
        let seen = upstream.await.unwrap();
        let seen = std::str::from_utf8(&seen).unwrap();
        assert!(
            seen.contains("Authorization: Bearer s3cret-token\r\n"),
            "upstream must receive the injected credential: {seen:?}"
        );
        assert!(
            seen.contains("Host: upstream.test\r\n"),
            "upstream must see its own host: {seen:?}"
        );
    }
}
