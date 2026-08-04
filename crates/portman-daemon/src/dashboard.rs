//! Localhost web dashboard — static UI + JSON API mirroring IPC.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use httparse::Request as HttpRequest;
use httparse::Status;
use portman_core::{Mode, Request, Response};
use rust_embed::Embed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::handlers;
use crate::DaemonState;

const MAX_HEADER_BYTES: usize = 8192;
const MAX_BODY_BYTES: usize = 65536;

#[derive(Embed)]
#[folder = "dashboard/"]
struct Assets;

pub(crate) async fn run(state: DaemonState, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding dashboard on {addr}"))?;
    info!(%addr, "dashboard listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, state).await {
                warn!(error = %err, "dashboard client error");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, state: DaemonState) -> Result<()> {
    let mut buf = vec![0u8; MAX_HEADER_BYTES + MAX_BODY_BYTES];
    let n = stream
        .read(&mut buf)
        .await
        .context("reading dashboard request")?;
    if n == 0 {
        return Ok(());
    }

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = HttpRequest::new(&mut headers);
    let header_len = match req.parse(&buf[..n]) {
        Ok(Status::Complete(len)) => len,
        Ok(Status::Partial) => return Ok(()),
        Err(e) => return Err(anyhow::anyhow!("parse request: {e:?}")),
    };
    if req.version != Some(1) {
        return write_response(stream, 505, "text/plain", b"HTTP Version Not Supported").await;
    }

    let method = req.method.unwrap_or("GET");
    let raw_path = req.path.unwrap_or("/");
    let (path, query) = match raw_path.split_once('?') {
        Some((path, query)) => (path, query),
        None => (raw_path, ""),
    };
    let body = if header_len < n {
        &buf[header_len..n]
    } else {
        &[]
    };

    // Security: the dashboard is a localhost control API that can add/remove
    // proxy routes, but any process — or web page — able to reach 127.0.0.1 can
    // call it. Reject rebound hostnames (DNS rebinding) on every request, and
    // reject cross-origin state changes (CSRF) on mutating methods. Same-origin
    // requests from the dashboard itself carry a loopback Host/Origin and pass;
    // non-browser clients (no Origin) are still gated by the Host check.
    if !host_is_local(header_value(&req, "host")) {
        return write_response(stream, 403, "text/plain", b"Forbidden").await;
    }
    if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
        if let Some(origin) = header_value(&req, "origin") {
            if !origin_is_local(origin) {
                return write_response(stream, 403, "text/plain", b"Forbidden").await;
            }
        }
    }

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => serve_asset(stream, "index.html").await,
        ("GET", "/style.css") => serve_asset(stream, "style.css").await,
        ("GET", "/app.js") => serve_asset(stream, "app.js").await,
        ("GET", "/api/status") => api_json(stream, handlers::handle_status(&state).await).await,
        ("GET", "/api/entries") => {
            api_json(
                stream,
                handlers::dispatch(Request::ListEntries, &state).await,
            )
            .await
        }
        ("GET", "/api/tlds") => {
            api_json(stream, handlers::dispatch(Request::TldList, &state).await).await
        }
        ("GET", "/api/certs") => {
            api_json(
                stream,
                handlers::dispatch(Request::CertHealth, &state).await,
            )
            .await
        }
        ("GET", "/api/resources") => {
            api_json(
                stream,
                handlers::dispatch(Request::ResourceUsage, &state).await,
            )
            .await
        }
        ("GET", "/api/resources/history") => {
            api_json(
                stream,
                handlers::dispatch(Request::ResourceHistory, &state).await,
            )
            .await
        }
        ("GET", "/api/services") => {
            api_json(
                stream,
                handlers::dispatch(Request::ServiceStatus, &state).await,
            )
            .await
        }
        // Cursor read of a supervised service's captured output. Keyed by
        // *service name* (host is optional on a service). Read-only: the
        // Host check above is the whole gate, same as the other GETs.
        ("GET", path) if path.starts_with("/api/services/") && path.ends_with("/logs") => {
            let segment = &path["/api/services/".len()..path.len() - "/logs".len()];
            let service = urlencoding_path_segment(segment);
            let (after_id, limit) = parse_logs_query(query);
            api_json(
                stream,
                handlers::dispatch(
                    Request::LogsQuery {
                        service,
                        after_id,
                        limit,
                    },
                    &state,
                )
                .await,
            )
            .await
        }
        ("POST", "/api/static") => handle_add_static(stream, state, body).await,
        ("GET", "/api/config") => handle_config_get(stream, state, query).await,
        ("POST", "/api/config") => handle_config_post(stream, state, body).await,
        // Batch lifecycle: a JSON body of names, straight onto the same IPC
        // requests `portman up a b c` uses. This is how a whole group stops
        // in one action instead of N round-trips.
        ("POST", "/api/services/up") => handle_batch(stream, state, body, true).await,
        ("POST", "/api/services/down") => handle_batch(stream, state, body, false).await,
        // Supervisor lifecycle, keyed by *service name*. `up`/`down` map
        // straight onto the IPC requests `portman up`/`down` use; `restart`
        // is down-then-up server-side so the dashboard can't half-do it.
        ("POST", path) if path.starts_with("/api/service/") && path.ends_with("/up") => {
            let segment = &path["/api/service/".len()..path.len() - "/up".len()];
            let names = vec![urlencoding_path_segment(segment)];
            api_json(
                stream,
                handlers::dispatch(Request::ServiceUp { names }, &state).await,
            )
            .await
        }
        ("POST", path) if path.starts_with("/api/service/") && path.ends_with("/down") => {
            let segment = &path["/api/service/".len()..path.len() - "/down".len()];
            let names = vec![urlencoding_path_segment(segment)];
            api_json(
                stream,
                handlers::dispatch(Request::ServiceDown { names }, &state).await,
            )
            .await
        }
        ("POST", path) if path.starts_with("/api/service/") && path.ends_with("/restart") => {
            let segment = &path["/api/service/".len()..path.len() - "/restart".len()];
            let names = vec![urlencoding_path_segment(segment)];
            let down = handlers::dispatch(
                Request::ServiceDown {
                    names: names.clone(),
                },
                &state,
            )
            .await;
            if matches!(down, Response::Err { .. }) {
                return api_json(stream, down).await;
            }
            api_json(
                stream,
                handlers::dispatch(Request::ServiceUp { names }, &state).await,
            )
            .await
        }
        ("POST", path) if path.starts_with("/api/services/") && path.ends_with("/start") => {
            let segment = &path["/api/services/".len()..path.len() - "/start".len()];
            let host = urlencoding_path_segment(segment);
            api_json(
                stream,
                handlers::dispatch(Request::StartService { host }, &state).await,
            )
            .await
        }
        ("DELETE", path) if path.starts_with("/api/static/") => {
            let host = urlencoding_path_segment(&path["/api/static/".len()..]);
            api_json(
                stream,
                handlers::dispatch(Request::RemoveStatic { host }, &state).await,
            )
            .await
        }
        _ => write_response(stream, 404, "text/plain", b"Not Found").await,
    }
}

/// Look up a request header value case-insensitively.
fn header_value<'b>(req: &HttpRequest<'_, 'b>, name: &str) -> Option<&'b str> {
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
}

/// Accept only loopback `Host` values, so a page served from a rebound hostname
/// (DNS rebinding) can't drive the control API. The dashboard binds 127.0.0.1,
/// so legitimate clients send `127.0.0.1` or `localhost` (optionally with a port).
fn host_is_local(host: Option<&str>) -> bool {
    let Some(host) = host.map(str::trim) else {
        return false;
    };
    // Strip a trailing :port, but not the colons inside an IPv6 literal.
    let bare = match host.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    };
    let bare = bare.trim_start_matches('[').trim_end_matches(']');
    matches!(bare, "127.0.0.1" | "localhost" | "::1")
}

/// For state-changing requests, reject a cross-origin `Origin` (CSRF). A
/// same-origin request from the dashboard carries a loopback origin; an opaque
/// or foreign origin is untrusted.
fn origin_is_local(origin: &str) -> bool {
    match origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    {
        Some(host_port) => host_is_local(Some(host_port)),
        None => false,
    }
}

/// The two names the config editor may touch — nothing else, ever.
const CONFIG_FILES: [&str; 2] = [
    portman_core::service_config::CONFIG_FILE,
    portman_core::service_config::LOCAL_CONFIG_FILE,
];

fn config_root_allowed(state: &DaemonState, root: &std::path::Path) -> bool {
    state.supervisor.known_roots().iter().any(|r| r == root)
}

fn config_query_root(query: &str) -> Option<std::path::PathBuf> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == "root").then(|| std::path::PathBuf::from(url_decode(value)))
    })
}

async fn handle_config_get(stream: TcpStream, state: DaemonState, query: &str) -> Result<()> {
    let Some(root) = config_query_root(query) else {
        return api_json(stream, err_response("missing `root` query parameter")).await;
    };
    if !config_root_allowed(&state, &root) {
        return api_json(
            stream,
            err_response(&format!(
                "`{}` is not a root the daemon supervises",
                root.display()
            )),
        )
        .await;
    }
    let files: Vec<serde_json::Value> = CONFIG_FILES
        .iter()
        .map(|name| {
            let content = std::fs::read_to_string(root.join(name)).ok();
            serde_json::json!({
                "name": name,
                "present": content.is_some(),
                "content": content.unwrap_or_default(),
            })
        })
        .collect();
    let body = serde_json::json!({ "kind": "config", "root": root, "files": files });
    let bytes = serde_json::to_vec(&body)?;
    write_response(stream, 200, "application/json", &bytes).await
}

async fn handle_config_post(stream: TcpStream, state: DaemonState, body: &[u8]) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct Edit {
        root: std::path::PathBuf,
        file: String,
        content: String,
    }
    let edit: Edit = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return api_json(stream, err_response(&format!("invalid JSON: {e}"))).await,
    };
    if !CONFIG_FILES.contains(&edit.file.as_str()) {
        return api_json(
            stream,
            err_response("file must be portman.toml or portman.local.toml"),
        )
        .await;
    }
    if !config_root_allowed(&state, &edit.root) {
        return api_json(
            stream,
            err_response(&format!(
                "`{}` is not a root the daemon supervises",
                edit.root.display()
            )),
        )
        .await;
    }

    // Validate the edited buffer merged with its on-disk sibling BEFORE
    // anything touches disk — the exact resolve `portman up` runs.
    let sibling_name = CONFIG_FILES
        .iter()
        .find(|n| **n != edit.file)
        .expect("two config filenames");
    let sibling = std::fs::read_to_string(edit.root.join(sibling_name)).ok();
    let (committed, local) = if edit.file == portman_core::service_config::CONFIG_FILE {
        (Some(edit.content.as_str()), sibling.as_deref())
    } else {
        (sibling.as_deref(), Some(edit.content.as_str()))
    };
    if let Err(e) = portman_core::service_config::load_from_strings(&edit.root, committed, local) {
        return api_json(stream, err_response(&format!("{e:#}"))).await;
    }

    if let Err(e) = write_config_preserving_owner(&edit.root, &edit.file, &edit.content) {
        return api_json(stream, err_response(&format!("writing config: {e:#}"))).await;
    }

    // Apply: same load + sync `portman up` performs (sync restarts changed
    // running services and drops removed ones; added services are synced but
    // not started).
    let config = match portman_core::service_config::load(&edit.root) {
        Ok(c) => c,
        Err(e) => {
            return api_json(stream, err_response(&format!("re-reading config: {e:#}"))).await
        }
    };
    let services: Vec<_> = config.services.into_values().collect();
    match state
        .supervisor
        .sync(&edit.root, services, config.secrets)
        .await
    {
        Ok(report) => {
            api_json(
                stream,
                Response::SyncReport {
                    added: report.added,
                    updated: report.updated,
                    removed: report.removed,
                    unchanged: report.unchanged,
                },
            )
            .await
        }
        Err(e) => api_json(stream, err_response(&format!("applying config: {e:#}"))).await,
    }
}

/// Atomic write that keeps the file owned by whoever owns it now (or the repo
/// root, for a new file). The daemon runs as root; a root-owned file
/// appearing in the user's repo breaks their editor and their git.
fn write_config_preserving_owner(
    root: &std::path::Path,
    file: &str,
    content: &str,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::os::unix::fs::MetadataExt;

    let target = root.join(file);
    let meta = std::fs::metadata(&target).or_else(|_| std::fs::metadata(root));
    let (uid, gid) = meta
        .map(|m| (m.uid(), m.gid()))
        .context("stat config target")?;

    let tmp = root.join(format!(".{file}.portman-edit.tmp"));
    std::fs::write(&tmp, content).with_context(|| format!("writing {}", tmp.display()))?;
    std::os::unix::fs::chown(&tmp, Some(uid), Some(gid))
        .with_context(|| format!("chown {}", tmp.display()))?;
    std::fs::rename(&tmp, &target)
        .with_context(|| format!("renaming into {}", target.display()))?;
    Ok(())
}

fn err_response(message: &str) -> Response {
    Response::Err {
        message: message.to_string(),
    }
}

async fn handle_batch(stream: TcpStream, state: DaemonState, body: &[u8], up: bool) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct Batch {
        names: Vec<String>,
    }
    let parsed: Batch = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(err) => {
            return api_json(
                stream,
                Response::Err {
                    message: format!("invalid JSON: {err}"),
                },
            )
            .await;
        }
    };
    if parsed.names.is_empty() {
        // An empty list means "everything" at the IPC layer — far too big a
        // hammer to hand a web endpoint. Be explicit or be refused.
        return api_json(
            stream,
            Response::Err {
                message: "names must not be empty".into(),
            },
        )
        .await;
    }
    let request = if up {
        Request::ServiceUp {
            names: parsed.names,
        }
    } else {
        Request::ServiceDown {
            names: parsed.names,
        }
    };
    api_json(stream, handlers::dispatch(request, &state).await).await
}

async fn handle_add_static(stream: TcpStream, state: DaemonState, body: &[u8]) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct AddBody {
        host: String,
        target: String,
        #[serde(default)]
        mode: String,
        #[serde(default)]
        service: Option<String>,
    }
    let parsed: AddBody = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(err) => {
            return api_json(
                stream,
                Response::Err {
                    message: format!("invalid JSON: {err}"),
                },
            )
            .await;
        }
    };
    let mode = if parsed.mode.eq_ignore_ascii_case("tcp") {
        Mode::Tcp
    } else {
        Mode::Http
    };
    api_json(
        stream,
        handlers::dispatch(
            Request::AddStatic {
                host: parsed.host,
                target: parsed.target,
                mode,
                service: parsed.service.filter(|s| !s.trim().is_empty()),
            },
            &state,
        )
        .await,
    )
    .await
}

fn urlencoding_path_segment(s: &str) -> String {
    url_decode(s)
}

/// `after=<id>&limit=<n>` → (cursor, limit). Missing/garbled params fall
/// back to the tail-read defaults.
fn parse_logs_query(query: &str) -> (Option<i64>, u32) {
    let mut after_id = None;
    let mut limit = 200;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key {
            "after" => after_id = value.parse().ok(),
            "limit" => limit = value.parse().unwrap_or(200),
            _ => {}
        }
    }
    (after_id, limit)
}

fn url_decode(input: &str) -> String {
    let mut out = String::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

async fn serve_asset(stream: TcpStream, file: &str) -> Result<()> {
    let content = Assets::get(file).ok_or_else(|| anyhow::anyhow!("missing asset {file}"))?;
    let mime = mime_guess::from_path(file)
        .first_or_octet_stream()
        .essence_str()
        .to_string();
    write_response(stream, 200, &mime, content.data.as_ref()).await
}

async fn api_json(stream: TcpStream, response: Response) -> Result<()> {
    let body = serde_json::to_vec(&response).context("serializing API response")?;
    write_response(stream, 200, "application/json", &body).await
}

async fn write_response(
    mut stream: TcpStream,
    code: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let status = match code {
        200 => "200 OK",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        505 => "505 HTTP Version Not Supported",
        _ => "500 Internal Server Error",
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await.ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        config_query_root, host_is_local, origin_is_local, parse_logs_query,
        write_config_preserving_owner,
    };

    #[test]
    fn config_root_query_is_url_decoded() {
        assert_eq!(
            config_query_root("root=%2FUsers%2Fdev%2Fprojects%2Fdemo"),
            Some(std::path::PathBuf::from("/Users/dev/projects/demo"))
        );
        assert_eq!(config_query_root("other=x"), None);
    }

    #[test]
    fn config_write_is_atomic_and_keeps_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("portman.local.toml"), "old").unwrap();
        write_config_preserving_owner(dir.path(), "portman.local.toml", "new-content").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("portman.local.toml")).unwrap(),
            "new-content"
        );
        // No temp litter left behind.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    #[test]
    fn logs_query_params_honored() {
        assert_eq!(parse_logs_query(""), (None, 200));
        assert_eq!(parse_logs_query("after=42"), (Some(42), 200));
        assert_eq!(parse_logs_query("after=42&limit=50"), (Some(42), 50));
        assert_eq!(parse_logs_query("limit=50"), (None, 50));
        assert_eq!(parse_logs_query("after=junk&limit=junk"), (None, 200));
    }

    #[test]
    fn accepts_loopback_hosts() {
        for h in [
            "127.0.0.1",
            "127.0.0.1:7341",
            "localhost",
            "localhost:7341",
            "[::1]:7341",
        ] {
            assert!(host_is_local(Some(h)), "should accept {h}");
        }
    }

    #[test]
    fn rejects_rebound_and_missing_hosts() {
        for h in [
            "evil.com",
            "evil.com:7341",
            "localhost.evil.com",
            "app.acme.internal",
            "0.0.0.0",
        ] {
            assert!(!host_is_local(Some(h)), "should reject {h}");
        }
        assert!(!host_is_local(None));
    }

    #[test]
    fn origin_only_trusts_loopback() {
        assert!(origin_is_local("http://127.0.0.1:7341"));
        assert!(origin_is_local("http://localhost:7341"));
        assert!(!origin_is_local("http://evil.com"));
        assert!(!origin_is_local("https://localhost.evil.com"));
        assert!(!origin_is_local("null"));
    }
}
