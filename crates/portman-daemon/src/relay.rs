//! Client→upstream relay that stamps every request with the forwarded
//! headers a backend needs to know how it was reached.
//!
//! The proxies terminate TLS (or accept plain HTTP) and hand the backend a
//! plain-HTTP byte stream. Without `X-Forwarded-Proto` a Rails/Django/Phoenix
//! app behind an https entry believes it is serving http: CSRF origin checks
//! reject forms, `request.ssl?` lies, and generated URLs carry the wrong
//! scheme.
//!
//! Injecting into the first request only would be worse than nothing —
//! browsers reuse connections, so later requests on the same keep-alive
//! connection would arrive without the header and the backend would flip
//! scheme mid-connection. So the client→upstream direction is a per-request
//! loop: parse each head, rewrite it, forward the body by its framing
//! (Content-Length or chunked), repeat. An `Upgrade` request switches the
//! rest of the connection to an opaque splice, which keeps WebSockets intact.
//! The upstream→client direction is copied verbatim throughout.

use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How the client reached the proxy — the value `X-Forwarded-Proto` carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

/// Max bytes accumulated while searching for the end of a request head.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Splice `client` and `upstream`, rewriting every request head on the way
/// up. `initial` holds bytes already read from the client (at least one
/// complete head, possibly more). Returns `(client_bytes, upstream_bytes)`
/// like `copy_bidirectional`.
pub(crate) async fn relay<C, U>(
    client: &mut C,
    upstream: &mut U,
    initial: Vec<u8>,
    scheme: Scheme,
    peer: IpAddr,
) -> Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_rd, mut client_wr) = tokio::io::split(client);
    let (mut upstream_rd, mut upstream_wr) = tokio::io::split(upstream);

    let up = async {
        let n = forward_requests(&mut client_rd, &mut upstream_wr, initial, scheme, peer).await;
        // Client is done sending: pass the half-close on so the upstream
        // sees EOF, exactly as copy_bidirectional would.
        upstream_wr.shutdown().await.ok();
        n
    };
    let down = async {
        let n = tokio::io::copy(&mut upstream_rd, &mut client_wr).await;
        client_wr.shutdown().await.ok();
        n
    };
    let (up, down) = tokio::join!(up, down);
    Ok((up?, down.context("copying upstream to client")?))
}

/// Body framing of one request, per RFC 9112 §6.
enum Body {
    Fixed(u64),
    Chunked,
}

/// The per-request loop. Consumes `buf` (already-read client bytes) and then
/// `client`; returns the total bytes read from the client.
async fn forward_requests<R, W>(
    client: &mut R,
    upstream: &mut W,
    mut buf: Vec<u8>,
    scheme: Scheme,
    peer: IpAddr,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = buf.len() as u64;
    let mut chunk = [0u8; 8192];

    loop {
        // Find a complete head, reading more as needed.
        let parsed = loop {
            match parse_head(&buf, scheme, peer)? {
                Some(parsed) => break parsed,
                None if buf.len() >= MAX_HEADER_BYTES => bail!("request head exceeds limit"),
                None => {
                    let n = client.read(&mut chunk).await.context("reading request")?;
                    if n == 0 {
                        // EOF mid-head. Whatever is buffered is either
                        // nothing (clean close) or a fragment the upstream
                        // can reject itself.
                        upstream.write_all(&buf).await?;
                        return Ok(total);
                    }
                    total += n as u64;
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
        };

        upstream.write_all(&parsed.head).await?;
        buf.drain(..parsed.head_len);

        if parsed.upgrade {
            // WebSocket (or any other) upgrade: the rest of the connection is
            // not HTTP. Flush what we have and splice raw until EOF.
            upstream.write_all(&buf).await?;
            total += tokio::io::copy(client, upstream).await?;
            return Ok(total);
        }

        match parsed.body {
            Body::Fixed(len) => {
                total += forward_fixed(client, upstream, &mut buf, len).await?;
            }
            Body::Chunked => {
                total += forward_chunked(client, upstream, &mut buf).await?;
            }
        }
    }
}

struct ParsedHead {
    head: Vec<u8>,
    head_len: usize,
    body: Body,
    upgrade: bool,
}

/// Parse one request head from the front of `buf` and render the rewritten
/// head. `None` when the head is still incomplete.
fn parse_head(buf: &[u8], scheme: Scheme, peer: IpAddr) -> Result<Option<ParsedHead>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let head_len = match req.parse(buf).context("parsing request head")? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Ok(None),
    };

    let mut head = Vec::with_capacity(head_len + 64);
    head.extend_from_slice(req.method.unwrap_or("GET").as_bytes());
    head.push(b' ');
    head.extend_from_slice(req.path.unwrap_or("/").as_bytes());
    head.extend_from_slice(b" HTTP/1.");
    head.extend_from_slice(if req.version == Some(0) { b"0" } else { b"1" });
    head.extend_from_slice(b"\r\n");

    let mut body = Body::Fixed(0);
    let mut upgrade = false;
    let mut forwarded_for: Option<Vec<u8>> = None;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("x-forwarded-proto") {
            // The proxy is the authority on how it was reached; a
            // client-supplied value is dropped rather than trusted.
            continue;
        }
        if h.name.eq_ignore_ascii_case("x-forwarded-for") {
            forwarded_for = Some(h.value.to_vec());
            continue;
        }
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            if ascii_contains_token(h.value, "chunked") {
                body = Body::Chunked;
            }
        } else if h.name.eq_ignore_ascii_case("content-length") {
            if !matches!(body, Body::Chunked) {
                let len = std::str::from_utf8(h.value)
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .context("invalid Content-Length")?;
                body = Body::Fixed(len);
            }
        } else if h.name.eq_ignore_ascii_case("upgrade") {
            upgrade = true;
        }
        head.extend_from_slice(h.name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(h.value);
        head.extend_from_slice(b"\r\n");
    }

    head.extend_from_slice(b"X-Forwarded-Proto: ");
    head.extend_from_slice(scheme.as_str().as_bytes());
    head.extend_from_slice(b"\r\nX-Forwarded-For: ");
    if let Some(prior) = forwarded_for {
        head.extend_from_slice(&prior);
        head.extend_from_slice(b", ");
    }
    head.extend_from_slice(peer.to_string().as_bytes());
    head.extend_from_slice(b"\r\n\r\n");

    Ok(Some(ParsedHead {
        head,
        head_len,
        body,
        upgrade,
    }))
}

/// `<[u8]>::trim_ascii` is 1.80; the crate MSRV is 1.78.
fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if !first.is_ascii_whitespace() {
            break;
        }
        bytes = rest;
    }
    while let [rest @ .., last] = bytes {
        if !last.is_ascii_whitespace() {
            break;
        }
        bytes = rest;
    }
    bytes
}

/// Does a comma-separated header value carry `token` (case-insensitive)?
fn ascii_contains_token(value: &[u8], token: &str) -> bool {
    value
        .split(|&b| b == b',')
        .any(|part| trim_ascii(part).eq_ignore_ascii_case(token.as_bytes()))
}

/// Forward exactly `len` body bytes, draining `buf` first. Bytes beyond the
/// body stay in `buf` for the next head. Returns bytes newly read.
async fn forward_fixed<R, W>(
    client: &mut R,
    upstream: &mut W,
    buf: &mut Vec<u8>,
    len: u64,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = len;
    let mut read = 0u64;
    let mut chunk = [0u8; 8192];
    loop {
        let take = (buf.len() as u64).min(remaining) as usize;
        upstream.write_all(&buf[..take]).await?;
        buf.drain(..take);
        remaining -= take as u64;
        if remaining == 0 {
            return Ok(read);
        }
        let n = client
            .read(&mut chunk)
            .await
            .context("reading request body")?;
        if n == 0 {
            bail!("client closed mid-body ({remaining} bytes short)");
        }
        read += n as u64;
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Forward a chunked body through its terminating chunk and trailers. Bytes
/// beyond the body stay in `buf` for the next head. Returns bytes newly read.
async fn forward_chunked<R, W>(client: &mut R, upstream: &mut W, buf: &mut Vec<u8>) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut read = 0u64;
    loop {
        let line = read_line(client, buf, &mut read).await?;
        let size_text = std::str::from_utf8(&buf[..line])
            .ok()
            .and_then(|s| s.split(';').next())
            .map(str::trim)
            .context("invalid chunk size line")?;
        let size = u64::from_str_radix(size_text, 16).context("invalid chunk size")?;
        // chunk-size line + data + CRLF, or for the last chunk just the line
        // and then the trailer section through its blank line.
        if size == 0 {
            read += forward_fixed(client, upstream, buf, line as u64 + 2).await?;
            loop {
                let trailer = read_line(client, buf, &mut read).await?;
                read += forward_fixed(client, upstream, buf, trailer as u64 + 2).await?;
                if trailer == 0 {
                    return Ok(read);
                }
            }
        }
        read += forward_fixed(client, upstream, buf, line as u64 + 2 + size + 2).await?;
    }
}

/// Ensure `buf` starts with a complete CRLF-terminated line and return its
/// length excluding the CRLF. Nothing is consumed.
async fn read_line<R>(client: &mut R, buf: &mut Vec<u8>, read: &mut u64) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            return Ok(pos);
        }
        if buf.len() >= MAX_HEADER_BYTES {
            bail!("chunk line exceeds limit");
        }
        let n = client
            .read(&mut chunk)
            .await
            .context("reading chunked body")?;
        if n == 0 {
            bail!("client closed mid-chunked-body");
        }
        *read += n as u64;
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// Run the relay over in-memory pipes: `client_bytes` are fed through
    /// (the first head as `initial`, the rest streamed), the fake upstream
    /// replies with `response` and closes. Returns what the upstream saw and
    /// what the client got back.
    async fn run_relay(
        client_bytes: &[u8],
        initial_len: usize,
        scheme: Scheme,
        response: &'static [u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let (mut client_side, mut proxy_client) = tokio::io::duplex(64 * 1024);
        let (mut proxy_upstream, mut upstream_side) = tokio::io::duplex(64 * 1024);
        let initial = client_bytes[..initial_len].to_vec();
        let rest = client_bytes[initial_len..].to_vec();

        let client = tokio::spawn(async move {
            client_side.write_all(&rest).await.unwrap();
            client_side.shutdown().await.unwrap();
            let mut got = Vec::new();
            client_side.read_to_end(&mut got).await.unwrap();
            got
        });
        let upstream = tokio::spawn(async move {
            let mut seen = Vec::new();
            upstream_side.read_to_end(&mut seen).await.unwrap();
            upstream_side.write_all(response).await.unwrap();
            upstream_side.shutdown().await.unwrap();
            seen
        });

        relay(
            &mut proxy_client,
            &mut proxy_upstream,
            initial,
            scheme,
            PEER,
        )
        .await
        .unwrap();
        drop(proxy_client);
        drop(proxy_upstream);
        (upstream.await.unwrap(), client.await.unwrap())
    }

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn every_request_on_a_keep_alive_connection_carries_the_scheme() {
        let first = b"GET /a HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let second = b"GET /b HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n";
        let mut all = first.to_vec();
        all.extend_from_slice(second);

        let (seen, _) = run_relay(&all, first.len(), Scheme::Https, b"").await;
        let seen = text(&seen);
        let heads: Vec<&str> = seen.split("\r\n\r\n").filter(|h| !h.is_empty()).collect();
        assert_eq!(heads.len(), 2, "{seen}");
        for head in heads {
            assert!(head.contains("\r\nX-Forwarded-Proto: https\r\n"), "{head}");
            assert!(head.ends_with("\r\nX-Forwarded-For: 127.0.0.1"), "{head}");
        }
        assert!(seen.starts_with("GET /a HTTP/1.1\r\nHost: app.test\r\n"));
        assert!(seen.contains("GET /b HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n"));
    }

    #[tokio::test]
    async fn client_supplied_proto_is_replaced_and_for_is_appended() {
        let req = b"GET / HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 10.0.0.9\r\n\r\n";
        let (seen, _) = run_relay(req, req.len(), Scheme::Http, b"").await;
        let seen = text(&seen);
        assert_eq!(seen.matches("X-Forwarded-Proto").count(), 1, "{seen}");
        assert!(seen.contains("X-Forwarded-Proto: http\r\n"), "{seen}");
        assert!(
            seen.contains("X-Forwarded-For: 10.0.0.9, 127.0.0.1\r\n"),
            "{seen}"
        );
    }

    #[tokio::test]
    async fn content_length_body_is_forwarded_intact_and_the_next_head_is_rewritten() {
        let post =
            b"POST /form HTTP/1.1\r\nHost: app.test\r\nContent-Length: 11\r\n\r\nhello\r\n\r\nxx";
        let get = b"GET /next HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let mut all = post.to_vec();
        all.extend_from_slice(get);
        // Split so the body arrives in a later read than the first head.
        let (seen, _) = run_relay(&all, 40, Scheme::Https, b"").await;
        let seen = text(&seen);
        assert!(
            seen.contains(
                "X-Forwarded-For: 127.0.0.1\r\n\r\nhello\r\n\r\nxxGET /next HTTP/1.1\r\n"
            ),
            "{seen}"
        );
        assert_eq!(
            seen.matches("X-Forwarded-Proto: https").count(),
            2,
            "{seen}"
        );
    }

    #[tokio::test]
    async fn chunked_body_is_forwarded_through_its_trailers() {
        let post = b"POST /up HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n";
        let get = b"GET /next HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let mut all = post.to_vec();
        all.extend_from_slice(get);
        let (seen, _) = run_relay(&all, 30, Scheme::Https, b"").await;
        let seen = text(&seen);
        assert!(
            seen.contains("\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\nGET /next HTTP/1.1\r\n"),
            "{seen}"
        );
        assert_eq!(
            seen.matches("X-Forwarded-Proto: https").count(),
            2,
            "{seen}"
        );
    }

    #[tokio::test]
    async fn upgrade_switches_to_an_opaque_splice() {
        let req = b"GET /cable HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let frames = b"\x81\x05hello GET /not-http HTTP/1.1\r\n\r\n garbage";
        let mut all = req.to_vec();
        all.extend_from_slice(frames);
        let (seen, _) = run_relay(&all, req.len(), Scheme::Https, b"").await;
        assert!(text(&seen[..seen.len() - frames.len()]).contains("Upgrade: websocket\r\n"));
        assert!(text(&seen[..seen.len() - frames.len()]).contains("X-Forwarded-Proto: https\r\n"));
        assert_eq!(&seen[seen.len() - frames.len()..], frames);
    }

    #[tokio::test]
    async fn upstream_response_reaches_the_client_verbatim() {
        let req = b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (_, got) = run_relay(req, req.len(), Scheme::Http, response).await;
        assert_eq!(got, response);
    }
}
