//! Authenticated egress: attaching a credential the caller never holds.
//!
//! A [`Mode::Egress`](portman_protocol::Mode::Egress) route names an external
//! upstream and a `[secrets.<block>]` key. The proxy resolves that key and
//! rewrites the request head on its way out, so a process reaching the route
//! gets an authenticated request without ever having been given the value —
//! the same shape as an authenticated reverse proxy in front of a REST API.
//!
//! What this does NOT do, so nobody reads more into it than is there: it
//! authenticates nothing about the *caller*. Any local process that can reach
//! the proxy port can use the credential. It stops the value being copied into
//! environments, config files, and logs; it does not stop a process that
//! wanted to make the call from making it.

use std::sync::Arc;

use portman_protocol::EgressSpec;

/// Headers the caller must never dictate on an egress route: the proxy owns
/// authentication and the upstream identity, and it closes the connection
/// after one request (see [`rewrite_head`]).
const CALLER_OWNED: [&str; 4] = ["authorization", "proxy-authorization", "host", "connection"];

/// Case-insensitive membership in [`CALLER_OWNED`].
fn is_caller_owned(name: &str) -> bool {
    CALLER_OWNED
        .iter()
        .any(|owned| name.eq_ignore_ascii_case(owned))
}

/// Resolves the value behind an [`EgressSpec`].
///
/// Threaded into the proxy the same way the runner is, so the proxy gains one
/// capability rather than the whole daemon state. Async because the value may
/// come from a remote provider (Infisical/1Password), resolved at proxy time.
#[async_trait::async_trait]
pub(crate) trait CredentialSource: Send + Sync + 'static {
    /// The secret named by `spec`, or `None` if the block or key is unknown.
    async fn resolve(&self, spec: &EgressSpec) -> Option<String>;
}

/// No egress routes configured; every lookup misses. The host-facing proxy
/// that passes it is macOS-only, so on Linux only tests construct it.
#[cfg(any(target_os = "macos", test))]
pub(crate) struct NoCredentials;

#[cfg(any(target_os = "macos", test))]
#[async_trait::async_trait]
impl CredentialSource for NoCredentials {
    async fn resolve(&self, _spec: &EgressSpec) -> Option<String> {
        None
    }
}

/// Production credential source: delegates to the supervisor, which owns the
/// synced `[secrets.*]` blocks and the provider cache. Kept as a separate
/// type (rather than threading the whole `Supervisor` through the proxy) so
/// the proxy depends on one narrow capability, matching how it gets the
/// runner.
pub(crate) struct SupervisorCredentials {
    pub(crate) supervisor: crate::supervisor::Supervisor,
}

#[async_trait::async_trait]
impl CredentialSource for SupervisorCredentials {
    async fn resolve(&self, spec: &EgressSpec) -> Option<String> {
        self.supervisor.resolve_egress_value(spec).await
    }
}

/// Rebuild a request head for an egress hop.
///
/// Emits from the header PAIRS the proxy's parser already saw (`headers`),
/// never from the raw request bytes. That split is load-bearing: httparse
/// accepts a bare `\n` line terminator, and a pass that re-tokenizes the raw
/// text would disagree with the parser about where a header line ends — a
/// caller could smuggle an unstripped `Authorization` through as a "folded"
/// continuation. Emitting the parsed pairs makes the parser's line
/// boundaries authoritative: whatever it saw as a header line, we see as a
/// header line, and the caller-owned strip applies to every one.
///
/// Four changes, and each is load-bearing:
///
/// - **caller-supplied `Authorization`/`Proxy-Authorization` are dropped.**
///   The injected header is written last, but a duplicate would still reach
///   the upstream, and which one wins is the upstream's choice rather than
///   ours. Stripping is what makes injection authoritative.
/// - **`Host` is rewritten** to the upstream's, since the caller addressed a
///   local name the upstream has never heard of.
/// - **`Connection: close`** — the proxy parses only the FIRST head on a
///   connection and splices the rest verbatim, so a keep-alive connection
///   would carry request 2 straight through unstripped and unauthenticated.
///   Closing after one request is what makes that safe. Removing this without
///   also framing every request is a security regression, not a performance
///   tweak.
/// - **the credential is appended last**, after the strip pass.
///
/// The request line is rebuilt from the parsed method and path (the caller's
/// version is normalized to HTTP/1.1, the only version this proxy speaks).
pub(crate) fn rewrite_head(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    spec: &EgressSpec,
    value: &str,
) -> Vec<u8> {
    let mut out = String::with_capacity(256);
    out.push_str(method);
    out.push(' ');
    out.push_str(path);
    out.push_str(" HTTP/1.1\r\n");
    for (name, val) in headers {
        if is_caller_owned(name) {
            continue;
        }
        out.push_str(name);
        out.push_str(": ");
        out.push_str(val);
        out.push_str("\r\n");
    }
    out.push_str(&format!("Host: {}\r\n", spec.upstream_host));
    out.push_str("Connection: close\r\n");
    let rendered = spec.render(value);
    assert!(
        !rendered.contains(['\r', '\n']),
        "rendered credential contains a newline — refusing to emit a header-smuggling line"
    );
    out.push_str(&format!("{}: {}\r\n", spec.header, rendered));
    out.push_str("\r\n");
    out.into_bytes()
}

/// Everything an egress hop logs. Deliberately structural: it carries the
/// credential's KEY, never its value, so no logging call site can leak one.
pub(crate) struct EgressAudit<'a> {
    pub host: &'a str,
    pub upstream: &'a str,
    pub secrets_block: &'a str,
    pub key: &'a str,
}

impl EgressAudit<'_> {
    pub(crate) fn from_spec<'a>(
        host: &'a str,
        upstream: &'a str,
        spec: &'a EgressSpec,
    ) -> EgressAudit<'a> {
        EgressAudit {
            host,
            upstream,
            secrets_block: &spec.secrets,
            key: &spec.key,
        }
    }
}

/// Convenience alias for the trait object the proxy carries.
pub(crate) type Credentials = Arc<dyn CredentialSource>;

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> EgressSpec {
        EgressSpec {
            secrets: "gh".into(),
            key: "GITHUB_TOKEN".into(),
            header: "Authorization".into(),
            format: "Bearer {value}".into(),
            upstream_host: "api.github.com".into(),
            tls: false,
        }
    }

    /// Parse `raw` the way the proxy does (httparse — accepts both CRLF and
    /// bare-LF terminators) and hand the parsed head to `rewrite_head`, so
    /// these tests exercise exactly the production byte path.
    fn rewrite(raw: &str) -> String {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        let end = match req.parse(raw.as_bytes()).expect("test head parses") {
            httparse::Status::Complete(end) => end,
            httparse::Status::Partial => panic!("test head is partial"),
        };
        let _ = end;
        let method = req.method.unwrap_or("GET").to_string();
        let path = req.path.unwrap_or("/").to_string();
        let pairs: Vec<(String, String)> = req
            .headers
            .iter()
            .filter_map(|h| {
                std::str::from_utf8(h.value)
                    .ok()
                    .map(|value| (h.name.to_string(), value.to_string()))
            })
            .collect();
        String::from_utf8(rewrite_head(&method, &path, &pairs, &spec(), "s3cret")).expect("utf8")
    }

    #[test]
    fn injects_the_credential_and_rewrites_the_upstream_host() {
        let out = rewrite("GET /user HTTP/1.1\r\nHost: github.api.test\r\nAccept: */*\r\n\r\n");
        assert!(out.starts_with("GET /user HTTP/1.1\r\n"), "{out:?}");
        assert!(out.contains("Authorization: Bearer s3cret\r\n"), "{out:?}");
        assert!(out.contains("Host: api.github.com\r\n"), "{out:?}");
        assert!(
            !out.contains("github.api.test"),
            "local host must not leak: {out:?}"
        );
        assert!(
            out.contains("Accept: */*\r\n"),
            "unrelated headers survive: {out:?}"
        );
        assert!(
            out.ends_with("\r\n\r\n"),
            "head must stay terminated: {out:?}"
        );
    }

    #[test]
    fn a_caller_supplied_credential_is_stripped_not_duplicated() {
        let out = rewrite(
            "GET / HTTP/1.1\r\nHost: github.api.test\r\nAuthorization: Bearer attacker\r\nProxy-Authorization: Basic xyz\r\n\r\n",
        );
        assert!(!out.contains("attacker"), "{out:?}");
        assert!(
            !out.to_ascii_lowercase().contains("proxy-authorization"),
            "{out:?}"
        );
        assert_eq!(
            out.matches("Authorization: ").count(),
            1,
            "exactly one authorization header: {out:?}"
        );
    }

    #[test]
    fn header_matching_ignores_case() {
        let out = rewrite(
            "GET / HTTP/1.1\r\nhost: github.api.test\r\nAUTHORIZATION: Bearer attacker\r\n\r\n",
        );
        assert!(!out.contains("attacker"), "{out:?}");
        assert_eq!(out.matches("Host: ").count(), 1, "{out:?}");
    }

    #[test]
    fn keep_alive_is_forced_closed() {
        let out =
            rewrite("GET / HTTP/1.1\r\nHost: github.api.test\r\nConnection: keep-alive\r\n\r\n");
        assert!(out.contains("Connection: close\r\n"), "{out:?}");
        assert_eq!(out.matches("Connection: ").count(), 1, "{out:?}");
    }

    #[test]
    fn the_format_template_is_honoured() {
        let mut spec = spec();
        spec.header = "X-Api-Key".into();
        spec.format = "{value}".into();
        let raw = "GET / HTTP/1.1\r\nHost: github.api.test\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        let _ = req.parse(raw.as_bytes()).unwrap();
        let pairs: Vec<(String, String)> = req
            .headers
            .iter()
            .filter_map(|h| {
                std::str::from_utf8(h.value)
                    .ok()
                    .map(|value| (h.name.to_string(), value.to_string()))
            })
            .collect();
        let out = String::from_utf8(rewrite_head("GET", "/", &pairs, &spec, "abc123")).unwrap();
        assert!(out.contains("X-Api-Key: abc123\r\n"), "{out:?}");
    }

    /// The P0 regression: httparse accepts a bare `\n` line terminator, and
    /// the rewriter must see the same line boundaries the parser saw. A
    /// caller smuggling `Authorization` in a bare-LF "folded" line must not
    /// get it through — the strip pass applies to every parsed header.
    #[test]
    fn bare_lf_headers_are_stripped_like_crlf_ones() {
        let out = rewrite("GET / HTTP/1.1\nHost: github.api.test\nAuthorization: Bearer attacker\nAccept: */*\n\n");
        assert!(!out.contains("attacker"), "{out:?}");
        assert_eq!(
            out.matches("Authorization: ").count(),
            1,
            "exactly one authorization header: {out:?}"
        );
        assert!(out.contains("Accept: */*\r\n"), "{out:?}");
        assert!(out.contains("Connection: close\r\n"), "{out:?}");
    }

    /// A rendered credential that contains a newline would smuggle header
    /// lines (or end the head early); a caller-facing refusal covers it, but
    /// the rewriter itself must refuse to emit it rather than produce a
    /// malformed head on the wire.
    #[test]
    #[should_panic(expected = "newline")]
    fn rendered_value_with_a_newline_is_refused() {
        let mut spec = spec();
        spec.format = "{value}".into();
        let raw = "GET / HTTP/1.1\r\nHost: github.api.test\r\n\r\n";
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        let _ = req.parse(raw.as_bytes()).unwrap();
        let pairs: Vec<(String, String)> = req
            .headers
            .iter()
            .filter_map(|h| {
                std::str::from_utf8(h.value)
                    .ok()
                    .map(|value| (h.name.to_string(), value.to_string()))
            })
            .collect();
        let _ = rewrite_head("GET", "/", &pairs, &spec, "good\r\nX-Injected: yes");
    }
}
