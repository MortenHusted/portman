//! Infisical provider — native universal-auth via reqwest (KTD3).
//!
//! `POST /api/v1/auth/universal-auth/login` with the stored machine
//! identity yields a bearer token (cached, re-login near `expiresIn`);
//! then one list call per configured folder path. The default endpoint is
//! the deprecated-but-universal `/api/v3/secrets/raw` (works on self-hosted
//! instances); `api_version = "v4"` selects `/api/v4/secrets`. On duplicate
//! keys across paths the FIRST path wins — matching the `infisical run
//! --path a --path b` semantics multi-path stacks rely on.
//!
//! Fallback mode (`mode = "cli"`) logs in natively the same way, then
//! shells `infisical export --format=dotenv` with `INFISICAL_TOKEN` — still
//! fully non-interactive — for instances where the API path misbehaves.
//!
//! Error classification (R15): connect/timeout/5xx → transient (retried
//! under the service's backoff policy); 401/403/404 (auth rejection,
//! unknown project/path) → fatal.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use portman_protocol::{InfisicalApiVersion, InfisicalMode, SecretsProviderConfig};
use serde::Deserialize;
use tracing::{debug, warn};

use super::InfisicalCredentials;
use crate::supervisor::SecretsError;

/// Re-login this long before the token's stated expiry.
const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(60);
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const CLI_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct InfisicalClient {
    http: reqwest::Client,
    /// Bearer tokens keyed by `url|client_id`.
    tokens: Mutex<HashMap<String, CachedToken>>,
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Deserialize)]
struct SecretsResponse {
    #[serde(default)]
    secrets: Vec<SecretEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretEntry {
    secret_key: String,
    #[serde(default)]
    secret_value: String,
}

impl Default for InfisicalClient {
    fn default() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .build()
                .expect("building reqwest client"),
            tokens: Mutex::new(HashMap::new()),
        }
    }
}

impl InfisicalClient {
    pub(crate) async fn fetch(
        &self,
        config: &SecretsProviderConfig,
        credentials: &InfisicalCredentials,
    ) -> Result<Vec<(String, String)>, SecretsError> {
        let SecretsProviderConfig::Infisical {
            url,
            project_id,
            environment,
            paths,
            api_version,
            mode,
        } = config
        else {
            return Err(SecretsError::fatal("not an infisical block"));
        };
        let url = url.trim_end_matches('/');
        let token = self.bearer_token(url, credentials).await?;

        // First path wins on duplicate keys (`infisical run` semantics).
        let mut merged: Vec<(String, String)> = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for path in paths {
            let pairs = match mode {
                InfisicalMode::Native => {
                    self.list_path(url, &token, project_id, environment, path, *api_version)
                        .await?
                }
                InfisicalMode::Cli => {
                    cli_export(url, &token, project_id, environment, path).await?
                }
            };
            for (key, value) in pairs {
                if seen.insert(key.clone()) {
                    merged.push((key, value));
                }
            }
        }
        Ok(merged)
    }

    /// A valid bearer token for `url`, logging in (or re-logging near
    /// expiry) with the machine identity.
    async fn bearer_token(
        &self,
        url: &str,
        credentials: &InfisicalCredentials,
    ) -> Result<String, SecretsError> {
        let cache_key = format!("{url}|{}", credentials.client_id);
        {
            let tokens = self.tokens.lock().expect("token cache poisoned");
            if let Some(cached) = tokens.get(&cache_key) {
                if cached.expires_at > Instant::now() {
                    return Ok(cached.token.clone());
                }
            }
        }

        debug!(%url, "infisical universal-auth login");
        let response = self
            .http
            .post(format!("{url}/api/v1/auth/universal-auth/login"))
            .json(&serde_json::json!({
                "clientId": credentials.client_id,
                "clientSecret": credentials.client_secret,
            }))
            .send()
            .await
            .map_err(transport_error)?;
        let login: LoginResponse = decode(response, "universal-auth login").await?;

        let ttl =
            Duration::from_secs(login.expires_in.max(120)).saturating_sub(TOKEN_EXPIRY_MARGIN);
        self.tokens.lock().expect("token cache poisoned").insert(
            cache_key,
            CachedToken {
                token: login.access_token.clone(),
                expires_at: Instant::now() + ttl,
            },
        );
        Ok(login.access_token)
    }

    async fn list_path(
        &self,
        url: &str,
        token: &str,
        project_id: &str,
        environment: &str,
        path: &str,
        api_version: InfisicalApiVersion,
    ) -> Result<Vec<(String, String)>, SecretsError> {
        let request = match api_version {
            InfisicalApiVersion::V3 => self.http.get(format!("{url}/api/v3/secrets/raw")).query(&[
                ("workspaceId", project_id),
                ("environment", environment),
                ("secretPath", path),
                ("expandSecretReferences", "true"),
                ("include_imports", "true"),
            ]),
            InfisicalApiVersion::V4 => self.http.get(format!("{url}/api/v4/secrets")).query(&[
                ("projectId", project_id),
                ("environment", environment),
                ("secretPath", path),
                ("expandSecretReferences", "true"),
            ]),
        };
        let response = request
            .bearer_auth(token)
            .send()
            .await
            .map_err(transport_error)?;
        let listed: SecretsResponse = decode(response, "listing secrets").await?;
        Ok(listed
            .secrets
            .into_iter()
            .map(|s| (s.secret_key, s.secret_value))
            .collect())
    }
}

/// Decode a response, classifying HTTP failures per R15.
async fn decode<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    what: &str,
) -> Result<T, SecretsError> {
    let status = response.status();
    if status.is_success() {
        return response
            .json::<T>()
            .await
            .map_err(|err| SecretsError::fatal(format!("{what}: invalid response: {err}")));
    }
    let body = response.text().await.unwrap_or_default();
    let summary = body.chars().take(200).collect::<String>();
    if status.as_u16() == 401 || status.as_u16() == 403 || status.as_u16() == 404 {
        Err(SecretsError::fatal(format!(
            "{what}: HTTP {status}: {summary}"
        )))
    } else {
        Err(SecretsError::transient(format!(
            "{what}: HTTP {status}: {summary}"
        )))
    }
}

fn transport_error(err: reqwest::Error) -> SecretsError {
    SecretsError::transient(format!("infisical unreachable: {err}"))
}

/// `mode = "cli"` fallback: shell `infisical export` with the natively
/// obtained token — zero interactive login, explicit coordinates.
async fn cli_export(
    url: &str,
    token: &str,
    project_id: &str,
    environment: &str,
    path: &str,
) -> Result<Vec<(String, String)>, SecretsError> {
    let infisical = [
        "/opt/homebrew/bin/infisical",
        "/usr/local/bin/infisical",
        "/usr/bin/infisical", // Linux package installs
    ]
    .iter()
    .find(|p| std::path::Path::new(p).is_file())
    .ok_or_else(|| {
        SecretsError::fatal(
            "mode = \"cli\" but no infisical binary in /opt/homebrew/bin or /usr/local/bin",
        )
    })?;

    let mut cmd = tokio::process::Command::new(infisical);
    cmd.args([
        "export",
        "--format=dotenv",
        "--domain",
        url,
        "--projectId",
        project_id,
        "--env",
        environment,
        "--path",
        path,
    ])
    .env_clear()
    .env("INFISICAL_TOKEN", token)
    .env("HOME", "/tmp") // the CLI insists on a home for its config probe
    .env("PATH", "/usr/bin:/bin")
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());

    let output = tokio::time::timeout(CLI_TIMEOUT, cmd.output())
        .await
        .map_err(|_| SecretsError::transient("infisical export timed out"))?
        .map_err(|err| SecretsError::fatal(format!("spawning infisical export: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail = stderr.lines().last().unwrap_or("").to_string();
        warn!(%tail, "infisical export failed");
        return Err(SecretsError::transient(format!(
            "infisical export failed ({}): {tail}",
            output.status
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_dotenv(&stdout))
}

/// Parse `infisical export --format=dotenv` output (KEY='value' lines).
fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let value = value.trim();
            let value = value
                .strip_prefix('\'')
                .and_then(|v| v.strip_suffix('\''))
                .or_else(|| value.strip_prefix('"').and_then(|v| v.strip_suffix('"')))
                .unwrap_or(value);
            Some((key.trim().to_string(), value.to_string()))
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Minimal canned-response HTTP server: records each request head and
    /// answers from a script. Shared with the mod-level cache tests.
    pub(crate) async fn mock_server(
        responses: Vec<&'static str>,
    ) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        let handle = tokio::spawn(async move {
            for body in responses {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 16384];
                let mut n = 0;
                // Read until the full head (plus any body bytes) arrived.
                loop {
                    let read = stream.read(&mut buf[n..]).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    n += read;
                    let text = String::from_utf8_lossy(&buf[..n]);
                    if let Some(head_end) = text.find("\r\n\r\n") {
                        let head = &text[..head_end];
                        let content_length = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if n >= head_end + 4 + content_length {
                            break;
                        }
                    }
                }
                record
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = stream.write_all(body.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        (format!("http://{addr}"), seen, handle)
    }

    fn canned(status: &str, json: &str) -> &'static str {
        Box::leak(
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
                json.len()
            )
            .into_boxed_str(),
        )
    }

    pub(crate) fn response_line(status: &str, json: &str) -> &'static str {
        canned(status, json)
    }

    fn config(
        url: &str,
        paths: Vec<&str>,
        api_version: InfisicalApiVersion,
    ) -> SecretsProviderConfig {
        SecretsProviderConfig::Infisical {
            url: url.to_string(),
            project_id: "proj-1".into(),
            environment: "dev".into(),
            paths: paths.into_iter().map(String::from).collect(),
            api_version,
            mode: InfisicalMode::Native,
        }
    }

    fn creds() -> InfisicalCredentials {
        InfisicalCredentials {
            client_id: "machine-id".into(),
            client_secret: "machine-secret".into(),
        }
    }

    const LOGIN_OK: &str = r#"{"accessToken":"tok-1","expiresIn":3600}"#;

    #[tokio::test(flavor = "multi_thread")]
    async fn login_then_fetch_composes_the_right_requests() {
        let (url, seen, _handle) = mock_server(vec![
            response_line("200 OK", LOGIN_OK),
            response_line(
                "200 OK",
                r#"{"secrets":[{"secretKey":"A","secretValue":"1"}]}"#,
            ),
        ])
        .await;

        let client = InfisicalClient::default();
        let values = client
            .fetch(
                &config(&url, vec!["/apps/demo"], InfisicalApiVersion::V3),
                &creds(),
            )
            .await
            .unwrap();
        assert_eq!(values, vec![("A".to_string(), "1".to_string())]);

        let seen = seen.lock().unwrap();
        assert!(seen[0].starts_with("POST /api/v1/auth/universal-auth/login"));
        assert!(seen[0].contains(r#""clientId":"machine-id""#));
        assert!(seen[0].contains(r#""clientSecret":"machine-secret""#));
        assert!(seen[1].starts_with("GET /api/v3/secrets/raw?"));
        assert!(seen[1].contains("workspaceId=proj-1"), "{}", seen[1]);
        assert!(seen[1].contains("environment=dev"));
        assert!(seen[1].contains("secretPath=%2Fapps%2Fdemo"));
        assert!(
            seen[1].contains("authorization: Bearer tok-1")
                || seen[1].contains("Authorization: Bearer tok-1")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn v4_request_shape_differs() {
        let (url, seen, _handle) = mock_server(vec![
            response_line("200 OK", LOGIN_OK),
            response_line("200 OK", r#"{"secrets":[]}"#),
        ])
        .await;
        let client = InfisicalClient::default();
        client
            .fetch(
                &config(&url, vec!["/shared"], InfisicalApiVersion::V4),
                &creds(),
            )
            .await
            .unwrap();
        let seen = seen.lock().unwrap();
        assert!(seen[1].starts_with("GET /api/v4/secrets?"), "{}", seen[1]);
        assert!(seen[1].contains("projectId=proj-1"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multi_path_merge_first_path_wins() {
        let (url, _seen, _handle) = mock_server(vec![
            response_line("200 OK", LOGIN_OK),
            response_line(
                "200 OK",
                r#"{"secrets":[{"secretKey":"SHARED","secretValue":"from-first"},{"secretKey":"A","secretValue":"1"}]}"#,
            ),
            response_line(
                "200 OK",
                r#"{"secrets":[{"secretKey":"SHARED","secretValue":"from-second"},{"secretKey":"B","secretValue":"2"}]}"#,
            ),
        ])
        .await;
        let client = InfisicalClient::default();
        let values = client
            .fetch(
                &config(&url, vec!["/apps/demo", "/shared"], InfisicalApiVersion::V3),
                &creds(),
            )
            .await
            .unwrap();
        let map: std::collections::BTreeMap<_, _> = values.into_iter().collect();
        assert_eq!(map["SHARED"], "from-first");
        assert_eq!(map["A"], "1");
        assert_eq!(map["B"], "2");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn token_reused_within_ttl_and_relogin_after_expiry() {
        let (url, seen, _handle) = mock_server(vec![
            // expiresIn 120 is the floor; margin 60 leaves 60s — still valid
            // for the second fetch, so no second login.
            response_line("200 OK", r#"{"accessToken":"tok-1","expiresIn":3600}"#),
            response_line("200 OK", r#"{"secrets":[]}"#),
            response_line("200 OK", r#"{"secrets":[]}"#),
        ])
        .await;
        let client = InfisicalClient::default();
        let cfg = config(&url, vec!["/shared"], InfisicalApiVersion::V3);
        client.fetch(&cfg, &creds()).await.unwrap();
        client.fetch(&cfg, &creds()).await.unwrap();
        {
            let seen = seen.lock().unwrap();
            assert_eq!(
                seen.iter()
                    .filter(|r| r.starts_with("POST /api/v1/auth"))
                    .count(),
                1,
                "token must be reused within its ttl"
            );
        }

        // Force expiry → next fetch re-logs-in.
        {
            let mut tokens = client.tokens.lock().unwrap();
            for cached in tokens.values_mut() {
                cached.expires_at = Instant::now() - Duration::from_secs(1);
            }
        }
        let (url2, seen2, _handle2) = mock_server(vec![
            response_line("200 OK", r#"{"accessToken":"tok-2","expiresIn":3600}"#),
            response_line("200 OK", r#"{"secrets":[]}"#),
        ])
        .await;
        let cfg2 = config(&url2, vec!["/shared"], InfisicalApiVersion::V3);
        client.fetch(&cfg2, &creds()).await.unwrap();
        let seen2 = seen2.lock().unwrap();
        assert!(
            seen2[0].starts_with("POST /api/v1/auth"),
            "expired token must re-login"
        );
        assert!(seen2[1].contains("Bearer tok-2") || seen2[1].contains("bearer tok-2"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_401_is_fatal_and_5xx_transient() {
        let (url, _seen, _handle) = mock_server(vec![response_line(
            "401 Unauthorized",
            r#"{"message":"bad identity"}"#,
        )])
        .await;
        let client = InfisicalClient::default();
        let err = client
            .fetch(
                &config(&url, vec!["/shared"], InfisicalApiVersion::V3),
                &creds(),
            )
            .await
            .unwrap_err();
        assert!(!err.transient, "auth rejection must be fatal: {err:?}");

        let (url, _seen, _handle) = mock_server(vec![response_line(
            "503 Service Unavailable",
            r#"{"message":"maintenance"}"#,
        )])
        .await;
        let err = client
            .fetch(
                &config(&url, vec!["/shared"], InfisicalApiVersion::V3),
                &creds(),
            )
            .await
            .unwrap_err();
        assert!(err.transient, "5xx must be transient: {err:?}");
    }

    #[test]
    fn dotenv_parse_handles_quotes_and_comments() {
        let parsed = parse_dotenv("# comment\nA='one'\nB=\"two\"\nC=three\n\n");
        assert_eq!(
            parsed,
            vec![
                ("A".to_string(), "one".to_string()),
                ("B".to_string(), "two".to_string()),
                ("C".to_string(), "three".to_string()),
            ]
        );
    }
}
