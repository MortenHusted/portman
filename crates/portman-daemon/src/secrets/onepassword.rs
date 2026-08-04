//! 1Password provider — `op` CLI with a service-account token (KTD4).
//!
//! A `[secrets.<name>]` block with `provider = "1password"` maps env keys to
//! `op://vault/item/field` references. Resolution shells `op` with
//! `OP_SERVICE_ACCOUNT_TOKEN` injected from the credentials store — never
//! from the daemon's ambient env — which is the documented headless path
//! (desktop-app biometric auth is tty-session-scoped and dies on app lock;
//! rejected for any unattended process).
//!
//! Fields of one item batch into a single `op item get --format json` call
//! (one read instead of three); references with a section segment fall back
//! to `op read` individually. Resolved values are cached per block for the
//! daemon run by `ProviderSecretsSource` — service-account rate limits are
//! account-wide daily caps on non-Business tiers — and refreshed on
//! `portman up`.
//!
//! The binary comes from a fixed candidate list, never a shim-bearing PATH
//! (the mise exec-time lesson from the runner applies here too). The token
//! is never interpolated into logs or error strings.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use tracing::debug;

use super::OnePasswordCredentials;
use crate::supervisor::SecretsError;

const OP_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) async fn resolve(
    refs: &BTreeMap<String, String>,
    credentials: &OnePasswordCredentials,
) -> Result<Vec<(String, String)>, SecretsError> {
    let op = find_op_binary()?;
    resolve_with(&op, refs, credentials).await
}

/// Fixed candidate list — no PATH search, no shims.
fn find_op_binary() -> Result<PathBuf, SecretsError> {
    let candidates = [
        PathBuf::from("/opt/homebrew/bin/op"),
        PathBuf::from("/usr/local/bin/op"),
        PathBuf::from("/usr/bin/op"), // Linux package installs
    ];
    candidates
        .iter()
        .find(|p| p.is_file())
        .cloned()
        .ok_or_else(|| {
            SecretsError::fatal(
                "1password provider needs the `op` CLI (brew install 1password-cli)",
            )
        })
}

async fn resolve_with(
    op: &Path,
    refs: &BTreeMap<String, String>,
    credentials: &OnePasswordCredentials,
) -> Result<Vec<(String, String)>, SecretsError> {
    // Group plain op://vault/item/field references by item so one
    // `op item get` serves every field of that item; section'd references
    // (op://vault/item/section/field) resolve individually via `op read`.
    let mut by_item: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    let mut singles: Vec<(String, String)> = Vec::new();
    for (key, reference) in refs {
        match parse_ref(reference) {
            Some((vault, item, field)) => by_item
                .entry((vault, item))
                .or_default()
                .push((key.clone(), field)),
            None => singles.push((key.clone(), reference.clone())),
        }
    }

    let mut values: Vec<(String, String)> = Vec::new();
    for ((vault, item), fields) in by_item {
        if fields.len() == 1 {
            // No batching win — a direct read has simpler failure modes.
            let (key, field) = &fields[0];
            let reference = format!("op://{vault}/{item}/{field}");
            values.push((key.clone(), op_read(op, credentials, &reference).await?));
            continue;
        }
        let item_fields = op_item_get(op, credentials, &vault, &item).await?;
        for (key, field) in fields {
            let value = item_fields
                .iter()
                .find(|f| f.matches(&field))
                .and_then(|f| f.value.clone())
                .ok_or_else(|| {
                    SecretsError::fatal(format!(
                        "op://{vault}/{item}/{field}: item has no such field"
                    ))
                })?;
            values.push((key, value));
        }
    }
    for (key, reference) in singles {
        values.push((key, op_read(op, credentials, &reference).await?));
    }
    Ok(values)
}

/// Split `op://vault/item/field` (exactly three segments). Anything else —
/// including section'd `op://vault/item/section/field` — returns `None`
/// and resolves via `op read` verbatim.
fn parse_ref(reference: &str) -> Option<(String, String, String)> {
    let rest = reference.strip_prefix("op://")?;
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        [vault, item, field] if !vault.is_empty() && !item.is_empty() && !field.is_empty() => {
            Some((vault.to_string(), item.to_string(), field.to_string()))
        }
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
struct OpItem {
    #[serde(default)]
    fields: Vec<OpField>,
}

#[derive(Debug, Deserialize)]
struct OpField {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

impl OpField {
    fn matches(&self, wanted: &str) -> bool {
        self.label
            .as_deref()
            .is_some_and(|l| l.eq_ignore_ascii_case(wanted))
            || self.id.as_deref() == Some(wanted)
    }
}

async fn op_read(
    op: &Path,
    credentials: &OnePasswordCredentials,
    reference: &str,
) -> Result<String, SecretsError> {
    let stdout = run_op(op, credentials, &["read", "--no-newline", reference]).await?;
    Ok(String::from_utf8_lossy(&stdout).trim_end().to_string())
}

async fn op_item_get(
    op: &Path,
    credentials: &OnePasswordCredentials,
    vault: &str,
    item: &str,
) -> Result<Vec<OpField>, SecretsError> {
    let stdout = run_op(
        op,
        credentials,
        &["item", "get", item, "--vault", vault, "--format", "json"],
    )
    .await?;
    let parsed: OpItem = serde_json::from_slice(&stdout)
        .map_err(|err| SecretsError::fatal(format!("op item get: invalid JSON: {err}")))?;
    Ok(parsed.fields)
}

/// Run `op` headless: cleared env, the service-account token from the
/// credentials store, and nothing else that could reach an interactive
/// auth path. The token goes into the child env only — never into argv,
/// logs, or error strings.
async fn run_op(
    op: &Path,
    credentials: &OnePasswordCredentials,
    args: &[&str],
) -> Result<Vec<u8>, SecretsError> {
    debug!(?args, "op invocation");
    let mut cmd = tokio::process::Command::new(op);
    cmd.args(args)
        .env_clear()
        .env("OP_SERVICE_ACCOUNT_TOKEN", &credentials.token)
        .env("HOME", "/tmp") // op insists on a writable config probe
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = tokio::time::timeout(OP_TIMEOUT, cmd.output())
        .await
        .map_err(|_| SecretsError::transient("op timed out"))?
        .map_err(|err| SecretsError::fatal(format!("spawning op: {err}")))?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let tail: String = stderr.lines().rev().take(2).collect::<Vec<_>>().join(" | ");
    let lowered = tail.to_ascii_lowercase();
    // Real-world op auth failures include e.g. "failed to
    // DecodeSACredentials" (malformed/revoked token) — credential problems
    // are fatal, not retry material. The markers are deliberately narrow:
    // bare "credentials"/"authentication" matched transient messages like
    // "failed to refresh credentials: timeout" and parked the service in
    // Failed despite a working restart policy.
    let auth_failure = [
        "401",
        "unauthorized",
        "invalid token",
        "authentication failed",
        "decodesacredentials",
        "not signed in",
    ]
    .iter()
    .any(|marker| lowered.contains(marker));
    let message = format!(
        "op {} failed ({}): {tail}",
        args.first().unwrap_or(&"?"),
        output.status
    );
    if auth_failure {
        Err(SecretsError::fatal(message))
    } else {
        Err(SecretsError::transient(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::tempdir;

    fn creds() -> OnePasswordCredentials {
        OnePasswordCredentials {
            token: "ops_TEST_TOKEN_VALUE".into(),
        }
    }

    /// A stub `op` that records every invocation (argv + whether the token
    /// env var was present) and answers reads/gets deterministically.
    fn stub_op(dir: &Path) -> PathBuf {
        let log = dir.join("invocations.log");
        let path = dir.join("op");
        let script = format!(
            r#"#!/bin/sh
echo "argv:$* token:${{OP_SERVICE_ACCOUNT_TOKEN:-missing}}" >> {log}
case "$1" in
  read) printf 'value-of-%s' "$3" ;;
  item) printf '{{"fields":[{{"id":"username","label":"username","value":"user-1"}},{{"id":"password","label":"password","value":"pass-1"}}]}}' ;;
esac
"#,
            log = log.display()
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Pre-warm: syspolicyd assesses fresh scripts on first exec.
        let _ = std::process::Command::new(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        path
    }

    fn invocations(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("invocations.log"))
            .unwrap_or_default()
            .lines()
            // The pre-warm exec logs one argv-less line; not an invocation.
            .filter(|l| !l.starts_with("argv: "))
            .map(String::from)
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn single_ref_maps_to_op_read_with_token_in_env() {
        let dir = tempdir().unwrap();
        let op = stub_op(dir.path());
        let refs = BTreeMap::from([(
            "API_KEY".to_string(),
            "op://dev/openrouter/api-key".to_string(),
        )]);

        let values = resolve_with(&op, &refs, &creds()).await.unwrap();
        assert_eq!(
            values,
            vec![(
                "API_KEY".to_string(),
                "value-of-op://dev/openrouter/api-key".to_string()
            )]
        );

        let seen = invocations(dir.path());
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].contains("argv:read --no-newline op://dev/openrouter/api-key"),
            "{seen:?}"
        );
        assert!(
            seen[0].contains("token:ops_TEST_TOKEN_VALUE"),
            "token must reach op via env: {seen:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_fields_of_one_item_batch_into_one_invocation() {
        let dir = tempdir().unwrap();
        let op = stub_op(dir.path());
        let refs = BTreeMap::from([
            (
                "DB_USER".to_string(),
                "op://dev/postgres/username".to_string(),
            ),
            (
                "DB_PASS".to_string(),
                "op://dev/postgres/password".to_string(),
            ),
        ]);

        let values = resolve_with(&op, &refs, &creds()).await.unwrap();
        let map: BTreeMap<_, _> = values.into_iter().collect();
        assert_eq!(map["DB_USER"], "user-1");
        assert_eq!(map["DB_PASS"], "pass-1");

        let seen = invocations(dir.path());
        assert_eq!(seen.len(), 1, "one item get, not two reads: {seen:?}");
        assert!(
            seen[0].contains("argv:item get postgres --vault dev --format json"),
            "{seen:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn nonzero_exit_surfaces_as_error_without_token_material() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("op");
        std::fs::write(
            &path,
            "#!/bin/sh\necho 'op error 401 unauthorized' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::process::Command::new(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let refs = BTreeMap::from([("K".to_string(), "op://v/i/f".to_string())]);
        let err = resolve_with(&path, &refs, &creds()).await.unwrap_err();
        assert!(!err.transient, "401-style failures are fatal: {err:?}");
        assert!(err.message.contains("401"), "{err:?}");
        assert!(
            !err.message.contains("ops_TEST_TOKEN_VALUE"),
            "token must never reach error strings: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn section_refs_fall_back_to_op_read() {
        let dir = tempdir().unwrap();
        let op = stub_op(dir.path());
        let refs = BTreeMap::from([(
            "K".to_string(),
            "op://dev/service/section-a/field-b".to_string(),
        )]);
        let values = resolve_with(&op, &refs, &creds()).await.unwrap();
        assert_eq!(values[0].1, "value-of-op://dev/service/section-a/field-b");
        let seen = invocations(dir.path());
        assert!(seen[0].contains("argv:read"), "{seen:?}");
    }

    #[test]
    fn ref_parsing() {
        assert_eq!(
            parse_ref("op://vault/item/field"),
            Some(("vault".into(), "item".into(), "field".into()))
        );
        assert_eq!(parse_ref("op://vault/item/section/field"), None);
        assert_eq!(parse_ref("op://vault/item"), None);
        assert_eq!(parse_ref("not-a-ref"), None);
    }
}
