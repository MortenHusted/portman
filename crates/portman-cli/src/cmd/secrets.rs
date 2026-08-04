//! Machine-identity secrets credentials (`portman secrets set-*`).

use anyhow::{bail, Context, Result};

use crate::client::request;
use portman_protocol::{Request, Response};

pub(crate) async fn cmd_secrets_set_infisical(
    client_id: String,
    client_secret: Option<String>,
) -> Result<()> {
    let secret = read_secret_arg(client_secret, "Infisical client secret")?;
    match request(Request::SetSecretsCredentials {
        provider: "infisical".into(),
        client_id: Some(client_id),
        client_secret: Some(portman_protocol::Redacted(secret)),
        token: None,
    })
    .await?
    {
        Response::Ok => {
            println!("stored Infisical machine identity (credentials.json, 0600)");
            Ok(())
        }
        other => other.unexpected(),
    }
}

pub(crate) async fn cmd_secrets_set_op(token: Option<String>) -> Result<()> {
    let token = read_secret_arg(token, "1Password service-account token")?;
    match request(Request::SetSecretsCredentials {
        provider: "1password".into(),
        client_id: None,
        client_secret: None,
        token: Some(portman_protocol::Redacted(token)),
    })
    .await?
    {
        Response::Ok => {
            println!("stored 1Password service-account token (credentials.json, 0600)");
            Ok(())
        }
        other => other.unexpected(),
    }
}

/// Take the secret from the flag, or read one line from stdin — piping or
/// interactive paste both work, and nothing lands in shell history.
pub(crate) fn read_secret_arg(flag: Option<String>, label: &str) -> Result<String> {
    if let Some(value) = flag {
        let value = value.trim().to_string();
        if value.is_empty() {
            bail!("{label} cannot be empty");
        }
        return Ok(value);
    }
    eprint!("{label}: ");
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading secret from stdin")?;
    let value = line.trim().to_string();
    if value.is_empty() {
        bail!("{label} cannot be empty");
    }
    Ok(value)
}
