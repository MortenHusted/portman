//! Provider credentials (`portman secrets set-*`) and the local vault
//! (`portman secrets set|unset|list`).

use anyhow::{bail, Context, Result};

use crate::client::request;
use portman_protocol::{Redacted, Request, Response};

pub(crate) async fn cmd_secrets_set(key: String, value: Option<String>) -> Result<()> {
    let key = key.trim().to_string();
    portman_core::service_config::validate_env_key(&key)?;
    let value = read_secret_arg(value, &format!("value for {key}"))?;
    match request(Request::SetLocalSecret {
        key: key.clone(),
        value: Redacted(value),
    })
    .await?
    {
        Response::Ok => {
            println!("stored {key} in the local vault (credentials.json, 0600)");
            Ok(())
        }
        other => other.unexpected(),
    }
}

pub(crate) async fn cmd_secrets_unset(key: String) -> Result<()> {
    match request(Request::UnsetLocalSecret { key: key.clone() }).await? {
        Response::Ok => {
            println!("removed {key} from the local vault");
            Ok(())
        }
        other => other.unexpected(),
    }
}

pub(crate) async fn cmd_secrets_list() -> Result<()> {
    match request(Request::SecretsStatus).await? {
        Response::SecretsStatus {
            infisical_client_id,
            onepassword,
            local,
            blocks,
        } => {
            match infisical_client_id {
                Some(id) => println!("infisical   configured (client id {id})"),
                None => println!("infisical   not configured  (portman secrets set-infisical)"),
            }
            if onepassword {
                println!("1password   configured");
            } else {
                println!("1password   not configured  (portman secrets set-op)");
            }
            println!();
            if local.is_empty() {
                println!("(no local secrets — portman secrets set KEY)");
            } else {
                let width = local.iter().map(|s| s.key.len()).max().unwrap_or(0);
                for s in &local {
                    let state = if s.set { "set" } else { "MISSING" };
                    let refs = if s.blocks.is_empty() {
                        String::from("(not referenced)")
                    } else {
                        s.blocks
                            .iter()
                            .map(|b| format!("[secrets.{b}]"))
                            .collect::<Vec<_>>()
                            .join(" ")
                    };
                    println!("{:<width$}  {state:<7}  {refs}", s.key);
                }
            }
            println!();
            if blocks.is_empty() {
                println!("(no [secrets.*] blocks — define one in the dashboard or a portman.toml)");
                return Ok(());
            }
            let width = blocks.iter().map(|b| b.name.len()).max().unwrap_or(0);
            for b in &blocks {
                let owner = match &b.root {
                    Some(root) => root.display().to_string(),
                    None => String::from("(global)"),
                };
                let used = if b.used_by.is_empty() {
                    String::from("unused")
                } else {
                    b.used_by.join(", ")
                };
                println!(
                    "[secrets.{:<width$}]  {:<10}  {owner}  used by: {used}",
                    b.name,
                    provider_label(&b.config)
                );
            }
            Ok(())
        }
        other => other.unexpected(),
    }
}

fn provider_label(config: &portman_protocol::SecretsProviderConfig) -> &'static str {
    match config {
        portman_protocol::SecretsProviderConfig::Infisical { .. } => "infisical",
        portman_protocol::SecretsProviderConfig::OnePassword { .. } => "1password",
        portman_protocol::SecretsProviderConfig::Local { .. } => "local",
    }
}

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
