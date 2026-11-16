//! The one place the CLI talks to the daemon from.
//!
//! Both the command handlers and the TUI go through [`request`] so the
//! "is the daemon running?" context is attached uniformly — the TUI used
//! to surface bare connection errors from its own copy.

use anyhow::{Context, Result};
use portman_core::paths::socket_path;
use portman_protocol::transport::{read_response, write_request};
use portman_protocol::{BridgePhase, Request, Response};
use tokio::net::UnixStream;

pub(crate) async fn request(req: Request) -> Result<Response> {
    let req = if std::env::var("PORTMAN_MANAGED_BROKER").is_ok_and(|v| v == "true" || v == "1") {
        let token = std::fs::read_to_string(portman_core::paths::dashboard_token_path()?)
            .context("reading host control token for managed broker")?;
        Request::Authenticated {
            token: portman_protocol::Redacted(token.trim().into()),
            request: Box::new(req),
        }
    } else {
        req
    };
    let path = socket_path()?;
    let mut stream = UnixStream::connect(&path).await.with_context(|| {
        format!(
            "connecting to portman daemon at {}. Is the daemon running? Try: mise run daemon",
            path.display()
        )
    })?;
    write_request(&mut stream, &req).await?;
    read_response(&mut stream).await
}

pub(crate) async fn bridge_phase() -> Result<BridgePhase> {
    match request(Request::Status).await? {
        Response::Status {
            bridge_phase,
            bridge_enabled,
            ..
        } => Ok(bridge_phase.or_from_enabled(bridge_enabled)),
        other => other.unexpected(),
    }
}

/// Poll until the bridge is up, or until it is off and gone. The daemon
/// applies bridge changes asynchronously; 120 × 500ms = 60s bound.
pub(crate) async fn wait_for_bridge_state(desired_enabled: bool) -> Result<()> {
    let desired = if desired_enabled {
        BridgePhase::Up
    } else {
        BridgePhase::Disabled
    };
    for attempt in 0..120 {
        if bridge_phase().await? == desired {
            return Ok(());
        }
        if attempt < 119 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    anyhow::bail!(
        "netbridge did not report {} after 60s",
        desired.display_word()
    )
}
