//! The one place the CLI talks to the daemon from.
//!
//! Both the command handlers and the TUI go through [`request`] so the
//! "is the daemon running?" context is attached uniformly — the TUI used
//! to surface bare connection errors from its own copy.

use anyhow::{Context, Result};
use portman_core::paths::socket_path;
use portman_protocol::transport::{read_response, write_request};
use portman_protocol::{Request, Response};
use tokio::net::UnixStream;

pub(crate) async fn request(req: Request) -> Result<Response> {
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

pub(crate) async fn bridge_enabled() -> Result<bool> {
    match request(Request::Status).await? {
        Response::Status { bridge_enabled, .. } => Ok(bridge_enabled),
        other => other.unexpected(),
    }
}

/// Poll until the daemon reports the desired bridge on/off state. The
/// daemon applies bridge changes asynchronously; 120 × 500ms = 60s bound.
pub(crate) async fn wait_for_bridge_state(desired_enabled: bool) -> Result<()> {
    for attempt in 0..120 {
        if bridge_enabled().await? == desired_enabled {
            return Ok(());
        }
        if attempt < 119 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    anyhow::bail!(
        "netbridge did not report {} after 60s",
        if desired_enabled {
            "enabled"
        } else {
            "disabled"
        }
    )
}
