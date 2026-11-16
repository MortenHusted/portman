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

#[derive(Debug, PartialEq, Eq)]
enum Poll {
    Reached,
    Pending,
    /// The bridge was on its way up and is now off, so another client
    /// disabled it and no later poll will find it up.
    TurnedOff,
}

/// What one poll of the phase tells a wait. `previous` is the phase of the
/// poll before it. A `disabled` with no poll before it can be the phase from
/// before the daemon took the request, so only a phase that becomes
/// `disabled` ends a wait for up.
fn poll(desired_enabled: bool, previous: Option<BridgePhase>, phase: BridgePhase) -> Poll {
    match (desired_enabled, phase) {
        (true, BridgePhase::Up) | (false, BridgePhase::Disabled) => Poll::Reached,
        (true, BridgePhase::Disabled)
            if previous.is_some_and(|before| before != BridgePhase::Disabled) =>
        {
            Poll::TurnedOff
        }
        _ => Poll::Pending,
    }
}

fn timed_out(desired_enabled: bool, last: BridgePhase) -> String {
    let word = last.display_word();
    match (desired_enabled, last) {
        (true, BridgePhase::Starting | BridgePhase::WaitingForDocker) => format!(
            "netbridge is still {word} after 60s. It stays enabled and the daemon keeps retrying; \
             the daemon log has the reason. To stop it, run `portman bridge disable`."
        ),
        (true, _) => format!("netbridge did not report up after 60s; it reports {word}"),
        (false, _) => format!("netbridge did not report disabled after 60s; it reports {word}"),
    }
}

/// Poll until the bridge is up, or until it is off and gone. The daemon
/// applies bridge changes asynchronously; 120 × 500ms = 60s bound.
pub(crate) async fn wait_for_bridge_state(desired_enabled: bool) -> Result<()> {
    let mut last = None;
    for attempt in 0..120 {
        let phase = bridge_phase().await?;
        match poll(desired_enabled, last, phase) {
            Poll::Reached => return Ok(()),
            Poll::TurnedOff => anyhow::bail!("netbridge was disabled before it came up"),
            Poll::Pending => last = Some(phase),
        }
        if attempt < 119 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    anyhow::bail!(timed_out(desired_enabled, last.unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use BridgePhase::{Disabled, Starting, Stopping, Up, WaitingForDocker};

    const ENABLE: bool = true;
    const DISABLE: bool = false;

    #[test]
    fn a_wait_ends_when_the_answer_is_known() {
        // (asked for, phase of the poll before, phase) → what the poll tells
        let table = [
            (ENABLE, None, Up, Poll::Reached),
            (ENABLE, Some(Starting), Up, Poll::Reached),
            (ENABLE, None, Starting, Poll::Pending),
            (ENABLE, None, WaitingForDocker, Poll::Pending),
            (ENABLE, Some(Starting), Starting, Poll::Pending),
            (ENABLE, None, Stopping, Poll::Pending),
            (ENABLE, None, Disabled, Poll::Pending),
            (ENABLE, Some(Disabled), Disabled, Poll::Pending),
            (ENABLE, Some(Starting), Disabled, Poll::TurnedOff),
            (ENABLE, Some(WaitingForDocker), Disabled, Poll::TurnedOff),
            (ENABLE, Some(Stopping), Disabled, Poll::TurnedOff),
            (DISABLE, None, Disabled, Poll::Reached),
            (DISABLE, Some(Stopping), Disabled, Poll::Reached),
            (DISABLE, None, Stopping, Poll::Pending),
            (DISABLE, None, Starting, Poll::Pending),
            (DISABLE, None, WaitingForDocker, Poll::Pending),
            (DISABLE, None, Up, Poll::Pending),
            (DISABLE, Some(Stopping), Up, Poll::Pending),
        ];
        for (desired_enabled, previous, phase, want) in table {
            assert_eq!(
                poll(desired_enabled, previous, phase),
                want,
                "desired_enabled={desired_enabled} previous={previous:?} phase={phase:?}"
            );
        }
    }

    #[test]
    fn an_enable_that_times_out_says_the_bridge_stays_wanted_and_how_to_stop_it() {
        for still_wanted in [Starting, WaitingForDocker] {
            let message = timed_out(ENABLE, still_wanted);
            assert!(message.contains("stays enabled"), "{message}");
            assert!(message.contains("keeps retrying"), "{message}");
            assert!(message.contains("`portman bridge disable`"), "{message}");
        }
        for (desired_enabled, last) in [(ENABLE, Disabled), (DISABLE, Stopping), (DISABLE, Up)] {
            let message = timed_out(desired_enabled, last);
            assert!(!message.contains("keeps retrying"), "{message}");
            assert!(message.contains(last.display_word()), "{message}");
        }
    }
}
