//! The one place the CLI talks to the daemon from.
//!
//! Both the command handlers and the TUI go through [`request`] so the
//! "is the daemon running?" context is attached uniformly — the TUI used
//! to surface bare connection errors from its own copy.

use std::future::Future;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use portman_core::paths::socket_path;
use portman_protocol::transport::{read_response, write_request};
use portman_protocol::{BridgePhase, NetbridgeMode, Request, Response};
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

/// The bridge fields of one status response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BridgeStatus {
    /// As the daemon sent it. A daemon that predates the phase sends none,
    /// and that reads as `Unknown`.
    sent_phase: BridgePhase,
    enabled: bool,
    pub(crate) mode: NetbridgeMode,
}

impl BridgeStatus {
    pub(crate) fn phase(self) -> BridgePhase {
        self.sent_phase.or_from_enabled(self.enabled)
    }
}

pub(crate) async fn bridge_status() -> Result<BridgeStatus> {
    match request(Request::Status).await? {
        Response::Status {
            bridge_phase,
            bridge_enabled,
            bridge_mode,
            ..
        } => Ok(BridgeStatus {
            sent_phase: bridge_phase,
            enabled: bridge_enabled,
            mode: bridge_mode,
        }),
        other => other.unexpected(),
    }
}

const WAIT_LIMIT: Duration = Duration::from_secs(60);
const FIRST_PAUSE: Duration = Duration::from_millis(10);
const LONGEST_PAUSE: Duration = Duration::from_millis(500);

/// The pauses between the status reads of one wait. The daemon answers a
/// bridge request before its loop acts on it, so the first read can be a few
/// milliseconds too early. The pauses start short for that, double to 500ms,
/// and add up to 60s.
pub(crate) struct Pauses {
    next: Duration,
    left: Duration,
}

impl Pauses {
    pub(crate) fn new() -> Self {
        Self {
            next: FIRST_PAUSE,
            left: WAIT_LIMIT,
        }
    }

    /// False when the 60s are used up.
    pub(crate) async fn pause(&mut self) -> bool {
        if self.left.is_zero() {
            return false;
        }
        let pause = self.next.min(self.left);
        tokio::time::sleep(pause).await;
        self.left -= pause;
        self.next = (pause * 2).min(LONGEST_PAUSE);
        true
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
/// applies bridge changes asynchronously.
pub(crate) async fn wait_for_bridge_state(desired_enabled: bool) -> Result<()> {
    wait_for_state(bridge_status, desired_enabled).await
}

async fn wait_for_state<F>(mut read: impl FnMut() -> F, desired_enabled: bool) -> Result<()>
where
    F: Future<Output = Result<BridgeStatus>>,
{
    let mut previous = None;
    let mut pauses = Pauses::new();
    loop {
        let phase = read().await?.phase();
        match poll(desired_enabled, previous, phase) {
            Poll::Reached => return Ok(()),
            Poll::TurnedOff => bail!("netbridge was disabled before it came up"),
            Poll::Pending => previous = Some(phase),
        }
        if !pauses.pause().await {
            bail!(timed_out(desired_enabled, phase));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;
    use BridgePhase::{Disabled, Starting, Stopping, Up, WaitingForDocker};
    use NetbridgeMode::{All, OptIn};

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

    /// A status from a daemon that sends the phase.
    fn sent(mode: NetbridgeMode, phase: BridgePhase) -> BridgeStatus {
        BridgeStatus {
            sent_phase: phase,
            enabled: matches!(phase, Up),
            mode,
        }
    }

    /// The status reads of one wait, in order. The last one repeats.
    struct Script {
        statuses: Vec<BridgeStatus>,
        read_at: Vec<Instant>,
    }

    impl Script {
        fn new(statuses: &[BridgeStatus]) -> Self {
            Self {
                statuses: statuses.to_vec(),
                read_at: Vec::new(),
            }
        }

        fn read(&mut self) -> std::future::Ready<Result<BridgeStatus>> {
            let next = self.read_at.len().min(self.statuses.len() - 1);
            self.read_at.push(Instant::now());
            std::future::ready(Ok(self.statuses[next]))
        }

        fn pauses(&self) -> Vec<Duration> {
            self.read_at.windows(2).map(|w| w[1] - w[0]).collect()
        }
    }

    fn millis<const N: usize>(pauses: [u64; N]) -> [Duration; N] {
        pauses.map(Duration::from_millis)
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_that_read_the_old_phase_first_returns_after_one_short_pause() {
        let mut script = Script::new(&[sent(All, Starting), sent(All, Disabled)]);

        wait_for_state(|| script.read(), DISABLE).await.unwrap();

        assert_eq!(script.pauses(), millis([10]));
    }

    #[tokio::test(start_paused = true)]
    async fn an_enable_waits_through_a_start_with_pauses_that_grow_to_half_a_second() {
        let mut statuses = vec![sent(OptIn, Disabled)];
        statuses.extend([sent(OptIn, Starting); 8]);
        statuses.push(sent(OptIn, Up));
        let mut script = Script::new(&statuses);

        wait_for_state(|| script.read(), ENABLE).await.unwrap();

        assert_eq!(
            script.pauses(),
            millis([10, 20, 40, 80, 160, 320, 500, 500, 500])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_gives_up_sixty_seconds_after_its_first_read() {
        let mut script = Script::new(&[sent(OptIn, Starting)]);

        let failed = wait_for_state(|| script.read(), ENABLE).await.unwrap_err();

        let waited = *script.read_at.last().unwrap() - script.read_at[0];
        assert_eq!(waited, Duration::from_secs(60));
        assert_eq!(failed.to_string(), timed_out(ENABLE, Starting));
    }

    #[tokio::test(start_paused = true)]
    async fn an_enable_ends_at_the_read_that_finds_the_bridge_turned_off() {
        let mut script = Script::new(&[
            sent(OptIn, Disabled),
            sent(OptIn, Starting),
            sent(OptIn, Disabled),
        ]);

        let failed = wait_for_state(|| script.read(), ENABLE).await.unwrap_err();

        assert_eq!(script.read_at.len(), 3);
        assert!(failed.to_string().contains("was disabled"), "{failed}");
    }
}
