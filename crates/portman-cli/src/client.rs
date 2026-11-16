//! The one place the CLI talks to the daemon from.
//!
//! Both the command handlers and the TUI go through [`request`] so the
//! "is the daemon running?" context is attached uniformly — the TUI used
//! to surface bare connection errors from its own copy.

use std::future::Future;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
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
    fn phase(self) -> BridgePhase {
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
struct Pauses {
    next: Duration,
    left: Duration,
}

impl Pauses {
    fn new() -> Self {
        Self {
            next: FIRST_PAUSE,
            left: WAIT_LIMIT,
        }
    }

    /// False when the 60s are used up.
    async fn pause(&mut self) -> bool {
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
            "netbridge is still {word} after 60s. It stays enabled. If a start fails, the daemon \
             logs the reason and tries again. To stop it, run `portman bridge disable`."
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

#[derive(Debug, PartialEq, Eq)]
enum ModePoll {
    Reached,
    Pending,
    SetByAnother(NetbridgeMode),
    TurnedOff,
}

/// What one status read tells a wait for a mode change. `previous` is the
/// mode of the read before it, and the first one is from before the request.
/// The daemon reports the old mode until the bridge built for it is gone, so
/// a mode that is neither the last one seen nor the wanted one comes from
/// another command.
///
/// With `wait_for_up` the bridge was up before the request. A daemon that
/// sends the phase sends `disabled` only for a bridge that nobody wants, so
/// that `disabled` is final. A daemon that sends no phase reads as disabled
/// while it replaces the bridge, so that wait goes on.
fn mode_poll(
    wanted: NetbridgeMode,
    wait_for_up: bool,
    previous: NetbridgeMode,
    now: BridgeStatus,
) -> ModePoll {
    if now.mode != wanted {
        return if now.mode == previous {
            ModePoll::Pending
        } else {
            ModePoll::SetByAnother(now.mode)
        };
    }
    if !wait_for_up || now.phase() == BridgePhase::Up {
        ModePoll::Reached
    } else if now.sent_phase == BridgePhase::Disabled {
        ModePoll::TurnedOff
    } else {
        ModePoll::Pending
    }
}

/// Poll until the daemon reports `wanted`, and until a bridge that was up in
/// `before` is up again. `before` is the status from before the request.
pub(crate) async fn wait_for_bridge_mode(
    wanted: NetbridgeMode,
    before: BridgeStatus,
) -> Result<()> {
    wait_for_mode(bridge_status, wanted, before).await
}

async fn wait_for_mode<F>(
    mut read: impl FnMut() -> F,
    wanted: NetbridgeMode,
    before: BridgeStatus,
) -> Result<()>
where
    F: Future<Output = Result<BridgeStatus>>,
{
    let word = NetbridgeMode::display_word(wanted);
    let not_up = || format!("netbridge mode is set to {word} and the bridge is not up");
    let wait_for_up = before.phase() == BridgePhase::Up;
    let mut previous = before.mode;
    let mut pauses = Pauses::new();
    loop {
        let now = read().await?;
        match mode_poll(wanted, wait_for_up, previous, now) {
            ModePoll::Reached => return Ok(()),
            ModePoll::SetByAnother(mode) => bail!(
                "another command set the netbridge mode to {}",
                NetbridgeMode::display_word(mode)
            ),
            ModePoll::TurnedOff => {
                return Err(anyhow!(
                    "netbridge was disabled while this command waited for it"
                ))
                .with_context(not_up)
            }
            ModePoll::Pending => previous = now.mode,
        }
        if !pauses.pause().await {
            if now.mode != wanted {
                bail!("netbridge did not report mode {word} after 60s");
            }
            return Err(anyhow!(timed_out(true, now.phase()))).with_context(not_up);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;
    use BridgePhase::{Disabled, Starting, Stopping, Unknown, Up, WaitingForDocker};
    use NetbridgeMode::{All, Docker, OptIn};

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
            assert!(message.contains("If a start fails"), "{message}");
            assert!(message.contains("`portman bridge disable`"), "{message}");
        }
        for (desired_enabled, last) in [(ENABLE, Disabled), (DISABLE, Stopping), (DISABLE, Up)] {
            let message = timed_out(desired_enabled, last);
            assert!(!message.contains("stays enabled"), "{message}");
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

    /// A status from a daemon that predates the phase.
    fn older(mode: NetbridgeMode, enabled: bool) -> BridgeStatus {
        BridgeStatus {
            sent_phase: Unknown,
            enabled,
            mode,
        }
    }

    #[test]
    fn a_mode_wait_ends_when_the_answer_is_known() {
        let (for_up, mode_only) = (true, false);
        // (wanted, waits for up, mode of the read before, status) → what the read tells
        let table = [
            (
                Docker,
                mode_only,
                OptIn,
                sent(OptIn, Disabled),
                ModePoll::Pending,
            ),
            (
                Docker,
                mode_only,
                OptIn,
                sent(Docker, Disabled),
                ModePoll::Reached,
            ),
            (
                Docker,
                mode_only,
                OptIn,
                sent(Docker, Starting),
                ModePoll::Reached,
            ),
            (
                Docker,
                mode_only,
                OptIn,
                sent(All, Starting),
                ModePoll::SetByAnother(All),
            ),
            (
                Docker,
                mode_only,
                Docker,
                sent(All, Disabled),
                ModePoll::SetByAnother(All),
            ),
            (Docker, for_up, OptIn, sent(OptIn, Up), ModePoll::Pending),
            (
                Docker,
                for_up,
                OptIn,
                sent(OptIn, Stopping),
                ModePoll::Pending,
            ),
            (
                Docker,
                for_up,
                OptIn,
                sent(OptIn, Disabled),
                ModePoll::Pending,
            ),
            (
                Docker,
                for_up,
                OptIn,
                sent(All, Starting),
                ModePoll::SetByAnother(All),
            ),
            (
                Docker,
                for_up,
                OptIn,
                sent(All, Up),
                ModePoll::SetByAnother(All),
            ),
            (
                Docker,
                for_up,
                Docker,
                sent(OptIn, Stopping),
                ModePoll::SetByAnother(OptIn),
            ),
            (
                Docker,
                for_up,
                OptIn,
                sent(Docker, Starting),
                ModePoll::Pending,
            ),
            (
                Docker,
                for_up,
                Docker,
                sent(Docker, WaitingForDocker),
                ModePoll::Pending,
            ),
            (
                Docker,
                for_up,
                Docker,
                sent(Docker, Stopping),
                ModePoll::Pending,
            ),
            (Docker, for_up, Docker, sent(Docker, Up), ModePoll::Reached),
            (
                Docker,
                for_up,
                OptIn,
                sent(Docker, Disabled),
                ModePoll::TurnedOff,
            ),
            (
                Docker,
                for_up,
                Docker,
                sent(Docker, Disabled),
                ModePoll::TurnedOff,
            ),
            (
                Docker,
                for_up,
                OptIn,
                older(OptIn, false),
                ModePoll::Pending,
            ),
            (
                Docker,
                for_up,
                OptIn,
                older(Docker, false),
                ModePoll::Pending,
            ),
            (
                Docker,
                for_up,
                Docker,
                older(Docker, false),
                ModePoll::Pending,
            ),
            (
                Docker,
                for_up,
                Docker,
                older(Docker, true),
                ModePoll::Reached,
            ),
            (
                Docker,
                mode_only,
                OptIn,
                older(Docker, false),
                ModePoll::Reached,
            ),
        ];
        for (wanted, wait_for_up, previous, now, want) in table {
            assert_eq!(
                mode_poll(wanted, wait_for_up, previous, now),
                want,
                "wanted={wanted:?} wait_for_up={wait_for_up} previous={previous:?} now={now:?}"
            );
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

    #[tokio::test(start_paused = true)]
    async fn a_mode_change_waits_for_the_new_mode_and_then_for_the_bridge() {
        let mut script = Script::new(&[
            sent(OptIn, Stopping),
            sent(Docker, Starting),
            sent(Docker, Up),
        ]);

        wait_for_mode(|| script.read(), Docker, sent(OptIn, Up))
            .await
            .unwrap();

        assert_eq!(script.read_at.len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_mode_change_on_a_bridge_that_was_not_up_ends_when_the_new_mode_shows() {
        for not_up in [Disabled, Starting] {
            let mut script = Script::new(&[sent(OptIn, not_up), sent(Docker, not_up)]);

            wait_for_mode(|| script.read(), Docker, sent(OptIn, not_up))
                .await
                .unwrap();

            assert_eq!(script.read_at.len(), 2, "{not_up:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_mode_change_that_another_command_overrides_ends_at_once_and_names_its_mode() {
        let before_it_showed = [sent(OptIn, Stopping), sent(All, Starting)];
        let back_to_the_old_mode_after_it_showed = [
            sent(OptIn, Stopping),
            sent(Docker, Starting),
            sent(OptIn, Starting),
        ];
        // the status reads → the mode that the error names
        let table = [
            (&before_it_showed[..], "all"),
            (&back_to_the_old_mode_after_it_showed[..], "opt-in"),
        ];
        for (statuses, mode) in table {
            let mut script = Script::new(statuses);

            let failed = wait_for_mode(|| script.read(), Docker, sent(OptIn, Up))
                .await
                .unwrap_err();

            assert_eq!(script.read_at.len(), statuses.len());
            assert_eq!(
                failed.to_string(),
                format!("another command set the netbridge mode to {mode}")
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_mode_change_ends_at_once_when_the_bridge_is_disabled_under_it() {
        let mut script = Script::new(&[sent(OptIn, Stopping), sent(Docker, Disabled)]);

        let failed = wait_for_mode(|| script.read(), Docker, sent(OptIn, Up))
            .await
            .unwrap_err();

        assert_eq!(script.read_at.len(), 2);
        assert!(format!("{failed:#}").contains("was disabled"), "{failed:#}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_mode_change_on_a_daemon_that_sends_no_phase_waits_until_the_bridge_is_back() {
        let mut script = Script::new(&[
            older(Docker, false),
            older(Docker, false),
            older(Docker, true),
        ]);

        wait_for_mode(|| script.read(), Docker, older(OptIn, true))
            .await
            .unwrap();

        assert_eq!(script.read_at.len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_mode_change_that_times_out_says_which_half_is_missing() {
        let mut never_reported = Script::new(&[sent(OptIn, Stopping)]);
        let failed = wait_for_mode(|| never_reported.read(), Docker, sent(OptIn, Up))
            .await
            .unwrap_err();
        assert_eq!(
            failed.to_string(),
            "netbridge did not report mode docker after 60s"
        );

        let mut never_up = Script::new(&[sent(Docker, Starting)]);
        let failed = wait_for_mode(|| never_up.read(), Docker, sent(OptIn, Up))
            .await
            .unwrap_err();
        assert_eq!(
            failed.to_string(),
            "netbridge mode is set to docker and the bridge is not up"
        );
        assert_eq!(failed.root_cause().to_string(), timed_out(ENABLE, Starting));
    }
}
