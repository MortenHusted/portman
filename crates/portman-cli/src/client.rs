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
use portman_protocol::{BridgeCleanup, BridgePhase, NetbridgeMode, Request, Response};
use tokio::net::UnixStream;
use tokio::time::Instant;

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
    /// What holds up the cleanup that the last disable asked for.
    cleanup: Option<BridgeCleanup>,
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
            bridge_cleanup,
            ..
        } => Ok(BridgeStatus {
            sent_phase: bridge_phase,
            enabled: bridge_enabled,
            mode: bridge_mode,
            cleanup: bridge_cleanup,
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

/// How a wait for the bridge ended, when it ended without an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Settled {
    /// The bridge is as the command asked.
    Reached,
    /// The user wants the bridge and no container engine is connected, so
    /// no wait can see it come up. The daemon starts it when one connects.
    WaitsForDocker,
    /// The bridge is off as the command asked, and the daemon has not
    /// removed the DNS forwarder and the docker network.
    LeftoversStay(BridgeCleanup),
}

impl Settled {
    /// The line a command prints. `done` says what the command did.
    pub(crate) fn line(self, done: &str) -> String {
        match self {
            Settled::Reached => done.to_string(),
            Settled::WaitsForDocker => format!("{done}; the bridge starts when Docker connects"),
            Settled::LeftoversStay(BridgeCleanup::Pending) => format!(
                "{done}; {}. `portman bridge status` prints a `cleanup` line for as long as something holds it up",
                BridgeCleanup::Pending.in_words()
            ),
            Settled::LeftoversStay(held) => format!("{done}; {}", held.in_words()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Poll {
    Reached,
    Pending,
    WaitsForDocker,
    /// The bridge was on its way up and is now off, so another client
    /// disabled it and no later poll will find it up.
    TurnedOff,
}

/// What one poll of the phase tells a wait. `previous` is the phase of the
/// poll before it. A `disabled` with no poll before it can be the phase from
/// before the daemon took the request, so only a phase that becomes
/// `disabled` ends a wait for up. The daemon reports `waiting_for_docker`
/// only for a bridge that the user wants, so that phase ends a wait for up
/// at the first read that shows it.
fn poll(desired_enabled: bool, previous: Option<BridgePhase>, phase: BridgePhase) -> Poll {
    match (desired_enabled, phase) {
        (true, BridgePhase::Up) | (false, BridgePhase::Disabled) => Poll::Reached,
        (true, BridgePhase::WaitingForDocker) => Poll::WaitsForDocker,
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
        (true, BridgePhase::Starting) => format!(
            "netbridge is still {word} after 60s. It stays enabled. If a start fails, the daemon \
             logs the reason and tries again. To stop it, run `portman bridge disable`."
        ),
        (true, _) => format!("netbridge did not report up after 60s; it reports {word}"),
        (false, _) => format!("netbridge did not report disabled after 60s; it reports {word}"),
    }
}

/// Poll until the bridge is up, or until it is off and gone and the daemon
/// has said what became of the cleanup that a disable asks for. The daemon
/// applies bridge changes asynchronously. A cleanup that still runs or is
/// still to come when the 60 s are used up ends the wait with no error,
/// because the bridge is off.
pub(crate) async fn wait_for_bridge_state(desired_enabled: bool) -> Result<Settled> {
    wait_for_state(bridge_status, desired_enabled).await
}

async fn wait_for_state<F>(mut read: impl FnMut() -> F, desired_enabled: bool) -> Result<Settled>
where
    F: Future<Output = Result<BridgeStatus>>,
{
    let mut previous = None;
    let mut pauses = Pauses::new();
    loop {
        let status = read().await?;
        let phase = status.phase();
        let cleanup = status.cleanup.filter(|_| !desired_enabled);
        let off_with_a_cleanup_to_come = match (poll(desired_enabled, previous, phase), cleanup) {
            (Poll::Reached, None) => return Ok(Settled::Reached),
            (
                Poll::Reached,
                Some(to_come @ (BridgeCleanup::Pending | BridgeCleanup::WaitsForBridges { .. })),
            ) => Some(to_come),
            (Poll::Reached, Some(held)) => return Ok(Settled::LeftoversStay(held)),
            (Poll::WaitsForDocker, _) => return Ok(Settled::WaitsForDocker),
            (Poll::TurnedOff, _) => bail!("netbridge was disabled before it came up"),
            (Poll::Pending, _) => None,
        };
        previous = Some(phase);
        if !pauses.pause().await {
            if let Some(to_come) = off_with_a_cleanup_to_come {
                return Ok(Settled::LeftoversStay(to_come));
            }
            bail!(timed_out(desired_enabled, phase));
        }
    }
}

/// How long a mode wait goes on after the mode of another command first
/// showed, before it ends with [`ModePoll::SetByAnother`]. The daemon takes
/// `mode` requests in the order they arrive, so of two commands that start a
/// few milliseconds apart, the second can read the mode of the first before
/// its own shows. The grace time is for that. It is too short for a daemon
/// that is in the middle of a bridge start for another command's mode: the
/// daemon's loop holds a request until that start ends. A wait whose read
/// before its request came before the daemon published that mode then reads
/// it for longer than the grace time, and fails although the daemon applies
/// its own mode afterwards. A wait ends at the first read after the grace time,
/// and no pause between reads is longer than 500 ms.
const MODE_GRACE: Duration = Duration::from_millis(500);

#[derive(Debug, PartialEq, Eq)]
enum ModePoll {
    Reached,
    Pending,
    WaitsForDocker,
    /// A mode of another command shows, and less than [`MODE_GRACE`] has
    /// passed since one first did.
    Contested,
    /// The mode that shows when the grace time is over.
    SetByAnother(NetbridgeMode),
    TurnedOff,
}

/// What one status read tells a wait for a mode change. `previous` is the
/// mode of the read before it, and the first one is from before the request.
/// The daemon reports the old mode until the bridge built for it is gone, so
/// a mode that is neither the last one seen nor the wanted one comes from
/// another command. `contested_for` is the time since the first read that
/// showed such a mode, with the wanted mode in no read since. It does not
/// start over when a third mode, or the old one, takes the place of that
/// mode. Another command won when a read at or after [`MODE_GRACE`] still
/// shows a mode that is not the wanted one, and the wait names the mode of
/// that read. A wait that reads only the old mode cannot tell a command
/// that set it back from a daemon that has not acted yet, so it goes on
/// until the 60 s are used up.
///
/// With `wait_for_up` the bridge was up before the request. A daemon that
/// sends the phase sends `disabled` only for a bridge that nobody wants, so
/// that `disabled` is final. A daemon that sends no phase reads as disabled
/// while it replaces the bridge, so that wait goes on.
///
/// The new mode beside `waiting_for_docker` ends every wait, as that phase
/// ends a wait for up in [`poll`]: the daemon starts the bridge in the new
/// mode when an engine connects.
fn mode_poll(
    wanted: NetbridgeMode,
    wait_for_up: bool,
    previous: NetbridgeMode,
    contested_for: Option<Duration>,
    now: BridgeStatus,
) -> ModePoll {
    if now.mode != wanted {
        return match contested_for {
            None if now.mode == previous => ModePoll::Pending,
            Some(shown) if shown >= MODE_GRACE => ModePoll::SetByAnother(now.mode),
            _ => ModePoll::Contested,
        };
    }
    if now.sent_phase == BridgePhase::WaitingForDocker {
        ModePoll::WaitsForDocker
    } else if !wait_for_up || now.phase() == BridgePhase::Up {
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
) -> Result<Settled> {
    wait_for_mode(bridge_status, wanted, before).await
}

async fn wait_for_mode<F>(
    mut read: impl FnMut() -> F,
    wanted: NetbridgeMode,
    before: BridgeStatus,
) -> Result<Settled>
where
    F: Future<Output = Result<BridgeStatus>>,
{
    let word = NetbridgeMode::display_word(wanted);
    let not_up = || format!("netbridge mode is set to {word} and the bridge is not up");
    let wait_for_up = before.phase() == BridgePhase::Up;
    let mut previous = before.mode;
    let mut contested_since: Option<Instant> = None;
    let mut pauses = Pauses::new();
    loop {
        let now = read().await?;
        let contested_for = contested_since.map(|since| since.elapsed());
        match mode_poll(wanted, wait_for_up, previous, contested_for, now) {
            ModePoll::Reached => return Ok(Settled::Reached),
            ModePoll::WaitsForDocker => return Ok(Settled::WaitsForDocker),
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
            ModePoll::Contested => {
                contested_since.get_or_insert_with(Instant::now);
            }
            ModePoll::Pending => {
                previous = now.mode;
                contested_since = None;
            }
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
            (ENABLE, None, WaitingForDocker, Poll::WaitsForDocker),
            (
                ENABLE,
                Some(Disabled),
                WaitingForDocker,
                Poll::WaitsForDocker,
            ),
            (
                ENABLE,
                Some(Starting),
                WaitingForDocker,
                Poll::WaitsForDocker,
            ),
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
            (DISABLE, Some(Up), WaitingForDocker, Poll::Pending),
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
        let message = timed_out(ENABLE, Starting);
        assert!(message.contains("stays enabled"), "{message}");
        assert!(message.contains("If a start fails"), "{message}");
        assert!(message.contains("`portman bridge disable`"), "{message}");
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
            cleanup: None,
        }
    }

    /// A status from a daemon whose bridge is off and that says what holds
    /// up the cleanup of a disable.
    fn off_with(cleanup: BridgeCleanup) -> BridgeStatus {
        BridgeStatus {
            cleanup: Some(cleanup),
            ..sent(OptIn, Disabled)
        }
    }

    /// A status from a daemon that predates the phase.
    fn older(mode: NetbridgeMode, enabled: bool) -> BridgeStatus {
        BridgeStatus {
            sent_phase: Unknown,
            enabled,
            mode,
            cleanup: None,
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
                ModePoll::Contested,
            ),
            (
                Docker,
                mode_only,
                Docker,
                sent(All, Disabled),
                ModePoll::Contested,
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
                ModePoll::Contested,
            ),
            (Docker, for_up, OptIn, sent(All, Up), ModePoll::Contested),
            (
                Docker,
                for_up,
                Docker,
                sent(OptIn, Stopping),
                ModePoll::Contested,
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
                ModePoll::WaitsForDocker,
            ),
            (
                Docker,
                for_up,
                OptIn,
                sent(Docker, WaitingForDocker),
                ModePoll::WaitsForDocker,
            ),
            (
                Docker,
                for_up,
                OptIn,
                sent(OptIn, WaitingForDocker),
                ModePoll::Pending,
            ),
            (
                Docker,
                mode_only,
                OptIn,
                sent(Docker, WaitingForDocker),
                ModePoll::WaitsForDocker,
            ),
            (
                Docker,
                mode_only,
                OptIn,
                sent(OptIn, WaitingForDocker),
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
                mode_poll(wanted, wait_for_up, previous, None, now),
                want,
                "wanted={wanted:?} wait_for_up={wait_for_up} previous={previous:?} now={now:?}"
            );
        }
    }

    #[test]
    fn another_command_wins_a_mode_wait_only_when_its_mode_outlasts_the_grace_time() {
        let (for_up, mode_only) = (true, false);
        let ms = |ms| Some(Duration::from_millis(ms));
        // The command wants docker, and the read before the request showed
        // opt-in.
        // (waits for up, time since another mode first showed, status) → what the read tells
        let table = [
            (mode_only, ms(0), sent(All, Disabled), ModePoll::Contested),
            (mode_only, ms(90), sent(All, Disabled), ModePoll::Contested),
            (mode_only, ms(499), sent(All, Disabled), ModePoll::Contested),
            (
                mode_only,
                ms(500),
                sent(All, Disabled),
                ModePoll::SetByAnother(All),
            ),
            (
                mode_only,
                ms(2000),
                sent(All, Disabled),
                ModePoll::SetByAnother(All),
            ),
            (
                mode_only,
                ms(499),
                sent(OptIn, Disabled),
                ModePoll::Contested,
            ),
            (
                mode_only,
                ms(500),
                sent(OptIn, Disabled),
                ModePoll::SetByAnother(OptIn),
            ),
            (mode_only, ms(90), sent(Docker, Disabled), ModePoll::Reached),
            (
                mode_only,
                ms(2000),
                sent(Docker, Disabled),
                ModePoll::Reached,
            ),
            (for_up, ms(90), sent(Docker, Starting), ModePoll::Pending),
            (for_up, ms(90), sent(Docker, Up), ModePoll::Reached),
            (for_up, ms(499), sent(All, Up), ModePoll::Contested),
            (for_up, ms(500), sent(All, Up), ModePoll::SetByAnother(All)),
        ];
        for (wait_for_up, contested_for, now, want) in table {
            assert_eq!(
                mode_poll(Docker, wait_for_up, OptIn, contested_for, now),
                want,
                "wait_for_up={wait_for_up} contested_for={contested_for:?} now={now:?}"
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
    async fn an_enable_returns_at_the_read_that_finds_the_bridge_waiting_for_docker() {
        let mut already_waiting = Script::new(&[sent(Docker, WaitingForDocker)]);
        let settled = wait_for_state(|| already_waiting.read(), ENABLE).await;
        assert_eq!(settled.unwrap(), Settled::WaitsForDocker);
        assert_eq!(already_waiting.read_at.len(), 1);

        let mut read_too_early =
            Script::new(&[sent(Docker, Disabled), sent(Docker, WaitingForDocker)]);
        let settled = wait_for_state(|| read_too_early.read(), ENABLE).await;
        assert_eq!(settled.unwrap(), Settled::WaitsForDocker);
        assert_eq!(read_too_early.pauses(), millis([10]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_waits_for_its_cleanup_and_says_what_held_it_up() {
        let no_answer = BridgeCleanup::NoAnswer { within_secs: 20 };
        let (pending, off) = (off_with(BridgeCleanup::Pending), sent(OptIn, Disabled));
        let gives_a_head_start = off_with(BridgeCleanup::WaitsForBridges { for_secs: 10 });
        let stays = Settled::LeftoversStay;
        // the statuses that a disable reads → how its wait ends
        let table = [
            (vec![off], Settled::Reached),
            (vec![pending, pending, off], Settled::Reached),
            (vec![gives_a_head_start, pending, off], Settled::Reached),
            (
                vec![gives_a_head_start, off_with(BridgeCleanup::PortTaken)],
                stays(BridgeCleanup::PortTaken),
            ),
            (
                vec![sent(OptIn, Stopping), pending, off_with(no_answer)],
                stays(no_answer),
            ),
            (
                vec![off_with(BridgeCleanup::WaitsForDocker)],
                stays(BridgeCleanup::WaitsForDocker),
            ),
            (
                vec![pending, off_with(BridgeCleanup::PortTaken)],
                stays(BridgeCleanup::PortTaken),
            ),
        ];
        for (statuses, ends) in table {
            let mut script = Script::new(&statuses);

            let settled = wait_for_state(|| script.read(), false).await;

            assert_eq!(settled.unwrap(), ends, "{statuses:?}");
            assert_eq!(script.read_at.len(), statuses.len(), "{statuses:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_whose_cleanup_still_runs_after_60s_ends_with_no_error_and_says_so() {
        let mut script = Script::new(&[off_with(BridgeCleanup::Pending)]);
        let asked = Instant::now();

        let settled = wait_for_state(|| script.read(), false).await.unwrap();

        assert_eq!(settled, Settled::LeftoversStay(BridgeCleanup::Pending));
        assert_eq!(asked.elapsed(), Duration::from_secs(60));
        assert_eq!(
            settled.line("netbridge disabled"),
            "netbridge disabled; portman has not removed the dns forwarder and the `portman` \
             network yet: the removal still runs. `portman bridge status` prints a `cleanup` line for as \
             long as something holds it up"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_enable_does_not_wait_for_the_cleanup_of_a_disable() {
        let up_beside_a_disable_in_flight = BridgeStatus {
            cleanup: Some(BridgeCleanup::Pending),
            ..sent(OptIn, Up)
        };
        let mut script = Script::new(&[up_beside_a_disable_in_flight]);

        let settled = wait_for_state(|| script.read(), true).await;

        assert_eq!(settled.unwrap(), Settled::Reached);
        assert_eq!(script.read_at.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_disable_waits_through_a_bridge_that_waits_for_docker() {
        let mut script = Script::new(&[sent(Docker, WaitingForDocker), sent(Docker, Disabled)]);

        let settled = wait_for_state(|| script.read(), DISABLE).await;

        assert_eq!(settled.unwrap(), Settled::Reached);
        assert_eq!(script.read_at.len(), 2);
    }

    #[test]
    fn a_command_says_that_the_bridge_starts_when_docker_connects() {
        assert_eq!(
            Settled::Reached.line("netbridge enabled"),
            "netbridge enabled"
        );
        assert_eq!(
            Settled::WaitsForDocker.line("netbridge enabled"),
            "netbridge enabled; the bridge starts when Docker connects"
        );
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
        // the phase of a bridge that is not up → how the wait ends
        let table = [
            (Disabled, Settled::Reached),
            (Starting, Settled::Reached),
            (WaitingForDocker, Settled::WaitsForDocker),
        ];
        for (not_up, ends) in table {
            let mut script = Script::new(&[sent(OptIn, not_up), sent(Docker, not_up)]);

            let settled = wait_for_mode(|| script.read(), Docker, sent(OptIn, not_up)).await;

            assert_eq!(settled.unwrap(), ends, "{not_up:?}");
            assert_eq!(script.read_at.len(), 2, "{not_up:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_mode_change_returns_when_the_bridge_it_waits_for_waits_for_docker() {
        let mut script = Script::new(&[sent(OptIn, Stopping), sent(Docker, WaitingForDocker)]);

        let settled = wait_for_mode(|| script.read(), Docker, sent(OptIn, Up)).await;

        assert_eq!(settled.unwrap(), Settled::WaitsForDocker);
        assert_eq!(script.read_at.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_mode_change_that_reads_the_mode_of_an_earlier_command_succeeds_when_its_own_shows() {
        let bridge_off = [sent(All, Disabled), sent(Docker, Disabled)];
        let bridge_up = [
            sent(OptIn, Stopping),
            sent(All, Starting),
            sent(Docker, Starting),
            sent(Docker, Up),
        ];
        let mut shows_late = vec![sent(All, Disabled); 5];
        shows_late.push(sent(Docker, Disabled));
        // (the status before the request, the status reads)
        let table = [
            (sent(OptIn, Disabled), &bridge_off[..]),
            (sent(OptIn, Up), &bridge_up[..]),
            (sent(OptIn, Disabled), &shows_late[..]),
        ];
        for (before, statuses) in table {
            let mut script = Script::new(statuses);

            let settled = wait_for_mode(|| script.read(), Docker, before).await;

            assert_eq!(settled.unwrap(), Settled::Reached, "{statuses:?}");
            assert_eq!(script.read_at.len(), statuses.len(), "{statuses:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_grace_time_starts_over_when_the_wanted_mode_has_shown() {
        let mut statuses = vec![sent(All, Starting)];
        statuses.extend([sent(Docker, Starting); 6]);
        statuses.extend([sent(All, Starting), sent(Docker, Up)]);
        let mut script = Script::new(&statuses);

        let settled = wait_for_mode(|| script.read(), Docker, sent(OptIn, Up)).await;

        let second_showing = script.read_at[7] - script.read_at[0];
        assert!(second_showing > Duration::from_millis(500));
        assert_eq!(settled.unwrap(), Settled::Reached);
    }

    #[tokio::test(start_paused = true)]
    async fn a_mode_change_that_another_command_overrides_fails_after_the_grace_time() {
        let before_it_showed = [sent(OptIn, Stopping), sent(All, Starting)];
        let back_to_the_old_mode_after_it_showed = [
            sent(OptIn, Stopping),
            sent(Docker, Starting),
            sent(OptIn, Starting),
        ];
        // the status reads, of which the last repeats → the mode that the error names
        let table = [
            (&before_it_showed[..], "all"),
            (&back_to_the_old_mode_after_it_showed[..], "opt-in"),
        ];
        for (statuses, mode) in table {
            let mut script = Script::new(statuses);

            let failed = wait_for_mode(|| script.read(), Docker, sent(OptIn, Up))
                .await
                .unwrap_err();

            let first_shown = script.read_at[statuses.len() - 1];
            let shown_for: Vec<_> = script.read_at.iter().map(|at| *at - first_shown).collect();
            let [.., read_before, last_read] = shown_for[..] else {
                panic!("the wait ended at its first read");
            };
            assert!(read_before < Duration::from_millis(500), "{shown_for:?}");
            assert!(last_read >= Duration::from_millis(500), "{shown_for:?}");
            assert!(last_read < Duration::from_secs(1), "{shown_for:?}");
            assert_eq!(
                failed.to_string(),
                format!("another command set the netbridge mode to {mode}")
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_mode_wait_that_two_modes_contest_counts_from_the_first_and_names_the_last() {
        let mut statuses = vec![sent(All, Disabled); 5];
        statuses.push(sent(OptIn, Disabled));
        let mut script = Script::new(&statuses);

        let failed = wait_for_mode(|| script.read(), Docker, sent(OptIn, Disabled))
            .await
            .unwrap_err();

        let since_all_showed: Vec<_> = script
            .read_at
            .iter()
            .map(|at| *at - script.read_at[0])
            .collect();
        let [.., opt_in_showed, last_read] = since_all_showed[..] else {
            panic!("the wait ended at its first read");
        };
        assert!(
            opt_in_showed < Duration::from_millis(500),
            "{since_all_showed:?}"
        );
        assert!(
            last_read >= Duration::from_millis(500),
            "{since_all_showed:?}"
        );
        assert!(last_read < Duration::from_secs(1), "{since_all_showed:?}");
        assert_eq!(
            failed.to_string(),
            "another command set the netbridge mode to opt-in"
        );
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
