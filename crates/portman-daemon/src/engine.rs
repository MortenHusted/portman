//! The daemon's link to the container engine. One task owns the Docker
//! connection and publishes it as a [`Link`]. While a session lasts, a
//! Docker event only says when to look, and one list of the running
//! containers says which container routes the registry holds.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::{self, Display};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::models::{EventMessage, EventMessageTypeEnum};
use bollard::query_parameters::{EventsOptionsBuilder, ListContainersOptionsBuilder};
use bollard::Docker;
use futures_util::{Stream, StreamExt};
use portman_core::{Mode, Registry};
use tokio::sync::{watch, Notify};
use tracing::{debug, info, warn};

use crate::discovery::{self, Container, Skip, Skipped};
use crate::DaemonState;

/// One event stream to an engine, from the connect attempt that the engine
/// answered until the stream ends. bollard opens a connection for each
/// request, so only that stream shows that the engine stayed. What is built
/// on an engine records its session. Once the link holds another one, the
/// engine can have restarted or be another engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Session(pub(crate) u64);

/// What the daemon knows about the container engine. [`run`] is the only
/// writer.
#[derive(Clone)]
pub(crate) enum Link {
    Absent(Absent),
    Connected {
        session: Session,
        docker: Docker,
        /// The socket the engine answered on.
        socket: PathBuf,
        /// The engine's own version, when it reports one.
        version: Option<String>,
    },
}

impl Link {
    pub(crate) fn session(&self) -> Option<Session> {
        match self {
            Link::Absent(_) => None,
            Link::Connected { session, .. } => Some(*session),
        }
    }
}

/// Why no engine is connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Absent {
    /// No connect attempt has ended. The link stays so in managed-broker
    /// mode, which never polls [`run`].
    Idle,
    /// None of the candidate socket paths exists.
    NoSocket,
    /// The configured socket path does not exist.
    NoSocketAt(PathBuf),
    /// A socket exists and no engine answered on it.
    Unreachable { socket: PathBuf, error: String },
}

impl Display for Absent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("docker is not connected: ")?;
        match self {
            Absent::Idle => f.write_str("no connect attempt has ended"),
            Absent::NoSocket => f.write_str(
                "no docker socket found; start a runtime (e.g. `colima start`) \
                 or set PORTMAN_DOCKER_SOCKET",
            ),
            Absent::NoSocketAt(socket) => write!(
                f,
                "no docker socket at {}, the path the daemon was given; \
                 start the runtime that serves it or correct the path",
                socket.display()
            ),
            Absent::Unreachable { socket, error } => {
                write!(f, "no answer on {}: {error}", socket.display())
            }
        }
    }
}

impl std::error::Error for Absent {}

/// The daemon's handle on the [`Link`]. Cheap to clone.
#[derive(Clone)]
pub(crate) struct Engine {
    link: watch::Receiver<Link>,
}

/// The handle the daemon shares, and the end that only [`run`] holds.
pub(crate) fn channel() -> (Engine, watch::Sender<Link>) {
    let (publisher, link) = watch::channel(Link::Absent(Absent::Idle));
    (Engine { link }, publisher)
}

impl Engine {
    /// The Docker handle for one call. A caller that keeps it talks to an
    /// engine that may be gone.
    pub(crate) fn docker(&self) -> Result<Docker, Absent> {
        match &*self.link.borrow() {
            Link::Absent(reason) => Err(reason.clone()),
            Link::Connected { docker, .. } => Ok(docker.clone()),
        }
    }

    pub(crate) fn session(&self) -> Option<Session> {
        self.link.borrow().session()
    }

    /// The link as it is at this call, for a status report.
    pub(crate) fn link(&self) -> Link {
        self.link.borrow().clone()
    }

    /// The link itself, for a task that acts when it changes. Only the
    /// macOS bridge and its health check do.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn watch(&self) -> watch::Receiver<Link> {
        self.link.clone()
    }
}

/// Where the daemon looks for the engine's socket.
pub(crate) enum Sockets {
    /// The one path that `--docker-socket` or `PORTMAN_DOCKER_SOCKET` names.
    Configured(PathBuf),
    /// The paths of the runtimes that the daemon knows, in the order it
    /// tries them.
    Detected(Vec<PathBuf>),
}

impl Sockets {
    fn candidates(&self) -> &[PathBuf] {
        match self {
            Sockets::Configured(path) => std::slice::from_ref(path),
            Sockets::Detected(paths) => paths,
        }
    }

    /// Why no engine is connected when no candidate path holds a socket.
    fn none_found(&self) -> Absent {
        match self {
            Sockets::Configured(path) => Absent::NoSocketAt(path.clone()),
            Sockets::Detected(_) => Absent::NoSocket,
        }
    }
}

/// How long one candidate socket has to answer a connect attempt.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// The wait before each connect attempt. The first attempt comes at once,
/// and the last delay repeats.
const RECONNECT_DELAYS: [Duration; 5] = [
    Duration::ZERO,
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];

/// A connect attempt that lasts this long, the session it opens included,
/// starts the delays over. A shorter one moves to the next delay, so an
/// engine whose sessions end at once is not asked in a tight loop.
const SETTLED: Duration = Duration::from_secs(10);

/// A handle on the socket at `path`. `None` when bollard refuses the path,
/// as it does when no file is there.
pub(crate) fn open_socket(path: &Path) -> Option<Docker> {
    Docker::connect_with_socket(path.to_str()?, 120, bollard::API_DEFAULT_VERSION).ok()
}

/// Owns the link for as long as the daemon polls it. Every connect attempt
/// goes through the candidates of `sockets` in order until one answers, so a
/// socket that appears or goes stale at one of those paths needs no daemon
/// restart. The paths are fixed at boot.
/// The container routes are cleared when an attempt finds no engine. They
/// stay while a session that ended is replaced by the next one, and the
/// first list of that session corrects them.
pub(crate) async fn run(
    publisher: watch::Sender<Link>,
    sockets: Sockets,
    open: impl Fn(&Path) -> Option<Docker>,
    state: DaemonState,
) -> Infallible {
    let mut sessions = 0;
    let mut attempt = 0;
    loop {
        tokio::time::sleep(RECONNECT_DELAYS[attempt.min(RECONNECT_DELAYS.len() - 1)]).await;
        let began = tokio::time::Instant::now();
        match connect(&sockets, &open).await {
            Ok(found) => {
                sessions += 1;
                let session = Session(sessions);
                info!(session = session.0, "docker session opened");
                publisher.send_replace(Link::Connected {
                    session,
                    docker: found.docker.clone(),
                    socket: found.socket,
                    version: found.version,
                });
                serve(&found.docker, &state).await;
            }
            Err(reason) => lose(&publisher, &state, reason),
        }
        attempt = if began.elapsed() >= SETTLED {
            0
        } else {
            attempt + 1
        };
    }
}

/// An engine that answered a connect attempt.
struct Found {
    docker: Docker,
    socket: PathBuf,
    version: Option<String>,
}

/// The first candidate that answers. When none does, the reason names the
/// first socket that exists.
async fn connect(
    sockets: &Sockets,
    open: &impl Fn(&Path) -> Option<Docker>,
) -> Result<Found, Absent> {
    let mut unreachable = None;
    for socket in sockets.candidates() {
        let Some(docker) = open(socket) else {
            continue;
        };
        let error = match tokio::time::timeout(PROBE_TIMEOUT, docker.version()).await {
            Ok(Ok(version)) => {
                info!(
                    socket = %socket.display(),
                    api_version = version.api_version.as_deref().unwrap_or("?"),
                    server_version = version.version.as_deref().unwrap_or("?"),
                    "connected to docker"
                );
                return Ok(Found {
                    docker,
                    socket: socket.clone(),
                    version: version.version,
                });
            }
            Ok(Err(err)) => unanswered(&err),
            Err(_) => format!("no answer in {} s", PROBE_TIMEOUT.as_secs()),
        };
        unreachable.get_or_insert(Absent::Unreachable {
            socket: socket.clone(),
            error,
        });
    }
    Err(unreachable.unwrap_or_else(|| sockets.none_found()))
}

/// bollard wraps the error of its HTTP client, and that error's own text
/// names only the step of the client that failed. The cause at the end of
/// the chain says what happened.
fn unanswered(err: &bollard::errors::Error) -> String {
    let mut cause: &dyn std::error::Error = err;
    while let Some(deeper) = cause.source() {
        cause = deeper;
    }
    let refused = cause
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused);
    if refused {
        "no engine listens on this socket".to_string()
    } else {
        cause.to_string()
    }
}

/// Publishes that no engine is connected and clears the container routes,
/// which would point at the containers of an engine that is gone.
fn lose(publisher: &watch::Sender<Link>, state: &DaemonState, reason: Absent) {
    let changed = publisher.send_if_modified(|link| {
        let known = matches!(link, Link::Absent(was) if *was == reason);
        if !known {
            *link = Link::Absent(reason.clone());
        }
        !known
    });
    if changed {
        warn!(%reason, "no container engine");
    }
    for entry in state.registry.replace_container_entries(Vec::new()).removed {
        info!(host = %entry.host, id = entry.container_id, "unregistered");
    }
}

/// Delays between lists that no wake caused. The loop takes these steps while
/// a labelled container has no address, after a list that failed, and for the
/// lists a network event owes. Each delay runs from the end of the list before
/// it, and a wake starts the steps over.
const RELIST_DELAYS: [Duration; 5] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

/// How long the loop keeps reading events after a trigger before it lists.
/// A burst, such as the event buffer the engine replays at subscription, then
/// costs one list, not one for each socket read. When a network event opens
/// the quiet time, the list also comes after the lag between that event and
/// the engine's container list. On Docker 29.5.2 on an idle 2-CPU VM, a list
/// sent when the event was read lacked the change in 15 of 40 attaches and
/// detaches, and a list sent 25 to 40 ms after the read had it in all 40.
const QUIET: Duration = Duration::from_millis(50);

/// Timed lists that a network event owes after its first list. The first list
/// is past the lag measured for [`QUIET`] only when the network event opens
/// the quiet time. The timed lists cover a network event that is read late in
/// a quiet time, whose first list comes a few milliseconds later, and an
/// engine slower than the one measured.
const NETWORK_EVENT_RELISTS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Trigger {
    /// A container `start` or `die`. The engine updates its container list
    /// before it sends the event.
    Container,
    /// A network `connect` or `disconnect`. The engine sends the event before
    /// it updates its container list, so a list made at once can show the old
    /// addresses.
    Network,
}

/// When the loop lists again with no wake.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Relist {
    /// Timed lists since the last wake.
    attempt: usize,
    /// Timed lists still owed to a network event.
    owed: usize,
}

impl Relist {
    fn after_trigger(self, trigger: Trigger) -> Self {
        let owed = match trigger {
            Trigger::Container => self.owed,
            Trigger::Network => NETWORK_EVENT_RELISTS,
        };
        Self { attempt: 0, owed }
    }

    fn after_resync(self) -> Self {
        Self { attempt: 0, ..self }
    }

    fn after_delay(self) -> Self {
        Self {
            attempt: self.attempt + 1,
            owed: self.owed.saturating_sub(1),
        }
    }

    /// `retry` says that the last list failed or left a container waiting for
    /// an address. `None` means wait for a wake.
    fn delay(self, retry: bool) -> Option<Duration> {
        RELIST_DELAYS
            .get(self.attempt)
            .copied()
            .filter(|_| retry || self.owed > 0)
    }
}

/// The daemon's registry and the handle that wakes the reconcile loop. The
/// registry wakes it for every hostname it releases. With no session open
/// the handle keeps one wake, and the next session then lists once more.
pub(crate) fn registry_with_resync() -> (Registry, Arc<Notify>) {
    let resync = Arc::new(Notify::new());
    let wake = resync.clone();
    let registry = Registry::with_release_hook(move || wake.notify_one());
    (registry, resync)
}

/// One session. It returns when the event stream ends. A list that fails
/// says nothing about the stream, so it is retried here and the session, and
/// what the daemon built on it, stays.
async fn serve(docker: &Docker, state: &DaemonState) {
    // bollard sends the request on the first poll, so the subscription cannot
    // be open before the first list. `since` makes the engine replay its event
    // buffer in the same step as the subscription, so an event from that gap
    // still causes a list. Epoch 0 asks for the whole buffer whatever the
    // engine's clock says.
    let options = EventsOptionsBuilder::default().since("0").build();
    let mut events = docker.events(Some(options)).fuse();
    info!("streaming docker events");

    let mut reported = Vec::new();
    let mut relist = Relist::default();
    loop {
        let retry = match reconcile(docker, state, &mut reported).await {
            Ok(waiting) => waiting,
            Err(err) => {
                warn!(error = format!("{err:#}"), "container reconcile failed");
                true
            }
        };
        let Some(next) = wait(&mut events, &state.container_resync, relist, retry).await else {
            warn!("docker events stream ended");
            return;
        };
        relist = next;
    }
}

/// Waits for the next reason to list and returns the schedule that follows
/// it. `None` once the stream has ended. A stream that ends during the quiet
/// time first returns the schedule for the burst it cut short, and the next
/// call returns `None`. Never drop it early, because a drop during the quiet
/// time loses the trigger.
async fn wait<E: Display>(
    events: &mut (impl Stream<Item = Result<EventMessage, E>> + Unpin),
    resync: &Notify,
    relist: Relist,
    retry: bool,
) -> Option<Relist> {
    let delay = relist.delay(retry);
    tokio::select! {
        trigger = next_trigger(events) => {
            Some(relist.after_trigger(settle(events, trigger?).await))
        }
        _ = resync.notified() => Some(relist.after_resync()),
        _ = tokio::time::sleep(delay.unwrap_or_default()), if delay.is_some() => {
            Some(relist.after_delay())
        }
    }
}

async fn reconcile(
    docker: &Docker,
    state: &DaemonState,
    reported: &mut Vec<Skipped>,
) -> Result<bool> {
    let filters = HashMap::from([("label", vec![discovery::LABEL_HOST])]);
    let options = ListContainersOptionsBuilder::default()
        .filters(&filters)
        .build();
    let summaries = docker
        .list_containers(Some(options))
        .await
        .context("listing running containers")?;
    let containers: Vec<_> = summaries
        .into_iter()
        .filter_map(discovery::observe)
        .collect();
    Ok(apply(state, &containers, reported))
}

/// Makes the registry's container entries match `containers` and warns once
/// for each container it skips, for as long as its reason lasts. A container
/// that waits for an address is not skipped and gets no warning. Returns
/// whether a container still waits for an address.
fn apply(state: &DaemonState, containers: &[Container], reported: &mut Vec<Skipped>) -> bool {
    let plan = discovery::plan(containers, |host| state.host_is_routable(host));

    let diff = state.registry.replace_container_entries(plan.entries);
    for entry in &diff.removed {
        info!(host = %entry.host, id = entry.container_id, "unregistered");
    }
    for entry in &diff.added {
        if entry.mode == Mode::Http && state.host_tls_enabled(&entry.host) {
            if let Err(err) = state.cert_manager.ensure(&entry.host) {
                warn!(host = %entry.host, error = %err, "failed to provision cert for container");
            }
        }
        info!(
            host = %entry.host,
            target = %entry.target,
            mode = entry.mode.as_str(),
            id = entry.container_id,
            "registered"
        );
    }

    let mut skipped = plan.skipped;
    skipped.extend(diff.shadowed.iter().map(|(entry, holder)| Skipped {
        id: entry.container_id.clone().unwrap_or_default(),
        host: entry.host.clone(),
        reason: Skip::HostHeldBy(*holder),
    }));
    for skipped in &skipped {
        if !reported.contains(skipped) {
            warn!(
                host = %skipped.host,
                id = %skipped.id,
                reason = %skipped.reason,
                "ignoring container"
            );
        }
    }
    *reported = skipped;

    if !plan.waiting.is_empty() {
        debug!(ids = ?plan.waiting, "labelled containers have no address yet");
    }
    !plan.waiting.is_empty()
}

/// Waits for an event that can change the container routes. `None` when the
/// stream has ended. It holds nothing across an await, so `select!` can drop
/// it without losing a trigger.
async fn next_trigger<E: Display>(
    events: &mut (impl Stream<Item = Result<EventMessage, E>> + Unpin),
) -> Option<Trigger> {
    loop {
        match events.next().await? {
            Ok(event) => {
                if let Some(trigger) = trigger(&event) {
                    return Some(trigger);
                }
            }
            Err(err) => warn!(error = %err, "docker events stream error"),
        }
    }
}

/// Reads events for [`QUIET`] after `first`, so the whole burst shares one
/// list. A burst that holds a network event is a network trigger. It reads
/// for the whole time because the stream hands over one socket read at a
/// time, so a single drain at the end would not see the reads behind it.
async fn settle<E: Display>(
    events: &mut (impl Stream<Item = Result<EventMessage, E>> + Unpin),
    first: Trigger,
) -> Trigger {
    let quiet_until = tokio::time::Instant::now() + QUIET;
    let mut burst = first;
    while let Ok(Some(next)) = tokio::time::timeout_at(quiet_until, events.next()).await {
        match next {
            Ok(event) => burst = burst.max(trigger(&event).unwrap_or(burst)),
            Err(err) => warn!(error = %err, "docker events stream error"),
        }
    }
    burst
}

fn trigger(event: &EventMessage) -> Option<Trigger> {
    match (event.typ, event.action.as_deref()) {
        (Some(EventMessageTypeEnum::CONTAINER), Some("start" | "die")) => Some(Trigger::Container),
        (Some(EventMessageTypeEnum::NETWORK), Some("connect" | "disconnect")) => {
            Some(Trigger::Network)
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    use bollard::models::{ContainerSummary, ContainerSummaryNetworkSettings, EndpointSettings};
    use futures_util::{stream, FutureExt};
    use hyper_util::rt::TokioIo;
    use portman_core::Source;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn event(typ: EventMessageTypeEnum, action: &str) -> EventMessage {
        EventMessage {
            typ: Some(typ),
            action: Some(action.into()),
            ..Default::default()
        }
    }

    fn open_stream(
        events: Vec<EventMessage>,
    ) -> impl Stream<Item = Result<EventMessage, String>> + Unpin {
        stream::iter(events.into_iter().map(Ok))
            .chain(stream::pending())
            .fuse()
    }

    #[test]
    fn only_events_that_change_the_container_list_or_an_address_trigger() {
        use EventMessageTypeEnum::{CONTAINER, IMAGE, NETWORK};
        let cases = [
            (CONTAINER, "start", Some(Trigger::Container)),
            (CONTAINER, "die", Some(Trigger::Container)),
            (NETWORK, "connect", Some(Trigger::Network)),
            (NETWORK, "disconnect", Some(Trigger::Network)),
            (CONTAINER, "create", None),
            (CONTAINER, "exec_start: sh", None),
            (CONTAINER, "health_status: healthy", None),
            (NETWORK, "create", None),
            (IMAGE, "pull", None),
        ];
        for (typ, action, expected) in cases {
            assert_eq!(trigger(&event(typ, action)), expected, "{typ} {action}");
        }
        assert_eq!(trigger(&EventMessage::default()), None);
    }

    /// A stream that gives each event the stated number of milliseconds
    /// after the one before it, and then stays open.
    fn timed_stream(
        events: Vec<(u64, EventMessage)>,
    ) -> impl Stream<Item = Result<EventMessage, String>> + Unpin {
        let timed = stream::iter(events).then(|(after_ms, event)| async move {
            tokio::time::sleep(Duration::from_millis(after_ms)).await;
            Ok(event)
        });
        Box::pin(timed.chain(stream::pending())).fuse()
    }

    /// The times, in milliseconds from now, at which the loop lists because
    /// of `events`, when each list takes no time and asks for no retry.
    async fn list_times(
        mut events: impl Stream<Item = Result<EventMessage, String>> + Unpin,
    ) -> Vec<u128> {
        let resync = Notify::new();
        let start = tokio::time::Instant::now();
        let mut relist = Relist::default();
        let mut lists = Vec::new();
        while let Ok(Some(next)) = tokio::time::timeout(
            Duration::from_secs(60),
            wait(&mut events, &resync, relist, false),
        )
        .await
        {
            lists.push(start.elapsed().as_millis());
            relist = next;
        }
        lists
    }

    #[tokio::test(start_paused = true)]
    async fn the_events_of_each_quiet_time_cost_one_list() {
        let cases = [
            (vec![(0, "start"), (10, "die"), (10, "start")], vec![50]),
            (vec![(0, "start"), (60, "die")], vec![50, 110]),
        ];
        for (actions, lists) in cases {
            let events = actions
                .iter()
                .map(|&(after_ms, action)| {
                    (after_ms, event(EventMessageTypeEnum::CONTAINER, action))
                })
                .collect();
            assert_eq!(list_times(timed_stream(events)).await, lists, "{actions:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_network_event_anywhere_in_a_burst_owes_its_timed_lists() {
        use EventMessageTypeEnum::{CONTAINER, NETWORK};
        for burst in [
            vec![
                (0, event(NETWORK, "connect")),
                (6, event(CONTAINER, "start")),
            ],
            vec![
                (0, event(CONTAINER, "die")),
                (6, event(NETWORK, "disconnect")),
            ],
        ] {
            assert_eq!(list_times(timed_stream(burst)).await, [50, 300, 800]);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_resync_wake_lists_without_the_quiet_time() {
        let resync = Notify::new();
        resync.notify_one();
        let mut events = timed_stream(vec![]);
        let start = tokio::time::Instant::now();

        let woken = wait(&mut events, &resync, Relist::default(), false).await;

        assert_eq!(woken, Some(Relist::default()));
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[test]
    fn a_network_trigger_owes_timed_lists_and_a_container_trigger_owes_none() {
        let ms = |millis| Some(Duration::from_millis(millis));
        let idle = Relist::default();
        assert_eq!(idle.delay(false), None);
        assert_eq!(idle.after_trigger(Trigger::Container).delay(false), None);
        assert_eq!(idle.after_resync().delay(false), None);

        let mut network = idle.after_trigger(Trigger::Network);
        let mut owed = Vec::new();
        while let Some(delay) = network.delay(false) {
            owed.push(delay);
            network = network.after_delay();
        }
        assert_eq!(owed, [250, 500].map(Duration::from_millis));

        let network = idle.after_trigger(Trigger::Network);

        for later_wake in [
            network.after_trigger(Trigger::Container),
            network.after_resync(),
        ] {
            assert_eq!(later_wake.delay(false), ms(250), "{later_wake:?}");
        }
    }

    #[test]
    fn a_retry_follows_the_whole_schedule_and_a_wake_starts_it_over() {
        let mut relist = Relist::default();
        let mut delays = Vec::new();
        while let Some(delay) = relist.delay(true) {
            delays.push(delay);
            relist = relist.after_delay();
        }
        assert_eq!(delays, RELIST_DELAYS);

        for woken in [
            relist.after_trigger(Trigger::Container),
            relist.after_trigger(Trigger::Network),
            relist.after_resync(),
        ] {
            assert_eq!(woken.delay(true), Some(RELIST_DELAYS[0]), "{woken:?}");
        }
    }

    #[tokio::test]
    async fn events_that_are_not_triggers_keep_the_loop_waiting() {
        let mut events = open_stream(vec![
            event(EventMessageTypeEnum::CONTAINER, "create"),
            event(EventMessageTypeEnum::IMAGE, "pull"),
        ]);

        assert!(next_trigger(&mut events).now_or_never().is_none());
    }

    #[tokio::test]
    async fn a_stream_error_is_skipped_and_a_stream_end_is_reported() {
        let mut events = stream::iter(vec![
            Err("connection reset".to_string()),
            Ok(event(EventMessageTypeEnum::CONTAINER, "die")),
        ])
        .fuse();

        assert_eq!(next_trigger(&mut events).await, Some(Trigger::Container));
        assert_eq!(next_trigger(&mut events).await, None);
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Asked {
        Version,
        List,
        Events,
        /// Any other request. [`FakeEngine::calls`] says which.
        Other,
    }

    /// What is at the fake engine's socket path.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Socket {
        Missing,
        /// A socket file that no engine listens on.
        Stale,
        /// An engine that takes a request and never answers it.
        Silent,
        Serving,
    }

    const ENGINE_URL: &str = "http://engine.test";

    /// A Docker engine inside the test. bollard reaches it over in-memory
    /// pipes, because the paused clock runs ahead of a real socket. A list
    /// takes `list_ms`. The events response follows `replay`: each step
    /// waits its milliseconds and then sends its events as one read. After
    /// the last step the response ends, or with `holds_streams` it stays
    /// open until the test ends it.
    pub(crate) struct FakeEngine {
        started: tokio::time::Instant,
        list_ms: u64,
        replay: Vec<(u64, Vec<EventMessage>)>,
        holds_streams: bool,
        socket: Mutex<Socket>,
        listed: Mutex<Listed>,
        /// The body of the inspect response for each path. The engine
        /// answers 404 for any other path.
        holds: Mutex<HashMap<String, String>>,
        /// The paths whose inspect gets the head of a response and never
        /// its body.
        hangs: Mutex<Vec<String>>,
        /// What answers a delete of each path in place of the removal: a
        /// status line and a message, or with `None` the end of the
        /// connection.
        failed_deletes: Mutex<HashMap<String, Option<(&'static str, &'static str)>>>,
        /// The method and path of each [`Asked::Other`].
        calls: Mutex<Vec<String>>,
        stream_ends: watch::Sender<u64>,
        probed: Mutex<Vec<u128>>,
        asked: Mutex<Vec<(u128, Asked)>>,
        /// Runs when a request arrives, before the engine answers it.
        on_request: Mutex<Option<Box<dyn Fn() + Send>>>,
    }

    /// How the fake engine answers a list.
    #[derive(Clone)]
    enum Listed {
        /// The body of the response.
        Containers(String),
        Fails,
        /// Sends the head of the response and never its body, as a VM does
        /// that froze with its socket open.
        Hangs,
    }

    impl FakeEngine {
        /// An engine that serves, lists no containers, and ends each events
        /// response after `replay`.
        fn start(list_ms: u64, replay: Vec<(u64, Vec<EventMessage>)>) -> (Docker, Arc<Self>) {
            let engine = Self::new(list_ms, replay, false, Socket::Serving);
            (engine.open().unwrap(), engine)
        }

        /// An engine whose events responses stay open, for a test that
        /// moves it between socket states.
        fn at(socket: Socket) -> Arc<Self> {
            Self::new(0, vec![], true, socket)
        }

        fn new(
            list_ms: u64,
            replay: Vec<(u64, Vec<EventMessage>)>,
            holds_streams: bool,
            socket: Socket,
        ) -> Arc<Self> {
            Arc::new(Self {
                started: tokio::time::Instant::now(),
                list_ms,
                replay,
                holds_streams,
                socket: Mutex::new(socket),
                listed: Mutex::new(Listed::Containers("[]".into())),
                holds: Default::default(),
                hangs: Default::default(),
                failed_deletes: Default::default(),
                calls: Default::default(),
                stream_ends: watch::Sender::new(0),
                probed: Default::default(),
                asked: Default::default(),
                on_request: Default::default(),
            })
        }

        fn now_ms(&self) -> u128 {
            self.started.elapsed().as_millis()
        }

        fn socket(&self) -> Socket {
            *self.socket.lock().unwrap()
        }

        /// Stands in for [`open_socket`] at this engine's socket path.
        fn open(self: &Arc<Self>) -> Option<Docker> {
            self.probed.lock().unwrap().push(self.now_ms());
            if self.socket() == Socket::Missing {
                return None;
            }
            let engine = self.clone();
            let transport = move |request: bollard::BollardRequest| {
                let engine = engine.clone();
                async move {
                    if let Some(on_request) = &*engine.on_request.lock().unwrap() {
                        on_request();
                    }
                    match engine.socket() {
                        Socket::Missing | Socket::Stale => {
                            let refused = std::io::ErrorKind::ConnectionRefused;
                            return Err(std::io::Error::from(refused).into());
                        }
                        Socket::Silent => std::future::pending().await,
                        Socket::Serving => {}
                    }
                    let (client, server) = tokio::io::duplex(64 * 1024);
                    tokio::spawn(engine.serve(server));
                    let (mut sender, connection) =
                        hyper::client::conn::http1::handshake(TokioIo::new(client)).await?;
                    tokio::spawn(connection);
                    Ok(sender.send_request(request).await?)
                }
            };
            let docker = Docker::connect_with_custom_transport(
                transport,
                Some(ENGINE_URL),
                5,
                bollard::API_DEFAULT_VERSION,
            );
            Some(docker.unwrap())
        }

        async fn serve(self: Arc<Self>, mut pipe: tokio::io::DuplexStream) {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(pipe.read_u8().await.unwrap());
            }
            let head = String::from_utf8(head).unwrap();
            let request_line = head.lines().next().unwrap();
            let asked = |asked| self.asked.lock().unwrap().push((self.now_ms(), asked));
            if request_line.contains("/version") {
                asked(Asked::Version);
                let version = r#"{"Version":"29.2.1","ApiVersion":"1.49"}"#;
                respond(&mut pipe, "200 OK", version).await;
            } else if request_line.contains("/containers/json?") {
                asked(Asked::List);
                tokio::time::sleep(Duration::from_millis(self.list_ms)).await;
                let listed = self.listed.lock().unwrap().clone();
                match listed {
                    Listed::Containers(containers) => {
                        respond(&mut pipe, "200 OK", &containers).await;
                    }
                    Listed::Fails => {
                        let failed = r#"{"message":"the engine is shutting down"}"#;
                        respond(&mut pipe, "500 Internal Server Error", failed).await;
                    }
                    Listed::Hangs => never_finish(&mut pipe).await,
                }
            } else if request_line.contains("/events?") {
                asked(Asked::Events);
                let mut stream_ends = self.stream_ends.subscribe();
                let streaming = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n";
                pipe.write_all(streaming).await.unwrap();
                for (after_ms, events) in &self.replay {
                    tokio::time::sleep(Duration::from_millis(*after_ms)).await;
                    let lines: String = events
                        .iter()
                        .map(|event| serde_json::to_string(event).unwrap() + "\n")
                        .collect();
                    if !lines.is_empty() {
                        let read = format!("{:x}\r\n{lines}\r\n", lines.len());
                        pipe.write_all(read.as_bytes()).await.unwrap();
                    }
                }
                if self.holds_streams {
                    stream_ends.changed().await.unwrap();
                    if self.socket() != Socket::Serving {
                        return;
                    }
                }
                pipe.write_all(b"0\r\n\r\n").await.unwrap();
            } else {
                asked(Asked::Other);
                self.serve_held(&mut pipe, request_line).await;
            }
        }

        /// Answers an inspect with what the engine holds at the path, takes
        /// a delete for the removal of that unless the delete is to fail,
        /// and takes any other request as done.
        async fn serve_held(&self, pipe: &mut tokio::io::DuplexStream, request_line: &str) {
            let mut words = request_line.split(' ');
            let (method, url) = (words.next().unwrap(), words.next().unwrap());
            let path = url.trim_start_matches(ENGINE_URL);
            let path = path.split('?').next().unwrap();
            self.calls.lock().unwrap().push(format!("{method} {path}"));
            if self.hangs.lock().unwrap().iter().any(|hung| hung == path) {
                never_finish(pipe).await;
            }
            if method == "DELETE" {
                let failed = self.failed_deletes.lock().unwrap().get(path).copied();
                match failed {
                    Some(Some((status, message))) => {
                        let body = serde_json::json!({ "message": message }).to_string();
                        return respond(pipe, status, &body).await;
                    }
                    Some(None) => return,
                    None => {}
                }
            }
            let held = match method {
                "GET" => self.holds.lock().unwrap().get(path).cloned(),
                "DELETE" => {
                    let mut holds = self.holds.lock().unwrap();
                    let inspect_path = format!("{path}/json");
                    holds.remove(path).or_else(|| holds.remove(&inspect_path))
                }
                _ => Some(String::new()),
            };
            match held {
                Some(json) if method == "GET" => respond(pipe, "200 OK", &json).await,
                Some(_) => respond(pipe, "204 No Content", "").await,
                None => {
                    let missing = r#"{"message":"the engine holds no such thing"}"#;
                    respond(pipe, "404 Not Found", missing).await;
                }
            }
        }

        /// Makes the engine answer an inspect of `path` with `json`, until
        /// a request deletes what is there.
        #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
        pub(crate) fn hold(&self, path: &str, json: &str) {
            self.holds.lock().unwrap().insert(path.into(), json.into());
        }

        /// Makes the engine answer an inspect of `path` as a VM does that
        /// froze with its socket open.
        #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
        pub(crate) fn hang(&self, path: &str) {
            self.hangs.lock().unwrap().push(path.into());
        }

        /// Makes the engine keep what it holds at `path`. It answers a
        /// delete of it with the status line and message of `answer`, or
        /// with `None` ends the connection and answers nothing.
        #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
        pub(crate) fn fail_delete(&self, path: &str, answer: Option<(&'static str, &'static str)>) {
            self.failed_deletes
                .lock()
                .unwrap()
                .insert(path.into(), answer);
        }

        #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn set_socket(&self, socket: Socket) {
            *self.socket.lock().unwrap() = socket;
        }

        fn list(&self, containers: &[ContainerSummary]) {
            let containers = serde_json::to_string(containers).unwrap();
            *self.listed.lock().unwrap() = Listed::Containers(containers);
        }

        pub(crate) fn fail_lists(&self) {
            *self.listed.lock().unwrap() = Listed::Fails;
        }

        pub(crate) fn hang_lists(&self) {
            *self.listed.lock().unwrap() = Listed::Hangs;
        }

        /// Ends the events responses that are open. An engine that serves
        /// ends them as a response ends. Any other cuts them off.
        fn end_streams(&self) {
            self.stream_ends.send_modify(|ended| *ended += 1);
        }

        /// The engine goes away and takes its socket with it.
        fn vanish(&self) {
            self.set_socket(Socket::Missing);
            self.end_streams();
        }

        fn on_request(&self, observe: impl Fn() + Send + 'static) {
            *self.on_request.lock().unwrap() = Some(Box::new(observe));
        }

        fn probes(&self) -> Vec<u128> {
            self.probed.lock().unwrap().clone()
        }

        fn asked(&self) -> Vec<(u128, Asked)> {
            self.asked.lock().unwrap().clone()
        }

        fn times(&self, wanted: Asked) -> Vec<u128> {
            self.asked()
                .into_iter()
                .filter_map(|(at, asked)| (asked == wanted).then_some(at))
                .collect()
        }

        pub(crate) fn lists(&self) -> Vec<u128> {
            self.times(Asked::List)
        }
    }

    /// Sends the head of a response and never its body.
    async fn never_finish(pipe: &mut tokio::io::DuplexStream) {
        let head = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n";
        pipe.write_all(head).await.unwrap();
        std::future::pending::<()>().await;
    }

    async fn respond(pipe: &mut tokio::io::DuplexStream, status: &str, json: &str) {
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{json}",
            json.len()
        );
        pipe.write_all(response.as_bytes()).await.unwrap();
    }

    /// Runs one session against an engine until the events response ends,
    /// and returns that engine. `release_at_ms` frees a hostname that many
    /// milliseconds in, which wakes the reconcile. The test fails when the
    /// session has not ended one hour later, which takes no real time on
    /// the paused clock.
    async fn run_to_the_end(
        list_ms: u64,
        replay: Vec<(u64, Vec<EventMessage>)>,
        release_at_ms: Option<u64>,
    ) -> Arc<FakeEngine> {
        let (docker, engine) = FakeEngine::start(list_ms, replay);
        let dir = tempfile::tempdir().unwrap();
        let state = crate::handlers::tests::test_state(&dir);
        let session = {
            let state = state.clone();
            tokio::spawn(async move { serve(&docker, &state).await })
        };

        if let Some(release_at_ms) = release_at_ms {
            state.registry.upsert(static_route("api.acme.test"));
            tokio::time::sleep(Duration::from_millis(release_at_ms)).await;
            state.registry.remove("api.acme.test");
        }
        tokio::time::timeout(HOUR, session)
            .await
            .expect("the session ends when the event stream ends")
            .unwrap();
        engine
    }

    /// A handle whose link is in its first session, and the engine behind
    /// it, which serves and lists no containers.
    pub(crate) fn connected() -> (Engine, Arc<FakeEngine>) {
        let (engine, publisher) = channel();
        (engine, connect(&publisher))
    }

    /// Opens the first session of a link, with an engine that serves and
    /// lists no containers.
    pub(crate) fn connect(publisher: &watch::Sender<Link>) -> Arc<FakeEngine> {
        let (docker, fake) = FakeEngine::start(0, vec![]);
        publisher.send_replace(Link::Connected {
            session: Session(1),
            docker,
            socket: SOCKET.into(),
            version: Some("29.2.1".into()),
        });
        fake
    }

    const HOUR: Duration = Duration::from_secs(3600);

    fn static_route(host: &str) -> portman_core::Entry {
        portman_core::Entry {
            host: host.into(),
            target: "127.0.0.1:3070".into(),
            source: Source::Static,
            mode: Mode::Http,
            container_id: None,
            project: None,
            egress: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_start_lists_before_the_events_request_then_once_for_the_replay_and_twice_more() {
        use EventMessageTypeEnum::{CONTAINER, NETWORK};
        let replay = vec![
            (
                0,
                vec![
                    event(CONTAINER, "create"),
                    event(NETWORK, "connect"),
                    event(CONTAINER, "start"),
                ],
            ),
            (
                20,
                vec![event(NETWORK, "connect"), event(CONTAINER, "start")],
            ),
            (2000, vec![]),
        ];

        let engine = run_to_the_end(0, replay, None).await;

        assert_eq!(
            engine.asked(),
            [
                (0, Asked::List),
                (0, Asked::Events),
                (50, Asked::List),
                (300, Asked::List),
                (800, Asked::List),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_session_ends_when_the_event_stream_ends() {
        let engine = run_to_the_end(0, vec![(30, vec![])], None).await;

        assert_eq!(engine.lists(), [0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_ends_in_the_quiet_time_gets_the_list_for_its_burst_and_ends_the_session()
    {
        let die = vec![event(EventMessageTypeEnum::CONTAINER, "die")];

        let engine = run_to_the_end(0, vec![(0, die), (20, vec![])], None).await;

        assert_eq!(engine.lists(), [0, 20]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_hostname_released_in_the_quiet_time_lists_again_after_the_burst() {
        let start = vec![event(EventMessageTypeEnum::CONTAINER, "start")];

        let engine = run_to_the_end(0, vec![(0, start), (1000, vec![])], Some(20)).await;

        assert_eq!(engine.lists(), [0, 50, 50]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_hostname_released_during_a_list_lists_again_after_it() {
        let engine = run_to_the_end(10, vec![(1000, vec![])], Some(5)).await;

        assert_eq!(engine.lists(), [0, 10]);
    }

    #[derive(Clone, Default)]
    struct Logs(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Logs {
        fn capture() -> (Self, tracing::subscriber::DefaultGuard) {
            let logs = Self::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(logs.clone())
                .with_ansi(false)
                .finish();
            (logs, tracing::subscriber::set_default(subscriber))
        }

        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for Logs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for Logs {
        type Writer = Self;

        fn make_writer(&self) -> Self {
            self.clone()
        }
    }

    const ID: &str = "aaaaaaaaaaaa1111";
    const SHORT_ID: &str = "aaaaaaaaaaaa";

    fn labelled(host: &str) -> Container {
        Container {
            id: ID.into(),
            created: 100,
            host: host.into(),
            port: None,
            mode: Mode::Http,
            project: None,
            addresses: vec![("bridge".into(), [172, 17, 0, 2].into())],
            unaddressable: None,
        }
    }

    fn warnings_about(logs: &Logs, id: &str) -> usize {
        logs.text()
            .lines()
            .filter(|line| line.contains("WARN") && line.contains(id))
            .count()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_label_that_a_service_route_shadows_is_warned_once_and_routes_after_the_release() {
        let (logs, _guard) = Logs::capture();
        let dir = tempfile::tempdir().unwrap();
        let state = crate::handlers::tests::test_state(&dir);
        state.known_tlds.write().unwrap().insert("test".into());
        let service = portman_core::Entry {
            host: "web.demo.test".into(),
            target: "127.0.0.1:3070".into(),
            source: portman_core::Source::Service,
            mode: Mode::Http,
            container_id: None,
            project: None,
            egress: None,
        };
        state.registry.upsert(service.clone());
        let containers = [labelled("web.demo.test")];
        let mut reported = Vec::new();

        assert!(!apply(&state, &containers, &mut reported));
        assert!(!apply(&state, &containers, &mut reported));
        assert_eq!(state.registry.get("web.demo.test"), Some(service));
        assert_eq!(warnings_about(&logs, SHORT_ID), 1, "{}", logs.text());

        state.registry.remove("web.demo.test");
        assert!(state.container_resync.notified().now_or_never().is_some());
        apply(&state, &containers, &mut reported);

        let route = state
            .registry
            .get("web.demo.test")
            .expect("container route");
        assert_eq!(route.source, portman_core::Source::Container);
        assert_eq!(route.target, "172.17.0.2:80");
        assert_eq!(warnings_about(&logs, SHORT_ID), 1, "{}", logs.text());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_host_network_container_is_warned_once_and_never_waits() {
        let (logs, _guard) = Logs::capture();
        let dir = tempfile::tempdir().unwrap();
        let state = crate::handlers::tests::test_state(&dir);
        state.known_tlds.write().unwrap().insert("test".into());
        let containers = [Container {
            addresses: vec![],
            unaddressable: Some("host".into()),
            ..labelled("web.demo.test")
        }];
        let mut reported = Vec::new();

        assert!(!apply(&state, &containers, &mut reported));
        assert!(!apply(&state, &containers, &mut reported));

        assert!(state.registry.get("web.demo.test").is_none());
        assert_eq!(warnings_about(&logs, SHORT_ID), 1, "{}", logs.text());
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_fails_behind_a_trigger_costs_one_list_and_logs_the_error() {
        let (logs, _guard) = Logs::capture();
        let events = stream::iter(vec![
            Ok(event(EventMessageTypeEnum::CONTAINER, "die")),
            Err("connection reset".to_string()),
        ])
        .fuse();

        assert_eq!(list_times(events).await.len(), 1);
        assert!(logs.text().contains("connection reset"), "{}", logs.text());
    }

    const SOCKET: &str = "/run/demo/docker.sock";
    const OTHER_SOCKET: &str = "/run/acme/docker.sock";
    const WEB: &str = "web.demo.test";
    const API: &str = "api.demo.test";

    fn running(host: &str, address: &str) -> ContainerSummary {
        let endpoint = EndpointSettings {
            ip_address: Some(address.into()),
            ..Default::default()
        };
        ContainerSummary {
            id: Some(ID.into()),
            labels: Some(HashMap::from([(
                discovery::LABEL_HOST.to_string(),
                host.to_string(),
            )])),
            network_settings: Some(ContainerSummaryNetworkSettings {
                networks: Some(HashMap::from([("bridge".to_string(), endpoint)])),
            }),
            ..Default::default()
        }
    }

    /// The engine task over fake engines, each at its socket path.
    struct Rig {
        state: DaemonState,
        link: watch::Receiver<Link>,
        task: tokio::task::JoinHandle<Infallible>,
        _dir: tempfile::TempDir,
    }

    impl Rig {
        /// `engines` are the socket candidates, in the order the task
        /// tries them.
        fn boot(engines: Vec<(&'static str, Arc<FakeEngine>)>) -> Self {
            let candidates = engines.iter().map(|(path, _)| path.into()).collect();
            Self::boot_on(Sockets::Detected(candidates), engines)
        }

        /// `engines` are the fake engines, each at its socket path.
        fn boot_on(sockets: Sockets, engines: Vec<(&'static str, Arc<FakeEngine>)>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (engine, publisher) = channel();
            let state = DaemonState {
                engine,
                ..crate::handlers::tests::test_state(&dir)
            };
            state.known_tlds.write().unwrap().insert("test".into());
            let link = publisher.subscribe();
            let open = move |path: &Path| {
                let (_, engine) = engines.iter().find(|(at, _)| Path::new(at) == path)?;
                engine.open()
            };
            let task = tokio::spawn(run(publisher, sockets, open, state.clone()));
            Self {
                state,
                link,
                task,
                _dir: dir,
            }
        }

        /// A rig in its first session, with [`WEB`] routed to a container
        /// of the engine at [`SOCKET`].
        async fn connected() -> (Self, Arc<FakeEngine>) {
            let engine = FakeEngine::at(Socket::Serving);
            engine.list(&[running(WEB, "172.17.0.2")]);
            let mut rig = Self::boot(vec![(SOCKET, engine.clone())]);
            rig.session(1).await;
            assert_eq!(rig.target(WEB).as_deref(), Some("172.17.0.2:80"));
            (rig, engine)
        }

        /// Waits for the session with this number and for its first list.
        async fn session(&mut self, number: u64) {
            let wanted = Some(Session(number));
            tokio::time::timeout(HOUR, self.link.wait_for(|link| link.session() == wanted))
                .await
                .unwrap_or_else(|_| panic!("the link never reached session {number}"))
                .unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        /// Waits until a connect attempt has found no engine.
        async fn absent(&mut self) -> Absent {
            let found_none =
                |link: &Link| matches!(link, Link::Absent(why) if *why != Absent::Idle);
            let link = tokio::time::timeout(HOUR, self.link.wait_for(found_none))
                .await
                .expect("the link never reported an absent engine")
                .unwrap();
            match &*link {
                Link::Absent(reason) => reason.clone(),
                Link::Connected { .. } => unreachable!(),
            }
        }

        /// The target of the container route for `host`.
        fn target(&self, host: &str) -> Option<String> {
            let entry = self.state.registry.get(host)?;
            (entry.source == Source::Container).then_some(entry.target)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_records_its_socket_and_the_version_of_its_engine() {
        let (rig, _engine) = Rig::connected().await;

        match &*rig.link.borrow() {
            Link::Connected {
                socket, version, ..
            } => {
                assert_eq!(socket, Path::new(SOCKET));
                assert_eq!(version.as_deref(), Some("29.2.1"));
            }
            Link::Absent(reason) => panic!("the link is absent: {reason}"),
        };
    }

    #[tokio::test(start_paused = true)]
    async fn with_no_socket_the_link_is_absent_and_the_task_keeps_running() {
        let mut rig = Rig::boot(vec![(SOCKET, FakeEngine::at(Socket::Missing))]);

        assert_eq!(rig.absent().await, Absent::NoSocket);
        assert_eq!(rig.state.engine.docker().err(), Some(Absent::NoSocket));
        assert_eq!(rig.state.engine.session(), None);

        tokio::time::sleep(HOUR).await;
        assert!(!rig.task.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn a_configured_socket_that_is_missing_is_named_and_the_user_is_not_told_to_set_it() {
        let engines = vec![(SOCKET, FakeEngine::at(Socket::Missing))];
        let mut rig = Rig::boot_on(Sockets::Configured(SOCKET.into()), engines);

        let reason = rig.absent().await;

        assert_eq!(reason, Absent::NoSocketAt(SOCKET.into()));
        let message = reason.to_string();
        assert!(message.contains(SOCKET), "{message}");
        assert!(!message.contains("set PORTMAN_DOCKER_SOCKET"), "{message}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_absent_engine_is_tried_again_after_a_delay_that_grows_to_two_seconds() {
        let engine = FakeEngine::at(Socket::Missing);
        let _rig = Rig::boot(vec![(SOCKET, engine.clone())]);

        tokio::time::sleep(Duration::from_secs(6)).await;

        assert_eq!(engine.probes(), [0, 250, 750, 1750, 3750, 5750]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_engine_that_appears_is_connected_and_its_labelled_container_is_routed() {
        let engine = FakeEngine::at(Socket::Missing);
        engine.list(&[running(WEB, "172.17.0.2")]);
        let mut rig = Rig::boot(vec![(SOCKET, engine.clone())]);
        rig.absent().await;
        assert_eq!(rig.target(WEB), None);

        engine.set_socket(Socket::Serving);
        rig.session(1).await;

        assert_eq!(rig.target(WEB).as_deref(), Some("172.17.0.2:80"));
        assert!(rig.state.engine.docker().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_engine_clears_container_routes_and_keeps_a_static_route() {
        let (mut rig, engine) = Rig::connected().await;
        rig.state.registry.upsert(static_route("api.acme.test"));

        engine.vanish();

        assert_eq!(rig.absent().await, Absent::NoSocket);
        assert_eq!(rig.target(WEB), None);
        assert_eq!(
            rig.state.registry.get("api.acme.test"),
            Some(static_route("api.acme.test"))
        );
        assert_eq!(rig.state.engine.docker().err(), Some(Absent::NoSocket));
        tokio::time::sleep(HOUR).await;
        assert!(!rig.task.is_finished(), "the task ended with the engine");
    }

    #[tokio::test(start_paused = true)]
    async fn a_returning_engine_gets_a_new_session_and_its_routes_return() {
        let (mut rig, engine) = Rig::connected().await;
        engine.vanish();
        rig.absent().await;

        engine.list(&[running(WEB, "172.17.0.9")]);
        engine.set_socket(Socket::Serving);
        rig.session(2).await;

        assert_eq!(rig.target(WEB).as_deref(), Some("172.17.0.9:80"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_ends_while_the_engine_answers_gets_a_new_session_and_no_route_is_gone() {
        // (how long the first session lasted, the wait before the reconnect)
        let cases = [
            (SETTLED, Duration::ZERO),
            (Duration::from_secs(1), RECONNECT_DELAYS[1]),
        ];
        for (lasted, reconnect_after) in cases {
            let (mut rig, engine) = Rig::connected().await;
            let routed_at_each_request = Arc::new(Mutex::new(Vec::new()));
            engine.on_request({
                let (state, seen) = (rig.state.clone(), routed_at_each_request.clone());
                move || {
                    let routed = state.registry.get(WEB).is_some();
                    let connected = state.engine.session().is_some();
                    seen.lock().unwrap().push(routed && connected);
                }
            });
            tokio::time::sleep(lasted).await;

            let ended_at = engine.now_ms();
            engine.end_streams();
            rig.session(2).await;

            assert_eq!(
                engine.times(Asked::Version).last(),
                Some(&(ended_at + reconnect_after.as_millis())),
                "{lasted:?}"
            );
            assert_eq!(*routed_at_each_request.lock().unwrap(), [true; 3]);
            assert_eq!(rig.target(WEB).as_deref(), Some("172.17.0.2:80"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_list_that_fails_on_a_live_stream_is_retried_in_its_session() {
        let (rig, engine) = Rig::connected().await;

        engine.fail_lists();
        let failed_at = engine.now_ms();
        rig.state.container_resync.notify_one();
        tokio::time::sleep(HOUR).await;

        let retries: Vec<u128> = engine
            .lists()
            .into_iter()
            .filter_map(|at| at.checked_sub(failed_at))
            .collect();
        assert_eq!(retries, [0, 250, 750, 1750, 3750, 7750]);
        assert_eq!(rig.state.engine.session(), Some(Session(1)));
        assert_eq!(engine.times(Asked::Version).len(), 1);
        assert_eq!(rig.target(WEB).as_deref(), Some("172.17.0.2:80"));

        engine.list(&[running(API, "172.17.0.3")]);
        rig.state.container_resync.notify_one();
        tokio::time::sleep(Duration::from_millis(1)).await;

        assert_eq!(rig.target(API).as_deref(), Some("172.17.0.3:80"));
        assert_eq!(rig.target(WEB), None);
        assert_eq!(rig.state.engine.session(), Some(Session(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn sessions_that_end_at_once_come_at_a_growing_delay() {
        let engine = FakeEngine::new(0, vec![], false, Socket::Serving);
        let rig = Rig::boot(vec![(SOCKET, engine.clone())]);

        tokio::time::sleep(Duration::from_secs(6)).await;

        assert_eq!(
            engine.times(Asked::Version),
            [0, 250, 750, 1750, 3750, 5750]
        );
        assert_eq!(rig.state.engine.session(), Some(Session(6)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stale_socket_is_skipped_for_a_candidate_that_answers() {
        let stale = FakeEngine::at(Socket::Stale);
        let live = FakeEngine::at(Socket::Serving);
        live.list(&[running(WEB, "172.17.0.2")]);
        let mut rig = Rig::boot(vec![(OTHER_SOCKET, stale), (SOCKET, live)]);

        rig.session(1).await;

        assert_eq!(rig.target(WEB).as_deref(), Some("172.17.0.2:80"));
    }

    #[tokio::test(start_paused = true)]
    async fn sockets_that_no_engine_answers_on_are_reported_with_the_first_of_them() {
        let started = tokio::time::Instant::now();
        let mut rig = Rig::boot(vec![
            ("/run/missing/docker.sock", FakeEngine::at(Socket::Missing)),
            (SOCKET, FakeEngine::at(Socket::Silent)),
            (OTHER_SOCKET, FakeEngine::at(Socket::Stale)),
        ]);

        let reason = rig.absent().await;

        assert!(
            matches!(&reason, Absent::Unreachable { socket, .. } if socket == Path::new(SOCKET)),
            "{reason:?}"
        );
        assert_eq!(started.elapsed(), PROBE_TIMEOUT);
    }

    #[tokio::test]
    async fn a_socket_file_that_a_dead_engine_left_reads_as_a_socket_no_engine_listens_on() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("docker.sock");
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());

        let reason = super::connect(&Sockets::Configured(socket.clone()), &open_socket)
            .await
            .err();

        let error = "no engine listens on this socket".to_string();
        assert_eq!(reason, Some(Absent::Unreachable { socket, error }));
    }

    #[tokio::test]
    async fn a_socket_that_closes_every_connection_is_not_reported_in_the_words_of_the_http_client()
    {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            while let Ok((connection, _)) = listener.accept().await {
                drop(connection);
            }
        });

        let reason = super::connect(&Sockets::Configured(socket), &open_socket)
            .await
            .err()
            .expect("no engine answered");

        let message = reason.to_string();
        assert!(!message.contains("hyper"), "{message}");
        assert!(!message.contains("client error"), "{message}");
    }

    #[tokio::test(start_paused = true)]
    async fn when_one_runtime_stops_and_another_starts_the_link_moves_to_it() {
        let first = FakeEngine::at(Socket::Serving);
        first.list(&[running(WEB, "172.17.0.2")]);
        let second = FakeEngine::at(Socket::Missing);
        second.list(&[running(API, "172.18.0.2")]);
        let engines = vec![(SOCKET, first.clone()), (OTHER_SOCKET, second.clone())];
        let mut rig = Rig::boot(engines);
        rig.session(1).await;

        second.set_socket(Socket::Serving);
        first.vanish();
        rig.session(2).await;

        assert_eq!(rig.target(API).as_deref(), Some("172.18.0.2:80"));
        assert_eq!(rig.target(WEB), None);
    }
}
