//! Container route reconcile. A Docker event only says when to look. One list
//! of the running containers says which container routes the registry holds.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::models::{EventMessage, EventMessageTypeEnum};
use bollard::query_parameters::{EventsOptionsBuilder, ListContainersOptionsBuilder};
use bollard::Docker;
use futures_util::{Stream, StreamExt};
use portman_core::{Mode, Registry};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::discovery::{self, Container, Skip, Skipped};
use crate::DaemonState;

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

/// The daemon's registry and the handle that wakes [`run`]. The registry
/// wakes it for every hostname it releases.
pub(crate) fn registry_with_resync() -> (Registry, Arc<Notify>) {
    let resync = Arc::new(Notify::new());
    let wake = resync.clone();
    let registry = Registry::with_release_hook(move || wake.notify_one());
    (registry, resync)
}

pub(crate) async fn run(docker: Docker, state: DaemonState) -> Result<()> {
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
        let retry = match reconcile(&docker, &state, &mut reported).await {
            Ok(waiting) => waiting,
            Err(err) => {
                warn!(error = format!("{err:#}"), "container reconcile failed");
                true
            }
        };
        let Some(next) = wait(&mut events, &state.container_resync, relist, retry).await else {
            warn!("docker events stream ended");
            return Ok(());
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
mod tests {
    use super::*;
    use futures_util::{stream, FutureExt};
    use hyper_util::rt::TokioIo;
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
        List,
        Events,
    }

    /// A Docker engine inside the test. bollard reaches it over in-memory
    /// pipes, because the paused clock runs ahead of a real socket. A list
    /// takes `list_ms` and holds no containers. The events response follows
    /// `replay`: each step waits its milliseconds and then sends its events
    /// as one read. The response ends after the last step.
    struct Engine {
        started: tokio::time::Instant,
        list_ms: u64,
        replay: Vec<(u64, Vec<EventMessage>)>,
        asked: std::sync::Mutex<Vec<(u128, Asked)>>,
    }

    impl Engine {
        fn start(list_ms: u64, replay: Vec<(u64, Vec<EventMessage>)>) -> (Docker, Arc<Self>) {
            let engine = Arc::new(Self {
                started: tokio::time::Instant::now(),
                list_ms,
                replay,
                asked: Default::default(),
            });
            let serving = engine.clone();
            let docker = Docker::connect_with_custom_transport(
                move |request: bollard::BollardRequest| {
                    let engine = serving.clone();
                    async move {
                        let (client, server) = tokio::io::duplex(64 * 1024);
                        tokio::spawn(engine.serve(server));
                        let (mut sender, connection) =
                            hyper::client::conn::http1::handshake(TokioIo::new(client)).await?;
                        tokio::spawn(connection);
                        Ok(sender.send_request(request).await?)
                    }
                },
                Some("http://engine.test"),
                5,
                bollard::API_DEFAULT_VERSION,
            )
            .unwrap();
            (docker, engine)
        }

        async fn serve(self: Arc<Self>, mut pipe: tokio::io::DuplexStream) {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(pipe.read_u8().await.unwrap());
            }
            let head = String::from_utf8(head).unwrap();
            let request_line = head.lines().next().unwrap();
            let at = self.started.elapsed().as_millis();
            if request_line.contains("/containers/json?") {
                self.asked.lock().unwrap().push((at, Asked::List));
                tokio::time::sleep(Duration::from_millis(self.list_ms)).await;
                let listed = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n[]";
                pipe.write_all(listed).await.unwrap();
            } else if request_line.contains("/events?") {
                self.asked.lock().unwrap().push((at, Asked::Events));
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
                pipe.write_all(b"0\r\n\r\n").await.unwrap();
            } else {
                panic!("the loop asked for {request_line}");
            }
        }

        fn asked(&self) -> Vec<(u128, Asked)> {
            self.asked.lock().unwrap().clone()
        }

        fn lists(&self) -> Vec<u128> {
            self.asked()
                .into_iter()
                .filter_map(|(at, asked)| (asked == Asked::List).then_some(at))
                .collect()
        }
    }

    /// Runs the loop against an engine until the events response ends, and
    /// returns that engine. `release_at_ms` frees a hostname that many
    /// milliseconds in, which wakes the loop. The test fails when the loop
    /// has not ended one hour later, which takes no real time on the paused
    /// clock.
    async fn run_to_the_end(
        list_ms: u64,
        replay: Vec<(u64, Vec<EventMessage>)>,
        release_at_ms: Option<u64>,
    ) -> Arc<Engine> {
        let (docker, engine) = Engine::start(list_ms, replay);
        let dir = tempfile::tempdir().unwrap();
        let state = crate::handlers::tests::test_state(&dir);
        let running = tokio::spawn(run(docker, state.clone()));

        if let Some(release_at_ms) = release_at_ms {
            state.registry.upsert(portman_core::Entry {
                host: "api.acme.test".into(),
                target: "127.0.0.1:3070".into(),
                source: portman_core::Source::Static,
                mode: Mode::Http,
                container_id: None,
                project: None,
                egress: None,
            });
            tokio::time::sleep(Duration::from_millis(release_at_ms)).await;
            state.registry.remove("api.acme.test");
        }
        tokio::time::timeout(Duration::from_secs(3600), running)
            .await
            .expect("the loop ends when the event stream ends")
            .unwrap()
            .unwrap();
        engine
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
    async fn the_loop_ends_when_the_event_stream_ends() {
        let engine = run_to_the_end(0, vec![(30, vec![])], None).await;

        assert_eq!(engine.lists(), [0]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_ends_in_the_quiet_time_gets_the_list_for_its_burst_and_ends_the_loop() {
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
}
