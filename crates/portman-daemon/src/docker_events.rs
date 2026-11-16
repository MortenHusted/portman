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
use futures_util::{FutureExt, Stream, StreamExt};
use portman_core::{Mode, Registry};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::discovery::{self, Container, Skip, Skipped};
use crate::DaemonState;

/// Delays between lists that no wake caused. The loop takes these steps while
/// a labelled container has no address, after a list that failed, and for the
/// lists a network event owes.
const RELIST_DELAYS: [Duration; 5] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

/// Timed lists that a network event owes. The engine writes two small files
/// between the event and its list update, so the first step is long enough
/// unless the disk stalls. The second step covers a stall.
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
        let delay = relist.delay(retry);
        relist = tokio::select! {
            trigger = next_trigger(&mut events) => match trigger {
                Some(trigger) => relist.after_trigger(trigger),
                None => {
                    warn!("docker events stream ended");
                    return Ok(());
                }
            },
            _ = state.container_resync.notified() => relist.after_resync(),
            _ = tokio::time::sleep(delay.unwrap_or_default()), if delay.is_some() => {
                relist.after_delay()
            }
        };
    }
}

/// Lists the labelled running containers once and applies the list. Returns
/// what [`apply`] returns.
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
/// for each container that gets no route, for as long as its reason lasts.
/// Returns whether a container still waits for an address.
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

/// Waits for an event that can change the container routes, then drains the
/// events the stream already holds, so the events buffered behind it share its
/// list. A burst that holds a network event is a network trigger. `None` when
/// the stream has ended.
async fn next_trigger<E: Display>(
    events: &mut (impl Stream<Item = Result<EventMessage, E>> + Unpin),
) -> Option<Trigger> {
    let mut burst = None;
    loop {
        let next = if burst.is_some() {
            match events.next().now_or_never() {
                Some(Some(next)) => next,
                _ => return burst,
            }
        } else {
            events.next().await?
        };
        match next {
            Ok(event) => burst = burst.max(trigger(&event)),
            Err(err) => warn!(error = %err, "docker events stream error"),
        }
    }
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
    use futures_util::stream;

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

    #[tokio::test]
    async fn a_burst_of_events_is_one_trigger() {
        use EventMessageTypeEnum::{CONTAINER, NETWORK};
        let mut events = open_stream(vec![
            event(CONTAINER, "create"),
            event(CONTAINER, "start"),
            event(NETWORK, "connect"),
            event(CONTAINER, "start"),
        ]);

        assert_eq!(next_trigger(&mut events).await, Some(Trigger::Network));
        assert!(next_trigger(&mut events).now_or_never().is_none());
    }

    #[tokio::test]
    async fn a_burst_without_a_network_event_is_a_container_trigger() {
        use EventMessageTypeEnum::CONTAINER;
        let mut events = open_stream(vec![event(CONTAINER, "start"), event(CONTAINER, "die")]);

        assert_eq!(next_trigger(&mut events).await, Some(Trigger::Container));
    }

    #[test]
    fn a_network_trigger_owes_timed_lists_and_a_container_trigger_owes_none() {
        let ms = |millis| Some(Duration::from_millis(millis));
        let idle = Relist::default();
        assert_eq!(idle.delay(false), None);
        assert_eq!(idle.after_trigger(Trigger::Container).delay(false), None);
        assert_eq!(idle.after_resync().delay(false), None);

        let network = idle.after_trigger(Trigger::Network);
        assert_eq!(network.delay(false), ms(250));
        assert_eq!(network.after_delay().delay(false), ms(500));
        assert_eq!(network.after_delay().after_delay().delay(false), None);

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

    #[tokio::test]
    async fn a_stream_error_behind_a_trigger_is_logged() {
        let (logs, _guard) = Logs::capture();
        let mut events = stream::iter(vec![
            Ok(event(EventMessageTypeEnum::CONTAINER, "die")),
            Err("connection reset".to_string()),
        ])
        .fuse();

        assert_eq!(next_trigger(&mut events).await, Some(Trigger::Container));
        assert_eq!(next_trigger(&mut events).await, None);
        assert!(logs.text().contains("connection reset"), "{}", logs.text());
    }
}
