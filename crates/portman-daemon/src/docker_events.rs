//! Container route reconcile. A Docker event only says when to look. One list
//! of the running containers says which container routes the registry holds.

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::models::{EventMessage, EventMessageTypeEnum};
use bollard::query_parameters::{EventsOptionsBuilder, ListContainersOptionsBuilder};
use bollard::Docker;
use futures_util::{FutureExt, Stream, StreamExt};
use portman_core::Mode;
use tracing::{debug, info, warn};

use crate::discovery::{self, Skipped};
use crate::DaemonState;

/// Delays between reconciles while a labelled container has no address.
const ADDRESS_RETRY: [Duration; 5] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

pub(crate) async fn run(docker: Docker, state: DaemonState) -> Result<()> {
    // bollard sends the request on the first poll, so the subscription cannot
    // be open before the first list. `since` makes the engine replay its event
    // buffer in the same step as the subscription, so an event from that gap
    // still causes a list. Epoch 0 asks for the whole buffer whatever the
    // engine's clock says.
    let options = EventsOptionsBuilder::default().since("0").build();
    let mut events = docker.events(Some(options)).fuse();
    info!("streaming docker events");

    let mut reported = HashSet::new();
    let mut retries = 0;
    loop {
        let waiting = match reconcile(&docker, &state, &mut reported).await {
            Ok(waiting) => waiting,
            Err(err) => {
                warn!(error = format!("{err:#}"), "container reconcile failed");
                true
            }
        };
        let retry = ADDRESS_RETRY.get(retries).copied().filter(|_| waiting);
        tokio::select! {
            trigger = next_trigger(&mut events) => {
                if trigger.is_none() {
                    warn!("docker events stream ended");
                    return Ok(());
                }
                retries = 0;
            }
            _ = state.container_resync.notified() => retries = 0,
            _ = tokio::time::sleep(retry.unwrap_or_default()), if retry.is_some() => retries += 1,
        }
    }
}

/// Lists the labelled running containers once and makes the registry's
/// container entries match. Returns whether a container that holds a host has
/// no address yet.
async fn reconcile(
    docker: &Docker,
    state: &DaemonState,
    reported: &mut HashSet<Skipped>,
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
    let plan = discovery::plan(&containers, |host| state.host_is_routable(host));

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

    for skipped in &plan.skipped {
        if !reported.contains(skipped) {
            warn!(
                host = %skipped.host,
                id = %skipped.id,
                reason = %skipped.reason,
                "ignoring container"
            );
        }
    }
    *reported = plan.skipped.into_iter().collect();

    if !plan.waiting.is_empty() {
        debug!(ids = ?plan.waiting, "labelled containers have no address yet");
    }
    Ok(!plan.waiting.is_empty())
}

/// Waits for an event that can change the container routes, then drains the
/// events the stream already holds, so a burst costs one list. `None` when the
/// stream has ended.
async fn next_trigger<E: Display>(
    events: &mut (impl Stream<Item = Result<EventMessage, E>> + Unpin),
) -> Option<()> {
    loop {
        match events.next().await? {
            Ok(event) if is_trigger(&event) => break,
            Ok(_) => {}
            Err(err) => warn!(error = %err, "docker events stream error"),
        }
    }
    while let Some(Some(_)) = events.next().now_or_never() {}
    Some(())
}

fn is_trigger(event: &EventMessage) -> bool {
    matches!(
        (event.typ, event.action.as_deref()),
        (Some(EventMessageTypeEnum::CONTAINER), Some("start" | "die"))
            | (
                Some(EventMessageTypeEnum::NETWORK),
                Some("connect" | "disconnect")
            )
    )
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
            (CONTAINER, "start", true),
            (CONTAINER, "die", true),
            (NETWORK, "connect", true),
            (NETWORK, "disconnect", true),
            (CONTAINER, "create", false),
            (CONTAINER, "exec_start: sh", false),
            (CONTAINER, "health_status: healthy", false),
            (NETWORK, "create", false),
            (IMAGE, "pull", false),
        ];
        for (typ, action, expected) in cases {
            assert_eq!(is_trigger(&event(typ, action)), expected, "{typ} {action}");
        }
        assert!(!is_trigger(&EventMessage::default()));
    }

    #[tokio::test]
    async fn a_burst_of_events_is_one_trigger() {
        use EventMessageTypeEnum::{CONTAINER, NETWORK};
        let mut events = open_stream(vec![
            event(CONTAINER, "create"),
            event(NETWORK, "connect"),
            event(CONTAINER, "start"),
            event(NETWORK, "connect"),
            event(CONTAINER, "start"),
        ]);

        assert_eq!(next_trigger(&mut events).await, Some(()));
        assert!(next_trigger(&mut events).now_or_never().is_none());
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

        assert_eq!(next_trigger(&mut events).await, Some(()));
        assert_eq!(next_trigger(&mut events).await, None);
    }
}
