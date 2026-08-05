//! Docker event loop: stream container lifecycle events, resolve the
//! container's IP via `docker inspect`, and update the registry.

use anyhow::{Context, Result};
use bollard::models::{EventActor, EventMessage, EventMessageTypeEnum};
use bollard::query_parameters::{EventsOptionsBuilder, InspectContainerOptions};
use bollard::Docker;
use futures_util::StreamExt;
use portman_core::{Entry, Mode, Source};
use tracing::{debug, info, warn};

use crate::DaemonState;

const LABEL_HOST: &str = "dev.portman.host";
const LABEL_PORT: &str = "dev.portman.port";
const LABEL_MODE: &str = "dev.portman.mode";

pub(crate) async fn run(docker: Docker, state: DaemonState) -> Result<()> {
    let options = EventsOptionsBuilder::default().build();
    let mut stream = docker.events(Some(options));

    info!("streaming docker events (filtering for dev.portman.* labels)");
    while let Some(event) = stream.next().await {
        match event {
            Ok(msg) => handle_event(&docker, &state, msg).await,
            Err(err) => warn!(error = %err, "docker events stream error"),
        }
    }
    warn!("docker events stream ended");
    Ok(())
}

async fn handle_event(docker: &Docker, state: &DaemonState, msg: EventMessage) {
    let registry = &state.registry;
    if msg.typ != Some(EventMessageTypeEnum::CONTAINER) {
        return;
    }
    let action = msg.action.as_deref().unwrap_or("");
    let Some(actor) = msg.actor.as_ref() else {
        return;
    };
    let id = actor.id.as_deref().unwrap_or("");
    if id.is_empty() {
        return;
    }

    match action {
        "start" => {
            let Some(raw_host) = host_label(actor) else {
                debug!(
                    id = short(id),
                    "ignoring start event without dev.portman.host label"
                );
                return;
            };
            let host = match normalize_host_label(&raw_host) {
                Ok(host) => host,
                Err(err) => {
                    warn!(
                        host = %raw_host,
                        id = short(id),
                        error = %err,
                        "ignoring container: invalid dev.portman.host label"
                    );
                    return;
                }
            };
            if !state.host_tld_is_managed(&host) {
                warn!(
                    %host,
                    id = short(id),
                    "ignoring container: TLD is not managed; run `portman tld add <tld>` first"
                );
                return;
            }
            let mode = Mode::parse_label(mode_label(actor).as_deref());
            let port = match (port_label(actor), mode) {
                (Some(p), _) => p,
                (None, Mode::Http | Mode::Egress) => "80".into(),
                (None, Mode::Tcp) => {
                    warn!(
                        %host,
                        id = short(id),
                        "ignoring container: dev.portman.mode=tcp requires dev.portman.port"
                    );
                    return;
                }
            };
            match resolve_target(docker, id, &port).await {
                Ok(target) => {
                    let entry = Entry {
                        host: host.clone(),
                        target: target.clone(),
                        source: Source::Container,
                        mode,
                        container_id: Some(short(id).to_string()),
                        project: project_label(actor),
                        egress: None,
                    };
                    registry.upsert(entry);
                    if mode == Mode::Http && state.host_tls_enabled(&host) {
                        if let Err(err) = state.cert_manager.ensure(&host) {
                            warn!(host = %host, error = %err, "failed to provision cert for container");
                        }
                    }
                    info!(
                        action = "start",
                        host = %host,
                        target = %target,
                        mode = mode.as_str(),
                        id = short(id),
                        "registered"
                    );
                }
                Err(err) => warn!(error = %err, id = short(id), "failed to resolve container IP"),
            }
        }
        "stop" | "die" => {
            let removed = registry.remove_by_container_id(short(id));
            if !removed.is_empty() {
                for entry in &removed {
                    info!(
                        action,
                        host = %entry.host,
                        id = short(id),
                        "unregistered"
                    );
                }
            }
        }
        _ => {}
    }
}

fn project_label(actor: &EventActor) -> Option<String> {
    actor
        .attributes
        .as_ref()?
        .get("dev.portman.project")
        .cloned()
        .filter(|v| !v.is_empty())
}

fn host_label(actor: &EventActor) -> Option<String> {
    actor
        .attributes
        .as_ref()?
        .get(LABEL_HOST)
        .cloned()
        .filter(|v| !v.is_empty())
}

pub(crate) fn normalize_host_label(raw: &str) -> Result<String> {
    portman_core::static_store::validate_host(raw).context("invalid dev.portman.host label")
}

fn port_label(actor: &EventActor) -> Option<String> {
    actor
        .attributes
        .as_ref()?
        .get(LABEL_PORT)
        .cloned()
        .filter(|v| !v.is_empty())
}

fn mode_label(actor: &EventActor) -> Option<String> {
    actor
        .attributes
        .as_ref()?
        .get(LABEL_MODE)
        .cloned()
        .filter(|v| !v.is_empty())
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// Call `docker inspect <id>` and pick the primary IP. Prefers the default
/// `NetworkSettings.IPAddress`; falls back to the first named network.
async fn resolve_target(docker: &Docker, id: &str, port: &str) -> Result<String> {
    let inspect = docker
        .inspect_container(id, None::<InspectContainerOptions>)
        .await?;
    let settings = inspect
        .network_settings
        .ok_or_else(|| anyhow::anyhow!("container has no network_settings"))?;

    if let Some(ip) = settings.ip_address.as_deref() {
        if !ip.is_empty() {
            return Ok(format!("{ip}:{port}"));
        }
    }
    if let Some(networks) = settings.networks {
        for net in networks.values() {
            if let Some(ip) = net.ip_address.as_deref() {
                if !ip.is_empty() {
                    return Ok(format!("{ip}:{port}"));
                }
            }
        }
    }
    anyhow::bail!("container has no usable IP yet")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host_label_matches_static_host_rules() {
        assert_eq!(normalize_host_label("Crm.Test").unwrap(), "crm.test");
        assert!(normalize_host_label("missingdot").is_err());
        assert!(normalize_host_label("bad host.test").is_err());
        assert!(normalize_host_label(".leading.test").is_err());
    }
}
