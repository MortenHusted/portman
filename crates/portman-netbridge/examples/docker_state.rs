//! Phase A.2 — docker-events subscription + network/container state machine.
//!
//! Streams Docker lifecycle events from colima's VM and keeps a small
//! in-memory snapshot of "which containers are on which docker network".
//! Complements `route_observer` (Phase A.1): one tells us routes coming
//! and going on the macOS host, the other tells us the Docker-side
//! reality that produces those routes.
//!
//! Together they'll drive the Phase A.3 `BridgeHealth` assessment —
//! "portman sees containers on network X but no route via utun to X" is
//! exactly the "bridge flap" signal that motivates the Rust port.
//!
//! **This is observation-only.** No container create/kill/restart/remove
//! calls. Safe to run alongside the v0 stack.
//!
//! Run: `cargo run -p portman-netbridge --example docker_state`
//!
//! Output shape (first line on start, then a new line per lifecycle
//! event, and a compact snapshot every 10s):
//!
//! ```text
//! dev_default   (172.18.0.0/16)    pg, pg174, mysql84, mysql-archival, osrm
//! bridge        (172.17.0.0/16)    portman-v0-test
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::models::{EventMessage, EventMessageTypeEnum};
use bollard::query_parameters::{
    EventsOptionsBuilder, InspectNetworkOptions, ListContainersOptionsBuilder,
    ListNetworksOptionsBuilder,
};
use bollard::Docker;
use futures_util::StreamExt;
use portman_core::paths::docker_socket_candidates;

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("docker_state: subscribing to Docker events via colima socket.");
    eprintln!("observation-only — no container mutations.\n");

    let docker = connect_docker()?;

    // Baseline snapshot: walk networks + containers once so we have something
    // to compare events against.
    print_snapshot(&docker).await?;

    // Tick: re-print snapshot every 10s. Events in between get inline logs.
    let mut ticker = tokio::time::interval(Duration::from_secs(10));
    ticker.tick().await; // consume the immediate first tick (we just printed)

    let mut event_stream = docker.events(Some(EventsOptionsBuilder::default().build()));

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                print_snapshot(&docker).await.ok();
            }
            Some(event) = event_stream.next() => {
                match event {
                    Ok(msg) => log_event(&msg),
                    Err(err) => eprintln!("event stream error: {err}"),
                }
            }
            else => break,
        }
    }
    Ok(())
}

fn connect_docker() -> Result<Docker> {
    for path in docker_socket_candidates() {
        if path.exists() {
            eprintln!("using docker socket: {}", path.display());
            let Some(s) = path.to_str() else {
                continue;
            };
            return Ok(Docker::connect_with_socket(
                s,
                120,
                bollard::API_DEFAULT_VERSION,
            )?);
        }
    }
    anyhow::bail!(
        "no docker socket found — is colima running? tried DOCKER_HOST + \
         ~/.colima, ~/.config/colima, ~/.orbstack, ~/.docker, /var/run/docker.sock"
    )
}

/// Print the current networks → containers mapping.
async fn print_snapshot(docker: &Docker) -> Result<()> {
    let networks = docker
        .list_networks(None::<ListNetworksOptionsBuilder>.map(|b| b.build()))
        .await
        .context("list_networks")?;

    // Index containers → network-ids → container-names so we can group.
    // list_containers gives us container→(network→ip) via NetworkSettings.
    let containers = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::default().all(true).build(),
        ))
        .await
        .context("list_containers")?;

    let mut by_network: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for c in &containers {
        let Some(name) = c
            .names
            .as_ref()
            .and_then(|ns| ns.first())
            .map(|n| n.trim_start_matches('/').to_string())
        else {
            continue;
        };
        let Some(nets) = c
            .network_settings
            .as_ref()
            .and_then(|s| s.networks.as_ref())
        else {
            continue;
        };
        for net_name in nets.keys() {
            by_network
                .entry(net_name.clone())
                .or_default()
                .insert(name.clone());
        }
    }

    println!("\n── snapshot ──────────────────────────────");
    let mut any_shown = false;
    for net in &networks {
        let Some(name) = net.name.as_deref() else {
            continue;
        };
        // Skip noise networks (no containers, no interesting subnet).
        let containers_here = by_network.get(name).cloned().unwrap_or_default();
        if containers_here.is_empty() && !matches!(name, "bridge" | "host" | "none") {
            continue;
        }

        let subnet = net
            .ipam
            .as_ref()
            .and_then(|i| i.config.as_ref())
            .and_then(|cfgs| cfgs.iter().find_map(|c| c.subnet.clone()))
            .unwrap_or_else(|| "-".to_string());

        let names: Vec<String> = containers_here.into_iter().collect();
        let joined = if names.is_empty() {
            "(empty)".to_string()
        } else {
            names.join(", ")
        };

        println!("  {name:<14}  ({subnet:<15})  {joined}");
        any_shown = true;
    }
    if !any_shown {
        println!("  (no networks with containers)");
    }

    // Inspect the default bridge for its gateway/mask — useful for
    // correlating with `route_observer`'s "172.17/16 → utun0" events.
    if let Ok(bridge) = docker
        .inspect_network("bridge", None::<InspectNetworkOptions>)
        .await
    {
        if let Some(cfg) = bridge
            .ipam
            .as_ref()
            .and_then(|i| i.config.as_ref())
            .and_then(|cfgs| cfgs.first())
        {
            if let (Some(subnet), Some(gateway)) = (&cfg.subnet, &cfg.gateway) {
                println!("  ── bridge subnet {subnet} via gateway {gateway}");
            }
        }
    }
    println!();
    Ok(())
}

/// Inline log for lifecycle events we care about. Filters noise
/// (exec_*, image pulls, health_status updates — useful for debugging
/// but drown out the signal for our purposes).
fn log_event(msg: &EventMessage) {
    let Some(typ) = msg.typ else { return };
    let action = msg.action.as_deref().unwrap_or("?");

    // Filter out the chatty actions.
    if action.starts_with("exec_") || action.starts_with("health_status") || action == "heartbeat" {
        return;
    }

    match typ {
        EventMessageTypeEnum::CONTAINER => {
            let name = msg
                .actor
                .as_ref()
                .and_then(|a| a.attributes.as_ref())
                .and_then(|attrs| attrs.get("name"))
                .cloned()
                .unwrap_or_else(|| "?".to_string());
            // Only print lifecycle-relevant actions. Add more as needed.
            if matches!(
                action,
                "create" | "start" | "die" | "stop" | "destroy" | "restart" | "pause" | "unpause"
            ) {
                println!("  container {action:>8}  {name}");
            }
        }
        EventMessageTypeEnum::NETWORK => {
            let name = msg
                .actor
                .as_ref()
                .and_then(|a| a.attributes.as_ref())
                .and_then(|attrs| attrs.get("name"))
                .cloned()
                .unwrap_or_else(|| "?".to_string());
            if matches!(action, "create" | "destroy" | "connect" | "disconnect") {
                println!("  network   {action:>8}  {name}");
            }
        }
        _ => {}
    }
}
