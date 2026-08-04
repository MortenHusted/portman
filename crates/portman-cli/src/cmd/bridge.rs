//! Netbridge commands: status, enable/disable, mode, prepare, doctor.

use crate::client::{bridge_enabled, wait_for_bridge_state};
use crate::cmd::{locate_repo_root, run_setup_image_build};
use crate::doctor;
use anyhow::{bail, Context, Result};
use portman_protocol::NetbridgeMode;
use tokio::time::{sleep, Duration};

use crate::client::request;
use portman_protocol::{Request, Response};

pub(crate) async fn cmd_bridge_status() -> Result<()> {
    match request(Request::Status).await? {
        Response::Status {
            bridge_assessment,
            bridge_enabled,
            bridge_mode,
            ..
        } => {
            println!("bridge:    {bridge_assessment}");
            println!(
                "netbridge: {}",
                if bridge_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("mode:      {}", NetbridgeMode::display_word(bridge_mode));
            for line in doctor::render_docker_routes(&doctor::collect_docker_routes()) {
                println!("{line}");
            }
            Ok(())
        }
        other => other.unexpected(),
    }
}

pub(crate) async fn cmd_doctor() -> Result<()> {
    let report = doctor::DoctorReport {
        daemon: daemon_snapshot().await,
        setup_image: doctor::inspect_setup_image(),
        legacy_bridge: doctor::detect_legacy_bridge(),
        docker_routes: doctor::collect_docker_routes(),
        container_facing: doctor::inspect_container_facing(),
    };
    print!("{}", doctor::render_report(&report));
    Ok(())
}

pub(crate) async fn daemon_snapshot() -> doctor::DaemonSnapshot {
    match request(Request::Status).await {
        Ok(Response::Status {
            version,
            bridge_assessment,
            bridge_enabled,
            bridge_mode,
            ..
        }) => doctor::DaemonSnapshot {
            reachable: true,
            version: Some(version),
            bridge_assessment: Some(bridge_assessment),
            bridge_enabled: Some(bridge_enabled),
            bridge_mode: Some(bridge_mode),
        },
        _ => doctor::DaemonSnapshot {
            reachable: false,
            version: None,
            bridge_assessment: None,
            bridge_enabled: None,
            bridge_mode: None,
        },
    }
}

pub(crate) async fn cmd_bridge(req: Request, desired_enabled: bool, verb: &str) -> Result<()> {
    match request(req).await? {
        Response::Ok => {
            wait_for_bridge_state(desired_enabled).await?;
            println!("netbridge {verb}");
            Ok(())
        }
        other => other.unexpected(),
    }
}

pub(crate) async fn cmd_bridge_mode(mode: Option<String>) -> Result<()> {
    let Some(raw_mode) = mode else {
        match request(Request::Status).await? {
            Response::Status { bridge_mode, .. } => {
                println!("{}", NetbridgeMode::display_word(bridge_mode));
                return Ok(());
            }
            other => return other.unexpected(),
        }
    };

    let mode = parse_netbridge_mode(&raw_mode)?;
    let was_enabled = bridge_enabled().await?;
    match request(Request::BridgeSetMode { mode }).await? {
        Response::Ok => {
            wait_for_bridge_mode(mode).await?;
            if was_enabled {
                wait_for_bridge_state(true).await?;
            }
            println!(
                "netbridge mode set to {}",
                NetbridgeMode::display_word(mode)
            );
            Ok(())
        }
        other => other.unexpected(),
    }
}

pub(crate) async fn cmd_bridge_prepare() -> Result<()> {
    let repo = locate_repo_root().context("locating portman repo root")?;
    eprintln!("building netbridge setup image from {}", repo.display());
    run_setup_image_build(&repo)?;
    println!("netbridge setup image ready: {}", doctor::SETUP_IMAGE);
    Ok(())
}

pub(crate) async fn wait_for_bridge_mode(desired_mode: NetbridgeMode) -> Result<()> {
    for attempt in 0..120 {
        if bridge_mode().await? == desired_mode {
            return Ok(());
        }
        if attempt < 119 {
            sleep(Duration::from_millis(500)).await;
        }
    }
    bail!(
        "netbridge did not report mode {} after 60s",
        NetbridgeMode::display_word(desired_mode)
    );
}

pub(crate) async fn bridge_mode() -> Result<NetbridgeMode> {
    match request(Request::Status).await? {
        Response::Status { bridge_mode, .. } => Ok(bridge_mode),
        other => other.unexpected(),
    }
}

pub(crate) fn parse_netbridge_mode(raw: &str) -> Result<NetbridgeMode> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "opt-in" | "optin" => Ok(NetbridgeMode::OptIn),
        "docker" => Ok(NetbridgeMode::Docker),
        "all" => Ok(NetbridgeMode::All),
        other => bail!("unknown netbridge mode `{other}`; expected opt-in, docker, or all"),
    }
}
