//! Netbridge commands: status, enable/disable, mode, prepare, doctor.

use crate::client::{bridge_status, wait_for_bridge_mode, wait_for_bridge_state};
use crate::cmd::run_setup_image_build;
use crate::doctor;
use anyhow::{bail, Result};
use portman_protocol::NetbridgeMode;

use crate::client::request;
use portman_protocol::{Request, Response};

pub(crate) async fn cmd_bridge_status() -> Result<()> {
    match request(Request::Status).await? {
        Response::Status {
            bridge_assessment,
            bridge_enabled,
            bridge_phase,
            bridge_mode,
            ..
        } => {
            println!("bridge:    {bridge_assessment}");
            println!(
                "netbridge: {}",
                bridge_phase.or_from_enabled(bridge_enabled).display_word()
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
        daemon: doctor::DaemonSnapshot::from_status(request(Request::Status).await.ok()),
        setup_image: doctor::inspect_setup_image(),
        legacy_bridge: doctor::detect_legacy_bridge(),
        docker_routes: doctor::collect_docker_routes(),
        container_facing: doctor::inspect_container_facing(),
    };
    print!("{}", doctor::render_report(&report));
    Ok(())
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
    let before = bridge_status().await?;
    match request(Request::BridgeSetMode { mode }).await? {
        Response::Ok => {
            wait_for_bridge_mode(mode, before).await?;
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
    eprintln!("building netbridge setup image from the embedded context…");
    run_setup_image_build()?;
    println!("netbridge setup image ready: {}", doctor::SETUP_IMAGE);
    Ok(())
}

pub(crate) fn parse_netbridge_mode(raw: &str) -> Result<NetbridgeMode> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "opt-in" | "optin" => Ok(NetbridgeMode::OptIn),
        "docker" => Ok(NetbridgeMode::Docker),
        "all" => Ok(NetbridgeMode::All),
        other => bail!("unknown netbridge mode `{other}`; expected opt-in, docker, or all"),
    }
}
