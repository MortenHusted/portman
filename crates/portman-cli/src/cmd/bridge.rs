//! Netbridge commands: status, enable/disable, mode, prepare, doctor.

use crate::client::{bridge_status, wait_for_bridge_mode, wait_for_bridge_state};
use crate::cmd::run_setup_image_build;
use crate::doctor;
use anyhow::{bail, Result};
use portman_protocol::{BridgeAssessment, BridgePhase, DockerStatus, NetbridgeMode};

use crate::client::request;
use portman_protocol::{Request, Response};

pub(crate) async fn cmd_bridge_status() -> Result<()> {
    match request(Request::Status).await? {
        Response::Status {
            bridge_assessment,
            bridge_enabled,
            bridge_phase,
            bridge_mode,
            docker,
            ..
        } => {
            let routes = doctor::collect_docker_routes().await;
            let lines = bridge_status_lines(
                bridge_assessment,
                bridge_phase.or_from_enabled(bridge_enabled),
                bridge_mode,
                docker.as_ref(),
                &routes,
            );
            for line in lines {
                println!("{line}");
            }
            Ok(())
        }
        other => other.unexpected(),
    }
}

/// What `portman bridge status` prints. `routes` is what the `docker` CLI
/// found. A daemon that reports no engine state gets no `docker` line.
fn bridge_status_lines(
    assessment: BridgeAssessment,
    phase: BridgePhase,
    mode: NetbridgeMode,
    docker: Option<&DockerStatus>,
    routes: &doctor::DockerRouteStatus,
) -> Vec<String> {
    let mut lines = vec![
        format!("bridge:    {assessment}"),
        format!("netbridge: {}", phase.display_word()),
        format!("mode:      {}", NetbridgeMode::display_word(mode)),
    ];
    lines.extend(docker.map(|docker| format!("docker:    {}", docker.summary())));
    lines.extend(doctor::docker_cli_note(
        docker,
        &[routes.cli_answer()],
        "labelled docker networks lines",
    ));
    lines.extend(doctor::render_docker_routes(routes));
    lines
}

pub(crate) async fn cmd_doctor() -> Result<()> {
    let daemon = doctor::DaemonSnapshot::from_status(request(Request::Status).await.ok());
    let (setup_image, docker_routes) = tokio::join!(
        doctor::inspect_setup_image(),
        doctor::collect_docker_routes()
    );
    let report = doctor::DoctorReport {
        daemon,
        setup_image,
        legacy_bridge: doctor::detect_legacy_bridge(),
        docker_routes,
        container_facing: doctor::inspect_container_facing(),
    };
    print!("{}", doctor::render_report(&report));
    Ok(())
}

pub(crate) async fn cmd_bridge(req: Request, desired_enabled: bool, verb: &str) -> Result<()> {
    match request(req).await? {
        Response::Ok => {
            let settled = wait_for_bridge_state(desired_enabled).await?;
            println!("{}", settled.line(&format!("netbridge {verb}")));
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
            let settled = wait_for_bridge_mode(mode, before).await?;
            let done = format!(
                "netbridge mode set to {}",
                NetbridgeMode::display_word(mode)
            );
            println!("{}", settled.line(&done));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::{DockerCliError, DockerRouteStatus};
    use portman_protocol::DockerState;

    fn docker(state: DockerState, reason: Option<&str>) -> DockerStatus {
        DockerStatus {
            state,
            socket: Some("/run/demo/docker.sock".to_string()),
            reason: reason.map(str::to_string),
            ..DockerStatus::default()
        }
    }

    fn lines(
        phase: BridgePhase,
        docker: Option<&DockerStatus>,
        routes: &DockerRouteStatus,
    ) -> Vec<String> {
        bridge_status_lines(
            BridgeAssessment::Offline,
            phase,
            NetbridgeMode::OptIn,
            docker,
            routes,
        )
    }

    #[test]
    fn bridge_status_prints_the_bridge_the_engine_and_the_labelled_networks_in_that_order() {
        let no_containers = DockerRouteStatus::NoLabelledContainers;
        let networks = "labelled docker networks: no running dev.portman.host containers";
        let connected = docker(DockerState::Connected, None);

        assert_eq!(
            lines(BridgePhase::Up, Some(&connected), &no_containers),
            [
                "bridge:    offline",
                "netbridge: up",
                "mode:      opt-in",
                "docker:    connected to /run/demo/docker.sock",
                networks,
            ]
        );
        assert_eq!(
            lines(BridgePhase::Disabled, None, &no_containers),
            [
                "bridge:    offline",
                "netbridge: disabled",
                "mode:      opt-in",
                networks,
            ]
        );
    }

    #[test]
    fn bridge_status_puts_the_docker_cli_note_between_the_engine_and_the_networks() {
        let no_socket = docker(DockerState::Disconnected, Some("no socket"));
        let waiting = lines(
            BridgePhase::WaitingForDocker,
            Some(&no_socket),
            &DockerRouteStatus::NoLabelledContainers,
        );
        assert_eq!(
            waiting[1..],
            [
                "netbridge: waiting for docker",
                "mode:      opt-in",
                "docker:    disconnected, no socket at /run/demo/docker.sock",
                "docker CLI: a check reached an engine, and the daemon is connected to none; \
                 the labelled docker networks lines below come from the `docker` CLI",
                "labelled docker networks: no running dev.portman.host containers",
            ]
        );

        let silent = DockerCliError::NoAnswer("no answer in 3 s".to_string());
        let connected = docker(DockerState::Connected, None);
        let cli_silent = lines(
            BridgePhase::Up,
            Some(&connected),
            &DockerRouteStatus::Unavailable(silent),
        );
        assert_eq!(
            cli_silent[3..],
            [
                "docker:    connected to /run/demo/docker.sock",
                "docker CLI: a check got no answer from an engine, and the daemon is connected \
                 to one; the labelled docker networks lines below come from the `docker` CLI",
                "labelled docker networks: unavailable (no answer in 3 s)",
            ]
        );
    }
}
