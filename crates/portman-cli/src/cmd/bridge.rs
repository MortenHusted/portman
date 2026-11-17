//! Netbridge commands: status, enable/disable, mode, prepare, doctor.

use crate::client::{bridge_status, wait_for_bridge_mode, wait_for_bridge_state, Settled};
use crate::cmd::run_setup_image_build;
use crate::doctor;
use anyhow::{bail, Result};
use portman_protocol::{BridgeAssessment, BridgeCleanup, BridgePhase, DockerStatus, NetbridgeMode};

use crate::client::request;
use portman_protocol::{Request, Response};

pub(crate) async fn cmd_bridge_status() -> Result<()> {
    let status = request(Request::Status).await?;
    let routes = doctor::collect_docker_routes().await;
    for line in lines_of_status(status, &routes)? {
        println!("{line}");
    }
    Ok(())
}

fn lines_of_status(status: Response, routes: &doctor::DockerRouteStatus) -> Result<Vec<String>> {
    match status {
        Response::Status {
            bridge_assessment,
            bridge_enabled,
            bridge_phase,
            bridge_retry_in_secs,
            bridge_cleanup,
            bridge_mode,
            docker,
            ..
        } => Ok(bridge_status_lines(
            bridge_assessment,
            bridge_phase.or_from_enabled(bridge_enabled),
            bridge_retry_in_secs,
            bridge_cleanup,
            bridge_mode,
            docker.as_ref(),
            routes,
        )),
        other => other.unexpected(),
    }
}

/// What `portman bridge status` prints. `routes` is what the `docker` CLI
/// found. A daemon that reports no engine state gets no `docker` line, and
/// one that reports no cleanup state gets no `cleanup` line.
fn bridge_status_lines(
    assessment: BridgeAssessment,
    phase: BridgePhase,
    retry_in_secs: Option<u64>,
    cleanup: Option<BridgeCleanup>,
    mode: NetbridgeMode,
    docker: Option<&DockerStatus>,
    routes: &doctor::DockerRouteStatus,
) -> Vec<String> {
    let mut lines = vec![
        format!("bridge:    {assessment}"),
        format!("netbridge: {}", phase.status_words(retry_in_secs)),
    ];
    lines.extend(cleanup.map(|held| format!("cleanup:   {}", held.in_words())));
    lines.push(format!("mode:      {}", NetbridgeMode::display_word(mode)));
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
    // The entries are read before the status, so that no request without a
    // bound follows the wait for the health. A daemon that stops answering
    // during that wait would hold such a request with no end.
    let routes = match request(Request::ListEntries).await {
        Ok(Response::Entries { entries }) => entries,
        _ => Vec::new(),
    };
    let daemon = doctor::settled_daemon(|| async { request(Request::Status).await.ok() }).await;
    let (setup_image, docker_routes, dns_forwarder) = tokio::join!(
        doctor::inspect_setup_image(),
        doctor::collect_docker_routes(),
        doctor::inspect_dns_forwarder(daemon.bridge_phase, &routes),
    );
    let report = doctor::DoctorReport {
        daemon,
        setup_image,
        legacy_bridge: doctor::detect_legacy_bridge(),
        docker_routes,
        container_facing: doctor::inspect_container_facing(),
        dns_forwarder,
    };
    print!("{}", doctor::render_report(&report));
    Ok(())
}

/// What `portman bridge enable` and `portman bridge disable` print. A
/// disable whose cleanup did not remove the DNS forwarder says so in its
/// one line, and does not add the note that portman removes it.
fn settled_lines(settled: Settled, desired_enabled: bool, verb: &str) -> Vec<String> {
    match settled {
        Settled::LeftoversStay(_) => vec![settled.line(&format!("netbridge {verb}"))],
        Settled::Reached | Settled::WaitsForDocker => {
            bridge_command_lines(settled, desired_enabled, verb)
        }
    }
}

pub(crate) async fn cmd_bridge(req: Request, desired_enabled: bool, verb: &str) -> Result<()> {
    match request(req).await? {
        Response::Ok => {
            let settled = wait_for_bridge_state(desired_enabled).await?;
            for line in settled_lines(settled, desired_enabled, verb) {
                println!("{line}");
            }
            Ok(())
        }
        other => other.unexpected(),
    }
}

/// What `portman bridge enable` and `portman bridge disable` print when the
/// bridge has settled.
fn bridge_command_lines(settled: Settled, desired_enabled: bool, verb: &str) -> Vec<String> {
    let mut lines = vec![settled.line(&format!("netbridge {verb}"))];
    if !desired_enabled {
        lines.extend(disable_note());
    }
    lines
}

/// Only a bridge on macOS has a DNS forwarder for a disable to remove.
pub(crate) fn disable_note() -> Option<String> {
    cfg!(target_os = "macos").then(|| {
        format!(
            "portman removes the dns forwarder at {}; a container that lists it as its only resolver resolves no name until the bridge is enabled again",
            doctor::DNS_FORWARDER_IP
        )
    })
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
            for line in bridge_mode_lines(settled, mode) {
                println!("{line}");
            }
            Ok(())
        }
        other => other.unexpected(),
    }
}

fn bridge_mode_lines(settled: Settled, mode: NetbridgeMode) -> Vec<String> {
    let mut lines = vec![format!(
        "netbridge mode set to {}",
        NetbridgeMode::display_word(mode)
    )];
    if settled == Settled::WaitsForDocker {
        lines.push(
            "Docker is not connected; the bridge starts in this mode when Docker connects"
                .to_string(),
        );
    }
    lines
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
            None,
            None,
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
    fn bridge_status_says_when_a_failed_start_runs_again() {
        let waits = bridge_status_lines(
            BridgeAssessment::Offline,
            BridgePhase::Starting,
            Some(12),
            None,
            NetbridgeMode::OptIn,
            None,
            &DockerRouteStatus::NoLabelledContainers,
        );

        assert_eq!(
            waits[1],
            "netbridge: starting, the last start failed, tries again in 12s"
        );
    }

    #[test]
    fn bridge_status_says_what_holds_up_the_cleanup_of_a_disable_after_the_bridge_line() {
        let held = bridge_status_lines(
            BridgeAssessment::Offline,
            BridgePhase::Disabled,
            None,
            Some(BridgeCleanup::NoAnswer { within_secs: 20 }),
            NetbridgeMode::OptIn,
            None,
            &DockerRouteStatus::NoLabelledContainers,
        );

        assert_eq!(
            held[1..4],
            [
                "netbridge: disabled",
                "cleanup:   portman could not remove the dns forwarder and the `portman` \
                 network: the container engine gave no answer within 20 s. It tries again \
                 when it next connects to Docker, or at the next `portman bridge disable`",
                "mode:      opt-in",
            ]
        );
    }

    #[test]
    fn bridge_status_prints_the_cleanup_state_that_the_daemon_sends() {
        let sent =
            r#"{"kind":"status","bridge_phase":"disabled","bridge_cleanup":{"state":"failed"}}"#;
        let status: Response = serde_json::from_str(sent).unwrap();

        let lines = lines_of_status(status, &DockerRouteStatus::NoLabelledContainers).unwrap();

        assert_eq!(lines[1], "netbridge: disabled");
        assert!(
            lines[2].starts_with("cleanup:   portman could not"),
            "{lines:?}"
        );
    }

    #[test]
    fn a_disable_says_that_the_dns_forwarder_goes_and_what_a_container_loses() {
        let note = "portman removes the dns forwarder at 192.168.99.129; a container that \
                    lists it as its only resolver resolves no name until the bridge is \
                    enabled again";
        let disabled = bridge_command_lines(Settled::Reached, false, "disabled");
        if cfg!(target_os = "macos") {
            assert_eq!(disabled, ["netbridge disabled", note]);
        } else {
            assert_eq!(disabled, ["netbridge disabled"]);
        }

        assert_eq!(
            bridge_command_lines(Settled::Reached, true, "enabled"),
            ["netbridge enabled"]
        );
        assert_eq!(
            bridge_command_lines(Settled::WaitsForDocker, true, "enabled"),
            ["netbridge enabled; the bridge starts when Docker connects"]
        );
    }

    #[test]
    fn a_mode_change_says_when_docker_is_not_connected_and_when_the_mode_applies() {
        assert_eq!(
            bridge_mode_lines(Settled::Reached, NetbridgeMode::Docker),
            ["netbridge mode set to docker"]
        );
        assert_eq!(
            bridge_mode_lines(Settled::WaitsForDocker, NetbridgeMode::All),
            [
                "netbridge mode set to all",
                "Docker is not connected; the bridge starts in this mode when Docker connects",
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

    #[test]
    fn a_disable_that_left_the_forwarder_says_why_and_not_that_portman_removes_it() {
        let no_answer = portman_protocol::BridgeCleanup::NoAnswer { within_secs: 20 };

        let lines = settled_lines(Settled::LeftoversStay(no_answer), false, "disabled");

        assert_eq!(
            lines,
            [
                "netbridge disabled; portman could not remove the dns forwarder and the \
              `portman` network: the container engine gave no answer within 20 s. It tries \
              again when it next connects to Docker, or at the next `portman bridge disable`"
            ]
        );
        for (settled, enable, verb) in [
            (Settled::Reached, false, "disabled"),
            (Settled::Reached, true, "enabled"),
            (Settled::WaitsForDocker, true, "enabled"),
        ] {
            assert_eq!(
                settled_lines(settled, enable, verb),
                bridge_command_lines(settled, enable, verb),
                "{settled:?}"
            );
        }
    }
}
