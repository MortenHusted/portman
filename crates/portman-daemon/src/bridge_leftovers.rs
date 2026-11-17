//! A daemon that stops leaves the setup container, the DNS forwarder and
//! the `portman` network in the engine, so that containers keep their
//! lookups and their addresses until the daemon is back. An uninstall brings
//! no daemon back, so it removes what `portman bridge disable` removes, by
//! the same rules: only what carries portman's labels, and only while it
//! holds the UDP port that every bridge listens on. It does not go through
//! the daemon's `Disable`, which would save the bridge as off for the next
//! install.

use std::path::{Path, PathBuf};

use bollard::Docker;
use portman_netbridge::runtime::{
    remove_leftovers, Cleanup, Leftovers, DNS_CONTAINER, PORTMAN_NETWORK,
};
use portman_netbridge::tunnel::HOST_WG_LISTEN_PORT;

use crate::engine::{self, Absent, Sockets};

/// How the removal of a bridge's leftovers ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeLeftovers {
    /// The engine at `socket` has nothing left for a removal to try. What a
    /// bridge left is gone or is not portman's. The `portman` network stays
    /// while a running container is attached to it.
    NoneLeft { socket: PathBuf },
    /// The engine at `socket` can still hold them. Another process holds
    /// the listen port, a removal failed, or the engine gave no answer in
    /// the time that a cleanup gives it.
    Owed { socket: PathBuf },
    /// No engine answered. `reason` says where the removal looked.
    NoEngine { reason: String },
}

/// The commands that remove the DNS forwarder and the `portman` network by
/// hand, for an uninstall that could not.
pub fn manual_removal_commands() -> [String; 2] {
    [
        format!("docker rm -f {DNS_CONTAINER}"),
        format!("docker network rm {PORTMAN_NETWORK}"),
    ]
}

/// Removes from the engine what a bridge left there. Call it when the
/// daemon is gone: a daemon that still runs a bridge holds the listen port,
/// and nothing is removed then.
///
/// `engine_socket` is the socket that the daemon was connected to, when the
/// daemon said so. With `None` the engine is the first that answers among
/// the paths that a daemon tries.
pub async fn remove_bridge_leftovers(engine_socket: Option<PathBuf>) -> BridgeLeftovers {
    let sockets = match engine_socket {
        Some(socket) => Sockets::Configured(socket),
        None => Sockets::Detected(portman_core::paths::docker_socket_candidates()),
    };
    remove_from(&sockets, &engine::open_socket, HOST_WG_LISTEN_PORT).await
}

async fn remove_from(
    sockets: &Sockets,
    open: &impl Fn(&Path) -> Option<Docker>,
    listen_port: u16,
) -> BridgeLeftovers {
    let found = match engine::connect(sockets, open).await {
        Ok(found) => found,
        Err(absent) => {
            return BridgeLeftovers::NoEngine {
                reason: where_no_engine_answered(absent),
            }
        }
    };
    let socket = found.socket;
    match remove_leftovers(
        &found.docker,
        listen_port,
        Leftovers::SetupContainerAndNetwork,
    )
    .await
    {
        Cleanup::Complete => BridgeLeftovers::NoneLeft { socket },
        Cleanup::Owed => BridgeLeftovers::Owed { socket },
    }
}

fn where_no_engine_answered(absent: Absent) -> String {
    match absent {
        Absent::Unreachable { socket, error } => {
            format!("no answer on {}: {error}", socket.display())
        }
        Absent::NoSocketAt(socket) => format!("no docker socket at {}", socket.display()),
        Absent::NoSocket | Absent::Idle => "no docker socket found".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::engine::tests::FakeEngine;

    const SOCKET: &str = "/run/demo/docker.sock";
    const SETUP_CONTAINER: &str = "/containers/portman-netbridge-setup/json";
    const NETWORK: &str = "/networks/portman";
    const FORWARDER: &str = "/containers/portman-netbridge-dns/json";
    const FORWARDER_BY_ID: &str = "/containers/dddd2222/json";

    /// A listen port that nobody holds: a bind to port 0 gets a port that
    /// the system picks.
    const FREE_PORT: u16 = 0;

    fn container(role: Option<&str>) -> String {
        let labels = role.map_or(String::new(), |role| {
            format!(r#""dev.portman.managed": "1", "dev.portman.role": "{role}""#)
        });
        format!(
            r#"{{"Id": "dddd2222", "Config": {{"Labels": {{{labels}}}}}, "State": {{"Running": true}}}}"#
        )
    }

    /// An engine that holds a setup container, a forwarder and a network
    /// named as portman names them.
    fn engine_with_leftovers(
        carry_portmans_labels: bool,
    ) -> (crate::engine::Engine, Arc<FakeEngine>) {
        let (engine, fake) = crate::engine::tests::connected();
        let role = |role| carry_portmans_labels.then_some(role);
        fake.hold(SETUP_CONTAINER, &container(role("netbridge-setup")));
        fake.hold(FORWARDER, &container(role("dns-forwarder")));
        fake.hold(FORWARDER_BY_ID, &container(role("dns-forwarder")));
        let network_labels = if carry_portmans_labels {
            r#"{"Labels": {"dev.portman.managed": "1"}}"#
        } else {
            r#"{"Labels": {}}"#
        };
        fake.hold(NETWORK, network_labels);
        (engine, fake)
    }

    #[tokio::test(start_paused = true)]
    async fn an_uninstall_removes_what_a_disable_removes_and_only_that() {
        let another_daemons_bridge = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let taken = another_daemons_bridge.local_addr().unwrap().port();
        let socket = PathBuf::from(SOCKET);
        let none_left = BridgeLeftovers::NoneLeft {
            socket: socket.clone(),
        };
        let everything = vec![
            "DELETE /containers/portman-netbridge-setup",
            "DELETE /containers/dddd2222",
            "DELETE /networks/portman",
        ];
        let table = [
            ((true, FREE_PORT), (everything, none_left.clone())),
            ((false, FREE_PORT), (vec![], none_left)),
            ((true, taken), (vec![], BridgeLeftovers::Owed { socket })),
        ];
        for ((carry_portmans_labels, listen_port), (removed, ended)) in table {
            let (engine, fake) = engine_with_leftovers(carry_portmans_labels);
            let sockets = Sockets::Configured(SOCKET.into());

            let uninstalled = remove_from(&sockets, &|_| engine.docker().ok(), listen_port).await;

            let removals: Vec<String> = fake
                .calls()
                .into_iter()
                .filter(|call| call.starts_with("DELETE"))
                .collect();
            let case =
                format!("carry_portmans_labels={carry_portmans_labels} listen_port={listen_port}");
            assert_eq!(removals, removed, "{case}");
            assert_eq!(uninstalled, ended, "{case}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_uninstall_that_finds_no_engine_says_where_it_looked_and_names_no_daemon_setting() {
        let table = [
            (
                Sockets::Configured(SOCKET.into()),
                "no docker socket at /run/demo/docker.sock",
            ),
            (Sockets::Detected(vec![]), "no docker socket found"),
        ];
        for (sockets, why) in table {
            let ended = remove_from(&sockets, &|_| None, FREE_PORT).await;

            assert_eq!(ended, BridgeLeftovers::NoEngine { reason: why.into() });
        }
    }
}
