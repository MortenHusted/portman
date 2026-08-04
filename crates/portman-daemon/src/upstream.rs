//! Upstream connects for the proxy and forwarder subsystems.
//!
//! A plain `TcpStream::connect` routes by the system default — which a
//! VPN/exit-node (e.g. Tailscale) can claim at the Network Extension layer,
//! blackholing bridge-subnet targets even while a more specific kernel route
//! exists. NE flow rules don't honor the routing table; interface-scoped
//! sockets (`IP_BOUND_IF`) do their route lookup against the named interface
//! only, so the capture never applies. When a target sits on the netbridge
//! subnet and the bridge is up, we scope the socket to the bridge's utun;
//! everything else falls through to a plain connect.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use tokio::net::TcpStream;

/// First three octets of the netbridge subnet (192.168.99.0/24). Matches
/// `portman_netbridge::tunnel::PORTMAN_SUBNET_CIDR` — kept local rather than
/// imported for the same reason as `host_facing::HOST_TUNNEL_IP`: one literal
/// doesn't justify coupling to the (macOS-only) netbridge crate's internals.
const BRIDGE_SUBNET_PREFIX: [u8; 3] = [192, 168, 99];

/// Interface index of the netbridge utun. Published by the netbridge task
/// while the bridge is up, cleared to `None` when it goes down. Shared with
/// every subsystem that opens upstream connections.
pub(crate) type BridgeIfIndex = Arc<RwLock<Option<u32>>>;

pub(crate) fn new_bridge_ifindex() -> BridgeIfIndex {
    Arc::new(RwLock::new(None))
}

/// Connect to `target` (`host-or-ip:port`), scoping the socket to the bridge
/// utun when the target is a literal bridge-subnet IPv4 address and the
/// bridge has published its interface index.
pub(crate) async fn connect(target: &str, bridge: &BridgeIfIndex) -> io::Result<TcpStream> {
    if let Some((addr, ifindex)) = scoped_route(target, bridge) {
        return connect_bound(addr, ifindex).await;
    }
    TcpStream::connect(target).await
}

/// `Some((addr, ifindex))` iff `target` parses as a bridge-subnet IPv4
/// socket address and the bridge is up. Hostname targets can't be on the
/// bridge subnet (container entries carry literal IPs) and fall through.
fn scoped_route(target: &str, bridge: &BridgeIfIndex) -> Option<(SocketAddr, u32)> {
    let addr: SocketAddr = target.parse().ok()?;
    let std::net::IpAddr::V4(ip) = addr.ip() else {
        return None;
    };
    if ip.octets()[..3] != BRIDGE_SUBNET_PREFIX {
        return None;
    }
    let ifindex = (*bridge.read().expect("bridge ifindex lock poisoned"))?;
    Some((addr, ifindex))
}

#[cfg(target_os = "macos")]
async fn connect_bound(addr: SocketAddr, ifindex: u32) -> io::Result<TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind_device_by_index_v4(std::num::NonZeroU32::new(ifindex))?;
    socket.set_nonblocking(true)?;
    tokio::net::TcpSocket::from_std_stream(socket.into())
        .connect(addr)
        .await
}

#[cfg(not(target_os = "macos"))]
async fn connect_bound(addr: SocketAddr, _ifindex: u32) -> io::Result<TcpStream> {
    // Container IPs are natively routable on Linux and the stub netbridge
    // never publishes an index, so this path is unreachable in practice.
    TcpStream::connect(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published(ifindex: Option<u32>) -> BridgeIfIndex {
        Arc::new(RwLock::new(ifindex))
    }

    #[test]
    fn bridge_subnet_target_with_live_bridge_is_scoped() {
        let route = scoped_route("192.168.99.133:3306", &published(Some(7)));
        assert_eq!(route, Some(("192.168.99.133:3306".parse().unwrap(), 7)));
    }

    #[test]
    fn bridge_subnet_target_without_bridge_falls_through() {
        assert_eq!(scoped_route("192.168.99.133:3306", &published(None)), None);
    }

    #[test]
    fn non_bridge_targets_fall_through() {
        let bridge = published(Some(7));
        assert_eq!(scoped_route("127.0.0.1:3306", &bridge), None);
        assert_eq!(scoped_route("10.19.108.20:80", &bridge), None);
        assert_eq!(scoped_route("192.168.98.10:80", &bridge), None);
    }

    #[test]
    fn hostname_and_v6_targets_fall_through() {
        let bridge = published(Some(7));
        assert_eq!(scoped_route("mysql.internal:3306", &bridge), None);
        assert_eq!(scoped_route("[::1]:3306", &bridge), None);
    }

    #[tokio::test]
    async fn connect_falls_through_for_loopback_targets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = connect(&addr.to_string(), &published(Some(7)))
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), addr);
    }
}
