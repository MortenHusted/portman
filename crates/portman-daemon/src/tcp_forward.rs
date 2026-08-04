//! Loopback TCP forwarders for `Mode::Tcp` entries.
//!
//! HTTP entries ride portman's shared `:80`/`:443` proxy and route by `Host:`.
//! TCP entries can't, so each one is fronted on its own `127.0.0.0/8` address
//! (see [`portman_core::LoopbackAllocator`]): DNS answers with that address,
//! and this task binds a listener there that relays to the real target. The
//! target port is preserved, so `pg.pacer.internal:5432` still works unchanged
//! — but the traffic now rides loopback and survives a VPN/exit-node that
//! captures the target's real subnet.
//!
//! Reconciliation is a short poll of the registry. The registry has no change
//! signal, and the DNS TTL is 30s, so a 2s poll converges well within the
//! window a client would re-resolve in.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use portman_core::{LoopbackAllocator, Mode, Platform, PlatformApi, Registry};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::upstream::{self, BridgeIfIndex};

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// One running forwarder: a listener on a dedicated loopback address relaying
/// to `target`. Keyed by host in the running set.
struct Forward {
    ip: Ipv4Addr,
    target: String,
    handle: JoinHandle<()>,
}

/// Long-running task spawned from `main`. Reconciles the set of loopback
/// forwarders with the registry's current TCP-mode entries every
/// `POLL_INTERVAL`. Never returns `Ok` — mirrors the other daemon subsystems
/// so `select!` treats an exit uniformly.
pub(crate) async fn run(
    registry: Registry,
    loopback: LoopbackAllocator,
    bridge: BridgeIfIndex,
) -> Result<()> {
    let platform = Platform;
    let mut running: HashMap<String, Forward> = HashMap::new();

    loop {
        reconcile(&registry, &loopback, &platform, &bridge, &mut running);
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Bring `running` in line with the registry: drop forwarders whose entry is
/// gone or whose target moved, then start forwarders for new TCP entries.
fn reconcile(
    registry: &Registry,
    loopback: &LoopbackAllocator,
    platform: &Platform,
    bridge: &BridgeIfIndex,
    running: &mut HashMap<String, Forward>,
) {
    let desired: HashMap<String, String> = registry
        .list()
        .into_iter()
        .filter(|e| e.mode == Mode::Tcp)
        .map(|e| (e.host, e.target))
        .collect();

    // Tear down anything no longer wanted, or whose target changed (container
    // restarted with a new IP) — the add pass below re-creates the latter.
    let stale: Vec<String> = running
        .iter()
        .filter(|(host, fwd)| desired.get(*host).map(|t| t != &fwd.target).unwrap_or(true))
        .map(|(host, _)| host.clone())
        .collect();
    for host in stale {
        if let Some(fwd) = running.remove(&host) {
            fwd.handle.abort();
            if let Err(err) = platform.remove_loopback_alias(fwd.ip) {
                warn!(%host, ip = %fwd.ip, %err, "removing loopback alias");
            }
            info!(%host, ip = %fwd.ip, "stopped tcp forwarder");
        }
    }

    for (host, target) in desired {
        if running.contains_key(&host) {
            continue;
        }
        let Some(port) = target_port(&target) else {
            warn!(%host, %target, "tcp entry target has no port; not fronting");
            continue;
        };
        let ip = loopback.get_or_assign(&host);
        if let Err(err) = platform.ensure_loopback_alias(ip) {
            warn!(
                %host, %ip, %err,
                "could not add loopback alias; tcp entry not fronted (is the daemon running as root?)"
            );
            continue;
        }
        let listen = SocketAddr::from((ip, port));
        let handle = spawn_forwarder(host.clone(), listen, target.clone(), bridge.clone());
        info!(%host, %listen, %target, "started tcp forwarder");
        running.insert(host, Forward { ip, target, handle });
    }
}

fn spawn_forwarder(
    host: String,
    listen: SocketAddr,
    target: String,
    bridge: BridgeIfIndex,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(listen).await {
            Ok(l) => l,
            Err(err) => {
                error!(%host, %listen, %err, "tcp forwarder bind failed");
                return;
            }
        };
        info!(%host, %listen, %target, "tcp forwarder listening");
        loop {
            match listener.accept().await {
                Ok((client, peer)) => {
                    let target = target.clone();
                    let host = host.clone();
                    let bridge = bridge.clone();
                    tokio::spawn(async move {
                        if let Err(err) = relay(client, &target, &bridge).await {
                            debug!(%host, %peer, %target, %err, "tcp forward connection ended");
                        }
                    });
                }
                Err(err) => error!(%host, %err, "tcp forwarder accept failed"),
            }
        }
    })
}

/// Splice `client` to a fresh connection to `target`, byte-for-byte in both
/// directions until either side closes. The upstream leg is interface-scoped
/// to the bridge utun for bridge-subnet targets (see [`crate::upstream`]) —
/// without that, an exit-node captures the daemon's own connect and the
/// loopback front dies exactly like a direct client connection would.
async fn relay(mut client: TcpStream, target: &str, bridge: &BridgeIfIndex) -> Result<()> {
    let mut upstream =
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, upstream::connect(target, bridge))
            .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(err)) => return Err(err).with_context(|| format!("connecting to {target}")),
            Err(_) => anyhow::bail!("connecting to {target} timed out"),
        };
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Port from a `host:port` target string.
fn target_port(target: &str) -> Option<u16> {
    target
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn target_port_parses_and_rejects() {
        assert_eq!(target_port("192.168.99.130:5432"), Some(5432));
        assert_eq!(target_port("127.0.0.1:3306"), Some(3306));
        assert_eq!(target_port("no-port"), None);
        assert_eq!(target_port("host:notaport"), None);
    }

    #[tokio::test]
    async fn relay_pipes_bytes_to_target() {
        // Upstream echo server.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = upstream.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            tokio::io::copy(&mut r, &mut w).await.ok();
        });

        // A front listener whose accepted connection we relay to upstream.
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let target = upstream_addr.to_string();
        tokio::spawn(async move {
            let (client, _) = front.accept().await.unwrap();
            relay(client, &target, &upstream::new_bridge_ifindex())
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }
}
