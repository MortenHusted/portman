//! Container-facing listeners on `192.168.99.1` (the host's utun
//! tunnel IP). Runs only while the v1 netbridge is up — the address
//! doesn't exist otherwise.
//!
//! Today: DNS/HTTP/TLS listeners on `192.168.99.1` that answer the
//! same way the host-facing DNS/proxy surfaces do, except DNS rewrites
//! any A-record answer of `127.0.0.1` to `192.168.99.1`.
//! That's what makes static rules like `crm.acme → 127.0.0.1:3070`
//! work from inside a portman-network container: the container
//! resolves to the host's tunnel IP, hits Portman's tunnel-side proxy,
//! and the macOS daemon forwards to the Rails app locally.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use portman_core::{Registry, TlsStore};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::certs::CertManager;
use crate::runner::Starter;
use crate::upstream::BridgeIfIndex;
use crate::{dns, proxy, tls_proxy};

/// Tunnel-side IP the daemon binds container-facing services on.
/// Matches `portman_netbridge::tunnel::HOST_TUNNEL_IP` — kept local
/// rather than imported to avoid making the daemon depend on the
/// netbridge crate's internal constants for a single IP literal.
const HOST_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 99, 1);

/// Port number containers expect DNS on. Standard 53 — unlike the
/// host-facing listener on 5335 (where mDNSResponder squats on 53),
/// no one else is on `192.168.99.1`, so we use the real port.
const CONTAINER_DNS_PORT: u16 = 53;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContainerFacingAddrs {
    dns: SocketAddr,
    http: SocketAddr,
    tls: SocketAddr,
}

fn container_facing_addrs(http_port: u16, tls_port: u16) -> ContainerFacingAddrs {
    ContainerFacingAddrs {
        dns: SocketAddr::from((HOST_TUNNEL_IP, CONTAINER_DNS_PORT)),
        http: SocketAddr::from((HOST_TUNNEL_IP, http_port)),
        tls: SocketAddr::from((HOST_TUNNEL_IP, tls_port)),
    }
}

struct RunningServices {
    dns: JoinHandle<()>,
    http: JoinHandle<()>,
    tls: JoinHandle<()>,
}

impl RunningServices {
    fn abort(self) {
        self.dns.abort();
        self.http.abort();
        self.tls.abort();
    }
}

/// Long-running task. Subscribes to `state_rx`; spawns the
/// container-facing listeners when the bridge comes up and aborts
/// them when it goes down.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    registry: Registry,
    mut state_rx: watch::Receiver<bool>,
    http_port: u16,
    tls_port: u16,
    cert_manager: CertManager,
    tls_store: Arc<TlsStore>,
    bridge: BridgeIfIndex,
    starter: Arc<dyn Starter>,
) -> Result<()> {
    let mut services: Option<RunningServices> = None;
    let addrs = container_facing_addrs(http_port, tls_port);

    loop {
        let want_up = *state_rx.borrow_and_update();

        match (&services, want_up) {
            (None, true) => {
                services = Some(spawn_services(
                    registry.clone(),
                    addrs,
                    cert_manager.clone(),
                    tls_store.clone(),
                    bridge.clone(),
                    starter.clone(),
                ));
            }
            (Some(_), false) => {
                if let Some(running) = services.take() {
                    running.abort();
                }
                info!("container-facing services stopped");
            }
            _ => {}
        }

        if state_rx.changed().await.is_err() {
            // Sender dropped → daemon is exiting.
            if let Some(running) = services.take() {
                running.abort();
            }
            return Ok(());
        }
    }
}

fn spawn_services(
    registry: Registry,
    addrs: ContainerFacingAddrs,
    cert_manager: CertManager,
    tls_store: Arc<TlsStore>,
    bridge: BridgeIfIndex,
    starter: Arc<dyn Starter>,
) -> RunningServices {
    RunningServices {
        dns: spawn_dns(registry.clone(), addrs.dns),
        http: spawn_http(registry.clone(), addrs.http, bridge.clone(), starter),
        tls: spawn_tls(registry, addrs.tls, cert_manager, tls_store, bridge),
    }
}

fn spawn_dns(registry: Registry, addr: SocketAddr) -> JoinHandle<()> {
    tokio::spawn(async move {
        // utun10's IP may need a brief moment to become usable after
        // the netbridge task signals the bridge is up (route install,
        // kernel state settle). Keep retrying while the bridge stays up:
        // this task is aborted by the parent when the bridge goes down.
        let mut attempt = 1u64;
        loop {
            match dns::run_on(registry.clone(), addr, Some(HOST_TUNNEL_IP), None).await {
                Ok(()) => {
                    warn!("container-facing dns listener stopped unexpectedly; retrying");
                }
                Err(err) => {
                    warn!(%err, attempt, "container-facing dns listener failed; retrying");
                }
            }
            tokio::time::sleep(retry_delay(attempt)).await;
            attempt = attempt.saturating_add(1);
        }
    })
}

fn spawn_http(
    registry: Registry,
    addr: SocketAddr,
    bridge: BridgeIfIndex,
    starter: Arc<dyn Starter>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut attempt = 1u64;
        loop {
            match proxy::run_on(registry.clone(), addr, bridge.clone(), starter.clone()).await {
                Ok(()) => warn!("container-facing http proxy stopped unexpectedly; retrying"),
                Err(err) => {
                    warn!(%err, attempt, %addr, "container-facing http proxy failed; retrying")
                }
            }
            tokio::time::sleep(retry_delay(attempt)).await;
            attempt = attempt.saturating_add(1);
        }
    })
}

fn spawn_tls(
    registry: Registry,
    addr: SocketAddr,
    cert_manager: CertManager,
    tls_store: Arc<TlsStore>,
    bridge: BridgeIfIndex,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut attempt = 1u64;
        loop {
            match tls_proxy::run_on(
                registry.clone(),
                addr,
                cert_manager.clone(),
                tls_store.clone(),
                bridge.clone(),
            )
            .await
            {
                Ok(()) => warn!("container-facing tls proxy stopped unexpectedly; retrying"),
                Err(err) => {
                    warn!(%err, attempt, %addr, "container-facing tls proxy failed; retrying")
                }
            }
            tokio::time::sleep(retry_delay(attempt)).await;
            attempt = attempt.saturating_add(1);
        }
    })
}

fn retry_delay(attempt: u64) -> Duration {
    if attempt < 5 {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn dns_retry_delay_backs_off_without_stopping() {
        assert_eq!(retry_delay(1), Duration::from_secs(2));
        assert_eq!(retry_delay(4), Duration::from_secs(2));
        assert_eq!(retry_delay(5), Duration::from_secs(10));
        assert_eq!(retry_delay(u64::MAX), Duration::from_secs(10));
    }

    #[test]
    fn container_facing_services_bind_on_host_tunnel_ip() {
        let addrs = container_facing_addrs(80, 443);
        let host = Ipv4Addr::new(192, 168, 99, 1);

        assert_eq!(addrs.dns, SocketAddr::from((host, 53)));
        assert_eq!(addrs.http, SocketAddr::from((host, 80)));
        assert_eq!(addrs.tls, SocketAddr::from((host, 443)));
    }
}
