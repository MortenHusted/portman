//! Embedded authoritative DNS server backed by the registry.
//!
//! Answers A queries for hostnames present in the registry, returning
//! `NXDOMAIN` otherwise. Other record types (AAAA, SOA, …) return NOERROR
//! with zero answers for now.
//!
//! Two ways it's bound:
//!   - `run(registry, port, loopback)` — host-facing, on `127.0.0.1:<port>`.
//!     This is what `/etc/resolver/<tld>` points at. TCP-mode hosts resolve
//!     to their dedicated loopback front (see `tcp_forward`).
//!   - `run_on(registry, addr, rewrite_localhost, loopback)` — generic. Used
//!     for the container-facing listener on `192.168.99.1:53` when the
//!     netbridge is enabled. If `rewrite_localhost` is `Some(ip)`, any loopback
//!     A-record answer is rewritten to `ip` before being sent (so a
//!     portman-network container resolves an HTTP-mode host to the host's
//!     tunnel IP instead of its own loopback). `loopback` is `None` there:
//!     containers reach TCP targets directly, not via a host loopback front.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::op::{Header, HeaderCounts, Metadata, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, Server};
use hickory_server::zone_handler::MessageResponseBuilder;
use portman_core::{LoopbackAllocator, Mode, Registry};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

/// TTL on answers, in seconds. Short — users add/remove rules frequently.
const ANSWER_TTL: u32 = 30;
const HOST_PROXY_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

pub(crate) async fn run(registry: Registry, port: u16, loopback: LoopbackAllocator) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    run_on(registry, addr, None, Some(loopback)).await
}

/// Bind a DNS server on `addr`. Two knobs make this reusable for the
/// container-facing listener:
///   - `rewrite_localhost`: if set, loopback A answers are rewritten to this
///     IP (so a container resolves an HTTP-mode host to the host tunnel IP).
///   - `loopback`: if set (host-facing), TCP-mode hosts resolve to their
///     dedicated loopback front instead of the raw target IP. Left `None` for
///     the container-facing listener, where containers reach targets directly.
pub(crate) async fn run_on(
    registry: Registry,
    addr: SocketAddr,
    rewrite_localhost: Option<Ipv4Addr>,
    loopback: Option<LoopbackAllocator>,
) -> Result<()> {
    let udp = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("binding UDP {addr}"))?;
    let tcp = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding TCP {addr}"))?;
    info!(%addr, rewrite = ?rewrite_localhost, "dns server listening (UDP + TCP)");

    let handler = DnsHandler {
        registry,
        rewrite_localhost,
        loopback,
    };
    let mut server = Server::new(handler);
    server.register_socket(udp);
    server.register_listener(tcp, Duration::from_secs(5), 65_535);
    server
        .block_until_done()
        .await
        .context("dns server terminated")?;
    Ok(())
}

#[derive(Clone)]
struct DnsHandler {
    registry: Registry,
    /// When set, loopback A answers are rewritten to this IP. Used by the
    /// container-facing listener so HTTP-mode hosts resolve to a reachable
    /// host IP from inside a portman-network container.
    rewrite_localhost: Option<Ipv4Addr>,
    /// When set (host-facing), TCP-mode hosts resolve to their dedicated
    /// loopback front. `None` on the container-facing listener.
    loopback: Option<LoopbackAllocator>,
}

impl DnsHandler {
    fn lookup_ipv4(&self, host: &str) -> Option<Ipv4Addr> {
        let (_, entry) = self.registry.lookup(host)?;
        let raw = match entry.mode {
            // HTTP/HTTPS flows must land on Portman's local proxy. The proxy
            // then uses the Host header to reach entry.target, including
            // non-default ports. An unknown mode routes the same way — the
            // proxy only special-cases Tcp and Egress.
            Mode::Http | Mode::Egress | Mode::Unknown => HOST_PROXY_IP,
            // TCP mode host-facing: answer with the entry's dedicated loopback
            // front, where portman's TCP forwarder relays to the target. This
            // keeps the route on loopback, immune to a VPN/exit-node that
            // captures the target's real subnet. Container-facing (loopback
            // = None): answer with the target IP and stay out of the path.
            Mode::Tcp => match &self.loopback {
                Some(alloc) => alloc.get_or_assign(host),
                None => target_ipv4(&entry.target)?,
            },
        };
        Some(match self.rewrite_localhost {
            Some(rewrite) if raw.is_loopback() => rewrite,
            _ => raw,
        })
    }
}

fn target_ipv4(target: &str) -> Option<Ipv4Addr> {
    let (host_part, _) = target.rsplit_once(':')?;
    match host_part.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None, // v0: ignore IPv6 targets for A queries
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let Ok(info) = request.request_info() else {
            return respond_error(request, &mut response_handle, ResponseCode::FormErr).await;
        };
        let qtype = info.query.query_type();
        let qname = info.query.name().to_string();
        let host = qname.trim_end_matches('.').to_ascii_lowercase();

        debug!(%qtype, %host, "dns query");

        match qtype {
            RecordType::A => match self.lookup_ipv4(&host) {
                Some(ip) => respond_a(request, &mut response_handle, &host, ip).await,
                None => respond_error(request, &mut response_handle, ResponseCode::NXDomain).await,
            },
            // AAAA / SOA / NS / etc: NOERROR with no answers — "no such record
            // type at this name" rather than "no such name".
            _ => respond_noerror_empty(request, &mut response_handle).await,
        }
    }
}

async fn respond_a<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    host: &str,
    ip: Ipv4Addr,
) -> ResponseInfo {
    let mut record_name = match Name::from_ascii(host) {
        Ok(n) => n,
        Err(err) => {
            warn!(%host, %err, "failed to parse query name; sending SERVFAIL");
            return respond_error(request, response_handle, ResponseCode::ServFail).await;
        }
    };
    record_name.set_fqdn(true);

    let record = Record::from_rdata(record_name, ANSWER_TTL, RData::A(A(ip)));
    let answers = [record];

    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = ResponseCode::NoError;

    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.build(metadata, answers.iter(), [], [], []);

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(err) => {
            warn!(%err, "dns response send failed");
            fallback_info(request, ResponseCode::ServFail)
        }
    }
}

async fn respond_error<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    code: ResponseCode,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.error_msg(&request.metadata, code);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(err) => {
            warn!(%err, "dns error response send failed");
            fallback_info(request, code)
        }
    }
}

async fn respond_noerror_empty<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = ResponseCode::NoError;
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.build_no_records(metadata);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(err) => {
            warn!(%err, "dns noerror-empty response send failed");
            fallback_info(request, ResponseCode::ServFail)
        }
    }
}

/// Build a ResponseInfo directly — used only when we couldn't send a real
/// response and need to return something from handle_request.
fn fallback_info(request: &Request, code: ResponseCode) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(&request.metadata);
    metadata.response_code = code;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use portman_core::{Entry, Source};

    fn entry(host: &str, target: &str, mode: Mode) -> Entry {
        Entry {
            host: host.into(),
            target: target.into(),
            source: Source::Static,
            mode,
            container_id: None,
            project: None,
            egress: None,
        }
    }

    #[test]
    fn http_entries_resolve_to_local_proxy() {
        let registry = Registry::new();
        registry.upsert(entry("app.test", "10.0.0.8:3000", Mode::Http));
        let handler = DnsHandler {
            registry,
            rewrite_localhost: None,
            loopback: None,
        };

        assert_eq!(handler.lookup_ipv4("app.test"), Some(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn host_facing_tcp_entries_resolve_to_a_loopback_front() {
        let registry = Registry::new();
        registry.upsert(entry("db.test", "10.0.0.9:5432", Mode::Tcp));
        let handler = DnsHandler {
            registry,
            rewrite_localhost: None,
            loopback: Some(LoopbackAllocator::new()),
        };

        let answer = handler.lookup_ipv4("db.test").unwrap();
        // A dedicated loopback front, never the raw target or plain localhost.
        assert!(answer.is_loopback());
        assert_ne!(answer, Ipv4Addr::new(10, 0, 0, 9));
        assert_ne!(answer, Ipv4Addr::LOCALHOST);
        // Stable across repeated queries.
        assert_eq!(handler.lookup_ipv4("db.test"), Some(answer));
    }

    #[test]
    fn container_facing_tcp_entries_resolve_to_target_ip() {
        let registry = Registry::new();
        registry.upsert(entry("db.test", "10.0.0.9:5432", Mode::Tcp));
        let handler = DnsHandler {
            registry,
            rewrite_localhost: None,
            loopback: None,
        };

        assert_eq!(
            handler.lookup_ipv4("db.test"),
            Some(Ipv4Addr::new(10, 0, 0, 9))
        );
    }

    #[test]
    fn container_facing_dns_rewrites_loopback_answers() {
        let registry = Registry::new();
        registry.upsert(entry("app.test", "10.0.0.8:3000", Mode::Http));
        let tunnel_ip = Ipv4Addr::new(192, 168, 99, 1);
        let handler = DnsHandler {
            registry,
            rewrite_localhost: Some(tunnel_ip),
            loopback: None,
        };

        assert_eq!(handler.lookup_ipv4("app.test"), Some(tunnel_ip));
    }
}
