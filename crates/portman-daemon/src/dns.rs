//! Embedded authoritative DNS server backed by the registry.
//!
//! Answers A queries for hostnames present in the registry. For such a
//! hostname, other record types (AAAA, SOA, …) return NOERROR with zero
//! answers for now. The two listeners differ in what they answer for a
//! name that the registry does not hold.
//!
//! Two listeners:
//!   - `run(registry, port, loopback)` — host-facing, on `127.0.0.1:<port>`.
//!     This is what `/etc/resolver/<tld>` points at. TCP-mode hosts resolve
//!     to their dedicated loopback front (see `tcp_forward`). A name that
//!     the registry does not hold gets `NXDOMAIN` for an A query.
//!   - `run_for_containers(registry, addr, proxy)` — container-facing, on
//!     `192.168.99.1:53` while the netbridge is up. A loopback A answer is
//!     rewritten to `proxy` (so a container resolves an HTTP-mode host to
//!     the host's tunnel IP instead of its own loopback). Containers reach
//!     TCP targets directly, not via a host loopback front. A name that the
//!     registry does not hold gets `REFUSED` for every query type. The
//!     forwarder in the VM then asks its next upstream, which it does not
//!     do after `NXDOMAIN`.

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
    serve(addr, DnsHandler::host_facing(registry, loopback)).await
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) async fn run_for_containers(
    registry: Registry,
    addr: SocketAddr,
    proxy: Ipv4Addr,
) -> Result<()> {
    serve(addr, DnsHandler::container_facing(registry, proxy)).await
}

async fn serve(addr: SocketAddr, handler: DnsHandler) -> Result<()> {
    let udp = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("binding UDP {addr}"))?;
    let tcp = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding TCP {addr}"))?;
    info!(%addr, rewrite = ?handler.rewrite_localhost, "dns server listening (UDP + TCP)");

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
    unheld: Unheld,
}

/// What a listener answers for a name that the registry does not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unheld {
    /// `NXDOMAIN` for an A query and an empty `NOERROR` for any other type.
    NoSuchName,
    /// `REFUSED` for every type.
    Refused,
}

impl DnsHandler {
    fn host_facing(registry: Registry, loopback: LoopbackAllocator) -> Self {
        Self {
            registry,
            rewrite_localhost: None,
            loopback: Some(loopback),
            unheld: Unheld::NoSuchName,
        }
    }

    fn container_facing(registry: Registry, proxy: Ipv4Addr) -> Self {
        Self {
            registry,
            rewrite_localhost: Some(proxy),
            loopback: None,
            unheld: Unheld::Refused,
        }
    }

    fn refuses(&self, host: &str) -> bool {
        self.unheld == Unheld::Refused && self.registry.lookup(host).is_none()
    }

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

        if self.refuses(&host) {
            return respond_error(request, &mut response_handle, ResponseCode::Refused).await;
        }
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
            unheld: Unheld::NoSuchName,
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
            unheld: Unheld::NoSuchName,
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
            unheld: Unheld::NoSuchName,
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
            unheld: Unheld::NoSuchName,
        };

        assert_eq!(handler.lookup_ipv4("app.test"), Some(tunnel_ip));
    }

    /// Keeps the response that a listener sends.
    #[derive(Clone, Default)]
    struct Sent(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    #[async_trait::async_trait]
    impl ResponseHandler for Sent {
        async fn send_response<'a>(
            &mut self,
            response: hickory_server::zone_handler::MessageResponse<
                '_,
                'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
            >,
        ) -> Result<ResponseInfo, hickory_server::net::NetError> {
            let mut wire = Vec::new();
            let mut encoder = hickory_proto::serialize::binary::BinEncoder::new(&mut wire);
            let info = response.destructive_emit(&mut encoder)?;
            *self.0.lock().unwrap() = wire;
            Ok(info)
        }
    }

    /// The response code and the A answers that `listener` sends for one
    /// query.
    async fn ask(
        listener: &DnsHandler,
        name: &str,
        qtype: RecordType,
    ) -> (ResponseCode, Vec<Ipv4Addr>) {
        use hickory_proto::op::{Message, Query};
        use hickory_server::net::runtime::TokioTime;
        use hickory_server::net::xfer::Protocol;

        let mut query = Message::query();
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        let from = SocketAddr::from(([192, 168, 99, 129], 40000));
        let request = Request::from_bytes(query.to_vec().unwrap(), from, Protocol::Udp).unwrap();
        let sent = Sent::default();
        listener
            .handle_request::<_, TokioTime>(&request, sent.clone())
            .await;
        let response = Message::from_vec(&sent.0.lock().unwrap()).unwrap();
        let addresses = response
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect();
        (response.metadata.response_code, addresses)
    }

    #[tokio::test]
    async fn only_the_container_facing_listener_refuses_a_name_the_registry_does_not_hold() {
        use RecordType::{A as TypeA, AAAA, MX};
        use ResponseCode::{NXDomain, NoError, Refused};

        let registry = Registry::new();
        registry.upsert(entry("web.demo.test", "10.0.0.8:3000", Mode::Http));
        registry.upsert(entry("db.demo.test", "10.0.0.9:5432", Mode::Tcp));
        registry.upsert(entry("*.acme.test", "10.0.0.7:3000", Mode::Http));
        let tunnel = Ipv4Addr::new(192, 168, 99, 1);
        let host = DnsHandler::host_facing(registry.clone(), LoopbackAllocator::new());
        let containers = DnsHandler::container_facing(registry, tunnel);
        let front = host.lookup_ipv4("db.demo.test").unwrap();
        let target = Ipv4Addr::new(10, 0, 0, 9);

        // (listener, name, type) → (response code, A answers)
        let table = [
            (
                &host,
                "web.demo.test",
                TypeA,
                NoError,
                vec![Ipv4Addr::LOCALHOST],
            ),
            (&host, "db.demo.test", TypeA, NoError, vec![front]),
            (&host, "web.demo.test", AAAA, NoError, vec![]),
            (&host, "gone.demo.test", TypeA, NXDomain, vec![]),
            (&host, "gone.demo.test", AAAA, NoError, vec![]),
            (&host, "gone.demo.test", MX, NoError, vec![]),
            (&containers, "web.demo.test", TypeA, NoError, vec![tunnel]),
            (&containers, "db.demo.test", TypeA, NoError, vec![target]),
            (&containers, "web.demo.test", AAAA, NoError, vec![]),
            (&containers, "gone.demo.test", TypeA, Refused, vec![]),
            (&containers, "gone.demo.test", AAAA, Refused, vec![]),
            (&containers, "gone.demo.test", MX, Refused, vec![]),
            (&containers, "host.docker.internal", TypeA, Refused, vec![]),
            (&containers, "api.acme.test", TypeA, NoError, vec![tunnel]),
            (&containers, "api.acme.test", AAAA, NoError, vec![]),
            (&containers, "v2.api.acme.test", TypeA, Refused, vec![]),
            (
                &host,
                "api.acme.test",
                TypeA,
                NoError,
                vec![Ipv4Addr::LOCALHOST],
            ),
        ];
        for (listener, name, qtype, code, addresses) in table {
            assert_eq!(
                ask(listener, name, qtype).await,
                (code, addresses),
                "unheld={:?} name={name} type={qtype}",
                listener.unheld
            );
        }
    }

    /// The response code that the listener on `server` sends for an A query
    /// over UDP, or `None` when no response came.
    async fn ask_over_udp(server: SocketAddr, name: &str) -> Option<ResponseCode> {
        use hickory_proto::op::{Message, Query};

        let mut query = Message::query();
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&query.to_vec().unwrap(), server)
            .await
            .ok()?;
        let mut response = [0; 512];
        let received = socket.recv_from(&mut response);
        let (length, _) = tokio::time::timeout(Duration::from_millis(200), received)
            .await
            .ok()?
            .ok()?;
        let response = Message::from_vec(&response[..length]).unwrap();
        Some(response.metadata.response_code)
    }

    /// Starts a listener with `start` on a loopback port and asks it for
    /// `name`. The port is one that the system just gave out and took back,
    /// so another socket can get it first. The listener then ends at once,
    /// and the next port is tried.
    async fn answer_of_a_listener_started_with<F>(
        start: impl Fn(SocketAddr) -> F,
        name: &str,
    ) -> ResponseCode
    where
        F: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        for _ in 0..10 {
            let free = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = free.local_addr().unwrap();
            drop(free);
            let listener = tokio::spawn(start(addr));
            for _ in 0..25 {
                if listener.is_finished() {
                    break;
                }
                if let Some(code) = ask_over_udp(addr, name).await {
                    listener.abort();
                    return code;
                }
            }
            listener.abort();
        }
        panic!("no listener answered on ten loopback ports");
    }

    #[tokio::test]
    async fn each_listener_is_started_with_its_own_answer_for_a_name_that_is_not_held() {
        let registry = Registry::new();
        registry.upsert(entry("web.demo.test", "10.0.0.8:3000", Mode::Http));
        let tunnel = Ipv4Addr::new(192, 168, 99, 1);
        let for_containers = |addr| run_for_containers(registry.clone(), addr, tunnel);
        let for_the_host =
            |addr: SocketAddr| run(registry.clone(), addr.port(), LoopbackAllocator::new());

        assert_eq!(
            answer_of_a_listener_started_with(for_containers, "gone.demo.test").await,
            ResponseCode::Refused
        );
        assert_eq!(
            answer_of_a_listener_started_with(for_containers, "web.demo.test").await,
            ResponseCode::NoError
        );
        assert_eq!(
            answer_of_a_listener_started_with(for_the_host, "gone.demo.test").await,
            ResponseCode::NXDomain
        );
    }
}
