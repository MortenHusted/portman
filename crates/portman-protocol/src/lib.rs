//! IPC protocol between the portman daemon and its clients (CLI, web dashboard).
//!
//! Framing: length-prefixed JSON over a Unix socket at
//! `~/Library/Application Support/portman/portman.sock`. The protocol is
//! intentionally simple — JSON lets the Swift side parse with `Codable` and
//! the Rust side with `serde_json` without ceremony.

use serde::{Deserialize, Deserializer, Serialize};

#[cfg(feature = "transport")]
pub mod transport;

fn default_unknown() -> String {
    "?".to_string()
}

fn default_empty_string() -> String {
    String::new()
}

fn default_unknown_port() -> u16 {
    0
}

/// Per-TLD TLS mode. Snake_case on the wire (`"off"` | `"mkcert"` | `"le"`),
/// identical to the strings the protocol carried before it was typed.
/// Also the persisted representation in `tls.json` (via `portman-core`),
/// so an unknown mode is a hard parse error there, never silently coerced.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    #[default]
    Off,
    Mkcert,
    Le,
}

impl TlsMode {
    pub fn requires_tls(self) -> bool {
        matches!(self, TlsMode::Mkcert)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TlsMode::Off => "off",
            TlsMode::Mkcert => "mkcert",
            TlsMode::Le => "le",
        }
    }
}

/// Supervised-service lifecycle state. Serializes to the same snake_case
/// strings the field carried as a `String`; deserialization is lossy —
/// a state minted by a newer daemon lands in `Unknown` instead of failing
/// the whole status parse.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", from = "String")]
pub enum ServiceState {
    Pending,
    Starting,
    Ready,
    Backoff,
    Failed,
    Stopped,
    Unknown,
}

impl ServiceState {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceState::Pending => "pending",
            ServiceState::Starting => "starting",
            ServiceState::Ready => "ready",
            ServiceState::Backoff => "backoff",
            ServiceState::Failed => "failed",
            ServiceState::Stopped => "stopped",
            ServiceState::Unknown => "unknown",
        }
    }
}

impl From<String> for ServiceState {
    fn from(s: String) -> Self {
        match s.as_str() {
            "pending" => ServiceState::Pending,
            "starting" => ServiceState::Starting,
            "ready" => ServiceState::Ready,
            "backoff" => ServiceState::Backoff,
            "failed" => ServiceState::Failed,
            "stopped" => ServiceState::Stopped,
            _ => ServiceState::Unknown,
        }
    }
}

/// macOS-host ↔ VM bridge health. Same lossy-deserialize contract as
/// [`ServiceState`]: unknown future assessments become `Unknown`, and
/// `Unknown` is also the pre-Phase-A.3 default — "we have no signal
/// either way".
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", from = "String")]
pub enum BridgeAssessment {
    Healthy,
    RoutesMissing,
    TunnelDead,
    Offline,
    #[default]
    Unknown,
}

impl BridgeAssessment {
    pub fn as_str(self) -> &'static str {
        match self {
            BridgeAssessment::Healthy => "healthy",
            BridgeAssessment::RoutesMissing => "routes_missing",
            BridgeAssessment::TunnelDead => "tunnel_dead",
            BridgeAssessment::Offline => "offline",
            BridgeAssessment::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for TlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Display for BridgeAssessment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<String> for BridgeAssessment {
    fn from(s: String) -> Self {
        match s.as_str() {
            "healthy" => BridgeAssessment::Healthy,
            "routes_missing" => BridgeAssessment::RoutesMissing,
            "tunnel_dead" => BridgeAssessment::TunnelDead,
            "offline" => BridgeAssessment::Offline,
            _ => BridgeAssessment::Unknown,
        }
    }
}

/// Response-shape helpers for clients. Behind the `transport` feature only
/// because that's what brings in `anyhow`; they have no tokio dependency.
#[cfg(feature = "transport")]
impl Response {
    /// Expect a bare `Ok` acknowledgement: the daemon's own message on
    /// `Err`, "unexpected response" on anything else.
    pub fn into_ok(self) -> anyhow::Result<()> {
        match self {
            Response::Ok => Ok(()),
            other => other.unexpected(),
        }
    }

    /// The standard fallback arm for a match that expected some other
    /// variant: surfaces a daemon `Err` verbatim, labels everything else
    /// unexpected. Always returns `Err`.
    pub fn unexpected<T>(self) -> anyhow::Result<T> {
        match self {
            Response::Err { message } => Err(anyhow::anyhow!(message)),
            other => Err(anyhow::anyhow!("unexpected response: {other:?}")),
        }
    }
}

/// Default used when deserializing a Status response from a pre-B.7
/// daemon (no v1 netbridge integration). Off is the safe default —
/// older daemons never ran the bridge in-process.
fn default_bridge_enabled() -> bool {
    false
}

fn default_netbridge_mode() -> NetbridgeMode {
    NetbridgeMode::OptIn
}

fn default_dashboard_port() -> u16 {
    7341
}

/// A client → daemon request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    ListEntries,
    /// Retained CPU/memory time series for services, containers, and totals.
    ResourceHistory,
    AddStatic {
        host: String,
        target: String,
        /// Defaults to `Mode::Http` for backward-compat with older clients.
        #[serde(default)]
        mode: Mode,
        /// Optional service-runner mapping (e.g. a pitchfork daemon id like
        /// `acme/web`). When set, `StartService` for this host shells out to
        /// the process manager instead of Docker. Absent = no mapping.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
        /// Project tag for UI grouping/filtering. Absent = no project.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project: Option<String>,
    },
    RemoveStatic {
        host: String,
    },
    /// Start whatever is behind `host`: the pitchfork service mapped on its
    /// static rule, or its (possibly stopped) labelled Docker container.
    StartService {
        host: String,
    },
    Status,
    /// List portman-managed TLDs (files in `/etc/resolver/` with our marker).
    /// The response carries name + TLS mode + entry count per TLD.
    TldList,
    /// Notify the daemon that the CLI just wrote `/etc/resolver/<tld>`.
    /// `tls_mode` (optional) sets the per-TLD TLS mode. Absent = leave
    /// current mode alone.
    TldAdd {
        tld: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls_mode: Option<TlsMode>,
    },
    /// Mirror of `TldAdd` for removals.
    TldRemove {
        tld: String,
    },
    /// Diagnostic info about the cert subsystem (mkcert availability,
    /// CAROOT validity, issued cert count). Used by the About / TLDs pane.
    CertHealth,
    /// Read-only Docker resource usage snapshot for running containers.
    ResourceUsage,
    /// Turn the v1 Rust netbridge on. Idempotent: enabling an
    /// already-enabled bridge is a no-op that still persists the
    /// setting across daemon restarts.
    BridgeEnable,
    /// Turn the v1 Rust netbridge off. Also idempotent.
    BridgeDisable,
    /// Set the native netbridge route ownership mode.
    BridgeSetMode {
        mode: NetbridgeMode,
    },
    /// Sync a repo's parsed service definitions into the daemon (sent by
    /// `portman up`, which parses `portman.toml` + `portman.local.toml`
    /// client-side). Changed definitions restart their running service;
    /// definitions missing from the set (same root) are stopped and dropped.
    SyncServices {
        root: std::path::PathBuf,
        services: Vec<ServiceDefinition>,
        #[serde(default)]
        secrets: std::collections::BTreeMap<String, SecretsProviderConfig>,
        /// `[egress.<name>]` routes from the same config files. Wire-defaults
        /// so an older CLI syncing against a newer daemon stays valid.
        #[serde(default)]
        egress: std::collections::BTreeMap<String, EgressRoute>,
    },
    /// Start services by name (dependencies come up with them). Empty =
    /// every known service.
    ServiceUp {
        #[serde(default)]
        names: Vec<String>,
    },
    /// Stop services by name. Empty = every known service.
    ServiceDown {
        #[serde(default)]
        names: Vec<String>,
    },
    /// List supervised services and their states.
    ServiceStatus,
    /// Cursor read of a service's captured output. `after_id: None` returns
    /// the newest `limit` lines (the initial view); `Some(id)` returns lines
    /// newer than `id`. Chunks are bounded to fit the IPC frame — poll with
    /// the returned `last_id` to tail.
    LogsQuery {
        service: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after_id: Option<i64>,
        #[serde(default = "default_logs_limit")]
        limit: u32,
    },
    /// Store machine credentials for a secrets provider (written 0600 into
    /// the daemon's data dir). Secret fields are [`Redacted`] so the derived
    /// `Debug` (which the IPC server logs) never prints them.
    SetSecretsCredentials {
        /// `infisical` | `1password`.
        provider: String,
        /// Infisical universal-auth machine identity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_secret: Option<Redacted>,
        /// 1Password service-account token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<Redacted>,
    },
}

/// A secret value whose `Debug` rendering is always `<redacted>` — the IPC
/// server logs requests verbatim at debug level, and derived `Debug` on
/// [`Request`] would otherwise print tokens into the daemon log. Serializes
/// transparently as a plain string.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Redacted(pub String);

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

fn default_logs_limit() -> u32 {
    200
}

/// A daemon → client response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Entries {
        entries: Vec<Entry>,
    },
    Tlds {
        #[serde(deserialize_with = "deserialize_tld_infos")]
        tlds: Vec<TldInfo>,
    },
    Ok,
    Status {
        #[serde(default = "default_unknown")]
        version: String,
        #[serde(default = "default_unknown")]
        running_since: String,
        /// UDP/TCP port the daemon's DNS server is bound to on 127.0.0.1.
        #[serde(default = "default_unknown_port")]
        dns_port: u16,
        /// TCP port the HTTP proxy is bound to on 127.0.0.1.
        #[serde(default = "default_unknown_port")]
        proxy_port: u16,
        /// TCP port the HTTPS/TLS proxy is bound to on 127.0.0.1.
        #[serde(default = "default_unknown_port")]
        tls_port: u16,
        /// Absolute path of the Unix socket this response was read from.
        #[serde(default = "default_empty_string")]
        socket_path: String,
        /// Absolute path of portman's data dir (static.json, tls.json, certs/).
        #[serde(default = "default_empty_string")]
        data_dir: String,
        /// Absolute path of the generated-certs dir.
        #[serde(default = "default_empty_string")]
        cert_dir: String,
        /// Current macOS-host ↔ VM bridge health assessment.
        /// `Healthy` — bridge observed routing all docker subnets that
        /// currently have containers via a live utun; `RoutesMissing` —
        /// docker reports containers on subnet X but host has no route to X
        /// via any utun interface (i.e. the wrapped bridge has flapped);
        /// `TunnelDead` — a route exists but names a utun that no longer
        /// exists, so traffic is black-holed while the routing table looks
        /// correct; `Offline` — docker itself unreachable; `Unknown` —
        /// daemon just started, first assessment hasn't completed yet.
        /// Default preserves backward compat with pre-Phase-A.3 daemons.
        #[serde(default)]
        bridge_assessment: BridgeAssessment,
        /// Whether the v1 in-process netbridge is currently enabled
        /// (i.e. owning the `portman` docker network + utun tunnel).
        /// Distinct from `bridge_assessment`, which describes health
        /// of whichever bridge is routing — including the wrapped
        /// chipmk bridge in v0.
        #[serde(default = "default_bridge_enabled")]
        bridge_enabled: bool,
        /// Route ownership mode for the native netbridge.
        #[serde(default = "default_netbridge_mode")]
        bridge_mode: NetbridgeMode,
        /// TCP port the web dashboard binds to on 127.0.0.1.
        #[serde(default = "default_dashboard_port")]
        dashboard_port: u16,
    },
    CertHealth {
        /// `true` if `mkcert` is on the daemon's `PATH`.
        mkcert_available: bool,
        /// `$CAROOT` the daemon is using for mkcert invocations (may be `None`
        /// if the user's home couldn't be resolved).
        caroot_path: Option<String>,
        /// `true` if `caroot_path` exists and looks like a populated mkcert
        /// root (`rootCA.pem` present).
        caroot_valid: bool,
        /// Number of certs currently persisted under `cert_dir`.
        issued_count: u32,
    },
    ResourceUsage {
        #[serde(default)]
        snapshot: ResourceUsageSnapshot,
    },
    /// Answer to `ResourceHistory`: one series per live service/container plus
    /// the machine-wide total, oldest point first.
    ResourceHistory {
        #[serde(default)]
        series: Vec<ResourceSeries>,
    },
    /// Successful `StartService`. `detail` says which backend acted and how
    /// (e.g. `restarted container 2267…` / `pitchfork start acme/web: ok`).
    Started {
        #[serde(default)]
        detail: String,
    },
    /// What a `SyncServices` changed.
    SyncReport {
        #[serde(default)]
        added: Vec<String>,
        #[serde(default)]
        updated: Vec<String>,
        #[serde(default)]
        removed: Vec<String>,
        #[serde(default)]
        unchanged: Vec<String>,
    },
    /// Supervised services and their states.
    ServiceStatuses {
        #[serde(default)]
        services: Vec<ServiceStatusInfo>,
    },
    /// One bounded chunk of captured service output; `last_id` is the
    /// cursor for the next poll.
    Logs {
        #[serde(default)]
        lines: Vec<LogLineInfo>,
        #[serde(default)]
        last_id: i64,
    },
    Err {
        message: String,
    },
}

/// One row of the supervised-service status list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceStatusInfo {
    pub name: String,
    /// Config root that owns this service. Missing when talking to an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<std::path::PathBuf>,
    pub state: ServiceState,
    /// Human detail: last error, backoff note. Empty when healthy.
    #[serde(default)]
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default)]
    pub restarts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub desired_up: bool,
    /// Group tags from the service definition. Empty → UI groups by the
    /// `root` directory name instead.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Project tag from the owning config file; `None` → UI falls back to
    /// the `root` directory name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

/// One captured log line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogLineInfo {
    pub id: i64,
    #[serde(default)]
    pub ts_ms: i64,
    /// `stdout` | `stderr`.
    #[serde(default)]
    pub stream: String,
    #[serde(default)]
    pub line: String,
}

/// A single hostname → target mapping, regardless of how it was registered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub host: String,
    pub target: String,
    pub source: Source,
    /// Connection model. `Http` goes through portman's `:80`/`:443` proxy and
    /// routes by `Host:` header. `Tcp` is fronted per-host on a dedicated
    /// loopback address: DNS answers with the front and the daemon relays to
    /// `target` (see the daemon's `tcp_forward` module).
    #[serde(default)]
    pub mode: Mode,
    /// Short Docker container id for `Source::Container` entries; `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    /// Project tag: from `portman add --project` on static rules, the
    /// `dev.portman.project` label on containers, or the owning config
    /// file's `project` on service-derived routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Credential to attach when proxying to `target`. Only meaningful for
    /// [`Mode::Egress`]; `None` everywhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressSpec>,
}

/// Which credential the proxy attaches to a request on its way out, and how.
///
/// This names a secret; it never carries one. The daemon resolves the named
/// `[secrets.<block>]` key at proxy time, so the value exists only inside the
/// daemon and never in a config file, a registry dump, or a caller's
/// environment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressSpec {
    /// `[secrets.<block>]` the value comes from.
    pub secrets: String,
    /// Key within that block.
    pub key: String,
    /// Header to set, e.g. `Authorization`.
    pub header: String,
    /// Value template; `{value}` is replaced with the resolved secret.
    pub format: String,
    /// `Host:` to present to the upstream, e.g. `api.github.com`.
    pub upstream_host: String,
    /// Speak TLS to the upstream (default off: plaintext targets like
    /// `127.0.0.1:3000` or test fakes). Real APIs are `https`, so real
    /// egress routes set this — the proxy then originates TLS to `target`.
    #[serde(default)]
    pub tls: bool,
}

impl EgressSpec {
    /// Render the header value. Kept here so the substitution rule has one
    /// definition rather than one per call site.
    #[must_use]
    pub fn render(&self, value: &str) -> String {
        self.format.replace("{value}", value)
    }
}

/// One `[egress.<name>]` route as synced from repo config: where local
/// callers reach the proxy, which upstream answers, and which credential
/// gets attached on the way out. Names a secret; never carries one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressRoute {
    /// Hostname local callers address (under a managed TLD).
    pub host: String,
    /// Upstream `host:port` the rewritten request is forwarded to.
    pub target: String,
    /// Credential attachment (block, key, header, format, upstream Host,
    /// and whether the hop is TLS).
    pub spec: EgressSpec,
}

/// One row of the TldList response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TldInfo {
    pub name: String,
    #[serde(default)]
    pub tls_mode: TlsMode,
    /// Number of entries in the registry whose host falls under this TLD.
    #[serde(default)]
    pub entry_count: u32,
}

/// A point-in-time Docker resource snapshot. CPU is expressed the same way
/// Docker does: 100.0 means one full vCPU, so totals can exceed 100.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ResourceUsageSnapshot {
    #[serde(default)]
    pub sampled_at_unix_ms: u64,
    #[serde(default)]
    pub sample_window_ms: u64,
    #[serde(default)]
    pub container_count: u32,
    #[serde(default)]
    pub totals: ResourceUsageTotals,
    #[serde(default)]
    pub containers: Vec<ContainerResourceUsage>,
    /// Supervised host services, sampled per process group. `default` so a
    /// stale client deserializes snapshots from newer daemons cleanly.
    /// `totals` above stays docker-only.
    #[serde(default)]
    pub services: Vec<ServiceResourceUsage>,
}

/// Resource usage of one supervised service's process group. Gauge fields
/// match the container semantics (cpu 100.0 = one full core); identity
/// fields are service-shaped — overloading `ContainerResourceUsage` was
/// deliberately rejected (KTD5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ServiceResourceUsage {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Leader pid of the service's process group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default)]
    pub cpu_percent: f64,
    #[serde(default)]
    pub memory_usage_bytes: u64,
    #[serde(default)]
    pub pids_current: u64,
}

/// One retained CPU/memory time series. `key` is the service name, the full
/// container id, or `"total"`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ResourceSeries {
    pub key: String,
    #[serde(default)]
    pub kind: SeriesKind,
    /// Oldest first; points are appended on the daemon's sampling clock.
    #[serde(default)]
    pub points: Vec<HistoryPoint>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum SeriesKind {
    Service,
    Container,
    #[default]
    Total,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
pub struct HistoryPoint {
    pub t_ms: u64,
    pub cpu_percent: f64,
    pub memory_usage_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ResourceUsageTotals {
    #[serde(default)]
    pub cpu_percent: f64,
    #[serde(default)]
    pub memory_usage_bytes: u64,
    #[serde(default)]
    pub network_rx_bytes: u64,
    #[serde(default)]
    pub network_tx_bytes: u64,
    #[serde(default)]
    pub network_rx_rate_bytes_per_sec: f64,
    #[serde(default)]
    pub network_tx_rate_bytes_per_sec: f64,
    #[serde(default)]
    pub block_read_bytes: u64,
    #[serde(default)]
    pub block_write_bytes: u64,
    #[serde(default)]
    pub block_read_rate_bytes_per_sec: f64,
    #[serde(default)]
    pub block_write_rate_bytes_per_sec: f64,
    #[serde(default)]
    pub pids_current: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ContainerResourceUsage {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub portman_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_service: Option<String>,
    /// Explicit `dev.portman.project` label — groups the container with host
    /// services under one project in the UI. Absent: UI falls back to the
    /// compose project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default)]
    pub cpu_percent: f64,
    #[serde(default)]
    pub memory_usage_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit_bytes: Option<u64>,
    #[serde(default)]
    pub network_rx_bytes: u64,
    #[serde(default)]
    pub network_tx_bytes: u64,
    #[serde(default)]
    pub network_rx_rate_bytes_per_sec: f64,
    #[serde(default)]
    pub network_tx_rate_bytes_per_sec: f64,
    #[serde(default)]
    pub block_read_bytes: u64,
    #[serde(default)]
    pub block_write_bytes: u64,
    #[serde(default)]
    pub block_read_rate_bytes_per_sec: f64,
    #[serde(default)]
    pub block_write_rate_bytes_per_sec: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_current: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TldInfoWire {
    Rich(TldInfo),
    LegacyName(String),
}

fn deserialize_tld_infos<'de, D>(deserializer: D) -> Result<Vec<TldInfo>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<TldInfoWire>::deserialize(deserializer).map(|items| {
        items
            .into_iter()
            .map(|item| match item {
                TldInfoWire::Rich(info) => info,
                TldInfoWire::LegacyName(name) => TldInfo {
                    name,
                    tls_mode: TlsMode::default(),
                    entry_count: 0,
                },
            })
            .collect()
    })
}

/// Where the entry came from. Treated identically by the DNS and proxy layers.
///
/// Wire-compatible: unknown future variants deserialize to [`Source::Unknown`]
/// so a newer daemon can't break an older client's whole list parse.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", from = "String")]
pub enum Source {
    /// A route owned by the daemon itself rather than user configuration.
    /// Built-ins cannot be removed or replaced by another route source.
    Builtin,
    Container,
    Static,
    /// Derived from a supervised service's `host` + `port` declaration;
    /// appears on `portman up`, disappears on `portman down` (re-seeding any
    /// static rule that still exists for the host).
    Service,
    /// Declared by a repo config's `[egress.<name>]` block; appears on
    /// `portman up`, disappears when the block is removed. Same lifecycle as
    /// `Service`, kept distinct so tooling can tell routes with no local
    /// backend from routes with one.
    Egress,
    /// Unknown (newer daemon than this client). Preserved round-trip so a
    /// future `portman down` can still release the entry.
    Unknown,
}

impl From<String> for Source {
    fn from(s: String) -> Self {
        match s.as_str() {
            "builtin" => Source::Builtin,
            "container" => Source::Container,
            "static" => Source::Static,
            "service" => Source::Service,
            "egress" => Source::Egress,
            _ => Source::Unknown,
        }
    }
}

/// How the entry wants to be reached. Drives proxy behavior and CLI display.
///
/// Wire-compatible: unknown future variants deserialize to [`Mode::Unknown`]
/// (the proxy treats those like [`Mode::Http`] — a plain Host-routed hop —
/// which is also what an old CLI's unknown mode would mean in practice).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", from = "String")]
pub enum Mode {
    /// Default. Traffic flows through portman's HTTP proxy; the proxy routes
    /// by `Host:` header to `target`.
    #[default]
    Http,
    /// Raw TCP — fronted on a dedicated loopback address that relays to
    /// `target`. Required for Postgres, MySQL, Redis, gRPC without Host, etc.
    Tcp,
    /// Authenticated egress: the proxy rewrites the request head and attaches
    /// the credential named by [`Entry::egress`] before forwarding to an
    /// external `target`, so the caller never holds it.
    ///
    /// This is the one mode the proxy branches on beyond `Tcp`; routing
    /// otherwise stays source-agnostic.
    Egress,
    /// Unknown (newer daemon than this client). Rendered as `http` — the
    /// proxy only special-cases `Tcp` and `Egress`, so routing stays safe.
    Unknown,
}

impl From<String> for Mode {
    fn from(s: String) -> Self {
        match s.as_str() {
            "http" => Mode::Http,
            "tcp" => Mode::Tcp,
            "egress" => Mode::Egress,
            _ => Mode::Unknown,
        }
    }
}

impl Mode {
    /// Parse a `dev.portman.mode` label value or a `--tcp`-style flag.
    /// Accepts `"tcp"` (→ Tcp) and `"http"` / empty / unknown (→ Http).
    pub fn parse_label(v: Option<&str>) -> Self {
        match v.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("tcp") => Mode::Tcp,
            _ => Mode::Http,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Http => "http",
            Mode::Tcp => "tcp",
            Mode::Egress => "egress",
            Mode::Unknown => "http",
        }
    }
}

/// A fully resolved service definition, as shipped from the CLI (which parses
/// the repo's `portman.toml` / `portman.local.toml`) to the daemon. All paths
/// are absolute — the CLI resolves them against the config file's directory
/// before sending, so the daemon never guesses a working directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceDefinition {
    pub name: String,
    /// Discrete argv — no shell involved anywhere in the spawn path.
    pub run: Vec<String>,
    /// Absolute working directory for the child.
    pub dir: std::path::PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Hostname to route to `127.0.0.1:port` while the service is registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub ready: ReadyCheck,
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default)]
    pub restart: RestartPolicy,
    /// Grace period between SIGTERM and SIGKILL on stop.
    #[serde(default = "default_stop_grace_ms")]
    pub stop_grace_ms: u64,
    /// Absolute paths, applied in order (later wins) before secrets + inline env.
    #[serde(default)]
    pub env_files: Vec<std::path::PathBuf>,
    /// Inline environment — the last (winning) layer of composition.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Names of `[secrets.<name>]` provider blocks this service pulls from.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// When true, a secrets-provider failure degrades to env_files-only
    /// startup (flagged in status) instead of blocking the service.
    #[serde(default)]
    pub secrets_optional: bool,
    /// Absolute paths (or globs) whose change respawns the service. Empty
    /// means no watching — the service restarts on crash only.
    #[serde(default)]
    pub watch: Vec<std::path::PathBuf>,
    #[serde(default)]
    pub watch_mode: WatchMode,
    /// Quiet period after the last change before respawning. A rebuild writes
    /// several files; without this the service would cycle once per write.
    #[serde(default = "default_watch_debounce_ms")]
    pub watch_debounce_ms: u64,
    /// Free-form group tags for UI grouping (file-level `groups` unioned with
    /// per-service `groups`, deduped, sorted). Empty means "fall back to the
    /// config root's directory name" — the UI decides that, not the config
    /// layer, so the fallback tracks a moved checkout.
    #[serde(default)]
    pub groups: Vec<String>,
    /// File-level `project` tag: one project per config file, inherited by
    /// every service in it. `None` means the UI falls back to the config
    /// root's directory name — same contract as empty `groups`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

fn default_stop_grace_ms() -> u64 {
    5_000
}

fn default_watch_debounce_ms() -> u64 {
    500
}

/// Which filesystem-notification backend a service's `watch` paths use.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum WatchMode {
    /// Stat the paths on an interval. The default, because a watched path is
    /// usually a build output and `cargo build` replaces it by rename — a
    /// native watcher follows the old inode and silently stops firing.
    #[default]
    Poll,
    /// Kernel notifications (FSEvents on macOS, inotify on Linux). Cheaper for
    /// directory watches, and correct as long as the paths aren't replaced.
    Native,
}

/// How the supervisor decides a service is ready (gates dependents in
/// `portman up`). Resolution defaults to `Port(port)` when the service
/// declares a `port`, else `None` (ready as soon as it spawned).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReadyCheck {
    /// A TCP connect to `127.0.0.1:port` succeeds.
    Port(u16),
    /// A fixed delay after spawn.
    DelayMs(u64),
    /// No gate — ready immediately after spawn.
    #[default]
    None,
}

/// Per-service crash-restart policy. Restarts always use exponential backoff.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// Restart forever (the default).
    #[default]
    Always,
    /// Never restart — a crash lands the service in `Failed`.
    Never,
    /// Restart up to N consecutive times, then `Failed`. The counter resets
    /// once the service reaches `Ready`.
    Limit(u32),
}

/// A `[secrets.<name>]` provider block from `portman.toml`, resolved and
/// validated. Carries provider *coordinates* only — machine credentials live
/// in the daemon's credentials store, never in repo config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum SecretsProviderConfig {
    Infisical {
        /// Base URL of the instance (e.g. `https://secrets.example.com`).
        url: String,
        project_id: String,
        /// Environment slug (e.g. `dev`, `prod`).
        environment: String,
        /// Folder paths fetched in order; on duplicate keys the first path wins
        /// (matches `infisical run` semantics).
        paths: Vec<String>,
        /// Secrets API flavor: `v3` (`/api/v3/secrets/raw`, default — works on
        /// self-hosted) or `v4` (`/api/v4/secrets`).
        #[serde(default)]
        api_version: InfisicalApiVersion,
        /// `native` (reqwest, default) or `cli` (`infisical export` fallback).
        #[serde(default)]
        mode: InfisicalMode,
    },
    #[serde(rename = "1password")]
    OnePassword {
        /// Env key → `op://vault/item/field` reference.
        refs: std::collections::BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum InfisicalApiVersion {
    #[default]
    V3,
    V4,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum InfisicalMode {
    #[default]
    Native,
    Cli,
}

/// Native netbridge route ownership mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetbridgeMode {
    /// Safe default: only Portman's dedicated docker network is routed.
    #[default]
    OptIn,
    /// Route Docker bridge networks that contain Portman-labelled containers.
    Docker,
    /// Reserved explicit full-replacement mode for every Docker bridge network.
    All,
}

impl NetbridgeMode {
    /// snake_case token matching the serde wire form; used in log fields.
    pub fn as_str(self) -> &'static str {
        match self {
            NetbridgeMode::OptIn => "opt_in",
            NetbridgeMode::Docker => "docker",
            NetbridgeMode::All => "all",
        }
    }

    /// Human-facing word used by CLI, TUI, and doctor alike ("opt-in").
    pub fn display_word(self) -> &'static str {
        match self {
            NetbridgeMode::OptIn => "opt-in",
            NetbridgeMode::Docker => "docker",
            NetbridgeMode::All => "all",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_status_response_deserializes_with_safe_defaults() {
        let json = r#"{
            "kind": "status",
            "version": "0.0.1",
            "running_since": "5s",
            "dns_port": 5335
        }"#;

        let response: Response = serde_json::from_str(json).unwrap();

        match response {
            Response::Status {
                version,
                running_since,
                dns_port,
                proxy_port,
                tls_port,
                socket_path,
                data_dir,
                cert_dir,
                bridge_assessment,
                bridge_enabled,
                bridge_mode,
                dashboard_port,
            } => {
                assert_eq!(version, "0.0.1");
                assert_eq!(running_since, "5s");
                assert_eq!(dns_port, 5335);
                assert_eq!(proxy_port, 0);
                assert_eq!(tls_port, 0);
                assert!(socket_path.is_empty());
                assert!(data_dir.is_empty());
                assert!(cert_dir.is_empty());
                assert_eq!(bridge_assessment, BridgeAssessment::Unknown);
                assert!(!bridge_enabled);
                assert_eq!(bridge_mode, NetbridgeMode::OptIn);
                assert_eq!(dashboard_port, 7341);
            }
            other => panic!("expected status response, got {other:?}"),
        }
    }

    #[test]
    fn legacy_tld_string_list_deserializes_as_off_mode_infos() {
        let json = r#"{"kind":"tlds","tlds":["test","acme"]}"#;

        let response: Response = serde_json::from_str(json).unwrap();

        match response {
            Response::Tlds { tlds } => {
                assert_eq!(
                    tlds,
                    vec![
                        TldInfo {
                            name: "test".into(),
                            tls_mode: TlsMode::Off,
                            entry_count: 0,
                        },
                        TldInfo {
                            name: "acme".into(),
                            tls_mode: TlsMode::Off,
                            entry_count: 0,
                        },
                    ]
                );
            }
            other => panic!("expected tlds response, got {other:?}"),
        }
    }

    #[test]
    fn sparse_tld_info_defaults_tls_mode_and_count() {
        let json = r#"{"kind":"tlds","tlds":[{"name":"test"}]}"#;

        let response: Response = serde_json::from_str(json).unwrap();

        match response {
            Response::Tlds { tlds } => {
                assert_eq!(tlds.len(), 1);
                assert_eq!(tlds[0].name, "test");
                assert_eq!(tlds[0].tls_mode, TlsMode::Off);
                assert_eq!(tlds[0].entry_count, 0);
            }
            other => panic!("expected tlds response, got {other:?}"),
        }
    }

    #[test]
    fn add_static_without_service_field_deserializes() {
        // Older clients (and the dashboard form) don't send `service`.
        let json = r#"{"kind":"add_static","host":"a.test","target":"127.0.0.1:80"}"#;
        let request: Request = serde_json::from_str(json).unwrap();
        match request {
            Request::AddStatic { service, mode, .. } => {
                assert_eq!(service, None);
                assert_eq!(mode, Mode::Http);
            }
            other => panic!("expected add_static, got {other:?}"),
        }
    }

    #[test]
    fn unknown_source_and_mode_deserialize_lossily() {
        // A newer daemon minting `source: "quantum"` / `mode: "wormhole"`
        // must not break an older client's whole list parse — the CLAUDE.md
        // wire-compat rule: protocol enums deserialize unknown → Unknown.
        let json = r#"{
            "kind": "service_statuses",
            "services": [{
                "name": "web",
                "root": "/repo",
                "state": "ready",
                "detail": "",
                "pid": 123,
                "restarts": 0,
                "host": "web.test",
                "port": 3000,
                "desired_up": true,
                "groups": []
            }]
        }"#;
        let response: Response = serde_json::from_str(json).unwrap();
        match response {
            Response::ServiceStatuses { services } => {
                assert_eq!(services.len(), 1);
                assert_eq!(services[0].name, "web");
            }
            other => panic!("expected service_statuses, got {other:?}"),
        }

        // The Entry variant the older CLI receives on a list query.
        let json = r#"[
            {"host":"a.test","target":"127.0.0.1:80","source":"quantum","mode":"wormhole"},
            {"host":"b.test","target":"api.example.com:443","source":"egress","mode":"egress"},
            {"host":"portman.localhost","target":"127.0.0.1:7341","source":"builtin","mode":"http"}
        ]"#;
        let entries: Vec<Entry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries[0].source, Source::Unknown);
        assert_eq!(entries[0].mode, Mode::Unknown);
        assert_eq!(entries[1].source, Source::Egress);
        assert_eq!(entries[1].mode, Mode::Egress);
        assert_eq!(entries[2].source, Source::Builtin);
        assert_eq!(entries[2].mode, Mode::Http);

        // Unknown still round-trips to a concrete token (never panics the
        // serializer) — rendered as "http" so an old client's own display
        // treats it as a plain Host-routed entry.
        assert_eq!(entries[0].mode.as_str(), "http");
    }

    #[test]
    fn start_service_round_trips() {
        let json = serde_json::to_string(&Request::StartService {
            host: "db.test".into(),
        })
        .unwrap();
        assert_eq!(json, r#"{"kind":"start_service","host":"db.test"}"#);

        let response: Response = serde_json::from_str(r#"{"kind":"started"}"#).unwrap();
        match response {
            Response::Started { detail } => assert!(detail.is_empty()),
            other => panic!("expected started, got {other:?}"),
        }
    }

    #[test]
    fn logs_query_defaults_limit_and_omits_cursor() {
        // A minimal client request (no cursor, no limit) gets the defaults.
        let json = r#"{"kind":"logs_query","service":"web"}"#;
        let request: Request = serde_json::from_str(json).unwrap();
        match request {
            Request::LogsQuery {
                service,
                after_id,
                limit,
            } => {
                assert_eq!(service, "web");
                assert_eq!(after_id, None);
                assert_eq!(limit, 200);
            }
            other => panic!("expected logs_query, got {other:?}"),
        }
    }

    #[test]
    fn sync_services_round_trips_with_definition() {
        let request = Request::SyncServices {
            root: std::path::PathBuf::from("/repo"),
            services: vec![ServiceDefinition {
                name: "web".into(),
                run: vec!["bin/server".into()],
                dir: std::path::PathBuf::from("/repo"),
                port: Some(3000),
                host: Some("web.test".into()),
                mode: Mode::Http,
                ready: ReadyCheck::Port(3000),
                depends: vec!["db".into()],
                restart: RestartPolicy::Limit(3),
                stop_grace_ms: 5000,
                env_files: vec![std::path::PathBuf::from("/repo/.env")],
                env: std::collections::BTreeMap::new(),
                secrets: vec!["pacer".into()],
                secrets_optional: true,
                watch: vec![std::path::PathBuf::from("/repo/dist/server")],
                watch_mode: WatchMode::Poll,
                watch_debounce_ms: 500,
                groups: vec!["pacer".into()],
                project: None,
            }],
            secrets: std::collections::BTreeMap::from([(
                "pacer".to_string(),
                SecretsProviderConfig::Infisical {
                    url: "https://secrets.example.com".into(),
                    project_id: "pid".into(),
                    environment: "dev".into(),
                    paths: vec!["/shared".into()],
                    api_version: InfisicalApiVersion::V3,
                    mode: InfisicalMode::Native,
                },
            )]),
            egress: std::collections::BTreeMap::from([(
                "github".to_string(),
                EgressRoute {
                    host: "github.api.test".into(),
                    target: "api.github.com:443".into(),
                    spec: EgressSpec {
                        secrets: "pacer".into(),
                        key: "GITHUB_TOKEN".into(),
                        header: "Authorization".into(),
                        format: "Bearer {value}".into(),
                        upstream_host: "api.github.com".into(),
                        tls: true,
                    },
                },
            )]),
        };
        let json = serde_json::to_string(&request).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        match back {
            Request::SyncServices {
                root,
                services,
                secrets,
                egress,
            } => {
                assert_eq!(root, std::path::PathBuf::from("/repo"));
                assert_eq!(services.len(), 1);
                assert_eq!(services[0].ready, ReadyCheck::Port(3000));
                assert!(secrets.contains_key("pacer"));
                assert_eq!(egress["github"].spec.key, "GITHUB_TOKEN");
                assert!(egress["github"].spec.tls);
            }
            other => panic!("expected sync_services, got {other:?}"),
        }
    }

    #[test]
    fn sparse_service_definition_deserializes_with_defaults() {
        // A future client omitting optional fields still parses.
        let json = r#"{"name":"w","run":["cmd"],"dir":"/r"}"#;
        let def: ServiceDefinition = serde_json::from_str(json).unwrap();
        assert_eq!(def.ready, ReadyCheck::None);
        assert_eq!(def.restart, RestartPolicy::Always);
        assert_eq!(def.stop_grace_ms, 5000);
        assert!(!def.secrets_optional);
    }

    #[test]
    fn service_statuses_and_logs_responses_round_trip() {
        let response = Response::ServiceStatuses {
            services: vec![ServiceStatusInfo {
                name: "web".into(),
                root: Some("/tmp/project".into()),
                state: ServiceState::Ready,
                detail: String::new(),
                pid: Some(42),
                restarts: 1,
                host: Some("web.test".into()),
                port: Some(3000),
                desired_up: true,
                groups: vec!["pacer".into()],
                project: None,
            }],
        };
        let json = serde_json::to_string(&response).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Response::ServiceStatuses { services } if services.len() == 1));

        let logs = r#"{"kind":"logs","lines":[{"id":7,"line":"hi"}],"last_id":7}"#;
        let back: Response = serde_json::from_str(logs).unwrap();
        match back {
            Response::Logs { lines, last_id } => {
                assert_eq!(last_id, 7);
                assert_eq!(lines[0].id, 7);
                assert_eq!(lines[0].line, "hi");
                assert!(lines[0].stream.is_empty()); // sparse wire defaults
            }
            other => panic!("expected logs, got {other:?}"),
        }
    }

    #[test]
    fn resource_usage_request_serializes_with_snake_case_kind() {
        let json = serde_json::to_string(&Request::ResourceUsage).unwrap();

        assert_eq!(json, r#"{"kind":"resource_usage"}"#);
    }

    #[test]
    fn sparse_resource_usage_response_deserializes_with_empty_defaults() {
        let json = r#"{"kind":"resource_usage","snapshot":{}}"#;

        let response: Response = serde_json::from_str(json).unwrap();

        match response {
            Response::ResourceUsage { snapshot } => {
                assert_eq!(snapshot.sampled_at_unix_ms, 0);
                assert_eq!(snapshot.sample_window_ms, 0);
                assert_eq!(snapshot.container_count, 0);
                assert_eq!(snapshot.totals.cpu_percent, 0.0);
                assert!(snapshot.containers.is_empty());
                assert!(snapshot.services.is_empty());
            }
            other => panic!("expected resource_usage response, got {other:?}"),
        }
    }

    #[test]
    fn credential_request_debug_contains_no_secret_material() {
        let request = Request::SetSecretsCredentials {
            provider: "infisical".into(),
            client_id: Some("machine-id-1".into()),
            client_secret: Some(Redacted("SUPER-SECRET-VALUE".into())),
            token: Some(Redacted("OP-TOKEN-VALUE".into())),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("SUPER-SECRET-VALUE"), "{rendered}");
        assert!(!rendered.contains("OP-TOKEN-VALUE"), "{rendered}");
        assert!(rendered.contains("<redacted>"));

        // …but the wire form carries the real value (transparent serde).
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("SUPER-SECRET-VALUE"));
        let back: Request = serde_json::from_str(&json).unwrap();
        match back {
            Request::SetSecretsCredentials { client_secret, .. } => {
                assert_eq!(client_secret.unwrap().0, "SUPER-SECRET-VALUE");
            }
            other => panic!("expected credentials request, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_without_services_field_deserializes_back_compat() {
        // A snapshot serialized by a pre-services daemon.
        let json = r#"{"sampled_at_unix_ms":1,"sample_window_ms":2,"container_count":0,"totals":{},"containers":[]}"#;
        let snapshot: ResourceUsageSnapshot = serde_json::from_str(json).unwrap();
        assert!(snapshot.services.is_empty());

        let with_services = r#"{"services":[{"name":"web","cpu_percent":12.5,"memory_usage_bytes":1024,"pids_current":3}]}"#;
        let snapshot: ResourceUsageSnapshot = serde_json::from_str(with_services).unwrap();
        assert_eq!(snapshot.services.len(), 1);
        assert_eq!(snapshot.services[0].name, "web");
        assert_eq!(snapshot.services[0].pids_current, 3);
        assert_eq!(snapshot.services[0].pid, None);
    }
}
