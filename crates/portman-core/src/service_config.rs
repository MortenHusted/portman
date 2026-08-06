//! Per-repo service definitions: `portman.toml` + `portman.local.toml`.
//!
//! A repo declares host services in a committed `portman.toml`; a gitignored
//! `portman.local.toml` beside it carries personal additions and overrides.
//! The merge is **per-service, field-level**: a local `[service.<name>]`
//! patches the committed service of the same name — fields it mentions win,
//! fields it omits keep the committed value — so attaching one `env_files`
//! locally doesn't mean shadow-copying `run`/`port`/`depends` and drifting
//! when the committed definition changes. A service only the local file
//! declares stands alone and must carry `run`. Either file alone is a valid
//! config — a purely personal stack can live in `portman.local.toml` with no
//! committed file. `[secrets.<name>]` provider blocks replace wholesale:
//! provider coordinates are one atomic value.
//!
//! Parsing is strict (unknown fields are errors, naming the offending key)
//! and resolution is repo-relative: `dir` and `env_files` resolve against the
//! config file's directory, so definitions work from any clone. `watch` is the
//! exception — it resolves against the service's own `dir`, because a watched
//! path is nearly always the thing being run, and `run[0]` resolves there too.
//! The resolved output is `portman_protocol::ServiceDefinition` — the exact
//! shape the CLI ships to the daemon.
//!
//! Env files are *declared* here but parsed at compose time (see the daemon's
//! `env_compose`), so a missing file surfaces when a service starts, not when
//! the config loads.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use portman_protocol::{
    EgressRoute, EgressSpec, InfisicalApiVersion, InfisicalMode, Mode, ReadyCheck, RestartPolicy,
    SecretsProviderConfig, ServiceDefinition, WatchMode,
};
use serde::Deserialize;

use crate::static_store::{validate_host, validate_target};

/// Committed config filename, looked up by walking ancestors from the cwd.
pub const CONFIG_FILE: &str = "portman.toml";
/// Gitignored personal overlay, merged over the committed file per-service.
pub const LOCAL_CONFIG_FILE: &str = "portman.local.toml";

/// A fully parsed, merged, and validated repo config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Directory the config file(s) live in — the repo root as far as
    /// portman is concerned. All relative paths resolved against it.
    pub root: PathBuf,
    /// Resolved definitions, name-keyed. Dependency-closed and cycle-free.
    pub services: BTreeMap<String, ServiceDefinition>,
    /// Resolved `[secrets.<name>]` provider blocks.
    pub secrets: BTreeMap<String, SecretsProviderConfig>,
    /// Resolved `[egress.<name>]` routes, ready for the daemon to register.
    pub egress: BTreeMap<String, EgressRoute>,
}

/// Find the config root for `start_dir`: the nearest ancestor containing
/// `portman.toml` or `portman.local.toml`. Returns `None` if neither exists
/// anywhere up the tree.
pub fn discover_root(start_dir: &Path) -> Option<PathBuf> {
    start_dir
        .ancestors()
        .find(|dir| dir.join(CONFIG_FILE).is_file() || dir.join(LOCAL_CONFIG_FILE).is_file())
        .map(Path::to_path_buf)
}

/// Load and merge the config at `root` (a directory, as returned by
/// [`discover_root`]). At least one of the two files must exist.
pub fn load(root: &Path) -> Result<ServiceConfig> {
    let committed = read_raw(&root.join(CONFIG_FILE))?;
    let local = read_raw(&root.join(LOCAL_CONFIG_FILE))?;
    if committed.is_none() && local.is_none() {
        bail!(
            "no {CONFIG_FILE} or {LOCAL_CONFIG_FILE} in {}",
            root.display()
        );
    }

    merge_and_resolve(root, committed, local)
}

fn merge_and_resolve(
    root: &Path,
    committed: Option<RawConfig>,
    local: Option<RawConfig>,
) -> Result<ServiceConfig> {
    let mut raw = committed.unwrap_or_default();
    if let Some(local) = local {
        // Per-service *field-level* merge: a local [service.<name>] patches
        // the committed one — fields it mentions win, fields it omits keep
        // the committed value. Wholesale replacement forced local files to
        // repeat run/port/depends verbatim just to attach one env file, and
        // those shadow copies kept overriding the committed definition with
        // stale values whenever it changed. A service only the local file
        // declares stands alone (and must carry `run`). [secrets.<name>]
        // and [egress.<name>] blocks still replace wholesale — provider
        // coordinates and a route's credential attachment are each one
        // atomic value, not a set of independent knobs.
        for (name, overlay) in local.service {
            let merged = match raw.service.remove(&name) {
                Some(base) => base.merged_under(overlay),
                None => overlay,
            };
            raw.service.insert(name, merged);
        }
        raw.secrets.extend(local.secrets);
        raw.egress.extend(local.egress);
        // Scalar file-level fields: the overlay wins when it speaks.
        if local.project.is_some() {
            raw.project = local.project.clone();
        }
        // File-level groups union across both files — tags are additive, and
        // wholesale-replacing them would silently untag committed services
        // the moment a local overlay exists.
        raw.groups.extend(local.groups);
    }
    resolve(root, raw)
}

fn read_raw(path: &Path) -> Result<Option<RawConfig>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    parse_raw(&text, path).map(Some)
}

fn parse_raw(text: &str, label: &Path) -> Result<RawConfig> {
    toml::from_str(text).with_context(|| format!("parsing {}", label.display()))
}

/// As [`load`], but with the file contents supplied by the caller.
///
/// This is the validate-before-write path for editors: it runs the exact
/// merge + resolve `load` runs (and therefore what `portman up` accepts),
/// so validation cannot drift from the real thing. `None` means "this file
/// does not exist", same as on disk.
pub fn load_from_strings(
    root: &Path,
    committed: Option<&str>,
    local: Option<&str>,
) -> Result<ServiceConfig> {
    let committed = committed
        .map(|text| parse_raw(text, &root.join(CONFIG_FILE)))
        .transpose()?;
    let local = local
        .map(|text| parse_raw(text, &root.join(LOCAL_CONFIG_FILE)))
        .transpose()?;
    merge_and_resolve(root, committed, local)
}

// ---------------------------------------------------------------------------
// Raw on-disk shapes. Strict: unknown fields are parse errors so a typo'd
// key fails loudly instead of silently doing nothing.

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// File-level project tag, inherited by every service in the file.
    /// One project per config file — a project that spans repos repeats the
    /// same name in each file.
    #[serde(default)]
    project: Option<String>,
    /// File-level group tags, applied to every service in the file. Unioned
    /// with each service's own `groups` — tags are additive, so repeating one
    /// on five services is exactly the tedium this form removes.
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    service: BTreeMap<String, RawService>,
    #[serde(default)]
    secrets: BTreeMap<String, RawSecrets>,
    #[serde(default)]
    egress: BTreeMap<String, RawEgress>,
}

/// Every field is `Option` so the overlay merge can tell "not mentioned"
/// from "set to the default". `run` is only *required* once merging is done —
/// a local `[service.<name>]` that patches a committed service may omit it,
/// which is the whole point of the overlay being a patch and not a shadow
/// copy that drifts when the committed definition changes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawService {
    run: Option<RawRun>,
    /// Working directory, relative to the config file's directory (default:
    /// the config directory itself).
    dir: Option<String>,
    port: Option<u16>,
    host: Option<String>,
    mode: Option<Mode>,
    /// Readiness gate: TCP connect to this port. Defaults to `port` when the
    /// service declares one.
    ready_port: Option<u16>,
    /// Readiness gate: fixed delay after spawn. Mutually exclusive with
    /// `ready_port`.
    ready_delay_ms: Option<u64>,
    depends: Option<Vec<String>>,
    /// `true` = restart forever (default), `false` = never, N = up to N
    /// consecutive restarts then Failed.
    retry: Option<RawRetry>,
    /// Grace period between SIGTERM and SIGKILL on stop (default 5000).
    stop_grace_ms: Option<u64>,
    env_files: Option<Vec<String>>,
    env: Option<BTreeMap<String, String>>,
    secrets: Option<Vec<String>>,
    secrets_optional: Option<bool>,
    /// Paths or globs, relative to `dir`, whose change respawns the service.
    watch: Option<Vec<String>>,
    watch_mode: Option<WatchMode>,
    /// Quiet period after the last change before respawning (default 500).
    watch_debounce_ms: Option<u64>,
    /// Group tags for UI grouping, unioned with the file-level `groups`.
    groups: Option<Vec<String>>,
}

impl RawService {
    /// Lay `overlay` over `self`, field by field: a field the overlay mentions
    /// wins, a field it omits keeps the committed value.
    ///
    /// "Field by field" means whole-value-per-field, including collections:
    /// a local `env` map replaces the committed map outright (no key-level
    /// merge), same for `env_files`, `depends`, `secrets`, and service-level
    /// `groups`. Pinned by `overlay_collection_fields_replace_wholesale`;
    /// documented in the README's overlay section.
    ///
    /// The readiness pair travels together — `ready_port` and `ready_delay_ms`
    /// are two spellings of one setting, so an overlay that sets either
    /// replaces both. Without that, a local `ready_delay_ms` over a committed
    /// `ready_port` would merge into the "mutually exclusive" error.
    fn merged_under(self, overlay: RawService) -> RawService {
        let (ready_port, ready_delay_ms) =
            if overlay.ready_port.is_some() || overlay.ready_delay_ms.is_some() {
                (overlay.ready_port, overlay.ready_delay_ms)
            } else {
                (self.ready_port, self.ready_delay_ms)
            };
        RawService {
            run: overlay.run.or(self.run),
            dir: overlay.dir.or(self.dir),
            port: overlay.port.or(self.port),
            host: overlay.host.or(self.host),
            mode: overlay.mode.or(self.mode),
            ready_port,
            ready_delay_ms,
            depends: overlay.depends.or(self.depends),
            retry: overlay.retry.or(self.retry),
            stop_grace_ms: overlay.stop_grace_ms.or(self.stop_grace_ms),
            env_files: overlay.env_files.or(self.env_files),
            env: overlay.env.or(self.env),
            secrets: overlay.secrets.or(self.secrets),
            secrets_optional: overlay.secrets_optional.or(self.secrets_optional),
            watch: overlay.watch.or(self.watch),
            watch_mode: overlay.watch_mode.or(self.watch_mode),
            watch_debounce_ms: overlay.watch_debounce_ms.or(self.watch_debounce_ms),
            groups: overlay.groups.or(self.groups),
        }
    }
}

/// `run = "cmd --flag arg"` (shell-word split, no shell execution) or
/// `run = ["cmd", "--flag", "arg"]` (verbatim argv).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawRun {
    Line(String),
    Argv(Vec<String>),
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(untagged)]
enum RawRetry {
    Flag(bool),
    Limit(u32),
}

/// One `[secrets.<name>]` block. A single permissive struct (rather than a
/// serde-tagged enum) so unknown fields are still rejected with their key
/// named, and provider-mismatched fields get an actionable error.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecrets {
    provider: String,
    // infisical
    url: Option<String>,
    project_id: Option<String>,
    environment: Option<String>,
    paths: Option<Vec<String>>,
    api_version: Option<InfisicalApiVersion>,
    mode: Option<InfisicalMode>,
    // 1password
    refs: Option<BTreeMap<String, String>>,
}

/// One `[egress.<name>]` block: a local hostname the proxy answers, the
/// upstream it forwards to, and which `[secrets.*]` value it attaches.
/// Every field is required except `header`/`format` (sensible API-auth
/// defaults) and `upstream_host` (defaults to the target's hostname).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEgress {
    /// Local hostname callers address (must sit under a managed TLD).
    host: String,
    /// Upstream `host:port` the rewritten request lands at.
    target: String,
    /// `[secrets.<name>]` block the value comes from.
    secrets: String,
    /// Key within that block.
    key: String,
    /// Header carrying the credential (default `Authorization`).
    #[serde(default = "default_egress_header")]
    header: String,
    /// Header value template; `{value}` is the secret (default `Bearer {value}`).
    #[serde(default = "default_egress_format")]
    format: String,
    /// `Host:` presented to the upstream (default: the target's hostname).
    upstream_host: Option<String>,
    /// Speak TLS to the upstream (default false).
    #[serde(default)]
    tls: bool,
}

fn default_egress_header() -> String {
    "Authorization".to_string()
}

fn default_egress_format() -> String {
    "Bearer {value}".to_string()
}

// ---------------------------------------------------------------------------
// Resolution + validation.

fn resolve(root: &Path, raw: RawConfig) -> Result<ServiceConfig> {
    let secrets: BTreeMap<String, SecretsProviderConfig> = raw
        .secrets
        .into_iter()
        .map(|(name, block)| {
            let resolved =
                resolve_secrets(&name, block).with_context(|| format!("in [secrets.{name}]"))?;
            Ok((name, resolved))
        })
        .collect::<Result<_>>()?;

    for tag in &raw.groups {
        validate_group_tag(tag).context("in file-level `groups`")?;
    }
    if let Some(project) = &raw.project {
        validate_group_tag(project).context("in file-level `project`")?;
    }

    let mut services = BTreeMap::new();
    for (name, svc) in raw.service {
        validate_service_name(&name)?;
        let def = resolve_service(
            root,
            &name,
            svc,
            &secrets,
            &raw.groups,
            raw.project.as_deref(),
        )
        .with_context(|| format!("in [service.{name}]"))?;
        services.insert(name, def);
    }

    validate_depends(&services)?;

    let mut egress = BTreeMap::new();
    for (name, route) in raw.egress {
        validate_egress_name(&name)?;
        let resolved = resolve_egress(&name, route, &secrets)
            .with_context(|| format!("in [egress.{name}]"))?;
        egress.insert(name, resolved);
    }

    Ok(ServiceConfig {
        root: root.to_path_buf(),
        services,
        secrets,
        egress,
    })
}

fn resolve_service(
    root: &Path,
    name: &str,
    raw: RawService,
    secrets: &BTreeMap<String, SecretsProviderConfig>,
    file_groups: &[String],
    project: Option<&str>,
) -> Result<ServiceDefinition> {
    // Absent after merging = the local file introduced this service without
    // saying what to run. (Patching a committed service never lands here --
    // the merge keeps the committed `run`.)
    let run = match raw.run {
        Some(RawRun::Argv(argv)) => argv,
        Some(RawRun::Line(line)) => shlex::split(&line)
            .ok_or_else(|| anyhow::anyhow!("`run` has unbalanced quotes: {line}"))?,
        None => bail!(
            "`run` is required -- this service isn't in the committed portman.toml, so the local file must say what to run"
        ),
    };
    if run.is_empty() || run[0].trim().is_empty() {
        bail!("`run` must name a command");
    }

    let dir = match raw.dir {
        Some(dir) => resolve_path(root, &dir),
        None => root.to_path_buf(),
    };

    let host = raw.host.as_deref().map(validate_host).transpose()?;
    if raw.host.is_some() && raw.port.is_none() {
        bail!("`host` requires `port` — portman needs to know where to route {name}");
    }
    if let Some(port) = raw.port {
        if port == 0 {
            bail!("`port` cannot be 0");
        }
    }

    let ready = match (raw.ready_port, raw.ready_delay_ms) {
        (Some(_), Some(_)) => {
            bail!("`ready_port` and `ready_delay_ms` are mutually exclusive")
        }
        (Some(port), None) => ReadyCheck::Port(port),
        (None, Some(ms)) => ReadyCheck::DelayMs(ms),
        // Default: gate on the declared service port; no port → no gate.
        (None, None) => raw.port.map_or(ReadyCheck::None, ReadyCheck::Port),
    };

    let restart = match raw.retry {
        None | Some(RawRetry::Flag(true)) => RestartPolicy::Always,
        Some(RawRetry::Flag(false)) => RestartPolicy::Never,
        Some(RawRetry::Limit(n)) => RestartPolicy::Limit(n),
    };

    let service_secrets = raw.secrets.unwrap_or_default();
    for provider in &service_secrets {
        if !secrets.contains_key(provider) {
            bail!("`secrets` references `{provider}` but no [secrets.{provider}] block exists");
        }
    }

    if let Some(ms) = raw.watch_debounce_ms {
        if ms == 0 {
            bail!("`watch_debounce_ms` cannot be 0 — a rebuild writes several files, and no quiet period means one respawn per write");
        }
    }
    let raw_watch = raw.watch.unwrap_or_default();
    if raw_watch.is_empty() && (raw.watch_mode.is_some() || raw.watch_debounce_ms.is_some()) {
        bail!("`watch_mode`/`watch_debounce_ms` do nothing without `watch`");
    }
    // Relative to `dir`, matching how `run[0]` resolves — not to the config
    // file's directory, which is what `env_files` uses.
    let watch = raw_watch.iter().map(|w| resolve_path(&dir, w)).collect();

    let raw_groups = raw.groups.unwrap_or_default();
    for tag in &raw_groups {
        validate_group_tag(tag)?;
    }
    // File-level tags union with the service's own; BTreeSet gives dedup and
    // a stable order in one move.
    let groups: Vec<String> = file_groups
        .iter()
        .chain(raw_groups.iter())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    Ok(ServiceDefinition {
        name: name.to_string(),
        run,
        dir,
        port: raw.port,
        host,
        mode: raw.mode.unwrap_or_default(),
        ready,
        depends: raw.depends.unwrap_or_default(),
        restart,
        stop_grace_ms: raw.stop_grace_ms.unwrap_or(5_000),
        env_files: raw
            .env_files
            .unwrap_or_default()
            .iter()
            .map(|f| resolve_path(root, f))
            .collect(),
        env: raw.env.unwrap_or_default(),
        secrets: service_secrets,
        secrets_optional: raw.secrets_optional.unwrap_or(false),
        watch,
        watch_mode: raw.watch_mode.unwrap_or_default(),
        watch_debounce_ms: raw.watch_debounce_ms.unwrap_or(500),
        groups,
        project: project.map(str::to_string),
    })
}

/// Group tags land in URLs and UI labels, so keep the charset as boring as
/// service names'.
fn validate_group_tag(tag: &str) -> Result<()> {
    if tag.is_empty() || tag.len() > 64 {
        bail!("group tag `{tag}` must be 1-64 characters");
    }
    if !tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("group tag `{tag}` may only contain letters, digits, and . _ -");
    }
    Ok(())
}

fn resolve_secrets(name: &str, raw: RawSecrets) -> Result<SecretsProviderConfig> {
    match raw.provider.as_str() {
        "infisical" => {
            if raw.refs.is_some() {
                bail!("`refs` is not valid for provider `infisical`");
            }
            Ok(SecretsProviderConfig::Infisical {
                url: raw
                    .url
                    .with_context(|| format!("[secrets.{name}] requires `url`"))?,
                project_id: raw
                    .project_id
                    .with_context(|| format!("[secrets.{name}] requires `project_id`"))?,
                environment: raw
                    .environment
                    .with_context(|| format!("[secrets.{name}] requires `environment`"))?,
                paths: raw
                    .paths
                    .with_context(|| format!("[secrets.{name}] requires `paths`"))?,
                api_version: raw.api_version.unwrap_or_default(),
                mode: raw.mode.unwrap_or_default(),
            })
        }
        "1password" => {
            for (field, set) in [
                ("url", raw.url.is_some()),
                ("project_id", raw.project_id.is_some()),
                ("environment", raw.environment.is_some()),
                ("paths", raw.paths.is_some()),
                ("api_version", raw.api_version.is_some()),
                ("mode", raw.mode.is_some()),
            ] {
                if set {
                    bail!("`{field}` is not valid for provider `1password`");
                }
            }
            let refs = raw
                .refs
                .with_context(|| format!("[secrets.{name}] requires `refs`"))?;
            for (key, reference) in &refs {
                if !reference.starts_with("op://") {
                    bail!("refs.{key} must be an op:// reference, got `{reference}`");
                }
            }
            Ok(SecretsProviderConfig::OnePassword { refs })
        }
        other => bail!("unknown secrets provider `{other}` (expected `infisical` or `1password`)"),
    }
}

/// Validate and resolve one `[egress.<name>]` block. The referenced
/// secrets block must exist in the same config — an egress route naming a
/// block that isn't synced would fail only at proxy time, and "looks fine
/// until it doesn't" is exactly what config validation exists to remove.
fn resolve_egress(
    name: &str,
    raw: RawEgress,
    secrets: &BTreeMap<String, SecretsProviderConfig>,
) -> Result<EgressRoute> {
    let host = validate_host(&raw.host).with_context(|| format!("`host` in [egress.{name}]"))?;
    let target =
        validate_target(&raw.target).with_context(|| format!("`target` in [egress.{name}]"))?;
    if !secrets.contains_key(&raw.secrets) {
        bail!("references [secrets.{}] which does not exist", raw.secrets);
    }
    if raw.key.trim().is_empty() {
        bail!("`key` cannot be empty");
    }
    if !raw.format.contains("{value}") {
        bail!("`format` must contain the `{{value}}` placeholder");
    }
    // A header line is a single line: any CR/LF the config could inject would
    // let the credential header smuggle extra lines (or end the head early).
    // Same for the header NAME — it must be a bare RFC 7230 token, or the
    // rendered line could carry arbitrary bytes.
    if raw.header.contains(['\r', '\n']) || !is_rfc7230_token(&raw.header) {
        bail!("`header` must be a single HTTP token (no whitespace, no CR/LF)");
    }
    if raw.format.contains(['\r', '\n']) {
        bail!("`format` cannot contain CR/LF — it is rendered into a header line");
    }
    if let Some(h) = raw.upstream_host.as_deref() {
        if h.contains(['\r', '\n']) {
            bail!("`upstream_host` cannot contain CR/LF");
        }
    }
    let upstream_host = match raw.upstream_host {
        Some(h) if !h.trim().is_empty() => h,
        Some(_) => bail!("`upstream_host` cannot be blank"),
        // Default: the target's hostname — the usual case where the
        // upstream's Host and its network address agree.
        None => target
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| target.clone()),
    };
    // The credential rides in a header line written into the TCP stream to
    // `target`. Over a non-loopback target it crosses a real network
    // boundary in cleartext — require TLS unless the target is the local
    // machine, the one case where there is no wire to eavesdrop on.
    let target_host = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(&target);
    if !raw.tls && !is_loopback_host(target_host) {
        bail!(
            "`tls = true` is required: target `{target_host}` is not the local \
             machine, and an egress credential must not cross the network in cleartext"
        );
    }
    Ok(EgressRoute {
        host,
        target,
        spec: EgressSpec {
            secrets: raw.secrets,
            key: raw.key,
            header: raw.header,
            format: raw.format,
            upstream_host,
            tls: raw.tls,
        },
    })
}

/// RFC 7230 `token`: `!#$%&'*+-.^_`|~` plus alphanumerics — the only charset
/// a header name may use.
fn is_rfc7230_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
}

/// Is `host` (a hostname or IP literal) the local machine? Loopback
/// addresses and the `localhost` name. Used to decide whether an egress
/// route may ship its credential in cleartext.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim().trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost") || {
        host.parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    }
}

/// Egress route names appear in the same places service names do — same
/// boring charset.
fn validate_egress_name(name: &str) -> Result<()> {
    validate_service_name(name)
}

/// Service names appear in CLI args, log queries, and dashboard URL paths —
/// keep the charset boring.
fn validate_service_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        bail!("service name `{name}` must be 1-64 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("service name `{name}` may only contain letters, digits, and . _ -");
    }
    Ok(())
}

/// Every `depends` entry must name a known service, and the graph must be
/// acyclic. Cycles are reported with their members so the fix is obvious.
fn validate_depends(services: &BTreeMap<String, ServiceDefinition>) -> Result<()> {
    for (name, def) in services {
        for dep in &def.depends {
            if !services.contains_key(dep) {
                bail!("[service.{name}] depends on unknown service `{dep}`");
            }
        }
    }

    // Iterative DFS with an explicit path so a cycle reports its members.
    let mut done: BTreeSet<&str> = BTreeSet::new();
    for start in services.keys() {
        if done.contains(start.as_str()) {
            continue;
        }
        let mut path: Vec<&str> = Vec::new();
        let mut stack: Vec<(&str, usize)> = vec![(start, 0)];
        while let Some((name, next_dep)) = stack.pop() {
            if next_dep == 0 {
                if let Some(pos) = path.iter().position(|p| *p == name) {
                    let cycle = path[pos..].join(" -> ");
                    bail!("dependency cycle: {cycle} -> {name}");
                }
                if done.contains(name) {
                    continue;
                }
                path.push(name);
            }
            let deps = &services[name].depends;
            if next_dep < deps.len() {
                stack.push((name, next_dep + 1));
                stack.push((deps[next_dep].as_str(), 0));
            } else {
                path.pop();
                done.insert(name);
            }
        }
    }
    Ok(())
}

fn resolve_path(root: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_config(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn committed_only_parse_round_trips_all_fields() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "bin/server --config 'conf/dev.toml'"
            dir = "app"
            port = 3000
            host = "web.test"
            mode = "http"
            ready_port = 3001
            depends = ["db"]
            retry = 5
            stop_grace_ms = 2000
            env_files = ["deploy/base.env", "/abs/local.env"]
            env = { RAILS_ENV = "development" }
            secrets = ["pacer"]
            secrets_optional = true

            [service.db]
            run = ["postgres", "-D", "data"]
            port = 5432
            mode = "tcp"

            [secrets.pacer]
            provider = "infisical"
            url = "https://secrets.example.com"
            project_id = "48bb04cb"
            environment = "dev"
            paths = ["/apps/demo", "/shared"]
            "#,
        );

        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.root, dir.path());
        let web = &cfg.services["web"];
        assert_eq!(web.run, vec!["bin/server", "--config", "conf/dev.toml"]);
        assert_eq!(web.dir, dir.path().join("app"));
        assert_eq!(web.port, Some(3000));
        assert_eq!(web.host.as_deref(), Some("web.test"));
        assert_eq!(web.mode, Mode::Http);
        assert_eq!(web.ready, ReadyCheck::Port(3001));
        assert_eq!(web.depends, vec!["db"]);
        assert_eq!(web.restart, RestartPolicy::Limit(5));
        assert_eq!(web.stop_grace_ms, 2000);
        assert_eq!(
            web.env_files,
            vec![
                dir.path().join("deploy/base.env"),
                PathBuf::from("/abs/local.env"),
            ]
        );
        assert_eq!(web.env["RAILS_ENV"], "development");
        assert_eq!(web.secrets, vec!["pacer"]);
        assert!(web.secrets_optional);

        let db = &cfg.services["db"];
        assert_eq!(db.run, vec!["postgres", "-D", "data"]);
        assert_eq!(db.mode, Mode::Tcp);
        // No explicit ready gate → defaults to the declared port.
        assert_eq!(db.ready, ReadyCheck::Port(5432));
        assert_eq!(db.restart, RestartPolicy::Always);
        assert_eq!(db.stop_grace_ms, 5000);
        assert_eq!(db.dir, dir.path());

        match &cfg.secrets["pacer"] {
            SecretsProviderConfig::Infisical {
                url,
                project_id,
                environment,
                paths,
                api_version,
                mode,
            } => {
                assert_eq!(url, "https://secrets.example.com");
                assert_eq!(project_id, "48bb04cb");
                assert_eq!(environment, "dev");
                assert_eq!(paths, &vec!["/apps/demo".to_string(), "/shared".into()]);
                assert_eq!(*api_version, InfisicalApiVersion::V3);
                assert_eq!(*mode, InfisicalMode::Native);
            }
            other => panic!("expected infisical, got {other:?}"),
        }
    }

    #[test]
    fn local_overlay_patches_and_adds() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "old-cmd"
            port = 3000
            env = { KEEP = "yes" }
            "#,
        );
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            [service.web]
            run = "new-cmd"

            [service.extra]
            run = "extra-cmd"
            "#,
        );

        let cfg = load(dir.path()).unwrap();
        let web = &cfg.services["web"];
        // Field-level patch: the overlay's run wins, everything else survives.
        // (This used to assert wholesale replacement — deliberately inverted
        // when the merge became a patch.)
        assert_eq!(web.run, vec!["new-cmd"]);
        assert_eq!(web.port, Some(3000));
        assert_eq!(web.env.get("KEEP").map(String::as_str), Some("yes"));
        assert!(cfg.services.contains_key("extra"));
    }

    #[test]
    fn overlay_collection_fields_replace_wholesale() {
        // Pins the decided semantics: the patch is per *field*, so a
        // collection field the overlay mentions replaces the committed value
        // outright — a local `env` does not key-merge into the committed map.
        // Changing this to a deep merge is a behavior break; update the
        // README's overlay section if you ever do.
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "cmd"
            env = { COMMITTED = "yes", SHARED = "committed" }
            env_files = [".env.committed"]
            groups = ["committed-group"]
            "#,
        );
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            [service.web]
            env = { SHARED = "local", LOCAL_ONLY = "yes" }
            "#,
        );

        let cfg = load(dir.path()).unwrap();
        let web = &cfg.services["web"];
        // The overlay's env map is the whole story now.
        assert_eq!(web.env.get("SHARED").map(String::as_str), Some("local"));
        assert_eq!(web.env.get("LOCAL_ONLY").map(String::as_str), Some("yes"));
        assert!(
            !web.env.contains_key("COMMITTED"),
            "a mentioned collection field must replace, not key-merge"
        );
        // Unmentioned collection fields keep the committed value untouched
        // (env_files resolve to absolute paths under the config root).
        assert_eq!(web.env_files, vec![dir.path().join(".env.committed")]);
        assert_eq!(web.groups, vec!["committed-group".to_string()]);
    }

    #[test]
    fn file_level_project_inherits_and_local_overrides() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            project = "acme"
            [service.web]
            run = "cmd"
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.services["web"].project.as_deref(), Some("acme"));

        // The overlay's project wins wholesale, like every scalar field.
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            project = "acme-dev"
            [service.extra]
            run = "cmd2"
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.services["web"].project.as_deref(), Some("acme-dev"));
        assert_eq!(cfg.services["extra"].project.as_deref(), Some("acme-dev"));
    }

    #[test]
    fn project_tag_is_validated_like_group_tags() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            project = "bad name!"
            [service.web]
            run = "cmd"
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(
            err.contains("project"),
            "error should name the field: {err}"
        );
    }

    #[test]
    fn local_only_config_is_valid() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            [service.personal]
            run = "cmd"
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        assert!(cfg.services.contains_key("personal"));
    }

    #[test]
    fn missing_both_files_is_an_error() {
        let dir = tempdir().unwrap();
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("portman.toml"));
    }

    #[test]
    fn unknown_field_rejected_with_key_named() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "cmd"
            portt = 3000
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("portt"), "error should name the key: {err}");
    }

    #[test]
    fn missing_run_rejected() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            port = 3000
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("run"), "error should name `run`: {err}");
    }

    #[test]
    fn unknown_depends_rejected() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "cmd"
            depends = ["ghost"]
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("ghost"));
        assert!(err.contains("web"));
    }

    #[test]
    fn depends_cycle_rejected_with_members_named() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.a]
            run = "cmd"
            depends = ["b"]

            [service.b]
            run = "cmd"
            depends = ["c"]

            [service.c]
            run = "cmd"
            depends = ["a"]
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("cycle"), "{err}");
        for member in ["a", "b", "c"] {
            assert!(err.contains(member), "cycle should name `{member}`: {err}");
        }
    }

    #[test]
    fn diamond_depends_is_not_a_cycle() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.a]
            run = "cmd"

            [service.b]
            run = "cmd"
            depends = ["a"]

            [service.c]
            run = "cmd"
            depends = ["a"]

            [service.d]
            run = "cmd"
            depends = ["b", "c"]
            "#,
        );
        assert!(load(dir.path()).is_ok());
    }

    #[test]
    fn ready_port_and_delay_are_mutually_exclusive() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "cmd"
            ready_port = 3000
            ready_delay_ms = 500
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn host_requires_port() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "cmd"
            host = "web.test"
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("port"));
    }

    #[test]
    fn watch_paths_resolve_against_the_service_dir() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.builder]
            run = "cmd"
            dir = "sub"
            watch = ["dist/bin/thing", "config/*.toml"]
            watch_mode = "native"
            watch_debounce_ms = 250
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        let svc = &cfg.services["builder"];
        assert_eq!(
            svc.watch,
            vec![
                dir.path().join("sub/dist/bin/thing"),
                dir.path().join("sub/config/*.toml"),
            ]
        );
        assert_eq!(svc.watch_mode, WatchMode::Native);
        assert_eq!(svc.watch_debounce_ms, 250);
    }

    #[test]
    fn watch_defaults_to_polling_with_no_paths() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "cmd"
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        let svc = &cfg.services["web"];
        assert!(svc.watch.is_empty());
        assert_eq!(svc.watch_mode, WatchMode::Poll);
        assert_eq!(svc.watch_debounce_ms, 500);
    }

    #[test]
    fn watch_knobs_without_watch_paths_are_rejected() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "cmd"
            watch_mode = "native"
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("without `watch`"), "{err}");
    }

    #[test]
    fn zero_watch_debounce_is_rejected() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "cmd"
            watch = ["x"]
            watch_debounce_ms = 0
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("watch_debounce_ms"), "{err}");
    }

    #[test]
    fn load_from_strings_matches_load_exactly() {
        // The editor's validate path must accept and reject exactly what
        // `portman up` does — same merge, same resolve, same errors.
        let dir = tempdir().unwrap();
        let committed = r#"
            [service.web]
            run = ["bin/server"]
            port = 3050
        "#;
        let local = r#"
            [service.web]
            env_files = [".env"]
        "#;
        write_config(dir.path(), CONFIG_FILE, committed);
        write_config(dir.path(), LOCAL_CONFIG_FILE, local);

        let from_disk = load(dir.path()).unwrap();
        let from_strings = load_from_strings(dir.path(), Some(committed), Some(local)).unwrap();
        assert_eq!(from_disk, from_strings);

        // And a broken buffer errors with the file named, before any disk IO.
        let err = format!(
            "{:?}",
            load_from_strings(dir.path(), Some(committed), Some("host = \"x\"o")).unwrap_err()
        );
        assert!(err.contains(LOCAL_CONFIG_FILE), "{err}");
    }

    #[test]
    fn local_overlay_patches_fields_without_repeating_the_definition() {
        // The motivating papercut: attaching one env file used to demand a shadow
        // copy of run/port/host/depends, which then drifted whenever the
        // committed definition changed.
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = ["bin/server"]
            port = 3050
            host = "app.acme.internal"
            depends = ["db"]

            [service.db]
            run = ["postgres"]
            port = 5432
            "#,
        );
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            [service.web]
            env_files = [".env"]
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        let web = &cfg.services["web"];
        // The patch took…
        assert_eq!(web.env_files, vec![dir.path().join(".env")]);
        // …and everything the overlay didn't mention survived.
        assert_eq!(web.run, vec!["bin/server"]);
        assert_eq!(web.port, Some(3050));
        assert_eq!(web.host.as_deref(), Some("app.acme.internal"));
        assert_eq!(web.depends, vec!["db"]);
    }

    #[test]
    fn overlay_fields_win_over_committed_ones() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = ["bin/server"]
            port = 3050
            "#,
        );
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            [service.web]
            port = 3081
            "#,
        );
        let web = &load(dir.path()).unwrap().services["web"];
        assert_eq!(web.port, Some(3081));
        assert_eq!(web.run, vec!["bin/server"]);
    }

    #[test]
    fn overlay_readiness_replaces_the_committed_pair_not_merges_into_it() {
        // ready_port and ready_delay_ms are two spellings of one setting; a
        // field-by-field merge of the pair would trip the mutual-exclusion
        // error on a perfectly reasonable overlay.
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = ["bin/server"]
            ready_port = 3050
            "#,
        );
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            [service.web]
            ready_delay_ms = 250
            "#,
        );
        let web = &load(dir.path()).unwrap().services["web"];
        assert_eq!(web.ready, ReadyCheck::DelayMs(250));
    }

    #[test]
    fn a_local_only_service_still_requires_run() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            [service.mystery]
            port = 3000
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("`run` is required"), "{err}");
    }

    #[test]
    fn file_level_groups_union_with_service_groups_and_dedup() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            groups = ["pacer"]

            [service.web]
            run = "cmd"
            groups = ["pacer", "frontline"]

            [service.db]
            run = "cmd"
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.services["web"].groups, vec!["frontline", "pacer"]);
        // Untagged service still inherits the file-level tag; falling back to
        // the repo directory name is the UI's job and only kicks in when this
        // list is empty.
        assert_eq!(cfg.services["db"].groups, vec!["pacer"]);
    }

    #[test]
    fn local_overlay_file_groups_add_rather_than_replace() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            groups = ["pacer"]
            [service.web]
            run = "cmd"
            "#,
        );
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            groups = ["local-only"]
            [service.extra]
            run = "cmd"
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        // Wholesale-replacing file-level tags would silently untag committed
        // services the moment a local overlay exists — they union instead.
        assert_eq!(cfg.services["web"].groups, vec!["local-only", "pacer"]);
        assert_eq!(cfg.services["extra"].groups, vec!["local-only", "pacer"]);
    }

    #[test]
    fn group_tags_keep_a_boring_charset() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "cmd"
            groups = ["has space"]
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("group tag"), "{err}");
    }

    #[test]
    fn retry_flag_and_limit_forms() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.forever]
            run = "cmd"

            [service.never]
            run = "cmd"
            retry = false

            [service.bounded]
            run = "cmd"
            retry = 3
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.services["forever"].restart, RestartPolicy::Always);
        assert_eq!(cfg.services["never"].restart, RestartPolicy::Never);
        assert_eq!(cfg.services["bounded"].restart, RestartPolicy::Limit(3));
    }

    #[test]
    fn unknown_secrets_ref_rejected() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service.web]
            run = "cmd"
            secrets = ["nope"]
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("nope"));
    }

    #[test]
    fn onepassword_block_validates_refs_and_rejects_foreign_fields() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [secrets.op]
            provider = "1password"
            [secrets.op.refs]
            API_KEY = "op://dev/openrouter/api-key"
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        match &cfg.secrets["op"] {
            SecretsProviderConfig::OnePassword { refs } => {
                assert_eq!(refs["API_KEY"], "op://dev/openrouter/api-key");
            }
            other => panic!("expected 1password, got {other:?}"),
        }

        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [secrets.op]
            provider = "1password"
            paths = ["/nope"]
            [secrets.op.refs]
            API_KEY = "op://dev/x/y"
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("paths"), "{err}");

        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [secrets.op]
            provider = "1password"
            [secrets.op.refs]
            API_KEY = "not-a-ref"
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("op://"), "{err}");
    }

    #[test]
    fn infisical_requires_coordinates() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [secrets.pacer]
            provider = "infisical"
            url = "https://secrets.example.com"
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("project_id"), "{err}");
    }

    #[test]
    fn unknown_provider_rejected() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [secrets.x]
            provider = "vault"
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("vault"));
    }

    #[test]
    fn service_name_charset_enforced() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [service."bad name"]
            run = "cmd"
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("bad name"));
    }

    #[test]
    fn discover_walks_ancestors() {
        let dir = tempdir().unwrap();
        write_config(dir.path(), CONFIG_FILE, "");
        let nested = dir.path().join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(discover_root(&nested), Some(dir.path().to_path_buf()));

        let elsewhere = tempdir().unwrap();
        assert_eq!(discover_root(elsewhere.path()), None);
    }

    #[test]
    fn discover_finds_local_only_root() {
        let dir = tempdir().unwrap();
        write_config(dir.path(), LOCAL_CONFIG_FILE, "");
        assert_eq!(discover_root(dir.path()), Some(dir.path().to_path_buf()));
    }

    /// A real-world process-manager config, hand-translated:
    /// proves the vocabulary covers the pilot stack (U1 verification).
    #[test]
    fn full_stack_config_translates() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            [service.demo-rs-sublog]
            run = "../sublog-rs/target/release/sublog-rs --config local/demo-rs.acme.internal/config/sublogger.toml"
            port = 3065
            env_files = ["deploy/base.env", "local/.env"]
            secrets = ["pacer"]
            secrets_optional = true

            [service.demo-rs-logrelay]
            run = "dist/bin/logrelay --config local/demo-rs.acme.internal/config/logrelay.toml --admin-socket local/demo-rs.acme.internal/data/logrelay/admin.sock"
            port = 3066
            depends = ["demo-rs-sublog"]
            env_files = ["deploy/base.env", "local/.env"]
            secrets = ["pacer"]
            secrets_optional = true

            [service.demo-rs-proxy]
            run = "dist/bin/pacer_proxy --config local/demo-rs.acme.internal/config/pacer_proxy.toml"
            port = 3062
            host = "demo-rs.acme.internal"
            depends = ["demo-rs-logrelay", "demo-rs-sublog"]
            env_files = ["deploy/base.env", "local/.env"]
            secrets = ["pacer"]
            secrets_optional = true

            [secrets.pacer]
            provider = "infisical"
            url = "https://secrets.example.com"
            project_id = "48bb04cb-36ae-4892-b31e-327373382ee0"
            environment = "dev"
            paths = ["/apps/demo", "/shared", "/vendors/openrouter"]
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.services.len(), 3);
        let proxy = &cfg.services["demo-rs-proxy"];
        assert_eq!(proxy.host.as_deref(), Some("demo-rs.acme.internal"));
        assert_eq!(proxy.ready, ReadyCheck::Port(3062));
        assert_eq!(proxy.depends, vec!["demo-rs-logrelay", "demo-rs-sublog"]);
    }

    /// The `[egress.*]` block in its full form: every field lands where the
    /// daemon expects it, and the two optional knobs (`tls`, explicit
    /// `upstream_host`) take effect.
    #[test]
    fn egress_block_resolves_with_defaults_and_overrides() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [secrets.gh]
            provider = "1password"
            [secrets.gh.refs]
            TOKEN = "op://dev/github/token"

            [egress.github]
            host = "github.api.test"
            target = "api.github.com:443"
            secrets = "gh"
            key = "TOKEN"
            tls = true

            [egress.local]
            host = "local.api.test"
            target = "127.0.0.1:9999"
            secrets = "gh"
            key = "TOKEN"
            header = "X-Api-Key"
            format = "{value}"
            upstream_host = "internal.upstream"
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.egress.len(), 2);

        let github = &cfg.egress["github"];
        assert_eq!(github.host, "github.api.test");
        assert_eq!(github.target, "api.github.com:443");
        assert_eq!(github.spec.secrets, "gh");
        assert_eq!(github.spec.key, "TOKEN");
        // Defaults: Authorization / Bearer / hostname of the target / no TLS.
        assert_eq!(github.spec.header, "Authorization");
        assert_eq!(github.spec.format, "Bearer {value}");
        assert_eq!(github.spec.upstream_host, "api.github.com");
        assert!(github.spec.tls);

        let local = &cfg.egress["local"];
        assert_eq!(local.spec.header, "X-Api-Key");
        assert_eq!(local.spec.format, "{value}");
        assert_eq!(local.spec.upstream_host, "internal.upstream");
        assert!(!local.spec.tls);
    }

    /// An egress route naming a secrets block that isn't in the config
    /// fails at load time with the block named — not at proxy time with a
    /// 502 the user then has to chase.
    #[test]
    fn egress_referencing_missing_secrets_block_rejected() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [egress.github]
            host = "github.api.test"
            target = "api.github.com:443"
            secrets = "nope"
            key = "TOKEN"
            "#,
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("[secrets.nope]"), "{err}");
        assert!(err.contains("does not exist"), "{err}");
    }

    /// Strict parsing: a typo'd field names the key; a missing required
    /// field names the block; a `format` without `{value}` is rejected
    /// (rendering it would produce a constant header with no secret in it —
    /// a route that looks configured while sending nothing).
    #[test]
    fn egress_block_validation_rejects_malformed_blocks() {
        let dir = tempdir().unwrap();
        let base = r#"
            [secrets.gh]
            provider = "1password"
            [secrets.gh.refs]
            TOKEN = "op://dev/github/token"
        "#;

        write_config(
            dir.path(),
            CONFIG_FILE,
            &format!(
                "{base}
                [egress.g]
                host = \"g.test\"
                target = \"api.example.com:443\"
                secrets = \"gh\"
                key = \"TOKEN\"
                upstrem_host = \"oops\"
                "
            ),
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("upstrem_host"), "{err}");

        write_config(
            dir.path(),
            CONFIG_FILE,
            &format!(
                "{base}
                [egress.g]
                host = \"g.test\"
                secrets = \"gh\"
                key = \"TOKEN\"
                "
            ),
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("target"), "{err}");

        write_config(
            dir.path(),
            CONFIG_FILE,
            &format!(
                "{base}
                [egress.g]
                host = \"g.test\"
                target = \"api.example.com:443\"
                secrets = \"gh\"
                key = \"TOKEN\"
                format = \"Bearer constant\"
                "
            ),
        );
        let err = format!("{:?}", load(dir.path()).unwrap_err());
        assert!(err.contains("value"), "{err}");
    }

    /// A local `[egress.*]` overlay merges wholesale with committed
    /// egress blocks, exactly like `[secrets.*]`: same name = the local
    /// block replaces the committed one; new names stand alone.
    #[test]
    fn egress_overlay_replaces_wholesale() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            CONFIG_FILE,
            r#"
            [secrets.gh]
            provider = "1password"
            [secrets.gh.refs]
            TOKEN = "op://dev/github/token"

            [egress.github]
            host = "github.api.test"
            target = "api.github.com:443"
            secrets = "gh"
            key = "TOKEN"
            tls = true
            "#,
        );
        write_config(
            dir.path(),
            LOCAL_CONFIG_FILE,
            r#"
            [egress.github]
            host = "github.api.test"
            target = "127.0.0.1:1"
            secrets = "gh"
            key = "TOKEN"

            [egress.extra]
            host = "extra.api.test"
            target = "extra.example.com:443"
            secrets = "gh"
            key = "TOKEN"
            tls = true
            "#,
        );
        let cfg = load(dir.path()).unwrap();
        assert_eq!(cfg.egress.len(), 2);
        assert_eq!(cfg.egress["github"].target, "127.0.0.1:1");
        assert!(cfg.egress.contains_key("extra"));
    }
}
