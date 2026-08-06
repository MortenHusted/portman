//! `portman` — CLI client for the daemon.
//!
//! Phase 5: `tld` subcommands manage `/etc/resolver/<tld>` files via sudo
//! and notify the daemon so it accepts entries under the new TLD.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod client;
mod cmd;
mod doctor;
mod fmt;
mod tui;

use client::request;
use cmd::bridge::{cmd_bridge, cmd_bridge_mode, cmd_bridge_prepare, cmd_bridge_status, cmd_doctor};
use cmd::install::{cmd_install, cmd_uninstall};
use cmd::secrets::{cmd_secrets_set_infisical, cmd_secrets_set_op};
use cmd::services::{cmd_down, cmd_logs, cmd_status, cmd_up};
use cmd::tld::{cmd_tld_add, cmd_tld_list, cmd_tld_remove};
use fmt::{format_bytes, format_rate, open_browser, truncate};
use portman_core::paths::DEFAULT_DASHBOARD_PORT;
use portman_protocol::{
    ContainerResourceUsage, Entry, Mode, Request, ResourceUsageSnapshot, Response, Source,
};

#[derive(Parser)]
#[command(
    name = "portman",
    version,
    about = "Local dev DNS + HTTP proxy for macOS and Linux"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// List all registered hostnames (container-labelled and static).
    List,
    /// Add a static host rule mapping a hostname to an `ip:port`.
    ///
    /// Default mode is HTTP (routed through portman's `:80`/`:443` proxy by
    /// `Host:` header). Pass `--tcp` for raw TCP — DNS resolves to the target
    /// IP and clients connect directly, which is what Postgres, MySQL, Redis,
    /// and other non-HTTP protocols need.
    Add {
        /// Hostname to route, under a managed TLD (e.g. `crm.test`).
        host: String,
        /// Where to send it, as `ip:port` (e.g. `127.0.0.1:3000`).
        target: String,
        /// Raw TCP mode. DNS returns the target IP verbatim; portman stays out
        /// of the data path. Use for Postgres, MySQL, Redis, etc.
        #[arg(long)]
        tcp: bool,
        /// Service-runner mapping for `portman start` and the 502 page's
        /// Start button — a pitchfork daemon id like `acme/web`.
        #[arg(long, value_name = "ID")]
        service: Option<String>,
        /// Project tag for dashboard grouping/filtering (e.g. `acme`).
        #[arg(long, value_name = "NAME")]
        project: Option<String>,
    },
    /// Remove a static host rule.
    Remove {
        /// Hostname whose rule to drop.
        host: String,
    },
    /// Start the service behind a hostname.
    ///
    /// Resolves in order: its native portman.toml service, its pitchfork
    /// service (static rules added with `--service`), or its labelled Docker
    /// container.
    Start {
        /// Hostname whose backing service to start.
        host: String,
    },
    /// Start the services declared in this repo's portman.toml.
    ///
    /// Walks up from the cwd; portman.local.toml merges over portman.toml.
    /// Syncs the parsed config into the daemon, starts in dependency order,
    /// and waits for readiness. Pass names to start a subset — dependencies
    /// come along.
    Up {
        /// Services to start. Omit for every service the repo declares.
        #[arg(value_name = "SERVICE")]
        names: Vec<String>,
    },
    /// Stop supervised services.
    ///
    /// With no names, stops every service declared in this repo's
    /// portman.toml — or everything, when run outside a repo.
    Down {
        /// Services to stop. Omit for every service the repo declares.
        #[arg(value_name = "SERVICE")]
        names: Vec<String>,
        /// Stop and remove every service definition owned by this repo root.
        #[arg(long, conflicts_with = "names")]
        forget: bool,
        /// Explicit synced root to forget, even if its config no longer exists.
        #[arg(
            long,
            value_name = "PATH",
            requires = "forget",
            conflicts_with = "names"
        )]
        root: Option<std::path::PathBuf>,
    },
    /// Show captured output of a supervised service.
    Logs {
        /// Service name, as declared in portman.toml.
        service: String,
        /// Keep polling for new lines (like `tail -f`).
        #[arg(short, long)]
        follow: bool,
        /// How many recent lines to show initially.
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: u32,
    },
    /// Daemon status and version.
    Status {
        /// Show only services declared by this repo's Portman config.
        #[arg(long)]
        repo: bool,
    },
    /// Certificate subsystem diagnostics from the daemon.
    CertHealth,
    /// Show per-container CPU, memory, network, and IO usage.
    #[command(alias = "stats")]
    Resources,
    /// Diagnose install, bridge, Docker route, and legacy bridge readiness.
    Doctor,
    /// Manage TLDs routed through portman via `/etc/resolver/`.
    Tld {
        #[command(subcommand)]
        action: TldAction,
    },
    /// Store machine credentials for secrets providers.
    ///
    /// Credentials live 0600 in the daemon's data dir — never in repo config,
    /// never in a service's environment beyond the declared keys.
    Secrets {
        #[command(subcommand)]
        action: SecretsAction,
    },
    /// Install system service so portman starts on boot. Requires sudo.
    Install,
    /// Remove system service. Requires sudo for the system daemon.
    Uninstall,
    /// Open the embedded web dashboard in your browser.
    Dashboard,
    /// Launch the terminal UI (same as running `portman` with no args).
    Tui,
    /// Control the v1 Rust netbridge.
    ///
    /// Owns the docker network `portman`, routed via portman-netbridge's
    /// WireGuard tunnel, and runs in parallel to the wrapped chipmk bridge.
    /// Default mode only affects containers that opt in by attaching to the
    /// `portman` network; docker mode routes Portman-labelled containers on
    /// existing bridge networks.
    Bridge {
        #[command(subcommand)]
        action: BridgeAction,
    },
}

#[derive(Subcommand)]
enum BridgeAction {
    /// Print bridge health and netbridge enabled state.
    Status,
    /// Diagnose netbridge replacement readiness without mutating services.
    Doctor,
    /// Build the VM-side netbridge setup image from this checkout.
    Prepare,
    /// Bring the netbridge up. Persists across daemon restarts.
    Enable,
    /// Take the netbridge down. Persists across daemon restarts.
    Disable,
    /// Show or set route ownership mode: opt-in, docker, or all.
    Mode {
        /// New mode: `opt-in`, `docker`, or `all`. Omit to print the current one.
        #[arg(value_name = "MODE")]
        mode: Option<String>,
    },
}

#[derive(Subcommand)]
enum SecretsAction {
    /// Store an Infisical universal-auth machine identity.
    ///
    /// Kills the per-directory `infisical login`.
    SetInfisical {
        #[arg(long, value_name = "ID")]
        client_id: String,
        /// Omit to read the secret from stdin (keeps it out of shell history).
        #[arg(long, value_name = "SECRET")]
        client_secret: Option<String>,
    },
    /// Store a 1Password service-account token.
    ///
    /// The documented headless path — no desktop-app or biometric dependency.
    SetOp {
        /// Omit to read the token from stdin.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
enum TldAction {
    /// List TLDs portman currently manages.
    ///
    /// These are the files in /etc/resolver/ carrying portman's marker.
    List,
    /// Write /etc/resolver/<tld> pointing at portman's DNS. Requires sudo.
    Add {
        /// TLD to manage, without the leading dot (e.g. `test`).
        tld: String,
        /// TLS mode for this TLD. `mkcert` generates per-host certs using
        /// your local mkcert root CA. Use `off` to disable TLS on an existing
        /// TLD; omitting the flag preserves existing mode and defaults new TLDs
        /// to HTTP only.
        #[arg(long, value_name = "MODE")]
        tls: Option<String>,
    },
    /// Remove /etc/resolver/<tld> (only if we wrote it). Requires sudo.
    Remove {
        /// TLD to stop managing, without the leading dot.
        tld: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // `portman status | head` closes stdout early; the default panic on the
    // resulting broken-pipe write is noise, not an error. The workspace
    // forbids unsafe (no SIGPIPE reset), so exit quietly from the hook.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let broken_pipe = info
            .payload()
            .downcast_ref::<String>()
            .map(|s| s.contains("Broken pipe"))
            .unwrap_or(false);
        if broken_pipe {
            std::process::exit(0);
        }
        default_hook(info);
    }));

    let cli = Cli::parse();
    let Some(command) = cli.command else {
        // Bare `portman` launches the TUI. This is the primary surface.
        return tui::run().await;
    };
    match command {
        Command::List => cmd_list().await,
        Command::Status { repo } => cmd_status(repo).await,
        Command::CertHealth => cmd_cert_health().await,
        Command::Resources => cmd_resources().await,
        Command::Doctor => cmd_doctor().await,
        Command::Add {
            host,
            target,
            tcp,
            service,
            project,
        } => cmd_add(host, target, tcp, service, project).await,
        Command::Remove { host } => cmd_remove(host).await,
        Command::Start { host } => cmd_start(host).await,
        Command::Up { names } => cmd_up(names).await,
        Command::Down {
            names,
            forget,
            root,
        } => cmd_down(names, forget, root).await,
        Command::Logs {
            service,
            follow,
            lines,
        } => cmd_logs(service, follow, lines).await,
        Command::Secrets { action } => match action {
            SecretsAction::SetInfisical {
                client_id,
                client_secret,
            } => cmd_secrets_set_infisical(client_id, client_secret).await,
            SecretsAction::SetOp { token } => cmd_secrets_set_op(token).await,
        },
        Command::Tld { action } => match action {
            TldAction::List => cmd_tld_list().await,
            TldAction::Add { tld, tls } => cmd_tld_add(tld, tls).await,
            TldAction::Remove { tld } => cmd_tld_remove(tld).await,
        },
        Command::Install => cmd_install().await,
        Command::Uninstall => cmd_uninstall().await,
        Command::Dashboard => cmd_dashboard().await,
        Command::Tui => tui::run().await,
        Command::Bridge { action } => match action {
            BridgeAction::Status => cmd_bridge_status().await,
            BridgeAction::Doctor => cmd_doctor().await,
            BridgeAction::Prepare => cmd_bridge_prepare().await,
            BridgeAction::Enable => cmd_bridge(Request::BridgeEnable, true, "enabled").await,
            BridgeAction::Disable => cmd_bridge(Request::BridgeDisable, false, "disabled").await,
            BridgeAction::Mode { mode } => cmd_bridge_mode(mode).await,
        },
    }
}

async fn cmd_list() -> Result<()> {
    let resp = request(Request::ListEntries).await?;
    match resp {
        Response::Entries { entries } => print_entries(&entries),
        other => return other.unexpected(),
    }
    Ok(())
}

async fn cmd_cert_health() -> Result<()> {
    let resp = request(Request::CertHealth).await?;
    match resp {
        Response::CertHealth {
            mkcert_available,
            caroot_path,
            caroot_valid,
            issued_count,
        } => {
            println!(
                "mkcert:          {}",
                if mkcert_available {
                    "available"
                } else {
                    "missing"
                }
            );
            println!(
                "CAROOT:          {}",
                caroot_path.unwrap_or_else(|| "(unknown)".to_string())
            );
            println!(
                "CAROOT status:   {}",
                if caroot_valid {
                    "valid"
                } else {
                    "missing rootCA.pem"
                }
            );
            println!("issued certs:    {issued_count}");
        }
        other => return other.unexpected(),
    }
    Ok(())
}

async fn cmd_resources() -> Result<()> {
    let resp = request(Request::ResourceUsage).await?;
    match resp {
        Response::ResourceUsage { snapshot } => print_resources(&snapshot),
        other => return other.unexpected(),
    }
    Ok(())
}

fn print_resources(snapshot: &ResourceUsageSnapshot) {
    println!(
        "containers: {}  sample: {}ms",
        snapshot.container_count, snapshot.sample_window_ms
    );
    println!(
        "total:      cpu {:>6.1}%  mem {:>9}  rx/s {:>9}  tx/s {:>9}  read/s {:>9}  write/s {:>9}  pids {}",
        snapshot.totals.cpu_percent,
        format_bytes(snapshot.totals.memory_usage_bytes),
        format_rate(snapshot.totals.network_rx_rate_bytes_per_sec),
        format_rate(snapshot.totals.network_tx_rate_bytes_per_sec),
        format_rate(snapshot.totals.block_read_rate_bytes_per_sec),
        format_rate(snapshot.totals.block_write_rate_bytes_per_sec),
        snapshot.totals.pids_current
    );
    if snapshot.containers.is_empty() {
        println!("(no running containers)");
        return;
    }

    println!();
    println!(
        "{:<24} {:>7} {:>9} {:>6} {:>9} {:>9} {:>9} {:>9}  HOSTS/IMAGE",
        "CONTAINER", "CPU", "MEM", "PIDS", "RX", "TX", "READ", "WRITE"
    );
    for row in &snapshot.containers {
        print_resource_row(row);
    }
}

fn print_resource_row(row: &ContainerResourceUsage) {
    let label = match (&row.compose_project, &row.compose_service) {
        (Some(project), Some(service)) => format!("{project}/{service}"),
        _ if !row.name.is_empty() => row.name.clone(),
        _ => row.id.chars().take(12).collect(),
    };
    let hosts = if row.portman_hosts.is_empty() {
        row.image.clone()
    } else {
        row.portman_hosts.join(",")
    };
    let pids = row
        .pids_current
        .map(|pids| pids.to_string())
        .unwrap_or_else(|| "-".to_string());
    println!(
        "{:<24} {:>6.1}% {:>9} {:>6} {:>9} {:>9} {:>9} {:>9}  {}",
        truncate(&label, 24),
        row.cpu_percent,
        format_bytes(row.memory_usage_bytes),
        pids,
        format_rate(row.network_rx_rate_bytes_per_sec),
        format_rate(row.network_tx_rate_bytes_per_sec),
        format_rate(row.block_read_rate_bytes_per_sec),
        format_rate(row.block_write_rate_bytes_per_sec),
        hosts
    );
    if let Some(error) = &row.error {
        println!("{:<24} {}", "", error);
    }
}

async fn cmd_add(
    host: String,
    target: String,
    tcp: bool,
    service: Option<String>,
    project: Option<String>,
) -> Result<()> {
    let mode = if tcp { Mode::Tcp } else { Mode::Http };
    let added_host = host.clone();
    let resp = request(Request::AddStatic {
        host,
        target,
        mode,
        service,
        project,
    })
    .await?;
    match resp {
        Response::Ok => println!("ok"),
        other => return other.unexpected(),
    }
    warn_if_target_shared(&added_host).await;
    Ok(())
}

/// After a successful add, tell the user if the new rule's target is already
/// claimed by another host. Best-effort: a failed re-read just stays quiet
/// rather than turning a successful add into an error.
async fn warn_if_target_shared(host: &str) {
    let Ok(Response::Entries { entries }) = request(Request::ListEntries).await else {
        return;
    };
    for (target, hosts) in portman_core::target_collisions(&entries) {
        if hosts.iter().any(|h| h == host) {
            let others: Vec<&str> = hosts
                .iter()
                .filter(|h| h.as_str() != host)
                .map(String::as_str)
                .collect();
            eprintln!(
                "warning: {target} is also claimed by {} — only one process can own that port",
                others.join(", ")
            );
        }
    }
}

async fn cmd_start(host: String) -> Result<()> {
    let resp = request(Request::StartService { host }).await?;
    match resp {
        Response::Started { detail } => {
            if detail.is_empty() {
                println!("ok");
            } else {
                println!("{detail}");
            }
        }
        other => return other.unexpected(),
    }
    Ok(())
}

async fn cmd_remove(host: String) -> Result<()> {
    let resp = request(Request::RemoveStatic { host }).await?;
    match resp {
        Response::Ok => println!("ok"),
        other => return other.unexpected(),
    }
    Ok(())
}

async fn cmd_dashboard() -> Result<()> {
    let port = match request(Request::Status).await {
        Ok(Response::Status { dashboard_port, .. }) => dashboard_port,
        _ => DEFAULT_DASHBOARD_PORT,
    };
    // The API needs a bearer token and a browser navigation cannot send a
    // header, so it rides in once on the query string; the page moves it to
    // sessionStorage and clears the address bar.
    let url = match dashboard_token() {
        Some(token) => format!("http://127.0.0.1:{port}/?token={token}"),
        None => format!("http://127.0.0.1:{port}"),
    };
    println!("http://127.0.0.1:{port}");
    open_browser(&url)
}

/// The dashboard token, if this user can read it. Absent when auth is off, or
/// when the daemon could not hand the file to the login user.
fn dashboard_token() -> Option<String> {
    let path = portman_core::paths::dashboard_token_path().ok()?;
    let token = std::fs::read_to_string(&path).ok()?;
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn print_entries(entries: &[Entry]) {
    if entries.is_empty() {
        println!("(no entries)");
        return;
    }
    let host_w = entries
        .iter()
        .map(|e| e.host.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let target_w = entries
        .iter()
        .map(|e| e.target.len())
        .max()
        .unwrap_or(6)
        .max(6);
    println!(
        "{:<host_w$}  {:<target_w$}  {:<4}  {:<9}  CONTAINER",
        "HOST",
        "TARGET",
        "MODE",
        "SOURCE",
        host_w = host_w,
        target_w = target_w,
    );
    for e in entries {
        let source = match e.source {
            Source::Container => "container",
            Source::Static => "static",
            Source::Service => "service",
            Source::Egress => "egress",
            Source::Unknown => "unknown",
        };
        let container = e.container_id.as_deref().unwrap_or("-");
        println!(
            "{:<host_w$}  {:<target_w$}  {:<4}  {:<9}  {}",
            e.host,
            e.target,
            e.mode.as_str(),
            source,
            container,
            host_w = host_w,
            target_w = target_w,
        );
    }
    print_target_collisions(entries);
}

/// Warn about targets claimed by more than one hostname. Not an error — two
/// names for one app is a legitimate alias — but only one process can own a
/// port, so when the names belong to *different* apps the extra hostnames
/// silently serve whichever app won the bind.
fn print_target_collisions(entries: &[Entry]) {
    let collisions = portman_core::target_collisions(entries);
    if collisions.is_empty() {
        return;
    }
    println!();
    println!(
        "warning: {} target(s) claimed by more than one host — only one process can own each port:",
        collisions.len()
    );
    for (target, hosts) in collisions {
        println!("  {target}  ←  {}", hosts.join(", "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn down_forget_is_repo_scoped_and_rejects_named_services() {
        let cli = Cli::try_parse_from(["portman", "down", "--forget"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Down {
                names,
                forget: true,
                root: None
            }) if names.is_empty()
        ));

        assert!(Cli::try_parse_from(["portman", "down", "web", "--forget"]).is_err());
        assert!(Cli::try_parse_from(["portman", "down", "--root", "/tmp/project"]).is_err());

        let cli =
            Cli::try_parse_from(["portman", "down", "--forget", "--root", "/tmp/project"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Down {
                names,
                forget: true,
                root: Some(root)
            }) if names.is_empty() && root == std::path::Path::new("/tmp/project")
        ));
    }

    #[test]
    fn status_accepts_repo_scope() {
        let cli = Cli::try_parse_from(["portman", "status", "--repo"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Status { repo: true })));
    }
}
