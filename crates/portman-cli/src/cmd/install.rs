//! Install/uninstall: release build as the invoking user, binary placement,
//! launchd/systemd unit management, and straggler sweeps.

#[cfg(target_os = "macos")]
use crate::client::request;
use crate::cmd::services::InterruptedServices;
use crate::cmd::{locate_repo_root, run, run_sudo, sudo_write};
use anyhow::{bail, Context, Result};
#[cfg(target_os = "macos")]
use portman_daemon::BridgeLeftovers;
#[cfg(target_os = "macos")]
use portman_protocol::{DockerState, DockerStatus, Request, Response};
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::process::Command as StdCommand;
#[cfg(target_os = "macos")]
use std::time::Duration;

/// portman install: build release binaries, copy to /usr/local/bin, install
/// the system service (launchd on macOS, systemd on Linux).
pub(crate) async fn cmd_install() -> Result<()> {
    #[cfg(target_os = "macos")]
    return cmd_install_macos().await;
    #[cfg(target_os = "linux")]
    return cmd_install_linux().await;
}

/// Where the binaries to install come from. In a checkout, build them
/// fresh; otherwise (brew, shell installer, a downloaded tarball) install
/// the very binaries we're running from — `portman-daemon` must sit next
/// to the running `portman`.
fn resolve_install_sources() -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    if let Ok(repo) = locate_repo_root() {
        eprintln!("using repo: {}", repo.display());
        let install_target_dir = repo.join("target/portman-install");
        eprintln!("building release binaries…");
        run(&mut release_build_command(&repo, &install_target_dir))?;
        let daemon_src = install_target_dir.join("release/portman-daemon");
        let cli_src = install_target_dir.join("release/portman");
        for p in [&daemon_src, &cli_src] {
            if !p.exists() {
                bail!("expected build output missing: {}", p.display());
            }
        }
        return Ok((daemon_src, cli_src));
    }
    let cli_src = std::env::current_exe().context("resolving the running portman binary")?;
    let daemon_src = cli_src
        .parent()
        .context("running binary has no parent directory")?
        .join("portman-daemon");
    if !daemon_src.exists() {
        bail!(
            "not inside a portman checkout, and no portman-daemon next to {} — \
             install prebuilt binaries (brew or the shell installer) or run from a checkout",
            cli_src.display()
        );
    }
    eprintln!(
        "installing from prebuilt binaries at {}",
        cli_src.parent().unwrap().display()
    );
    Ok((daemon_src, cli_src))
}

#[cfg(target_os = "macos")]
pub(crate) async fn cmd_install_macos() -> Result<()> {
    use crate::cmd::run_setup_image_build;
    use portman_core::launchd::{daemon_plist, DAEMON_LABEL, DAEMON_PLIST_PATH};
    use portman_core::paths::user_home;

    let (daemon_src, cli_src) = resolve_install_sources()?;

    eprintln!("building netbridge setup image…");
    run_setup_image_build()?;

    install_binaries(&daemon_src, &cli_src)?;

    let home = user_home()?;
    let log_dir = home.join("Library/Logs/portman");
    std::fs::create_dir_all(&log_dir)?;

    let sudo_user = std::env::var("SUDO_USER").ok().unwrap_or_else(whoami);
    let daemon_dst = std::path::Path::new(portman_core::paths::INSTALLED_DAEMON_BIN);
    let daemon_xml = daemon_plist(daemon_dst, &log_dir, &sudo_user);

    // Skip the plist write when the installed plist is already identical. The
    // content is deterministic per machine (binary path, log dir, user), so the
    // common reinstall loop never needs the write — which also lets the sudoers
    // fragment omit the arbitrary-content `tee` rule (a passwordless-root
    // primitive). A template change still writes, prompting once, visibly.
    let plist_current = std::fs::read_to_string(DAEMON_PLIST_PATH)
        .map(|existing| existing == daemon_xml)
        .unwrap_or(false);
    if plist_current {
        eprintln!("{DAEMON_PLIST_PATH} unchanged, skipping write");
    } else {
        eprintln!("writing {} (sudo required)", DAEMON_PLIST_PATH);
        sudo_write(std::path::Path::new(DAEMON_PLIST_PATH), &daemon_xml)?;
        run_sudo(&["chown", "root:wheel", DAEMON_PLIST_PATH])?;
        run_sudo(&["chmod", "0644", DAEMON_PLIST_PATH])?;
    }

    let interrupted = InterruptedServices::record().await.say_what_stops();
    eprintln!("loading launchd service…");
    let _ = StdCommand::new("sudo")
        .args(["launchctl", "bootout", &format!("system/{DAEMON_LABEL}")])
        .status();
    sweep_stragglers();
    // `bootout` is asynchronous: it tells launchd to stop the service and
    // returns while the old daemon is still draining (it holds :80/:443 and
    // supervised children, so a graceful exit takes seconds). Bootstrapping
    // over a live instance fails with I/O error 5 — twice in the field before
    // this wait existed. The sweep above can't help: killing the root-owned
    // daemon by pid has no safe passwordless sudoers form.
    wait_for_old_daemon_exit();
    run_sudo(&["launchctl", "bootstrap", "system", DAEMON_PLIST_PATH])
        .inspect_err(|_| interrupted.say_how_to_start())?;
    interrupted.restore().await;

    print_install_success(&log_dir);
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) async fn cmd_install_linux() -> Result<()> {
    use portman_core::systemd::{daemon_unit, DAEMON_UNIT_PATH};

    let (daemon_src, cli_src) = resolve_install_sources()?;

    install_binaries(&daemon_src, &cli_src)?;

    let log_dir = std::path::Path::new("/var/log/portman");
    run_sudo(&["mkdir", "-p", log_dir.to_str().unwrap()])?;

    let sudo_user = std::env::var("SUDO_USER").ok().unwrap_or_else(whoami);
    let daemon_dst = std::path::Path::new(portman_core::paths::INSTALLED_DAEMON_BIN);
    let unit = daemon_unit(daemon_dst, log_dir, &sudo_user);

    eprintln!("writing {} (sudo required)", DAEMON_UNIT_PATH);
    sudo_write(std::path::Path::new(DAEMON_UNIT_PATH), &unit)?;

    let recorded = InterruptedServices::record().await;
    eprintln!("enabling systemd service…");
    run_sudo(&["systemctl", "daemon-reload"])?;
    run_sudo(&["systemctl", "enable", "--now", "portman-daemon"])?;
    // `enable --now` is a no-op when the unit is already active — an
    // upgrade must actually swap onto the new binary.
    let interrupted = recorded.say_what_stops();
    run_sudo(&["systemctl", "restart", "portman-daemon"])
        .inspect_err(|_| interrupted.say_how_to_start())?;
    interrupted.restore().await;

    print_install_success(log_dir);
    Ok(())
}

pub(crate) fn install_binaries(
    daemon_src: &std::path::Path,
    cli_src: &std::path::Path,
) -> Result<()> {
    let bin_dir = std::path::Path::new("/usr/local/bin");
    eprintln!(
        "installing binaries to {} (sudo required)",
        bin_dir.display()
    );
    if !bin_dir.exists() {
        run_sudo(&["mkdir", "-p", bin_dir.to_str().unwrap()])?;
    }
    let daemon_dst = bin_dir.join("portman-daemon");
    let cli_dst = bin_dir.join("portman");
    for (src, dst) in [(daemon_src, &daemon_dst), (cli_src, &cli_dst)] {
        if let (Ok(s), Ok(d)) = (std::fs::canonicalize(src), std::fs::canonicalize(dst)) {
            if s == d {
                continue;
            }
        }
        run_sudo(&[
            "install",
            "-m",
            "0755",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ])?;
    }
    Ok(())
}

pub(crate) fn print_install_success(log_dir: &std::path::Path) {
    println!(
        "\nportman installed. Daemon autostarts on boot. Logs in {}.",
        log_dir.display()
    );
    println!(
        "Open the dashboard: http://{}  (or run `portman dashboard`)",
        portman_core::registry::DASHBOARD_HOST
    );
    println!("Uninstall with: portman uninstall");
}

pub(crate) async fn cmd_uninstall() -> Result<()> {
    #[cfg(target_os = "macos")]
    return cmd_uninstall_macos().await;
    #[cfg(target_os = "linux")]
    return cmd_uninstall_linux().await;
}

#[cfg(target_os = "macos")]
pub(crate) async fn cmd_uninstall_macos() -> Result<()> {
    uninstall(&ThisMac).await;
    println!("portman uninstalled.");
    Ok(())
}

#[cfg(target_os = "macos")]
trait Uninstall {
    async fn daemon_status(&self) -> Result<Response>;
    fn stop_daemon(&self);
    fn wait_for_daemon_exit(&self);
    async fn remove_bridge_leftovers(&self, engine_socket: Option<PathBuf>) -> BridgeLeftovers;
    fn remove_service_files(&self);
    fn saved_bridge_state(&self) -> SavedBridge;
    fn say(&self, line: &str);
}

/// What the saved state file says about the bridge. It is not what a bridge
/// does now: the daemon is stopped when the uninstall reads it.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SavedBridge {
    On,
    /// Also a file that is absent or cannot be read as JSON.
    Off,
    /// The path of the file could not be built.
    Unknown,
}

#[cfg(target_os = "macos")]
fn saved_bridge(saved: &portman_core::netbridge_state::NetbridgeState) -> SavedBridge {
    if saved.enabled {
        SavedBridge::On
    } else {
        SavedBridge::Off
    }
}

/// The plist goes before the engine is asked. An uninstall that is
/// interrupted while it waits for the engine then leaves no plist that
/// starts the daemon again at the next boot.
#[cfg(target_os = "macos")]
async fn uninstall(mac: &impl Uninstall) {
    let engine_socket = daemon_engine_socket(mac.daemon_status()).await;
    mac.stop_daemon();
    mac.remove_service_files();
    mac.wait_for_daemon_exit();
    let removal = mac.remove_bridge_leftovers(engine_socket);
    let lines = match tokio::time::timeout(REMOVAL_BUDGET, removal).await {
        Ok(BridgeLeftovers::NoEngine { .. }) if mac.saved_bridge_state() == SavedBridge::Off => {
            vec![]
        }
        Ok(leftovers) => bridge_leftover_lines(&leftovers),
        Err(_) => stalled_removal_lines(),
    };
    for line in lines {
        mac.say(&line);
    }
}

/// The engine's client bounds only the wait for the head of each response,
/// so an engine that stalls after the connect probe would hold the
/// uninstall for minutes. The budget must exceed the 3 s of the connect
/// probe plus the 15 s that the stop and removal of the setup container may
/// take, so that it never cuts a removal that the engine answers.
#[cfg(target_os = "macos")]
const REMOVAL_BUDGET: Duration = Duration::from_secs(35);

#[cfg(target_os = "macos")]
fn by_hand_lines() -> Vec<String> {
    let mut lines: Vec<String> = portman_daemon::manual_removal_commands()
        .map(|command| format!("    {command}"))
        .into();
    lines.push(
        "bridge: do not run them while another portman daemon runs a bridge on this engine: they would remove its forwarder and network"
            .to_string(),
    );
    lines
}

#[cfg(target_os = "macos")]
fn stalled_removal_lines() -> Vec<String> {
    [
        vec![
            format!(
                "bridge: Docker gave no answer in {} s and may still hold the dns forwarder",
                REMOVAL_BUDGET.as_secs()
            ),
            "bridge: when Docker answers again, remove the forwarder and its network with:"
                .to_string(),
        ],
        by_hand_lines(),
    ]
    .concat()
}

#[cfg(target_os = "macos")]
struct ThisMac;

#[cfg(target_os = "macos")]
impl Uninstall for ThisMac {
    async fn daemon_status(&self) -> Result<Response> {
        request(Request::Status).await
    }

    fn stop_daemon(&self) {
        eprintln!("tearing down launchd service…");
        let service = format!("system/{}", portman_core::launchd::DAEMON_LABEL);
        let _ = StdCommand::new("sudo")
            .args(["launchctl", "bootout", &service])
            .status();
        sweep_stragglers();
        remove_legacy_menubar();
    }

    fn wait_for_daemon_exit(&self) {
        if !old_daemon_exits_within_30s() {
            eprintln!("previous daemon still running after 30s");
        }
    }

    async fn remove_bridge_leftovers(&self, engine_socket: Option<PathBuf>) -> BridgeLeftovers {
        eprintln!("looking in Docker for what the bridge left…");
        portman_daemon::remove_bridge_leftovers(engine_socket).await
    }

    fn remove_service_files(&self) {
        eprintln!("removing system plist (sudo required)");
        let _ = run_sudo(&["rm", "-f", portman_core::launchd::DAEMON_PLIST_PATH]);
        remove_installed_binaries();
    }

    fn saved_bridge_state(&self) -> SavedBridge {
        match portman_core::paths::netbridge_state_path() {
            Ok(path) => saved_bridge(&portman_core::netbridge_state::load(&path)),
            Err(_) => SavedBridge::Unknown,
        }
    }

    fn say(&self, line: &str) {
        eprintln!("{line}");
    }
}

/// How long the daemon has to say which engine it is connected to. An
/// uninstall also has to remove a daemon that no longer answers.
#[cfg(target_os = "macos")]
const STATUS_BUDGET: Duration = Duration::from_secs(3);

/// The socket of the engine that the daemon is connected to, from the
/// daemon's answer to a status request. `None` when no daemon answers in
/// time or the daemon is connected to no engine.
#[cfg(target_os = "macos")]
async fn daemon_engine_socket(
    status: impl std::future::Future<Output = Result<Response>>,
) -> Option<PathBuf> {
    match tokio::time::timeout(STATUS_BUDGET, status).await {
        Ok(Ok(Response::Status {
            docker:
                Some(DockerStatus {
                    state: DockerState::Connected,
                    socket: Some(socket),
                    ..
                }),
            ..
        })) => Some(socket.into()),
        _ => None,
    }
}

/// What `portman uninstall` prints about the setup container, the DNS
/// forwarder and the docker network that a bridge leaves in the engine.
#[cfg(target_os = "macos")]
fn bridge_leftover_lines(leftovers: &BridgeLeftovers) -> Vec<String> {
    match leftovers {
        BridgeLeftovers::NoneLeft { socket } => vec![
            format!(
                "bridge: Docker at {} holds nothing of the bridge now; a `portman` network that a running container uses stays",
                socket.display()
            ),
            format!(
                "bridge: a container that lists the dns forwarder at {} as its only resolver resolves no name until portman is installed again",
                crate::doctor::DNS_FORWARDER_IP
            ),
        ],
        BridgeLeftovers::Owed { socket } => [
            vec![
                format!(
                    "bridge: Docker at {} may still hold the dns forwarder. Another process holds the bridge's UDP port, or Docker refused a removal or gave no answer",
                    socket.display()
                ),
                "bridge: to remove the forwarder and its network by hand, run:".to_string(),
            ],
            by_hand_lines(),
        ]
        .concat(),
        BridgeLeftovers::NoEngine { reason } => [
            vec![
                format!("bridge: found no Docker engine to ask ({reason})"),
                "bridge: the Docker VM may still hold the dns forwarder. When Docker runs again, remove the forwarder and its network with:".to_string(),
            ],
            by_hand_lines(),
        ]
        .concat(),
    }
}

/// One-time cleanup for machines that ran the retired menu-bar app (a user
/// LaunchAgent plus a `portman-menubar` binary). Without this an old KeepAlive
/// agent lingers and keeps trying to relaunch a binary that no longer exists.
/// Safe to delete once no machine still has the legacy agent.
#[cfg(target_os = "macos")]
pub(crate) fn remove_legacy_menubar() {
    use portman_core::paths::user_home;

    const LEGACY_MENUBAR_LABEL: &str = "dev.portman.menubar";

    let uid = get_uid();
    let _ = launchctl_in_user_context(
        uid,
        &["bootout", &format!("gui/{uid}/{LEGACY_MENUBAR_LABEL}")],
    )
    .status();
    if let Ok(home) = user_home() {
        let plist = home.join("Library/LaunchAgents/dev.portman.menubar.plist");
        if plist.exists() {
            std::fs::remove_file(&plist).ok();
            eprintln!("removed legacy {}", plist.display());
        }
    }
    let _ = run_sudo(&["rm", "-f", "/usr/local/bin/portman-menubar"]);
}

#[cfg(target_os = "linux")]
pub(crate) async fn cmd_uninstall_linux() -> Result<()> {
    use portman_core::systemd::DAEMON_UNIT_PATH;

    eprintln!("stopping systemd service…");
    let _ = run_sudo(&["systemctl", "disable", "--now", "portman-daemon"]);
    let _ = run_sudo(&["rm", "-f", DAEMON_UNIT_PATH]);
    let _ = run_sudo(&["systemctl", "daemon-reload"]);

    sweep_stragglers();
    remove_installed_binaries();
    println!("portman uninstalled.");
    Ok(())
}

pub(crate) fn remove_installed_binaries() {
    eprintln!("removing installed binaries (sudo required)");
    let _ = run_sudo(&["rm", "-f", portman_core::paths::INSTALLED_DAEMON_BIN]);
    eprintln!("leaving /usr/local/bin/portman (the CLI you're running) in place.");
}

pub(crate) fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
}

/// The release build for `portman install`, run as the invoking user even when
/// install was started with `sudo`.
///
/// Once `scripts/setup-sudoers.sh` is in place, `portman install` needs no sudo
/// at all — but running it under sudo anyway is an easy habit, and then cargo
/// builds as root and leaves root-owned artifacts in `target/`. Every later
/// non-sudo build then dies with EACCES on a file it can't rewrite, which reads
/// as a broken checkout rather than a permissions mistake. Dropping back to
/// `SUDO_USER` for the build keeps the tree owned by one user however install
/// was invoked.
/// Pure argv for the release build; `sudo_user` is `$SUDO_USER` when set
/// and non-blank. Split out so the sudo-vs-plain shape is unit-testable.
/// The target dir rides as a cargo `--target-dir` argument, never the
/// CARGO_TARGET_DIR env var: sudo env_reset strips the env before cargo
/// runs, so the sudo path built into the default target/ while install
/// looked in target/portman-install (found the first time install ran under sudo on a real Linux box).
fn release_build_argv(sudo_user: Option<&str>, target_dir: &std::path::Path) -> Vec<String> {
    let mut argv: Vec<String> = Vec::new();
    if let Some(user) = sudo_user {
        argv.extend(["sudo", "-u", user].map(String::from));
    }
    argv.extend(["cargo", "build", "--release", "--workspace", "--target-dir"].map(String::from));
    argv.push(target_dir.display().to_string());
    argv
}

pub(crate) fn release_build_command(
    repo: &std::path::Path,
    install_target_dir: &std::path::Path,
) -> StdCommand {
    let build_user = std::env::var("SUDO_USER")
        .ok()
        .filter(|user| !user.trim().is_empty());
    if let Some(user) = &build_user {
        eprintln!("running under sudo; building as {user} to keep target/ user-owned");
    }

    let argv = release_build_argv(build_user.as_deref(), install_target_dir);
    let mut cmd = StdCommand::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(repo);
    cmd
}

/// Build a `launchctl <args…>` command that will reach the logged-in user's
/// GUI domain, even when the caller is running as root (e.g. `sudo portman
/// install` via a NOPASSWD sudoers rule). Under sudo, we thread through
/// `launchctl asuser <uid> launchctl <args…>` — `gui/<uid>` can't be
/// bootstrapped straight from root otherwise (err 125: "Domain does not
/// support specified action"). Outside sudo we call launchctl directly.
/// Pure argv for a launchctl call that must reach the GUI domain.
#[cfg(target_os = "macos")]
fn launchctl_argv(under_sudo: bool, uid: u32, args: &[&str]) -> Vec<String> {
    let mut argv = vec!["launchctl".to_string()];
    if under_sudo {
        argv.push("asuser".to_string());
        argv.push(uid.to_string());
        argv.push("launchctl".to_string());
    }
    argv.extend(args.iter().map(|a| a.to_string()));
    argv
}

#[cfg(target_os = "macos")]
pub(crate) fn launchctl_in_user_context(uid: u32, args: &[&str]) -> StdCommand {
    let under_sudo = std::env::var("SUDO_USER")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let argv = launchctl_argv(under_sudo, uid, args);
    let mut c = StdCommand::new(&argv[0]);
    c.args(&argv[1..]);
    c
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StragglerPattern {
    grep: &'static str,
    exact: bool,
    requires_sudo: bool,
}

pub(crate) const STRAGGLER_PATTERNS: &[StragglerPattern] = &[
    StragglerPattern {
        grep: portman_core::paths::DAEMON_BIN_NAME,
        exact: true,
        requires_sudo: true,
    },
    StragglerPattern {
        grep: "target/release/portman-daemon",
        exact: false,
        requires_sudo: true,
    },
];

fn pgrep_pids(pattern: &StragglerPattern) -> Vec<String> {
    let flag = if pattern.exact { "-x" } else { "-f" };
    let Ok(out) = StdCommand::new("pgrep")
        .arg(flag)
        .arg(pattern.grep)
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let self_pid = std::process::id().to_string();
    std::str::from_utf8(&out.stdout)
        .unwrap_or("")
        .split_ascii_whitespace()
        .filter(|pid| *pid != self_pid)
        .map(String::from)
        .collect()
}

/// Kill any `portman-daemon` processes still running. Used between bootout and
/// bootstrap so a dev binary left over from `mise run daemon-root` doesn't end
/// up shadowing the freshly installed daemon.
///
/// Matches by `pgrep -x portman-daemon` or full binary path so editors/shells
/// mentioning `portman-daemon` in their argv are never touched. SIGTERM first,
/// 1s grace, SIGKILL for stragglers.
pub(crate) fn sweep_stragglers() {
    for pattern in STRAGGLER_PATTERNS {
        let pids_owned = pgrep_pids(pattern);
        if pids_owned.is_empty() {
            continue;
        }
        let pids: Vec<&str> = pids_owned.iter().map(String::as_str).collect();
        eprintln!(
            "sweeping straggling {}: pids {}",
            pattern.grep,
            pids.join(",")
        );
        kill_pids("-TERM", &pids, pattern.requires_sudo);
    }
    // Give the processes a beat to exit cleanly before any bootstrap.
    std::thread::sleep(std::time::Duration::from_millis(1000));
    for pattern in STRAGGLER_PATTERNS {
        let pids_owned = pgrep_pids(pattern);
        if pids_owned.is_empty() {
            continue;
        }
        let pids: Vec<&str> = pids_owned.iter().map(String::as_str).collect();
        eprintln!(
            "  escalating to SIGKILL for stubborn {}: pids {}",
            pattern.grep,
            pids.join(",")
        );
        if !kill_pids("-KILL", &pids, pattern.requires_sudo) {
            eprintln!(
                "  could not sweep {} (pids {}) — sudo needs a password for kill, \
                 which has no safe passwordless rule. If the new daemon fails to bind, run:\n    \
                 sudo kill -9 {}",
                pattern.grep,
                pids.join(","),
                pids.join(" ")
            );
        }
    }
}

/// Signal `pids`, returning whether the kill actually ran.
///
/// `false` means a sudo-requiring kill was refused for want of a password —
/// the caller says what was left behind rather than the install stalling on a
/// prompt it can't answer.
/// Block until no installed `portman-daemon` process remains, bounded at 30s.
///
/// Only watches the installed path — a dev daemon from `mise run daemon-root`
/// is the sweep's problem, not a reason to stall the install. On timeout we
/// proceed and let `launchctl bootstrap` report the conflict; waiting forever
/// on a wedged daemon would be worse.
#[cfg(target_os = "macos")]
pub(crate) fn wait_for_old_daemon_exit() {
    if !old_daemon_exits_within_30s() {
        eprintln!("previous daemon still running after 30s; attempting bootstrap anyway");
    }
}

/// Whether the installed `portman-daemon` process is gone, after a wait of
/// at most 30s for it.
#[cfg(target_os = "macos")]
fn old_daemon_exits_within_30s() -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut waited = false;
    loop {
        let alive = StdCommand::new("pgrep")
            .args(["-f", portman_core::paths::INSTALLED_DAEMON_BIN])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if !alive {
            if waited {
                eprintln!("previous daemon exited");
            }
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        if !waited {
            eprintln!("waiting for the previous daemon to exit…");
            waited = true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

pub(crate) fn kill_pids(signal: &str, pids: &[&str], requires_sudo: bool) -> bool {
    let argv = kill_argv(signal, pids, requires_sudo);
    let Some((program, args)) = argv.split_first() else {
        return true;
    };
    StdCommand::new(program)
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub(crate) fn kill_argv(signal: &str, pids: &[&str], requires_sudo: bool) -> Vec<String> {
    let mut argv = Vec::new();
    if requires_sudo {
        argv.push("sudo".to_string());
        // Non-interactive: `portman install` is meant to run unattended once
        // scripts/setup-sudoers.sh is in place. Killing by pid can't be
        // expressed as an exact sudoers rule — pids are dynamic, and a
        // wildcard `kill` rule would hand out passwordless "terminate any root
        // process", which is precisely the sort of primitive that fragment is
        // written to avoid. So this may legitimately be refused; the caller
        // reports it instead of blocking on a TTY prompt.
        argv.push("-n".to_string());
    }
    argv.push("kill".to_string());
    argv.push(signal.to_string());
    argv.extend(pids.iter().map(|pid| (*pid).to_string()));
    argv
}

/// Parse a `SUDO_UID`-style value; uid 0 is not a usable GUI-domain uid
/// (root has no GUI session) so it is treated as absent.
#[cfg(target_os = "macos")]
fn uid_from_env(sudo_uid: Option<&str>) -> Option<u32> {
    let uid = sudo_uid?.trim().parse::<u32>().ok()?;
    (uid != 0).then_some(uid)
}

#[cfg(target_os = "macos")]
pub(crate) fn get_uid() -> u32 {
    if let Some(uid) = uid_from_env(std::env::var("SUDO_UID").ok().as_deref()) {
        return uid;
    }
    match StdCommand::new("id").arg("-u").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(501),
        _ => 501,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_build_argv_drops_to_the_invoking_user_only_under_sudo() {
        let dir = std::path::Path::new("/tmp/t");
        assert_eq!(
            release_build_argv(Some("dev"), dir),
            [
                "sudo",
                "-u",
                "dev",
                "cargo",
                "build",
                "--release",
                "--workspace",
                "--target-dir",
                "/tmp/t"
            ]
        );
        assert_eq!(
            release_build_argv(None, dir),
            [
                "cargo",
                "build",
                "--release",
                "--workspace",
                "--target-dir",
                "/tmp/t"
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchctl_argv_threads_through_asuser_only_under_sudo() {
        assert_eq!(
            launchctl_argv(true, 501, &["bootstrap", "gui/501"]),
            [
                "launchctl",
                "asuser",
                "501",
                "launchctl",
                "bootstrap",
                "gui/501"
            ]
        );
        assert_eq!(
            launchctl_argv(false, 501, &["bootstrap", "gui/501"]),
            ["launchctl", "bootstrap", "gui/501"]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn uid_from_env_ignores_root_and_garbage() {
        assert_eq!(uid_from_env(Some("501")), Some(501));
        assert_eq!(uid_from_env(Some(" 502 ")), Some(502));
        assert_eq!(uid_from_env(Some("0")), None, "uid 0 has no GUI domain");
        assert_eq!(uid_from_env(Some("nope")), None);
        assert_eq!(uid_from_env(None), None);
    }

    #[cfg(target_os = "macos")]
    fn status(docker: &str) -> Result<Response> {
        let json = format!(r#"{{"kind":"status","docker":{docker}}}"#);
        Ok(serde_json::from_str(&json).unwrap())
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn an_uninstall_asks_the_engine_that_the_daemon_is_connected_to() {
        let connected = r#"{"state":"connected","socket":"/run/demo/docker.sock"}"#;
        let disconnected = r#"{"state":"disconnected","socket":"/run/demo/docker.sock"}"#;
        let table = [
            (status(connected), Some("/run/demo/docker.sock")),
            (status(disconnected), None),
            (status("null"), None),
            (Ok(Response::Ok), None),
            (Err(anyhow::anyhow!("no daemon answers")), None),
        ];
        for (answer, socket) in table {
            let said = format!("{answer:?}");
            assert_eq!(
                daemon_engine_socket(async { answer }).await,
                socket.map(std::path::PathBuf::from),
                "{said}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_does_not_answer_does_not_hold_an_uninstall_up() {
        let began = tokio::time::Instant::now();

        let socket = daemon_engine_socket(std::future::pending()).await;

        assert_eq!(socket, None);
        assert_eq!(began.elapsed(), STATUS_BUDGET);
    }

    #[cfg(target_os = "macos")]
    enum StandInEngine {
        Answers(BridgeLeftovers),
        Stalls,
    }

    #[cfg(target_os = "macos")]
    struct StandInMac {
        engine: StandInEngine,
        saved_bridge: SavedBridge,
        did: std::sync::Mutex<Vec<String>>,
    }

    #[cfg(target_os = "macos")]
    impl StandInMac {
        fn new(engine: StandInEngine) -> Self {
            Self {
                engine,
                saved_bridge: SavedBridge::On,
                did: Default::default(),
            }
        }

        fn note(&self, what: impl Into<String>) {
            self.did.lock().unwrap().push(what.into());
        }

        fn did(&self) -> Vec<String> {
            self.did.lock().unwrap().clone()
        }
    }

    #[cfg(target_os = "macos")]
    impl Uninstall for StandInMac {
        async fn daemon_status(&self) -> Result<Response> {
            self.note("ask the daemon for its engine");
            status(r#"{"state":"connected","socket":"/run/demo/docker.sock"}"#)
        }

        fn stop_daemon(&self) {
            self.note("stop the daemon");
        }

        fn wait_for_daemon_exit(&self) {
            self.note("wait for the daemon to exit");
        }

        async fn remove_bridge_leftovers(&self, engine_socket: Option<PathBuf>) -> BridgeLeftovers {
            self.note(format!(
                "ask the engine at {engine_socket:?} for the removal"
            ));
            match &self.engine {
                StandInEngine::Answers(leftovers) => leftovers.clone(),
                StandInEngine::Stalls => std::future::pending().await,
            }
        }

        fn remove_service_files(&self) {
            self.note("remove the plist and the daemon's binary");
        }

        fn saved_bridge_state(&self) -> SavedBridge {
            self.saved_bridge
        }

        fn say(&self, line: &str) {
            self.note(format!("say: {line}"));
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn an_uninstall_does_each_step_once_in_this_order() {
        let owed = BridgeLeftovers::Owed {
            socket: "/run/demo/docker.sock".into(),
        };
        let mac = StandInMac::new(StandInEngine::Answers(owed.clone()));

        uninstall(&mac).await;

        let said = bridge_leftover_lines(&owed)
            .into_iter()
            .map(|line| format!("say: {line}"));
        let steps = [UP_TO_THE_REMOVAL.map(String::from).to_vec(), said.collect()];
        assert_eq!(mac.did(), steps.concat());
    }

    #[cfg(target_os = "macos")]
    const UP_TO_THE_REMOVAL: [&str; 5] = [
        "ask the daemon for its engine",
        "stop the daemon",
        "remove the plist and the daemon's binary",
        "wait for the daemon to exit",
        r#"ask the engine at Some("/run/demo/docker.sock") for the removal"#,
    ];

    #[cfg(target_os = "macos")]
    #[tokio::test(start_paused = true)]
    async fn an_engine_that_stalls_does_not_hold_an_uninstall_up() {
        let mac = StandInMac::new(StandInEngine::Stalls);
        let began = tokio::time::Instant::now();

        let ended = tokio::time::timeout(Duration::from_secs(3600), uninstall(&mac)).await;

        assert!(ended.is_ok(), "still waiting for the engine after an hour");
        assert_eq!(began.elapsed(), Duration::from_secs(35));
        let did = mac.did();
        assert_eq!(did[..5], UP_TO_THE_REMOVAL);
        assert_eq!(
            did[5..],
            [
                "say: bridge: Docker gave no answer in 35 s and may still hold the dns forwarder",
                "say: bridge: when Docker answers again, remove the forwarder and its network with:",
                "say:     docker rm -f portman-netbridge-dns",
                "say:     docker network rm portman",
                "say: bridge: do not run them while another portman daemon runs a bridge on \
                 this engine: they would remove its forwarder and network",
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_bridge_is_saved_as_off_only_when_no_disable_still_owes_its_removal() {
        use portman_core::netbridge_state::NetbridgeState;
        let saved = |enabled, cleanup_owed| NetbridgeState {
            enabled,
            cleanup_owed,
            ..NetbridgeState::default()
        };

        assert_eq!(saved_bridge(&saved(false, false)), SavedBridge::Off);
        assert_eq!(saved_bridge(&saved(true, false)), SavedBridge::On);
        assert_eq!(saved_bridge(&saved(false, true)), SavedBridge::On);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn an_uninstall_that_finds_no_engine_is_silent_only_for_a_bridge_that_is_saved_as_off() {
        let no_engine = BridgeLeftovers::NoEngine {
            reason: "no docker socket found".into(),
        };
        let table = [
            (SavedBridge::Off, false),
            (SavedBridge::On, true),
            (SavedBridge::Unknown, true),
        ];
        for (saved_bridge, names_the_forwarder) in table {
            let mac = StandInMac {
                saved_bridge,
                ..StandInMac::new(StandInEngine::Answers(no_engine.clone()))
            };

            uninstall(&mac).await;

            let did = mac.did();
            assert_eq!(did[..5], UP_TO_THE_REMOVAL, "{saved_bridge:?}");
            let said: Vec<String> = bridge_leftover_lines(&no_engine)
                .into_iter()
                .filter(|_| names_the_forwarder)
                .map(|line| format!("say: {line}"))
                .collect();
            assert_eq!(did[5..], said, "{saved_bridge:?}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_uninstall_says_what_is_left_of_the_bridge_and_how_to_remove_it_by_hand() {
        let socket = std::path::PathBuf::from("/run/demo/docker.sock");
        let by_hand = [
            "    docker rm -f portman-netbridge-dns",
            "    docker network rm portman",
            "bridge: do not run them while another portman daemon runs a bridge on this \
             engine: they would remove its forwarder and network",
        ];

        assert_eq!(
            bridge_leftover_lines(&BridgeLeftovers::NoneLeft {
                socket: socket.clone()
            }),
            [
                "bridge: Docker at /run/demo/docker.sock holds nothing of the bridge now; \
                 a `portman` network that a running container uses stays",
                "bridge: a container that lists the dns forwarder at 192.168.99.129 as its \
                 only resolver resolves no name until portman is installed again",
            ]
        );
        assert_eq!(
            bridge_leftover_lines(&BridgeLeftovers::Owed { socket }),
            [
                "bridge: Docker at /run/demo/docker.sock may still hold the dns forwarder. \
                 Another process holds the bridge's UDP port, or Docker refused a removal or \
                 gave no answer",
                "bridge: to remove the forwarder and its network by hand, run:",
                by_hand[0],
                by_hand[1],
                by_hand[2],
            ]
        );
        assert_eq!(
            bridge_leftover_lines(&BridgeLeftovers::NoEngine {
                reason: "no docker socket found".into()
            }),
            [
                "bridge: found no Docker engine to ask (no docker socket found)",
                "bridge: the Docker VM may still hold the dns forwarder. When Docker runs \
                 again, remove the forwarder and its network with:",
                by_hand[0],
                by_hand[1],
                by_hand[2],
            ]
        );
    }

    #[test]
    fn daemon_straggler_patterns_require_sudo() {
        assert!(STRAGGLER_PATTERNS
            .iter()
            .any(|p| p.grep == "portman-daemon" && p.requires_sudo));
        assert!(STRAGGLER_PATTERNS
            .iter()
            .any(|p| p.grep == "target/release/portman-daemon" && p.requires_sudo));
    }

    #[test]
    fn kill_argv_uses_sudo_only_when_required() {
        assert_eq!(
            kill_argv("-KILL", &["789"], false),
            vec!["kill", "-KILL", "789"]
        );
    }

    #[test]
    fn sudo_kills_never_wait_on_a_password_prompt() {
        // `portman install` runs unattended. Killing by pid can't be granted a
        // safe passwordless sudoers rule, so this must fail fast rather than
        // block the install on a TTY prompt it has no way to answer.
        assert_eq!(
            kill_argv("-TERM", &["123", "456"], true),
            vec!["sudo", "-n", "kill", "-TERM", "123", "456"]
        );
    }
}
