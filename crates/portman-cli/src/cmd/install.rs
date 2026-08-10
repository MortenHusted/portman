//! Install/uninstall: release build as the invoking user, binary placement,
//! launchd/systemd unit management, and straggler sweeps.

use crate::cmd::{locate_repo_root, run, run_sudo, sudo_write};
use anyhow::{bail, Context, Result};
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
    run_sudo(&["launchctl", "bootstrap", "system", DAEMON_PLIST_PATH])?;

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

    eprintln!("enabling systemd service…");
    run_sudo(&["systemctl", "daemon-reload"])?;
    run_sudo(&["systemctl", "enable", "--now", "portman-daemon"])?;
    // `enable --now` is a no-op when the unit is already active — an
    // upgrade must actually swap onto the new binary.
    run_sudo(&["systemctl", "restart", "portman-daemon"])?;

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
    use portman_core::launchd::{DAEMON_LABEL, DAEMON_PLIST_PATH};

    eprintln!("tearing down launchd service…");
    let _ = StdCommand::new("sudo")
        .args(["launchctl", "bootout", &format!("system/{DAEMON_LABEL}")])
        .status();

    sweep_stragglers();
    remove_legacy_menubar();

    eprintln!("removing system plist (sudo required)");
    let _ = run_sudo(&["rm", "-f", DAEMON_PLIST_PATH]);

    remove_installed_binaries();
    println!("portman uninstalled.");
    Ok(())
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
    requires_sudo: bool,
}

pub(crate) const STRAGGLER_PATTERNS: &[StragglerPattern] = &[
    StragglerPattern {
        grep: portman_core::paths::DAEMON_BIN_NAME,
        requires_sudo: true,
    },
    StragglerPattern {
        grep: "target/release/portman-daemon",
        requires_sudo: true,
    },
];

/// Kill any `portman-daemon` processes still running. Used between bootout and
/// bootstrap so a dev binary left over from `mise run daemon-root` doesn't end
/// up shadowing the freshly installed daemon.
///
/// Matches by `pgrep -f` patterns so it catches both the installed path
/// (`/usr/local/bin/portman-daemon`) and the cargo build output
/// (`target/release/portman-daemon`). SIGTERM first, 1s grace, SIGKILL for
/// stragglers.
pub(crate) fn sweep_stragglers() {
    for pattern in STRAGGLER_PATTERNS {
        let Ok(out) = StdCommand::new("pgrep")
            .arg("-f")
            .arg(pattern.grep)
            .output()
        else {
            continue;
        };
        if !out.status.success() {
            continue; // pgrep exits 1 when nothing matches — that's fine.
        }
        let pids: Vec<&str> = std::str::from_utf8(&out.stdout)
            .unwrap_or("")
            .split_ascii_whitespace()
            .collect();
        if pids.is_empty() {
            continue;
        }
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
        let Ok(out) = StdCommand::new("pgrep")
            .arg("-f")
            .arg(pattern.grep)
            .output()
        else {
            continue;
        };
        if !out.status.success() {
            continue;
        }
        let pids: Vec<&str> = std::str::from_utf8(&out.stdout)
            .unwrap_or("")
            .split_ascii_whitespace()
            .collect();
        if pids.is_empty() {
            continue;
        }
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
            return;
        }
        if std::time::Instant::now() >= deadline {
            eprintln!("previous daemon still running after 30s; attempting bootstrap anyway");
            return;
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
