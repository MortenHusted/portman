//! launchd plist generation + `launchctl` wrappers.
//!
//! One service: a system-wide daemon (needs root for `:80` / resolver config).
//! Installed and torn down by `portman install` / `portman uninstall`.

use std::path::Path;

pub const DAEMON_LABEL: &str = "dev.portman.daemon";

pub const DAEMON_PLIST_PATH: &str = "/Library/LaunchDaemons/dev.portman.daemon.plist";

/// Render the daemon plist. The binary runs as root (default for
/// `/Library/LaunchDaemons/`), KeepAlive so it respawns if it crashes.
/// Same signature as `systemd::daemon_unit` — one render call, no
/// placeholder-finalize dance.
pub fn daemon_plist(daemon_bin: &Path, log_dir: &Path, sudo_user: &str) -> String {
    let env_xml = crate::paths::daemon_env(sudo_user)
        .iter()
        .map(|(key, value)| format!("        <key>{key}</key>\n        <string>{value}</string>"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{DAEMON_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{daemon}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>{log_dir}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/daemon.err</string>
    <key>EnvironmentVariables</key>
    <dict>
{env_xml}
    </dict>
</dict>
</plist>
"#,
        daemon = daemon_bin.display(),
        log_dir = log_dir.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn daemon_plist_sets_homebrew_runtime_path_and_user() {
        let plist = daemon_plist(
            Path::new(crate::paths::INSTALLED_DAEMON_BIN),
            Path::new("/Users/dev/Library/Logs/portman"),
            "dev",
        );

        assert!(plist.contains("<key>PATH</key>"));
        assert!(plist.contains(crate::paths::DAEMON_RUNTIME_PATH));
        assert!(plist.contains("/opt/homebrew/bin"));
        assert!(plist.contains("/usr/local/bin"));
        assert!(plist.contains("/sbin"));
        assert!(plist.contains("<string>dev</string>"));
    }
}
