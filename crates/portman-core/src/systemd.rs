//! systemd unit generation for Linux installs.

use std::path::Path;

pub const DAEMON_UNIT_NAME: &str = "portman-daemon.service";
pub const DAEMON_UNIT_PATH: &str = "/etc/systemd/system/portman-daemon.service";

/// Render the systemd unit for the portman daemon. Same signature as
/// `launchd::daemon_plist`; environment comes from the shared
/// `paths::daemon_env` so the platforms can't drift.
pub fn daemon_unit(daemon_bin: &Path, log_dir: &Path, sudo_user: &str) -> String {
    let env_lines = crate::paths::daemon_env(sudo_user)
        .iter()
        .map(|(key, value)| format!("Environment={key}={value}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"[Unit]
Description=portman local dev DNS and HTTP proxy
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={daemon}
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
{env_lines}
StandardOutput=append:{log_dir}/daemon.log
StandardError=append:{log_dir}/daemon.err

[Install]
WantedBy=multi-user.target
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
    fn daemon_unit_includes_bind_capability() {
        let unit = daemon_unit(
            Path::new(crate::paths::INSTALLED_DAEMON_BIN),
            Path::new("/var/log/portman"),
            "dev",
        );

        assert!(unit.contains("CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("/sbin"));
        assert!(unit.contains("SUDO_USER=dev"));
        assert!(unit.contains("portman-daemon"));
    }
}
