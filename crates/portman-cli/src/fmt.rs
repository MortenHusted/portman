//! Small display helpers shared by the command output and the TUI.

use anyhow::{bail, Result};

pub(crate) fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0_usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes}B")
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

pub(crate) fn format_rate(bytes_per_second: f64) -> String {
    if !bytes_per_second.is_finite() || bytes_per_second <= 0.0 {
        return "0B/s".to_string();
    }
    format!("{}/s", format_bytes(bytes_per_second.round() as u64))
}

pub(crate) fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>()
        + "..."
}

pub(crate) fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(target_os = "linux")]
    let program = "xdg-open";
    let status = std::process::Command::new(program).arg(url).status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => bail!("{program} failed with {s}"),
        Err(err) => bail!("failed to open browser: {err}"),
    }
}
