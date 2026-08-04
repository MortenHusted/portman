//! Command handlers, one module per domain; `main.rs` keeps the clap
//! definitions and dispatch. Shared shell-out helpers live here.

pub(crate) mod bridge;
pub(crate) mod install;
pub(crate) mod secrets;
pub(crate) mod services;
pub(crate) mod tld;

use std::io::Write;
use std::process::{Command as StdCommand, Stdio};

use crate::doctor;

use anyhow::{bail, Context, Result};

/// Walk up from CWD to find a directory that contains a workspace `Cargo.toml`.
pub(crate) fn locate_repo_root() -> Result<std::path::PathBuf> {
    let cwd = std::env::current_dir()?;
    for dir in cwd.ancestors() {
        let cargo = dir.join("Cargo.toml");
        if cargo.exists() {
            if let Ok(contents) = std::fs::read_to_string(&cargo) {
                if contents.contains("[workspace]") && dir.join("crates/portman-daemon").exists() {
                    return Ok(dir.to_path_buf());
                }
            }
        }
    }
    bail!(
        "could not find portman repo root (looked for [workspace] Cargo.toml from {}). \
         Run this from inside a portman checkout.",
        cwd.display()
    )
}

pub(crate) fn run(cmd: &mut StdCommand) -> Result<()> {
    let status = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        bail!("{cmd:?} failed with {status}");
    }
    Ok(())
}

pub(crate) fn run_sudo(argv: &[&str]) -> Result<()> {
    let status = StdCommand::new("sudo").args(argv).status()?;
    if !status.success() {
        bail!("sudo {argv:?} failed with {status}");
    }
    Ok(())
}

/// Build the netbridge setup image from a context embedded in this binary
/// at compile time (include_str! of the repo files), so the image is always
/// exactly the one this build expects — and no repo checkout is needed.
/// A brew- or installer-delivered binary can build it just the same.
pub(crate) fn run_setup_image_build() -> Result<()> {
    let dir = std::env::temp_dir().join("portman-setup-image");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::write(
        dir.join("Dockerfile"),
        include_str!("../../../portman-netbridge/setup-image/Dockerfile"),
    )
    .context("writing embedded Dockerfile")?;
    std::fs::write(
        dir.join("entrypoint.sh"),
        include_str!("../../../portman-netbridge/setup-image/entrypoint.sh"),
    )
    .context("writing embedded entrypoint.sh")?;
    let spec = doctor::setup_image_build_command(&dir);
    let mut cmd = StdCommand::new(&spec.program);
    cmd.args(&spec.args).current_dir(&spec.current_dir);
    run(&mut cmd).with_context(|| format!("building {}", doctor::SETUP_IMAGE))
}

/// Pipe `contents` into `sudo tee <path>` so the daemon doesn't need root.
/// Creates the parent directory if it doesn't exist (first run on a clean mac
/// typically has no `/etc/resolver/`).
pub(crate) fn sudo_write(path: &std::path::Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            let status = StdCommand::new("sudo")
                .arg("mkdir")
                .arg("-p")
                .arg(parent)
                .status()
                .context("spawning sudo mkdir")?;
            if !status.success() {
                bail!(
                    "sudo mkdir -p {} failed with status {status}",
                    parent.display()
                );
            }
        }
    }
    let mut child = StdCommand::new("sudo")
        .arg("tee")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("spawning sudo tee")?;
    child
        .stdin
        .as_mut()
        .context("child stdin missing")?
        .write_all(contents.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        bail!("sudo tee failed with status {status}");
    }
    Ok(())
}
