//! Thin shim: the daemon lives in the `portman-daemon` lib crate; this bin
//! target exists so one distributable package ships both binaries.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    portman_daemon::daemon_main().await
}
