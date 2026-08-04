//! Platform abstraction. Anything that touches macOS- or Linux-specific APIs
//! goes behind this trait so the daemon core can stay portable.
//!
//! v0 implements macOS and Linux. macOS resolver integration uses
//! `/etc/resolver/`; Linux uses systemd-resolved drop-ins.

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
pub use macos::MacOs as Platform;

#[cfg(target_os = "linux")]
pub use linux::Linux as Platform;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("portman supports macOS and Linux only.");

/// Operations the daemon performs on the host OS. Each one is something that
/// typically needs root or special entitlements on macOS.
pub trait PlatformApi {
    /// Register `tld` with the system resolver so queries land on our local DNS.
    ///
    /// On macOS this writes `/etc/resolver/<tld>` with `nameserver` + `port`.
    /// On Linux (v1+) this will use `resolvectl domain` or equivalent.
    fn install_resolver(&self, tld: &str, nameserver: &str, port: u16) -> anyhow::Result<()>;

    /// Undo `install_resolver`.
    fn uninstall_resolver(&self, tld: &str) -> anyhow::Result<()>;

    /// Add a host route so `subnet` is reachable via `iface`. Used by the
    /// VM↔host WireGuard bridge in v1+.
    fn add_route(&self, subnet: &str, iface: &str) -> anyhow::Result<()>;

    /// Make `ip` (a `127.0.0.0/8` address) usable as a bind/connect target so
    /// portman can front a TCP-mode entry on it. On macOS only `127.0.0.1` is
    /// up by default; other loopback addresses must be aliased onto `lo0`. On
    /// Linux the whole `127.0.0.0/8` is already loopback, so this is a no-op.
    fn ensure_loopback_alias(&self, ip: std::net::Ipv4Addr) -> anyhow::Result<()>;

    /// Undo [`ensure_loopback_alias`]. No-op on Linux.
    fn remove_loopback_alias(&self, ip: std::net::Ipv4Addr) -> anyhow::Result<()>;
}
