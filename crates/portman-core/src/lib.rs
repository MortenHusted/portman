//! Core types and abstractions for portman.
//!
//! This crate is where shared, platform-independent logic lives. The daemon
//! binary wires these pieces together with Docker events, DNS, and the proxy.

pub mod atomic_json;
#[cfg(target_os = "macos")]
pub mod launchd;
pub mod loopback_alloc;
pub mod netbridge_state;
pub mod paths;
pub mod platform;
pub mod registry;
pub mod service_config;
pub mod static_store;
#[cfg(target_os = "linux")]
pub mod systemd;
pub mod tld;
pub mod tls_store;

pub use loopback_alloc::LoopbackAllocator;
pub use platform::{Platform, PlatformApi};
pub use portman_protocol::{Entry, Mode, NetbridgeMode, Request, Response, Source};
pub use registry::{target_collisions, Registry};
pub use static_store::StaticStore;
pub use tls_store::{TlsMode, TlsStore};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
