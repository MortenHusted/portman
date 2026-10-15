//! portman-netbridge — native Rust WireGuard bridge between macOS and
//! the container VM (`colima`, `lima`, Docker Desktop).
//!
//! Creates an additive `portman` Docker network (`192.168.99.0/24`),
//! spawns a one-shot setup container inside the VM to configure the peer
//! WireGuard interface (`chip0`), and pumps packets between a macOS `utun`
//! interface and `boringtun` over UDP.

#![doc(html_root_url = "https://docs.rs/portman-netbridge/0.0.1")]

/// Version string shared with the rest of the workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Phase B.0 — key types + subnet constants + `Peer` over boringtun:
pub mod tunnel;

// Phase B.5 — start/stop the whole bridge as a long-running Runtime
// (utun + UDP + VM setup container + docker network + packet pumps):
pub mod runtime;

// Phase A will promote from examples/ to src/:
//   pub mod route_observer; (PF_ROUTE read loop — A.1 is in examples/)
//   pub mod docker_state;   (bollard events → FSM — A.2 is in examples/)
// Phase B will add:
//   pub mod setup_image;    (spawn the Linux-side setup container)
//   pub mod network;        (docker network create/inspect helpers)
// Phase D retired; see PHASES.md.
