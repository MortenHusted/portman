//! portman-netbridge — native Rust replacement for
//! `chipmk/docker-mac-net-connect`.
//!
//! Started 2026-04-23. Port motivation and acceptance criteria live in the
//! repo-root `PLAN.md` (§ "v1 roadmap"). Phase sequence — and workflow
//! safety guarantees at each step — live in this crate's `PHASES.md`.
//!
//! **Current state: Phase 0 — crate scaffold only.** No functionality is
//! wired into `portman-daemon` yet. Building this crate has zero impact on
//! the v0 wrapped-bridge stack running on the user's main driver.
//!
//! Do not add heavy dependencies (`boringtun`, `tun`, `libc`-route stuff)
//! until the phase that actually uses them is being implemented. Each phase
//! opens a new module in this file; today we have none.

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
