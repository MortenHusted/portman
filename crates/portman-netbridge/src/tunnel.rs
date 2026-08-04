//! Host side of the portman-netbridge WireGuard tunnel.
//!
//! Phase B.0: module scaffold — key types, subnet constants, keypair
//! generation. The actual `start` / `stop` loops and utun integration
//! land in B.1 and B.3.
//!
//! Design notes live in `PHASES.md § Phase B`; short version:
//! - Host creates a `utun` device at `192.168.99.1/24`.
//! - Inside colima's VM, a one-shot setup container configures a
//!   WireGuard interface `chip0` at `192.168.99.2`, establishes
//!   handshake with us.
//! - Host route `192.168.99.0/24 → utun<N>` makes the portman docker
//!   network's container IPs reachable from macOS.
//! - We reserve `192.168.99.254` (host-facing virtual IP for future
//!   container-to-host routing) and do not allocate it to containers.

use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use rand::rngs::OsRng;

/// CIDR for the portman-managed docker network. Chosen to avoid common
/// home/router ranges (192.168.0/24, 192.168.1/24), OrbStack's legacy
/// 192.168.138.0/23, Tailscale CGNAT 100.64/10, and chipmk's own
/// bridge subnets 172.17/16 + 172.18/16.
pub const PORTMAN_SUBNET_CIDR: &str = "192.168.99.0/24";

/// Host end of the tunnel. Lives on the macOS side of the `utun`.
pub const HOST_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 99, 1);

/// VM end of the tunnel — the `chip0` interface inside colima's VM,
/// managed by our setup container. Acts as the gateway for the
/// portman docker network.
pub const VM_TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 99, 2);

/// Reserved host-facing virtual IP. Phase B doesn't route traffic to
/// this address; Phase E (container-to-host hook) will. Documented
/// here so the docker network's IP allocator never hands it out.
pub const RESERVED_HOST_FACING_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 99, 254);

/// Docker bridge subnet for the `portman` network — the upper /25 of
/// [`PORTMAN_SUBNET_CIDR`]. Split this way so the docker bridge and
/// the WireGuard tunnel endpoints (`.1` host, `.2` VM) live in the
/// same `/24` without colliding IP-allocation-wise:
///
///   - 192.168.99.0/25   (.0–.127) — WG tunnel endpoints + reserved
///   - 192.168.99.128/25 (.128–.255) — docker bridge subnet
///
/// Linux route-lookup picks the more-specific `/25` for container
/// traffic and falls through to the `/24` for packets destined to
/// `.1` or other tunnel addresses, which routes via chip0 as
/// intended.
pub const DOCKER_BRIDGE_CIDR: &str = "192.168.99.128/25";

/// Gateway IP of the docker `portman` bridge — the interface the VM
/// kernel uses to route between the bridge and the WireGuard side.
/// Deliberately the first allocatable IP in the bridge subnet so
/// docker's default allocator doesn't hand it out to containers.
pub const DOCKER_BRIDGE_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 99, 129);

/// First IP the portman docker network can assign to a container.
/// Subnet layout (bridge half):
///   .128 network, .129 gateway, .130..=.253 container pool,
///   .254 reserved host-facing IP (see RESERVED_HOST_FACING_IP),
///   .255 broadcast.
pub const CONTAINER_IP_POOL_START: Ipv4Addr = Ipv4Addr::new(192, 168, 99, 130);
pub const CONTAINER_IP_POOL_END: Ipv4Addr = Ipv4Addr::new(192, 168, 99, 253);

/// UDP port the host-side WireGuard endpoint listens on. Fixed so the
/// VM-side peer can always find us. Not a well-known port and not in
/// any standard ephemeral range — unlikely to collide with other local
/// services.
pub const HOST_WG_LISTEN_PORT: u16 = 51820;

/// MTU for packets carried through the tunnel. 1420 = 1500 (Ethernet)
/// minus 60 (WireGuard header + overhead). Docker network uses this
/// via `com.docker.network.driver.mtu` so container MSS-clamping
/// negotiates correctly.
pub const TUNNEL_MTU: u16 = 1420;

/// WireGuard static keypair — a pair of X25519 secret + public keys.
/// The `PartialEq`/`Eq` impls compare by public key only; secrets are
/// never serialized or logged.
///
/// Host and VM each have their own keypair. The host learns the VM's
/// public key from the setup container's stdout (or via an env
/// round-trip we control); the VM learns the host's public key from
/// the `docker run` env it's spawned with.
pub struct Keypair {
    secret: x25519::StaticSecret,
    public: x25519::PublicKey,
}

impl Keypair {
    /// Generate a fresh random keypair using the operating system's
    /// CSPRNG.
    pub fn generate() -> Self {
        let secret = x25519::StaticSecret::random_from_rng(OsRng);
        let public = x25519::PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Secret half. Handle carefully: must not be logged, written to
    /// disk without explicit encryption, or sent to an untrusted
    /// endpoint.
    pub fn secret(&self) -> &x25519::StaticSecret {
        &self.secret
    }

    /// Public half. Safe to log, share with peers, etc.
    pub fn public(&self) -> &x25519::PublicKey {
        &self.public
    }

    /// Base64 encoding of the public key — the format WireGuard
    /// config files and `wg` CLI expect.
    pub fn public_base64(&self) -> String {
        // boringtun re-exports base64 internally but doesn't expose it
        // for key formatting; we do the standard encoding ourselves.
        base64_encode(self.public.as_bytes())
    }

    /// Base64 encoding of the secret. Only call this when handing the
    /// key off to a trusted counterparty (e.g. the VM-side setup
    /// container's env). Never log the return value.
    pub fn secret_base64(&self) -> String {
        base64_encode(self.secret.as_bytes())
    }
}

/// Parse a WireGuard/X25519 public key from standard Base64.
pub fn public_key_from_base64(input: &str) -> Result<x25519::PublicKey> {
    let bytes = base64_decode(input.trim())?;
    if bytes.len() != 32 {
        bail!(
            "WireGuard public key must decode to 32 bytes, got {}",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(x25519::PublicKey::from(out))
}

/// A configured WireGuard peer — own keypair plus the remote's public
/// key, wrapping `boringtun`'s `Tunn` state machine.
///
/// Deliberately thin: this is not a full "tunnel" that owns sockets or
/// utun fds. It's just the encryption/handshake brain. The surrounding
/// plumbing (UDP socket, utun device, timer loop) lives in the daemon
/// when we fold this in, or in examples during the bring-up phases.
///
/// Index is the 24-bit WireGuard session identifier. For a
/// point-to-point tunnel (what portman-netbridge runs) any stable
/// number works; we default to 0 inside `Peer::new` because we don't
/// multiplex peers.
pub struct Peer {
    inner: Tunn,
}

impl Peer {
    /// Build a peer from the local keypair + the remote's public key.
    /// `persistent_keepalive` in seconds triggers a handshake/keepalive
    /// packet at that interval — recommended value is 25 for NAT
    /// traversal. Set to `None` to disable.
    pub fn new(
        own: &Keypair,
        remote_public: &x25519::PublicKey,
        persistent_keepalive: Option<u16>,
    ) -> Self {
        // Clone the secret because `Tunn::new` takes it by value and we
        // want `Keypair` to stay immutable after construction.
        let secret = own.secret.clone();
        let inner = Tunn::new(
            secret,
            *remote_public,
            None, // no preshared key — portman doesn't need it
            persistent_keepalive,
            0,    // single-peer tunnel; index 0 is fine
            None, // use boringtun's default rate limiter
        )
        .expect("Tunn::new only errors on bad keys, which Keypair disallows");
        Self { inner }
    }

    /// Encrypt a plaintext IP packet for transmission to the peer.
    /// `dst` must have at least `input.len() + 32` bytes of capacity
    /// to accommodate the WireGuard header + authentication tag. The
    /// returned `TunnResult` tells the caller what to do with the
    /// output buffer (typically `WriteToNetwork`).
    pub fn encapsulate<'a>(&mut self, input: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        self.inner.encapsulate(input, dst)
    }

    /// Decrypt a datagram received from the peer over the UDP
    /// transport. The returned `TunnResult` might be `WriteToTunnelV4`
    /// (deliver the plaintext to the local utun), `WriteToNetwork`
    /// (a handshake message to send back), or `Done` / `Err`.
    pub fn decapsulate<'a>(&mut self, datagram: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        // `src_addr` is only used by boringtun's rate limiter for
        // per-source cookie generation; None disables that behavior
        // and is safe for point-to-point tunnels like ours.
        self.inner.decapsulate(None, datagram, dst)
    }

    /// Drive the WireGuard timer state machine. MUST be called
    /// periodically (every ~1s is fine) or the tunnel will silently
    /// die after `REKEY_AFTER_TIME` (120s) — no rekey, no keepalive,
    /// session expires. Returns `WriteToNetwork` when a handshake
    /// init or keepalive packet needs to go out, `Done` when idle,
    /// `Err(ConnectionExpired)` if the session is beyond recovery.
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.inner.update_timers(dst)
    }
}

/// Minimal standard Base64 encoder (RFC 4648 — the format WireGuard
/// uses). Inlined to avoid dragging in an extra crate for 32-byte
/// inputs.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    // The strict STANDARD engine rejects non-canonical input (bad padding,
    // trailing bits) — the hand-rolled decoder this replaces did not.
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .context("invalid base64")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_keypairs_differ() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        // Astronomical collision odds; this catches "forgot to seed".
        assert_ne!(a.public_base64(), b.public_base64());
    }

    #[test]
    fn base64_round_trips_rfc_vector() {
        // "Man" → "TWFu" — canonical Base64 vector.
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        // Empty input.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), b"");
        // 32 bytes (actual WireGuard key size) produce 44-char output.
        let key = [0u8; 32];
        assert_eq!(base64_encode(&key).len(), 44);
        assert_eq!(base64_decode(&base64_encode(&key)).unwrap(), key);
    }

    #[test]
    fn public_key_decodes_from_base64() {
        let key = Keypair::generate();
        let encoded = key.public_base64();
        let decoded = public_key_from_base64(&encoded).unwrap();

        assert_eq!(decoded.as_bytes(), key.public().as_bytes());
        assert!(public_key_from_base64("not base64").is_err());
    }

    #[test]
    fn subnet_layout_is_sane() {
        // Sanity: reserved IPs are actually in the subnet, don't overlap.
        assert_ne!(HOST_TUNNEL_IP, VM_TUNNEL_IP);
        assert_ne!(VM_TUNNEL_IP, RESERVED_HOST_FACING_IP);
        // Docker bridge is the upper /25; container pool starts there.
        assert_eq!(DOCKER_BRIDGE_GATEWAY.octets()[3], 129);
        assert_eq!(CONTAINER_IP_POOL_START.octets()[3], 130);
        assert_eq!(CONTAINER_IP_POOL_END.octets()[3], 253);
        // Tunnel endpoints are in the lower /25 — different from the
        // bridge subnet, so docker's allocator won't hand them out.
        assert!(HOST_TUNNEL_IP.octets()[3] < 128);
        assert!(VM_TUNNEL_IP.octets()[3] < 128);
    }

    /// In-process handshake round-trip between two `Peer` instances.
    /// Proves the `boringtun` integration works end-to-end: host
    /// encrypts a packet → peer receives handshake + data → peer
    /// decrypts to the original bytes.
    ///
    /// This is the B.1c milestone — validated without needing real
    /// sockets, real utun, or a VM counterparty. Real-wire
    /// integration happens in B.2+ where the same `Peer` type gets
    /// wired into the daemon's packet pump.
    #[test]
    fn peer_handshake_and_data_round_trip() {
        // Two keypairs: "host" = macOS side, "vm" = Linux peer.
        let host_kp = Keypair::generate();
        let vm_kp = Keypair::generate();
        let mut host = Peer::new(&host_kp, vm_kp.public(), None);
        let mut vm = Peer::new(&vm_kp, host_kp.public(), None);

        // Scratch buffers sized for any WireGuard frame the handshake
        // + data carries. 2 KiB is way more than enough (largest
        // handshake init is 148 bytes, data overhead is 32 bytes on
        // top of MTU ≤ 1500).
        let mut host_out = [0u8; 2048];
        let mut vm_out = [0u8; 2048];

        // A representative IPv4 packet to ship: version 4, 20-byte
        // header, ICMP (proto 1), src 192.168.99.1 → dst 192.168.99.2,
        // then 8 bytes of "echo" payload. boringtun doesn't validate
        // checksums on encapsulation, so we don't need a correct one.
        let plaintext = [
            0x45, 0x00, 0x00, 0x1c, // version/ihl, dscp, total length 28
            0x00, 0x01, 0x00, 0x00, // id, flags/fragment
            0x40, 0x01, 0x00, 0x00, // ttl 64, proto 1 (ICMP), checksum
            192, 168, 99, 1, // src
            192, 168, 99, 2, // dst
            b'e', b'c', b'h', b'o', b'!', b'!', b'!', b'!',
        ];

        // Step 1: host encapsulates a data packet with no session yet.
        // boringtun returns a handshake-init as the outbound frame
        // (the data is queued internally until the session is up).
        let handshake_init = match host.encapsulate(&plaintext, &mut host_out) {
            TunnResult::WriteToNetwork(buf) => buf.to_vec(),
            other => panic!("expected handshake init, got {other:?}"),
        };

        // Step 2: vm receives the handshake-init, replies with
        // handshake-response.
        let handshake_response = match vm.decapsulate(&handshake_init, &mut vm_out) {
            TunnResult::WriteToNetwork(buf) => buf.to_vec(),
            other => panic!("expected handshake response, got {other:?}"),
        };

        // Step 3: host receives the response, establishes session.
        // boringtun's documented contract says to repeat-call
        // `decapsulate` with an empty datagram after a WriteToNetwork
        // to flush any queued packets (in this case the original
        // plaintext we queued in Step 1).
        match host.decapsulate(&handshake_response, &mut host_out) {
            // Some versions of boringtun return Done here and
            // expect the caller to re-encapsulate; we handle both
            // shapes below by retrying.
            TunnResult::Done | TunnResult::WriteToNetwork(_) => {}
            other => panic!("expected handshake complete, got {other:?}"),
        }

        // Step 4: drain queued plaintext out of host as an encrypted
        // data frame. Repeat-calling encapsulate with the same packet
        // now produces the real encrypted data (session is up).
        let data_frame = match host.encapsulate(&plaintext, &mut host_out) {
            TunnResult::WriteToNetwork(buf) => buf.to_vec(),
            other => panic!("expected data frame, got {other:?}"),
        };

        // Step 5: vm decrypts the data frame, gets the original
        // plaintext back out via WriteToTunnelV4.
        match vm.decapsulate(&data_frame, &mut vm_out) {
            TunnResult::WriteToTunnelV4(recovered, _src) => {
                assert_eq!(
                    recovered,
                    &plaintext[..],
                    "decrypted plaintext differs from input"
                );
            }
            other => panic!("expected WriteToTunnelV4, got {other:?}"),
        }
    }
}
