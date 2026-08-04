//! Phase B.0 smoke test: does `boringtun` link and generate valid
//! WireGuard keypairs against the OS RNG? One-shot utility; prints
//! both peers' keys + the shared subnet constants.
//!
//! Run: `cargo run -p portman-netbridge --example tunnel_keygen`
//!
//! Nothing network-touching happens here — it's a pure keygen demo
//! that validates the boringtun integration before B.1 starts opening
//! sockets and utun devices.

use portman_netbridge::tunnel::{
    Keypair, CONTAINER_IP_POOL_END, CONTAINER_IP_POOL_START, HOST_TUNNEL_IP, HOST_WG_LISTEN_PORT,
    PORTMAN_SUBNET_CIDR, RESERVED_HOST_FACING_IP, TUNNEL_MTU, VM_TUNNEL_IP,
};

fn main() {
    let host = Keypair::generate();
    let vm = Keypair::generate();

    println!("portman-netbridge — Phase B.0 keygen smoke test\n");
    println!("subnet           : {PORTMAN_SUBNET_CIDR}");
    println!("host tunnel IP   : {HOST_TUNNEL_IP}");
    println!("VM tunnel IP     : {VM_TUNNEL_IP}");
    println!("reserved (c2h)   : {RESERVED_HOST_FACING_IP}");
    println!(
        "container pool   : {CONTAINER_IP_POOL_START} … {CONTAINER_IP_POOL_END} ({} slots)",
        usize::from(CONTAINER_IP_POOL_END.octets()[3])
            - usize::from(CONTAINER_IP_POOL_START.octets()[3])
            + 1
    );
    println!("host UDP port    : {HOST_WG_LISTEN_PORT}");
    println!("tunnel MTU       : {TUNNEL_MTU}");
    println!();
    println!("host public key  : {}", host.public_base64());
    println!("VM public key    : {}", vm.public_base64());
    println!();
    println!("(secrets not printed — handling them only happens via");
    println!(" `Keypair::secret_base64()` at the exact moment we hand");
    println!(" them to a trusted counterparty, never before.)");
}
