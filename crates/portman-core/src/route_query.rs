//! The question that the bridge health and `portman doctor` put to macOS
//! `route(8)` about a Docker subnet.

/// The arguments for `/sbin/route` that ask which route carries the network
/// address of the IPv4 subnet `cidr`.
pub fn carrying_route_query(cidr: &str) -> [&str; 3] {
    let network_address = cidr.split_once('/').map_or(cidr, |(address, _)| address);
    ["-n", "get", network_address]
}
