//! The question that the bridge health and `portman doctor` put to macOS
//! `route(8)` about a Docker subnet.

/// The arguments for `/sbin/route` that ask which route carries the network
/// address of the IPv4 subnet `cidr`.
///
/// `-host` makes the kernel take the longest match for the address. A route
/// to a wider prefix answers too, as the bridge's `192.168.99.0/24` does for
/// the `portman` network `192.168.99.128/25`. Without `-host`, `route` reads
/// an address whose host part is zero as a network and gives it a mask of
/// its own, `255.255.255.0` for `192.168.16.0`. The kernel then looks for a
/// route to exactly that prefix, and answers with the default route when
/// the subnet is `192.168.16.0/20`.
pub fn carrying_route_query(cidr: &str) -> [&str; 4] {
    let network_address = cidr.split_once('/').map_or(cidr, |(address, _)| address);
    ["-n", "get", "-host", network_address]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_question_for_a_subnet_names_its_network_address_as_a_host() {
        assert_eq!(
            carrying_route_query("192.168.16.0/20").join(" "),
            "-n get -host 192.168.16.0"
        );
    }
}
