//! The question that the bridge health and `portman doctor` put to macOS
//! `route(8)` about a Docker subnet.

/// The arguments for `/sbin/route` that ask which route carries the network
/// address of the IPv4 subnet `cidr`.
pub fn carrying_route_query(cidr: &str) -> [&str; 3] {
    let network_address = cidr.split_once('/').map_or(cidr, |(address, _)| address);
    ["-n", "get", network_address]
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
