//! Dedicated loopback addresses for TCP-mode entries.
//!
//! HTTP entries all share portman's `127.0.0.1:80`/`:443` proxy and route by
//! `Host:` header. TCP entries can't: raw protocols carry no host, and two
//! databases routinely share a port (two Postgres on `5432`, two MySQL on
//! `3306`). So each TCP host gets its own address inside `127.0.0.0/8` and
//! portman fronts it there, preserving the target port so connection strings
//! (`pg.pacer.internal:5432`) don't change.
//!
//! Loopback is never routed off-host, so these routes survive a VPN/exit-node
//! that captures the container's RFC1918 subnet — which is the whole reason
//! for fronting them instead of answering DNS with the raw container IP.
//!
//! Assignments live for the daemon's lifetime and are deliberately *not*
//! persisted: clients always re-resolve by hostname (short DNS TTL), so the
//! concrete address is an internal detail that can change across restarts.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

/// First address handed out. `127.0.0.1` is left alone so portman never
/// shadows a service already bound to plain localhost.
const FIRST_ADDR: u32 = 0x7F00_0002; // 127.0.0.2

/// Cloneable handle to the shared host → loopback-address map. All clones
/// point at the same allocation table, so the DNS server and the TCP
/// forwarder always agree on which address a host answers to.
#[derive(Debug, Default, Clone)]
pub struct LoopbackAllocator {
    inner: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
}

impl LoopbackAllocator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Address currently assigned to `host`, or `None` if it has never been
    /// assigned. Pure read — never mutates.
    pub fn get(&self, host: &str) -> Option<Ipv4Addr> {
        self.map().get(host).copied()
    }

    /// Address for `host`, assigning the next free `127.0.0.0/8` address the
    /// first time it's seen. Stable for the daemon's lifetime.
    pub fn get_or_assign(&self, host: &str) -> Ipv4Addr {
        let mut map = self.map();
        if let Some(ip) = map.get(host) {
            return *ip;
        }
        let ip = next_free(&map);
        map.insert(host.to_string(), ip);
        ip
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, Ipv4Addr>> {
        self.inner.lock().expect("loopback allocator lock poisoned")
    }
}

/// Lowest `127.0.0.0/8` address not already handed out, skipping `.0`/`.255`
/// in the final octet and `127.0.0.1`.
fn next_free(map: &HashMap<String, Ipv4Addr>) -> Ipv4Addr {
    let taken: HashSet<Ipv4Addr> = map.values().copied().collect();
    let mut candidate = FIRST_ADDR;
    loop {
        let ip = Ipv4Addr::from(candidate);
        let last = candidate & 0xFF;
        if last != 0 && last != 255 && !taken.contains(&ip) {
            return ip;
        }
        candidate = candidate.wrapping_add(1);
        // Stay inside 127/8. Exhausting 16M addresses is impossible in
        // practice; wrap defensively rather than leave 127/8.
        if candidate >> 24 != 127 {
            candidate = FIRST_ADDR;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_is_stable_per_host() {
        let alloc = LoopbackAllocator::new();
        let first = alloc.get_or_assign("pg.pacer.internal");
        let second = alloc.get_or_assign("pg.pacer.internal");
        assert_eq!(first, second);
    }

    #[test]
    fn distinct_hosts_get_distinct_addresses() {
        let alloc = LoopbackAllocator::new();
        let a = alloc.get_or_assign("pg.pacer.internal");
        let b = alloc.get_or_assign("pg.acme.internal");
        assert_ne!(a, b);
    }

    #[test]
    fn never_hands_out_localhost() {
        let alloc = LoopbackAllocator::new();
        for i in 0..64 {
            let ip = alloc.get_or_assign(&format!("db-{i}.test"));
            assert_ne!(ip, Ipv4Addr::LOCALHOST);
            assert!(ip.is_loopback());
        }
    }

    #[test]
    fn get_does_not_assign() {
        let alloc = LoopbackAllocator::new();
        assert_eq!(alloc.get("db.test"), None);
        let ip = alloc.get_or_assign("db.test");
        assert_eq!(alloc.get("db.test"), Some(ip));
    }

    #[test]
    fn skips_zero_and_broadcast_final_octet() {
        // 127.0.0.2 .. 127.0.0.254 is 253 usable addresses before .255 is
        // skipped and we roll into 127.0.1.x. Assign enough to cross it.
        let alloc = LoopbackAllocator::new();
        for i in 0..300 {
            let ip = alloc.get_or_assign(&format!("h-{i}.test"));
            let octets = ip.octets();
            assert_ne!(octets[3], 0);
            assert_ne!(octets[3], 255);
        }
    }
}
