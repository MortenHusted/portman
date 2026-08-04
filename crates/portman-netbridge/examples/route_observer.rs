//! Phase A — first primitive of the v1 Rust bridge port.
//!
//! Opens a read-only `PF_ROUTE` socket and streams route-table changes
//! from the macOS kernel. Use this to watch the chipmk bridge's boot add
//! `172.17.0.0/16 → utun0`, or to watch any route event live (e.g. the
//! `configd`-induced route flush when you change system DNS).
//!
//! **This is observation-only.** The socket is never written to, no
//! route is ever added or removed. Safe to run alongside the v0 stack.
//!
//! Run: `cargo run -p portman-netbridge --example route_observer`
//!
//! In another terminal, trigger a route event to see output:
//! - `sudo route add -net 10.99.99.0/24 127.0.0.1` (add a synthetic route)
//! - `sudo route delete -net 10.99.99.0/24` (remove it)
//! - Start/stop colima to see the chipmk bridge's 172.17/172.18 routes
//!   come and go.
//!
//! Parses just enough of `rt_msghdr` to print `type`, `seq`, `errno`, and
//! — when present — the destination AF_INET address. Not a full parser;
//! real consumer will move into `src/route_observer.rs` with a proper
//! event type and a tokio channel. This example exists to validate the
//! primitive works against real macOS routing traffic before committing
//! to the richer API shape.

// PF_ROUTE requires raw socket + manual struct parsing. Concentrated in
// this one file until the `route_observer` module takes it over.
#![allow(unsafe_code)]

#[cfg(target_os = "macos")]
use std::io;
#[cfg(target_os = "macos")]
use std::mem::size_of;
#[cfg(target_os = "macos")]
use std::net::Ipv4Addr;
#[cfg(target_os = "macos")]
use std::os::fd::{FromRawFd, OwnedFd};

// macOS `rt_msghdr` fixed-size prefix (see <net/route.h>). We only touch
// bytes up through `rtm_addrs` (offset 12..16). Structure lengths after
// that (pid, seq, errno, use, inits, rmx) are derived from rtm_msglen
// for bounds checking — we don't need their exact layout here.
#[cfg(target_os = "macos")]
const RTM_HEADER_FIXED: usize = 16;

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("route_observer is only available on macOS");
}

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    // On a busy Mac the kernel emits dozens of RTM_MISS (failed-lookup)
    // events per second — useful to see the socket firing, noisy for
    // route-change observation. Gate them behind an env flag.
    let show_miss = std::env::var_os("PORTMAN_ROUTE_OBSERVER_VERBOSE").is_some();

    // AF_ROUTE raw socket: delivers every routing-table and interface
    // change event the kernel emits. Unprivileged read access — no sudo.
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // Wrap in OwnedFd so the socket is closed automatically on return.
    let _owned = unsafe { OwnedFd::from_raw_fd(fd) };

    eprintln!("route_observer: PF_ROUTE socket open. Streaming events. ^C to quit.");
    eprintln!("(trigger a test event in another terminal, e.g.:");
    eprintln!("   sudo route add -net 10.99.99.0/24 127.0.0.1 && \\");
    eprintln!("   sudo route delete -net 10.99.99.0/24 )\n");

    // Routing messages fit easily in 2 KiB on macOS; kernel never emits
    // larger. If we ever see a short read at this boundary it's a signal
    // to grow, not a correctness issue.
    let mut buf = [0u8; 2048];

    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }
        let n = n as usize;
        if n < RTM_HEADER_FIXED {
            eprintln!("short read ({n} bytes) — skipping");
            continue;
        }
        print_message(&buf[..n], show_miss);
    }
}

/// Parse + print the small subset of rt_msghdr we care about for
/// the Phase A observation example.
#[cfg(target_os = "macos")]
fn print_message(msg: &[u8], show_miss: bool) {
    // Offsets per <net/route.h> on Darwin:
    //   u_short rtm_msglen;  // 0..2
    //   u_char  rtm_version; // 2
    //   u_char  rtm_type;    // 3
    //   u_short rtm_index;   // 4..6
    //   u_short _pad;        // 6..8  (alignment to int boundary)
    //   int     rtm_flags;   // 8..12
    //   int     rtm_addrs;   // 12..16   (bitmask: which sockaddrs follow)
    let msglen = u16::from_ne_bytes([msg[0], msg[1]]);
    let rtm_type = msg[3];
    let rtm_addrs = i32::from_ne_bytes([msg[12], msg[13], msg[14], msg[15]]);

    if !show_miss && rtm_type as i32 == libc::RTM_MISS {
        return;
    }

    let type_name = type_to_str(rtm_type);
    let dst = extract_dst(msg, rtm_addrs).unwrap_or_else(|| "-".to_string());

    println!(
        "{:>8}  len={msglen:<4}  dst={dst}  addrs_mask=0x{rtm_addrs:02x}",
        type_name
    );
}

#[cfg(target_os = "macos")]
fn type_to_str(t: u8) -> &'static str {
    // libc exposes these constants on Darwin; enumerate the ones we see
    // most often and fall through for anything unusual.
    match t as i32 {
        libc::RTM_ADD => "ADD",
        libc::RTM_DELETE => "DELETE",
        libc::RTM_CHANGE => "CHANGE",
        libc::RTM_GET => "GET",
        libc::RTM_LOSING => "LOSING",
        libc::RTM_REDIRECT => "REDIR",
        libc::RTM_MISS => "MISS",
        libc::RTM_LOCK => "LOCK",
        libc::RTM_NEWADDR => "NEWADDR",
        libc::RTM_DELADDR => "DELADDR",
        libc::RTM_IFINFO => "IFINFO",
        libc::RTM_NEWMADDR => "NEWMADDR",
        libc::RTM_DELMADDR => "DELMADDR",
        _ => "?",
    }
}

/// If the message carries an RTA_DST sockaddr and it's AF_INET, return
/// the dotted-quad. Otherwise `None`. Doesn't walk other addresses;
/// this is deliberately shallow (goal: show something useful in the CLI
/// output, not a full parser).
#[cfg(target_os = "macos")]
fn extract_dst(msg: &[u8], rtm_addrs: i32) -> Option<String> {
    // RTA_DST is bit 0. If it's not set, the destination isn't in the
    // trailing payload at all.
    if rtm_addrs & libc::RTA_DST == 0 {
        return None;
    }
    // On Darwin the rt_msghdr is 92 bytes (16 fixed + pid/seq/errno/use
    // = 16 more + inits = 4 + rt_metrics = 56). But the kernel reports
    // the true header size in nothing we can read directly; the rest of
    // the message is packed sockaddrs starting at byte 92 for rt_msghdr
    // and at 20 for if_msghdr. For this example we assume rt_msghdr and
    // skip past 92. A real parser branches on rtm_type.
    const RT_MSGHDR_SIZE: usize = 92;
    if msg.len() <= RT_MSGHDR_SIZE + 2 {
        return None;
    }
    let sa = &msg[RT_MSGHDR_SIZE..];
    let sa_len = sa[0] as usize;
    let sa_family = sa[1];
    if sa_len < size_of::<libc::sockaddr_in>() || sa_family as i32 != libc::AF_INET {
        return None;
    }
    // sockaddr_in { u8 sin_len, u8 sin_family, u16 sin_port, in_addr sin_addr, ... }
    // sin_addr starts at offset 4. Stored network-byte-order.
    let addr = Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]);
    Some(addr.to_string())
}
