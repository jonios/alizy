//! Best-effort ICMP echo probes for profile endpoints (the "Ping" column).
//!
//! The GUI runs unprivileged, so probes use Linux *ping sockets*
//! (`SOCK_DGRAM` + `IPPROTO_ICMP`): no root, no raw socket and no `ping`
//! subprocess. Such a socket opens for any user whose group is inside
//! `net.ipv4.ping_group_range` (the default on mainstream distributions).
//!
//! The kernel owns the probe's ICMP id and checksum: `ping_v4_sendmsg` and
//! `ping_v6_sendmsg` rebuild the header with `checksum = 0` (filled in by
//! `ping_*_push_pending_frames`) and `id = inet_sport`, which is also what
//! `ping_rcv` matches replies on — the local port of the socket *is* the id,
//! so the socket is bound to an ephemeral port before connecting.
//!
//! With Alizy's kill switch engaged the output chain rejects ICMP to anything
//! outside the LAN and split-direct ranges. Two shapes were measured against
//! an `nft ... reject with icmpx admin-prohibited` rule:
//!
//! * the rule fires in the local output chain (kill switch engaged): the
//!   reject answers `NF_DROP`, which the kernel turns into `EPERM` on
//!   `send()`, so the probe fails instantly with `blocked`;
//! * the ICMP error arrives after a successful send (a filtered path on the
//!   way): `recv()` fails within microseconds with the mapped errno rather
//!   than waiting out the timeout, because `IP_RECVERR` makes `ping_err`
//!   park the error on the socket for *any* ICMP error, fatal or not.
//!
//! Either way the probe reports what is actually happening on the wire.

use nix::errno::Errno;
use nix::sys::socket::{
    bind, connect, getsockname, recv, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags, SockFlag,
    SockProtocol, SockType, SockaddrStorage,
};
use nix::sys::time::TimeValLike;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Deadline for one probe: send → matching reply.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1000);
/// Probes in flight; each occupies one blocking-pool thread while waiting.
const CONCURRENCY: usize = 16;
/// Addresses tried per host before giving up (dual-stack hosts get two).
const MAX_ADDRS: usize = 3;
const ICMP_HEADER: usize = 8;
const PAYLOAD: usize = 16;
const PAYLOAD_BYTES: [u8; PAYLOAD] = *b"alizy-ping-v1.0!";

static SEQ: AtomicU16 = AtomicU16::new(1);

/// Outcome of one profile's endpoint probe. `latency_ms` and `error` are
/// mutually exclusive: exactly one of them is set.
#[derive(Debug, Clone, Serialize)]
pub struct PingResult {
    pub profile_id: String,
    /// Endpoint host exactly as configured (IP literal or hostname).
    pub host: String,
    /// Round-trip time in milliseconds (at least 1 for a real reply).
    pub latency_ms: Option<u64>,
    /// Short reason when there is no latency: `timeout`, `blocked`,
    /// `unreachable`, `DNS lookup failed: …`, `ICMP sockets are not …`.
    pub error: Option<String>,
}

/// Probe every target concurrently (bounded) and return one result per
/// target, in the order the targets were given. Several profiles pointing at
/// the same server are probed once and share the outcome.
pub async fn ping_all(targets: Vec<(String, String)>) -> Vec<PingResult> {
    if targets.is_empty() {
        return Vec::new();
    }

    let mut hosts: Vec<String> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (_, host) in &targets {
        if !seen.contains_key(host) {
            seen.insert(host.clone(), hosts.len());
            hosts.push(host.clone());
        }
    }

    let sem = Arc::new(Semaphore::new(CONCURRENCY));
    let mut tasks = JoinSet::new();
    for (i, host) in hosts.into_iter().enumerate() {
        let sem = sem.clone();
        tasks.spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return (i, (None, Some("probe cancelled".into()))),
            };
            let probed = host.clone();
            let outcome = tokio::task::spawn_blocking(move || probe_host(&probed))
                .await
                .unwrap_or_else(|e| (None, Some(format!("probe task failed: {e}"))));
            (i, outcome)
        });
    }

    let mut outcomes: Vec<Option<(Option<u64>, Option<String>)>> = vec![None; seen.len()];
    while let Some(joined) = tasks.join_next().await {
        if let Ok((i, outcome)) = joined {
            outcomes[i] = Some(outcome);
        }
    }

    targets
        .into_iter()
        .map(|(profile_id, host)| {
            let (latency_ms, error) = outcomes[seen[host.as_str()]]
                .clone()
                .unwrap_or_else(|| (None, Some("probe did not finish".into())));
            PingResult {
                profile_id,
                host,
                latency_ms,
                error,
            }
        })
        .collect()
}

/// Resolve the host and probe every address it has, first success wins.
fn probe_host(host: &str) -> (Option<u64>, Option<String>) {
    let addrs = match resolve(host) {
        Ok(a) => a,
        Err(err) => return (None, Some(err)),
    };
    let mut last = "no reply".to_string();
    for addr in addrs.iter().take(MAX_ADDRS) {
        match probe(*addr) {
            Ok(latency_ms) => return (Some(latency_ms), None),
            Err(err) => last = err,
        }
    }
    (None, Some(last))
}

/// IP literals skip DNS; hostnames are resolved with the system resolver.
fn resolve(host: &str) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let mut addrs: Vec<IpAddr> = (host, 0u16)
        .to_socket_addrs()
        .map_err(|e| format!("DNS lookup failed: {e}"))?
        .map(|a| a.ip())
        .collect();
    if addrs.is_empty() {
        return Err("DNS returned no addresses".into());
    }
    // Prefer IPv4: WireGuard endpoints are usually v4-only on the wire.
    addrs.sort_by_key(|ip| u8::from(!ip.is_ipv4()));
    addrs.dedup();
    Ok(addrs)
}

/// One probe: bind an ephemeral port, connect, send an echo request and wait
/// for the matching reply. Returns the round trip in milliseconds.
fn probe(dst: IpAddr) -> Result<u64, String> {
    let v6 = dst.is_ipv6();
    let (family, proto) = if v6 {
        (AddressFamily::Inet6, SockProtocol::IcmpV6)
    } else {
        (AddressFamily::Inet, SockProtocol::Icmp)
    };
    let fd = open_socket(family, proto)?;

    setsockopt(
        &fd,
        sockopt::ReceiveTimeout,
        &TimeValLike::milliseconds(PROBE_TIMEOUT.as_millis() as i64),
    )
    .map_err(|e| e.to_string())?;
    // Surface ICMP errors (kill-switch "admin prohibited", no route, …)
    // straight away instead of waiting for the timeout.
    let _ = if v6 {
        setsockopt(&fd, sockopt::Ipv6RecvErr, &true)
    } else {
        setsockopt(&fd, sockopt::Ipv4RecvErr, &true)
    };

    // The local port doubles as the ICMP id (`ping_bind` → `ping_get_port`).
    let unspec = SocketAddr::new(
        if v6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        },
        0,
    );
    bind(fd.as_raw_fd(), &SockaddrStorage::from(unspec)).map_err(sock_err)?;
    connect(fd.as_raw_fd(), &SockaddrStorage::from(SocketAddr::new(dst, 0))).map_err(sock_err)?;

    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let request = echo_request(local_port(&fd), seq, v6);
    let started = Instant::now();
    send(fd.as_raw_fd(), &request, MsgFlags::empty()).map_err(sock_err)?;

    let mut buf = [0u8; 64];
    loop {
        if started.elapsed() >= PROBE_TIMEOUT {
            return Err("timeout".into());
        }
        let n = match recv(fd.as_raw_fd(), &mut buf, MsgFlags::empty()) {
            Ok(n) => n,
            Err(err) => return Err(sock_err(err)),
        };
        if let Some(latency_ms) = echo_reply(&buf[..n], seq, v6, started) {
            return Ok(latency_ms);
        }
        // Anything else (an unrelated or truncated packet): keep waiting,
        // bounded by the deadline above.
    }
}

fn open_socket(family: AddressFamily, proto: SockProtocol) -> Result<OwnedFd, String> {
    socket(family, SockType::Datagram, SockFlag::empty(), proto).map_err(|e| match e {
        Errno::EACCES | Errno::EPERM => {
            "ICMP sockets are not permitted for this user (net.ipv4.ping_group_range)".into()
        }
        Errno::EAFNOSUPPORT | Errno::EPROTONOSUPPORT => "ICMP is not supported".into(),
        other => other.to_string(),
    })
}

fn local_port(fd: &OwnedFd) -> u16 {
    getsockname::<SockaddrStorage>(fd.as_raw_fd())
        .ok()
        .and_then(|a| {
            a.as_sockaddr_in()
                .map(|s| s.port())
                .or_else(|| a.as_sockaddr_in6().map(|s| s.port()))
        })
        .unwrap_or(0)
}

fn sock_err(err: Errno) -> String {
    match err {
        Errno::EAGAIN => "timeout".into(),
        // A local nftables `reject` (Alizy's kill switch) drops the echo in
        // the output chain: nft answers NF_DROP, which the kernel surfaces as
        // EPERM on send(). Also the permission error of socket() itself.
        Errno::EACCES | Errno::EPERM => "blocked".into(),
        // An ICMP error that came back after the send — admin prohibited, no
        // route, host down, port refused — mapped from the ICMP code by
        // `ping_err` (e.g. "communication administratively prohibited" and
        // "host prohibited" both become EHOSTUNREACH).
        Errno::EHOSTUNREACH
        | Errno::ENETUNREACH
        | Errno::ENETDOWN
        | Errno::EHOSTDOWN
        | Errno::ECONNREFUSED
        | Errno::ECONNRESET
        | Errno::EPIPE => "unreachable".into(),
        Errno::EAFNOSUPPORT | Errno::EPROTONOSUPPORT => "ICMP is not supported".into(),
        other => other.to_string(),
    }
}

/// Echo request: type/code/sequence and payload are ours; the id and the
/// checksum are rewritten by the kernel (`ping_*_sendmsg`), but both are
/// filled in correctly so the packet stays valid if that ever changes.
fn echo_request(id: u16, seq: u16, v6: bool) -> Vec<u8> {
    let mut pkt = vec![0u8; ICMP_HEADER + PAYLOAD];
    pkt[0] = if v6 { 128 } else { 8 }; // echo request / echo request6
    pkt[1] = 0; // code
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt[ICMP_HEADER..].copy_from_slice(&PAYLOAD_BYTES);
    if !v6 {
        // IPv4: ours must match the packet as it stands, because the kernel
        // folds its checksum over this very header. IPv6 always carries a
        // pseudo-header and is computed by the kernel (left at zero here).
        let sum = checksum(&pkt);
        pkt[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    pkt
}

/// Matching echo reply → round trip in milliseconds, otherwise `None`.
fn echo_reply(buf: &[u8], seq: u16, v6: bool, started: Instant) -> Option<u64> {
    if buf.len() < ICMP_HEADER {
        return None;
    }
    let reply_type = if v6 { 129 } else { 0 };
    if buf[0] != reply_type || buf[1] != 0 {
        return None;
    }
    if u16::from_be_bytes([buf[6], buf[7]]) != seq {
        return None;
    }
    // Round to the nearest millisecond, but never show 0 for a real reply.
    let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    Some(((micros + 500) / 1000).max(1))
}

/// Internet checksum (RFC 1071) as used by ICMP.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (words, remainder) = data.as_chunks::<2>();
    for c in words {
        sum += u32::from(u16::from_be_bytes(*c));
    }
    for &b in remainder {
        sum += u32::from(b) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_carries_type_sequence_and_a_valid_checksum() {
        let pkt = echo_request(0x1234, 7, false);
        assert_eq!(pkt.len(), ICMP_HEADER + PAYLOAD);
        assert_eq!(pkt[0], 8, "IPv4 echo request type");
        assert_eq!(pkt[1], 0);
        assert_eq!(&pkt[4..6], &0x1234u16.to_be_bytes());
        assert_eq!(&pkt[6..8], &7u16.to_be_bytes());
        assert_eq!(&pkt[ICMP_HEADER..], &PAYLOAD_BYTES);
        // The stored checksum is the one of the packet it sits in.
        let mut zeroed = pkt.clone();
        zeroed[2..4].copy_from_slice(&[0, 0]);
        assert_eq!(checksum(&zeroed), u16::from_be_bytes([pkt[2], pkt[3]]));
        assert_ne!(pkt[2] | pkt[3], 0, "checksum should not be zero");
    }

    #[test]
    fn ipv6_request_leaves_the_checksum_to_the_kernel() {
        let pkt = echo_request(0x1234, 7, true);
        assert_eq!(pkt[0], 128, "IPv6 echo request type");
        assert_eq!(&pkt[2..4], &[0, 0], "kernel computes the ICMPv6 checksum");
    }

    #[test]
    fn replies_are_matched_by_type_and_sequence() {
        let started = Instant::now();
        let mut reply = echo_request(0, 42, false);
        reply[0] = 0; // echo reply
        assert!(echo_reply(&reply, 42, false, started).is_some());

        assert!(echo_reply(&reply, 43, false, started).is_none(), "wrong seq");
        reply[0] = 3; // destination unreachable
        assert!(echo_reply(&reply, 42, false, started).is_none(), "wrong type");
        assert!(echo_reply(&reply[..4], 42, false, started).is_none(), "truncated");

        let mut v6 = echo_request(0, 42, true);
        v6[0] = 129; // echo reply6
        assert!(echo_reply(&v6, 42, true, started).is_some());
        assert!(echo_reply(&v6, 42, false, started).is_none(), "v6 reply on a v4 probe");
    }

    #[test]
    fn loopback_replies() {
        // End-to-end check of the whole socket path (bind, connect, send, recv).
        let latency = probe(IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("loopback replies");
        assert!(latency >= 1, "sub-millisecond round trips are reported as 1");
    }

    #[test]
    fn ip_literals_skip_dns_and_bogus_names_fail_cleanly() {
        assert_eq!(resolve("1.1.1.1").unwrap(), vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        assert!(resolve("definitely-not-a-host.invalid")
            .unwrap_err()
            .starts_with("DNS lookup failed"));
    }

    #[test]
    fn blackhole_reports_a_timeout() {
        // TEST-NET-1: no host answers, so the probe must not hang forever. A
        // router on the way may answer "host unreachable" instead of staying silent.
        let started = Instant::now();
        let err = probe(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).unwrap_err();
        assert!(err == "timeout" || err == "unreachable", "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn ping_all_covers_every_target_in_order_and_shares_hosts() {
        let results = ping_all(vec![
            ("profile-a".into(), "127.0.0.1".into()),
            ("profile-b".into(), "127.0.0.1".into()), // same server as A
            ("profile-c".into(), "192.0.2.1".into()), // TEST-NET-1, no answer
        ])
        .await;

        assert_eq!(
            results.iter().map(|r| r.profile_id.as_str()).collect::<Vec<_>>(),
            ["profile-a", "profile-b", "profile-c"],
            "one result per target, in the order given"
        );
        assert!(results[0].latency_ms.unwrap_or(0) >= 1, "loopback answers: {results:?}");
        assert_eq!(
            results[1].latency_ms, results[0].latency_ms,
            "shared host, shared outcome"
        );
        assert!(results[1].latency_ms.is_some() && results[1].error.is_none());
        assert_eq!(results[2].latency_ms, None);
        assert!(
            matches!(results[2].error.as_deref(), Some("timeout" | "unreachable")),
            "{:?}",
            results[2]
        );
    }

    #[tokio::test]
    async fn ping_all_with_no_targets_is_empty() {
        assert!(ping_all(Vec::new()).await.is_empty());
    }
}
