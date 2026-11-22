//! DNS-over-SOCKS forwarder for SSH tunnels.
//!
//! `ssh -D` gives a SOCKS5 proxy that carries only TCP, so the system
//! resolver is pointed at a local forwarder which relays every query as
//! DNS-over-TCP (RFC 7766) through that proxy to the upstream resolvers.
//!
//! UDP replies: a DNS-over-TCP answer can exceed what a UDP client accepts.
//! When the query carries no EDNS OPT record the limit is 512 bytes; with
//! EDNS the advertised UDP payload size is honoured (floored at 512 and
//! capped at 1232). A reply over the limit is replaced by header + question
//! with the TC bit set, so the client retries over TCP.
//!
//! Query names are never logged above debug level.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use tracing::debug;

/// Maximum concurrent in-flight queries across UDP and TCP.
const MAX_INFLIGHT: usize = 256;
/// Per-upstream budget (SOCKS connect + query).
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
/// Idle limit while a TCP client sends its next query.
const TCP_IDLE: Duration = Duration::from_secs(10);
/// Maximum concurrent TCP client connections; excess are closed at once.
const MAX_TCP_CONNS: usize = 64;
const HEADER_LEN: usize = 12;
const MAX_UDP_NO_EDNS: usize = 512;
const MAX_UDP_EDNS: usize = 1232;

/// Running forwarder. Dropping it (or `stop`) closes both listeners and
/// aborts every in-flight query.
pub struct DnsForwarder {
    local: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl DnsForwarder {
    /// Bind UDP and TCP on `listen` and relay queries through the SOCKS5
    /// proxy at `socks` to `upstreams` (tried in order, port 53).
    pub async fn start(listen: SocketAddr, socks: SocketAddr, upstreams: Vec<IpAddr>) -> io::Result<DnsForwarder> {
        Self::start_with(listen, socks, upstreams, TCP_IDLE, MAX_TCP_CONNS).await
    }

    async fn start_with(
        listen: SocketAddr,
        socks: SocketAddr,
        upstreams: Vec<IpAddr>,
        tcp_idle: Duration,
        max_tcp: usize,
    ) -> io::Result<DnsForwarder> {
        // With port 0 the UDP socket must reuse the TCP port; retry on the
        // rare clash.
        let attempts = if listen.port() == 0 { 8 } else { 1 };
        let mut last = None;
        let (tcp, udp) = 'bind: {
            for _ in 0..attempts {
                let tcp = TcpListener::bind(listen).await?;
                let mut addr = listen;
                addr.set_port(tcp.local_addr()?.port());
                match UdpSocket::bind(addr).await {
                    Ok(udp) => break 'bind (tcp, udp),
                    Err(e) => last = Some(e),
                }
            }
            return Err(last.unwrap_or_else(|| io::Error::other("bind failed")));
        };
        let local = tcp.local_addr()?;
        let ctx = Arc::new(Ctx {
            socks,
            upstreams,
            permits: Semaphore::new(MAX_INFLIGHT),
            tcp_conns: Arc::new(Semaphore::new(max_tcp)),
            tcp_idle,
        });
        let udp_task = tokio::spawn(udp_loop(Arc::new(udp), ctx.clone()));
        let tcp_task = tokio::spawn(tcp_loop(tcp, ctx));
        Ok(DnsForwarder {
            local,
            tasks: vec![udp_task, tcp_task],
        })
    }

    /// The address both listeners are bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Stop both listeners and abort in-flight queries.
    pub fn stop(self) {}
}

impl Drop for DnsForwarder {
    fn drop(&mut self) {
        // Each listener task owns a JoinSet of its children, so aborting the
        // listener drops (and thereby aborts) all in-flight work.
        for t in &self.tasks {
            t.abort();
        }
    }
}

struct Ctx {
    socks: SocketAddr,
    upstreams: Vec<IpAddr>,
    permits: Semaphore,
    tcp_conns: Arc<Semaphore>,
    tcp_idle: Duration,
}

async fn udp_loop(sock: Arc<UdpSocket>, ctx: Arc<Ctx>) {
    let mut set = JoinSet::new();
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!("dns udp recv: {e}");
                // Avoid a hot loop on persistent errors.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        while set.try_join_next().is_some() {}
        let q = &buf[..n];
        if !is_query(q) {
            continue;
        }
        let Ok(permit) = ctx.permits.try_acquire() else {
            debug!("dns udp: in-flight limit reached, dropping query");
            continue;
        };
        permit.forget();
        let q = q.to_vec();
        let sock = sock.clone();
        let ctx = ctx.clone();
        set.spawn(async move {
            let reply = match resolve(&ctx, &q).await {
                Some(r) => fit_udp(&q, r),
                None => servfail(&q),
            };
            ctx.permits.add_permits(1);
            if let Some(r) = reply {
                let _ = sock.send_to(&r, peer).await;
            }
        });
    }
}

async fn tcp_loop(l: TcpListener, ctx: Arc<Ctx>) {
    let mut set = JoinSet::new();
    loop {
        let (s, _) = match l.accept().await {
            Ok(v) => v,
            Err(e) => {
                debug!("dns tcp accept: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        while set.try_join_next().is_some() {}
        let Ok(conn) = ctx.tcp_conns.clone().try_acquire_owned() else {
            debug!("dns tcp: connection limit reached, closing");
            continue;
        };
        let ctx = ctx.clone();
        set.spawn(async move {
            tcp_conn(s, ctx).await;
            drop(conn);
        });
    }
}

async fn tcp_conn(mut s: TcpStream, ctx: Arc<Ctx>) {
    loop {
        let mut len = [0u8; 2];
        match timeout(ctx.tcp_idle, s.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
        match timeout(ctx.tcp_idle, s.read_exact(&mut q)).await {
            Ok(Ok(_)) if is_query(&q) => {}
            _ => return,
        }
        let Ok(permit) = ctx.permits.try_acquire() else {
            debug!("dns tcp: in-flight limit reached, closing");
            return;
        };
        let reply = resolve(&ctx, &q).await;
        drop(permit);
        let Some(r) = reply else { return };
        let mut out = Vec::with_capacity(r.len() + 2);
        out.extend_from_slice(&(r.len() as u16).to_be_bytes());
        out.extend_from_slice(&r);
        match timeout(ctx.tcp_idle, s.write_all(&out)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
    }
}

/// Try each upstream in order; `None` when all fail.
async fn resolve(ctx: &Ctx, query: &[u8]) -> Option<Vec<u8>> {
    for up in &ctx.upstreams {
        let dst = SocketAddr::new(*up, 53);
        match timeout(UPSTREAM_TIMEOUT, query_upstream(ctx.socks, dst, query)).await {
            Ok(Ok(r)) => return Some(r),
            Ok(Err(e)) => debug!("dns upstream {up}: {e}"),
            Err(_) => debug!("dns upstream {up}: timed out"),
        }
    }
    None
}

async fn query_upstream(socks: SocketAddr, dst: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let mut s = socks5_connect(socks, dst).await?;
    let mut out = Vec::with_capacity(query.len() + 2);
    out.extend_from_slice(&(query.len() as u16).to_be_bytes());
    out.extend_from_slice(query);
    s.write_all(&out).await?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await?;
    let mut r = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut r).await?;
    if r.len() < HEADER_LEN || r[..2] != query[..2] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad dns reply"));
    }
    Ok(r)
}

/// SOCKS5 no-auth CONNECT to `dst` (IPv4 or IPv6 address type) through the
/// proxy at `socks`. Returns the stream, positioned after the reply.
pub async fn socks5_connect(socks: SocketAddr, dst: SocketAddr) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(socks).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut g = [0u8; 2];
    s.read_exact(&mut g).await?;
    if g != [5, 0] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5: no acceptable auth method",
        ));
    }
    let mut req = vec![5, 1, 0];
    match dst.ip() {
        IpAddr::V4(a) => {
            req.push(1);
            req.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            req.push(4);
            req.extend_from_slice(&a.octets());
        }
    }
    req.extend_from_slice(&dst.port().to_be_bytes());
    s.write_all(&req).await?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "socks5: bad version"));
    }
    if h[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("socks5: connect failed (reply {})", h[1]),
        ));
    }
    let skip = match h[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "socks5: bad atyp")),
    };
    let mut bind = vec![0u8; skip];
    s.read_exact(&mut bind).await?;
    Ok(s)
}

/// Minimal validity: a full header and the QR bit clear.
fn is_query(q: &[u8]) -> bool {
    q.len() >= HEADER_LEN && q[2] & 0x80 == 0
}

/// Skip a (possibly compressed) name starting at `i`; returns the offset
/// after it.
fn skip_name(m: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *m.get(i)? as usize;
        if l == 0 {
            return Some(i + 1);
        }
        if l & 0xC0 == 0xC0 {
            m.get(i + 1)?;
            return Some(i + 2);
        }
        i += 1 + l;
    }
}

/// Offset just past the first question, if the message is well formed.
fn question_end(q: &[u8]) -> Option<usize> {
    if u16::from_be_bytes([q[4], q[5]]) == 0 {
        return None;
    }
    let end = skip_name(q, HEADER_LEN)? + 4;
    (end <= q.len()).then_some(end)
}

/// The UDP payload size advertised by the query's EDNS OPT record.
fn edns_udp_size(q: &[u8]) -> Option<usize> {
    let qd = u16::from_be_bytes([q[4], q[5]]) as usize;
    let rrs = u16::from_be_bytes([q[6], q[7]]) as usize
        + u16::from_be_bytes([q[8], q[9]]) as usize
        + u16::from_be_bytes([q[10], q[11]]) as usize;
    let mut i = HEADER_LEN;
    for _ in 0..qd {
        i = skip_name(q, i)? + 4;
    }
    for _ in 0..rrs {
        i = skip_name(q, i)?;
        let hdr = q.get(i..i + 10)?;
        let ty = u16::from_be_bytes([hdr[0], hdr[1]]);
        if ty == 41 {
            return Some(u16::from_be_bytes([hdr[2], hdr[3]]) as usize);
        }
        i += 10 + u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
    }
    None
}

/// Fit a TCP-sourced reply into what the UDP client accepts, truncating
/// (TC bit, header + question only) when it does not.
fn fit_udp(query: &[u8], reply: Vec<u8>) -> Option<Vec<u8>> {
    let limit = match edns_udp_size(query) {
        Some(sz) => sz.clamp(MAX_UDP_NO_EDNS, MAX_UDP_EDNS),
        None => MAX_UDP_NO_EDNS,
    };
    if reply.len() <= limit {
        return Some(reply);
    }
    // Header and question from the query, flags from the reply.
    let mut t = match question_end(query) {
        Some(end) => {
            let mut t = query[..end].to_vec();
            t[4..6].copy_from_slice(&1u16.to_be_bytes());
            t
        }
        None => {
            let mut h = query[..HEADER_LEN].to_vec();
            h[4..6].fill(0);
            h
        }
    };
    t[2] = reply[2] | 0x80 | 0x02;
    t[3] = reply[3];
    t[6..12].fill(0);
    Some(t)
}

/// SERVFAIL built from the query header (and question when parseable).
fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    let mut r = match question_end(query) {
        Some(end) => {
            let mut r = query[..end].to_vec();
            r[4..6].copy_from_slice(&1u16.to_be_bytes());
            r
        }
        None => {
            let mut h = query[..HEADER_LEN].to_vec();
            h[4..6].fill(0);
            h
        }
    };
    // QR=1, keep opcode and RD, RA=1, RCODE=2.
    r[2] = (query[2] & 0x79) | 0x80;
    r[3] = 0x80 | 0x02;
    r[6..12].fill(0);
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};

    fn query(id: u16) -> Vec<u8> {
        let mut q = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        q
    }

    /// Fake DNS-over-TCP server: answers with the query echoed, QR set,
    /// followed by `pad` extra bytes.
    async fn fake_dns(pad: usize) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    q[2] |= 0x80;
                    q.extend(std::iter::repeat_n(0xAB, pad));
                    let _ = s.write_all(&(q.len() as u16).to_be_bytes()).await;
                    let _ = s.write_all(&q).await;
                });
            }
        });
        addr
    }

    /// Minimal SOCKS5 server. `map` sends a destination IP to a real
    /// loopback address, or `None` to refuse with reply code 5.
    async fn fake_socks(map: HashMap<IpAddr, Option<SocketAddr>>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let map = map.clone();
                tokio::spawn(async move {
                    let mut g = [0u8; 3];
                    s.read_exact(&mut g).await.unwrap();
                    assert_eq!(g, [5, 1, 0]);
                    s.write_all(&[5, 0]).await.unwrap();
                    let mut h = [0u8; 4];
                    s.read_exact(&mut h).await.unwrap();
                    assert_eq!(&h[..3], &[5, 1, 0]);
                    let ip: IpAddr = match h[3] {
                        1 => {
                            let mut b = [0u8; 4];
                            s.read_exact(&mut b).await.unwrap();
                            b.into()
                        }
                        4 => {
                            let mut b = [0u8; 16];
                            s.read_exact(&mut b).await.unwrap();
                            b.into()
                        }
                        _ => panic!("bad atyp"),
                    };
                    let mut p = [0u8; 2];
                    s.read_exact(&mut p).await.unwrap();
                    assert_eq!(u16::from_be_bytes(p), 53);
                    let Some(Some(real)) = map.get(&ip).cloned() else {
                        let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                        return;
                    };
                    let Ok(mut up) = TcpStream::connect(real).await else {
                        return;
                    };
                    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                });
            }
        });
        addr
    }

    const UP1: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    const UP2: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

    async fn start(pad: usize, upstreams: Vec<IpAddr>, dead_first: bool) -> DnsForwarder {
        let dns = fake_dns(pad).await;
        let mut map = HashMap::new();
        map.insert(UP1, if dead_first { None } else { Some(dns) });
        map.insert(UP2, Some(dns));
        let socks = fake_socks(map).await;
        DnsForwarder::start("127.0.0.1:0".parse().unwrap(), socks, upstreams)
            .await
            .unwrap()
    }

    async fn udp_ask(f: &DnsForwarder, q: &[u8]) -> Vec<u8> {
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.send_to(q, f.local_addr()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), c.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        buf.truncate(n);
        buf
    }

    #[tokio::test]
    async fn forwards_udp_query_via_socks() {
        let f = start(0, vec![UP1], false).await;
        let r = udp_ask(&f, &query(0x1234)).await;
        assert_eq!(&r[..2], &[0x12, 0x34]);
        assert!(r[2] & 0x80 != 0);
        f.stop();
    }

    #[tokio::test]
    async fn forwards_tcp_query() {
        let f = start(700, vec![UP1], false).await;
        let mut c = TcpStream::connect(f.local_addr()).await.unwrap();
        let q = query(0x4321);
        c.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        c.write_all(&q).await.unwrap();
        let mut len = [0u8; 2];
        c.read_exact(&mut len).await.unwrap();
        let mut r = vec![0u8; u16::from_be_bytes(len) as usize];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(&r[..2], &[0x43, 0x21]);
        assert_eq!(r.len(), q.len() + 700);
        f.stop();
    }

    #[tokio::test]
    async fn falls_back_to_second_upstream() {
        let f = start(0, vec![UP1, UP2], true).await;
        let r = udp_ask(&f, &query(7)).await;
        assert_eq!(&r[..2], &[0, 7]);
        assert_eq!(r[3] & 0x0F, 0, "no error rcode");
        f.stop();
    }

    #[tokio::test]
    async fn all_upstreams_failing_gives_servfail() {
        let f = start(0, vec![UP1], true).await;
        let r = udp_ask(&f, &query(9)).await;
        assert_eq!(&r[..2], &[0, 9]);
        assert_eq!(r[3] & 0x0F, 2);
        f.stop();
    }

    #[tokio::test]
    async fn large_udp_reply_without_edns_is_truncated() {
        let f = start(700, vec![UP1], false).await;
        let q = query(5);
        let r = udp_ask(&f, &q).await;
        assert!(r[2] & 0x02 != 0, "TC set");
        assert_eq!(r.len(), q.len());
        assert_eq!(&r[4..6], &[0, 1]);
        f.stop();
    }

    #[tokio::test]
    async fn large_udp_reply_with_edns_is_passed() {
        let f = start(700, vec![UP1], false).await;
        let mut q = query(6);
        q[11] = 1; // arcount
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]); // 1232
        let r = udp_ask(&f, &q).await;
        assert!(r[2] & 0x02 == 0);
        assert_eq!(r.len(), q.len() + 700);
        f.stop();
    }

    #[tokio::test]
    async fn garbage_is_dropped() {
        let f = start(0, vec![UP1], false).await;
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.send_to(&[1, 2, 3], f.local_addr()).await.unwrap();
        let mut resp = query(1);
        resp[2] |= 0x80; // QR set: not a query
        c.send_to(&resp, f.local_addr()).await.unwrap();
        let mut buf = [0u8; 64];
        assert!(tokio::time::timeout(Duration::from_millis(300), c.recv(&mut buf))
            .await
            .is_err());
        f.stop();
    }

    #[tokio::test]
    async fn stop_releases_the_port() {
        let f = start(0, vec![UP1], false).await;
        let addr = f.local_addr();
        f.stop();
        tokio::time::sleep(Duration::from_millis(100)).await;
        UdpSocket::bind(addr).await.unwrap();
        TcpListener::bind(addr).await.unwrap();
    }

    async fn start_short(idle_ms: u64, max_tcp: usize) -> DnsForwarder {
        let dns = fake_dns(0).await;
        let socks = fake_socks(HashMap::from([(UP1, Some(dns))])).await;
        DnsForwarder::start_with(
            "127.0.0.1:0".parse().unwrap(),
            socks,
            vec![UP1],
            Duration::from_millis(idle_ms),
            max_tcp,
        )
        .await
        .unwrap()
    }

    async fn assert_closed(c: &mut TcpStream) {
        let mut b = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut b))
            .await
            .expect("connection closed in time")
            .unwrap_or(0);
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn stalled_tcp_body_is_closed_within_idle_timeout() {
        let f = start_short(200, 64).await;
        let mut c = TcpStream::connect(f.local_addr()).await.unwrap();
        c.write_all(&[0xFF, 0xFF, 1, 2, 3]).await.unwrap(); // body never completes
        assert_closed(&mut c).await;
        f.stop();
    }

    #[tokio::test]
    async fn tcp_connection_cap_is_enforced() {
        let f = start_short(30_000, 2).await;
        let _a = TcpStream::connect(f.local_addr()).await.unwrap();
        let _b = TcpStream::connect(f.local_addr()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut c = TcpStream::connect(f.local_addr()).await.unwrap();
        assert_closed(&mut c).await;
        f.stop();
    }

    #[test]
    fn truncated_and_servfail_fix_qdcount_with_two_questions() {
        let mut q = query(3);
        q[5] = 2;
        q.extend_from_slice(b"\x05other\x03com\x00\x00\x01\x00\x01");
        let one_q = query(3).len();
        let mut reply = q.clone();
        reply[2] |= 0x80;
        reply.extend(std::iter::repeat_n(0, 600));
        let t = fit_udp(&q, reply).unwrap();
        assert_eq!(t.len(), one_q);
        assert_eq!(&t[4..6], &[0, 1]);
        assert!(t[2] & 0x02 != 0);
        let sf = servfail(&q).unwrap();
        assert_eq!(sf.len(), one_q);
        assert_eq!(&sf[4..6], &[0, 1]);
        assert_eq!(sf[3] & 0x0F, 2);
    }

    #[test]
    fn oversized_reply_with_unparseable_question_gets_header_only_tc() {
        let mut q = vec![0, 8, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&[0x3F, b'a']); // label runs past the end
        let mut reply = q.clone();
        reply[2] |= 0x80;
        reply.extend(std::iter::repeat_n(0, 600));
        let t = fit_udp(&q, reply).unwrap();
        assert_eq!(t.len(), HEADER_LEN);
        assert!(t[2] & 0x02 != 0);
        assert_eq!(&t[4..12], &[0u8; 8]);
        let sf = servfail(&q).unwrap();
        assert_eq!(sf.len(), HEADER_LEN);
        assert_eq!(&sf[4..12], &[0u8; 8]);
    }

    #[tokio::test]
    async fn socks5_connect_rejects_non_success_reply() {
        let socks = fake_socks(HashMap::new()).await;
        let err = socks5_connect(socks, "10.9.9.9:53".parse().unwrap()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }
}
