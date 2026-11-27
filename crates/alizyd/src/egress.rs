//! How Alizy's own proxies (LAN sharing, and proxy mode's local proxy) reach
//! the internet. The engine sets one [`Egress`] for the current mode and
//! tunnel; every proxy connection reads it at connect time.
//!
//! Proxy mode must never fall back to a direct connection: without a
//! connected tunnel the egress is [`Egress::Blocked`], and marked sockets are
//! additionally fenced in by the firewall's proxy guard.

use alizy_core::dnswire::{build_query, parse_response, WireError, TYPE_A, TYPE_AAAA};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Egress {
    /// Ordinary sockets; the system's routing decides (tunnel mode).
    /// `udp` is false when the active tunnel cannot carry UDP.
    System { udp: bool },
    /// Refuse every connection (proxy mode without a connected tunnel).
    Blocked,
    /// Sockets marked `mark`, which only the tunnel's routing table carries.
    /// Names are resolved over TCP through the tunnel's DNS servers.
    Marked { mark: u32, dns: Vec<IpAddr> },
    /// Through the SOCKS5 proxy at a loopback address (`ssh -D`); names are
    /// resolved on the far side. TCP only.
    Socks(SocketAddr),
}

impl Egress {
    pub fn udp(&self) -> bool {
        matches!(self, Self::System { udp: true } | Self::Marked { .. })
    }
}

/// Shared, cheaply readable current egress.
#[derive(Clone)]
pub struct EgressHandle(Arc<RwLock<Arc<Egress>>>);

impl Default for EgressHandle {
    fn default() -> Self {
        Self::new(Egress::System { udp: true })
    }
}

impl EgressHandle {
    pub fn new(e: Egress) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(e))))
    }

    pub fn get(&self) -> Arc<Egress> {
        self.0.read().unwrap().clone()
    }

    /// Returns whether it changed.
    pub fn set(&self, e: Egress) -> bool {
        let mut g = self.0.write().unwrap();
        if **g == e {
            return false;
        }
        *g = Arc::new(e);
        true
    }
}

fn blocked() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "the VPN is not connected; Alizy's proxy never connects directly",
    )
}

/// Resolve `host` and connect over TCP, trying every address, within one budget.
pub async fn connect_tcp(e: &Egress, host: &str, port: u16) -> io::Result<TcpStream> {
    match e {
        Egress::Blocked => Err(blocked()),
        Egress::Socks(socks) => timeout(CONNECT_TIMEOUT, socks5_connect(*socks, host, port))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))?,
        Egress::System { .. } | Egress::Marked { .. } => {
            let addrs = resolve(e, host, port).await?;
            let mark = match e {
                Egress::Marked { mark, .. } => Some(*mark),
                _ => None,
            };
            let mut last = None;
            for addr in addrs {
                match timeout(CONNECT_TIMEOUT, tcp(addr, mark)).await {
                    Ok(Ok(s)) => return Ok(s),
                    Ok(Err(e)) => last = Some(e),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
                }
            }
            Err(last.unwrap_or_else(|| io::Error::other(format!("no address for {host}"))))
        }
    }
}

/// Addresses for `host:port` the way this egress resolves names.
pub async fn resolve(e: &Egress, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    match e {
        Egress::Blocked => Err(blocked()),
        Egress::Socks(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "names are resolved by the SOCKS server",
        )),
        Egress::System { .. } => {
            let it = timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "name resolution timed out"))?
                .map_err(|e| io::Error::other(format!("cannot resolve {host}: {e}")))?;
            Ok(it.collect())
        }
        Egress::Marked { mark, dns } => {
            let ips = timeout(CONNECT_TIMEOUT, marked_lookup(dns, *mark, host))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "name resolution timed out"))??;
            Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
        }
    }
}

/// An unconnected UDP socket for relaying to `family_of`'s address family.
pub fn udp_socket(e: &Egress, family_of: &SocketAddr) -> io::Result<UdpSocket> {
    let bind: SocketAddr = if family_of.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    match e {
        Egress::System { udp: true } => {}
        Egress::Marked { .. } => {}
        Egress::Blocked => return Err(blocked()),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this tunnel cannot carry UDP",
            ))
        }
    }
    let s = std::net::UdpSocket::bind(bind)?;
    if let Egress::Marked { mark, .. } = e {
        set_mark(&s, *mark)?;
    }
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s)
}

fn set_mark(fd: &impl std::os::fd::AsFd, mark: u32) -> io::Result<()> {
    nix::sys::socket::setsockopt(fd, nix::sys::socket::sockopt::Mark, &mark).map_err(io::Error::from)
}

async fn tcp(addr: SocketAddr, mark: Option<u32>) -> io::Result<TcpStream> {
    let sock = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(m) = mark {
        set_mark(&sock, m)?;
    }
    sock.connect(addr).await
}

/// A and AAAA through the tunnel's resolvers, from marked sockets: UDP, and
/// TCP when the answer is truncated (as the daemon's main resolver does).
async fn marked_lookup(dns: &[IpAddr], mark: u32, host: &str) -> io::Result<Vec<IpAddr>> {
    let mut last = io::Error::other("no DNS server for the tunnel");
    for server in dns {
        let server = SocketAddr::new(*server, 53);
        let (a, aaaa) = tokio::join!(
            dns_query(server, mark, host, TYPE_A),
            dns_query(server, mark, host, TYPE_AAAA)
        );
        let mut out: Vec<IpAddr> = Vec::new();
        for v in [&a, &aaaa].into_iter().flatten() {
            out.extend(v);
        }
        if !out.is_empty() {
            return Ok(out);
        }
        match (a, aaaa) {
            (Err(e), _) | (_, Err(e)) => last = e,
            _ => last = io::Error::other(format!("{host} has no address")),
        }
    }
    Err(last)
}

async fn dns_query(server: SocketAddr, mark: u32, name: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    match dns_udp(server, mark, name, qtype).await? {
        Some(v) => Ok(v),
        None => dns_tcp(server, mark, name, qtype).await,
    }
}

/// `None` when the answer was truncated.
async fn dns_udp(server: SocketAddr, mark: u32, name: &str, qtype: u16) -> io::Result<Option<Vec<IpAddr>>> {
    let fut = async {
        let id = rand_id();
        let q = build_query(id, name, qtype).map_err(|e| io::Error::other(e.to_string()))?;
        let s = std::net::UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
        set_mark(&s, mark)?;
        s.set_nonblocking(true)?;
        let s = UdpSocket::from_std(s)?;
        s.connect(server).await?;
        s.send(&q).await?;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = s.recv(&mut buf).await?;
            match parse_response(&buf[..n], id, name, qtype) {
                Ok(a) => return Ok(Some(a.addrs.into_iter().map(|(ip, _)| ip).collect())),
                // Spoofed or unrelated datagram: keep waiting until the deadline.
                Err(WireError::Mismatch) => continue,
                Err(WireError::Truncated) => return Ok(None),
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
    };
    timeout(DNS_TIMEOUT, fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS timed out"))?
}

async fn dns_tcp(server: SocketAddr, mark: u32, name: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    let fut = async {
        let id = rand_id();
        let q = build_query(id, name, qtype).map_err(|e| io::Error::other(e.to_string()))?;
        let mut s = tcp(server, Some(mark)).await?;
        s.write_all(&(q.len() as u16).to_be_bytes()).await?;
        s.write_all(&q).await?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).await?;
        let a = parse_response(&buf, id, name, qtype).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(a.addrs.into_iter().map(|(ip, _)| ip).collect())
    };
    timeout(DNS_TIMEOUT, fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS timed out"))?
}

fn rand_id() -> u16 {
    let mut b = [0u8; 2];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    u16::from_ne_bytes(b)
}

/// SOCKS5 no-auth CONNECT to `host:port` (IP literal or domain name).
pub async fn socks5_connect(socks: SocketAddr, host: &str, port: u16) -> io::Result<TcpStream> {
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
    match host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.octets());
        }
        Ok(IpAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.octets());
        }
        Err(_) => {
            let n = host.as_bytes();
            if n.is_empty() || n.len() > 255 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid host name"));
            }
            req.push(3);
            req.push(n.len() as u8);
            req.extend_from_slice(n);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "socks5: bad version"));
    }
    if h[1] != 0 {
        let kind = match h[1] {
            5 => io::ErrorKind::ConnectionRefused,
            6 => io::ErrorKind::TimedOut,
            _ => io::ErrorKind::Other,
        };
        return Err(io::Error::new(kind, format!("socks5: connect failed (reply {})", h[1])));
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn blocked_never_connects() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let e = connect_tcp(&Egress::Blocked, "127.0.0.1", port).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(udp_socket(&Egress::Blocked, &"1.1.1.1:53".parse().unwrap()).is_err());
        assert!(!Egress::Blocked.udp() && !Egress::Socks("127.0.0.1:1".parse().unwrap()).udp());
        assert!(!Egress::System { udp: false }.udp() && Egress::System { udp: true }.udp());
    }

    #[tokio::test]
    async fn system_connects_directly() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        connect_tcp(&Egress::System { udp: true }, "127.0.0.1", port)
            .await
            .unwrap();
    }

    /// A tiny SOCKS5 server that records the requested target and then echoes.
    async fn fake_socks() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            c.read_exact(&mut g).await.unwrap();
            c.write_all(&[5, 0]).await.unwrap();
            let mut h = [0u8; 5];
            c.read_exact(&mut h).await.unwrap();
            let mut name = vec![0u8; h[4] as usize + 2];
            c.read_exact(&mut name).await.unwrap();
            let _ = tx.send(name);
            c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn socks_passes_names_to_the_far_side() {
        let (addr, rx) = fake_socks().await;
        connect_tcp(&Egress::Socks(addr), "example.org", 443).await.unwrap();
        let req = rx.await.unwrap();
        assert_eq!(&req[..11], b"example.org");
        assert_eq!(u16::from_be_bytes([req[11], req[12]]), 443);
    }

    #[test]
    fn handle_reports_changes() {
        let h = EgressHandle::default();
        assert!(!h.set(Egress::System { udp: true }));
        assert!(h.set(Egress::Blocked));
        assert_eq!(*h.get(), Egress::Blocked);
    }
}
