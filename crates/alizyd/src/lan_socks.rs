//! LAN SOCKS5 proxy: devices on the local network (a smart TV, a phone)
//! reach the internet through this machine's VPN connection using the SOCKS5
//! protocol. Unlike the HTTP proxy, this carries any TCP traffic (Telegram's
//! MTProto, SSH, etc.) — the client only needs SOCKS5 support.
//!
//! No authentication (method 0x00 only). CONNECT command only (no BIND or
//! UDP ASSOCIATE). Supports address types: IPv4 (0x01), domain (0x03),
//! IPv6 (0x04). Domain names are resolved by the system resolver, which the
//! daemon points at the tunnel while connected.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::debug;

const MAX_CLIENTS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const BUF: usize = 16 * 1024;

pub struct LanSocks {
    #[cfg_attr(not(test), allow(dead_code))]
    local: SocketAddr,
    task: Option<JoinHandle<()>>,
}

impl LanSocks {
    pub async fn start(port: u16) -> io::Result<LanSocks> {
        let listener = TcpListener::bind(("0.0.0.0", port))
            .await
            .map_err(|e| bind_error(&e, port))?;
        let local = listener.local_addr()?;
        let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
        let task = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            enum Ev {
                Accepted(io::Result<(TcpStream, SocketAddr)>),
                Reaped,
            }
            loop {
                let ev = if clients.is_empty() {
                    Ev::Accepted(listener.accept().await)
                } else {
                    tokio::select! {
                        a = listener.accept() => Ev::Accepted(a),
                        Some(_) = clients.join_next() => Ev::Reaped,
                    }
                };
                let (stream, peer) = match ev {
                    Ev::Reaped => continue,
                    Ev::Accepted(Ok(v)) => v,
                    Ev::Accepted(Err(e)) => {
                        debug!("lan socks accept: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    debug!(%peer, "lan socks: client limit reached; refusing");
                    drop(stream);
                    continue;
                };
                clients.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = serve(stream).await {
                        debug!(%peer, "lan socks client: {e}");
                    }
                });
            }
        });
        Ok(LanSocks {
            local,
            task: Some(task),
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub async fn stop(mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
            let _ = t.await;
        }
    }
}

impl Drop for LanSocks {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

fn bind_error(e: &io::Error, port: u16) -> io::Error {
    match e.kind() {
        io::ErrorKind::AddrInUse => {
            io::Error::other(format!("SOCKS5 port {port} is already in use by another service"))
        }
        io::ErrorKind::PermissionDenied => io::Error::other(format!("not allowed to bind SOCKS5 port {port}")),
        _ => io::Error::other(format!("could not listen on SOCKS5 port {port}: {e}")),
    }
}

/// SOCKS5 handshake → connect → relay.
async fn serve(mut client: TcpStream) -> io::Result<()> {
    // --- Method selection ---
    let mut hdr = [0u8; 2];
    timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut hdr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
        .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "client went away"))?;
    if hdr[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut methods))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))??;
    if !methods.contains(&0x00) {
        // No acceptable method — tell them we only do no-auth.
        client.write_all(&[5, 0xFF]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client offered no no-auth method",
        ));
    }
    client.write_all(&[5, 0x00]).await?;

    // --- CONNECT request ---
    let mut req = [0u8; 4];
    timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut req))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))??;
    if req[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad version in request"));
    }
    if req[1] != 0x01 {
        // Only CONNECT (0x01). BIND (0x02) and UDP ASSOCIATE (0x03) are unsupported.
        socks_reply(&mut client, 0x07, None).await?; // command not supported
        return Err(io::Error::new(io::ErrorKind::Unsupported, "only CONNECT is supported"));
    }

    let (host, port) = match req[3] {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p).await?;
            (IpAddr::V4(Ipv4Addr::from(addr)).to_string(), u16::from_be_bytes(p))
        }
        0x03 => {
            // Domain name
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name).await?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p).await?;
            let domain = String::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "domain is not UTF-8"))?;
            (domain, u16::from_be_bytes(p))
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p).await?;
            (IpAddr::V6(Ipv6Addr::from(addr)).to_string(), u16::from_be_bytes(p))
        }
        _ => {
            socks_reply(&mut client, 0x08, None).await?; // address type not supported
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported address type"));
        }
    };

    if port == 0 {
        socks_reply(&mut client, 0x01, None).await?;
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "port 0"));
    }

    let upstream = match connect(&host, port).await {
        Ok(s) => s,
        Err(e) => {
            let code = match e.kind() {
                io::ErrorKind::ConnectionRefused => 0x05,
                io::ErrorKind::TimedOut => 0x06,
                _ => 0x01, // general failure
            };
            socks_reply(&mut client, code, None).await?;
            return Err(e);
        }
    };

    let bound = upstream.local_addr().ok();
    socks_reply(&mut client, 0x00, bound.as_ref()).await?;
    relay(client, upstream).await
}

/// Send a SOCKS5 reply. `0x00` = success. `bound` is the address the upstream
/// socket is bound to (for the BND.ADDR/BND.PORT fields in the reply).
async fn socks_reply(client: &mut TcpStream, status: u8, bound: Option<&SocketAddr>) -> io::Result<()> {
    let mut buf = vec![5, status, 0];
    match bound {
        Some(SocketAddr::V4(a)) => {
            buf.push(0x01);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        Some(SocketAddr::V6(a)) => {
            buf.push(0x04);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        None => {
            buf.push(0x01);
            buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
    }
    client.write_all(&buf).await
}

async fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let addrs = timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "name resolution timed out"))?
        .map_err(|e| io::Error::other(format!("cannot resolve {host}: {e}")))?;
    let mut last = None;
    for addr in addrs {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = Some(e),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other(format!("no address for {host}"))))
}

async fn relay(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    tokio::try_join!(pump(cr, uw), pump(ur, cw)).map(|_| ())
}

async fn pump<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(mut r: R, mut w: W) -> io::Result<()> {
    let mut buf = vec![0u8; BUF];
    loop {
        let n = match timeout(IDLE_TIMEOUT, r.read(&mut buf)).await {
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "relay went idle")),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
        };
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn echo() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.into_split();
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match r.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if w.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    /// Do a full SOCKS5 no-auth handshake and CONNECT to `target`.
    async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
        let mut c = TcpStream::connect(proxy).await.unwrap();
        // Method selection
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0]);
        // CONNECT request (IPv4)
        let mut req = vec![5, 1, 0, 1];
        match target.ip() {
            IpAddr::V4(a) => req.extend_from_slice(&a.octets()),
            IpAddr::V6(a) => {
                req[3] = 4;
                req.extend_from_slice(&a.octets());
            }
        }
        req.extend_from_slice(&target.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        // Read reply
        let mut h = [0u8; 4];
        c.read_exact(&mut h).await.unwrap();
        assert_eq!(h[0], 5);
        assert_eq!(h[1], 0, "SOCKS5 CONNECT failed: {}", h[1]);
        let skip = match h[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            _ => panic!("unexpected atyp"),
        };
        let mut bind = vec![0u8; skip];
        c.read_exact(&mut bind).await.unwrap();
        c
    }

    #[tokio::test]
    async fn connect_tunnels_raw_bytes() {
        let target = echo().await;
        let p = LanSocks::start(0).await.unwrap();
        let mut c = socks_connect(p.local_addr(), target).await;
        c.write_all(b"hello socks").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello socks");
    }

    #[tokio::test]
    async fn domain_connect_resolves_localhost() {
        let target = echo().await;
        let p = LanSocks::start(0).await.unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0]);
        // CONNECT with domain name
        let domain = b"localhost";
        let mut req = vec![5, 1, 0, 3, domain.len() as u8];
        req.extend_from_slice(domain);
        req.extend_from_slice(&target.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut h = [0u8; 4];
        c.read_exact(&mut h).await.unwrap();
        assert_eq!(h[1], 0, "CONNECT to domain failed");
        let skip = match h[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            _ => panic!("unexpected atyp"),
        };
        let mut bind = vec![0u8; skip];
        c.read_exact(&mut bind).await.unwrap();
        c.write_all(b"domain-test").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"domain-test");
    }

    #[tokio::test]
    async fn unsupported_command_gets_0x07() {
        let p = LanSocks::start(0).await.unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        // BIND command (0x02)
        c.write_all(&[5, 2, 0, 1, 127, 0, 0, 1, 0, 80]).await.unwrap();
        let mut h = [0u8; 10];
        let n = c.read(&mut h).await.unwrap();
        assert!(n >= 2);
        assert_eq!(h[1], 0x07);
    }

    #[tokio::test]
    async fn no_auth_method_is_rejected() {
        let p = LanSocks::start(0).await.unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        // Offer only username/password (0x02), no no-auth
        c.write_all(&[5, 1, 2]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0xFF]);
    }

    #[tokio::test]
    async fn unreachable_target_gets_failure() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = l.local_addr().unwrap();
        drop(l);
        let p = LanSocks::start(0).await.unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        let mut req = vec![5, 1, 0, 1];
        match target.ip() {
            IpAddr::V4(a) => req.extend_from_slice(&a.octets()),
            _ => unreachable!(),
        }
        req.extend_from_slice(&target.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut h = [0u8; 10];
        let n = c.read(&mut h).await.unwrap();
        assert!(n >= 2);
        assert_ne!(h[1], 0x00, "should not succeed");
    }

    #[tokio::test]
    async fn stop_releases_the_port() {
        // Parallel tests' client sockets can take the freed ephemeral port
        // before the rebind; only that race is retried, with a fresh port.
        for _ in 0..5 {
            let p = LanSocks::start(0).await.unwrap();
            let port = p.local_addr().port();
            p.stop().await;
            match LanSocks::start(port).await {
                Ok(again) => return assert_eq!(again.local_addr().port(), port),
                Err(e) if e.to_string().contains("already in use") => continue,
                Err(e) => panic!("{e}"),
            }
        }
        panic!("the port stayed in use after stop() in 5 attempts");
    }

    #[tokio::test]
    async fn bind_conflict_has_a_clear_message() {
        let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let Err(e) = LanSocks::start(port).await else {
            panic!("binding a port already in use must fail");
        };
        assert!(e.to_string().contains("already in use"), "{e}");
    }
}
