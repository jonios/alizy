//! SOCKS5 proxy server, used for LAN sharing (bound to every interface) and
//! for proxy mode's local proxy (bound to 127.0.0.1). It carries any TCP
//! traffic and, through UDP ASSOCIATE, UDP datagrams.
//!
//! Authentication: none (method 0x00), or username/password (RFC 1929,
//! method 0x02) when credentials are configured. Commands: CONNECT and UDP
//! ASSOCIATE (BIND is refused). Address types: IPv4, domain, IPv6.
//! Outbound connections go through the current [`Egress`](crate::egress::Egress).
//!
//! UDP: one relay socket on the same port number as the TCP listener serves
//! every association, so the firewall can let its replies through the kill
//! switch by port. A datagram is accepted only from the address of a client
//! that holds an open (and, with credentials, authenticated) control
//! connection; the association ends when that connection closes.

use crate::egress::{self, EgressHandle};
use alizy_core::ipc::ProxyAuth;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::debug;

const MAX_CLIENTS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const BUF: usize = 16 * 1024;
const MAX_DATAGRAM: usize = 64 * 1024;
/// Datagrams queued per association before new ones are dropped.
const ASSOC_QUEUE: usize = 256;

/// What a proxy server needs besides its address: where connections go and
/// who may use it.
#[derive(Clone, Default)]
pub struct ServeOpts {
    pub egress: EgressHandle,
    pub auth: Option<Arc<ProxyAuth>>,
}

pub struct LanSocks {
    #[cfg_attr(not(test), allow(dead_code))]
    local: SocketAddr,
    udp: bool,
    task: Option<JoinHandle<()>>,
}

impl LanSocks {
    /// Listen on `bind:port` (TCP, and UDP on the same port for the relay).
    /// A UDP bind failure only disables UDP ASSOCIATE.
    pub async fn start(bind: IpAddr, port: u16, opts: ServeOpts) -> io::Result<LanSocks> {
        let listener = TcpListener::bind((bind, port))
            .await
            .map_err(|e| bind_error(&e, port))?;
        let local = listener.local_addr()?;
        let relay = match UdpSocket::bind(local).await {
            Ok(s) => Some(Relay::new(s)),
            Err(e) => {
                debug!("socks: no UDP relay on {local}: {e}");
                None
            }
        };
        let udp = relay.is_some();
        let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
        let task = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            if let Some(r) = &relay {
                let r = r.clone();
                clients.spawn(async move { r.demux().await });
            }
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
                        debug!("socks accept: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    debug!(%peer, "socks: client limit reached; refusing");
                    drop(stream);
                    continue;
                };
                let opts = opts.clone();
                let relay = relay.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = serve(stream, peer, &opts, relay.as_ref()).await {
                        debug!(%peer, "socks client: {e}");
                    }
                });
            }
        });
        Ok(LanSocks {
            local,
            udp,
            task: Some(task),
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// UDP ASSOCIATE is available (the relay socket is bound).
    pub fn udp(&self) -> bool {
        self.udp
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

async fn read_exact_t(c: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
    timeout(HANDSHAKE_TIMEOUT, c.read_exact(buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
        .map(|_| ())
}

/// Method selection, and RFC 1929 username/password when required.
async fn authenticate(client: &mut TcpStream, auth: Option<&ProxyAuth>) -> io::Result<()> {
    let mut hdr = [0u8; 2];
    read_exact_t(client, &mut hdr).await?;
    if hdr[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    read_exact_t(client, &mut methods).await?;
    let Some(auth) = auth else {
        if !methods.contains(&0x00) {
            client.write_all(&[5, 0xFF]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "client offered no no-auth method",
            ));
        }
        return client.write_all(&[5, 0x00]).await;
    };
    if !methods.contains(&0x02) {
        client.write_all(&[5, 0xFF]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "credentials required but the client offered none",
        ));
    }
    client.write_all(&[5, 0x02]).await?;
    let mut v = [0u8; 2];
    read_exact_t(client, &mut v).await?;
    if v[0] != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad auth version"));
    }
    let mut user = zeroize::Zeroizing::new(vec![0u8; v[1] as usize]);
    read_exact_t(client, &mut user).await?;
    let mut plen = [0u8; 1];
    read_exact_t(client, &mut plen).await?;
    let mut pass = zeroize::Zeroizing::new(vec![0u8; plen[0] as usize]);
    read_exact_t(client, &mut pass).await?;
    if auth.check(&user, &pass) {
        client.write_all(&[1, 0]).await
    } else {
        client.write_all(&[1, 1]).await?;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wrong username or password",
        ))
    }
}

/// Destination as sent by the client: an address literal or a domain name.
async fn read_target(client: &mut TcpStream, atyp: u8) -> io::Result<Option<(String, u16)>> {
    let host = match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            read_exact_t(client, &mut a).await?;
            IpAddr::V4(Ipv4Addr::from(a)).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_t(client, &mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            read_exact_t(client, &mut name).await?;
            String::from_utf8(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "domain is not UTF-8"))?
        }
        0x04 => {
            let mut a = [0u8; 16];
            read_exact_t(client, &mut a).await?;
            IpAddr::V6(Ipv6Addr::from(a)).to_string()
        }
        _ => return Ok(None),
    };
    let mut p = [0u8; 2];
    read_exact_t(client, &mut p).await?;
    Ok(Some((host, u16::from_be_bytes(p))))
}

/// SOCKS5 handshake → CONNECT relay or UDP association.
async fn serve(mut client: TcpStream, peer: SocketAddr, opts: &ServeOpts, relay: Option<&Relay>) -> io::Result<()> {
    authenticate(&mut client, opts.auth.as_deref()).await?;
    let mut req = [0u8; 4];
    read_exact_t(&mut client, &mut req).await?;
    if req[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad version in request"));
    }
    let Some((host, port)) = read_target(&mut client, req[3]).await? else {
        socks_reply(&mut client, 0x08, None).await?; // address type not supported
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported address type"));
    };
    match req[1] {
        0x01 => {}
        0x03 => {
            let Some(relay) = relay.filter(|_| opts.egress.get().udp()) else {
                socks_reply(&mut client, 0x07, None).await?;
                return Err(io::Error::new(io::ErrorKind::Unsupported, "UDP is not available"));
            };
            return associate(client, peer, &host, port, opts.egress.clone(), relay).await;
        }
        _ => {
            socks_reply(&mut client, 0x07, None).await?; // command not supported
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only CONNECT and UDP ASSOCIATE",
            ));
        }
    }
    if port == 0 {
        socks_reply(&mut client, 0x01, None).await?;
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "port 0"));
    }
    let upstream = match egress::connect_tcp(&opts.egress.get(), &host, port).await {
        Ok(s) => s,
        Err(e) => {
            let code = match e.kind() {
                io::ErrorKind::PermissionDenied => 0x02, // not allowed by ruleset
                io::ErrorKind::ConnectionRefused => 0x05,
                io::ErrorKind::TimedOut => 0x06,
                _ => 0x01,
            };
            socks_reply(&mut client, code, None).await?;
            return Err(e);
        }
    };
    let bound = upstream.local_addr().ok();
    socks_reply(&mut client, 0x00, bound.as_ref()).await?;
    relay_tcp(client, upstream).await
}

/// Send a SOCKS5 reply. `0x00` = success. `bound` fills BND.ADDR/BND.PORT.
async fn socks_reply(client: &mut TcpStream, status: u8, bound: Option<&SocketAddr>) -> io::Result<()> {
    let mut buf = vec![5, status, 0];
    push_addr(
        &mut buf,
        bound.copied().unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
    );
    client.write_all(&buf).await
}

fn push_addr(buf: &mut Vec<u8>, a: SocketAddr) {
    match a {
        SocketAddr::V4(a) => {
            buf.push(0x01);
            buf.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            buf.push(0x04);
            buf.extend_from_slice(&a.ip().octets());
        }
    }
    buf.extend_from_slice(&a.port().to_be_bytes());
}

async fn relay_tcp(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
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

// ---------------------------------------------------------------- UDP relay

type Datagram = (SocketAddr, Vec<u8>);

struct AssocEntry {
    id: u64,
    ip: IpAddr,
    /// Learned from the first datagram, or declared in the request.
    port: Option<u16>,
    tx: mpsc::Sender<Datagram>,
}

#[derive(Clone)]
struct Relay {
    sock: Arc<UdpSocket>,
    assocs: Arc<StdMutex<(u64, Vec<AssocEntry>)>>,
}

impl Relay {
    fn new(sock: UdpSocket) -> Self {
        Self {
            sock: Arc::new(sock),
            assocs: Arc::new(StdMutex::new((0, Vec::new()))),
        }
    }

    fn register(&self, ip: IpAddr, port: Option<u16>) -> (u64, mpsc::Receiver<Datagram>) {
        let (tx, rx) = mpsc::channel(ASSOC_QUEUE);
        let mut g = self.assocs.lock().unwrap();
        g.0 += 1;
        let id = g.0;
        g.1.push(AssocEntry { id, ip, port, tx });
        (id, rx)
    }

    fn unregister(&self, id: u64) {
        self.assocs.lock().unwrap().1.retain(|a| a.id != id);
    }

    /// The association a datagram from `src` belongs to; an association whose
    /// port is still unknown is bound to the first port its client uses.
    fn route(&self, src: SocketAddr) -> Option<mpsc::Sender<Datagram>> {
        let ip = src.ip().to_canonical();
        let mut g = self.assocs.lock().unwrap();
        if let Some(a) = g.1.iter().find(|a| a.ip == ip && a.port == Some(src.port())) {
            return Some(a.tx.clone());
        }
        let a = g.1.iter_mut().find(|a| a.ip == ip && a.port.is_none())?;
        a.port = Some(src.port());
        Some(a.tx.clone())
    }

    async fn demux(self) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let (n, src) = match self.sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("socks udp recv: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            match self.route(src) {
                // A full queue drops the datagram, as UDP may.
                Some(tx) => {
                    let _ = tx.try_send((src, buf[..n].to_vec()));
                }
                None => debug!(%src, "socks udp: datagram from a client without an association"),
            }
        }
    }
}

/// Parse a SOCKS5 UDP request header: `RSV(2) FRAG ATYP DST.ADDR DST.PORT DATA`.
/// Fragmented datagrams are not supported (dropped).
fn parse_udp(p: &[u8]) -> Option<(String, u16, &[u8])> {
    if p.len() < 4 || p[2] != 0 {
        return None;
    }
    let (host, rest) = match p[3] {
        0x01 if p.len() >= 10 => (Ipv4Addr::new(p[4], p[5], p[6], p[7]).to_string(), &p[8..]),
        0x04 if p.len() >= 22 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&p[4..20]);
            (Ipv6Addr::from(a).to_string(), &p[20..])
        }
        0x03 if p.len() >= 5 => {
            let l = p[4] as usize;
            let name = p.get(5..5 + l)?;
            (std::str::from_utf8(name).ok()?.to_string(), p.get(5 + l..)?)
        }
        _ => return None,
    };
    if rest.len() < 2 {
        return None;
    }
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Some((host, port, &rest[2..]))
}

/// Answer UDP ASSOCIATE, relay datagrams for this client until its control
/// connection closes.
async fn associate(
    mut client: TcpStream,
    peer: SocketAddr,
    host: &str,
    port: u16,
    egress: EgressHandle,
    relay: &Relay,
) -> io::Result<()> {
    let declared = host.parse::<IpAddr>().ok().filter(|ip| !ip.is_unspecified());
    let ip = declared.unwrap_or(peer.ip()).to_canonical();
    if ip != peer.ip().to_canonical() {
        // Only the client that holds this control connection may use it.
        socks_reply(&mut client, 0x02, None).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "association for another host",
        ));
    }
    let (id, rx) = relay.register(ip, (port != 0).then_some(port));
    let bnd = SocketAddr::new(client.local_addr()?.ip(), relay.sock.local_addr()?.port());
    let r = async {
        socks_reply(&mut client, 0x00, Some(&bnd)).await?;
        let task = tokio::spawn(run_assoc(relay.sock.clone(), rx, egress));
        // The association lives as long as the control connection.
        let mut sink = [0u8; 64];
        loop {
            match client.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        task.abort();
        Ok(())
    }
    .await;
    relay.unregister(id);
    r
}

async fn recv_on(s: &Option<UdpSocket>, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    match s {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

async fn run_assoc(relay: Arc<UdpSocket>, mut rx: mpsc::Receiver<Datagram>, egress: EgressHandle) {
    let (mut v4, mut v6): (Option<UdpSocket>, Option<UdpSocket>) = (None, None);
    let mut client: Option<SocketAddr> = None;
    let mut names: HashMap<(String, u16), SocketAddr> = HashMap::new();
    let (mut b4, mut b6) = (vec![0u8; MAX_DATAGRAM], vec![0u8; MAX_DATAGRAM]);
    loop {
        tokio::select! {
            m = rx.recv() => {
                let Some((src, pkt)) = m else { return };
                client = Some(src);
                let Some((host, port, data)) = parse_udp(&pkt) else { continue };
                let e = egress.get();
                let dst = match names.get(&(host.clone(), port)) {
                    Some(d) => *d,
                    None => match egress::resolve(&e, &host, port).await {
                        Ok(v) if !v.is_empty() => {
                            if names.len() >= 64 {
                                names.clear();
                            }
                            names.insert((host, port), v[0]);
                            v[0]
                        }
                        _ => continue,
                    },
                };
                let slot = if dst.is_ipv4() { &mut v4 } else { &mut v6 };
                if slot.is_none() {
                    match egress::udp_socket(&e, &dst) {
                        Ok(s) => *slot = Some(s),
                        Err(err) => {
                            debug!("socks udp upstream: {err}");
                            continue;
                        }
                    }
                }
                if let Some(s) = slot {
                    let _ = s.send_to(data, dst).await;
                }
            }
            r = recv_on(&v4, &mut b4) => reply(&relay, client, r, &b4).await,
            r = recv_on(&v6, &mut b6) => reply(&relay, client, r, &b6).await,
        }
    }
}

async fn reply(relay: &UdpSocket, client: Option<SocketAddr>, r: io::Result<(usize, SocketAddr)>, buf: &[u8]) {
    let (Ok((n, from)), Some(client)) = (r, client) else {
        return;
    };
    let mut out = vec![0, 0, 0];
    push_addr(&mut out, from);
    out.extend_from_slice(&buf[..n]);
    let _ = relay.send_to(&out, client).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::Egress;

    fn lo() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    async fn open() -> LanSocks {
        LanSocks::start(lo(), 0, ServeOpts::default()).await.unwrap()
    }

    fn with_auth() -> ServeOpts {
        ServeOpts {
            auth: Some(Arc::new(ProxyAuth {
                username: "tv".into(),
                password: None,
                verifier: Some(ProxyAuth::make_verifier("pw", &[1u8; 16])),
            })),
            ..Default::default()
        }
    }

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

    async fn udp_echo() -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut buf).await {
                let _ = s.send_to(&buf[..n], from).await;
            }
        });
        addr
    }

    async fn read_reply(c: &mut TcpStream) -> (u8, SocketAddr) {
        let mut h = [0u8; 4];
        c.read_exact(&mut h).await.unwrap();
        assert_eq!(h[0], 5);
        let addr = match h[3] {
            1 => {
                let mut b = [0u8; 6];
                c.read_exact(&mut b).await.unwrap();
                SocketAddr::from(([b[0], b[1], b[2], b[3]], u16::from_be_bytes([b[4], b[5]])))
            }
            4 => {
                let mut b = [0u8; 18];
                c.read_exact(&mut b).await.unwrap();
                let mut a = [0u8; 16];
                a.copy_from_slice(&b[..16]);
                SocketAddr::from((a, u16::from_be_bytes([b[16], b[17]])))
            }
            _ => panic!("unexpected atyp"),
        };
        (h[1], addr)
    }

    fn request(cmd: u8, target: SocketAddr) -> Vec<u8> {
        let mut req = vec![5, cmd, 0];
        push_addr(&mut req, target);
        req
    }

    /// Full no-auth handshake and CONNECT to `target`.
    async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0]);
        c.write_all(&request(1, target)).await.unwrap();
        let (code, _) = read_reply(&mut c).await;
        assert_eq!(code, 0, "SOCKS5 CONNECT failed: {code}");
        c
    }

    #[tokio::test]
    async fn connect_tunnels_raw_bytes() {
        let target = echo().await;
        let p = open().await;
        let mut c = socks_connect(p.local_addr(), target).await;
        c.write_all(b"hello socks").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello socks");
    }

    #[tokio::test]
    async fn domain_connect_resolves_localhost() {
        let target = echo().await;
        let p = open().await;
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0]);
        let domain = b"localhost";
        let mut req = vec![5, 1, 0, 3, domain.len() as u8];
        req.extend_from_slice(domain);
        req.extend_from_slice(&target.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        assert_eq!(read_reply(&mut c).await.0, 0, "CONNECT to domain failed");
        c.write_all(b"domain-test").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"domain-test");
    }

    #[tokio::test]
    async fn bind_command_gets_0x07() {
        let p = open().await;
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        c.write_all(&[5, 2, 0, 1, 127, 0, 0, 1, 0, 80]).await.unwrap();
        assert_eq!(read_reply(&mut c).await.0, 0x07);
    }

    #[tokio::test]
    async fn open_proxy_refuses_clients_without_no_auth() {
        let p = open().await;
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 2]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0xFF]);
    }

    async fn login(proxy: SocketAddr, user: &[u8], pass: &[u8]) -> (TcpStream, u8) {
        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(&[5, 2, 0, 2]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 2], "server must pick username/password");
        let mut m = vec![1, user.len() as u8];
        m.extend_from_slice(user);
        m.push(pass.len() as u8);
        m.extend_from_slice(pass);
        c.write_all(&m).await.unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        (c, r[1])
    }

    #[tokio::test]
    async fn credentials_are_required_and_checked() {
        let target = echo().await;
        let p = LanSocks::start(lo(), 0, with_auth()).await.unwrap();
        // No-auth only: refused.
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0xFF]);
        // Wrong password: refused.
        assert_eq!(login(p.local_addr(), b"tv", b"nope").await.1, 1);
        // Right credentials: CONNECT works.
        let (mut c, status) = login(p.local_addr(), b"tv", b"pw").await;
        assert_eq!(status, 0);
        c.write_all(&request(1, target)).await.unwrap();
        assert_eq!(read_reply(&mut c).await.0, 0);
        c.write_all(b"authed").await.unwrap();
        let mut buf = [0u8; 16];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"authed");
    }

    #[tokio::test]
    async fn udp_associate_relays_datagrams_both_ways() {
        let target = udp_echo().await;
        let p = open().await;
        assert!(p.udp());
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        c.write_all(&request(3, "0.0.0.0:0".parse().unwrap())).await.unwrap();
        let (code, relay) = read_reply(&mut c).await;
        assert_eq!(code, 0);
        assert_eq!(relay.port(), p.local_addr().port(), "relay shares the SOCKS port");
        let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut d = vec![0, 0, 0];
        push_addr(&mut d, target);
        d.extend_from_slice(b"ping-udp");
        u.send_to(&d, relay).await.unwrap();
        let mut buf = [0u8; 128];
        let (n, _) = timeout(Duration::from_secs(5), u.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let (host, port, data) = parse_udp(&buf[..n]).unwrap();
        assert_eq!((host.as_str(), port), ("127.0.0.1", target.port()));
        assert_eq!(data, b"ping-udp");
        // Closing the control connection ends the association.
        drop(c);
        tokio::time::sleep(Duration::from_millis(100)).await;
        u.send_to(&d, relay).await.unwrap();
        assert!(timeout(Duration::from_millis(300), u.recv_from(&mut buf))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn udp_refused_when_the_tunnel_cannot_carry_it() {
        let p = LanSocks::start(
            lo(),
            0,
            ServeOpts {
                egress: EgressHandle::new(Egress::System { udp: false }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        c.write_all(&request(3, "0.0.0.0:0".parse().unwrap())).await.unwrap();
        assert_eq!(read_reply(&mut c).await.0, 0x07);
    }

    #[tokio::test]
    async fn blocked_egress_refuses_connect() {
        let target = echo().await;
        let p = LanSocks::start(
            lo(),
            0,
            ServeOpts {
                egress: EgressHandle::new(Egress::Blocked),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        c.write_all(&request(1, target)).await.unwrap();
        assert_eq!(read_reply(&mut c).await.0, 0x02);
    }

    #[tokio::test]
    async fn unreachable_target_gets_failure() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = l.local_addr().unwrap();
        drop(l);
        let p = open().await;
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        c.write_all(&request(1, target)).await.unwrap();
        assert_ne!(read_reply(&mut c).await.0, 0x00, "should not succeed");
    }

    #[test]
    fn udp_header_parsing() {
        let mut d = vec![0, 0, 0, 3, 7];
        d.extend_from_slice(b"example");
        d.extend_from_slice(&53u16.to_be_bytes());
        d.extend_from_slice(b"q");
        assert_eq!(parse_udp(&d), Some(("example".into(), 53, &b"q"[..])));
        d[2] = 1; // fragment
        assert_eq!(parse_udp(&d), None);
        assert_eq!(parse_udp(&[0, 0, 0, 3, 200, b'a']), None);
    }

    #[tokio::test]
    async fn stop_releases_the_port() {
        for _ in 0..5 {
            let p = LanSocks::start("0.0.0.0".parse().unwrap(), 0, ServeOpts::default())
                .await
                .unwrap();
            let port = p.local_addr().port();
            p.stop().await;
            match LanSocks::start("0.0.0.0".parse().unwrap(), port, ServeOpts::default()).await {
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
        let Err(e) = LanSocks::start("0.0.0.0".parse().unwrap(), port, ServeOpts::default()).await else {
            panic!("binding a port already in use must fail");
        };
        assert!(e.to_string().contains("already in use"), "{e}");
    }
}
