//! HTTP forward proxy, used for LAN sharing (devices on the local network
//! reach the internet through this machine's VPN) and for proxy mode's local
//! proxy on 127.0.0.1.
//!
//! HTTP `CONNECT` tunnels TLS; absolute-form requests are forwarded for
//! plain HTTP, one request per connection (`Connection: close`). With
//! credentials configured, clients must send `Proxy-Authorization: Basic`
//! (answered with 407 otherwise); Basic sends them in clear text on the LAN,
//! which LAN_PROXY.md states.
//!
//! Outbound connections go through the current [`Egress`](crate::egress::Egress):
//! in tunnel mode ordinary sockets (policy routing carries them through the
//! tunnel, and names are resolved by the system resolver the daemon points
//! at the tunnel); in proxy mode marked sockets or the SSH SOCKS proxy.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::egress;
use crate::lan_socks::ServeOpts;
use alizy_core::ipc::ProxyAuth;
use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::debug;

/// Concurrent clients; further connections are refused at once.
const MAX_CLIENTS: usize = 64;
/// A client must send its request headers within this time.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// Request headers are capped; nothing larger is buffered from the network.
const MAX_HEADER: usize = 16 * 1024;
/// A relay with no bytes in either direction for this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Relay buffer size.
const BUF: usize = 16 * 1024;

/// Running proxy. Dropping it closes the listener and aborts every relay in
/// flight; [`LanProxy::stop`] does the same and *waits* until the listening
/// socket is actually closed, so the port can be re-bound immediately.
pub struct LanProxy {
    #[cfg_attr(not(test), allow(dead_code))]
    local: SocketAddr,
    task: Option<JoinHandle<()>>,
}

impl LanProxy {
    /// Listen on `bind:port` and serve HTTP-proxy clients. Port 0 asks
    /// the kernel for an ephemeral port (tests); user-supplied ports are
    /// validated by the IPC layer. Bind failures come back as messages a
    /// user can act on.
    pub async fn start(bind: IpAddr, port: u16, opts: ServeOpts) -> io::Result<LanProxy> {
        let listener = TcpListener::bind((bind, port))
            .await
            .map_err(|e| bind_error(&e, port))?;
        let local = listener.local_addr()?;
        let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
        let task = tokio::spawn(async move {
            // Clients live in this set: dropping the listener task (stop,
            // daemon exit) aborts every relay, not just new accepts.
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
                        debug!("lan proxy accept: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    debug!(%peer, "lan proxy: client limit reached; refusing");
                    drop(stream);
                    continue;
                };
                let opts = opts.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = serve(stream, &opts).await {
                        debug!(%peer, "lan proxy client: {e}");
                    }
                });
            }
        });
        Ok(LanProxy {
            local,
            task: Some(task),
        })
    }

    /// The address the listener is bound to.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Stop listening and abort every relay, returning only once the
    /// listening socket is closed (the port is free to re-bind).
    pub async fn stop(mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
            let _ = t.await;
        }
    }
}

impl Drop for LanProxy {
    fn drop(&mut self) {
        // Aborting the listener task drops its JoinSet, which aborts every
        // relay it owns, and closes the listening socket — asynchronously.
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

fn bind_error(e: &io::Error, port: u16) -> io::Error {
    match e.kind() {
        io::ErrorKind::AddrInUse => io::Error::other(format!("port {port} is already in use by another service")),
        io::ErrorKind::PermissionDenied => io::Error::other(format!("not allowed to bind port {port}")),
        _ => io::Error::other(format!("could not listen on port {port}: {e}")),
    }
}

/// Serve one client connection: read the request, pick the destination,
/// connect, then relay until either side goes away.
async fn serve(mut client: TcpStream, opts: &ServeOpts) -> io::Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(p) = header_end(&buf) {
            break p;
        }
        if buf.len() > MAX_HEADER {
            return reply(
                &mut client,
                "413 Request Header Fields Too Large",
                "request headers too large",
            )
            .await;
        }
        match timeout(HEADER_TIMEOUT, client.read_buf(&mut buf)).await {
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for request headers",
                ))
            }
            Ok(Ok(0)) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "client went away")),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e),
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let line = head.lines().next().unwrap_or_default().trim_end_matches('\r');
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return reply(&mut client, "400 Bad Request", "malformed request line").await;
    };
    if !version.starts_with("HTTP/") {
        return reply(&mut client, "400 Bad Request", "not an HTTP request").await;
    }
    if let Some(auth) = &opts.auth {
        if !authorized(&head, auth) {
            return reply_407(&mut client).await;
        }
    }
    let egress = opts.egress.get();

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = authority(target, None) else {
            return reply(&mut client, "400 Bad Request", "invalid CONNECT target").await;
        };
        let mut upstream = match egress::connect_tcp(&egress, &host, port).await {
            Ok(s) => s,
            Err(e) => return reply(&mut client, "502 Bad Gateway", &e.to_string()).await,
        };
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        // Some clients pipeline their first bytes (a TLS hello) right after
        // the CONNECT headers; hand them to the target untouched.
        let leftover = buf[head_end..].to_vec();
        if !leftover.is_empty() {
            upstream.write_all(&leftover).await?;
        }
        return relay(client, upstream).await;
    }

    // Absolute-form request: only plain HTTP can be forwarded here.
    let Some(rest) = target.strip_prefix("http://") else {
        let why = if target.starts_with("https://") {
            "plain HTTP cannot carry https:// URLs; use CONNECT"
        } else {
            "only http:// absolute URLs and CONNECT are supported"
        };
        return reply(&mut client, "400 Bad Request", why).await;
    };
    let (auth, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let path = path.split('#').next().filter(|p| !p.is_empty()).unwrap_or("/");
    let Some((host, port)) = authority(auth, Some(80)) else {
        return reply(&mut client, "400 Bad Request", "invalid URL authority").await;
    };

    // Rewrite to origin-form and drop proxy-specific headers: this is a
    // one-request-per-connection forwarder, so say so explicitly.
    let mut out = Vec::with_capacity(head_end + 64);
    out.extend_from_slice(format!("{method} {path} {version}\r\n").as_bytes());
    for h in head.lines().skip(1) {
        let h = h.trim_end_matches('\r');
        if h.is_empty() {
            break;
        }
        let name = h.split(':').next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");

    let mut upstream = match egress::connect_tcp(&egress, &host, port).await {
        Ok(s) => s,
        Err(e) => return reply(&mut client, "502 Bad Gateway", &e.to_string()).await,
    };
    upstream.write_all(&out).await?;
    let leftover = buf[head_end..].to_vec();
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    relay(client, upstream).await
}

/// Index just past the terminating CRLFCRLF, if the buffer has it.
fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// `host:port`, `[v6]:port` or (with `default_port`) a bare host. Rejects
/// userinfo, port 0 and bare IPv6 literals, which an authority must bracket.
fn authority(s: &str, default_port: Option<u16>) -> Option<(String, u16)> {
    let port16 = |p: &str| -> Option<u16> {
        let n: u16 = p.parse().ok()?;
        (n != 0).then_some(n)
    };
    if s.is_empty() || s.contains('@') {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (ip, tail) = rest.split_once(']')?;
        ip.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match tail.strip_prefix(':') {
            Some(p) => port16(p)?,
            None => default_port?,
        };
        return Some((ip.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host.to_string(), port16(port)?)),
        Some(_) => None, // more than one colon and no brackets
        None => Some((s.to_string(), default_port?)),
    }
}

/// `Proxy-Authorization: Basic base64(user:password)` matching the credentials.
fn authorized(head: &str, auth: &ProxyAuth) -> bool {
    head.lines().skip(1).any(|h| {
        let Some((name, value)) = h.split_once(':') else {
            return false;
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            return false;
        }
        let mut v = value.trim().splitn(2, ' ');
        let (Some(scheme), Some(token)) = (v.next(), v.next()) else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(token.trim()) else {
            return false;
        };
        let raw = zeroize::Zeroizing::new(raw);
        let Some(i) = raw.iter().position(|b| *b == b':') else {
            return false;
        };
        auth.check(&raw[..i], &raw[i + 1..])
    })
}

async fn reply_407(s: &mut TcpStream) -> io::Result<()> {
    let body = "407 Proxy Authentication Required\n";
    let msg = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Alizy\"\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(msg.as_bytes()).await?;
    s.shutdown().await
}

async fn reply(s: &mut TcpStream, status: &str, detail: &str) -> io::Result<()> {
    let body = format!("{status}\n{detail}\n");
    let msg = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(msg.as_bytes()).await?;
    s.shutdown().await
}

/// Copy both directions until one side ends or both go idle.
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

/// Global, non-tunnel IPv4 addresses other devices can reach us on, for the
/// UI to show. Virtual bridges (docker, libvirt, …) are left out: nothing
/// outside this machine can reach them.
pub async fn addresses(iface: &str) -> Vec<IpAddr> {
    let argv: Vec<String> = ["ip", "-j", "-4", "addr", "show", "scope", "global"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let out = match crate::exec::run(&argv, None).await {
        Ok(o) => o,
        Err(e) => {
            debug!("lan proxy: could not list addresses: {e}");
            return Vec::new();
        }
    };
    #[derive(serde::Deserialize)]
    struct Dev {
        ifname: String,
        #[serde(default)]
        operstate: Option<String>,
        #[serde(default)]
        addr_info: Vec<Addr>,
    }
    #[derive(serde::Deserialize)]
    struct Addr {
        #[serde(default)]
        family: Option<String>,
        #[serde(default)]
        local: Option<String>,
    }
    let Ok(devs) = serde_json::from_str::<Vec<Dev>>(&out) else {
        debug!("lan proxy: unrecognised `ip -j addr` output");
        return Vec::new();
    };
    const VIRTUAL: [&str; 5] = ["docker", "br-", "veth", "virbr", "vboxnet"];
    devs.into_iter()
        .filter(|d| d.ifname != iface && !VIRTUAL.iter().any(|p| d.ifname.starts_with(p)))
        .filter(|d| d.operstate.as_deref() != Some("down"))
        .flat_map(|d| d.addr_info)
        .filter(|a| a.family.as_deref() == Some("inet"))
        .filter_map(|a| a.local?.parse().ok())
        // `scope global` already excludes loopback and link-local; keep the
        // loopback guard anyway in case a future `ip` invocation does not.
        .filter(|ip: &IpAddr| !ip.is_loopback())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    fn any() -> IpAddr {
        "0.0.0.0".parse().unwrap()
    }

    #[tokio::test]
    async fn credentials_are_required_when_configured() {
        let target = echo().await;
        let opts = ServeOpts {
            auth: Some(Arc::new(ProxyAuth {
                username: "tv".into(),
                password: None,
                verifier: Some(ProxyAuth::make_verifier("pw", &[2u8; 16])),
            })),
            ..Default::default()
        };
        let p = LanProxy::start(any(), 0, opts).await.unwrap();
        let ask = |auth: Option<&str>| {
            let addr = p.local_addr();
            let auth = auth.map(String::from);
            async move {
                let mut c = TcpStream::connect(addr).await.unwrap();
                let hdr = auth
                    .map(|a| {
                        format!(
                            "Proxy-Authorization: Basic {}\r\n",
                            base64::engine::general_purpose::STANDARD.encode(a)
                        )
                    })
                    .unwrap_or_default();
                c.write_all(format!("CONNECT {target} HTTP/1.1\r\n{hdr}\r\n").as_bytes())
                    .await
                    .unwrap();
                let mut buf = vec![0u8; 256];
                let n = c.read(&mut buf).await.unwrap();
                String::from_utf8_lossy(&buf[..n]).into_owned()
            }
        };
        let r = ask(None).await;
        assert!(
            r.starts_with("HTTP/1.1 407") && r.contains("Proxy-Authenticate: Basic"),
            "{r}"
        );
        assert!(ask(Some("tv:wrong")).await.starts_with("HTTP/1.1 407"));
        assert!(ask(Some("tv:pw")).await.starts_with("HTTP/1.1 200"));
    }

    /// Echo server: returns everything it receives.
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

    /// One-shot HTTP server: records the request, answers `pong`, closes.
    async fn http_server() -> (SocketAddr, Arc<StdMutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            let Ok((mut s, _)) = l.accept().await else { return };
            let mut text = String::new();
            let mut buf = vec![0u8; 8192];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        text.push_str(&String::from_utf8_lossy(&buf[..n]));
                        if text.contains("\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            seen2.lock().unwrap().push(text);
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong")
                .await;
        });
        (addr, seen)
    }

    async fn read_all(s: &mut TcpStream) -> String {
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn connect_tunnels_raw_bytes_to_the_target() {
        let target = echo().await;
        let p = LanProxy::start(any(), 0, ServeOpts::default()).await.unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = c.read(&mut buf).await.unwrap();
        // If the CONNECT headers leaked to the target, the echo would come
        // back with them attached and this first read would not be exactly
        // the 200 reply.
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 Connection Established"),
            "{:?}",
            String::from_utf8_lossy(&buf[..n])
        );
        c.write_all(b"ping").await.unwrap();
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
    }

    #[tokio::test]
    async fn plain_http_request_is_forwarded_in_origin_form() {
        let (target, seen) = http_server().await;
        let p = LanProxy::start(any(), 0, ServeOpts::default()).await.unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(
            format!("GET http://{target}/x?a=1 HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: keep-alive\r\nCookie: k=v\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let resp = read_all(&mut c).await;
        assert!(resp.ends_with("pong"), "{resp}");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let req = &seen[0];
        assert!(req.starts_with("GET /x?a=1 HTTP/1.1\r\n"), "{req}");
        assert!(req.contains("\r\nHost: "), "{req}");
        assert!(req.contains("\r\nCookie: k=v\r\n"), "{req}");
        assert!(req.contains("\r\nConnection: close\r\n"), "{req}");
        assert!(!req.to_ascii_lowercase().contains("proxy-connection"), "{req}");
    }

    #[tokio::test]
    async fn https_urls_get_a_clear_400() {
        let p = LanProxy::start(any(), 0, ServeOpts::default()).await.unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let resp = read_all(&mut c).await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(resp.contains("CONNECT"), "{resp}");
    }

    #[tokio::test]
    async fn non_http_input_gets_a_400() {
        let p = LanProxy::start(any(), 0, ServeOpts::default()).await.unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(b"this is not http\r\n\r\n").await.unwrap();
        let resp = read_all(&mut c).await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
    }

    #[tokio::test]
    async fn unreachable_target_gets_a_502() {
        // An ephemeral port with nothing listening on it.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = l.local_addr().unwrap();
        drop(l);
        let p = LanProxy::start(any(), 0, ServeOpts::default()).await.unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let resp = read_all(&mut c).await;
        assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    }

    #[tokio::test]
    async fn oversized_headers_are_refused() {
        let p = LanProxy::start(any(), 0, ServeOpts::default()).await.unwrap();
        let mut c = TcpStream::connect(p.local_addr()).await.unwrap();
        c.write_all(&vec![b'a'; MAX_HEADER + 4096]).await.unwrap();
        let resp = read_all(&mut c).await;
        assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
    }

    #[tokio::test]
    async fn stop_releases_the_port() {
        // Parallel tests' client sockets can take the freed ephemeral port
        // before the rebind; only that race is retried, with a fresh port.
        for _ in 0..5 {
            let p = LanProxy::start(any(), 0, ServeOpts::default()).await.unwrap();
            let port = p.local_addr().port();
            p.stop().await;
            match LanProxy::start(any(), port, ServeOpts::default()).await {
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
        let Err(e) = LanProxy::start(any(), port, ServeOpts::default()).await else {
            panic!("binding a port already in use must fail");
        };
        assert!(e.to_string().contains("already in use"), "{e}");
    }

    #[test]
    fn authority_parsing() {
        assert_eq!(authority("example.com:443", None), Some(("example.com".into(), 443)));
        assert_eq!(authority("192.0.2.1:8080", None), Some(("192.0.2.1".into(), 8080)));
        assert_eq!(
            authority("[2001:db8::1]:8443", None),
            Some(("2001:db8::1".into(), 8443))
        );
        assert_eq!(authority("example.com", Some(80)), Some(("example.com".into(), 80)));
        assert_eq!(authority("[2001:db8::1]", Some(80)), Some(("2001:db8::1".into(), 80)));
        assert_eq!(authority("example.com", None), None);
        assert_eq!(authority("example.com:0", None), None);
        assert_eq!(authority("a@b:80", None), None);
        assert_eq!(authority("2001:db8::1:80", None), None); // must be bracketed
        assert_eq!(authority("", Some(80)), None);
    }
}
