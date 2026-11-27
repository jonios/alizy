//! GUI ⇄ daemon protocol: newline-delimited JSON over a Unix socket.
//!
//! The command set is closed and explicit; there is no generic "run" command.

use crate::config::{PublicConfig, WgConfig};
use crate::firewall::NetworkPolicy;
use crate::protocol::TunnelConfig;
use crate::ssh::{HostKey, SshConfig};
use crate::state::ConnectionState;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub const PROTOCOL_VERSION: u32 = 1;
pub const SOCKET_PATH: &str = "/run/alizy/alizyd.sock";
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// A connect request: which profile, and its full protocol configuration.
///
/// On the wire it keeps the shape older GUIs and daemons speak (`config` +
/// optional `ssh`), so a GUI and a daemon of different versions still agree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "WireTunnelSpec", into = "WireTunnelSpec")]
pub struct TunnelSpec {
    pub profile_id: String,
    pub profile_name: String,
    pub tunnel: TunnelConfig,
    /// Last known resolved address per endpoint slot (used when DNS is blocked).
    pub cached_endpoints: Vec<Option<SocketAddr>>,
}

#[derive(Serialize, Deserialize)]
struct WireTunnelSpec {
    profile_id: String,
    profile_name: String,
    config: WgConfig,
    #[serde(default)]
    cached_endpoints: Vec<Option<SocketAddr>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssh: Option<SshConfig>,
}

impl From<WireTunnelSpec> for TunnelSpec {
    fn from(w: WireTunnelSpec) -> Self {
        let tunnel = match w.ssh {
            Some(s) => TunnelConfig::Ssh(s),
            None => TunnelConfig::WireGuard(w.config),
        };
        Self {
            profile_id: w.profile_id,
            profile_name: w.profile_name,
            tunnel,
            cached_endpoints: w.cached_endpoints,
        }
    }
}

impl From<TunnelSpec> for WireTunnelSpec {
    fn from(s: TunnelSpec) -> Self {
        let (config, ssh) = match s.tunnel {
            TunnelConfig::WireGuard(c) => (c, None),
            TunnelConfig::Ssh(c) => (WgConfig::placeholder(), Some(c)),
        };
        Self {
            profile_id: s.profile_id,
            profile_name: s.profile_name,
            config,
            cached_endpoints: s.cached_endpoints,
            ssh,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    Hello {
        protocol: u32,
    },
    GetStatus,
    Connect {
        spec: Box<TunnelSpec>,
    },
    Disconnect,
    GetPolicy,
    SetPolicy {
        policy: NetworkPolicy,
    },
    /// Re-read the firewall from the kernel and report whether it matches.
    VerifyFirewall,
    GetEvents {
        since: u64,
    },
    /// Distribution / dependency / backend detection, run by the daemon as root.
    GetSystemReport,
    /// Replace the split-tunnel configuration (applied atomically).
    SetSplit {
        config: crate::split::SplitConfig,
    },
    GetSplitStatus,
    /// Routing test tool: a domain or IP address.
    TestRoute {
        query: String,
    },
    /// LAN forward proxy: read its state (running, port, addresses).
    GetLanProxy,
    /// Start/stop the LAN forward proxy (validated, persisted, re-applied).
    SetLanProxy {
        config: LanProxyConfig,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    #[serde(flatten)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    InvalidConfig,
    Firewall,
    Tunnel,
    Busy,
    Unsupported,
    Internal,
    HostKeyUnknown,
    HostKeyChanged,
    AuthFailed,
    MissingDependency,
    /// A connection attempt was abandoned because the user disconnected or
    /// started another connection meanwhile. Not a failure.
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct IpcError {
    pub code: ErrorCode,
    pub message: String,
    /// Set for `HostKeyUnknown` / `HostKeyChanged`: the key the server presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<HostKey>,
}

impl IpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            host_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Unix seconds of the most recent handshake across peers (0 = never).
    pub last_handshake: u64,
    pub endpoint: Option<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchStatus {
    pub enabled: bool,
    /// True only when the kernel ruleset was read back and carries the expected tag.
    pub firewall_verified: bool,
    pub firewall_tag: Option<String>,
}

/// LAN forward proxy configuration: devices on the local network (a smart
/// TV, a console) reach the internet through this machine's tunnel. Optional
/// username/password authentication — see LAN_PROXY.md.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanProxyConfig {
    pub enabled: bool,
    pub port: u16,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    /// `None`: open to anyone on the network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<ProxyAuth>,
}

/// Credentials for the LAN proxy. The GUI sends `password` only to set or
/// change it; the daemon replaces it with a salted SHA-256 `verifier` before
/// persisting, and never reports either back.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<zeroize::Zeroizing<String>>,
    /// `<salt hex>$<sha256(salt || password) hex>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
}

impl std::fmt::Debug for ProxyAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyAuth")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("verifier", &self.verifier.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Longest username/password RFC 1929 (SOCKS5 auth) can carry.
pub const MAX_PROXY_CREDENTIAL: usize = 255;

impl ProxyAuth {
    pub fn validate_username(u: &str) -> Result<(), String> {
        if u.is_empty() || u.len() > MAX_PROXY_CREDENTIAL {
            return Err(format!("username must be 1-{MAX_PROXY_CREDENTIAL} bytes"));
        }
        if u.contains(':') || u.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err("username must not contain ':', spaces or control characters".into());
        }
        Ok(())
    }

    pub fn validate_password(p: &str) -> Result<(), String> {
        if p.is_empty() || p.len() > MAX_PROXY_CREDENTIAL {
            return Err(format!("password must be 1-{MAX_PROXY_CREDENTIAL} bytes"));
        }
        if p.chars().any(char::is_control) {
            return Err("password must not contain control characters".into());
        }
        Ok(())
    }

    pub fn make_verifier(password: &str, salt: &[u8; 16]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(salt);
        h.update(password.as_bytes());
        format!("{}${}", hex::encode(salt), hex::encode(h.finalize()))
    }

    /// Constant-time check of a client's credentials against the stored verifier.
    pub fn check(&self, username: &[u8], password: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let Some((salt, want)) = self.verifier.as_deref().and_then(|v| v.split_once('$')) else {
            return false;
        };
        let (Ok(salt), Ok(want)) = (hex::decode(salt), hex::decode(want)) else {
            return false;
        };
        let mut h = Sha256::new();
        h.update(&salt);
        h.update(password);
        let got = h.finalize();
        let user_ok = ct_eq(username, self.username.as_bytes());
        ct_eq(&got, &want) & user_ok
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn default_socks_port() -> u16 {
    1080
}

impl Default for LanProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8080,
            socks_port: 1080,
            auth: None,
        }
    }
}

impl LanProxyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("HTTP proxy port must be between 1 and 65535".into());
        }
        if self.socks_port == 0 {
            return Err("SOCKS5 proxy port must be between 1 and 65535".into());
        }
        if self.port == self.socks_port {
            return Err("HTTP and SOCKS5 ports must be different".into());
        }
        if let Some(a) = &self.auth {
            ProxyAuth::validate_username(&a.username)?;
            if let Some(p) = &a.password {
                ProxyAuth::validate_password(p)?;
            }
        }
        Ok(())
    }
}

/// What the daemon reports about the LAN proxy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanProxyStatus {
    pub enabled: bool,
    /// Configured HTTP proxy port; 0 only in the default (never configured) status.
    pub port: u16,
    /// Configured SOCKS5 proxy port.
    #[serde(default)]
    pub socks_port: u16,
    /// IPv4 addresses other devices can reach the proxy on (loopback and the
    /// tunnel interface excluded). Refreshed on apply and on network changes.
    pub addresses: Vec<std::net::IpAddr>,
    /// Set when the HTTP listener could not be started (port in use, permission).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether the HTTP listener is actually accepting connections right now.
    #[serde(default)]
    pub listening: bool,
    /// Set when the SOCKS5 listener could not be started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_error: Option<String>,
    /// Whether the SOCKS5 listener is accepting connections right now.
    #[serde(default)]
    pub socks_listening: bool,
    /// Username clients must log in with; absent when the proxy is open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_username: Option<String>,
    /// SOCKS5 UDP ASSOCIATE is available (UDP relay on the SOCKS5 port).
    #[serde(default)]
    pub socks_udp: bool,
}

/// Proxy mode's local proxy on 127.0.0.1.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalProxyStatus {
    /// Proxy mode is selected (the listeners should be up).
    pub active: bool,
    pub socks_port: u16,
    pub http_port: u16,
    pub socks_listening: bool,
    pub http_listening: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// SOCKS5 UDP ASSOCIATE works with the current tunnel.
    #[serde(default)]
    pub udp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub state: ConnectionState,
    pub profile_id: Option<String>,
    pub profile_name: Option<String>,
    pub interface: Option<String>,
    /// Unix seconds when the current tunnel came up.
    pub connected_since: Option<u64>,
    pub stats: Option<TunnelStats>,
    pub kill_switch: KillSwitchStatus,
    pub policy: NetworkPolicy,
    pub last_error: Option<String>,
    pub tunnel_config: Option<PublicConfig>,
    pub daemon_version: String,
    pub dns_backend: crate::sysprobe::DnsBackend,
    /// Unix seconds when this daemon process started. Clients use a change
    /// to detect a service restart (upgrade, crash recovery).
    #[serde(default)]
    pub daemon_started: u64,
    /// `"ssh"` for SSH tunnels; absent for WireGuard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_kind: Option<String>,
    /// LAN forward proxy (share this machine's VPN with other devices).
    #[serde(default)]
    pub lan_proxy: LanProxyStatus,
    /// Proxy mode's local SOCKS5/HTTP proxy.
    #[serde(default)]
    pub local_proxy: LocalProxyStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Connection,
    Firewall,
    Dns,
    Network,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonEvent {
    pub seq: u64,
    pub ts: u64,
    pub level: EventLevel,
    pub category: EventCategory,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Payload {
    Hello { protocol: u32, version: String },
    Status(Box<DaemonStatus>),
    Policy(NetworkPolicy),
    Firewall { verified: bool, tag: Option<String> },
    Events(Vec<DaemonEvent>),
    System(Box<crate::sysprobe::SystemReport>),
    Split(Box<SplitStatus>),
    RouteTest(Box<RouteTest>),
    LanProxy(LanProxyStatus),
    Ok,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub result: Result<Payload, IpcError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_format() {
        let r = Request {
            id: 7,
            command: Command::GetEvents { since: 3 },
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"id":7,"cmd":"get_events","since":3}"#);
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back.command, Command::GetEvents { since: 3 }));
    }

    #[test]
    fn unknown_commands_are_rejected() {
        assert!(serde_json::from_str::<Request>(r#"{"id":1,"cmd":"exec","argv":["sh"]}"#).is_err());
    }

    #[test]
    fn lan_proxy_command_wire_format() {
        let c = Command::SetLanProxy {
            config: LanProxyConfig {
                enabled: true,
                port: 8080,
                socks_port: 1080,
                auth: None,
            },
        };
        let s = serde_json::to_string(&c).unwrap();
        assert_eq!(
            s,
            r#"{"cmd":"set_lan_proxy","config":{"enabled":true,"port":8080,"socks_port":1080}}"#
        );
        let back: Command = serde_json::from_str(&s).unwrap();
        assert!(
            matches!(back, Command::SetLanProxy { config } if config.enabled && config.port == 8080 && config.socks_port == 1080)
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"id":2,"cmd":"get_lan_proxy"}"#)
                .unwrap()
                .command,
            Command::GetLanProxy
        ));
    }

    #[test]
    fn proxy_auth_verifier_and_redaction() {
        let mut a = ProxyAuth {
            username: "tv".into(),
            password: Some(zeroize::Zeroizing::new("s3cret".into())),
            verifier: None,
        };
        assert!(!format!("{a:?}").contains("s3cret"));
        a.verifier = Some(ProxyAuth::make_verifier("s3cret", &[7u8; 16]));
        a.password = None;
        assert!(a.check(b"tv", b"s3cret"));
        assert!(!a.check(b"tv", b"s3cret!"));
        assert!(!a.check(b"tV", b"s3cret"));
        assert!(!ProxyAuth {
            verifier: None,
            ..a.clone()
        }
        .check(b"tv", b"s3cret"));
        let j = serde_json::to_string(&a).unwrap();
        assert!(!j.contains("s3cret") && !j.contains("password"));
        assert!(ProxyAuth::validate_username("a:b").is_err());
        assert!(ProxyAuth::validate_password(&"x".repeat(256)).is_err());
    }

    #[test]
    fn lan_proxy_status_tolerates_a_missing_error_field() {
        let s: LanProxyStatus = serde_json::from_str(r#"{"enabled":true,"port":9090,"addresses":[]}"#).unwrap();
        assert!(s.enabled);
        assert_eq!(s.port, 9090);
        assert_eq!(LanProxyStatus::default().port, 0);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedIp {
    pub ip: std::net::IpAddr,
    /// Unix seconds when the DNS TTL expires.
    pub expires_at: u64,
    /// Past TTL but kept for the grace period while refresh is failing.
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStatus {
    pub rule_id: String,
    pub domain: String,
    pub addrs: Vec<ResolvedIp>,
    pub cnames: Vec<String>,
    pub last_resolved: Option<u64>,
    pub next_refresh: Option<u64>,
    pub last_error: Option<String>,
    /// How this name was learned: "configured" (rule target) or "observed".
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitStatus {
    pub config: crate::split::SplitConfig,
    pub domains: Vec<DomainStatus>,
    pub warnings: Vec<crate::split::SplitWarning>,
    pub direct: crate::split::DirectSets,
    /// True when the kernel ruleset carrying these sets was verified.
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTestEntry {
    pub ip: std::net::IpAddr,
    pub decision: crate::split::Decision,
    /// Interface the policy intends ("alizy0", the physical uplink, or "blocked").
    pub intended: String,
    /// Membership in the kernel's direct set, read back from nftables.
    pub in_kernel_direct_set: Option<bool>,
    /// `ip route get` output for the address with the mark the packet would carry.
    pub kernel_route: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTest {
    pub query: String,
    pub domain_decision: Option<crate::split::Decision>,
    pub cnames: Vec<String>,
    pub entries: Vec<RouteTestEntry>,
    pub error: Option<String>,
}

#[cfg(test)]
mod ssh_ipc_tests {
    use super::*;
    use crate::ssh::{HostKey, SshConfig, SshPublic};

    const GOLD_CONNECT: &str = r#"{"cmd":"connect","spec":{"profile_id":"p1","profile_name":"Home","config":{"interface":{"private_key":"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=","addresses":["10.66.0.2/32","fd00:66::2/128"],"dns":["10.66.0.1"],"dns_search":["corp.example"],"mtu":1420,"listen_port":null},"peers":[{"public_key":"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=","preshared_key":"XDnhSwHmuXzMhW9ffSo/KQPg8f8ihQ0p0AeHPd5L6kI=","allowed_ips":["0.0.0.0/0","::/0"],"endpoint":{"host":{"kind":"name","value":"vpn.example.com"},"port":51820},"persistent_keepalive":25}]},"cached_endpoints":[null]}}"#;
    const GOLD_ERR: &str = r#"{"code":"tunnel","message":"boom"}"#;

    fn wg_spec() -> TunnelSpec {
        let cfg = crate::config::parse(&crate::config::tests::sample()).unwrap().config;
        TunnelSpec {
            profile_id: "p1".into(),
            profile_name: "Home".into(),
            tunnel: TunnelConfig::WireGuard(cfg),
            cached_endpoints: vec![None],
        }
    }

    #[test]
    fn wg_connect_json_unchanged() {
        let c = Command::Connect {
            spec: Box::new(wg_spec()),
        };
        assert_eq!(serde_json::to_string(&c).unwrap(), GOLD_CONNECT);
        let back: Command = serde_json::from_str(GOLD_CONNECT).unwrap();
        assert!(matches!(back, Command::Connect { spec } if matches!(spec.tunnel, TunnelConfig::WireGuard(_))));
    }

    /// What a pre-refactor GUI sends for an SSH profile, byte for byte.
    const GOLD_SSH_CONNECT: &str = r#"{"cmd":"connect","spec":{"profile_id":"s1","profile_name":"Box","config":{"interface":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","addresses":[],"dns":[],"dns_search":[],"mtu":null,"listen_port":null},"peers":[]},"cached_endpoints":[],"ssh":{"public":{"host":"203.0.113.5","port":22,"username":"alice","host_key":null,"dns":[]},"password":"hunter2"}}}"#;

    #[test]
    fn ssh_connect_json_unchanged() {
        let back: Command = serde_json::from_str(GOLD_SSH_CONNECT).unwrap();
        let Command::Connect { spec } = &back else { panic!() };
        let TunnelConfig::Ssh(ssh) = &spec.tunnel else {
            panic!("decoded as {:?}", spec.tunnel.kind())
        };
        assert_eq!(ssh.public.username, "alice");
        assert_eq!(serde_json::to_string(&back).unwrap(), GOLD_SSH_CONNECT);
    }

    #[test]
    fn ipc_error_without_host_key_json_unchanged() {
        let e = IpcError::new(ErrorCode::Tunnel, "boom");
        assert_eq!(serde_json::to_string(&e).unwrap(), GOLD_ERR);
        let back: IpcError = serde_json::from_str(GOLD_ERR).unwrap();
        assert!(back.host_key.is_none());
    }

    #[test]
    fn ssh_spec_roundtrips() {
        let mut spec = wg_spec();
        spec.tunnel = TunnelConfig::Ssh(SshConfig {
            public: SshPublic {
                host: "203.0.113.5".parse().unwrap(),
                port: 22,
                username: "alice".into(),
                host_key: None,
                dns: vec![],
            },
            password: zeroize::Zeroizing::new("hunter2".into()),
        });
        let s = serde_json::to_string(&Command::Connect { spec: Box::new(spec) }).unwrap();
        let back: Command = serde_json::from_str(&s).unwrap();
        let Command::Connect { spec } = back else { panic!() };
        let TunnelConfig::Ssh(ssh) = spec.tunnel else { panic!() };
        assert_eq!(ssh.public.username, "alice");
        assert_eq!(&*ssh.password, "hunter2");
        assert!(!format!("{ssh:?}").contains("hunter2"));
    }

    #[test]
    fn host_key_error_roundtrips() {
        let mut e = IpcError::new(ErrorCode::HostKeyUnknown, "unknown");
        e.host_key = Some(HostKey {
            key_type: "ssh-ed25519".into(),
            key_b64: "AAAA".into(),
        });
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(r#""code":"host_key_unknown""#));
        let back: IpcError = serde_json::from_str(&s).unwrap();
        assert_eq!(back.host_key, e.host_key);
        for c in [
            ErrorCode::HostKeyChanged,
            ErrorCode::AuthFailed,
            ErrorCode::MissingDependency,
            ErrorCode::Cancelled,
        ] {
            let j = serde_json::to_string(&c).unwrap();
            assert_eq!(serde_json::from_str::<ErrorCode>(&j).unwrap(), c);
        }
    }

    #[test]
    fn placeholder_splits_and_is_not_real() {
        let p = crate::config::WgConfig::placeholder();
        assert!(p.peers.is_empty());
        let _ = p.split();
    }
}
