//! GUI ⇄ daemon protocol: newline-delimited JSON over a Unix socket.
//!
//! The command set is closed and explicit; there is no generic "run" command.

use crate::config::{PublicConfig, WgConfig};
use crate::firewall::NetworkPolicy;
use crate::state::ConnectionState;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub const PROTOCOL_VERSION: u32 = 1;
pub const SOCKET_PATH: &str = "/run/alizy/alizyd.sock";
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelSpec {
    pub profile_id: String,
    pub profile_name: String,
    pub config: WgConfig,
    /// Last known resolved endpoint per peer (used when DNS is blocked).
    #[serde(default)]
    pub cached_endpoints: Vec<Option<SocketAddr>>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct IpcError {
    pub code: ErrorCode,
    pub message: String,
}

impl IpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
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
