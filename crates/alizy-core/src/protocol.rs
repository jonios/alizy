//! Protocol registry: the closed set of tunnel protocols the daemon accepts,
//! and the pure per-protocol planning the connection manager needs.
//!
//! This is the only module in `alizy-core` that names individual protocols.
//! The connection lifecycle, state machine and firewall planning work on the
//! protocol-neutral values returned from here ([`TunnelPlan`], endpoints).
//! The set is closed on purpose: the daemon deserialises only protocols it
//! knows how to validate and run.

use crate::config::{self, Endpoint, Host, PublicConfig, WgConfig};
use crate::firewall::NetworkPolicy;
use crate::routing::{self, DnsPlan};
use crate::ssh::{self, SshConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolKind {
    #[serde(rename = "wireguard")]
    WireGuard,
    #[serde(rename = "ssh")]
    Ssh,
}

impl ProtocolKind {
    /// Value of `DaemonStatus.tunnel_kind`. WireGuard reports none so its
    /// status JSON stays exactly as it was before other protocols existed.
    pub fn status_name(self) -> Option<&'static str> {
        match self {
            Self::WireGuard => None,
            Self::Ssh => Some("ssh"),
        }
    }

    /// How the tunnel interface is named in user-facing messages.
    pub fn interface_label(self) -> &'static str {
        match self {
            Self::WireGuard => "WireGuard",
            Self::Ssh => "SSH tunnel",
        }
    }

    /// Appended to "Connected to <profile> via <endpoints>".
    pub fn connected_suffix(self) -> &'static str {
        match self {
            Self::WireGuard => "",
            Self::Ssh => " (SSH)",
        }
    }
}

/// A complete, secret-bearing tunnel configuration for one protocol.
#[derive(Debug, Clone)]
pub enum TunnelConfig {
    WireGuard(WgConfig),
    Ssh(SshConfig),
}

/// Protocol-neutral description of the tunnel interface, derived purely from
/// a [`TunnelConfig`] and the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPlan {
    /// Interface addresses, MTU and captured prefixes; input to
    /// [`routing::route_plan`] and [`routing::compatibility_warnings`].
    pub public: PublicConfig,
    pub dns: DnsPlan,
}

impl TunnelConfig {
    pub fn kind(&self) -> ProtocolKind {
        match self {
            Self::WireGuard(_) => ProtocolKind::WireGuard,
            Self::Ssh(_) => ProtocolKind::Ssh,
        }
    }

    /// Re-validate untrusted input from the GUI from scratch.
    pub fn sanitize(self) -> Result<Self, String> {
        match self {
            Self::WireGuard(c) => {
                let c = config::parse(&c.to_wg_quick(true)).map_err(|e| e.to_string())?.config;
                if c.peers.is_empty() {
                    return Err("WireGuard configuration has no peers".into());
                }
                Ok(Self::WireGuard(c))
            }
            Self::Ssh(c) => {
                ssh::validate(&c)?;
                Ok(Self::Ssh(c))
            }
        }
    }

    /// Servers the tunnel's own traffic must reach outside the tunnel, in a
    /// stable order (WireGuard: one slot per peer, `None` without endpoint).
    pub fn endpoints(&self) -> Vec<Option<Endpoint>> {
        match self {
            Self::WireGuard(c) => c.peers.iter().map(|p| p.endpoint.clone()).collect(),
            Self::Ssh(c) => vec![Some(Endpoint {
                host: Host::Ip(c.public.host),
                port: c.public.port,
            })],
        }
    }

    pub fn plan(&self, policy: &NetworkPolicy) -> TunnelPlan {
        match self {
            Self::WireGuard(c) => {
                let (public, _) = c.split();
                let dns = routing::dns_plan(&public, policy);
                TunnelPlan { public, dns }
            }
            Self::Ssh(c) => TunnelPlan {
                public: routing::ssh_public_config(&c.public, policy),
                dns: routing::ssh_dns_plan(policy),
            },
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ssh::SshPublic;
    use zeroize::Zeroizing;

    pub fn ssh_config() -> SshConfig {
        SshConfig {
            public: SshPublic {
                host: "203.0.113.5".parse().unwrap(),
                port: 2222,
                username: "alice".into(),
                host_key: None,
                dns: vec![],
            },
            password: Zeroizing::new("pw".into()),
        }
    }

    fn wg() -> TunnelConfig {
        TunnelConfig::WireGuard(config::parse(&config::tests::sample()).unwrap().config)
    }

    #[test]
    fn kinds_and_status_names() {
        assert_eq!(wg().kind(), ProtocolKind::WireGuard);
        assert_eq!(ProtocolKind::WireGuard.status_name(), None);
        let s = TunnelConfig::Ssh(ssh_config());
        assert_eq!(s.kind().status_name(), Some("ssh"));
        assert_eq!(
            serde_json::to_string(&ProtocolKind::WireGuard).unwrap(),
            r#""wireguard""#
        );
    }

    #[test]
    fn sanitize_rejects_invalid_input_per_protocol() {
        assert!(wg().sanitize().is_ok());
        let e = TunnelConfig::WireGuard(WgConfig::placeholder()).sanitize().unwrap_err();
        assert!(e.contains("Peer") || e.contains("Address"), "{e}");
        let mut bad = ssh_config();
        bad.public.username = "-oProxyCommand=x".into();
        assert!(TunnelConfig::Ssh(bad).sanitize().is_err());
        assert!(TunnelConfig::Ssh(ssh_config()).sanitize().is_ok());
    }

    #[test]
    fn endpoints_are_protocol_neutral() {
        let eps = wg().endpoints();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].as_ref().unwrap().to_string(), "vpn.example.com:51820");
        let eps = TunnelConfig::Ssh(ssh_config()).endpoints();
        assert_eq!(eps, vec![Some("203.0.113.5:2222".parse().unwrap())]);
    }

    #[test]
    fn plans_match_the_existing_planners() {
        let policy = NetworkPolicy::default();
        let TunnelConfig::WireGuard(c) = wg() else {
            unreachable!()
        };
        let p = wg().plan(&policy);
        assert_eq!(p.public, c.split().0);
        assert_eq!(p.dns, routing::dns_plan(&p.public, &policy));
        let p = TunnelConfig::Ssh(ssh_config()).plan(&policy);
        assert_eq!(p.dns, routing::ssh_dns_plan(&policy));
        assert_eq!(p.public, routing::ssh_public_config(&ssh_config().public, &policy));
    }
}
