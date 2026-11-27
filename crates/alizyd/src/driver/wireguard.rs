//! Kernel WireGuard driver.

use super::{mismatch, BoxFut, Ctx, Session, TunnelDriver, UpError};
use crate::egress::Egress;
use alizy_core::config::WgConfig;
use alizy_core::firewall::TunnelRules;
use alizy_core::ipc::TunnelStats;
use alizy_core::protocol::{ProtocolKind, TunnelConfig};
use std::future::Future;
use std::net::SocketAddr;

/// OS boundary: `ip link` / `wg` (production: [`LinuxWg`]).
pub trait WgOps: Send + Sync + 'static {
    fn create(
        &self,
        iface: &str,
        cfg: &WgConfig,
        endpoints: &[Option<SocketAddr>],
    ) -> impl Future<Output = Result<(), String>> + Send;
    fn set_endpoint(&self, iface: &str, peer: &str, ep: SocketAddr) -> impl Future<Output = Result<(), String>> + Send;
    fn stats(&self, iface: &str) -> impl Future<Output = Result<Option<TunnelStats>, String>> + Send;
}

pub struct LinuxWg;

impl WgOps for LinuxWg {
    async fn create(&self, iface: &str, cfg: &WgConfig, endpoints: &[Option<SocketAddr>]) -> Result<(), String> {
        crate::linux::wireguard::create(iface, cfg, endpoints).await
    }
    async fn set_endpoint(&self, iface: &str, peer: &str, ep: SocketAddr) -> Result<(), String> {
        crate::linux::wireguard::set_endpoint(iface, peer, ep).await
    }
    async fn stats(&self, iface: &str) -> Result<Option<TunnelStats>, String> {
        crate::linux::wireguard::stats(iface).await
    }
}

pub struct WireGuardDriver<O = LinuxWg> {
    ops: O,
}

impl<O: WgOps> WireGuardDriver<O> {
    pub fn new(ops: O) -> Self {
        Self { ops }
    }
}

fn config(t: &TunnelConfig) -> Result<&WgConfig, UpError> {
    match t {
        TunnelConfig::WireGuard(c) => Ok(c),
        other => Err(mismatch(ProtocolKind::WireGuard, other)),
    }
}

impl<O: WgOps> TunnelDriver for WireGuardDriver<O> {
    fn kind(&self) -> ProtocolKind {
        ProtocolKind::WireGuard
    }

    /// Only the UDP endpoints, which the WireGuard socket reaches with FWMARK.
    fn firewall_rules(&self, iface: &str, endpoints: &[SocketAddr], _session: &Session) -> TunnelRules {
        TunnelRules {
            iface: iface.to_string(),
            endpoints: endpoints.to_vec(),
            ..Default::default()
        }
    }

    /// Sockets marked `PROXY_MARK` (routed only into the WireGuard table);
    /// names resolved through the tunnel's DNS (or public resolvers inside it).
    fn proxy_egress(&self, _session: &Session, dns: &[std::net::IpAddr]) -> Egress {
        let dns = if dns.is_empty() {
            alizy_core::ssh::DEFAULT_SSH_DNS.to_vec()
        } else {
            dns.to_vec()
        };
        Egress::Marked {
            mark: alizy_core::firewall::PROXY_MARK,
            dns,
        }
    }

    fn start<'a>(&'a self, ctx: Ctx<'a>) -> BoxFut<'a, Result<(), UpError>> {
        Box::pin(async move {
            let cfg = config(ctx.tunnel)?;
            self.ops.create(ctx.iface, cfg, ctx.endpoints).await?;
            Ok(())
        })
    }

    fn stats<'a>(&'a self, iface: &'a str) -> BoxFut<'a, Result<Option<TunnelStats>, String>> {
        Box::pin(self.ops.stats(iface))
    }

    fn update_endpoints<'a>(
        &'a self,
        iface: &'a str,
        tunnel: &'a TunnelConfig,
        endpoints: &'a [Option<SocketAddr>],
    ) -> BoxFut<'a, Vec<String>> {
        Box::pin(async move {
            let cfg = match config(tunnel) {
                Ok(c) => c,
                Err(e) => return vec![e.msg],
            };
            let mut errors = Vec::new();
            for (p, ep) in cfg.peers.iter().zip(endpoints) {
                if let Some(ep) = ep {
                    if let Err(e) = self.ops.set_endpoint(iface, &p.public_key.to_base64(), *ep).await {
                        errors.push(e);
                    }
                }
            }
            errors
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alizy_core::firewall::{FirewallPlan, NetworkPolicy};

    struct NoOps;
    impl WgOps for NoOps {
        async fn create(&self, _: &str, _: &WgConfig, _: &[Option<SocketAddr>]) -> Result<(), String> {
            Ok(())
        }
        async fn set_endpoint(&self, _: &str, _: &str, _: SocketAddr) -> Result<(), String> {
            Ok(())
        }
        async fn stats(&self, _: &str) -> Result<Option<TunnelStats>, String> {
            Ok(None)
        }
    }

    #[test]
    fn firewall_rules_unchanged() {
        let ep: SocketAddr = "198.51.100.7:51820".parse().unwrap();
        let d = WireGuardDriver::new(NoOps);
        let r = d.firewall_rules("alizy0", &[ep], &Session::default());
        let golden = TunnelRules {
            iface: "alizy0".into(),
            endpoints: vec![ep],
            ..Default::default()
        };
        assert_eq!(r, golden);
        let policy = NetworkPolicy {
            kill_switch: true,
            ..Default::default()
        };
        let text = FirewallPlan::new(&policy, Some(r)).render();
        assert!(!text.contains("ssh_mark") && !text.contains("meta l4proto udp reject"));
    }
}
