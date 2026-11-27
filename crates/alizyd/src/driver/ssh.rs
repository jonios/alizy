//! SSH tunnel driver: `ssh -D` + `badvpn-tun2socks` + the in-daemon
//! DNS-over-SOCKS forwarder, all as the unprivileged `alizy-ssh` user.

use super::{mismatch, BoxFut, Ctx, Session, TunnelDriver, UpError};
use crate::cancel::CancelToken;
use crate::egress::Egress;
use crate::linux::ssh::{self as sshb, SshError, SshTunnel, SshUp};
use alizy_core::firewall::TunnelRules;
use alizy_core::ipc::{ErrorCode, EventCategory as Cat, EventLevel as Lvl, TunnelStats};
use alizy_core::protocol::{ProtocolKind, TunnelConfig};
use alizy_core::routing::ssh_upstream_plan;
use alizy_core::ssh::{HostKey, SshConfig};
use alizy_core::sysprobe::{Dependency, SystemReport};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

pub const MISSING_SSH_USER: &str = "alizy-ssh system user missing; SSH tunnels are unavailable (reinstall Alizy)";

/// Where and as whom SSH tunnels run.
pub struct SshEnv {
    /// (uid, primary gid) of `alizy-ssh`; `None` disables SSH tunnels.
    pub user: Option<(u32, u32)>,
    /// Runtime directory for known_hosts files and askpass sockets.
    pub runtime: PathBuf,
}

/// OS boundary: child processes and `ssh-keyscan` (production: [`LinuxSsh`]).
pub trait SshOps: Send + Sync + 'static {
    type Tunnel: Send + 'static;
    fn start(&self, req: SshUp<'_>) -> impl Future<Output = Result<Self::Tunnel, SshError>> + Send;
    fn stop(&self, t: Self::Tunnel) -> impl Future<Output = ()> + Send;
    fn try_exited(&self, t: &mut Self::Tunnel) -> Option<String>;
    fn stats(&self, t: &Self::Tunnel, iface: &str) -> TunnelStats;
    /// Fetch a server's host key as `user` (never root); gives up once `cancel` fires.
    fn keyscan(
        &self,
        user: (u32, u32),
        host: IpAddr,
        port: u16,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<HostKey, String>> + Send;
    /// Missing dependencies; any version probe runs as `user` with a timeout.
    fn missing(&self, user: (u32, u32)) -> impl Future<Output = Vec<Dependency>> + Send;
}

pub struct LinuxSsh;

impl SshOps for LinuxSsh {
    type Tunnel = SshTunnel;
    async fn start(&self, req: SshUp<'_>) -> Result<SshTunnel, SshError> {
        sshb::start(&req).await
    }
    async fn stop(&self, t: SshTunnel) {
        t.stop().await
    }
    fn try_exited(&self, t: &mut SshTunnel) -> Option<String> {
        t.try_exited()
    }
    fn stats(&self, t: &SshTunnel, iface: &str) -> TunnelStats {
        t.stats(iface)
    }
    async fn keyscan(
        &self,
        user: (u32, u32),
        host: IpAddr,
        port: u16,
        cancel: &CancelToken,
    ) -> Result<HostKey, String> {
        sshb::keyscan(user, host, port, cancel).await
    }
    async fn missing(&self, user: (u32, u32)) -> Vec<Dependency> {
        sshb::missing_deps(user).await
    }
}

impl From<SshError> for UpError {
    fn from(e: SshError) -> Self {
        Self {
            code: e.code(),
            msg: e.to_string(),
            host_key: e.host_key(),
        }
    }
}

pub struct SshDriver<O: SshOps = LinuxSsh> {
    ops: O,
    env: SshEnv,
    tunnel: tokio::sync::Mutex<Option<O::Tunnel>>,
}

impl<O: SshOps> SshDriver<O> {
    pub fn new(ops: O, env: SshEnv) -> Self {
        Self {
            ops,
            env,
            tunnel: tokio::sync::Mutex::new(None),
        }
    }

    fn user(&self) -> Result<(u32, u32), UpError> {
        self.env
            .user
            .ok_or_else(|| UpError::new(ErrorCode::MissingDependency, MISSING_SSH_USER))
    }
}

fn config(t: &TunnelConfig) -> Result<&SshConfig, UpError> {
    match t {
        TunnelConfig::Ssh(c) => Ok(c),
        other => Err(mismatch(ProtocolKind::Ssh, other)),
    }
}

impl<O: SshOps> TunnelDriver for SshDriver<O> {
    fn kind(&self) -> ProtocolKind {
        ProtocolKind::Ssh
    }

    fn preflight(&self) -> BoxFut<'_, Result<(), UpError>> {
        Box::pin(async move {
            let user = self.user()?;
            let missing = self.ops.missing(user).await;
            if missing.is_empty() {
                return Ok(());
            }
            let names: Vec<&str> = missing.iter().map(|d| d.label()).collect();
            Err(UpError::new(
                ErrorCode::MissingDependency,
                format!("SSH tunnels need: {}", names.join(", ")),
            ))
        })
    }

    fn prepare(&self) -> Result<Session, UpError> {
        self.user()?;
        let port = sshb::pick_loopback_port().map_err(|e| format!("no free loopback port for the SSH proxy: {e}"))?;
        Ok(Session { local_port: Some(port) })
    }

    /// The server's TCP endpoint for alizy-ssh's uid, the SOCKS port, and the
    /// UDP block (the SSH tunnel cannot carry UDP).
    fn firewall_rules(&self, iface: &str, endpoints: &[SocketAddr], session: &Session) -> TunnelRules {
        TunnelRules {
            iface: iface.to_string(),
            tcp_endpoints: endpoints.to_vec(),
            ssh_uid: self.env.user.map(|u| u.0),
            socks_port: session.local_port,
            block_udp: true,
            ..Default::default()
        }
    }

    /// Through `ssh -D` (root may use its port; the firewall allows only
    /// root and alizy-ssh). Names are resolved by the SSH server. TCP only.
    fn proxy_egress(&self, session: &Session, _dns: &[IpAddr]) -> Egress {
        match session.local_port {
            Some(p) => Egress::Socks(SocketAddr::from(([127, 0, 0, 1], p))),
            None => Egress::Blocked,
        }
    }

    /// Unknown server: fetch its key (as alizy-ssh, through the new firewall's
    /// exception) for the user to confirm, then stop without touching the
    /// running tunnel.
    fn verify<'a>(&'a self, ctx: Ctx<'a>) -> BoxFut<'a, Result<(), UpError>> {
        Box::pin(async move {
            let cfg = config(ctx.tunnel)?;
            if cfg.public.host_key.is_some() {
                return Ok(());
            }
            let user = self.user()?;
            let key = self
                .ops
                .keyscan(user, cfg.public.host, cfg.public.port, ctx.cancel)
                .await
                .map_err(|e| format!("could not fetch the SSH server's host key: {e}"))?;
            Err(UpError {
                code: ErrorCode::HostKeyUnknown,
                msg: format!(
                    "the SSH server's host key is not known yet; confirm its fingerprint {} to connect",
                    key.fingerprint_sha256()
                ),
                host_key: Some(key),
            })
        })
    }

    fn start<'a>(&'a self, ctx: Ctx<'a>) -> BoxFut<'a, Result<(), UpError>> {
        Box::pin(async move {
            let cfg = config(ctx.tunnel)?;
            let user = self.user()?;
            let socks_port = ctx
                .session
                .local_port
                .ok_or_else(|| UpError::new(ErrorCode::Internal, "SSH session has no proxy port"))?;
            let upstreams = ssh_upstream_plan(&cfg.public, ctx.policy);
            if !upstreams.dropped.is_empty() {
                let list = |v: &[IpAddr]| v.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
                ctx.events.push(
                    Lvl::Warn,
                    Cat::Dns,
                    format!(
                        "Custom DNS servers on your local network can't be reached through an SSH tunnel; using {} (ignored: {}).",
                        list(&upstreams.servers),
                        list(&upstreams.dropped)
                    ),
                );
            }
            let t = self
                .ops
                .start(SshUp {
                    iface: ctx.iface,
                    cfg,
                    user,
                    runtime: &self.env.runtime,
                    socks_port,
                    upstreams: upstreams.servers,
                    ipv6: ctx.policy.ipv6_enabled,
                    cancel: ctx.cancel.clone(),
                })
                .await?;
            *self.tunnel.lock().await = Some(t);
            Ok(())
        })
    }

    fn stop(&self) -> BoxFut<'_, ()> {
        Box::pin(async move {
            let t = self.tunnel.lock().await.take();
            if let Some(t) = t {
                self.ops.stop(t).await;
            }
        })
    }

    fn exited(&self) -> BoxFut<'_, Option<String>> {
        Box::pin(async move {
            let mut g = self.tunnel.lock().await;
            g.as_mut()
                .and_then(|t| self.ops.try_exited(t))
                .map(|why| format!("SSH connection lost: {why}"))
        })
    }

    fn stats<'a>(&'a self, iface: &'a str) -> BoxFut<'a, Result<Option<TunnelStats>, String>> {
        Box::pin(async move { Ok(self.tunnel.lock().await.as_ref().map(|t| self.ops.stats(t, iface))) })
    }

    /// `probe` only checks that the SSH executables exist (it never runs ssh
    /// as root). The authoritative check, including the OpenSSH version, runs
    /// `ssh -V` as alizy-ssh with a timeout.
    fn augment_report<'a>(&'a self, report: &'a mut SystemReport) -> BoxFut<'a, ()> {
        Box::pin(async move {
            if let Some(user) = self.env.user {
                report.set_ssh_missing(self.ops.missing(user).await);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alizy_core::firewall::{FirewallPlan, NetworkPolicy};

    struct NoOps;
    impl SshOps for NoOps {
        type Tunnel = ();
        async fn start(&self, _: SshUp<'_>) -> Result<(), SshError> {
            Ok(())
        }
        async fn stop(&self, _: ()) {}
        fn try_exited(&self, _: &mut ()) -> Option<String> {
            None
        }
        fn stats(&self, _: &(), _: &str) -> TunnelStats {
            TunnelStats::default()
        }
        async fn keyscan(&self, _: (u32, u32), _: IpAddr, _: u16, _: &CancelToken) -> Result<HostKey, String> {
            Err("unused".into())
        }
        async fn missing(&self, _: (u32, u32)) -> Vec<Dependency> {
            vec![]
        }
    }

    fn driver(user: Option<(u32, u32)>) -> SshDriver<NoOps> {
        SshDriver::new(
            NoOps,
            SshEnv {
                user,
                runtime: PathBuf::from("/nonexistent"),
            },
        )
    }

    #[test]
    fn firewall_rules_set_tcp_uid_port_and_udp_block() {
        let ep: SocketAddr = "203.0.113.5:22".parse().unwrap();
        let s = Session {
            local_port: Some(40000),
        };
        let r = driver(Some((60123, 60123))).firewall_rules("alizy0", &[ep], &s);
        assert_eq!(
            r,
            TunnelRules {
                iface: "alizy0".into(),
                endpoints: vec![],
                tcp_endpoints: vec![ep],
                ssh_uid: Some(60123),
                socks_port: Some(40000),
                block_udp: true,
            }
        );
        let text = FirewallPlan::new(
            &NetworkPolicy {
                kill_switch: true,
                ..Default::default()
            },
            Some(r),
        )
        .render();
        assert!(text.contains("ssh_mark") && text.contains("meta skuid 60123"));
    }

    #[test]
    fn prepare_needs_the_system_user() {
        let e = driver(None).prepare().unwrap_err();
        assert_eq!(e.code, ErrorCode::MissingDependency);
        assert!(e.msg.contains("alizy-ssh"));
        let s = driver(Some((60123, 60123))).prepare().unwrap();
        assert!(s.local_port.is_some_and(|p| p != 0));
    }
}
