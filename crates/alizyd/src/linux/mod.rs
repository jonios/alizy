//! Linux platform adapter: kernel WireGuard (or an SSH tunnel) + iproute2 +
//! nftables + DNS backends.
//! One implementation for all distributions; behaviour depends on detected
//! capabilities only.

pub mod dns;
pub mod firewall;
pub mod netmon;
pub mod ssh;
pub mod wireguard;

use crate::engine::Backend;
use crate::exec::{argv, run};
use alizy_core::config::WgConfig;
use alizy_core::firewall::FirewallPlan;
use alizy_core::ipc::TunnelStats;
use alizy_core::platform::{AdapterResult, PlatformAdapter};
use alizy_core::routing::{split_rule_commands, teardown_commands, DnsPlan, RoutePlan};
use alizy_core::ssh::HostKey;
use alizy_core::sysprobe::DnsBackend;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct LinuxAdapter {
    dns: dns::Dns,
    /// `None` = DNS management disabled by flag (test environments only).
    dns_backend: Mutex<Option<DnsBackend>>,
    dns_disabled: bool,
    /// Kernel snapshot of the last successful apply (see firewall::Baseline).
    baseline: Mutex<Option<firewall::Baseline>>,
    /// The running SSH tunnel, if the current backend is SSH.
    ssh: tokio::sync::Mutex<Option<ssh::SshTunnel>>,
}

impl LinuxAdapter {
    pub async fn new(state_dir: &Path, dns_override: Option<Option<DnsBackend>>, resolv_conf: Option<PathBuf>) -> Self {
        let (backend, disabled) = match dns_override {
            Some(b) => (b, b.is_none()),
            None => (Some(dns::detect_backend().await), false),
        };
        Self {
            dns: dns::Dns::new(state_dir, resolv_conf),
            dns_backend: Mutex::new(backend),
            dns_disabled: disabled,
            baseline: Mutex::new(None),
            ssh: tokio::sync::Mutex::new(None),
        }
    }

    pub fn dns_backend(&self) -> Option<DnsBackend> {
        *self.dns_backend.lock().unwrap()
    }

    /// Re-detect (e.g. after resolved was started/stopped).
    pub async fn refresh_dns_backend(&self) {
        if !self.dns_disabled {
            let b = dns::detect_backend().await;
            *self.dns_backend.lock().unwrap() = Some(b);
        }
    }

    pub fn reassert_dns(&self, plan: &DnsPlan) -> Result<bool, String> {
        match self.dns_backend() {
            Some(b) => self.dns.reassert(b, plan),
            None => Ok(false),
        }
    }

    pub fn restore_dns_backup(&self) -> Result<(), String> {
        self.dns.restore_backup()
    }

    async fn apply_routes(&self, routes: &RoutePlan) -> Result<(), String> {
        for key in &routes.sysctls {
            let path = PathBuf::from("/proc/sys").join(key.replace('.', "/"));
            std::fs::write(&path, b"1").map_err(|e| format!("sysctl {key}: {e}"))?;
        }
        for cmd in &routes.up {
            match run(cmd, None).await {
                Ok(_) => {}
                // A route for this prefix already exists and belongs to someone
                // else (e.g. docker0 or the LAN): keep theirs, never replace it.
                Err(e)
                    if cmd.get(3).map(String::as_str) == Some("route")
                        && cmd.get(4).map(String::as_str) == Some("add")
                        && e.stderr_contains("File exists") =>
                {
                    tracing::warn!("route {} already exists; leaving the existing route in place", cmd[5]);
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(())
    }

    /// Bring up an SSH tunnel on `alizy0`: any previous tunnel (WireGuard or
    /// SSH) is torn down first; then ssh + tun2socks + DNS forwarder, routes,
    /// system DNS. On error the caller runs `tunnel_down`, which stops
    /// whatever was started here.
    pub async fn ssh_up(&self, req: ssh::SshUp<'_>) -> Result<(), ssh::SshError> {
        let had_ssh = self.ssh.lock().await.is_some();
        if had_ssh || wireguard::exists(req.iface) {
            self.tunnel_down(req.iface).await.map_err(ssh::SshError::Other)?;
        }
        let t = ssh::start(&req).await?;
        *self.ssh.lock().await = Some(t);
        self.apply_routes(req.routes).await.map_err(ssh::SshError::Other)?;
        if let Some(b) = self.dns_backend() {
            self.dns
                .apply(b, req.iface, req.dns)
                .await
                .map_err(ssh::SshError::Other)?;
        }
        if !wireguard::exists(req.iface) {
            return Err(ssh::SshError::Other("interface disappeared during bring-up".into()));
        }
        Ok(())
    }
}

impl PlatformAdapter for LinuxAdapter {
    async fn apply_firewall(&self, plan: &FirewallPlan) -> AdapterResult<()> {
        *self.baseline.lock().unwrap() = None;
        let b = firewall::apply_and_snapshot(plan).await?;
        *self.baseline.lock().unwrap() = Some(b);
        Ok(())
    }

    async fn verify_firewall(&self, plan: &FirewallPlan) -> AdapterResult<bool> {
        let baseline = self.baseline.lock().unwrap().clone();
        match baseline {
            Some(b) if b.tag == plan.tag() => firewall::verify_against(&b).await,
            // No snapshot for this plan: never report it as verified.
            _ => Ok(false),
        }
    }

    async fn tunnel_up(
        &self,
        iface: &str,
        cfg: &WgConfig,
        endpoints: &[Option<SocketAddr>],
        routes: &RoutePlan,
        dns_plan: &DnsPlan,
    ) -> AdapterResult<()> {
        if wireguard::exists(iface) {
            self.tunnel_down(iface).await?;
        }
        wireguard::create(iface, cfg, endpoints).await?;
        self.apply_routes(routes).await?;
        if let Some(b) = self.dns_backend() {
            self.dns.apply(b, iface, dns_plan).await?;
        }
        if !wireguard::exists(iface) {
            return Err("interface disappeared during bring-up".into());
        }
        Ok(())
    }

    async fn tunnel_down(&self, iface: &str) -> AdapterResult<()> {
        // SSH children and the DNS forwarder go first, before their TUN.
        if let Some(t) = self.ssh.lock().await.take() {
            t.stop().await;
        }
        let mut errors = Vec::new();
        if let Some(b) = self.dns_backend() {
            if let Err(e) = self.dns.revert(b, iface).await {
                errors.push(format!("DNS restore: {e}"));
            }
        }
        for cmd in teardown_commands(iface) {
            // Absent rules/links are expected here; real failures are caught below.
            let _ = run(&cmd, None).await;
        }
        // An SSH TUN is normally gone with `ip link del`; this catches the rest.
        let _ = run(&argv(&["ip", "tuntap", "del", "dev", iface, "mode", "tun"]), None).await;
        if wireguard::exists(iface) {
            errors.push(format!("interface {iface} could not be removed"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    async fn tunnel_stats(&self, iface: &str) -> AdapterResult<Option<TunnelStats>> {
        if let Some(t) = self.ssh.lock().await.as_ref() {
            return Ok(Some(t.stats(iface)));
        }
        wireguard::stats(iface).await
    }
}

impl Backend for LinuxAdapter {
    fn dns_backend(&self) -> Option<DnsBackend> {
        LinuxAdapter::dns_backend(self)
    }

    async fn refresh_dns_backend(&self) {
        LinuxAdapter::refresh_dns_backend(self).await
    }

    fn reassert_dns(&self, plan: &DnsPlan) -> Result<bool, String> {
        LinuxAdapter::reassert_dns(self, plan)
    }

    fn restore_dns_backup(&self) -> Result<(), String> {
        LinuxAdapter::restore_dns_backup(self)
    }

    fn iface_exists(&self, iface: &str) -> bool {
        wireguard::exists(iface)
    }

    async fn set_endpoint(&self, iface: &str, peer: &str, ep: SocketAddr) -> Result<(), String> {
        wireguard::set_endpoint(iface, peer, ep).await
    }

    async fn set_split_rule(&self, want: bool) -> Vec<String> {
        for c in split_rule_commands(false) {
            let _ = run(&c, None).await;
        }
        let mut errors = Vec::new();
        if want {
            let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/src_valid_mark", b"1");
            for c in split_rule_commands(true) {
                if let Err(e) = run(&c, None).await {
                    errors.push(e.to_string());
                }
            }
        }
        errors
    }

    async fn ssh_up(&self, req: ssh::SshUp<'_>) -> Result<(), ssh::SshError> {
        LinuxAdapter::ssh_up(self, req).await
    }

    async fn ssh_try_exited(&self) -> Option<String> {
        self.ssh.lock().await.as_mut().and_then(ssh::SshTunnel::try_exited)
    }

    async fn keyscan(&self, user: (u32, u32), host: IpAddr, port: u16) -> Result<HostKey, String> {
        ssh::keyscan(user, host, port).await
    }

    async fn ssh_missing(&self, user: (u32, u32)) -> Vec<String> {
        ssh::missing_deps(user)
            .await
            .iter()
            .map(|d| d.label().to_string())
            .collect()
    }
}
