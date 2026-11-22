//! Linux platform adapter: kernel WireGuard + iproute2 + nftables + DNS backends.
//! One implementation for all distributions; behaviour depends on detected
//! capabilities only.

pub mod dns;
pub mod firewall;
pub mod netmon;
pub mod wireguard;

use crate::exec::run;
use alizy_core::config::WgConfig;
use alizy_core::firewall::FirewallPlan;
use alizy_core::ipc::TunnelStats;
use alizy_core::platform::{AdapterResult, PlatformAdapter};
use alizy_core::routing::{teardown_commands, DnsPlan, RoutePlan};
use alizy_core::sysprobe::DnsBackend;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct LinuxAdapter {
    dns: dns::Dns,
    /// `None` = DNS management disabled by flag (test environments only).
    dns_backend: Mutex<Option<DnsBackend>>,
    dns_disabled: bool,
    /// Kernel snapshot of the last successful apply (see firewall::Baseline).
    baseline: Mutex<Option<firewall::Baseline>>,
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
        wireguard::stats(iface).await
    }
}
