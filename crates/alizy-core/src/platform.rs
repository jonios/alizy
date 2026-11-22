//! Platform adapter contract.
//!
//! Each operating system implements tunnel, firewall and DNS control with its
//! own native mechanism. The trait is deliberately small and synchronous at
//! the boundary of "apply a plan / verify it", so the security-critical policy
//! decisions stay in this crate.

use crate::config::WgConfig;
use crate::firewall::FirewallPlan;
use crate::ipc::TunnelStats;
use crate::routing::{DnsPlan, RoutePlan};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
}

/// Per-platform implementation status. Used by the UI to show honest capability info.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    pub tunnel: bool,
    pub kill_switch: bool,
    pub dns_protection: bool,
    pub family_blocking: bool,
}

pub const fn capabilities(p: Platform) -> Capabilities {
    match p {
        Platform::Linux => Capabilities {
            tunnel: true,
            kill_switch: true,
            dns_protection: true,
            family_blocking: true,
        },
        // Not implemented yet: see docs/PLATFORMS.md.
        Platform::Windows | Platform::MacOs => Capabilities {
            tunnel: false,
            kill_switch: false,
            dns_protection: false,
            family_blocking: false,
        },
    }
}

pub type AdapterResult<T> = Result<T, String>;

/// Implemented by `alizyd::linux::LinuxAdapter`. The daemon's engine is
/// generic over this trait so each OS plugs in its native mechanism.
#[allow(async_fn_in_trait)]
pub trait PlatformAdapter: Send + Sync {
    /// Atomically replace the owned firewall state with `plan`.
    async fn apply_firewall(&self, plan: &FirewallPlan) -> AdapterResult<()>;
    /// Read the firewall back from the OS; Ok(true) only if `plan` is active.
    async fn verify_firewall(&self, plan: &FirewallPlan) -> AdapterResult<bool>;
    async fn tunnel_up(
        &self,
        iface: &str,
        cfg: &WgConfig,
        endpoints: &[Option<SocketAddr>],
        routes: &RoutePlan,
        dns: &DnsPlan,
    ) -> AdapterResult<()>;
    async fn tunnel_down(&self, iface: &str) -> AdapterResult<()>;
    async fn tunnel_stats(&self, iface: &str) -> AdapterResult<Option<TunnelStats>>;
}
