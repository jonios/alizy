//! Platform adapter contract.
//!
//! Each operating system implements firewall, routing and DNS control with
//! its own native mechanism. The contract is protocol-neutral: creating a
//! tunnel's interface is a protocol driver's job (see `alizyd::driver`); the
//! platform applies the plans this crate renders for any tunnel. The
//! security-critical policy decisions stay in this crate.

use crate::firewall::FirewallPlan;
use crate::routing::{DnsPlan, RoutePlan};

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
    /// Install routes and (unless `None`, as in proxy mode) system DNS for a
    /// tunnel interface a driver created, then confirm it still exists.
    async fn network_up(&self, iface: &str, routes: &RoutePlan, dns: Option<&DnsPlan>) -> AdapterResult<()>;
    /// Restore DNS and remove the interface and its routing rules. Drivers
    /// stop their own processes before this runs.
    async fn tunnel_down(&self, iface: &str) -> AdapterResult<()>;
}
