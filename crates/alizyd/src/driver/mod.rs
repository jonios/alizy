//! Protocol adapter layer.
//!
//! The connection manager ([`crate::engine`]) runs one lifecycle for every
//! protocol: sanitise → preflight → resolve endpoints → prepare → firewall →
//! verify → tear down the previous tunnel → start → routes + DNS. A
//! [`TunnelDriver`] supplies only the protocol-specific steps. Firewall,
//! routing, DNS, kill switch, split tunnelling and the LAN proxy stay with the
//! engine and the platform adapter, so a driver cannot bypass them.
//!
//! Each driver is split again at the OS boundary (`WgOps`, `SshOps`): the
//! driver holds the protocol logic, the ops trait only runs processes and
//! kernel tools, so the logic is tested without root.

pub mod ssh;
pub mod wireguard;

use crate::cancel::CancelToken;
use crate::egress::Egress;
use crate::events::Events;
use alizy_core::firewall::{NetworkPolicy, TunnelRules};
use alizy_core::ipc::{ErrorCode, IpcError, TunnelStats};
use alizy_core::protocol::{ProtocolKind, TunnelConfig};
use alizy_core::ssh::HostKey;
use alizy_core::sysprobe::SystemReport;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

/// Object-safe async return type for [`TunnelDriver`] methods.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why a bring-up failed, with the IPC error code to report.
#[derive(Debug)]
pub struct UpError {
    pub code: ErrorCode,
    pub msg: String,
    pub host_key: Option<HostKey>,
}

impl UpError {
    pub fn new(code: ErrorCode, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
            host_key: None,
        }
    }

    pub fn into_ipc(self) -> IpcError {
        let mut e = IpcError::new(self.code, self.msg);
        e.host_key = self.host_key;
        e
    }
}

impl From<String> for UpError {
    fn from(msg: String) -> Self {
        Self::new(ErrorCode::Tunnel, msg)
    }
}

/// Runtime facts a driver decides for one bring-up attempt, before the
/// firewall is planned (the firewall must already allow them).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    /// Loopback port of the driver's local proxy (SSH: `ssh -D`).
    pub local_port: Option<u16>,
}

/// Everything a driver may read during one bring-up step.
#[derive(Clone, Copy)]
pub struct Ctx<'a> {
    pub iface: &'a str,
    pub tunnel: &'a TunnelConfig,
    /// Resolved addresses, one slot per [`TunnelConfig::endpoints`] entry.
    pub endpoints: &'a [Option<SocketAddr>],
    pub session: &'a Session,
    pub policy: &'a NetworkPolicy,
    pub events: &'a Events,
    /// Fired (without the engine lock) when the user disconnects or connects elsewhere.
    pub cancel: &'a CancelToken,
}

/// One protocol implementation. Registered once at daemon start; the engine
/// never names a concrete driver.
pub trait TunnelDriver: Send + Sync {
    fn kind(&self) -> ProtocolKind;

    /// Missing system requirements; checked when the user asks to connect.
    fn preflight(&self) -> BoxFut<'_, Result<(), UpError>> {
        Box::pin(async { Ok(()) })
    }

    /// Decide this attempt's runtime facts. Runs before the firewall is applied.
    fn prepare(&self) -> Result<Session, UpError> {
        Ok(Session::default())
    }

    /// Firewall exceptions the tunnel's own traffic needs. Pure; re-evaluated
    /// whenever the plan is rebuilt (e.g. after an endpoint address changes).
    fn firewall_rules(&self, iface: &str, endpoints: &[SocketAddr], session: &Session) -> TunnelRules;

    /// Checks that need the new firewall but must not disturb the running
    /// tunnel (SSH: an unknown host key stops here for user confirmation).
    fn verify<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFut<'a, Result<(), UpError>> {
        Box::pin(async { Ok(()) })
    }

    /// Create the interface and data plane. The previous tunnel is already
    /// gone; routes and system DNS are applied by the engine afterwards.
    fn start<'a>(&'a self, ctx: Ctx<'a>) -> BoxFut<'a, Result<(), UpError>>;

    /// Stop anything this driver runs. Idempotent; called before the
    /// platform removes the interface, also when the driver is not active.
    fn stop(&self) -> BoxFut<'_, ()> {
        Box::pin(async {})
    }

    /// `Some(reason)` once the running data plane has died on its own.
    fn exited(&self) -> BoxFut<'_, Option<String>> {
        Box::pin(async { None })
    }

    fn stats<'a>(&'a self, iface: &'a str) -> BoxFut<'a, Result<Option<TunnelStats>, String>>;

    /// Point the running tunnel at new endpoint addresses (after a network
    /// change); the firewall already allows them. Returns the failures.
    fn update_endpoints<'a>(
        &'a self,
        _iface: &'a str,
        _tunnel: &'a TunnelConfig,
        _endpoints: &'a [Option<SocketAddr>],
    ) -> BoxFut<'a, Vec<String>> {
        Box::pin(async { Vec::new() })
    }

    /// How proxy mode's local proxy reaches the internet through this
    /// driver's tunnel. `dns` are the tunnel's resolvers. The default refuses
    /// (a driver without proxy-mode support never leaks).
    fn proxy_egress(&self, _session: &Session, _dns: &[std::net::IpAddr]) -> Egress {
        Egress::Blocked
    }

    /// Add the driver's own readiness checks to the system report.
    fn augment_report<'a>(&'a self, _report: &'a mut SystemReport) -> BoxFut<'a, ()> {
        Box::pin(async {})
    }
}

/// The driver was handed another protocol's configuration (engine bug).
pub(crate) fn mismatch(want: ProtocolKind, got: &TunnelConfig) -> UpError {
    UpError::new(
        ErrorCode::Internal,
        format!("{want:?} driver received a {:?} configuration", got.kind()),
    )
}
