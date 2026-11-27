//! Connection manager + kill switch + split-tunnel orchestration.
//!
//! All state changes go through `alizy_core::state::transition`. Every
//! firewall change is one atomic nft transaction followed by a read-back
//! verification. The engine never removes blocking rules to perform an update.

use crate::cancel::{CancelSource, CancelToken};
use crate::driver::{Ctx, Session, TunnelDriver, UpError};
use crate::egress::{Egress, EgressHandle};
use crate::events::Events;
use crate::lan_proxy::LanProxy;
use crate::lan_socks::{LanSocks, ServeOpts};
use crate::linux::{firewall, LinuxAdapter};
use crate::persist::{Persist, PersistedState};
use crate::resolver::{now, Resolver};
use alizy_core::config::{Host, PublicConfig};
use alizy_core::firewall::{ConnectionMode, FirewallPlan, NetworkPolicy, SPLIT_MARK};
use alizy_core::ipc::{
    DaemonStatus, ErrorCode, EventCategory as Cat, EventLevel as Lvl, IpcError, KillSwitchStatus, LanProxyConfig,
    LanProxyStatus, LocalProxyStatus, ProxyAuth, RouteTest, RouteTestEntry, SplitStatus, TunnelSpec, TunnelStats,
};
use alizy_core::platform::PlatformAdapter;
use alizy_core::protocol::ProtocolKind;
use alizy_core::routing::{compatibility_warnings, route_plan, DnsPlan};
use alizy_core::split::{self, Action, SplitConfig, MAX_RULES};
use alizy_core::state::{transition, ConnectionState, Event};
use alizy_core::sysprobe::DnsBackend;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{watch, Mutex};

/// Everything the engine needs from the OS beyond [`PlatformAdapter`]. The
/// engine is generic over it (production: [`LinuxAdapter`]) so the connection
/// state machine can be exercised without root. Protocol-specific operations
/// live in [`TunnelDriver`]s, not here.
#[allow(async_fn_in_trait)]
pub trait Backend: PlatformAdapter {
    fn dns_backend(&self) -> Option<DnsBackend>;
    async fn refresh_dns_backend(&self);
    fn reassert_dns(&self, plan: &DnsPlan) -> Result<bool, String>;
    fn restore_dns_backup(&self) -> Result<(), String>;
    /// Whether the tunnel interface exists in the daemon's network namespace.
    fn iface_exists(&self, iface: &str) -> bool;
    /// Install (`want`) or remove the split-tunnel routing rule; returns the errors.
    async fn set_split_rule(&self, want: bool) -> Vec<String>;
}

/// The tunnel that is up (or being brought up).
struct Active {
    kind: ProtocolKind,
    public: PublicConfig,
    /// System DNS for the tunnel; `None` in proxy mode (system DNS untouched).
    dns: Option<DnsPlan>,
    /// Resolved addresses, one slot per `TunnelConfig::endpoints` entry.
    endpoints: Vec<Option<SocketAddr>>,
    session: Session,
    since: u64,
    stats: Option<TunnelStats>,
    /// How the local proxy reaches the internet through this tunnel (proxy mode).
    proxy_egress: Egress,
    /// The tunnel carries UDP.
    udp: bool,
}

struct Inner {
    state: ConnectionState,
    persisted: PersistedState,
    active: Option<Active>,
    /// Last requested tunnel (kept for reconnects; contains secrets, zeroized on drop).
    spec: Option<TunnelSpec>,
    last_error: Option<String>,
    plan: Option<FirewallPlan>,
    verified: bool,
    split_rule_installed: bool,
    reconnect_attempt: u32,
    next_reconnect: u64,
    /// Published LAN proxy state (config, addresses, start errors).
    lan: LanProxyStatus,
    /// Published state of proxy mode's local proxy.
    local: LocalProxyStatus,
}

pub struct Engine<A = LinuxAdapter> {
    started_at: u64,
    /// Rate limiting / single-flight for read-only commands that do work.
    verify_cache: Mutex<Option<(std::time::Instant, bool, Option<String>)>>,
    report_cache: Mutex<Option<(std::time::Instant, alizy_core::sysprobe::SystemReport)>>,
    route_tests: tokio::sync::Semaphore,
    adapter: A,
    /// Registered protocol drivers; the engine never names a concrete one.
    drivers: Vec<Box<dyn TunnelDriver>>,
    /// Cancels an in-progress bring-up. Deliberately outside `inner`:
    /// `disconnect`/`connect` bump it *before* waiting for the lock.
    cancel: CancelSource,
    inner: Mutex<Inner>,
    /// The HTTP LAN proxy listener; `None` while disabled or failed.
    /// Never held while locking `inner` (order is always inner → lan).
    lan: Mutex<Option<LanProxy>>,
    /// The SOCKS5 LAN proxy listener.
    lan_socks: Mutex<Option<LanSocks>>,
    /// Proxy mode's listeners on 127.0.0.1 (same lock order rule as `lan`).
    local_http: Mutex<Option<LanProxy>>,
    local_socks: Mutex<Option<LanSocks>>,
    /// Where every proxy's connections go; follows mode and tunnel state.
    egress: EgressHandle,
    pub events: Events,
    persist: Persist,
    resolver: Resolver,
    iface: String,
    status_tx: watch::Sender<DaemonStatus>,
}

fn err(code: ErrorCode, m: impl Into<String>) -> IpcError {
    IpcError::new(code, m)
}

impl<A: Backend> Engine<A> {
    pub async fn start(
        adapter: A,
        drivers: Vec<Box<dyn TunnelDriver>>,
        persist: Persist,
        resolver: Resolver,
        iface: String,
    ) -> Arc<Self> {
        let persisted = persist.load();
        let ks = persisted.policy.kill_switch_active();
        let initial = DaemonStatus {
            state: ConnectionState::Disconnected,
            profile_id: None,
            profile_name: None,
            interface: None,
            connected_since: None,
            stats: None,
            kill_switch: KillSwitchStatus {
                enabled: ks,
                firewall_verified: false,
                firewall_tag: None,
            },
            policy: persisted.policy.clone(),
            last_error: None,
            tunnel_config: None,
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            dns_backend: adapter
                .dns_backend()
                .unwrap_or(alizy_core::sysprobe::DnsBackend::ResolvConfFile),
            daemon_started: now(),
            tunnel_kind: None,
            lan_proxy: LanProxyStatus::default(),
            local_proxy: LocalProxyStatus::default(),
        };
        let (status_tx, _) = watch::channel(initial);
        let engine = Arc::new(Self {
            started_at: now(),
            verify_cache: Mutex::new(None),
            report_cache: Mutex::new(None),
            route_tests: tokio::sync::Semaphore::new(2),
            adapter,
            drivers,
            cancel: CancelSource::default(),
            inner: Mutex::new(Inner {
                state: ConnectionState::Disconnected,
                persisted,
                active: None,
                spec: None,
                last_error: None,
                plan: None,
                verified: false,
                split_rule_installed: true, // force cleanup of leftovers on first sync
                reconnect_attempt: 0,
                next_reconnect: 0,
                lan: LanProxyStatus::default(),
                local: LocalProxyStatus::default(),
            }),
            events: Events::default(),
            lan: Mutex::new(None),
            lan_socks: Mutex::new(None),
            local_http: Mutex::new(None),
            local_socks: Mutex::new(None),
            egress: EgressHandle::default(),
            persist,
            resolver,
            iface,
            status_tx,
        });
        engine.recover().await;
        // The firewall already carries the persisted proxy port (recover
        // enforced it); now open the listener it belongs to.
        {
            let mut inner = engine.inner.lock().await;
            engine.publish(&inner);
            engine.apply_lan(&mut inner).await;
            engine.apply_local(&mut inner).await;
            engine.publish(&inner);
        }
        engine
    }

    /// Boot / crash recovery: remove leftovers, restore DNS, re-establish protection.
    async fn recover(&self) {
        let mut inner = self.inner.lock().await;
        if self.adapter.iface_exists(&self.iface) {
            self.events.push(
                Lvl::Warn,
                Cat::Service,
                format!(
                    "Found leftover interface {} from a previous run; removing it.",
                    self.iface
                ),
            );
        }
        if let Err(e) = self.teardown().await {
            self.events.push(
                Lvl::Error,
                Cat::Service,
                format!("Cleanup of previous tunnel failed: {e}"),
            );
        }
        if let Err(e) = self.adapter.restore_dns_backup() {
            self.events
                .push(Lvl::Error, Cat::Dns, format!("Could not restore DNS backup: {e}"));
        }
        let ks = inner.persisted.policy.kill_switch_active();
        match self.enforce(&mut inner).await {
            Ok(()) if ks => self.events.push(
                Lvl::Info,
                Cat::Firewall,
                "Kill switch restored at startup; non-VPN traffic is blocked.",
            ),
            Ok(()) => self.events.push(Lvl::Info, Cat::Service, "Daemon started."),
            Err(e) => self.events.push(
                Lvl::Error,
                Cat::Firewall,
                format!("Could not establish firewall policy at startup: {e}. Retrying."),
            ),
        }
        inner.state = if ks {
            ConnectionState::Protected
        } else {
            ConnectionState::Disconnected
        };
        self.publish(&inner);
    }

    pub fn status(&self) -> DaemonStatus {
        self.status_tx.borrow().clone()
    }

    /// Where proxies connect now. Proxy mode never falls back to a direct
    /// connection: anything but a connected tunnel blocks.
    fn current_egress(inner: &Inner) -> Egress {
        match inner.persisted.policy.mode {
            ConnectionMode::Tunnel => Egress::System {
                udp: inner.active.as_ref().is_none_or(|a| a.udp),
            },
            ConnectionMode::Proxy => match (&inner.active, inner.state) {
                (Some(a), ConnectionState::Connected) => a.proxy_egress.clone(),
                _ => Egress::Blocked,
            },
        }
    }

    fn publish(&self, inner: &Inner) {
        let egress = Self::current_egress(inner);
        let local_udp = egress.udp();
        self.egress.set(egress);
        let a = inner.active.as_ref();
        let spec = inner.spec.as_ref().filter(|_| a.is_some());
        let s = DaemonStatus {
            state: inner.state,
            profile_id: spec.map(|s| s.profile_id.clone()),
            profile_name: spec.map(|s| s.profile_name.clone()),
            interface: a.map(|_| self.iface.clone()),
            connected_since: a.map(|a| a.since).filter(|_| inner.state == ConnectionState::Connected),
            stats: a.and_then(|a| a.stats.clone()),
            kill_switch: KillSwitchStatus {
                enabled: inner.persisted.policy.kill_switch_active(),
                firewall_verified: inner.verified
                    && inner
                        .plan
                        .as_ref()
                        .map(|p| p.kill_switch == inner.persisted.policy.kill_switch_active())
                        .unwrap_or(false),
                firewall_tag: inner.plan.as_ref().filter(|p| p.needs_table()).map(|p| p.tag()),
            },
            policy: inner.persisted.policy.clone(),
            last_error: inner.last_error.clone(),
            tunnel_config: a.map(|a| a.public.clone()),
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            dns_backend: self
                .adapter
                .dns_backend()
                .unwrap_or(alizy_core::sysprobe::DnsBackend::ResolvConfFile),
            daemon_started: self.started_at,
            tunnel_kind: a.and_then(|a| a.kind.status_name()).map(String::from),
            lan_proxy: inner.lan.clone(),
            local_proxy: LocalProxyStatus {
                udp: inner.local.udp && local_udp,
                ..inner.local.clone()
            },
        };
        self.status_tx.send_replace(s);
    }

    fn go(&self, inner: &mut Inner, ev: Event) -> Result<(), IpcError> {
        match transition(inner.state, ev) {
            Ok(to) => {
                if to != inner.state {
                    tracing::debug!(from = ?inner.state, ?to, "state transition");
                }
                inner.state = to;
                Ok(())
            }
            Err(e) => Err(err(ErrorCode::Busy, format!("operation not possible now ({e})"))),
        }
    }

    fn save(&self, inner: &Inner) {
        if let Err(e) = self.persist.save(&inner.persisted) {
            self.events
                .push(Lvl::Error, Cat::Service, format!("Could not persist state: {e}"));
        }
    }

    fn desired_plan(&self, inner: &Inner) -> FirewallPlan {
        let policy = &inner.persisted.policy.effective();
        let tunnel = inner.active.as_ref().and_then(|a| {
            let eps: Vec<SocketAddr> = a.endpoints.iter().flatten().copied().collect();
            let d = self.driver(a.kind).ok()?;
            Some(d.firewall_rules(&self.iface, &eps, &a.session))
        });
        // Split tunnelling decides what bypasses a full tunnel; proxy mode has none.
        let direct = if inner.persisted.split.enabled && inner.persisted.policy.mode == ConnectionMode::Tunnel {
            let resolved = inner
                .persisted
                .dns_cache
                .resolved_addrs(&inner.persisted.split.rules, now());
            split::compile(&inner.persisted.split.rules, &resolved)
        } else {
            Default::default()
        };
        let lan_cfg = &inner.persisted.lan_proxy;
        let lan_proxy = lan_cfg.enabled.then_some(lan_cfg.port);
        let lan_socks = lan_cfg.enabled.then_some(lan_cfg.socks_port);
        let guard = (inner.persisted.policy.mode == ConnectionMode::Proxy).then_some(self.iface.as_str());
        FirewallPlan::with_split(policy, tunnel, direct)
            .with_lan_proxy(lan_proxy)
            .with_lan_socks(lan_socks)
            .with_proxy_guard(guard)
    }

    /// Apply the desired firewall atomically and verify it in the kernel.
    async fn enforce(&self, inner: &mut Inner) -> Result<(), String> {
        let plan = self.desired_plan(inner);
        let applied = self.adapter.apply_firewall(&plan).await;
        let verified = match &applied {
            Ok(()) => self.adapter.verify_firewall(&plan).await.unwrap_or(false),
            Err(_) => false,
        };
        let changed = inner.plan.as_ref().map(|p| p.tag()) != Some(plan.tag());
        inner.verified = verified;
        inner.plan = Some(plan);
        self.sync_split_rule(inner).await;
        if changed && verified {
            let p = inner.plan.as_ref().unwrap();
            self.events.push(
                Lvl::Info,
                Cat::Firewall,
                format!(
                    "Firewall policy applied and verified ({}; kill switch {}, IPv4 {}, IPv6 {}, {} bypass ranges).",
                    p.tag(),
                    on(p.kill_switch),
                    on(p.ipv4_enabled),
                    on(p.ipv6_enabled),
                    p.direct.v4.len() + p.direct.v6.len()
                ),
            );
        }
        applied?;
        if verified {
            Ok(())
        } else {
            Err("the firewall could not be verified after applying it".into())
        }
    }

    async fn sync_split_rule(&self, inner: &mut Inner) {
        let want = inner.plan.as_ref().map(|p| p.split_active()).unwrap_or(false);
        if want == inner.split_rule_installed {
            return;
        }
        for e in self.adapter.set_split_rule(want).await {
            // Without the rule, marked traffic stays in the tunnel: safe direction.
            self.events.push(
                Lvl::Warn,
                Cat::Network,
                format!("Split-tunnel routing rule failed ({e}); bypass traffic will use the VPN."),
            );
        }
        inner.split_rule_installed = want;
    }

    /// Resolve all peer endpoints concurrently. Each hostname gets its own
    /// short deadline and falls back to the last address that worked (daemon
    /// cache, then the client's cache), because DNS is legitimately blocked
    /// while protected. Successful lookups refresh the daemon cache.
    async fn resolve_endpoints(&self, inner: &mut Inner, spec: &TunnelSpec) -> Result<Vec<Option<SocketAddr>>, String> {
        let cache = inner.persisted.endpoint_cache.clone();
        let lookups = spec.tunnel.endpoints().into_iter().enumerate().map(|(i, ep)| {
            let client_cached = spec.cached_endpoints.get(i).copied().flatten();
            let cache = &cache;
            async move {
                let Some(ep) = ep else { return Ok((None, None)) };
                match &ep.host {
                    Host::Ip(ip) => Ok((Some(SocketAddr::new(*ip, ep.port)), None)),
                    Host::Name(n) => {
                        let key = format!("{n}:{}", ep.port);
                        let looked = tokio::time::timeout(
                            std::time::Duration::from_secs(4),
                            tokio::net::lookup_host((n.as_str(), ep.port)),
                        )
                        .await;
                        match looked {
                            Ok(Ok(mut it)) => match it.next() {
                                Some(a) => Ok((Some(a), Some((key, a)))),
                                None => Err(format!("{n} has no address")),
                            },
                            _ => cache
                                .get(&key)
                                .copied()
                                .or(client_cached)
                                .map(|a| (Some(a), None))
                                .ok_or_else(|| {
                                    format!("could not resolve endpoint {n} and no previously used address is known")
                                }),
                        }
                    }
                }
            }
        });
        let results = match tokio::time::timeout(std::time::Duration::from_secs(10), futures_join_all(lookups)).await {
            Ok(r) => r,
            Err(_) => return Err("resolving the endpoint(s) timed out".into()),
        };
        let mut out = Vec::with_capacity(results.len());
        let mut learned = false;
        for r in results {
            let (addr, fresh) = r?;
            if let Some((k, a)) = fresh {
                if inner.persisted.endpoint_cache.get(&k) != Some(&a) {
                    inner.persisted.endpoint_cache.insert(k, a);
                    learned = true;
                }
            }
            out.push(addr);
        }
        // Bound the cache (oldest entries are not tracked; keep it small).
        while inner.persisted.endpoint_cache.len() > 256 {
            let k = inner.persisted.endpoint_cache.keys().next().cloned().unwrap();
            inner.persisted.endpoint_cache.remove(&k);
        }
        if learned {
            self.save(inner);
        }
        Ok(out)
    }

    fn driver(&self, kind: ProtocolKind) -> Result<&dyn TunnelDriver, UpError> {
        self.drivers
            .iter()
            .find(|d| d.kind() == kind)
            .map(|d| d.as_ref())
            .ok_or_else(|| UpError::new(ErrorCode::Unsupported, format!("{kind:?} tunnels are not available")))
    }

    /// Stop every driver's processes, then remove the interface, its routes
    /// and DNS. Safe to call with nothing running.
    async fn teardown(&self) -> Result<(), String> {
        for d in &self.drivers {
            d.stop().await;
        }
        self.adapter.tunnel_down(&self.iface).await
    }

    /// Bring a tunnel up. Firewall first, interface second. On failure the
    /// tunnel is removed and the no-tunnel policy re-applied; state is left to the caller.
    ///
    /// A bring-up that fails after `cancel` fired reports
    /// [`ErrorCode::Cancelled`]: the user disconnected or connected elsewhere,
    /// so it is neither an error nor a reason to reconnect.
    async fn bring_up(&self, inner: &mut Inner, spec: &TunnelSpec, cancel: &CancelToken) -> Result<(), UpError> {
        let result = match self.bring_up_inner(inner, spec, cancel).await {
            Err(_) if cancel.is_cancelled() => Err(UpError::new(
                ErrorCode::Cancelled,
                "the connection attempt was cancelled",
            )),
            r => r,
        };
        if let Err(e) = &result {
            if let Err(td) = self.teardown().await {
                self.events
                    .push(Lvl::Error, Cat::Connection, format!("Cleanup after failure: {td}"));
            }
            inner.active = None;
            if let Err(fe) = self.enforce(inner).await {
                self.events.push(
                    Lvl::Error,
                    Cat::Firewall,
                    format!("Re-applying protection after failure: {fe}"),
                );
            }
            if e.code == ErrorCode::Cancelled {
                self.events.push(
                    Lvl::Info,
                    Cat::Connection,
                    format!("Connection attempt to {} cancelled.", spec.profile_name),
                );
            } else if e.code == ErrorCode::HostKeyUnknown {
                // Not a failure: the user has to confirm the server's key first.
                self.events.push(
                    Lvl::Info,
                    Cat::Connection,
                    format!("Connection to {} needs confirmation: {}", spec.profile_name, e.msg),
                );
            } else {
                inner.last_error = Some(e.msg.clone());
                self.events.push(
                    Lvl::Error,
                    Cat::Connection,
                    format!("Connection to {} failed: {}", spec.profile_name, e.msg),
                );
            }
        }
        result
    }

    /// The one lifecycle every protocol goes through. The driver supplies the
    /// protocol steps; firewall, routes and DNS stay here.
    ///
    /// Lock hold: this runs under the engine lock. A driver's slow steps
    /// (SSH: keyscan at most 10 s, readiness at most 20 s) poll `cancel`, which
    /// `disconnect`/`connect` fire *before* waiting for the lock, so they get
    /// it within about a second. Status reads use the watch channel and never
    /// wait. The firewall is applied and verified before any slow step and
    /// stays in place throughout.
    async fn bring_up_inner(&self, inner: &mut Inner, spec: &TunnelSpec, cancel: &CancelToken) -> Result<(), UpError> {
        if cancel.is_cancelled() {
            // Superseded while waiting for the lock: start nothing.
            return Err(UpError::new(
                ErrorCode::Cancelled,
                "the connection attempt was cancelled",
            ));
        }
        let kind = spec.tunnel.kind();
        let driver = self.driver(kind)?;
        let policy = inner.persisted.policy.effective();
        let proxy_mode = policy.mode == ConnectionMode::Proxy;
        let plan = spec.tunnel.plan(&policy);
        let mut prev = inner.active.as_ref().map(|a| a.kind);
        if prev.is_some_and(|p| p != kind) {
            // Switching protocols: stop the old data plane and remove its
            // interface first. The old firewall stays in place meanwhile.
            self.teardown().await?;
            prev = None;
        }
        for w in compatibility_warnings(&plan.public, &policy) {
            self.events.push(Lvl::Warn, Cat::Connection, w);
        }
        let endpoints = self.resolve_endpoints(inner, spec).await?;
        let session = driver.prepare()?;
        let eps: Vec<SocketAddr> = endpoints.iter().flatten().copied().collect();
        let udp = !driver.firewall_rules(&self.iface, &eps, &session).block_udp;
        inner.active = Some(Active {
            kind,
            public: plan.public.clone(),
            dns: (!proxy_mode).then(|| plan.dns.clone()),
            endpoints: endpoints.clone(),
            proxy_egress: driver.proxy_egress(&session, &plan.dns.servers),
            udp,
            session: session.clone(),
            since: now(),
            stats: None,
        });
        // 1. Firewall for the new tunnel (old drop rules stay until the new table replaces them atomically).
        self.enforce(inner).await.map_err(|e| format!("firewall: {e}"))?;
        let ctx = Ctx {
            iface: &self.iface,
            tunnel: &spec.tunnel,
            endpoints: &endpoints,
            session: &session,
            policy: &policy,
            events: &self.events,
            cancel,
        };
        // 2. Checks that must not disturb the running tunnel.
        driver.verify(ctx).await?;
        // 3. Remove the previous tunnel of the same protocol (or any leftover).
        if prev.is_some() || self.adapter.iface_exists(&self.iface) {
            self.teardown().await?;
        }
        // 4. Interface and data plane, then routes and system DNS.
        driver.start(ctx).await?;
        let routes = route_plan(&plan.public, &self.iface, &policy);
        let dns = (!proxy_mode).then_some(&plan.dns);
        self.adapter.network_up(&self.iface, &routes, dns).await?;
        // Teardown removed the interface's routing rules, including the split
        // rule enforce() just installed: reset the flag so sync re-adds it.
        inner.split_rule_installed = false;
        self.sync_split_rule(inner).await;
        inner.last_error = None;
        inner.reconnect_attempt = 0;
        self.events.push(
            Lvl::Info,
            Cat::Connection,
            format!(
                "Connected to {} via {}{}.",
                spec.profile_name,
                endpoints
                    .iter()
                    .flatten()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                kind.connected_suffix()
            ),
        );
        Ok(())
    }

    pub async fn connect(&self, mut spec: TunnelSpec) -> Result<(), IpcError> {
        // The GUI is not trusted to have validated anything: re-check from scratch.
        spec.tunnel = spec.tunnel.sanitize().map_err(|e| err(ErrorCode::InvalidConfig, e))?;
        for s in [&spec.profile_id, &spec.profile_name] {
            if s.is_empty() || s.len() > 128 || s.chars().any(char::is_control) {
                return Err(err(ErrorCode::BadRequest, "invalid profile identifier"));
            }
        }
        let driver = self.driver(spec.tunnel.kind()).map_err(UpError::into_ipc)?;
        driver.preflight().await.map_err(UpError::into_ipc)?;
        // Abandon any bring-up in progress (it holds the lock) before waiting
        // for the lock; this attempt's own token is taken right after, so a
        // later disconnect or connect cancels it in turn.
        let preempt = self.cancel.preempt();
        let cancel = self.cancel.token();
        let mut inner = self.inner.lock().await;
        drop(preempt);
        let switching = inner.active.is_some();
        self.go(&mut inner, Event::ConnectRequested)?;
        if switching {
            self.events.push(
                Lvl::Info,
                Cat::Connection,
                format!(
                    "Switching to {} (protection stays active during the switch).",
                    spec.profile_name
                ),
            );
        }
        self.publish(&inner);
        let result = self.bring_up(&mut inner, &spec, &cancel).await;
        inner.spec = Some(spec);
        let r = match result {
            Ok(()) => self.go(&mut inner, Event::TunnelUp),
            Err(e) if matches!(e.code, ErrorCode::HostKeyUnknown | ErrorCode::Cancelled) => {
                // Waiting for the user, or superseded by the user, not an
                // error: end like a disconnect (no `error` state, no reconnect
                // attempt).
                let ks = inner.persisted.policy.kill_switch_active();
                inner.spec = None;
                let _ = self.go(&mut inner, Event::DisconnectRequested);
                let _ = self.go(&mut inner, Event::TornDown { kill_switch: ks });
                Err(e.into_ipc())
            }
            Err(e) => {
                let ks = inner.persisted.policy.kill_switch_active();
                inner.spec = None;
                let _ = self.go(&mut inner, Event::Failed { kill_switch: ks });
                Err(e.into_ipc())
            }
        };
        self.publish(&inner);
        r
    }

    pub async fn disconnect(&self) -> Result<(), IpcError> {
        // Make an in-progress SSH bring-up give up the lock promptly.
        let preempt = self.cancel.preempt();
        let mut inner = self.inner.lock().await;
        drop(preempt);
        if matches!(inner.state, ConnectionState::Disconnected) {
            return Ok(());
        }
        self.go(&mut inner, Event::DisconnectRequested)?;
        self.publish(&inner);
        let down = self.teardown().await;
        inner.active = None;
        inner.spec = None;
        inner.last_error = None;
        let fw = self.enforce(&mut inner).await;
        let ks = inner.persisted.policy.kill_switch_active();
        self.go(&mut inner, Event::TornDown { kill_switch: ks })?;
        self.events.push(
            Lvl::Info,
            Cat::Connection,
            if ks {
                "Disconnected. Kill switch keeps non-VPN traffic blocked."
            } else {
                "Disconnected."
            },
        );
        if let Err(e) = &down {
            inner.last_error = Some(e.clone());
            self.events
                .push(Lvl::Error, Cat::Connection, format!("Teardown problem: {e}"));
        }
        if let Err(e) = &fw {
            inner.last_error = Some(e.clone());
        }
        self.publish(&inner);
        down.and(fw).map_err(|e| err(ErrorCode::Tunnel, e))
    }

    pub async fn policy(&self) -> NetworkPolicy {
        self.inner.lock().await.persisted.policy.clone()
    }

    pub async fn set_policy(&self, policy: NetworkPolicy) -> Result<(), IpcError> {
        policy.validate().map_err(|e| err(ErrorCode::BadRequest, e))?;
        let mut inner = self.inner.lock().await;
        let old = inner.persisted.policy.clone();
        inner.persisted.policy = policy.clone();
        self.save(&inner);
        let mode_changed = old.mode != policy.mode;
        if mode_changed {
            self.events.push(
                Lvl::Info,
                Cat::Network,
                match policy.mode {
                    ConnectionMode::Tunnel => "Switched to tunnel mode: all traffic goes through the VPN.",
                    ConnectionMode::Proxy => {
                        "Switched to proxy mode: only apps using Alizy's local proxy go through the VPN."
                    }
                },
            );
        }
        // A mode switch rebuilds the tunnel: teardown removes the previous
        // mode's routes, rules and DNS before the new mode's are installed.
        let needs_rebuild = inner.active.is_some()
            && (mode_changed
                || old.ipv4_enabled != policy.ipv4_enabled
                || old.ipv6_enabled != policy.ipv6_enabled
                || old.custom_dns != policy.custom_dns);
        let r = if needs_rebuild {
            // Rebuild the tunnel for the new routing/DNS; the firewall is replaced atomically first.
            let spec = inner.spec.clone().expect("active tunnel has a spec");
            let cancel = self.cancel.token();
            match self.bring_up(&mut inner, &spec, &cancel).await {
                Ok(()) => {
                    if inner.state != ConnectionState::Connected {
                        let _ = self.go(&mut inner, Event::TunnelUp);
                    }
                    Ok(())
                }
                Err(e) if e.code == ErrorCode::Cancelled => {
                    // A disconnect/connect is waiting: end like a disconnect.
                    inner.spec = None;
                    let _ = self.go(&mut inner, Event::DisconnectRequested);
                    let _ = self.go(
                        &mut inner,
                        Event::TornDown {
                            kill_switch: policy.kill_switch_active(),
                        },
                    );
                    Ok(())
                }
                Err(e) => {
                    let _ = self.go(
                        &mut inner,
                        Event::Failed {
                            kill_switch: policy.kill_switch_active(),
                        },
                    );
                    Err(e.msg)
                }
            }
        } else {
            self.enforce(&mut inner).await
        };
        if old.kill_switch_active() != policy.kill_switch_active() {
            let _ = self.go(
                &mut inner,
                Event::KillSwitchChanged {
                    enabled: policy.kill_switch_active(),
                },
            );
            self.events.push(
                Lvl::Info,
                Cat::Firewall,
                if policy.kill_switch_active() {
                    "Kill switch enabled."
                } else {
                    "Kill switch disabled by user."
                },
            );
        }
        if let Err(e) = &r {
            inner.last_error = Some(e.clone());
        }
        self.publish(&inner);
        if mode_changed
            || old.proxy_socks_port != policy.proxy_socks_port
            || old.proxy_http_port != policy.proxy_http_port
        {
            self.apply_local(&mut inner).await;
            self.publish(&inner);
        }
        r.map_err(|e| err(ErrorCode::Firewall, e))
    }

    /// Published LAN proxy state.
    pub async fn lan_proxy_status(&self) -> LanProxyStatus {
        self.inner.lock().await.lan.clone()
    }

    /// Apply a LAN proxy configuration: persist it, re-render the firewall
    /// (its reply exception is part of the plan) and (re)start the listener.
    /// Lock order is inner → lan, never the other way round.
    pub async fn set_lan_proxy(&self, mut cfg: LanProxyConfig) -> Result<LanProxyStatus, IpcError> {
        cfg.validate().map_err(|e| err(ErrorCode::BadRequest, e))?;
        let mut inner = self.inner.lock().await;
        if let Some(a) = cfg.auth.as_mut() {
            // Never trust a verifier from the client: only a password sets one.
            a.verifier = None;
            match a.password.take() {
                Some(pw) => a.verifier = Some(ProxyAuth::make_verifier(&pw, &salt())),
                None => {
                    a.verifier = inner
                        .persisted
                        .lan_proxy
                        .auth
                        .as_ref()
                        .filter(|old| old.username == a.username)
                        .and_then(|old| old.verifier.clone());
                    if a.verifier.is_none() {
                        return Err(err(
                            ErrorCode::BadRequest,
                            "a password is required for the new username",
                        ));
                    }
                }
            }
        }
        inner.persisted.lan_proxy = cfg;
        self.save(&inner);
        let r = self.enforce(&mut inner).await;
        self.apply_lan(&mut inner).await;
        self.publish(&inner);
        let status = inner.lan.clone();
        drop(inner);
        r.map_err(|e| err(ErrorCode::Firewall, e))?;
        Ok(status)
    }

    /// Start or stop the listener to match `inner.persisted.lan_proxy` and
    /// record the outcome in `inner.lan`. `inner` must be held. `enabled`
    /// is the setting; `listening` says whether the listener is actually up
    /// (a bind failure leaves it false with `error` set, while the setting
    /// stays persisted for retry).
    async fn apply_lan(&self, inner: &mut Inner) {
        let cfg = inner.persisted.lan_proxy.clone();
        let was_http = inner.lan.listening;
        let was_socks = inner.lan.socks_listening;
        let mut status = LanProxyStatus {
            enabled: cfg.enabled,
            port: cfg.port,
            socks_port: cfg.socks_port,
            addresses: Vec::new(),
            error: None,
            listening: false,
            socks_error: None,
            socks_listening: false,
            auth_username: cfg.auth.as_ref().map(|a| a.username.clone()),
            socks_udp: false,
        };
        let opts = ServeOpts {
            egress: self.egress.clone(),
            auth: cfg.auth.clone().filter(|a| a.verifier.is_some()).map(Arc::new),
        };
        let any = IpAddr::from([0, 0, 0, 0]);
        // Stop the previous listeners first (waiting for sockets to close)
        // so a port change frees the old port immediately.
        let prev = self.lan.lock().await.take();
        if let Some(p) = prev {
            p.stop().await;
        }
        let prev_socks = self.lan_socks.lock().await.take();
        if let Some(p) = prev_socks {
            p.stop().await;
        }
        if cfg.enabled {
            // HTTP proxy
            match LanProxy::start(any, cfg.port, opts.clone()).await {
                Ok(p) => {
                    status.listening = true;
                    *self.lan.lock().await = Some(p);
                }
                Err(e) => {
                    status.error = Some(e.to_string());
                    self.events
                        .push(Lvl::Error, Cat::Network, format!("LAN HTTP proxy could not start: {e}"));
                }
            }
            // SOCKS5 proxy
            match LanSocks::start(any, cfg.socks_port, opts).await {
                Ok(p) => {
                    status.socks_listening = true;
                    status.socks_udp = p.udp();
                    *self.lan_socks.lock().await = Some(p);
                }
                Err(e) => {
                    status.socks_error = Some(e.to_string());
                    self.events.push(
                        Lvl::Error,
                        Cat::Network,
                        format!("LAN SOCKS5 proxy could not start: {e}"),
                    );
                }
            }
            if status.listening || status.socks_listening {
                status.addresses = crate::lan_proxy::addresses(&self.iface).await;
                let addrs = status
                    .addresses
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut parts = Vec::new();
                if status.listening {
                    parts.push(format!("HTTP :{}", cfg.port));
                }
                if status.socks_listening {
                    parts.push(format!("SOCKS5 :{}", cfg.socks_port));
                }
                let where_ = if addrs.is_empty() {
                    parts.join(", ")
                } else {
                    format!("{addrs} ({})", parts.join(", "))
                };
                let who = match &status.auth_username {
                    Some(u) => format!("devices on this network can use it after logging in as \"{u}\""),
                    None => "anyone on this network can use it (no password)".to_string(),
                };
                self.events.push(
                    Lvl::Info,
                    Cat::Network,
                    format!("LAN proxy listening on {where_}; {who}."),
                );
            }
        } else if was_http || was_socks {
            self.events.push(Lvl::Info, Cat::Network, "LAN proxy stopped.");
        }
        inner.lan = status;
    }

    /// Start or stop proxy mode's local listeners on 127.0.0.1 to match the
    /// policy. They exist only in proxy mode; their egress follows the tunnel.
    async fn apply_local(&self, inner: &mut Inner) {
        let policy = &inner.persisted.policy;
        let active = policy.mode == ConnectionMode::Proxy;
        let (socks_port, http_port) = (policy.proxy_socks_port, policy.proxy_http_port);
        let was = inner.local.socks_listening || inner.local.http_listening;
        let mut status = LocalProxyStatus {
            active,
            socks_port,
            http_port,
            ..Default::default()
        };
        if let Some(p) = self.local_http.lock().await.take() {
            p.stop().await;
        }
        if let Some(p) = self.local_socks.lock().await.take() {
            p.stop().await;
        }
        if active {
            let lo = IpAddr::from([127, 0, 0, 1]);
            let opts = ServeOpts {
                egress: self.egress.clone(),
                auth: None,
            };
            let mut errors = Vec::new();
            match LanSocks::start(lo, socks_port, opts.clone()).await {
                Ok(p) => {
                    status.socks_listening = true;
                    status.udp = p.udp();
                    *self.local_socks.lock().await = Some(p);
                }
                Err(e) => errors.push(e.to_string()),
            }
            match LanProxy::start(lo, http_port, opts).await {
                Ok(p) => {
                    status.http_listening = true;
                    *self.local_http.lock().await = Some(p);
                }
                Err(e) => errors.push(e.to_string()),
            }
            if !errors.is_empty() {
                let e = errors.join("; ");
                self.events
                    .push(Lvl::Error, Cat::Network, format!("Local proxy could not start: {e}"));
                status.error = Some(e);
            }
            if status.socks_listening || status.http_listening {
                self.events.push(
                    Lvl::Info,
                    Cat::Network,
                    format!(
                        "Local proxy ready: SOCKS5 127.0.0.1:{socks_port}, HTTP 127.0.0.1:{http_port}. It only works while the VPN is connected."
                    ),
                );
            }
        } else if was {
            self.events.push(Lvl::Info, Cat::Network, "Local proxy stopped.");
        }
        inner.local = status;
    }

    pub async fn set_split(&self, mut cfg: SplitConfig) -> Result<(), IpcError> {
        if cfg.rules.len() > MAX_RULES {
            return Err(err(ErrorCode::BadRequest, format!("at most {MAX_RULES} rules")));
        }
        // Re-validate every target (never trust the client).
        let clean = |s: &str| s.chars().all(|c| !c.is_control());
        for r in &mut cfg.rules {
            if r.id.is_empty() || r.id.len() > 64 || !r.id.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(err(ErrorCode::BadRequest, "invalid rule id"));
            }
            if r.category.as_deref().is_some_and(|c| c.len() > 64 || !clean(c))
                || r.note.as_deref().is_some_and(|n| n.len() > 256 || !clean(n))
            {
                return Err(err(ErrorCode::BadRequest, "invalid rule category or note"));
            }
            match &mut r.target {
                split::Target::Domain { domain, mode } => {
                    // Store the normalised form; an explicit `*.`/`.` prefix decides the mode.
                    let (name, parsed) =
                        split::parse_domain_pattern(domain).map_err(|e| err(ErrorCode::BadRequest, e.to_string()))?;
                    if parsed != split::DomainMatch::Exact {
                        *mode = parsed;
                    }
                    *domain = name;
                }
                split::Target::Ip { net } => {
                    if net.trunc() != *net {
                        return Err(err(ErrorCode::BadRequest, format!("{net} is not a canonical network")));
                    }
                }
                split::Target::App { .. } => {
                    return Err(err(
                        ErrorCode::Unsupported,
                        "application-based split tunnelling is not implemented on Linux yet",
                    ));
                }
            }
        }
        let mut inner = self.inner.lock().await;
        inner.persisted.split = cfg;
        let rules = inner.persisted.split.rules.clone();
        inner.persisted.dns_cache.prune(&rules, now());
        self.save(&inner);
        let r = self.enforce(&mut inner).await;
        self.events.push(
            Lvl::Info,
            Cat::Network,
            format!(
                "Split tunnelling updated ({} rules, {}).",
                rules.len(),
                if inner.persisted.split.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        );
        self.publish(&inner);
        drop(inner);
        // Resolve new domains right away instead of waiting for the next tick.
        self.refresh_split_dns().await;
        r.map_err(|e| err(ErrorCode::Firewall, e))
    }

    pub async fn split_status(&self) -> SplitStatus {
        let inner = self.inner.lock().await;
        let rules = &inner.persisted.split.rules;
        let t = now();
        let resolved = inner.persisted.dns_cache.resolved_addrs(rules, t);
        SplitStatus {
            config: inner.persisted.split.clone(),
            domains: inner.persisted.dns_cache.status(rules, t),
            warnings: split::shared_ip_warnings(rules, &resolved),
            direct: inner.plan.as_ref().map(|p| p.direct.clone()).unwrap_or_default(),
            applied: inner.verified,
        }
    }

    /// At most one kernel read per second, however many clients ask.
    pub async fn verify_firewall(&self) -> (bool, Option<String>) {
        let mut cache = self.verify_cache.lock().await;
        if let Some((at, ok, tag)) = cache.as_ref() {
            if at.elapsed() < std::time::Duration::from_secs(1) {
                return (*ok, tag.clone());
            }
        }
        let r = self.verify_firewall_now().await;
        *cache = Some((std::time::Instant::now(), r.0, r.1.clone()));
        r
    }

    /// Cached for 10 s; concurrent callers share one probe.
    pub async fn system_report(&self) -> Result<alizy_core::sysprobe::SystemReport, IpcError> {
        let mut cache = self.report_cache.lock().await;
        if let Some((at, r)) = cache.as_ref() {
            if at.elapsed() < std::time::Duration::from_secs(10) {
                return Ok(r.clone());
            }
        }
        let mut r = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            tokio::task::spawn_blocking(alizy_core::sysprobe::probe),
        )
        .await
        .map_err(|_| err(ErrorCode::Internal, "system probe timed out"))?
        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        for d in &self.drivers {
            d.augment_report(&mut r).await;
        }
        *cache = Some((std::time::Instant::now(), r.clone()));
        Ok(r)
    }

    async fn verify_firewall_now(&self) -> (bool, Option<String>) {
        let mut inner = self.inner.lock().await;
        let Some(plan) = inner.plan.clone() else {
            return (false, None);
        };
        let ok = self.adapter.verify_firewall(&plan).await.unwrap_or(false);
        inner.verified = ok;
        self.publish(&inner);
        (ok, plan.needs_table().then(|| plan.tag()))
    }

    /// Resolve due split-tunnel domains (outside the lock) and re-apply if sets changed.
    /// Runs on its own loop, never inside `tick`, so slow or hostile DNS can
    /// never delay firewall re-verification.
    pub async fn refresh_split_dns(&self) {
        let (due, rules) = {
            let inner = self.inner.lock().await;
            if !inner.persisted.split.enabled {
                return;
            }
            let rules = inner.persisted.split.rules.clone();
            (inner.persisted.dns_cache.due(&rules, now()), rules)
        };
        if due.is_empty() {
            return;
        }
        let mut set = tokio::task::JoinSet::new();
        let sem = Arc::new(tokio::sync::Semaphore::new(8));
        for name in due {
            let r = self.resolver.clone();
            let sem = sem.clone();
            set.spawn(async move {
                let _p = sem.acquire().await;
                let res = r.resolve(&name).await;
                (name, res)
            });
        }
        let mut results = Vec::new();
        while let Some(Ok(x)) = set.join_next().await {
            results.push(x);
        }
        let mut inner = self.inner.lock().await;
        let t = now();
        for (name, res) in results {
            let first_failure = res.is_err()
                && inner
                    .persisted
                    .dns_cache
                    .entries
                    .get(&name)
                    .map(|e| e.failures == 0)
                    .unwrap_or(true);
            if let Err(e) = &res {
                if first_failure {
                    self.events.push(Lvl::Warn, Cat::Dns, format!("Resolving {name} for split tunnelling failed: {e}. Keeping previous addresses for up to {} minutes.", crate::resolver::GRACE / 60));
                }
            }
            inner.persisted.dns_cache.record(&name, res, t);
        }
        inner.persisted.dns_cache.prune(&rules, t);
        let desired = self.desired_plan(&inner);
        if inner.plan.as_ref().map(|p| p.tag()) != Some(desired.tag()) {
            if let Err(e) = self.enforce(&mut inner).await {
                self.events
                    .push(Lvl::Error, Cat::Firewall, format!("Updating bypass ranges failed: {e}"));
            }
        }
        self.save(&inner);
        self.publish(&inner);
    }

    /// Periodic supervision (every 2 s).
    pub async fn tick(&self) {
        let mut inner = self.inner.lock().await;
        let t = now();

        // Firewall integrity: re-apply if the kernel state no longer matches.
        if let Some(plan) = inner.plan.clone() {
            let ok = self.adapter.verify_firewall(&plan).await.unwrap_or(false);
            if !ok {
                self.events.push(
                    Lvl::Warn,
                    Cat::Firewall,
                    "Firewall table was missing or modified by another program; re-applying.",
                );
                if let Err(e) = self.enforce(&mut inner).await {
                    self.events
                        .push(Lvl::Error, Cat::Firewall, format!("Re-applying firewall failed: {e}"));
                }
            } else {
                inner.verified = true;
            }
        } else if let Err(e) = self.enforce(&mut inner).await {
            self.events
                .push(Lvl::Error, Cat::Firewall, format!("Firewall not established: {e}"));
        }

        if inner.state == ConnectionState::Connected {
            self.health_check(&mut inner, t).await;
        }
        // A disconnect/connect waiting for the lock goes first (it would only
        // cancel a reconnect attempt started now).
        if inner.state == ConnectionState::Reconnecting && t >= inner.next_reconnect && !self.cancel.preempt_pending() {
            self.try_reconnect(&mut inner, t).await;
        }

        if let Some(dns) = inner.active.as_ref().and_then(|a| a.dns.as_ref()) {
            match self.adapter.reassert_dns(dns) {
                Ok(true) => self.events.push(
                    Lvl::Warn,
                    Cat::Dns,
                    "resolv.conf was overwritten by another program; VPN DNS re-applied.",
                ),
                Ok(false) => {}
                Err(e) => self
                    .events
                    .push(Lvl::Error, Cat::Dns, format!("Could not re-apply VPN DNS: {e}")),
            }
        }
        self.publish(&inner);
    }

    async fn health_check(&self, inner: &mut Inner, t: u64) {
        let Some(kind) = inner.active.as_ref().map(|a| a.kind) else {
            return;
        };
        let Ok(driver) = self.driver(kind) else { return };
        if let Some(why) = driver.exited().await {
            return self.degraded(inner, &why).await;
        }
        if !self.adapter.iface_exists(&self.iface) {
            let why = format!("the {} interface disappeared", kind.interface_label());
            return self.degraded(inner, &why).await;
        }
        let new = match driver.stats(&self.iface).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("stats: {e}");
                return;
            }
        };
        let Some(active) = inner.active.as_mut() else { return };
        let prev_tx = active.stats.as_ref().map(|s| s.tx_bytes).unwrap_or(0);
        let since = active.since;
        active.stats = new.clone();
        if let Some(s) = new {
            let sending = s.tx_bytes > prev_tx;
            let stale = if s.last_handshake == 0 {
                t.saturating_sub(since) > 25
            } else {
                t.saturating_sub(s.last_handshake) > 180
            };
            if sending && stale {
                self.degraded(inner, "no handshake with the server while sending traffic")
                    .await;
            }
        }
    }

    async fn degraded(&self, inner: &mut Inner, why: &str) {
        let ks = inner.persisted.policy.kill_switch_active();
        if inner.persisted.policy.auto_reconnect && inner.spec.is_some() {
            self.events.push(
                Lvl::Warn,
                Cat::Connection,
                format!(
                    "Connection lost: {why}. Reconnecting{}.",
                    if ks {
                        "; kill switch keeps traffic blocked meanwhile"
                    } else {
                        ""
                    }
                ),
            );
            let _ = self.go(inner, Event::Degraded);
            inner.reconnect_attempt = 0;
            inner.next_reconnect = 0;
        } else {
            self.events
                .push(Lvl::Error, Cat::Connection, format!("Connection lost: {why}."));
            let _ = self.teardown().await;
            inner.active = None;
            inner.spec = None;
            inner.last_error = Some(format!("Connection lost: {why}"));
            let _ = self.enforce(inner).await;
            let _ = self.go(inner, Event::Failed { kill_switch: ks });
        }
    }

    async fn try_reconnect(&self, inner: &mut Inner, t: u64) {
        let Some(spec) = inner.spec.clone() else {
            let ks = inner.persisted.policy.kill_switch_active();
            let _ = self.go(inner, Event::Failed { kill_switch: ks });
            return;
        };
        inner.reconnect_attempt += 1;
        self.events.push(
            Lvl::Info,
            Cat::Connection,
            format!(
                "Reconnect attempt {} to {}.",
                inner.reconnect_attempt, spec.profile_name
            ),
        );
        let cancel = self.cancel.token();
        match self.bring_up(inner, &spec, &cancel).await {
            Ok(()) => {
                let _ = self.go(inner, Event::TunnelUp);
            }
            Err(e) if e.code == ErrorCode::Cancelled => {
                // The user disconnected or connected elsewhere: stop
                // reconnecting and end like a disconnect.
                let ks = inner.persisted.policy.kill_switch_active();
                inner.spec = None;
                let _ = self.go(inner, Event::DisconnectRequested);
                let _ = self.go(inner, Event::TornDown { kill_switch: ks });
            }
            Err(e)
                if matches!(
                    e.code,
                    ErrorCode::AuthFailed
                        | ErrorCode::HostKeyChanged
                        | ErrorCode::HostKeyUnknown
                        | ErrorCode::MissingDependency
                ) =>
            {
                // Retrying cannot succeed and would hammer the server: give up.
                let ks = inner.persisted.policy.kill_switch_active();
                inner.spec = None;
                let _ = self.go(inner, Event::Failed { kill_switch: ks });
            }
            Err(_) => {
                let backoff = (2u64 << inner.reconnect_attempt.min(5)).min(60);
                inner.next_reconnect = t + backoff;
            }
        }
    }

    pub async fn on_network_change(&self, what: String) {
        self.adapter.refresh_dns_backend().await;
        let mut inner = self.inner.lock().await;
        self.events
            .push(Lvl::Info, Cat::Network, format!("Network change detected: {what}"));
        // The addresses other devices reach the proxy on may have changed.
        if inner.lan.listening {
            inner.lan.addresses = crate::lan_proxy::addresses(&self.iface).await;
            self.publish(&inner);
        }
        // Re-resolve split domains soon: answers may differ on the new network.
        for e in inner.persisted.dns_cache.entries.values_mut() {
            e.next_refresh = e.next_refresh.min(now() + 2);
        }
        if inner.state != ConnectionState::Connected {
            return;
        }
        let Some(spec) = inner.spec.clone() else { return };
        // Only hostname endpoints can move; literal addresses never need re-resolving.
        let has_names = spec
            .tunnel
            .endpoints()
            .iter()
            .flatten()
            .any(|e| matches!(e.host, Host::Name(_)));
        if !has_names {
            return;
        }
        match self.resolve_endpoints(&mut inner, &spec).await {
            Ok(eps) if Some(&eps) != inner.active.as_ref().map(|a| &a.endpoints) => {
                self.events.push(
                    Lvl::Info,
                    Cat::Connection,
                    "Endpoint address changed after network change; updating tunnel.",
                );
                if let Some(a) = inner.active.as_mut() {
                    a.endpoints = eps.clone();
                }
                // Allow the new endpoint in the firewall first, then point the tunnel at it.
                if let Err(e) = self.enforce(&mut inner).await {
                    return self.degraded(&mut inner, &format!("firewall update failed: {e}")).await;
                }
                if let Ok(d) = self.driver(spec.tunnel.kind()) {
                    for e in d.update_endpoints(&self.iface, &spec.tunnel, &eps).await {
                        self.events
                            .push(Lvl::Error, Cat::Connection, format!("Updating endpoint failed: {e}"));
                    }
                }
            }
            _ => {}
        }
        self.publish(&inner);
    }

    pub async fn test_route(&self, query: &str) -> RouteTest {
        let _permit = self.route_tests.acquire().await;
        let q = query.trim().to_ascii_lowercase();
        let mut out = RouteTest {
            query: q.clone(),
            domain_decision: None,
            cnames: vec![],
            entries: vec![],
            error: None,
        };
        let (domain, ips): (Option<String>, Vec<IpAddr>) = if let Ok(ip) = q.parse::<IpAddr>() {
            (None, vec![ip])
        } else if alizy_core::config::is_valid_hostname(&q) {
            match self.resolver.resolve(&q).await {
                Ok((a, b)) => {
                    out.cnames = if a.cnames.is_empty() {
                        b.cnames.clone()
                    } else {
                        a.cnames.clone()
                    };
                    (
                        Some(q.clone()),
                        a.addrs.iter().chain(b.addrs.iter()).map(|x| x.0).collect(),
                    )
                }
                Err(e) => {
                    out.error = Some(format!("DNS resolution failed: {e}"));
                    (Some(q.clone()), vec![])
                }
            }
        } else {
            out.error = Some("Enter a valid domain name or IP address.".into());
            return out;
        };
        let inner = self.inner.lock().await;
        let enabled = inner.persisted.split.enabled;
        let rules_owned = if enabled {
            inner.persisted.split.rules.clone()
        } else {
            Vec::new()
        };
        let rules = &rules_owned;
        out.domain_decision = domain.as_deref().map(|d| split::evaluate(rules, Some(d), None));
        let plan = inner.plan.clone();
        let tunnel_up = inner.active.is_some();
        let ks = inner.persisted.policy.kill_switch_active();
        drop(inner);
        let table = firewall::read_table().await.ok().flatten();
        const MAX_TEST_IPS: usize = 16;
        if ips.len() > MAX_TEST_IPS {
            out.error = Some(format!(
                "{} addresses returned; showing the first {MAX_TEST_IPS}.",
                ips.len()
            ));
        }
        for ip in ips.into_iter().take(MAX_TEST_IPS) {
            let mut decision = split::evaluate(rules, domain.as_deref(), Some(ip));
            let in_plan = plan.as_ref().map(|p| p.direct.contains(ip)).unwrap_or(false);
            if decision.action == Action::Direct && !in_plan {
                decision
                    .explanation
                    .push_str(" Not in the active bypass set (not resolved yet, disabled family, or overridden).");
            }
            let fam_on = plan
                .as_ref()
                .map(|p| if ip.is_ipv4() { p.ipv4_enabled } else { p.ipv6_enabled })
                .unwrap_or(true);
            let intended = if !fam_on {
                "blocked (address family disabled)".to_string()
            } else if in_plan {
                "physical network (bypass)".to_string()
            } else if tunnel_up {
                self.iface.clone()
            } else if ks {
                "blocked (kill switch, VPN not connected)".to_string()
            } else {
                "physical network (VPN not connected)".to_string()
            };
            let in_kernel = match &table {
                Some(_) if plan.as_ref().map(|p| !p.direct.is_empty()).unwrap_or(false) => {
                    let set = if ip.is_ipv4() { "direct4" } else { "direct6" };
                    let elem = format!("{{ {ip} }}");
                    Some(
                        crate::exec::run(
                            &crate::exec::argv(&["nft", "get", "element", "inet", "alizy", set, &elem]),
                            None,
                        )
                        .await
                        .is_ok(),
                    )
                }
                _ => table.is_some().then_some(false),
            };
            let ipstr = ip.to_string();
            let mark = format!("{SPLIT_MARK:#x}");
            let args: Vec<&str> = if in_plan {
                vec!["ip", "route", "get", &ipstr, "mark", &mark]
            } else {
                vec!["ip", "route", "get", &ipstr]
            };
            let kernel_route = crate::exec::run(&crate::exec::argv(&args), None)
                .await
                .ok()
                .and_then(|s| s.lines().next().map(|l| l.trim().to_string()));
            out.entries.push(RouteTestEntry {
                ip,
                decision,
                intended,
                in_kernel_direct_set: in_kernel,
                kernel_route,
            });
        }
        out
    }

    /// Orderly stop (SIGTERM): remove the tunnel; leave kill-switch protection in place.
    pub async fn shutdown(&self) {
        // Stop accepting proxy clients before tearing anything down; the
        // persisted settings bring the listeners back on the next start.
        self.lan.lock().await.take();
        self.lan_socks.lock().await.take();
        self.local_http.lock().await.take();
        self.local_socks.lock().await.take();
        let mut inner = self.inner.lock().await;
        if inner.active.is_some() {
            let _ = self.teardown().await;
            inner.active = None;
        }
        inner.spec = None;
        let _ = self.enforce(&mut inner).await;
        self.save(&inner);
        self.events.push(
            Lvl::Info,
            Cat::Service,
            if inner.persisted.policy.kill_switch_active() {
                "Service stopping; kill switch remains active in the kernel."
            } else {
                "Service stopping."
            },
        );
    }
}

/// 16 random bytes for a credential verifier.
fn salt() -> [u8; 16] {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    b
}

fn on(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

/// Minimal join_all (avoids a dependency): polls futures concurrently on this task.
async fn futures_join_all<F: std::future::Future>(futs: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut set = Vec::new();
    for f in futs {
        set.push(Box::pin(f));
    }
    let mut out: Vec<Option<F::Output>> = (0..set.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, f) in set.iter_mut().enumerate() {
            if out[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => out[i] = Some(v),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.into_iter().map(|o| o.expect("all ready")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::ssh::{SshDriver, SshEnv, SshOps};
    use crate::driver::wireguard::{WgOps, WireGuardDriver};
    use crate::driver::BoxFut;
    use crate::egress::Egress;
    use crate::linux::ssh::{SshError, SshUp};
    use alizy_core::config::WgConfig;
    use alizy_core::firewall::TunnelRules;
    use alizy_core::protocol::TunnelConfig;
    use alizy_core::routing::RoutePlan;
    use alizy_core::ssh::{HostKey, SshConfig, SshPublic};
    use alizy_core::sysprobe::Dependency;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zeroize::Zeroizing;

    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAICJ9AyQ1/Hf8ky/h28JhISjg1GkKGhTejR6j6uTwPF1l";
    const SSH_UID: u32 = 60123;

    /// A port nothing is listening on (released before use).
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        l.local_addr().unwrap().port()
    }

    /// Two distinct free ports (held simultaneously so the kernel can't hand
    /// back the same one twice).
    fn two_free_ports() -> (u16, u16) {
        let a = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let b = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        (a.local_addr().unwrap().port(), b.local_addr().unwrap().port())
    }

    #[derive(Default)]
    struct FakeState {
        log: Vec<String>,
        /// Which data plane is currently up: "wg", "ssh", "rec" or none.
        up: Option<&'static str>,
        applied: Vec<FirewallPlan>,
        ssh_exit: Option<String>,
        ssh_fail: Option<SshError>,
        violations: Vec<String>,
        /// `ssh_up` / the recording driver's start block until cancelled.
        slow: bool,
        /// What `ssh_missing` reports.
        missing: Vec<Dependency>,
        /// Upstreams passed to the last `ssh_up`.
        upstreams: Vec<IpAddr>,
        /// DNS plan of the last `network_up`.
        dns: Option<DnsPlan>,
        /// Recording driver: `exited` reports this once.
        rec_exit: Option<String>,
    }

    /// Shared fake OS: the platform adapter and every driver's ops record here.
    #[derive(Default)]
    struct Fake(std::sync::Mutex<FakeState>);

    impl Fake {
        fn with<R>(&self, f: impl FnOnce(&mut FakeState) -> R) -> R {
            f(&mut self.0.lock().unwrap())
        }
    }

    struct FakePlatform(Arc<Fake>);

    impl PlatformAdapter for FakePlatform {
        async fn apply_firewall(&self, plan: &FirewallPlan) -> Result<(), String> {
            self.0.with(|s| {
                s.log.push("fw".into());
                s.applied.push(plan.clone());
            });
            Ok(())
        }
        async fn verify_firewall(&self, plan: &FirewallPlan) -> Result<bool, String> {
            Ok(self.0.with(|s| s.applied.last().map(|p| p.tag()) == Some(plan.tag())))
        }
        async fn network_up(&self, _iface: &str, _routes: &RoutePlan, dns: Option<&DnsPlan>) -> Result<(), String> {
            self.0.with(|s| {
                s.log.push("net_up".into());
                s.dns = dns.cloned();
                if s.up.is_none() {
                    return Err("interface disappeared during bring-up".into());
                }
                Ok(())
            })
        }
        async fn tunnel_down(&self, _iface: &str) -> Result<(), String> {
            self.0.with(|s| {
                s.up = None;
                s.ssh_exit = None;
                s.log.push("down".into());
            });
            Ok(())
        }
    }

    impl Backend for FakePlatform {
        fn dns_backend(&self) -> Option<DnsBackend> {
            None
        }
        async fn refresh_dns_backend(&self) {}
        fn reassert_dns(&self, _plan: &DnsPlan) -> Result<bool, String> {
            Ok(false)
        }
        fn restore_dns_backup(&self) -> Result<(), String> {
            Ok(())
        }
        fn iface_exists(&self, _iface: &str) -> bool {
            self.0.with(|s| s.up.is_some())
        }
        async fn set_split_rule(&self, _want: bool) -> Vec<String> {
            Vec::new()
        }
    }

    struct FakeWg(Arc<Fake>);

    impl WgOps for FakeWg {
        async fn create(&self, _iface: &str, cfg: &WgConfig, _eps: &[Option<SocketAddr>]) -> Result<(), String> {
            assert!(!cfg.peers.is_empty());
            self.0.with(|s| {
                if s.up.is_some() {
                    s.violations
                        .push(format!("WireGuard brought up while {:?} still up", s.up));
                }
                s.up = Some("wg");
                s.log.push("wg_up".into());
            });
            Ok(())
        }
        async fn set_endpoint(&self, _iface: &str, _peer: &str, _ep: SocketAddr) -> Result<(), String> {
            self.0.with(|s| s.log.push("wg_set_endpoint".into()));
            Ok(())
        }
        async fn stats(&self, _iface: &str) -> Result<Option<TunnelStats>, String> {
            Ok(None)
        }
    }

    struct FakeSsh(Arc<Fake>);

    impl SshOps for FakeSsh {
        type Tunnel = ();
        async fn start(&self, req: SshUp<'_>) -> Result<(), SshError> {
            assert_eq!(req.user, (SSH_UID, SSH_UID));
            assert!(req.socks_port != 0);
            if self.0.with(|s| s.slow) {
                self.0.with(|s| s.log.push("ssh_up".into()));
                // Same shape as wait_ready: poll until ready, ssh exit or cancel.
                tokio::time::timeout(std::time::Duration::from_secs(30), req.cancel.cancelled())
                    .await
                    .expect("bring-up was never cancelled");
                return Err(SshError::Cancelled);
            }
            self.0.with(|s| {
                s.upstreams = req.upstreams.clone();
                s.log.push("ssh_up".into());
                if let Some(e) = s.ssh_fail.take() {
                    return Err(e);
                }
                if s.up.is_some() {
                    s.violations.push(format!("SSH brought up while {:?} still up", s.up));
                }
                s.up = Some("ssh");
                Ok(())
            })
        }
        async fn stop(&self, _t: ()) {
            self.0.with(|s| s.log.push("ssh_stop".into()));
        }
        fn try_exited(&self, _t: &mut ()) -> Option<String> {
            self.0.with(|s| s.ssh_exit.take())
        }
        fn stats(&self, _t: &(), _iface: &str) -> TunnelStats {
            TunnelStats::default()
        }
        async fn keyscan(
            &self,
            user: (u32, u32),
            _host: IpAddr,
            _port: u16,
            cancel: &CancelToken,
        ) -> Result<HostKey, String> {
            assert_eq!(user, (SSH_UID, SSH_UID));
            self.0.with(|s| s.log.push("keyscan".into()));
            if self.0.with(|s| s.slow) {
                cancel.cancelled().await;
                return Err(SshError::Cancelled.to_string());
            }
            Ok(host_key())
        }
        async fn missing(&self, _user: (u32, u32)) -> Vec<Dependency> {
            self.0.with(|s| s.missing.clone())
        }
    }

    /// A driver that knows nothing but the trait: proves the engine runs the
    /// whole lifecycle (firewall, verify, teardown, start, network, health,
    /// reconnect, cancellation) without any protocol-specific code path.
    struct Recording(Arc<Fake>);

    impl TunnelDriver for Recording {
        fn kind(&self) -> ProtocolKind {
            ProtocolKind::WireGuard
        }
        fn prepare(&self) -> Result<Session, UpError> {
            self.0.with(|s| s.log.push("rec_prepare".into()));
            Ok(Session { local_port: Some(4242) })
        }
        fn firewall_rules(&self, iface: &str, endpoints: &[SocketAddr], session: &Session) -> TunnelRules {
            TunnelRules {
                iface: iface.into(),
                tcp_endpoints: endpoints.to_vec(),
                socks_port: session.local_port,
                ..Default::default()
            }
        }
        fn verify<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFut<'a, Result<(), UpError>> {
            Box::pin(async move {
                self.0.with(|s| s.log.push("rec_verify".into()));
                Ok(())
            })
        }
        fn start<'a>(&'a self, ctx: Ctx<'a>) -> BoxFut<'a, Result<(), UpError>> {
            Box::pin(async move {
                self.0.with(|s| s.log.push("rec_start".into()));
                if self.0.with(|s| s.slow) {
                    ctx.cancel.cancelled().await;
                    return Err(UpError::from("gave up".to_string()));
                }
                self.0.with(|s| s.up = Some("rec"));
                Ok(())
            })
        }
        fn stop(&self) -> BoxFut<'_, ()> {
            Box::pin(async move { self.0.with(|s| s.log.push("rec_stop".into())) })
        }
        fn exited(&self) -> BoxFut<'_, Option<String>> {
            Box::pin(async move { self.0.with(|s| s.rec_exit.take()) })
        }
        fn stats<'a>(&'a self, _iface: &'a str) -> BoxFut<'a, Result<Option<TunnelStats>, String>> {
            Box::pin(async { Ok(None) })
        }
    }

    fn host_key() -> HostKey {
        HostKey {
            key_type: "ssh-ed25519".into(),
            key_b64: KEY.into(),
        }
    }

    struct T {
        engine: Arc<Engine<FakePlatform>>,
        fake: Arc<Fake>,
        _dir: tempfile::TempDir,
    }

    impl T {
        fn fake(&self) -> &Fake {
            &self.fake
        }
        fn log(&self) -> Vec<String> {
            self.fake().with(|s| s.log.clone())
        }
        async fn state(&self) -> ConnectionState {
            self.engine.inner.lock().await.state
        }
    }

    async fn engine_from(
        kill_switch: bool,
        drivers: impl FnOnce(&Arc<Fake>, &std::path::Path) -> Vec<Box<dyn TunnelDriver>>,
    ) -> T {
        let dir = tempfile::tempdir().unwrap();
        let persist = Persist::new(&dir.path().join("state")).unwrap();
        let fake = Arc::new(Fake::default());
        let drivers = drivers(&fake, dir.path());
        let engine = Engine::start(
            FakePlatform(fake.clone()),
            drivers,
            persist,
            Resolver::new(None),
            "alizy0".into(),
        )
        .await;
        if kill_switch {
            engine
                .set_policy(NetworkPolicy {
                    kill_switch: true,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        T {
            engine,
            fake,
            _dir: dir,
        }
    }

    async fn engine_with(user: Option<(u32, u32)>, kill_switch: bool) -> T {
        engine_from(kill_switch, |f, dir| {
            vec![
                Box::new(WireGuardDriver::new(FakeWg(f.clone()))),
                Box::new(SshDriver::new(
                    FakeSsh(f.clone()),
                    SshEnv {
                        user,
                        runtime: PathBuf::from(dir),
                    },
                )),
            ]
        })
        .await
    }

    async fn engine(kill_switch: bool) -> T {
        engine_with(Some((SSH_UID, SSH_UID)), kill_switch).await
    }

    fn wg_spec() -> TunnelSpec {
        let text = "[Interface]\nPrivateKey = dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=\nAddress = 10.66.0.2/32\n\n\
                    [Peer]\nPublicKey = 3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=\nAllowedIPs = 0.0.0.0/0\n\
                    Endpoint = 198.51.100.7:51820\n";
        TunnelSpec {
            profile_id: "wg1".into(),
            profile_name: "WG".into(),
            tunnel: TunnelConfig::WireGuard(alizy_core::parse(text).unwrap().config),
            cached_endpoints: vec![],
        }
    }

    fn ssh_spec(host_key: Option<HostKey>) -> TunnelSpec {
        TunnelSpec {
            profile_id: "ssh1".into(),
            profile_name: "SSH".into(),
            tunnel: TunnelConfig::Ssh(SshConfig {
                public: SshPublic {
                    host: "203.0.113.5".parse().unwrap(),
                    port: 22,
                    username: "alice".into(),
                    host_key,
                    dns: vec![],
                },
                password: Zeroizing::new("pw".into()),
            }),
            cached_endpoints: vec![],
        }
    }

    #[tokio::test]
    async fn lifecycle_is_driven_only_by_the_driver_trait() {
        let t = engine_from(true, |f, _| vec![Box::new(Recording(f.clone()))]).await;
        let start = t.log().len();
        t.engine.connect(wg_spec()).await.unwrap();
        assert_eq!(t.state().await, ConnectionState::Connected);
        let log: Vec<String> = t.log()[start..].iter().filter(|l| *l != "rec_stop").cloned().collect();
        assert_eq!(
            log,
            ["rec_prepare", "fw", "rec_verify", "rec_start", "net_up"],
            "{log:?}"
        );
        // The driver's firewall rules reached the plan unchanged.
        let tun = t.engine.inner.lock().await.plan.clone().unwrap().tunnel.unwrap();
        assert_eq!(tun.socks_port, Some(4242));
        assert_eq!(
            tun.tcp_endpoints,
            vec!["198.51.100.7:51820".parse::<SocketAddr>().unwrap()]
        );
        // Health: the driver reports its data plane died → reconnect through the same path.
        t.fake().with(|s| s.rec_exit = Some("engine crashed".into()));
        t.engine.tick().await;
        assert_eq!(t.state().await, ConnectionState::Connected);
        assert_eq!(t.log().iter().filter(|l| *l == "rec_start").count(), 2);
        assert!(t
            .engine
            .events
            .since(0)
            .iter()
            .any(|e| e.message.contains("Connection lost: engine crashed")));
        // Disconnect stops the driver before the platform removes the interface.
        let start = t.log().len();
        t.engine.disconnect().await.unwrap();
        let log = t.log()[start..].to_vec();
        let stop = log.iter().position(|l| l == "rec_stop").unwrap();
        let down = log.iter().position(|l| l == "down").unwrap();
        assert!(stop < down, "{log:?}");
        assert_eq!(t.state().await, ConnectionState::Protected);
        kill_switch_held_throughout(&t);
    }

    #[tokio::test]
    async fn cancellation_is_generic_for_every_driver() {
        let t = engine_from(true, |f, _| vec![Box::new(Recording(f.clone()))]).await;
        t.fake().with(|s| s.slow = true);
        let e = t.engine.clone();
        let attempt = tokio::spawn(async move { e.connect(wg_spec()).await });
        wait_for_log(&t, "rec_start").await;
        let started = std::time::Instant::now();
        t.engine.disconnect().await.unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(attempt.await.unwrap().unwrap_err().code, ErrorCode::Cancelled);
        assert_eq!(t.state().await, ConnectionState::Protected);
        assert!(t.engine.status().last_error.is_none());
        kill_switch_held_throughout(&t);
    }

    #[tokio::test]
    async fn unregistered_protocol_is_unsupported_and_touches_nothing() {
        let t = engine_from(true, |f, _| vec![Box::new(WireGuardDriver::new(FakeWg(f.clone())))]).await;
        let before = t.fake().with(|s| s.applied.len());
        let e = t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::Unsupported);
        assert_eq!(t.fake().with(|s| s.applied.len()), before);
        assert_eq!(t.state().await, ConnectionState::Protected);
        t.engine.connect(wg_spec()).await.unwrap();
    }

    #[tokio::test]
    async fn wg_bring_up_order_and_dns_unchanged() {
        let t = engine(false).await;
        let start = t.log().len();
        t.engine.connect(wg_spec()).await.unwrap();
        let log = t.log()[start..].to_vec();
        let fw = log.iter().position(|l| l == "fw").unwrap();
        let up = log.iter().position(|l| l == "wg_up").unwrap();
        let net = log.iter().position(|l| l == "net_up").unwrap();
        assert!(fw < up && up < net, "{log:?}");
        assert_eq!(t.engine.status().tunnel_kind, None);
        // SSH: the system resolver points at the local forwarder.
        t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap();
        assert_eq!(
            t.fake().with(|s| s.dns.clone()).unwrap(),
            alizy_core::routing::ssh_dns_plan(&NetworkPolicy::default())
        );
    }

    #[tokio::test]
    async fn ssh_connect_reports_kind_and_plan() {
        let t = engine(true).await;
        t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap();
        let st = t.engine.status();
        assert_eq!(st.state, ConnectionState::Connected);
        assert_eq!(st.tunnel_kind.as_deref(), Some("ssh"));
        let inner = t.engine.inner.lock().await;
        let tun = inner.plan.as_ref().unwrap().tunnel.clone().unwrap();
        assert_eq!(tun.tcp_endpoints, vec!["203.0.113.5:22".parse::<SocketAddr>().unwrap()]);
        assert_eq!(tun.ssh_uid, Some(SSH_UID));
        assert!(tun.block_udp && tun.socks_port.is_some() && tun.endpoints.is_empty());
        drop(inner);
        // WireGuard status keeps `tunnel_kind` absent (IPC JSON unchanged).
        t.engine.connect(wg_spec()).await.unwrap();
        assert_eq!(t.engine.status().tunnel_kind, None);
    }

    #[tokio::test]
    async fn child_exit_triggers_degraded() {
        let t = engine(true).await;
        t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap();
        assert_eq!(t.state().await, ConnectionState::Connected);
        let applied_before = t.fake().with(|s| s.applied.len());
        t.fake()
            .with(|s| s.ssh_exit = Some("ssh exited with status 255".into()));
        {
            // Drive only the health check so the intermediate state is observable.
            let mut inner = t.engine.inner.lock().await;
            t.engine.health_check(&mut inner, now()).await;
            assert_eq!(inner.state, ConnectionState::Reconnecting);
            // The tunnel's firewall (kill switch + SSH exceptions) stays in place.
            let plan = inner.plan.as_ref().unwrap();
            assert!(plan.kill_switch && plan.tunnel.as_ref().unwrap().ssh_uid.is_some());
        }
        assert!(t
            .engine
            .events
            .since(0)
            .iter()
            .any(|e| e.message.contains("SSH connection lost: ssh exited with status 255")));
        // The next supervision tick reconnects through the normal path.
        t.engine.tick().await;
        assert_eq!(t.state().await, ConnectionState::Connected);
        assert_eq!(t.log().iter().filter(|l| *l == "ssh_up").count(), 2);
        // Protection never dropped while reconnecting.
        assert!(t
            .fake()
            .with(|s| s.applied[applied_before..].iter().all(|p| p.kill_switch)));
    }

    #[tokio::test]
    async fn switch_kind_tears_down_previous_backend() {
        let t = engine(true).await;
        t.engine.connect(wg_spec()).await.unwrap();
        let start = t.log().len();
        t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap();
        let log = t.log()[start..].to_vec();
        let down = log.iter().position(|l| l == "down").expect("WireGuard torn down");
        let up = log.iter().position(|l| l == "ssh_up").unwrap();
        assert!(down < up, "{log:?}");
        let start = t.log().len();
        t.engine.connect(wg_spec()).await.unwrap();
        let log = t.log()[start..].to_vec();
        let down = log.iter().position(|l| l == "down").expect("SSH torn down");
        let up = log.iter().position(|l| l == "wg_up").unwrap();
        assert!(down < up, "{log:?}");
        t.fake().with(|s| {
            assert!(s.violations.is_empty(), "{:?}", s.violations);
            // The kill switch was in every plan applied after it was enabled.
            let first = s.applied.iter().position(|p| p.kill_switch).unwrap();
            assert!(s.applied[first..].iter().all(|p| p.kill_switch));
        });
        let inner = t.engine.inner.lock().await;
        let tun = inner.plan.as_ref().unwrap().tunnel.clone().unwrap();
        assert!(tun.ssh_uid.is_none() && !tun.block_udp && tun.tcp_endpoints.is_empty());
        assert_eq!(inner.state, ConnectionState::Connected);
    }

    #[tokio::test]
    async fn host_key_unknown_does_not_trigger_reconnect() {
        for ks in [false, true] {
            let t = engine(ks).await;
            let e = t.engine.connect(ssh_spec(None)).await.unwrap_err();
            assert_eq!(e.code, ErrorCode::HostKeyUnknown);
            assert_eq!(e.host_key, Some(host_key()));
            let log = t.log();
            // Firewall (with the SSH exceptions) is enforced before the scan.
            let scan = log.iter().position(|l| l == "keyscan").unwrap();
            assert_eq!(log[scan - 1], "fw");
            t.fake().with(|s| {
                let plan_at_scan = &s.applied[log[..scan].iter().filter(|l| *l == "fw").count() - 1];
                let tun = plan_at_scan.tunnel.as_ref().unwrap();
                assert_eq!(tun.ssh_uid, Some(SSH_UID));
                assert_eq!(tun.tcp_endpoints.len(), 1);
                // Afterwards the no-tunnel policy is back.
                assert!(s.applied.last().unwrap().tunnel.is_none());
            });
            assert!(!log.contains(&"ssh_up".to_string()));
            {
                let inner = t.engine.inner.lock().await;
                let want = if ks {
                    ConnectionState::Protected
                } else {
                    ConnectionState::Disconnected
                };
                assert_eq!(inner.state, want);
                assert_eq!(inner.reconnect_attempt, 0);
                assert!(inner.spec.is_none() && inner.active.is_none() && inner.last_error.is_none());
            }
            t.engine.tick().await;
            t.engine.tick().await;
            assert_eq!(t.log().iter().filter(|l| *l == "keyscan").count(), 1);
            assert!(!t.log().contains(&"ssh_up".to_string()));
        }
    }

    #[tokio::test]
    async fn ssh_auth_failure_fails_without_reconnect_loop() {
        let t = engine(true).await;
        t.fake().with(|s| s.ssh_fail = Some(SshError::AuthFailed));
        let e = t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::AuthFailed);
        assert!(e.message.contains("authentication failed"));
        assert_eq!(t.state().await, ConnectionState::Protected);
        t.fake()
            .with(|s| assert!(s.applied.last().unwrap().tunnel.is_none() && s.applied.last().unwrap().kill_switch));
        t.engine.tick().await;
        t.engine.tick().await;
        assert_eq!(t.log().iter().filter(|l| *l == "ssh_up").count(), 1);
    }

    #[tokio::test]
    async fn auth_failure_during_reconnect_stops_retrying() {
        let t = engine(true).await;
        t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap();
        t.fake().with(|s| {
            s.ssh_exit = Some("ssh exited".into());
            s.ssh_fail = Some(SshError::AuthFailed);
        });
        t.engine.tick().await;
        assert_eq!(t.state().await, ConnectionState::Protected);
        t.engine.tick().await;
        assert_eq!(t.log().iter().filter(|l| *l == "ssh_up").count(), 2);
    }

    #[tokio::test]
    async fn wg_connect_without_peers_rejected() {
        let t = engine(false).await;
        let mut spec = wg_spec();
        spec.tunnel = TunnelConfig::WireGuard(WgConfig::placeholder());
        let e = t.engine.connect(spec).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidConfig);
        assert!(!t.log().contains(&"wg_up".to_string()));
    }

    #[tokio::test]
    async fn ssh_connect_without_system_user_is_missing_dependency() {
        let t = engine_with(None, false).await;
        let e = t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::MissingDependency);
        assert!(e.message.contains("alizy-ssh"));
        // WireGuard still works.
        t.engine.connect(wg_spec()).await.unwrap();
    }

    #[tokio::test]
    async fn invalid_ssh_config_rejected_before_anything_runs() {
        let t = engine(false).await;
        let mut spec = ssh_spec(Some(host_key()));
        let TunnelConfig::Ssh(c) = &mut spec.tunnel else {
            unreachable!()
        };
        c.public.username = "-oProxyCommand=x".into();
        let e = t.engine.connect(spec).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidConfig);
        assert!(!t.log().iter().any(|l| l == "ssh_up" || l == "keyscan"));
    }

    async fn wait_for_log(t: &T, what: &str) {
        for _ in 0..500 {
            if t.log().iter().any(|l| l == what) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("{what} never happened: {:?}", t.log());
    }

    fn kill_switch_held_throughout(t: &T) {
        t.fake().with(|s| {
            let first = s.applied.iter().position(|p| p.kill_switch).unwrap();
            assert!(s.applied[first..].iter().all(|p| p.kill_switch));
            assert!(s.applied.last().unwrap().tunnel.is_none());
        });
    }

    #[tokio::test]
    async fn disconnect_cancels_slow_ssh_bring_up_promptly() {
        let t = engine(true).await;
        t.fake().with(|s| s.slow = true);
        let e = t.engine.clone();
        let attempt = tokio::spawn(async move { e.connect(ssh_spec(Some(host_key()))).await });
        wait_for_log(&t, "ssh_up").await;
        assert_eq!(t.engine.status().state, ConnectionState::Connecting);
        let started = std::time::Instant::now();
        t.engine.disconnect().await.unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        let e = attempt.await.unwrap().unwrap_err();
        assert_eq!(e.code, ErrorCode::Cancelled);
        assert_eq!(t.state().await, ConnectionState::Protected);
        assert!(t.engine.status().last_error.is_none());
        kill_switch_held_throughout(&t);
        assert!(!t.engine.events.since(0).iter().any(|e| e.level == Lvl::Error));
        // No reconnect loop afterwards.
        t.engine.tick().await;
        t.engine.tick().await;
        assert_eq!(t.log().iter().filter(|l| *l == "ssh_up").count(), 1);
    }

    #[tokio::test]
    async fn disconnect_cancels_slow_keyscan_promptly() {
        let t = engine(true).await;
        t.fake().with(|s| s.slow = true);
        let e = t.engine.clone();
        let attempt = tokio::spawn(async move { e.connect(ssh_spec(None)).await });
        wait_for_log(&t, "keyscan").await;
        let started = std::time::Instant::now();
        t.engine.disconnect().await.unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(attempt.await.unwrap().unwrap_err().code, ErrorCode::Cancelled);
        assert_eq!(t.state().await, ConnectionState::Protected);
        kill_switch_held_throughout(&t);
    }

    #[tokio::test]
    async fn disconnect_cancels_slow_reconnect_promptly() {
        let t = engine(true).await;
        t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap();
        t.fake().with(|s| {
            s.ssh_exit = Some("ssh exited".into());
            s.slow = true;
        });
        let e = t.engine.clone();
        // Health check → Reconnecting → reconnect attempt that never finishes on its own.
        let tick = tokio::spawn(async move { e.tick().await });
        for _ in 0..500 {
            if t.log().iter().filter(|l| *l == "ssh_up").count() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // (The published status lags until the tick ends; the attempt is running.)
        assert_eq!(t.log().iter().filter(|l| *l == "ssh_up").count(), 2);
        let started = std::time::Instant::now();
        t.engine.disconnect().await.unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        tick.await.unwrap();
        assert_eq!(t.state().await, ConnectionState::Protected);
        kill_switch_held_throughout(&t);
        t.engine.tick().await;
        assert_eq!(t.log().iter().filter(|l| *l == "ssh_up").count(), 2);
    }

    #[tokio::test]
    async fn new_connect_supersedes_slow_ssh_bring_up() {
        let t = engine(true).await;
        t.fake().with(|s| s.slow = true);
        let e = t.engine.clone();
        let first = tokio::spawn(async move { e.connect(ssh_spec(Some(host_key()))).await });
        wait_for_log(&t, "ssh_up").await;
        t.fake().with(|s| s.slow = false);
        tokio::time::timeout(std::time::Duration::from_secs(1), t.engine.connect(wg_spec()))
            .await
            .expect("second connect got the lock promptly")
            .unwrap();
        assert_eq!(first.await.unwrap().unwrap_err().code, ErrorCode::Cancelled);
        assert_eq!(t.state().await, ConnectionState::Connected);
    }

    #[tokio::test]
    async fn lan_custom_dns_is_dropped_with_a_warning() {
        let t = engine(false).await;
        t.engine
            .set_policy(NetworkPolicy {
                custom_dns: vec!["192.168.1.1".parse().unwrap()],
                ..Default::default()
            })
            .await
            .unwrap();
        t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap();
        assert_eq!(
            t.fake().with(|s| s.upstreams.clone()),
            alizy_core::ssh::DEFAULT_SSH_DNS.to_vec()
        );
        let ev = t.engine.events.since(0);
        let w = ev
            .iter()
            .find(|e| e.message.contains("can't be reached through an SSH tunnel"))
            .expect("warning");
        assert_eq!(w.level, Lvl::Warn);
        assert!(w.message.contains("using 1.1.1.1, 9.9.9.9") && w.message.contains("192.168.1.1"));
    }

    #[tokio::test]
    async fn system_report_uses_daemon_ssh_check() {
        let t = engine(false).await;
        t.fake().with(|s| s.missing = vec![Dependency::OpenSsh]);
        let r = t.engine.system_report().await.unwrap();
        assert_eq!(r.ssh_missing, vec![Dependency::OpenSsh]);
        assert!(!r.ssh_ready);
        // Without the alizy-ssh user the presence-only probe result stands.
        let t = engine_with(None, false).await;
        t.fake().with(|s| s.missing = vec![Dependency::OpenSsh]);
        let r = t.engine.system_report().await.unwrap();
        assert_eq!(r.ssh_ready, r.ssh_missing.is_empty());
    }

    #[tokio::test]
    async fn lan_proxy_starts_stops_and_reaches_the_firewall() {
        let t = engine(true).await; // kill switch on: the reply exception matters
                                    // Off by default, and the plan carries no proxy rule.
        assert!(!t.engine.lan_proxy_status().await.enabled);
        assert!(t.fake().with(|s| s.applied.last().unwrap().lan_proxy_port.is_none()));

        let (port, socks_port) = two_free_ports();
        let st = t
            .engine
            .set_lan_proxy(LanProxyConfig {
                enabled: true,
                port,
                socks_port,
                auth: None,
            })
            .await
            .unwrap();
        assert!(
            st.enabled
                && st.listening
                && st.port == port
                && st.error.is_none()
                && st.socks_listening
                && st.socks_port == socks_port
                && st.socks_error.is_none(),
            "{st:?}"
        );
        // The HTTP listener is really up.
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut resp = String::new();
        c.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        // The SOCKS5 listener is really up: a non-SOCKS greeting gets closed.
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap(); // greeting
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [5, 0]);
        // The firewall plan now carries both reply exceptions.
        assert_eq!(t.fake().with(|s| s.applied.last().unwrap().lan_proxy_port), Some(port));
        assert_eq!(
            t.fake().with(|s| s.applied.last().unwrap().lan_socks_port),
            Some(socks_port)
        );
        // Persisted: a fresh engine over the same state would come back on.
        let persisted = t.engine.inner.lock().await.persisted.lan_proxy.clone();
        assert_eq!(
            persisted,
            LanProxyConfig {
                enabled: true,
                port,
                socks_port,
                auth: None,
            }
        );

        // Disable: listeners gone (ports reusable) and no rules in the plan.
        t.engine
            .set_lan_proxy(LanProxyConfig {
                enabled: false,
                port,
                socks_port,
                auth: None,
            })
            .await
            .unwrap();
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err());
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await.is_err());
        assert!(t.fake().with(|s| s.applied.last().unwrap().lan_proxy_port.is_none()));
        assert!(t.fake().with(|s| s.applied.last().unwrap().lan_socks_port.is_none()));
        let st = t.engine.lan_proxy_status().await;
        assert!(!st.enabled && !st.listening && !st.socks_listening, "{st:?}");
    }

    #[tokio::test]
    async fn lan_proxy_bind_failure_is_reported_not_raised() {
        let t = engine(false).await;
        let taken = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let socks_port = free_port();
        let st = t
            .engine
            .set_lan_proxy(LanProxyConfig {
                enabled: true,
                port,
                socks_port,
                auth: None,
            })
            .await
            .unwrap();
        assert!(st.enabled && !st.listening, "{st:?}");
        let err = st.error.expect("bind error");
        assert!(err.contains("already in use"), "{err}");
        assert!(t.engine.inner.lock().await.persisted.lan_proxy.enabled);
        drop(taken);
        let st = t
            .engine
            .set_lan_proxy(LanProxyConfig {
                enabled: true,
                port,
                socks_port,
                auth: None,
            })
            .await
            .unwrap();
        assert!(st.error.is_none(), "{st:?}");
        assert!(st.enabled && st.listening, "{st:?}");
    }

    #[tokio::test]
    async fn lan_proxy_port_is_validated_and_needs_no_tunnel() {
        let t = engine(false).await;
        let e = t
            .engine
            .set_lan_proxy(LanProxyConfig {
                enabled: true,
                port: 0,
                socks_port: 1080,
                auth: None,
            })
            .await
            .unwrap_err();
        assert!(e.message.contains("port"), "{e:?}");
        let port = free_port();
        let socks_port = free_port();
        let st = t
            .engine
            .set_lan_proxy(LanProxyConfig {
                enabled: true,
                port,
                socks_port,
                auth: None,
            })
            .await
            .unwrap();
        assert!(st.enabled && st.listening && st.error.is_none(), "{st:?}");
        assert_eq!(t.state().await, ConnectionState::Disconnected);
    }

    fn proxy_policy(ks: bool) -> NetworkPolicy {
        let (socks, http) = two_free_ports();
        NetworkPolicy {
            kill_switch: ks,
            mode: ConnectionMode::Proxy,
            proxy_socks_port: socks,
            proxy_http_port: http,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn proxy_mode_leaves_system_alone_and_fails_closed() {
        let t = engine(false).await;
        let policy = proxy_policy(true);
        t.engine.set_policy(policy.clone()).await.unwrap();
        // No tunnel yet: no kill switch (proxy mode), egress blocked, listeners up.
        assert_eq!(t.state().await, ConnectionState::Disconnected);
        assert_eq!(*t.engine.egress.get(), Egress::Blocked);
        let st = t.engine.status();
        assert!(
            !st.kill_switch.enabled && st.policy.kill_switch,
            "preference kept, switch inactive"
        );
        assert!(st.local_proxy.active && st.local_proxy.socks_listening && st.local_proxy.http_listening);
        let plan = t.engine.inner.lock().await.plan.clone().unwrap();
        assert_eq!(plan.proxy_guard.as_deref(), Some("alizy0"));
        assert!(!plan.kill_switch);

        t.engine.connect(wg_spec()).await.unwrap();
        assert_eq!(t.state().await, ConnectionState::Connected);
        // System DNS untouched; firewall guards marked traffic; egress is marked.
        assert_eq!(t.fake().with(|s| s.dns.clone()), None);
        let plan = t.engine.inner.lock().await.plan.clone().unwrap();
        assert!(plan.proxy_guard.is_some() && !plan.kill_switch && !plan.dns_leak_protection);
        assert!(
            matches!(&*t.engine.egress.get(), Egress::Marked { mark, .. } if *mark == alizy_core::firewall::PROXY_MARK)
        );
        // The local proxy refuses rather than connecting directly once the tunnel is gone.
        t.engine.disconnect().await.unwrap();
        assert_eq!(*t.engine.egress.get(), Egress::Blocked);
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", policy.proxy_socks_port))
            .await
            .unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        c.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await.unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r[1], 0x02, "connection not allowed while the VPN is down");
    }

    #[tokio::test]
    async fn ssh_proxy_mode_goes_through_ssh_socks_port() {
        let t = engine(false).await;
        t.engine.set_policy(proxy_policy(false)).await.unwrap();
        t.engine.connect(ssh_spec(Some(host_key()))).await.unwrap();
        let port = t
            .engine
            .inner
            .lock()
            .await
            .active
            .as_ref()
            .unwrap()
            .session
            .local_port
            .unwrap();
        assert_eq!(
            *t.engine.egress.get(),
            Egress::Socks(SocketAddr::from(([127, 0, 0, 1], port)))
        );
        assert!(!t.engine.status().local_proxy.udp, "SSH carries no UDP");
    }

    #[tokio::test]
    async fn switching_mode_rebuilds_and_restores_the_kill_switch() {
        let t = engine(true).await;
        t.engine.connect(wg_spec()).await.unwrap();
        assert!(t.fake().with(|s| s.dns.is_some()));
        let start = t.log().len();
        let mut p = proxy_policy(true);
        t.engine.set_policy(p.clone()).await.unwrap();
        let log = t.log()[start..].to_vec();
        let down = log.iter().position(|l| l == "down").expect("previous mode cleaned up");
        let up = log.iter().position(|l| l == "wg_up").unwrap();
        assert!(down < up, "{log:?}");
        assert_eq!(t.state().await, ConnectionState::Connected);
        assert!(!t.engine.status().kill_switch.enabled);
        assert_eq!(t.fake().with(|s| s.dns.clone()), None);
        // Back to tunnel mode: kill switch and system DNS return, local proxy stops.
        p.mode = ConnectionMode::Tunnel;
        t.engine.set_policy(p.clone()).await.unwrap();
        let st = t.engine.status();
        assert!(st.kill_switch.enabled && !st.local_proxy.active && !st.local_proxy.socks_listening);
        assert!(t.fake().with(|s| s.dns.is_some()));
        assert!(t.engine.inner.lock().await.plan.as_ref().unwrap().proxy_guard.is_none());
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", p.proxy_socks_port))
            .await
            .is_err());
        // Disconnected in proxy mode with the preference on: not Protected.
        t.engine.disconnect().await.unwrap();
        assert_eq!(t.state().await, ConnectionState::Protected);
        p.mode = ConnectionMode::Proxy;
        t.engine.set_policy(p).await.unwrap();
        assert_eq!(t.state().await, ConnectionState::Disconnected);
    }

    #[tokio::test]
    async fn lan_credentials_are_hashed_and_kept() {
        let t = engine(false).await;
        let (port, socks_port) = two_free_ports();
        let auth = |pw: Option<&str>, user: &str| {
            Some(alizy_core::ipc::ProxyAuth {
                username: user.into(),
                password: pw.map(|p| Zeroizing::new(p.into())),
                verifier: Some("ff$00".into()), // a client-sent verifier is ignored
            })
        };
        let cfg = |a| LanProxyConfig {
            enabled: true,
            port,
            socks_port,
            auth: a,
        };
        let st = t.engine.set_lan_proxy(cfg(auth(Some("pw1"), "tv"))).await.unwrap();
        assert_eq!(st.auth_username.as_deref(), Some("tv"));
        assert!(st.socks_udp);
        let stored = t.engine.inner.lock().await.persisted.lan_proxy.auth.clone().unwrap();
        assert!(stored.password.is_none());
        assert!(stored.check(b"tv", b"pw1") && !stored.verifier.as_deref().unwrap().starts_with("ff$"));
        // Same user, no password: the old one stays.
        t.engine.set_lan_proxy(cfg(auth(None, "tv"))).await.unwrap();
        let again = t.engine.inner.lock().await.persisted.lan_proxy.auth.clone().unwrap();
        assert!(again.check(b"tv", b"pw1"));
        // New user without a password: refused.
        let e = t.engine.set_lan_proxy(cfg(auth(None, "phone"))).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::BadRequest);
        // Removing auth opens it again.
        let st = t.engine.set_lan_proxy(cfg(None)).await.unwrap();
        assert!(st.auth_username.is_none());
    }
}
