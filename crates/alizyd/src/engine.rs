//! Connection manager + kill switch + split-tunnel orchestration.
//!
//! All state changes go through `alizy_core::state::transition`. Every
//! firewall change is one atomic nft transaction followed by a read-back
//! verification. The engine never removes blocking rules to perform an update.

use crate::events::Events;
use crate::linux::{firewall, wireguard, LinuxAdapter};
use crate::persist::{Persist, PersistedState};
use crate::resolver::{now, Resolver};
use alizy_core::config::{Host, PublicConfig};
use alizy_core::firewall::{FirewallPlan, NetworkPolicy, TunnelRules, SPLIT_MARK};
use alizy_core::ipc::{
    DaemonStatus, ErrorCode, EventCategory as Cat, EventLevel as Lvl, IpcError, KillSwitchStatus, RouteTest,
    RouteTestEntry, SplitStatus, TunnelSpec, TunnelStats,
};
use alizy_core::platform::PlatformAdapter;
use alizy_core::routing::{compatibility_warnings, dns_plan, route_plan, split_rule_commands};
use alizy_core::split::{self, Action, SplitConfig, MAX_RULES};
use alizy_core::state::{transition, ConnectionState, Event};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{watch, Mutex};

struct Active {
    public: PublicConfig,
    endpoints: Vec<Option<SocketAddr>>,
    since: u64,
    stats: Option<TunnelStats>,
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
}

pub struct Engine {
    started_at: u64,
    /// Rate limiting / single-flight for read-only commands that do work.
    verify_cache: Mutex<Option<(std::time::Instant, bool, Option<String>)>>,
    report_cache: Mutex<Option<(std::time::Instant, alizy_core::sysprobe::SystemReport)>>,
    route_tests: tokio::sync::Semaphore,
    adapter: LinuxAdapter,
    inner: Mutex<Inner>,
    pub events: Events,
    persist: Persist,
    resolver: Resolver,
    iface: String,
    status_tx: watch::Sender<DaemonStatus>,
}

fn err(code: ErrorCode, m: impl Into<String>) -> IpcError {
    IpcError::new(code, m)
}

impl Engine {
    pub async fn start(adapter: LinuxAdapter, persist: Persist, resolver: Resolver, iface: String) -> Arc<Self> {
        let persisted = persist.load();
        let ks = persisted.policy.kill_switch;
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
        };
        let (status_tx, _) = watch::channel(initial);
        let engine = Arc::new(Self {
            started_at: now(),
            verify_cache: Mutex::new(None),
            report_cache: Mutex::new(None),
            route_tests: tokio::sync::Semaphore::new(2),
            adapter,
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
            }),
            events: Events::default(),
            persist,
            resolver,
            iface,
            status_tx,
        });
        engine.recover().await;
        engine
    }

    /// Boot / crash recovery: remove leftovers, restore DNS, re-establish protection.
    async fn recover(&self) {
        let mut inner = self.inner.lock().await;
        if wireguard::exists(&self.iface) {
            self.events.push(
                Lvl::Warn,
                Cat::Service,
                format!(
                    "Found leftover interface {} from a previous run; removing it.",
                    self.iface
                ),
            );
        }
        if let Err(e) = self.adapter.tunnel_down(&self.iface).await {
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
        let ks = inner.persisted.policy.kill_switch;
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

    fn publish(&self, inner: &Inner) {
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
                enabled: inner.persisted.policy.kill_switch,
                firewall_verified: inner.verified
                    && inner
                        .plan
                        .as_ref()
                        .map(|p| p.kill_switch == inner.persisted.policy.kill_switch)
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
            tunnel_kind: None,
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
        let policy = &inner.persisted.policy;
        let tunnel = inner.active.as_ref().map(|a| TunnelRules {
            iface: self.iface.clone(),
            endpoints: a.endpoints.iter().flatten().copied().collect(),
        });
        let direct = if inner.persisted.split.enabled {
            let resolved = inner
                .persisted
                .dns_cache
                .resolved_addrs(&inner.persisted.split.rules, now());
            split::compile(&inner.persisted.split.rules, &resolved)
        } else {
            Default::default()
        };
        FirewallPlan::with_split(policy, tunnel, direct)
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
        for c in split_rule_commands(false) {
            let _ = crate::exec::run(&c, None).await;
        }
        if want {
            let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/src_valid_mark", b"1");
            for c in split_rule_commands(true) {
                if let Err(e) = crate::exec::run(&c, None).await {
                    // Without the rule, marked traffic stays in the tunnel: safe direction.
                    self.events.push(
                        Lvl::Warn,
                        Cat::Network,
                        format!("Split-tunnel routing rule failed ({e}); bypass traffic will use the VPN."),
                    );
                }
            }
        }
        inner.split_rule_installed = want;
    }

    /// Resolve all peer endpoints concurrently. Each hostname gets its own
    /// short deadline and falls back to the last address that worked (daemon
    /// cache, then the client's cache), because DNS is legitimately blocked
    /// while protected. Successful lookups refresh the daemon cache.
    async fn resolve_endpoints(&self, inner: &mut Inner, spec: &TunnelSpec) -> Result<Vec<Option<SocketAddr>>, String> {
        let cache = inner.persisted.endpoint_cache.clone();
        let lookups = spec.config.peers.iter().enumerate().map(|(i, p)| {
            let ep = p.endpoint.clone();
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

    /// Bring a tunnel up. Firewall first, interface second. On failure the
    /// tunnel is removed and the no-tunnel policy re-applied; state is left to the caller.
    async fn bring_up(&self, inner: &mut Inner, spec: &TunnelSpec) -> Result<(), String> {
        let result = self.bring_up_inner(inner, spec).await;
        if let Err(e) = &result {
            if let Err(td) = self.adapter.tunnel_down(&self.iface).await {
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
            inner.last_error = Some(e.clone());
            self.events.push(
                Lvl::Error,
                Cat::Connection,
                format!("Connection to {} failed: {e}", spec.profile_name),
            );
        }
        result
    }

    async fn bring_up_inner(&self, inner: &mut Inner, spec: &TunnelSpec) -> Result<(), String> {
        let (public, _) = spec.config.split();
        for w in compatibility_warnings(&public, &inner.persisted.policy) {
            self.events.push(Lvl::Warn, Cat::Connection, w);
        }
        let endpoints = self.resolve_endpoints(inner, spec).await?;
        inner.active = Some(Active {
            public: public.clone(),
            endpoints: endpoints.clone(),
            since: now(),
            stats: None,
        });
        // 1. Firewall for the new tunnel (old drop rules stay until the new table replaces them atomically).
        self.enforce(inner).await.map_err(|e| format!("firewall: {e}"))?;
        // 2. Interface, routes, DNS.
        let policy = inner.persisted.policy.clone();
        let routes = route_plan(&public, &self.iface, &policy);
        let dns = dns_plan(&public, &policy);
        self.adapter
            .tunnel_up(&self.iface, &spec.config, &endpoints, &routes, &dns)
            .await?;
        self.sync_split_rule(inner).await;
        inner.last_error = None;
        inner.reconnect_attempt = 0;
        self.events.push(
            Lvl::Info,
            Cat::Connection,
            format!(
                "Connected to {} via {}.",
                spec.profile_name,
                endpoints
                    .iter()
                    .flatten()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        Ok(())
    }

    pub async fn connect(&self, mut spec: TunnelSpec) -> Result<(), IpcError> {
        // The GUI is not trusted to have validated anything: re-parse from scratch.
        let reparsed = alizy_core::parse(&spec.config.to_wg_quick(true))
            .map_err(|e| err(ErrorCode::InvalidConfig, e.to_string()))?;
        spec.config = reparsed.config;
        for s in [&spec.profile_id, &spec.profile_name] {
            if s.is_empty() || s.len() > 128 || s.chars().any(char::is_control) {
                return Err(err(ErrorCode::BadRequest, "invalid profile identifier"));
            }
        }
        let mut inner = self.inner.lock().await;
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
        let result = self.bring_up(&mut inner, &spec).await;
        inner.spec = Some(spec);
        let r = match result {
            Ok(()) => self.go(&mut inner, Event::TunnelUp),
            Err(e) => {
                let ks = inner.persisted.policy.kill_switch;
                inner.spec = None;
                let _ = self.go(&mut inner, Event::Failed { kill_switch: ks });
                Err(err(ErrorCode::Tunnel, e))
            }
        };
        self.publish(&inner);
        r
    }

    pub async fn disconnect(&self) -> Result<(), IpcError> {
        let mut inner = self.inner.lock().await;
        if matches!(inner.state, ConnectionState::Disconnected) {
            return Ok(());
        }
        self.go(&mut inner, Event::DisconnectRequested)?;
        self.publish(&inner);
        let down = self.adapter.tunnel_down(&self.iface).await;
        inner.active = None;
        inner.spec = None;
        inner.last_error = None;
        let fw = self.enforce(&mut inner).await;
        let ks = inner.persisted.policy.kill_switch;
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
        let needs_rebuild = inner.active.is_some()
            && (old.ipv4_enabled != policy.ipv4_enabled
                || old.ipv6_enabled != policy.ipv6_enabled
                || old.custom_dns != policy.custom_dns);
        let r = if needs_rebuild {
            // Rebuild the tunnel for the new routing/DNS; the firewall is replaced atomically first.
            let spec = inner.spec.clone().expect("active tunnel has a spec");
            match self.bring_up(&mut inner, &spec).await {
                Ok(()) => {
                    if inner.state != ConnectionState::Connected {
                        let _ = self.go(&mut inner, Event::TunnelUp);
                    }
                    Ok(())
                }
                Err(e) => {
                    let _ = self.go(
                        &mut inner,
                        Event::Failed {
                            kill_switch: policy.kill_switch,
                        },
                    );
                    Err(e)
                }
            }
        } else {
            self.enforce(&mut inner).await
        };
        if old.kill_switch != policy.kill_switch {
            let _ = self.go(
                &mut inner,
                Event::KillSwitchChanged {
                    enabled: policy.kill_switch,
                },
            );
            self.events.push(
                Lvl::Info,
                Cat::Firewall,
                if policy.kill_switch {
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
        r.map_err(|e| err(ErrorCode::Firewall, e))
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
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            tokio::task::spawn_blocking(alizy_core::sysprobe::probe),
        )
        .await
        .map_err(|_| err(ErrorCode::Internal, "system probe timed out"))?
        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
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
        if inner.state == ConnectionState::Reconnecting && t >= inner.next_reconnect {
            self.try_reconnect(&mut inner, t).await;
        }

        if let Some(active) = &inner.active {
            let dns = dns_plan(&active.public, &inner.persisted.policy);
            match self.adapter.reassert_dns(&dns) {
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
        if !wireguard::exists(&self.iface) {
            return self.degraded(inner, "the WireGuard interface disappeared").await;
        }
        let new = match self.adapter.tunnel_stats(&self.iface).await {
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
        let ks = inner.persisted.policy.kill_switch;
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
            let _ = self.adapter.tunnel_down(&self.iface).await;
            inner.active = None;
            inner.spec = None;
            inner.last_error = Some(format!("Connection lost: {why}"));
            let _ = self.enforce(inner).await;
            let _ = self.go(inner, Event::Failed { kill_switch: ks });
        }
    }

    async fn try_reconnect(&self, inner: &mut Inner, t: u64) {
        let Some(spec) = inner.spec.clone() else {
            let ks = inner.persisted.policy.kill_switch;
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
        match self.bring_up(inner, &spec).await {
            Ok(()) => {
                let _ = self.go(inner, Event::TunnelUp);
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
        // Re-resolve split domains soon: answers may differ on the new network.
        for e in inner.persisted.dns_cache.entries.values_mut() {
            e.next_refresh = e.next_refresh.min(now() + 2);
        }
        if inner.state != ConnectionState::Connected {
            return;
        }
        let Some(spec) = inner.spec.clone() else { return };
        let has_names = spec
            .config
            .peers
            .iter()
            .any(|p| matches!(p.endpoint.as_ref().map(|e| &e.host), Some(Host::Name(_))));
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
                // Allow the new endpoint in the firewall first, then point WireGuard at it.
                if let Err(e) = self.enforce(&mut inner).await {
                    return self.degraded(&mut inner, &format!("firewall update failed: {e}")).await;
                }
                for (p, ep) in spec.config.peers.iter().zip(eps) {
                    if let Some(ep) = ep {
                        if let Err(e) = wireguard::set_endpoint(&self.iface, &p.public_key.to_base64(), ep).await {
                            self.events
                                .push(Lvl::Error, Cat::Connection, format!("Updating endpoint failed: {e}"));
                        }
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
        let ks = inner.persisted.policy.kill_switch;
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
        let mut inner = self.inner.lock().await;
        if inner.active.is_some() {
            let _ = self.adapter.tunnel_down(&self.iface).await;
            inner.active = None;
        }
        inner.spec = None;
        let _ = self.enforce(&mut inner).await;
        self.save(&inner);
        self.events.push(
            Lvl::Info,
            Cat::Service,
            if inner.persisted.policy.kill_switch {
                "Service stopping; kill switch remains active in the kernel."
            } else {
                "Service stopping."
            },
        );
    }
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
