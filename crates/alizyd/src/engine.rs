//! Connection manager + kill switch + split-tunnel orchestration.
//!
//! All state changes go through `alizy_core::state::transition`. Every
//! firewall change is one atomic nft transaction followed by a read-back
//! verification. The engine never removes blocking rules to perform an update.

use crate::cancel::{CancelSource, CancelToken};
use crate::events::Events;
use crate::linux::ssh::{self as sshb, SshError, SshUp};
use crate::linux::{firewall, LinuxAdapter};
use crate::persist::{Persist, PersistedState};
use crate::resolver::{now, Resolver};
use alizy_core::config::{Host, PublicConfig};
use alizy_core::firewall::{FirewallPlan, NetworkPolicy, TunnelRules, SPLIT_MARK};
use alizy_core::ipc::{
    DaemonStatus, ErrorCode, EventCategory as Cat, EventLevel as Lvl, IpcError, KillSwitchStatus, RouteTest,
    RouteTestEntry, SplitStatus, TunnelSpec, TunnelStats,
};
use alizy_core::platform::PlatformAdapter;
use alizy_core::routing::{
    compatibility_warnings, dns_plan, route_plan, ssh_dns_plan, ssh_public_config, ssh_upstream_plan, DnsPlan,
};
use alizy_core::split::{self, Action, SplitConfig, MAX_RULES};
use alizy_core::ssh::{HostKey, SshConfig};
use alizy_core::state::{transition, ConnectionState, Event};
use alizy_core::sysprobe::{Dependency, DnsBackend};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};

/// Everything the engine needs from the OS beyond [`PlatformAdapter`]. The
/// engine is generic over it (production: [`LinuxAdapter`]) so the connection
/// state machine can be exercised without root.
#[allow(async_fn_in_trait)]
pub trait Backend: PlatformAdapter {
    fn dns_backend(&self) -> Option<DnsBackend>;
    async fn refresh_dns_backend(&self);
    fn reassert_dns(&self, plan: &DnsPlan) -> Result<bool, String>;
    fn restore_dns_backup(&self) -> Result<(), String>;
    /// Whether the tunnel interface exists in the daemon's network namespace.
    fn iface_exists(&self, iface: &str) -> bool;
    /// Point one WireGuard peer at a new endpoint.
    async fn set_endpoint(&self, iface: &str, peer: &str, ep: SocketAddr) -> Result<(), String>;
    /// Install (`want`) or remove the split-tunnel routing rule; returns the errors.
    async fn set_split_rule(&self, want: bool) -> Vec<String>;
    /// Bring an SSH tunnel up (tearing down any previous tunnel first).
    async fn ssh_up(&self, req: SshUp<'_>) -> Result<(), SshError>;
    /// `Some(reason)` once a running SSH tunnel's ssh or tun2socks has exited.
    async fn ssh_try_exited(&self) -> Option<String>;
    /// Fetch a server's host key, running as `user` (never root). Gives up
    /// promptly once `cancel` fires.
    async fn keyscan(&self, user: (u32, u32), host: IpAddr, port: u16, cancel: &CancelToken)
        -> Result<HostKey, String>;
    /// Missing SSH dependencies; empty when ready. Any version probe runs as
    /// `user`, never root, with a timeout.
    async fn ssh_missing(&self, user: (u32, u32)) -> Vec<Dependency>;
}

/// Where and as whom SSH tunnels run.
pub struct SshEnv {
    /// (uid, primary gid) of `alizy-ssh`; `None` disables SSH tunnels.
    pub user: Option<(u32, u32)>,
    /// Runtime directory for known_hosts files and askpass sockets.
    pub runtime: PathBuf,
}

const MISSING_SSH_USER: &str = "alizy-ssh system user missing; SSH tunnels are unavailable (reinstall Alizy)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelKind {
    WireGuard,
    Ssh,
}

struct Active {
    public: PublicConfig,
    endpoints: Vec<Option<SocketAddr>>,
    since: u64,
    stats: Option<TunnelStats>,
    kind: TunnelKind,
    /// `ssh -D` port (SSH only).
    socks_port: Option<u16>,
}

/// Why a bring-up failed, with the IPC error code to report.
#[derive(Debug)]
struct UpError {
    code: ErrorCode,
    msg: String,
    host_key: Option<HostKey>,
}

impl From<String> for UpError {
    fn from(msg: String) -> Self {
        Self {
            code: ErrorCode::Tunnel,
            msg,
            host_key: None,
        }
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

impl UpError {
    fn into_ipc(self) -> IpcError {
        let mut e = IpcError::new(self.code, self.msg);
        e.host_key = self.host_key;
        e
    }
}

/// Firewall exceptions for the active tunnel. WireGuard: its UDP endpoints
/// only (exactly as before SSH support). SSH: the server's TCP endpoint,
/// alizy-ssh's uid, the SOCKS port and the UDP block.
fn tunnel_rules(iface: &str, a: &Active, ssh_uid: Option<u32>) -> TunnelRules {
    match a.kind {
        TunnelKind::WireGuard => TunnelRules {
            iface: iface.to_string(),
            endpoints: a.endpoints.iter().flatten().copied().collect(),
            ..Default::default()
        },
        TunnelKind::Ssh => TunnelRules {
            iface: iface.to_string(),
            tcp_endpoints: a.endpoints.iter().flatten().copied().collect(),
            ssh_uid,
            socks_port: a.socks_port,
            block_udp: true,
            ..Default::default()
        },
    }
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

pub struct Engine<A = LinuxAdapter> {
    started_at: u64,
    /// Rate limiting / single-flight for read-only commands that do work.
    verify_cache: Mutex<Option<(std::time::Instant, bool, Option<String>)>>,
    report_cache: Mutex<Option<(std::time::Instant, alizy_core::sysprobe::SystemReport)>>,
    route_tests: tokio::sync::Semaphore,
    adapter: A,
    ssh: SshEnv,
    /// Cancels an in-progress bring-up. Deliberately outside `inner`:
    /// `disconnect`/`connect` bump it *before* waiting for the lock.
    cancel: CancelSource,
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

impl<A: Backend> Engine<A> {
    pub async fn start(adapter: A, persist: Persist, resolver: Resolver, iface: String, ssh: SshEnv) -> Arc<Self> {
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
            ssh,
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
            // Absent for WireGuard so its status JSON is unchanged.
            tunnel_kind: a.filter(|a| a.kind == TunnelKind::Ssh).map(|_| "ssh".to_string()),
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
        let tunnel = inner
            .active
            .as_ref()
            .map(|a| tunnel_rules(&self.iface, a, self.ssh.user.map(|u| u.0)));
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
    ///
    /// An SSH bring-up that fails after `cancel` fired reports
    /// [`ErrorCode::Cancelled`]: the user disconnected or connected elsewhere,
    /// so it is neither an error nor a reason to reconnect.
    async fn bring_up(&self, inner: &mut Inner, spec: &TunnelSpec, cancel: &CancelToken) -> Result<(), UpError> {
        let result = match self.bring_up_inner(inner, spec, cancel).await {
            Err(_) if spec.ssh.is_some() && cancel.is_cancelled() => Err(UpError::from(SshError::Cancelled)),
            r => r,
        };
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

    async fn bring_up_inner(&self, inner: &mut Inner, spec: &TunnelSpec, cancel: &CancelToken) -> Result<(), UpError> {
        let prev = inner.active.as_ref().map(|a| a.kind);
        if let Some(ssh) = &spec.ssh {
            return self.bring_up_ssh(inner, spec, ssh, prev, cancel).await;
        }
        if prev == Some(TunnelKind::Ssh) {
            // Switching SSH -> WireGuard: stop ssh, tun2socks and the forwarder and
            // remove the TUN first. The old firewall stays in place meanwhile.
            self.adapter.tunnel_down(&self.iface).await?;
        }
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
            kind: TunnelKind::WireGuard,
            socks_port: None,
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

    /// SSH bring-up. The firewall for the new tunnel is enforced first, so
    /// even with the kill switch on, `ssh-keyscan`/`ssh` (as alizy-ssh) reach
    /// the server through the ssh_mark chain and the TCP endpoint exception.
    ///
    /// Lock hold: this runs under the engine lock (like WireGuard bring-up).
    /// Bounded worst case, excluding pathological `ip`/`nft` hangs (each capped
    /// at 15 s by `exec`), is about 40 s:
    ///
    /// - previous-tunnel teardown: about 6 s (two 3 s kill waits);
    /// - firewall apply and verify;
    /// - either keyscan (unknown key, at most 10 s) or SOCKS readiness (at
    ///   most 20 s plus one 2 s probe), plus a re-keyscan of at most 10 s
    ///   when ssh reports a host-key failure;
    /// - the 0.3 s tun2socks start check.
    ///
    /// Status reads use the watch channel and are not blocked; other commands
    /// wait. `disconnect` and `connect` don't wait for the whole bring-up:
    /// they fire `cancel` before taking the lock, and the keyscan and
    /// readiness waits check it every poll (100–250 ms), so they get the lock
    /// within about a second. The supervision tick (and with it the periodic
    /// firewall re-verification) still pauses for the length of an SSH
    /// bring-up attempt; the firewall itself is applied and verified before
    /// the slow steps start, and stays in place throughout.
    async fn bring_up_ssh(
        &self,
        inner: &mut Inner,
        spec: &TunnelSpec,
        ssh: &SshConfig,
        prev: Option<TunnelKind>,
        cancel: &CancelToken,
    ) -> Result<(), UpError> {
        let user = self.ssh.user.ok_or_else(|| UpError {
            code: ErrorCode::MissingDependency,
            msg: MISSING_SSH_USER.into(),
            host_key: None,
        })?;
        if cancel.is_cancelled() {
            // Superseded while waiting for the lock: start nothing.
            return Err(SshError::Cancelled.into());
        }
        let policy = inner.persisted.policy.clone();
        let public = ssh_public_config(&ssh.public, &policy);
        for w in compatibility_warnings(&public, &policy) {
            self.events.push(Lvl::Warn, Cat::Connection, w);
        }
        if prev == Some(TunnelKind::WireGuard) {
            // Switching WireGuard -> SSH: remove the WireGuard interface first.
            self.adapter.tunnel_down(&self.iface).await?;
        }
        // The literal IP from the profile: the same address ssh is given.
        let endpoint = SocketAddr::new(ssh.public.host, ssh.public.port);
        let socks_port =
            sshb::pick_loopback_port().map_err(|e| format!("no free loopback port for the SSH proxy: {e}"))?;
        inner.active = Some(Active {
            public: public.clone(),
            endpoints: vec![Some(endpoint)],
            since: now(),
            stats: None,
            kind: TunnelKind::Ssh,
            socks_port: Some(socks_port),
        });
        // 1. Firewall for the new tunnel.
        self.enforce(inner).await.map_err(|e| format!("firewall: {e}"))?;
        // 2. Unknown server: fetch its key for the user to confirm, then stop.
        if ssh.public.host_key.is_none() {
            let key = self
                .adapter
                .keyscan(user, endpoint.ip(), endpoint.port(), cancel)
                .await
                .map_err(|e| format!("could not fetch the SSH server's host key: {e}"))?;
            return Err(UpError {
                code: ErrorCode::HostKeyUnknown,
                msg: format!(
                    "the SSH server's host key is not known yet; confirm its fingerprint {} to connect",
                    key.fingerprint_sha256()
                ),
                host_key: Some(key),
            });
        }
        // 3. ssh + tun2socks + DNS forwarder, routes, system DNS.
        let routes = route_plan(&public, &self.iface, &policy);
        let dns = ssh_dns_plan(&policy);
        let upstreams = ssh_upstream_plan(&ssh.public, &policy);
        if !upstreams.dropped.is_empty() {
            let list = |v: &[IpAddr]| v.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
            self.events.push(
                Lvl::Warn,
                Cat::Dns,
                format!(
                    "Custom DNS servers on your local network can't be reached through an SSH tunnel; using {} (ignored: {}).",
                    list(&upstreams.servers),
                    list(&upstreams.dropped)
                ),
            );
        }
        self.adapter
            .ssh_up(SshUp {
                iface: &self.iface,
                cfg: ssh,
                user,
                runtime: &self.ssh.runtime,
                socks_port,
                upstreams: upstreams.servers,
                ipv6: policy.ipv6_enabled,
                routes: &routes,
                dns: &dns,
                cancel: cancel.clone(),
            })
            .await?;
        self.sync_split_rule(inner).await;
        inner.last_error = None;
        inner.reconnect_attempt = 0;
        self.events.push(
            Lvl::Info,
            Cat::Connection,
            format!("Connected to {} via {endpoint} (SSH).", spec.profile_name),
        );
        Ok(())
    }

    pub async fn connect(&self, mut spec: TunnelSpec) -> Result<(), IpcError> {
        if let Some(ssh) = &spec.ssh {
            // `config` is a placeholder for SSH profiles and is never used.
            alizy_core::ssh::validate(ssh).map_err(|e| err(ErrorCode::InvalidConfig, e))?;
        } else {
            // The GUI is not trusted to have validated anything: re-parse from scratch.
            let reparsed = alizy_core::parse(&spec.config.to_wg_quick(true))
                .map_err(|e| err(ErrorCode::InvalidConfig, e.to_string()))?;
            spec.config = reparsed.config;
            if spec.config.peers.is_empty() {
                return Err(err(ErrorCode::InvalidConfig, "WireGuard configuration has no peers"));
            }
        }
        for s in [&spec.profile_id, &spec.profile_name] {
            if s.is_empty() || s.len() > 128 || s.chars().any(char::is_control) {
                return Err(err(ErrorCode::BadRequest, "invalid profile identifier"));
            }
        }
        if spec.ssh.is_some() {
            let Some(user) = self.ssh.user else {
                return Err(err(ErrorCode::MissingDependency, MISSING_SSH_USER));
            };
            let missing = self.adapter.ssh_missing(user).await;
            if !missing.is_empty() {
                let names: Vec<&str> = missing.iter().map(|d| d.label()).collect();
                return Err(err(
                    ErrorCode::MissingDependency,
                    format!("SSH tunnels need: {}", names.join(", ")),
                ));
            }
        }
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
                let ks = inner.persisted.policy.kill_switch;
                inner.spec = None;
                let _ = self.go(&mut inner, Event::DisconnectRequested);
                let _ = self.go(&mut inner, Event::TornDown { kill_switch: ks });
                Err(e.into_ipc())
            }
            Err(e) => {
                let ks = inner.persisted.policy.kill_switch;
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
                            kill_switch: policy.kill_switch,
                        },
                    );
                    Ok(())
                }
                Err(e) => {
                    let _ = self.go(
                        &mut inner,
                        Event::Failed {
                            kill_switch: policy.kill_switch,
                        },
                    );
                    Err(e.msg)
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
        let mut r = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            tokio::task::spawn_blocking(alizy_core::sysprobe::probe),
        )
        .await
        .map_err(|_| err(ErrorCode::Internal, "system probe timed out"))?
        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        // `probe` only checks that the SSH executables exist (it never runs
        // ssh as root). The authoritative check, including the OpenSSH
        // version, runs `ssh -V` as alizy-ssh with a timeout.
        if let Some(user) = self.ssh.user {
            r.set_ssh_missing(self.adapter.ssh_missing(user).await);
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

        if let Some(active) = &inner.active {
            let dns = match active.kind {
                TunnelKind::WireGuard => dns_plan(&active.public, &inner.persisted.policy),
                TunnelKind::Ssh => ssh_dns_plan(&inner.persisted.policy),
            };
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
        if inner.active.as_ref().map(|a| a.kind) == Some(TunnelKind::Ssh) {
            if let Some(why) = self.adapter.ssh_try_exited().await {
                return self.degraded(inner, &format!("SSH connection lost: {why}")).await;
            }
            if !self.adapter.iface_exists(&self.iface) {
                return self.degraded(inner, "the SSH tunnel interface disappeared").await;
            }
        } else if !self.adapter.iface_exists(&self.iface) {
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
        let cancel = self.cancel.token();
        match self.bring_up(inner, &spec, &cancel).await {
            Ok(()) => {
                let _ = self.go(inner, Event::TunnelUp);
            }
            Err(e) if e.code == ErrorCode::Cancelled => {
                // The user disconnected or connected elsewhere: stop
                // reconnecting and end like a disconnect.
                let ks = inner.persisted.policy.kill_switch;
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
                let ks = inner.persisted.policy.kill_switch;
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
        // Re-resolve split domains soon: answers may differ on the new network.
        for e in inner.persisted.dns_cache.entries.values_mut() {
            e.next_refresh = e.next_refresh.min(now() + 2);
        }
        if inner.state != ConnectionState::Connected {
            return;
        }
        let Some(spec) = inner.spec.clone() else { return };
        if spec.ssh.is_some() {
            // SSH profiles name their server by IP: nothing to re-resolve.
            return;
        }
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
                        if let Err(e) = self
                            .adapter
                            .set_endpoint(&self.iface, &p.public_key.to_base64(), ep)
                            .await
                        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::ssh::{SshError, SshUp};
    use alizy_core::config::WgConfig;
    use alizy_core::routing::{DnsPlan, RoutePlan};
    use alizy_core::ssh::{HostKey, SshConfig, SshPublic};
    use alizy_core::sysprobe::DnsBackend;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAICJ9AyQ1/Hf8ky/h28JhISjg1GkKGhTejR6j6uTwPF1l";
    const SSH_UID: u32 = 60123;

    #[derive(Default)]
    struct FakeState {
        log: Vec<String>,
        /// Which backend is currently up: "wg", "ssh" or none.
        up: Option<&'static str>,
        applied: Vec<FirewallPlan>,
        ssh_exit: Option<String>,
        ssh_fail: Option<SshError>,
        violations: Vec<String>,
        /// `ssh_up` blocks (like a server that never authenticates) until cancelled.
        slow: bool,
        /// What `ssh_missing` reports.
        missing: Vec<Dependency>,
        /// Upstreams passed to the last `ssh_up`.
        upstreams: Vec<IpAddr>,
    }

    #[derive(Default)]
    struct Fake(std::sync::Mutex<FakeState>);

    impl Fake {
        fn with<R>(&self, f: impl FnOnce(&mut FakeState) -> R) -> R {
            f(&mut self.0.lock().unwrap())
        }
    }

    impl PlatformAdapter for Fake {
        async fn apply_firewall(&self, plan: &FirewallPlan) -> Result<(), String> {
            self.with(|s| {
                s.log.push("fw".into());
                s.applied.push(plan.clone());
            });
            Ok(())
        }
        async fn verify_firewall(&self, plan: &FirewallPlan) -> Result<bool, String> {
            Ok(self.with(|s| s.applied.last().map(|p| p.tag()) == Some(plan.tag())))
        }
        async fn tunnel_up(
            &self,
            _iface: &str,
            _cfg: &WgConfig,
            _endpoints: &[Option<SocketAddr>],
            _routes: &RoutePlan,
            _dns: &DnsPlan,
        ) -> Result<(), String> {
            self.with(|s| {
                if s.up == Some("ssh") {
                    s.violations
                        .push("WireGuard brought up while SSH backend still up".into());
                }
                s.up = Some("wg");
                s.log.push("wg_up".into());
            });
            Ok(())
        }
        async fn tunnel_down(&self, _iface: &str) -> Result<(), String> {
            self.with(|s| {
                s.up = None;
                s.ssh_exit = None;
                s.log.push("down".into());
            });
            Ok(())
        }
        async fn tunnel_stats(&self, _iface: &str) -> Result<Option<TunnelStats>, String> {
            Ok(None)
        }
    }

    impl Backend for Fake {
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
            self.with(|s| s.up.is_some())
        }
        async fn set_endpoint(&self, _iface: &str, _peer: &str, _ep: SocketAddr) -> Result<(), String> {
            Ok(())
        }
        async fn set_split_rule(&self, _want: bool) -> Vec<String> {
            Vec::new()
        }
        async fn ssh_up(&self, req: SshUp<'_>) -> Result<(), SshError> {
            assert_eq!(req.user, (SSH_UID, SSH_UID));
            assert!(req.socks_port != 0);
            assert_eq!(req.dns.servers, vec!["127.77.0.1".parse::<IpAddr>().unwrap()]);
            if self.with(|s| s.slow) {
                self.with(|s| s.log.push("ssh_up".into()));
                // Same shape as wait_ready: poll until ready, ssh exit or cancel.
                tokio::time::timeout(std::time::Duration::from_secs(30), req.cancel.cancelled())
                    .await
                    .expect("bring-up was never cancelled");
                return Err(SshError::Cancelled);
            }
            self.with(|s| {
                s.upstreams = req.upstreams.clone();
                s.log.push("ssh_up".into());
                if let Some(e) = s.ssh_fail.take() {
                    return Err(e);
                }
                if s.up == Some("wg") {
                    s.violations
                        .push("SSH brought up while WireGuard backend still up".into());
                }
                s.up = Some("ssh");
                Ok(())
            })
        }
        async fn ssh_try_exited(&self) -> Option<String> {
            self.with(|s| s.ssh_exit.take())
        }
        async fn keyscan(
            &self,
            user: (u32, u32),
            _host: IpAddr,
            _port: u16,
            cancel: &CancelToken,
        ) -> Result<HostKey, String> {
            assert_eq!(user, (SSH_UID, SSH_UID));
            self.with(|s| s.log.push("keyscan".into()));
            if self.with(|s| s.slow) {
                cancel.cancelled().await;
                return Err(SshError::Cancelled.to_string());
            }
            Ok(host_key())
        }
        async fn ssh_missing(&self, _user: (u32, u32)) -> Vec<Dependency> {
            self.with(|s| s.missing.clone())
        }
    }

    fn host_key() -> HostKey {
        HostKey {
            key_type: "ssh-ed25519".into(),
            key_b64: KEY.into(),
        }
    }

    struct T {
        engine: Arc<Engine<Fake>>,
        _dir: tempfile::TempDir,
    }

    impl T {
        fn fake(&self) -> &Fake {
            &self.engine.adapter
        }
        fn log(&self) -> Vec<String> {
            self.fake().with(|s| s.log.clone())
        }
        async fn state(&self) -> ConnectionState {
            self.engine.inner.lock().await.state
        }
    }

    async fn engine_with(user: Option<(u32, u32)>, kill_switch: bool) -> T {
        let dir = tempfile::tempdir().unwrap();
        let persist = Persist::new(&dir.path().join("state")).unwrap();
        let ssh = SshEnv {
            user,
            runtime: PathBuf::from(dir.path()),
        };
        let engine = Engine::start(Fake::default(), persist, Resolver::new(None), "alizy0".into(), ssh).await;
        if kill_switch {
            engine
                .set_policy(NetworkPolicy {
                    kill_switch: true,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        T { engine, _dir: dir }
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
            config: alizy_core::parse(text).unwrap().config,
            cached_endpoints: vec![],
            ssh: None,
        }
    }

    fn ssh_spec(host_key: Option<HostKey>) -> TunnelSpec {
        TunnelSpec {
            profile_id: "ssh1".into(),
            profile_name: "SSH".into(),
            config: WgConfig::placeholder(),
            cached_endpoints: vec![],
            ssh: Some(SshConfig {
                public: SshPublic {
                    host: "203.0.113.5".parse().unwrap(),
                    port: 22,
                    username: "alice".into(),
                    host_key,
                    dns: vec![],
                },
                password: Zeroizing::new("pw".into()),
            }),
        }
    }

    fn active(kind: TunnelKind, endpoints: Vec<Option<SocketAddr>>, socks_port: Option<u16>) -> Active {
        Active {
            public: alizy_core::routing::ssh_public_config(
                &ssh_spec(None).ssh.unwrap().public,
                &NetworkPolicy::default(),
            ),
            endpoints,
            since: 0,
            stats: None,
            kind,
            socks_port,
        }
    }

    #[test]
    fn desired_plan_for_ssh_sets_tcp_and_udp_block() {
        let ep: SocketAddr = "203.0.113.5:22".parse().unwrap();
        let a = active(TunnelKind::Ssh, vec![Some(ep)], Some(40000));
        let r = tunnel_rules("alizy0", &a, Some(SSH_UID));
        assert_eq!(
            r,
            TunnelRules {
                iface: "alizy0".into(),
                endpoints: vec![],
                tcp_endpoints: vec![ep],
                ssh_uid: Some(SSH_UID),
                socks_port: Some(40000),
                block_udp: true,
            }
        );
    }

    #[test]
    fn desired_plan_for_wg_unchanged() {
        let ep: SocketAddr = "198.51.100.7:51820".parse().unwrap();
        let a = active(TunnelKind::WireGuard, vec![Some(ep), None], None);
        // Even if an SSH user exists, WireGuard rules carry none of the SSH fields.
        let r = tunnel_rules("alizy0", &a, Some(SSH_UID));
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
        let plan = FirewallPlan::new(&policy, Some(r));
        let text = plan.render();
        assert_eq!(text, FirewallPlan::new(&policy, Some(golden)).render());
        assert!(!text.contains("ssh_mark") && !text.contains("meta l4proto udp reject"));
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
        spec.config = WgConfig::placeholder();
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
        spec.ssh.as_mut().unwrap().public.username = "-oProxyCommand=x".into();
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
}
