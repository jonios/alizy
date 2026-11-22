//! Domain Resolution Engine for split tunnelling.
//!
//! Resolves the domains of enabled domain rules through the *system* resolver
//! (the nameservers in /etc/resolv.conf, normally the systemd-resolved stub),
//! so the addresses match what applications on this host receive. Tracks A and
//! AAAA records, CNAME chains and TTLs; refreshes on expiry with backoff on
//! failure; keeps expired addresses for a grace period so live connections are
//! not cut by a transient DNS failure; never re-resolves before expiry.

use alizy_core::dnswire::{build_query, nameservers, parse_response, Answer, WireError, TYPE_A, TYPE_AAAA};
use alizy_core::ipc::{DomainStatus, ResolvedIp};
use alizy_core::split::{DomainMatch, ResolvedAddr, Rule, Target};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub const MIN_REFRESH: u64 = 30;
pub const MAX_REFRESH: u64 = 3600;
/// Keep addresses this long past TTL expiry while refreshes fail.
pub const GRACE: u64 = 900;
/// Addresses kept per name (fresh first, then retiring ones).
pub const MAX_ADDRS_PER_NAME: usize = 64;
/// Upper bound on bypass addresses derived from DNS across all rules.
pub const MAX_TOTAL_ADDRS: usize = 8192;
/// Overall deadline for resolving one name (all servers, both families).
pub const NAME_DEADLINE: Duration = Duration::from_secs(8);
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedAddr {
    pub ip: IpAddr,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheEntry {
    pub addrs: Vec<CachedAddr>,
    pub cnames: Vec<String>,
    pub last_resolved: Option<u64>,
    pub next_refresh: u64,
    pub failures: u32,
    pub last_error: Option<String>,
}

/// name → entry. Persisted so bypass ranges survive a reboot while DNS is blocked.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Cache {
    pub entries: BTreeMap<String, CacheEntry>,
}

/// Names that must be resolved for the given rules. Wildcard rules have no
/// concrete name to resolve (see DOMAIN_ROUTING.md); Exact and Parent rules
/// resolve their apex.
pub fn wanted_names(rules: &[Rule]) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for r in rules.iter().filter(|r| r.enabled) {
        if let Target::Domain { domain, mode } = &r.target {
            if *mode != DomainMatch::Wildcard {
                v.push((r.id.clone(), domain.clone()));
            }
        }
    }
    v
}

impl Cache {
    /// Drop entries for names no longer referenced; drop addresses past grace.
    pub fn prune(&mut self, rules: &[Rule], now: u64) {
        let wanted: Vec<String> = wanted_names(rules).into_iter().map(|(_, d)| d).collect();
        self.entries.retain(|name, _| wanted.contains(name));
        for e in self.entries.values_mut() {
            e.addrs.retain(|a| a.expires_at + GRACE > now);
        }
    }

    pub fn due(&self, rules: &[Rule], now: u64) -> Vec<String> {
        let mut names: Vec<String> = wanted_names(rules)
            .into_iter()
            .map(|(_, d)| d)
            .filter(|d| self.entries.get(d).map(|e| e.next_refresh <= now).unwrap_or(true))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    pub fn record(&mut self, name: &str, result: Result<(Answer, Answer), String>, now: u64) {
        let e = self.entries.entry(name.to_string()).or_default();
        match result {
            Ok((a4, a6)) => {
                let mut fresh: Vec<CachedAddr> = a4
                    .addrs
                    .iter()
                    .chain(a6.addrs.iter())
                    .map(|(ip, ttl)| CachedAddr {
                        ip: *ip,
                        expires_at: now + (*ttl as u64).max(1),
                    })
                    .collect();
                fresh.sort_by_key(|a| a.ip);
                fresh.dedup_by(|a, b| a.ip == b.ip);
                // Addresses that vanished from the answer are retired safely: they
                // keep their old expiry and are dropped only after the grace period,
                // so connections opened just before the change are not cut.
                let mut addrs = fresh.clone();
                for old in &e.addrs {
                    if !fresh.iter().any(|f| f.ip == old.ip) && old.expires_at + GRACE > now {
                        addrs.push(old.clone());
                    }
                }
                // Bound growth: a hostile server rotating addresses cannot accumulate them.
                addrs.truncate(MAX_ADDRS_PER_NAME);
                let ttls: Vec<u32> = [a4.min_ttl, a6.min_ttl].into_iter().filter(|t| *t > 0).collect();
                let ttl = ttls.into_iter().min().unwrap_or(MIN_REFRESH as u32) as u64;
                e.addrs = addrs;
                e.cnames = if a4.cnames.is_empty() { a6.cnames } else { a4.cnames };
                e.last_resolved = Some(now);
                e.next_refresh = now + ttl.clamp(MIN_REFRESH, MAX_REFRESH);
                e.failures = 0;
                e.last_error = None;
            }
            Err(err) => {
                e.failures += 1;
                e.last_error = Some(err);
                // Exponential backoff 30s → 5 min; addresses kept until grace ends.
                let backoff = (MIN_REFRESH << e.failures.min(4)).min(300);
                e.next_refresh = now + backoff;
            }
        }
    }

    pub fn resolved_addrs(&self, rules: &[Rule], now: u64) -> Vec<ResolvedAddr> {
        let mut out = Vec::new();
        for (rule_id, domain) in wanted_names(rules) {
            if let Some(e) = self.entries.get(&domain) {
                for a in e.addrs.iter().filter(|a| a.expires_at + GRACE > now) {
                    if out.len() >= MAX_TOTAL_ADDRS {
                        return out;
                    }
                    out.push(ResolvedAddr {
                        rule_id: rule_id.clone(),
                        domain: domain.clone(),
                        ip: a.ip,
                    });
                }
            }
        }
        out
    }

    pub fn status(&self, rules: &[Rule], now: u64) -> Vec<DomainStatus> {
        wanted_names(rules)
            .into_iter()
            .map(|(rule_id, domain)| {
                let e = self.entries.get(&domain);
                DomainStatus {
                    rule_id,
                    addrs: e
                        .map(|e| {
                            e.addrs
                                .iter()
                                .map(|a| ResolvedIp {
                                    ip: a.ip,
                                    expires_at: a.expires_at,
                                    stale: a.expires_at <= now,
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    cnames: e.map(|e| e.cnames.clone()).unwrap_or_default(),
                    last_resolved: e.and_then(|e| e.last_resolved),
                    next_refresh: e.map(|e| e.next_refresh),
                    last_error: e.and_then(|e| e.last_error.clone()),
                    source: "configured".into(),
                    domain,
                }
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct Resolver {
    resolv_conf: PathBuf,
}

impl Resolver {
    pub fn new(resolv_conf: Option<PathBuf>) -> Self {
        Self {
            resolv_conf: resolv_conf.unwrap_or_else(|| PathBuf::from("/etc/resolv.conf")),
        }
    }

    fn servers(&self) -> Vec<IpAddr> {
        std::fs::read_to_string(&self.resolv_conf)
            .map(|t| nameservers(&t))
            .unwrap_or_default()
    }

    /// Resolve A and AAAA for `name`. Error only if *both* families failed.
    pub async fn resolve(&self, name: &str) -> Result<(Answer, Answer), String> {
        let servers = self.servers();
        if servers.is_empty() {
            return Err("no nameserver configured in resolv.conf".into());
        }
        let both = async {
            tokio::join!(
                self.query_any(&servers, name, TYPE_A),
                self.query_any(&servers, name, TYPE_AAAA)
            )
        };
        let (a, aaaa) = tokio::time::timeout(NAME_DEADLINE, both)
            .await
            .map_err(|_| "resolution timed out".to_string())?;
        match (a, aaaa) {
            (Err(e), Err(_)) => Err(e),
            (a, b) => Ok((a.unwrap_or_default(), b.unwrap_or_default())),
        }
    }

    async fn query_any(&self, servers: &[IpAddr], name: &str, qtype: u16) -> Result<Answer, String> {
        let mut last = String::from("no response");
        for s in servers {
            match query(SocketAddr::new(*s, 53), name, qtype).await {
                Ok(a) => return Ok(a),
                Err(e) => last = format!("{s}: {e}"),
            }
        }
        Err(last)
    }
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    u16::from_ne_bytes(b)
}

pub async fn query(server: SocketAddr, name: &str, qtype: u16) -> Result<Answer, String> {
    let id = random_id();
    let q = build_query(id, name, qtype).map_err(|e| e.to_string())?;
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    sock.connect(server).await.map_err(|e| e.to_string())?;
    sock.send(&q).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + QUERY_TIMEOUT;
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| e.to_string())?;
        match parse_response(&buf[..n], id, name, qtype) {
            Ok(a) => return Ok(a),
            // Ignore spoofed/unrelated datagrams; keep waiting until the deadline.
            Err(WireError::Mismatch) => continue,
            Err(WireError::Truncated) => return query_tcp(server, name, qtype).await,
            Err(e) => return Err(e.to_string()),
        }
    }
}

async fn query_tcp(server: SocketAddr, name: &str, qtype: u16) -> Result<Answer, String> {
    let id = random_id();
    let q = build_query(id, name, qtype).map_err(|e| e.to_string())?;
    let fut = async {
        let mut s = TcpStream::connect(server).await.map_err(|e| e.to_string())?;
        s.write_all(&(q.len() as u16).to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        s.write_all(&q).await.map_err(|e| e.to_string())?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
        parse_response(&buf, id, name, qtype).map_err(|e| e.to_string())
    };
    tokio::time::timeout(QUERY_TIMEOUT, fut)
        .await
        .map_err(|_| "timeout".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use alizy_core::split::{parse_target, Action};

    fn rule(id: &str, t: &str) -> Rule {
        Rule {
            id: id.into(),
            target: parse_target(t).unwrap(),
            action: Action::Direct,
            enabled: true,
            priority: 100,
            category: None,
            note: None,
        }
    }

    fn answer(ips: &[(&str, u32)]) -> Answer {
        Answer {
            addrs: ips.iter().map(|(i, t)| (i.parse().unwrap(), *t)).collect(),
            cnames: vec![],
            min_ttl: ips.iter().map(|x| x.1).min().unwrap_or(0),
        }
    }

    #[test]
    fn ttl_expiry_grace_and_refresh_schedule() {
        let rules = vec![rule("r", "bank.example.com"), rule("w", "*.cdn.example.com")];
        let mut c = Cache::default();
        assert_eq!(c.due(&rules, 1000), vec!["bank.example.com"]); // wildcard not resolvable
        c.record(
            "bank.example.com",
            Ok((
                answer(&[("192.0.2.1", 60), ("192.0.2.2", 300)]),
                answer(&[("2001:db8::1", 120)]),
            )),
            1000,
        );
        assert_eq!(c.entries["bank.example.com"].next_refresh, 1060);
        assert!(c.due(&rules, 1059).is_empty(), "must not re-resolve before TTL");
        assert_eq!(c.due(&rules, 1060).len(), 1);
        assert_eq!(c.resolved_addrs(&rules, 1000).len(), 3);
        // Refresh fails: addresses survive until expiry + grace, then are removed.
        c.record("bank.example.com", Err("timeout".into()), 1060);
        assert_eq!(c.entries["bank.example.com"].next_refresh, 1120);
        assert_eq!(c.resolved_addrs(&rules, 1060 + 100).len(), 3);
        assert_eq!(c.resolved_addrs(&rules, 1060 + GRACE).len(), 2); // 192.0.2.1 expired at 1060
        c.prune(&rules, 1300 + GRACE + 1);
        assert!(c.entries["bank.example.com"].addrs.is_empty());
        let st = c.status(&rules, 1061);
        assert_eq!(st[0].last_error.as_deref(), Some("timeout"));
    }

    #[test]
    fn changed_answer_retires_old_address_after_grace() {
        let rules = vec![rule("r", "bank.example.com")];
        let mut c = Cache::default();
        c.record(
            "bank.example.com",
            Ok((answer(&[("192.0.2.1", 60)]), Answer::default())),
            0,
        );
        c.record(
            "bank.example.com",
            Ok((answer(&[("192.0.2.2", 60)]), Answer::default())),
            60,
        );
        let ips = |c: &Cache, t| {
            c.resolved_addrs(&rules, t)
                .into_iter()
                .map(|r| r.ip.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(ips(&c, 61), vec!["192.0.2.2", "192.0.2.1"]);
        assert_eq!(ips(&c, 60 + GRACE), vec!["192.0.2.2"]);
    }

    #[test]
    fn prune_removes_deleted_rules() {
        let mut c = Cache::default();
        c.record(
            "old.example.com",
            Ok((answer(&[("192.0.2.9", 60)]), Answer::default())),
            0,
        );
        c.prune(&[rule("r", "bank.example.com")], 1);
        assert!(c.entries.is_empty());
    }
}
