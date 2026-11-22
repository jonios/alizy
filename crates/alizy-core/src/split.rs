//! Split tunnelling: rule model, matching semantics, deterministic precedence,
//! and compilation of rules into the final per-family "direct" IP ranges that
//! the platform adapter enforces.
//!
//! Default policy: **everything uses the VPN**. Only traffic matching an
//! enabled `Direct` rule bypasses it. See SPLIT_TUNNELING.md.
//!
//! Precedence (highest first):
//! 1. IP / CIDR rules — longest prefix wins, then lower `priority` number
//! 2. Exact domain rules
//! 3. Wildcard / parent-domain rules — longest suffix wins
//! 4. Application rules (enforced separately, by process identity)
//! 5. Default: VPN
//!
//! Domain rules only become IP ranges through resolution. Where two rules
//! claim the same address the higher-precedence rule wins; if they tie, `Vpn`
//! wins (fail towards the tunnel).

use crate::config::is_valid_hostname;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MAX_RULES: usize = 5000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Direct,
    Vpn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainMatch {
    /// `bank.example.com` matches only that name.
    Exact,
    /// `*.bank.example.com` matches any subdomain (any depth), NOT the apex.
    Wildcard,
    /// `bank.example.com` + subdomains: the apex and every subdomain.
    Parent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Target {
    Domain { domain: String, mode: DomainMatch },
    Ip { net: IpNet },
    App { path: String, sha256: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub target: Target,
    pub action: Action,
    pub enabled: bool,
    /// Tie-breaker inside a precedence tier. Lower = stronger. Default 100.
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

fn default_priority() -> u32 {
    100
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SplitConfig {
    pub enabled: bool,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    #[error("`{0}` is not a valid domain")]
    Domain(String),
    #[error("`{0}` is not a valid IP address or CIDR range")]
    Ip(String),
    #[error("`{0}` is not an absolute executable path")]
    App(String),
    #[error("too many rules (max {MAX_RULES})")]
    TooMany,
}

/// Normalise and validate a domain pattern. Returns (domain, mode).
/// `*.x.y` → Wildcard; `.x.y` → Parent; `x.y` → Exact (caller may upgrade to Parent).
pub fn parse_domain_pattern(raw: &str) -> Result<(String, DomainMatch), RuleError> {
    let s = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let (name, mode) = if let Some(rest) = s.strip_prefix("*.") {
        (rest.to_string(), DomainMatch::Wildcard)
    } else if let Some(rest) = s.strip_prefix('.') {
        (rest.to_string(), DomainMatch::Parent)
    } else {
        (s.clone(), DomainMatch::Exact)
    };
    // Reject wildcards anywhere else, and single-label TLD-only patterns.
    if name.contains('*') || !is_valid_hostname(&name) || !name.contains('.') {
        return Err(RuleError::Domain(raw.trim().to_string()));
    }
    Ok((name, mode))
}

pub fn parse_ip_target(raw: &str) -> Result<IpNet, RuleError> {
    let s = raw.trim();
    let net = s
        .parse::<IpNet>()
        .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| RuleError::Ip(s.to_string()))?;
    if net.trunc() != net {
        // 192.0.2.10/24 is ambiguous; require the canonical network.
        return Err(RuleError::Ip(format!("{s} (did you mean {}?)", net.trunc())));
    }
    Ok(net)
}

/// Does `name` match the domain rule? Comparison is on whole labels:
/// `notbank.example.com` never matches `bank.example.com`.
pub fn domain_matches(rule_domain: &str, mode: DomainMatch, name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let is_sub = name.len() > rule_domain.len()
        && name.ends_with(rule_domain)
        && name.as_bytes()[name.len() - rule_domain.len() - 1] == b'.';
    match mode {
        DomainMatch::Exact => name == rule_domain,
        DomainMatch::Wildcard => is_sub,
        DomainMatch::Parent => name == rule_domain || is_sub,
    }
}

/// Classify one free-form line from a bulk paste / TXT / CSV import.
pub fn parse_target(raw: &str) -> Result<Target, RuleError> {
    let s = raw.trim();
    if s.starts_with('/') {
        if s.contains('\0') || s.contains("/../") {
            return Err(RuleError::App(s.into()));
        }
        return Ok(Target::App {
            path: s.into(),
            sha256: None,
        });
    }
    if s.parse::<IpAddr>().is_ok() || s.contains('/') || (s.contains(':') && !s.contains('.')) {
        return parse_ip_target(s).map(|net| Target::Ip { net });
    }
    let (domain, mode) = parse_domain_pattern(s)?;
    Ok(Target::Domain { domain, mode })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedRule {
    pub target: Target,
    pub action: Action,
    pub category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImportResult {
    pub rules: Vec<ImportedRule>,
    pub errors: Vec<String>,
    pub duplicates: usize,
}

/// Import from text. Formats:
/// * TXT / paste: one target per line, `#` comments, commas/whitespace also separate.
/// * CSV: `target[,action[,category]]` with optional header row.
/// * JSON: `[{"target": "...", "action": "direct", "category": "..."}]` or `["a.com", ...]`.
pub fn import_rules(text: &str, default_action: Action, existing: &[Rule]) -> ImportResult {
    let mut res = ImportResult::default();
    let mut seen: Vec<Target> = existing.iter().map(|r| r.target.clone()).collect();
    let mut push = |res: &mut ImportResult, target: Target, action: Action, category: Option<String>| {
        if seen.contains(&target) {
            res.duplicates += 1;
        } else {
            seen.push(target.clone());
            res.rules.push(ImportedRule {
                target,
                action,
                category,
            });
        }
    };
    let trimmed = text.trim_start();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Item {
            Plain(String),
            Full {
                target: String,
                action: Option<Action>,
                category: Option<String>,
            },
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Doc {
            List(Vec<Item>),
            Wrapped { rules: Vec<Item> },
        }
        match serde_json::from_str::<Doc>(trimmed) {
            Ok(doc) => {
                let items = match doc {
                    Doc::List(v) | Doc::Wrapped { rules: v } => v,
                };
                for it in items {
                    let (t, a, c) = match it {
                        Item::Plain(t) => (t, None, None),
                        Item::Full {
                            target,
                            action,
                            category,
                        } => (target, action, category),
                    };
                    match parse_target(&t) {
                        Ok(target) => push(&mut res, target, a.unwrap_or(default_action), c),
                        Err(e) => res.errors.push(e.to_string()),
                    }
                }
            }
            Err(e) => res.errors.push(format!("invalid JSON: {e}")),
        }
        return res;
    }
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        let csv_action = fields.get(1).and_then(|a| match a.to_ascii_lowercase().as_str() {
            "direct" | "bypass" => Some(Action::Direct),
            "vpn" | "tunnel" => Some(Action::Vpn),
            _ => None,
        });
        if n == 0 && fields[0].eq_ignore_ascii_case("target") {
            continue; // CSV header
        }
        if let Some(action) = csv_action {
            match parse_target(fields[0]) {
                Ok(t) => push(
                    &mut res,
                    t,
                    action,
                    fields.get(2).filter(|c| !c.is_empty()).map(|c| c.to_string()),
                ),
                Err(e) => res.errors.push(format!("line {}: {e}", n + 1)),
            }
        } else {
            for tok in line
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|t| !t.is_empty())
            {
                match parse_target(tok) {
                    Ok(t) => push(&mut res, t, default_action, None),
                    Err(e) => res.errors.push(format!("line {}: {e}", n + 1)),
                }
            }
        }
    }
    res
}

// ───────────────────────────── evaluation ─────────────────────────────

/// Precedence tier; higher wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Default = 0,
    App = 1,
    WildcardDomain = 2,
    ExactDomain = 3,
    Ip = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub action: Action,
    pub tier: Tier,
    pub rule_id: Option<String>,
    pub explanation: String,
}

fn default_decision() -> Decision {
    Decision {
        action: Action::Vpn,
        tier: Tier::Default,
        rule_id: None,
        explanation: "No rule matched; default policy routes through the VPN.".into(),
    }
}

/// Strength key for comparisons inside a tier: (tier, specificity, -priority, vpn-wins).
fn strength(tier: Tier, specificity: u32, priority: u32, action: Action) -> (Tier, u32, i64, u8) {
    (tier, specificity, -(priority as i64), u8::from(action == Action::Vpn))
}

/// Best domain rule for a name (exact beats wildcard; longer suffix beats shorter).
pub fn evaluate_domain<'a>(rules: &'a [Rule], name: &str) -> Option<(&'a Rule, Tier)> {
    rules
        .iter()
        .filter(|r| r.enabled)
        .filter_map(|r| match &r.target {
            Target::Domain { domain, mode } if domain_matches(domain, *mode, name) => {
                let tier = if *mode == DomainMatch::Exact || (domain == name && *mode == DomainMatch::Parent) {
                    Tier::ExactDomain
                } else {
                    Tier::WildcardDomain
                };
                Some((r, tier, domain.len() as u32))
            }
            _ => None,
        })
        .max_by_key(|(r, tier, len)| strength(*tier, *len, r.priority, r.action))
        .map(|(r, t, _)| (r, t))
}

/// Best IP rule for an address (longest prefix, then priority, then VPN).
pub fn evaluate_ip(rules: &[Rule], ip: IpAddr) -> Option<&Rule> {
    rules
        .iter()
        .filter(|r| r.enabled)
        .filter_map(|r| match &r.target {
            Target::Ip { net } if net.contains(&ip) => Some((r, net.prefix_len() as u32)),
            _ => None,
        })
        .max_by_key(|(r, p)| strength(Tier::Ip, *p, r.priority, r.action))
        .map(|(r, _)| r)
}

/// Full decision for a destination: the address decides first; the domain
/// (if the address was obtained through a domain lookup) second.
pub fn evaluate(rules: &[Rule], domain: Option<&str>, ip: Option<IpAddr>) -> Decision {
    if let Some(ip) = ip {
        if let Some(r) = evaluate_ip(rules, ip) {
            return Decision {
                action: r.action,
                tier: Tier::Ip,
                rule_id: Some(r.id.clone()),
                explanation: format!(
                    "IP rule {} matches {ip} (IP rules take precedence over domain rules).",
                    describe(&r.target)
                ),
            };
        }
    }
    if let Some(d) = domain {
        if let Some((r, tier)) = evaluate_domain(rules, d) {
            return Decision {
                action: r.action,
                tier,
                rule_id: Some(r.id.clone()),
                explanation: format!("Domain rule {} matches {d}.", describe(&r.target)),
            };
        }
    }
    default_decision()
}

pub fn describe(t: &Target) -> String {
    match t {
        Target::Domain {
            domain,
            mode: DomainMatch::Exact,
        } => domain.clone(),
        Target::Domain {
            domain,
            mode: DomainMatch::Wildcard,
        } => format!("*.{domain}"),
        Target::Domain {
            domain,
            mode: DomainMatch::Parent,
        } => format!("{domain} (+subdomains)"),
        Target::Ip { net } => net.to_string(),
        Target::App { path, .. } => path.clone(),
    }
}

// ─────────────────────── compilation to IP ranges ───────────────────────

/// One resolved address attributed to a domain rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedAddr {
    pub rule_id: String,
    pub domain: String,
    pub ip: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DirectSets {
    pub v4: Vec<(Ipv4Addr, Ipv4Addr)>,
    pub v6: Vec<(Ipv6Addr, Ipv6Addr)>,
}

impl DirectSets {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => self.v4.iter().any(|(s, e)| *s <= a && a <= *e),
            IpAddr::V6(a) => self.v6.iter().any(|(s, e)| *s <= a && a <= *e),
        }
    }
}

type Key = (Tier, u32, i64, u8);

/// Paint intervals: later (stronger) paints overwrite weaker ones.
struct Painter {
    // non-overlapping, sorted: (start, end, action, strength)
    spans: Vec<(u128, u128, Action, Key)>,
}

impl Painter {
    fn paint(&mut self, start: u128, end: u128, action: Action, key: Key) {
        let mut out = Vec::with_capacity(self.spans.len() + 2);
        let mut new_parts = vec![(start, end)];
        for &(s, e, a, k) in &self.spans {
            if e < start || s > end {
                out.push((s, e, a, k));
                continue;
            }
            if k > key {
                // Existing span is stronger: keep it, carve it out of the new paint.
                out.push((s, e, a, k));
                new_parts = new_parts
                    .into_iter()
                    .flat_map(|(ns, ne)| {
                        let mut v = Vec::new();
                        if ns < s {
                            v.push((ns, s - 1));
                        }
                        if ne > e {
                            v.push((e + 1, ne));
                        }
                        if ne < s || ns > e {
                            v = vec![(ns, ne)];
                        }
                        v
                    })
                    .collect();
            } else {
                if s < start {
                    out.push((s, start - 1, a, k));
                }
                if e > end {
                    out.push((end + 1, e, a, k));
                }
            }
        }
        for (ns, ne) in new_parts {
            out.push((ns, ne, action, key));
        }
        out.sort_by_key(|x| x.0);
        self.spans = out;
    }
}

fn net_range(n: &IpNet) -> (u128, u128, bool) {
    match n {
        IpNet::V4(v) => (u32::from(v.network()) as u128, u32::from(v.broadcast()) as u128, true),
        IpNet::V6(v) => (u128::from(v.network()), u128::from(v.broadcast()), false),
    }
}

/// Compile enabled rules + resolved domain addresses into merged direct ranges.
pub fn compile(rules: &[Rule], resolved: &[ResolvedAddr]) -> DirectSets {
    let mut p4 = Painter { spans: Vec::new() };
    let mut p6 = Painter { spans: Vec::new() };
    let by_id: BTreeMap<&str, &Rule> = rules.iter().map(|r| (r.id.as_str(), r)).collect();
    for ra in resolved {
        let Some(r) = by_id.get(ra.rule_id.as_str()).filter(|r| r.enabled) else {
            continue;
        };
        let (tier, len) = match &r.target {
            Target::Domain { domain, mode } => (
                if *mode == DomainMatch::Exact || (domain == &ra.domain && *mode == DomainMatch::Parent) {
                    Tier::ExactDomain
                } else {
                    Tier::WildcardDomain
                },
                domain.len() as u32,
            ),
            _ => continue,
        };
        let key = strength(tier, len, r.priority, r.action);
        match ra.ip {
            IpAddr::V4(a) => p4.paint(u32::from(a) as u128, u32::from(a) as u128, r.action, key),
            IpAddr::V6(a) => p6.paint(u128::from(a), u128::from(a), r.action, key),
        }
    }
    for r in rules.iter().filter(|r| r.enabled) {
        if let Target::Ip { net } = &r.target {
            let (s, e, v4) = net_range(net);
            let key = strength(Tier::Ip, net.prefix_len() as u32, r.priority, r.action);
            if v4 {
                p4.paint(s, e, r.action, key)
            } else {
                p6.paint(s, e, r.action, key)
            }
        }
    }
    let merge = |spans: &[(u128, u128, Action, Key)]| {
        let mut out: Vec<(u128, u128)> = Vec::new();
        for &(s, e, a, _) in spans {
            if a != Action::Direct {
                continue;
            }
            match out.last_mut() {
                Some(last) if last.1.checked_add(1) == Some(s) => last.1 = e,
                _ => out.push((s, e)),
            }
        }
        out
    };
    DirectSets {
        v4: merge(&p4.spans)
            .into_iter()
            .map(|(s, e)| (Ipv4Addr::from(s as u32), Ipv4Addr::from(e as u32)))
            .collect(),
        v6: merge(&p6.spans)
            .into_iter()
            .map(|(s, e)| (Ipv6Addr::from(s), Ipv6Addr::from(e)))
            .collect(),
    }
}

// ───────────────────────────── warnings ─────────────────────────────

/// Partial list of large shared CDN / anycast ranges. Bypassing one of these
/// addresses also bypasses every other site served from it.
pub const KNOWN_SHARED_CDN: &[(&str, &str)] = &[
    ("104.16.0.0/13", "Cloudflare"),
    ("104.24.0.0/14", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("162.158.0.0/15", "Cloudflare"),
    ("188.114.96.0/20", "Cloudflare"),
    ("2606:4700::/32", "Cloudflare"),
    ("151.101.0.0/16", "Fastly"),
    ("2a04:4e40::/32", "Fastly"),
    ("13.32.0.0/15", "Amazon CloudFront"),
    ("13.224.0.0/14", "Amazon CloudFront"),
    ("18.64.0.0/14", "Amazon CloudFront"),
    ("23.32.0.0/11", "Akamai"),
    ("23.192.0.0/11", "Akamai"),
    ("2.16.0.0/13", "Akamai"),
];

pub fn shared_cdn(ip: IpAddr) -> Option<&'static str> {
    KNOWN_SHARED_CDN
        .iter()
        .find_map(|(net, name)| net.parse::<IpNet>().ok().filter(|n| n.contains(&ip)).map(|_| *name))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitWarning {
    pub ip: IpAddr,
    pub rule_ids: Vec<String>,
    pub message: String,
}

pub fn shared_ip_warnings(rules: &[Rule], resolved: &[ResolvedAddr]) -> Vec<SplitWarning> {
    let by_id: BTreeMap<&str, &Rule> = rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let mut per_ip: BTreeMap<IpAddr, Vec<&ResolvedAddr>> = BTreeMap::new();
    for ra in resolved {
        per_ip.entry(ra.ip).or_default().push(ra);
    }
    let mut out = Vec::new();
    for (ip, list) in per_ip {
        let mut domains: Vec<&str> = list.iter().map(|r| r.domain.as_str()).collect();
        domains.sort();
        domains.dedup();
        let actions: Vec<Action> = list
            .iter()
            .filter_map(|r| by_id.get(r.rule_id.as_str()).map(|x| x.action))
            .collect();
        let ids: Vec<String> = list.iter().map(|r| r.rule_id.clone()).collect();
        if actions.contains(&Action::Direct) && actions.contains(&Action::Vpn) {
            out.push(SplitWarning {
                ip,
                rule_ids: ids.clone(),
                message: format!(
                    "{ip} is used by both Direct and VPN domains ({}); the stronger rule wins for the whole address, so one of them cannot be routed as configured.",
                    domains.join(", ")
                ),
            });
        } else if domains.len() > 1 {
            out.push(SplitWarning {
                ip,
                rule_ids: ids.clone(),
                message: format!(
                    "{ip} is shared by {}. Routing is per address, so they always take the same path.",
                    domains.join(", ")
                ),
            });
        }
        if let Some(r) = evaluate_ip(rules, ip) {
            if list
                .iter()
                .any(|ra| by_id.get(ra.rule_id.as_str()).map(|x| x.action) != Some(r.action))
            {
                out.push(SplitWarning {
                    ip,
                    rule_ids: ids.clone(),
                    message: format!(
                        "{ip} (from {}) is also covered by IP rule {}, which takes precedence.",
                        domains.join(", "),
                        describe(&r.target)
                    ),
                });
            }
        }
        if let Some(cdn) = shared_cdn(ip) {
            if actions.contains(&Action::Direct) {
                out.push(SplitWarning {
                    ip,
                    rule_ids: ids,
                    message: format!("{ip} belongs to {cdn}, a shared CDN. Bypassing it also sends unrelated websites hosted on the same address outside the VPN."),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, t: &str, action: Action) -> Rule {
        let target = parse_target(t).unwrap();
        Rule {
            id: id.into(),
            target,
            action,
            enabled: true,
            priority: 100,
            category: None,
            note: None,
        }
    }

    #[test]
    fn exact_domain_matching() {
        assert!(domain_matches(
            "bank.example.com",
            DomainMatch::Exact,
            "bank.example.com"
        ));
        assert!(domain_matches(
            "bank.example.com",
            DomainMatch::Exact,
            "BANK.example.com."
        ));
        assert!(!domain_matches(
            "bank.example.com",
            DomainMatch::Exact,
            "www.bank.example.com"
        ));
        assert!(!domain_matches(
            "bank.example.com",
            DomainMatch::Exact,
            "notbank.example.com"
        ));
    }

    #[test]
    fn wildcard_matching_excludes_apex_and_lookalikes() {
        assert!(domain_matches(
            "bank.example.com",
            DomainMatch::Wildcard,
            "a.bank.example.com"
        ));
        assert!(domain_matches(
            "bank.example.com",
            DomainMatch::Wildcard,
            "a.b.bank.example.com"
        ));
        assert!(!domain_matches(
            "bank.example.com",
            DomainMatch::Wildcard,
            "bank.example.com"
        ));
        assert!(!domain_matches(
            "bank.example.com",
            DomainMatch::Wildcard,
            "evilbank.example.com"
        ));
        assert!(!domain_matches(
            "bank.example.com",
            DomainMatch::Wildcard,
            "bank.example.com.evil.net"
        ));
    }

    #[test]
    fn parent_matching() {
        assert!(domain_matches("example.com", DomainMatch::Parent, "example.com"));
        assert!(domain_matches("example.com", DomainMatch::Parent, "x.example.com"));
        assert!(!domain_matches("example.com", DomainMatch::Parent, "myexample.com"));
    }

    #[test]
    fn pattern_parsing() {
        assert_eq!(
            parse_domain_pattern("*.Bank.Example.com").unwrap(),
            ("bank.example.com".into(), DomainMatch::Wildcard)
        );
        assert_eq!(parse_domain_pattern(".example.com").unwrap().1, DomainMatch::Parent);
        assert!(parse_domain_pattern("com").is_err());
        assert!(parse_domain_pattern("a.*.com").is_err());
        assert!(parse_domain_pattern("bad domain.com").is_err());
    }

    #[test]
    fn ip_targets() {
        assert!(matches!(parse_target("192.0.2.10").unwrap(), Target::Ip { .. }));
        assert!(matches!(parse_target("2001:db8:100::/48").unwrap(), Target::Ip { .. }));
        assert!(parse_target("192.0.2.10/24").is_err());
        assert!(parse_target("300.1.1.1").is_err());
        assert!(matches!(parse_target("/usr/bin/firefox").unwrap(), Target::App { .. }));
    }

    #[test]
    fn precedence_ip_over_domain_and_longest_prefix() {
        let rules = vec![
            rule("d", "bank.example.com", Action::Direct),
            rule("n", "192.0.2.0/24", Action::Vpn),
            rule("h", "192.0.2.10", Action::Direct),
        ];
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(
            evaluate(&rules, Some("bank.example.com"), Some(ip)).rule_id.as_deref(),
            Some("h")
        );
        let ip2: IpAddr = "192.0.2.11".parse().unwrap();
        let d = evaluate(&rules, Some("bank.example.com"), Some(ip2));
        assert_eq!((d.action, d.tier), (Action::Vpn, Tier::Ip));
        let d = evaluate(&rules, Some("bank.example.com"), Some("198.51.100.1".parse().unwrap()));
        assert_eq!((d.action, d.tier), (Action::Direct, Tier::ExactDomain));
        assert_eq!(evaluate(&rules, Some("other.com"), None).tier, Tier::Default);
    }

    #[test]
    fn exact_beats_wildcard() {
        let rules = vec![
            rule("w", "*.example.com", Action::Direct),
            rule("e", "secure.example.com", Action::Vpn),
        ];
        assert_eq!(evaluate(&rules, Some("secure.example.com"), None).action, Action::Vpn);
        assert_eq!(evaluate(&rules, Some("www.example.com"), None).action, Action::Direct);
    }

    #[test]
    fn disabled_rules_are_ignored() {
        let mut r = rule("d", "192.0.2.0/24", Action::Direct);
        r.enabled = false;
        assert_eq!(
            evaluate(&[r.clone()], None, Some("192.0.2.1".parse().unwrap())).tier,
            Tier::Default
        );
        assert!(compile(&[r], &[]).is_empty());
    }

    #[test]
    fn compile_cidr_with_vpn_hole() {
        let rules = vec![
            rule("a", "192.0.2.0/24", Action::Direct),
            rule("b", "192.0.2.128/25", Action::Vpn),
        ];
        let s = compile(&rules, &[]);
        assert_eq!(
            s.v4,
            vec![("192.0.2.0".parse().unwrap(), "192.0.2.127".parse().unwrap())]
        );
        assert!(s.v6.is_empty());
    }

    #[test]
    fn compile_domains_respect_precedence_and_conflicts() {
        let rules = vec![
            rule("w", "*.example.com", Action::Direct),
            rule("e", "secure.example.com", Action::Vpn),
            rule("v6", "2001:db8::/32", Action::Direct),
        ];
        let resolved = vec![
            ResolvedAddr {
                rule_id: "w".into(),
                domain: "cdn.example.com".into(),
                ip: "198.51.100.5".parse().unwrap(),
            },
            // shared address: exact VPN rule must win
            ResolvedAddr {
                rule_id: "w".into(),
                domain: "www.example.com".into(),
                ip: "198.51.100.9".parse().unwrap(),
            },
            ResolvedAddr {
                rule_id: "e".into(),
                domain: "secure.example.com".into(),
                ip: "198.51.100.9".parse().unwrap(),
            },
        ];
        let s = compile(&rules, &resolved);
        assert!(s.contains("198.51.100.5".parse().unwrap()));
        assert!(!s.contains("198.51.100.9".parse().unwrap()));
        assert!(s.contains("2001:db8::10".parse().unwrap()));
        let w = shared_ip_warnings(&rules, &resolved);
        assert!(w.iter().any(|x| x.message.contains("both Direct and VPN")));
    }

    #[test]
    fn adjacent_ranges_merge() {
        let rules = vec![
            rule("a", "10.0.0.0/25", Action::Direct),
            rule("b", "10.0.0.128/25", Action::Direct),
        ];
        assert_eq!(
            compile(&rules, &[]).v4,
            vec![("10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap())]
        );
    }

    #[test]
    fn cdn_warning() {
        let rules = vec![rule("d", "site.example", Action::Direct)];
        let resolved = vec![ResolvedAddr {
            rule_id: "d".into(),
            domain: "site.example".into(),
            ip: "104.16.1.1".parse().unwrap(),
        }];
        let w = shared_ip_warnings(&rules, &resolved);
        assert!(w.iter().any(|x| x.message.contains("Cloudflare")));
    }

    #[test]
    fn imports_txt_csv_json_with_duplicates() {
        let existing = vec![rule("x", "a.example.com", Action::Direct)];
        let txt = import_rules(
            "# list\na.example.com\nb.example.com, 192.0.2.1\n*.c.example.com\nnot a domain!!\n",
            Action::Direct,
            &existing,
        );
        assert_eq!(txt.rules.len(), 3);
        assert_eq!(txt.duplicates, 1);
        assert_eq!(txt.errors.len(), 3); // "not", "a", "domain!!"
        let csv = import_rules(
            "target,action,category\nbank.example.com,direct,Banking\n10.0.0.0/8,vpn,\n",
            Action::Direct,
            &[],
        );
        assert_eq!(csv.rules.len(), 2);
        assert_eq!(csv.rules[0].category.as_deref(), Some("Banking"));
        assert_eq!(csv.rules[1].action, Action::Vpn);
        let json = import_rules(
            r#"[{"target":"*.gov.example","action":"direct"},"2001:db8::1"]"#,
            Action::Vpn,
            &[],
        );
        assert_eq!(json.rules.len(), 2);
        assert_eq!(json.rules[1].action, Action::Vpn);
    }
}
