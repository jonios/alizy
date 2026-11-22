//! Routing and DNS plans. Pure functions that produce argv vectors; the daemon
//! executes them without a shell.

use crate::config::PublicConfig;
use crate::firewall::{NetworkPolicy, FWMARK};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Policy-routing table id (same value as the fwmark, like wg-quick).
pub const ROUTE_TABLE: u32 = FWMARK;
/// Owned `ip rule` priorities. Removal is by priority so foreign rules are never touched.
pub const RULE_PRIO_SPLIT: u32 = 19029;
pub const RULE_PRIO_SUPPRESS: u32 = 19030;
pub const RULE_PRIO_TUNNEL: u32 = 19031;
pub const DEFAULT_MTU: u16 = 1420;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RoutePlan {
    /// `ip` argv lists, executed in order on bring-up.
    pub up: Vec<Vec<String>>,
    /// sysctl keys (dotted) that must be set to "1".
    pub sysctls: Vec<String>,
    pub full_tunnel_v4: bool,
    pub full_tunnel_v6: bool,
}

fn v(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

fn fam_flag(n: &IpNet) -> &'static str {
    match n {
        IpNet::V4(_) => "-4",
        IpNet::V6(_) => "-6",
    }
}

fn enabled(n: &IpNet, p: &NetworkPolicy) -> bool {
    match n {
        IpNet::V4(_) => p.ipv4_enabled,
        IpNet::V6(_) => p.ipv6_enabled,
    }
}

pub fn route_plan(cfg: &PublicConfig, iface: &str, policy: &NetworkPolicy) -> RoutePlan {
    let mut plan = RoutePlan::default();
    for a in cfg.addresses.iter().filter(|a| enabled(a, policy)) {
        plan.up
            .push(v(&["ip", fam_flag(a), "address", "add", &a.to_string(), "dev", iface]));
    }
    let mtu = cfg.mtu.unwrap_or(DEFAULT_MTU).to_string();
    plan.up.push(v(&["ip", "link", "set", "dev", iface, "mtu", &mtu, "up"]));

    let mut nets: Vec<IpNet> = cfg
        .peers
        .iter()
        .flat_map(|p| p.allowed_ips.iter().copied())
        .filter(|n| enabled(n, policy))
        .collect();
    nets.sort();
    nets.dedup();
    let table = ROUTE_TABLE.to_string();
    for n in &nets {
        let fam = fam_flag(n);
        if n.prefix_len() == 0 {
            let is_v4 = matches!(n, IpNet::V4(_));
            if is_v4 {
                plan.full_tunnel_v4 = true;
                plan.sysctls.push("net.ipv4.conf.all.src_valid_mark".into());
            } else {
                plan.full_tunnel_v6 = true;
            }
            plan.up.push(v(&[
                "ip",
                fam,
                "route",
                "replace",
                &n.to_string(),
                "dev",
                iface,
                "table",
                &table,
            ]));
            plan.up.push(v(&[
                "ip",
                fam,
                "rule",
                "add",
                "not",
                "fwmark",
                &table,
                "table",
                &table,
                "priority",
                &RULE_PRIO_TUNNEL.to_string(),
            ]));
            plan.up.push(v(&[
                "ip",
                fam,
                "rule",
                "add",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
                "priority",
                &RULE_PRIO_SUPPRESS.to_string(),
            ]));
        } else {
            // `add`, never `replace`: an existing route owned by someone else
            // (docker0, the LAN) is left alone; the executor reports the conflict.
            plan.up
                .push(v(&["ip", fam, "route", "add", &n.to_string(), "dev", iface]));
        }
    }
    plan
}

/// `ip rule` sending split-tunnel "direct" traffic (marked SPLIT_MARK) to the main table.
pub fn split_rule_commands(add: bool) -> Vec<Vec<String>> {
    let mark = format!("{:#x}", crate::firewall::SPLIT_MARK);
    let prio = RULE_PRIO_SPLIT.to_string();
    ["-4", "-6"]
        .iter()
        .map(|fam| {
            // Deletion uses the full selector so a foreign rule at the same priority survives.
            let verb = if add { "add" } else { "del" };
            v(&[
                "ip", fam, "rule", verb, "fwmark", &mark, "lookup", "main", "priority", &prio,
            ])
        })
        .collect()
}

/// Commands that remove every routing artefact Alizy may have created.
/// Each may fail harmlessly if the object does not exist.
pub fn teardown_commands(iface: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let table = ROUTE_TABLE.to_string();
    for fam in ["-4", "-6"] {
        out.extend(split_rule_commands(false).into_iter().filter(|c| c[1] == fam));
        out.push(v(&[
            "ip",
            fam,
            "rule",
            "del",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
            "priority",
            &RULE_PRIO_SUPPRESS.to_string(),
        ]));
        out.push(v(&[
            "ip",
            fam,
            "rule",
            "del",
            "not",
            "fwmark",
            &table,
            "table",
            &table,
            "priority",
            &RULE_PRIO_TUNNEL.to_string(),
        ]));
    }
    out.push(v(&["ip", "link", "del", "dev", iface]));
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DnsPlan {
    pub servers: Vec<IpAddr>,
    pub search: Vec<String>,
    /// Route every lookup to the tunnel (`~.`).
    pub route_all: bool,
}

pub fn dns_plan(cfg: &PublicConfig, policy: &NetworkPolicy) -> DnsPlan {
    let source = if policy.custom_dns.is_empty() {
        &cfg.dns
    } else {
        &policy.custom_dns
    };
    let servers = source
        .iter()
        .copied()
        .filter(|ip| match ip {
            IpAddr::V4(_) => policy.ipv4_enabled,
            IpAddr::V6(_) => policy.ipv6_enabled,
        })
        .collect();
    DnsPlan {
        servers,
        search: cfg.dns_search.clone(),
        route_all: cfg.is_full_tunnel(true) || cfg.is_full_tunnel(false),
    }
}

impl DnsPlan {
    /// systemd-resolved argv lists for a per-link configuration.
    pub fn resolvectl_commands(&self, iface: &str) -> Vec<Vec<String>> {
        if self.servers.is_empty() {
            return Vec::new();
        }
        let mut dns = v(&["resolvectl", "dns", iface]);
        dns.extend(self.servers.iter().map(ToString::to_string));
        let mut domain = v(&["resolvectl", "domain", iface]);
        if self.route_all {
            domain.push("~.".into());
        }
        domain.extend(self.search.iter().cloned());
        let mut out = vec![dns, domain];
        if self.route_all {
            out.push(v(&["resolvectl", "default-route", iface, "yes"]));
        }
        out
    }

    /// Contents for /etc/resolv.conf on systems without systemd-resolved.
    pub fn resolv_conf(&self) -> String {
        let mut s = String::from("# Generated by alizyd. The original is restored on disconnect.\n");
        for ip in &self.servers {
            s.push_str(&format!("nameserver {ip}\n"));
        }
        if !self.search.is_empty() {
            s.push_str(&format!("search {}\n", self.search.join(" ")));
        }
        s
    }
}

/// Human-readable warnings when a profile does not fit the user's network policy.
pub fn compatibility_warnings(cfg: &PublicConfig, policy: &NetworkPolicy) -> Vec<String> {
    let fam = cfg.tunnel_families();
    let mut w = Vec::new();
    if policy.ipv4_enabled && !fam.ipv4 && fam.ipv6 {
        w.push(if policy.kill_switch {
            "This profile has no IPv4 tunnel; IPv4 traffic will be blocked by the kill switch.".to_string()
        } else {
            "This profile has no IPv4 tunnel; IPv4 traffic will bypass the VPN. Disable IPv4 or enable the kill switch."
                .to_string()
        });
    }
    if policy.ipv6_enabled && !fam.ipv6 && fam.ipv4 {
        w.push(if policy.kill_switch {
            "This profile has no IPv6 tunnel; IPv6 traffic will be blocked by the kill switch.".to_string()
        } else {
            "This profile has no IPv6 tunnel; IPv6 traffic will bypass the VPN. Disable IPv6 or enable the kill switch."
                .to_string()
        });
    }
    let usable_v4 = policy.ipv4_enabled && fam.ipv4;
    let usable_v6 = policy.ipv6_enabled && fam.ipv6;
    if !usable_v4 && !usable_v6 {
        w.push("With the current IPv4/IPv6 settings this profile cannot carry any traffic.".into());
    }
    if policy.dns_leak_protection && policy.custom_dns.is_empty() && cfg.dns.is_empty() {
        w.push("The profile defines no DNS server; with DNS leak protection on, name resolution will fail. Set a custom DNS server.".into());
    }
    if cfg
        .endpoints()
        .iter()
        .any(|e| matches!(e.host, crate::config::Host::Name(_)))
    {
        w.push(
            "The endpoint is a hostname. While the kill switch blocks DNS, Alizy uses the last resolved address."
                .into(),
        );
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse, tests::sample};

    fn cfg() -> PublicConfig {
        parse(&sample()).unwrap().config.split().0
    }

    #[test]
    fn full_tunnel_uses_owned_policy_routing() {
        let p = route_plan(&cfg(), "alizy0", &NetworkPolicy::default());
        assert!(p.full_tunnel_v4 && p.full_tunnel_v6);
        let flat: Vec<String> = p.up.iter().map(|a| a.join(" ")).collect();
        assert!(flat.contains(&"ip -4 route replace 0.0.0.0/0 dev alizy0 table 19034".to_string()));
        assert!(flat.contains(&"ip -4 rule add not fwmark 19034 table 19034 priority 19031".to_string()));
        assert!(flat.contains(&"ip -6 rule add table main suppress_prefixlength 0 priority 19030".to_string()));
        assert!(flat.contains(&"ip link set dev alizy0 mtu 1420 up".to_string()));
        assert_eq!(p.sysctls, vec!["net.ipv4.conf.all.src_valid_mark"]);
    }

    #[test]
    fn disabled_family_is_not_routed() {
        let pol = NetworkPolicy {
            ipv6_enabled: false,
            ..Default::default()
        };
        let p = route_plan(&cfg(), "alizy0", &pol);
        assert!(!p.full_tunnel_v6);
        assert!(p.up.iter().all(|a| a[1] != "-6"));
    }

    #[test]
    fn teardown_deletes_rules_by_full_selector() {
        for c in teardown_commands("alizy0") {
            if c[2] == "rule" {
                assert!(c.contains(&"priority".to_string()));
                assert!(
                    c.contains(&"table".to_string()) || c.contains(&"lookup".to_string()),
                    "selector missing: {c:?}"
                );
            }
        }
    }

    #[test]
    fn dns_custom_overrides_profile() {
        let pol = NetworkPolicy {
            custom_dns: vec!["9.9.9.9".parse().unwrap()],
            ..Default::default()
        };
        let d = dns_plan(&cfg(), &pol);
        assert_eq!(d.servers, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
        let cmds = d.resolvectl_commands("alizy0");
        assert_eq!(cmds[1], vec!["resolvectl", "domain", "alizy0", "~.", "corp.example"]);
    }

    #[test]
    fn warnings_for_family_mismatch() {
        let text = sample().replace(", fd00:66::2/128", "").replace(", ::/0", "");
        let c = parse(&text).unwrap().config.split().0;
        let w = compatibility_warnings(&c, &NetworkPolicy::default());
        assert!(w.iter().any(|x| x.contains("no IPv6 tunnel")));
        let w = compatibility_warnings(
            &c,
            &NetworkPolicy {
                ipv4_enabled: false,
                ..Default::default()
            },
        );
        assert!(w.iter().any(|x| x.contains("cannot carry any traffic")));
    }
}
