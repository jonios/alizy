//! Routing and DNS plans. Pure functions that produce argv vectors; the daemon
//! executes them without a shell.

use crate::config::{PublicConfig, PublicPeer};
use crate::firewall::{ConnectionMode, NetworkPolicy, FWMARK, PROXY_MARK};
use crate::keys::PublicKey;
use crate::ssh::SshPublic;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Policy-routing table id (same value as the fwmark, like wg-quick).
pub const ROUTE_TABLE: u32 = FWMARK;
/// Owned `ip rule` priorities. Removal is by priority so foreign rules are never touched.
pub const RULE_PRIO_PROXY: u32 = 19028;
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
    if policy.mode == ConnectionMode::Proxy {
        return proxy_routes(cfg, iface, plan);
    }

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

/// Proxy mode: every captured prefix goes into Alizy's table only, and the
/// table is reached only by sockets marked `PROXY_MARK` (the local proxy).
/// The system's own traffic keeps using the main table.
fn proxy_routes(cfg: &PublicConfig, iface: &str, mut plan: RoutePlan) -> RoutePlan {
    let mut nets: Vec<IpNet> = cfg.peers.iter().flat_map(|p| p.allowed_ips.iter().copied()).collect();
    nets.sort();
    nets.dedup();
    let table = ROUTE_TABLE.to_string();
    for n in &nets {
        plan.up.push(v(&[
            "ip",
            fam_flag(n),
            "route",
            "replace",
            &n.to_string(),
            "dev",
            iface,
            "table",
            &table,
        ]));
    }
    for fam in ["-4", "-6"] {
        plan.up.push(proxy_rule(fam, "add"));
    }
    // Replies get the mark back from conntrack (firewall `proxy_pre`); strict
    // reverse-path filtering must take it into account.
    plan.sysctls.push("net.ipv4.conf.all.src_valid_mark".into());
    plan
}

fn proxy_rule(fam: &str, verb: &str) -> Vec<String> {
    v(&[
        "ip",
        fam,
        "rule",
        verb,
        "fwmark",
        &format!("{PROXY_MARK:#x}"),
        "table",
        &ROUTE_TABLE.to_string(),
        "priority",
        &RULE_PRIO_PROXY.to_string(),
    ])
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
        out.push(proxy_rule(fam, "del"));
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

/// SSH tunnel TUN address (v4) and the address tun2socks uses on its netif.
pub const SSH_TUN_V4: &str = "198.18.0.1/30";
pub const SSH_NETIF_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
/// SSH tunnel TUN address (v6) and the tun2socks netif address.
pub const SSH_TUN_V6: &str = "fd4a:5a00::1/126";
pub const SSH_NETIF_V6: Ipv6Addr = Ipv6Addr::new(0xfd4a, 0x5a00, 0, 0, 0, 0, 0, 2);
/// MTU of the SSH TUN device.
pub const SSH_TUN_MTU: u16 = 1500;
/// Local DNS forwarder the system resolver is pointed at during an SSH tunnel.
pub const SSH_DNS_FORWARDER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 77, 0, 1)), 53);

/// Synthesise a `PublicConfig` for the SSH TUN so the WireGuard `route_plan`
/// and `compatibility_warnings` apply unchanged. The single peer is a
/// full-tunnel placeholder with no endpoint; its all-zero public key (and the
/// all-zero interface key) are obviously synthetic and never used for crypto.
pub fn ssh_public_config(_p: &SshPublic, policy: &NetworkPolicy) -> PublicConfig {
    let zero = PublicKey::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").expect("all-zero key is valid base64");
    let mut addresses = vec![SSH_TUN_V4.parse::<IpNet>().expect("valid constant")];
    if policy.ipv6_enabled {
        addresses.push(SSH_TUN_V6.parse::<IpNet>().expect("valid constant"));
    }
    PublicConfig {
        interface_public_key: zero,
        addresses,
        dns: vec![SSH_DNS_FORWARDER.ip()],
        dns_search: Vec::new(),
        mtu: Some(SSH_TUN_MTU),
        listen_port: None,
        peers: vec![PublicPeer {
            public_key: zero,
            has_preshared_key: false,
            allowed_ips: vec!["0.0.0.0/0".parse().expect("valid"), "::/0".parse().expect("valid")],
            endpoint: None,
            persistent_keepalive: None,
        }],
    }
}

/// System DNS plan for SSH: always the local forwarder, routed for every
/// lookup (`route_all` renders as `~.`), regardless of `custom_dns`, which
/// instead feeds the forwarder's upstreams (see [`ssh_upstreams`]).
pub fn ssh_dns_plan(_policy: &NetworkPolicy) -> DnsPlan {
    DnsPlan {
        servers: vec![SSH_DNS_FORWARDER.ip()],
        search: Vec::new(),
        route_all: true,
    }
}

/// Upstream resolvers for the DNS forwarder: `custom_dns` if set, else the
/// profile's (or default) servers, limited to enabled IP families. If that
/// filtering leaves nothing, fall back to the unfiltered list's IPv4 entries,
/// and finally to the unfiltered list, so the forwarder always has an upstream.
///
/// Queries are sent from the SSH server's side, so `custom_dns` entries on
/// the local network (see [`is_local_network_addr`]) can't be reached and are
/// dropped; see [`ssh_upstream_plan`] for the dropped list.
pub fn ssh_upstreams(p: &SshPublic, policy: &NetworkPolicy) -> Vec<IpAddr> {
    ssh_upstream_plan(p, policy).servers
}

/// Forwarder upstreams plus the `custom_dns` entries dropped because they are
/// local-network addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshUpstreams {
    pub servers: Vec<IpAddr>,
    pub dropped: Vec<IpAddr>,
}

/// Loopback, unspecified, RFC 1918 private, link-local (v4 and v6) and
/// unique-local (fc00::/7) addresses, including their IPv4-mapped forms:
/// addresses that mean something only on this host or its LAN.
pub fn is_local_network_addr(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(a) => a.is_loopback() || a.is_unspecified() || a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || (a.segments()[0] & 0xfe00) == 0xfc00
                || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub fn ssh_upstream_plan(p: &SshPublic, policy: &NetworkPolicy) -> SshUpstreams {
    let (remote, dropped): (Vec<IpAddr>, Vec<IpAddr>) = policy
        .custom_dns
        .iter()
        .copied()
        .partition(|ip| !is_local_network_addr(*ip));
    let all = if remote.is_empty() { p.dns_servers() } else { remote };
    let filtered: Vec<IpAddr> = all
        .iter()
        .copied()
        .filter(|ip| match ip {
            IpAddr::V4(_) => policy.ipv4_enabled,
            IpAddr::V6(_) => policy.ipv6_enabled,
        })
        .collect();
    let servers = if !filtered.is_empty() {
        filtered
    } else {
        let v4: Vec<IpAddr> = all.iter().copied().filter(IpAddr::is_ipv4).collect();
        if v4.is_empty() {
            all
        } else {
            v4
        }
    };
    SshUpstreams { servers, dropped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse, tests::sample};
    use crate::ssh::DEFAULT_SSH_DNS;

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
    fn proxy_mode_routes_only_marked_traffic() {
        let pol = NetworkPolicy {
            mode: ConnectionMode::Proxy,
            ..Default::default()
        };
        let p = route_plan(&cfg(), "alizy0", &pol);
        let flat: Vec<String> = p.up.iter().map(|a| a.join(" ")).collect();
        assert!(flat.contains(&"ip -4 route replace 0.0.0.0/0 dev alizy0 table 19034".to_string()));
        assert!(flat.contains(&"ip -4 rule add fwmark 0x4a5c table 19034 priority 19028".to_string()));
        assert!(flat.contains(&"ip -6 rule add fwmark 0x4a5c table 19034 priority 19028".to_string()));
        // The system's own traffic is never captured.
        assert!(!flat
            .iter()
            .any(|c| c.contains("not fwmark") || c.contains("suppress_prefixlength")));
        assert!(!p.full_tunnel_v4 && !p.full_tunnel_v6);
        assert_eq!(p.sysctls, vec!["net.ipv4.conf.all.src_valid_mark"]);
        let down: Vec<String> = teardown_commands("alizy0").iter().map(|a| a.join(" ")).collect();
        assert!(down.contains(&"ip -4 rule del fwmark 0x4a5c table 19034 priority 19028".to_string()));
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

    fn ssh() -> SshPublic {
        SshPublic {
            host: "192.0.2.10".parse().unwrap(),
            port: 22,
            username: "alice".into(),
            host_key: None,
            dns: Vec::new(),
        }
    }

    #[test]
    fn ssh_route_plan_defaults_to_tun() {
        let pol = NetworkPolicy::default();
        let c = ssh_public_config(&ssh(), &pol);
        assert_eq!(c.mtu, Some(1500));
        let p = route_plan(&c, "alizy0", &pol);
        let flat: Vec<String> = p.up.iter().map(|a| a.join(" ")).collect();
        assert!(flat.contains(&"ip -4 route replace 0.0.0.0/0 dev alizy0 table 19034".to_string()));
        assert!(flat.iter().any(|l| l.contains("198.18.0.1/30")), "{flat:?}");
        assert!(flat.iter().any(|l| l.contains("fd4a:5a00::1/126")), "{flat:?}");
        assert!(flat.contains(&"ip link set dev alizy0 mtu 1500 up".to_string()));
        assert!(compatibility_warnings(&c, &pol).is_empty());
    }

    #[test]
    fn ssh_route_plan_omits_v6_when_disabled() {
        let pol = NetworkPolicy {
            ipv6_enabled: false,
            ..Default::default()
        };
        let c = ssh_public_config(&ssh(), &pol);
        assert!(c.addresses.iter().all(|a| matches!(a, IpNet::V4(_))));
        let p = route_plan(&c, "alizy0", &pol);
        assert!(!p.full_tunnel_v6);
        assert!(p.up.iter().all(|a| a[1] != "-6"));
        assert!(compatibility_warnings(&c, &pol).is_empty());
    }

    #[test]
    fn ssh_dns_plan_points_to_forwarder_even_with_custom_dns() {
        let pol = NetworkPolicy {
            custom_dns: vec!["9.9.9.9".parse().unwrap()],
            ..Default::default()
        };
        let d = ssh_dns_plan(&pol);
        assert_eq!(d.servers, vec!["127.77.0.1".parse::<IpAddr>().unwrap()]);
        let cmds = d.resolvectl_commands("alizy0");
        assert_eq!(cmds[0], vec!["resolvectl", "dns", "alizy0", "127.77.0.1"]);
        assert_eq!(cmds[1], vec!["resolvectl", "domain", "alizy0", "~."]);
    }

    #[test]
    fn ssh_upstreams_prefer_custom_dns() {
        let mut p = ssh();
        assert_eq!(ssh_upstreams(&p, &NetworkPolicy::default()), DEFAULT_SSH_DNS.to_vec());
        p.dns = vec!["8.8.8.8".parse().unwrap()];
        assert_eq!(
            ssh_upstreams(&p, &NetworkPolicy::default()),
            vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        );
        let pol = NetworkPolicy {
            custom_dns: vec!["9.9.9.9".parse().unwrap()],
            ..Default::default()
        };
        assert_eq!(ssh_upstreams(&p, &pol), vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn ssh_upstreams_filter_families_with_fallback() {
        let mut p = ssh();
        p.dns = vec!["2606:4700:4700::1111".parse().unwrap(), "1.1.1.1".parse().unwrap()];
        let pol = NetworkPolicy {
            ipv6_enabled: false,
            ..Default::default()
        };
        assert_eq!(ssh_upstreams(&p, &pol), vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        p.dns = vec!["2606:4700:4700::1111".parse().unwrap()];
        assert_eq!(ssh_upstreams(&p, &pol), p.dns);
    }

    #[test]
    fn ssh_upstreams_drop_local_network_custom_dns() {
        let mut p = ssh();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // Only LAN resolvers: dropped, profile DNS (here the defaults) used instead.
        let pol = NetworkPolicy {
            custom_dns: vec![ip("192.168.1.1"), ip("fd00::53"), ip("fe80::1"), ip("127.0.0.53")],
            ..Default::default()
        };
        let r = ssh_upstream_plan(&p, &pol);
        assert_eq!(r.servers, DEFAULT_SSH_DNS.to_vec());
        assert_eq!(r.dropped, pol.custom_dns);
        p.dns = vec![ip("8.8.8.8")];
        assert_eq!(ssh_upstreams(&p, &pol), vec![ip("8.8.8.8")]);
        // Mixed: the public entries are kept, the private ones reported.
        let pol = NetworkPolicy {
            custom_dns: vec![ip("10.0.0.1"), ip("9.9.9.9"), ip("169.254.1.1")],
            ..Default::default()
        };
        let r = ssh_upstream_plan(&p, &pol);
        assert_eq!(r.servers, vec![ip("9.9.9.9")]);
        assert_eq!(r.dropped, vec![ip("10.0.0.1"), ip("169.254.1.1")]);
        // Nothing local: nothing dropped.
        let pol = NetworkPolicy {
            custom_dns: vec![ip("9.9.9.9")],
            ..Default::default()
        };
        assert!(ssh_upstream_plan(&p, &pol).dropped.is_empty());
    }

    #[test]
    fn local_network_addresses() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for a in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.0.1",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(is_local_network_addr(ip(a)), "{a}");
        }
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "100.64.0.1",
            "2606:4700:4700::1111",
            "::ffff:1.1.1.1",
        ] {
            assert!(!is_local_network_addr(ip(a)), "{a}");
        }
    }
}
