//! nftables ruleset rendering for the kill switch, IPv4/IPv6 controls and DNS
//! leak protection.
//!
//! Alizy owns exactly one table, `inet alizy`. Rendering is pure; the daemon
//! applies the script atomically with `nft -f -` and verifies the tag.
//! See SECURITY.md → "Firewall ownership model".

use crate::split::DirectSets;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

pub const TABLE_FAMILY: &str = "inet";
pub const TABLE_NAME: &str = "alizy";
/// fwmark set by WireGuard on its own encrypted UDP packets, and routing table id.
pub const FWMARK: u32 = 0x4a5a;
pub const TUNNEL_IFACE: &str = "alizy0";
/// Mark for split-tunnel "direct" traffic; `ip rule fwmark SPLIT_MARK lookup main`.
pub const SPLIT_MARK: u32 = 0x4a5b;

const LAN_V4: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255";
const LAN_V6: &str = "fe80::/10, fc00::/7, ff00::/8";

/// User-facing network policy, persisted by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkPolicy {
    pub kill_switch: bool,
    pub allow_lan: bool,
    pub ipv4_enabled: bool,
    pub ipv6_enabled: bool,
    pub dns_leak_protection: bool,
    /// Overrides the profile's DNS servers when non-empty.
    pub custom_dns: Vec<IpAddr>,
    pub auto_reconnect: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            kill_switch: false,
            allow_lan: true,
            ipv4_enabled: true,
            ipv6_enabled: true,
            dns_leak_protection: true,
            custom_dns: Vec::new(),
            auto_reconnect: true,
        }
    }
}

impl NetworkPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if !self.ipv4_enabled && !self.ipv6_enabled {
            return Err("IPv4 and IPv6 cannot both be disabled".into());
        }
        if self.custom_dns.len() > 8 {
            return Err("at most 8 custom DNS servers".into());
        }
        for d in &self.custom_dns {
            if d.is_unspecified() || d.is_multicast() {
                return Err(format!("{d} is not a usable DNS server"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelRules {
    pub iface: String,
    /// Resolved WireGuard endpoints (allowed outside the tunnel when marked).
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallPlan {
    pub kill_switch: bool,
    pub allow_lan: bool,
    pub ipv4_enabled: bool,
    pub ipv6_enabled: bool,
    pub dns_leak_protection: bool,
    pub tunnel: Option<TunnelRules>,
    /// Split-tunnel bypass ranges (already filtered by enabled families).
    #[serde(default)]
    pub direct: DirectSets,
}

impl FirewallPlan {
    pub fn new(policy: &NetworkPolicy, tunnel: Option<TunnelRules>) -> Self {
        Self::with_split(policy, tunnel, DirectSets::default())
    }

    pub fn with_split(policy: &NetworkPolicy, tunnel: Option<TunnelRules>, mut direct: DirectSets) -> Self {
        if !policy.ipv4_enabled {
            direct.v4.clear();
        }
        if !policy.ipv6_enabled {
            direct.v6.clear();
        }
        Self {
            direct,
            kill_switch: policy.kill_switch,
            allow_lan: policy.allow_lan,
            ipv4_enabled: policy.ipv4_enabled,
            ipv6_enabled: policy.ipv6_enabled,
            dns_leak_protection: policy.dns_leak_protection,
            tunnel,
        }
    }

    /// Whether any rule needs to be installed at all.
    pub fn needs_table(&self) -> bool {
        self.kill_switch
            || !self.ipv4_enabled
            || !self.ipv6_enabled
            || (self.dns_leak_protection && self.tunnel.is_some())
            || (self.split_active())
    }

    /// Bypass marking/NAT is only needed while a tunnel captures traffic.
    pub fn split_active(&self) -> bool {
        self.tunnel.is_some() && !self.direct.is_empty()
    }

    /// Short content hash embedded in the ruleset as a comment for verification.
    pub fn tag(&self) -> String {
        let json = serde_json::to_vec(self).expect("plan serialises");
        let digest = Sha256::digest(json);
        format!("alizy:{}", hex::encode(&digest[..8]))
    }

    /// Full atomic nft script: ensure table exists, delete it, recreate it.
    /// Executed as one transaction, so there is no window without rules.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "table {TABLE_FAMILY} {TABLE_NAME}");
        let _ = writeln!(s, "delete table {TABLE_FAMILY} {TABLE_NAME}");
        if !self.needs_table() {
            return s;
        }
        let tag = self.tag();
        let _ = writeln!(s, "table {TABLE_FAMILY} {TABLE_NAME} {{");
        let _ = writeln!(s, "  comment \"{tag} managed by alizyd; do not edit\"");
        self.render_sets(&mut s);
        self.render_split(&mut s);
        self.render_output(&mut s, &tag);
        self.render_input(&mut s);
        self.render_forward(&mut s);
        s.push_str("}\n");
        s
    }

    fn has_direct(&self) -> bool {
        !self.direct.is_empty() && (self.kill_switch || self.tunnel.is_some())
    }

    fn render_sets(&self, s: &mut String) {
        if !self.has_direct() {
            return;
        }
        let elems = |v: Vec<String>| {
            if v.is_empty() {
                String::new()
            } else {
                format!(" elements = {{ {} }};", v.join(", "))
            }
        };
        let fmt = |a: String, b: String| if a == b { a } else { format!("{a}-{b}") };
        let v4 = self
            .direct
            .v4
            .iter()
            .map(|(a, b)| fmt(a.to_string(), b.to_string()))
            .collect();
        let v6 = self
            .direct
            .v6
            .iter()
            .map(|(a, b)| fmt(a.to_string(), b.to_string()))
            .collect();
        let _ = writeln!(s, "  set direct4 {{ type ipv4_addr; flags interval;{} }}", elems(v4));
        let _ = writeln!(s, "  set direct6 {{ type ipv6_addr; flags interval;{} }}", elems(v6));
    }

    /// Mark bypass traffic so `ip rule fwmark SPLIT_MARK lookup main` sends it
    /// to the physical network; masquerade it because the socket may have
    /// picked the tunnel address as source; restore the mark on replies so
    /// reverse-path filtering (with src_valid_mark) accepts them.
    fn render_split(&self, s: &mut String) {
        let Some(iface) = self.iface().filter(|_| self.split_active()) else {
            return;
        };
        s.push_str("  chain split_route {\n");
        s.push_str("    type route hook output priority mangle; policy accept;\n");
        let _ = writeln!(
            s,
            "    meta mark 0 ip daddr @direct4 meta mark set {SPLIT_MARK:#x} ct mark set {SPLIT_MARK:#x}"
        );
        let _ = writeln!(
            s,
            "    meta mark 0 ip6 daddr @direct6 meta mark set {SPLIT_MARK:#x} ct mark set {SPLIT_MARK:#x}"
        );
        s.push_str("  }\n");
        s.push_str("  chain split_pre {\n");
        s.push_str("    type filter hook prerouting priority mangle; policy accept;\n");
        let _ = writeln!(s, "    ct mark {SPLIT_MARK:#x} meta mark set ct mark");
        s.push_str("  }\n");
        s.push_str("  chain split_nat {\n");
        s.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
        let _ = writeln!(s, "    meta mark {SPLIT_MARK:#x} oifname != \"{iface}\" masquerade");
        s.push_str("  }\n");
    }

    fn iface(&self) -> Option<&str> {
        self.tunnel.as_ref().map(|t| t.iface.as_str())
    }

    fn endpoint_rules(&self, s: &mut String, outbound: bool) {
        let Some(t) = &self.tunnel else { return };
        for ep in &t.endpoints {
            let fam = if ep.is_ipv4() { "ip" } else { "ip6" };
            if outbound {
                let _ = writeln!(
                    s,
                    "    meta mark {FWMARK:#x} {fam} daddr {} udp dport {} accept",
                    ep.ip(),
                    ep.port()
                );
            } else {
                let _ = writeln!(s, "    {fam} saddr {} udp sport {} accept", ep.ip(), ep.port());
            }
        }
    }

    fn render_output(&self, s: &mut String, tag: &str) {
        s.push_str("  chain output {\n");
        s.push_str("    type filter hook output priority filter - 10; policy accept;\n");
        s.push_str("    oifname \"lo\" accept\n");
        // WireGuard transport packets to the endpoint (marked by the kernel module).
        self.endpoint_rules(s, true);
        // Link maintenance: DHCP and IPv6 neighbour discovery keep the physical link alive.
        // DHCP only towards broadcast / the local network, not arbitrary hosts.
        let _ = writeln!(s, "    udp sport 68 udp dport 67 ip daddr {{ {LAN_V4} }} accept");
        s.push_str("    udp sport 546 udp dport 547 ip6 daddr { ff02::1:2, fe80::/10 } accept\n");
        s.push_str("    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report } accept\n");
        if !self.ipv4_enabled {
            s.push_str("    meta nfproto ipv4 counter reject with icmpx admin-prohibited comment \"ipv4-disabled\"\n");
        }
        if !self.ipv6_enabled {
            s.push_str("    meta nfproto ipv6 counter reject with icmpx admin-prohibited comment \"ipv6-disabled\"\n");
        }
        if let Some(iface) = self.iface() {
            if self.dns_leak_protection {
                let _ = writeln!(s, "    oifname != \"{iface}\" udp dport {{ 53, 853 }} counter reject with icmpx admin-prohibited comment \"dns-leak\"");
                let _ = writeln!(s, "    oifname != \"{iface}\" tcp dport {{ 53, 853 }} counter reject with icmpx admin-prohibited comment \"dns-leak\"");
            }
            let _ = writeln!(s, "    oifname \"{iface}\" accept");
        }
        if self.kill_switch {
            if self.has_direct() {
                s.push_str("    ip daddr @direct4 accept comment \"split-direct\"\n");
                s.push_str("    ip6 daddr @direct6 accept comment \"split-direct\"\n");
            }
            if self.allow_lan {
                let _ = writeln!(s, "    ip daddr {{ {LAN_V4} }} accept comment \"lan\"");
                let _ = writeln!(s, "    ip6 daddr {{ {LAN_V6} }} accept comment \"lan\"");
            }
            let _ = writeln!(
                s,
                "    counter reject with icmpx admin-prohibited comment \"{tag} kill-switch\""
            );
        }
        s.push_str("  }\n");
    }

    fn render_input(&self, s: &mut String) {
        if self.ipv4_enabled && self.ipv6_enabled {
            return;
        }
        s.push_str("  chain input {\n");
        s.push_str("    type filter hook input priority filter - 10; policy accept;\n");
        s.push_str("    iifname \"lo\" accept\n");
        self.endpoint_rules(s, false);
        s.push_str("    udp sport 67 udp dport 68 accept\n");
        s.push_str("    udp sport 547 udp dport 546 accept\n");
        s.push_str(
            "    icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect } accept\n",
        );
        if !self.ipv4_enabled {
            s.push_str("    meta nfproto ipv4 counter drop comment \"ipv4-disabled\"\n");
        }
        if !self.ipv6_enabled {
            s.push_str("    meta nfproto ipv6 counter drop comment \"ipv6-disabled\"\n");
        }
        s.push_str("  }\n");
    }

    fn render_forward(&self, s: &mut String) {
        if !self.kill_switch && self.ipv4_enabled && self.ipv6_enabled {
            return;
        }
        s.push_str("  chain forward {\n");
        s.push_str("    type filter hook forward priority filter - 10; policy accept;\n");
        if !self.ipv4_enabled {
            s.push_str("    meta nfproto ipv4 counter drop comment \"ipv4-disabled\"\n");
        }
        if !self.ipv6_enabled {
            s.push_str("    meta nfproto ipv6 counter drop comment \"ipv6-disabled\"\n");
        }
        if self.kill_switch {
            if let Some(iface) = self.iface() {
                let _ = writeln!(s, "    oifname \"{iface}\" accept");
                let _ = writeln!(s, "    iifname \"{iface}\" accept");
            }
            if self.has_direct() {
                s.push_str("    ip daddr @direct4 accept\n");
                s.push_str("    ip6 daddr @direct6 accept\n");
            }
            if self.allow_lan {
                let _ = writeln!(s, "    ip daddr {{ {LAN_V4} }} accept comment \"lan\"");
                let _ = writeln!(s, "    ip6 daddr {{ {LAN_V6} }} accept comment \"lan\"");
            }
            s.push_str("    counter drop comment \"kill-switch\"\n");
        }
        s.push_str("  }\n");
    }
}

/// Script that removes Alizy's table (and only Alizy's table).
pub fn render_removal() -> String {
    format!("table {TABLE_FAMILY} {TABLE_NAME}\ndelete table {TABLE_FAMILY} {TABLE_NAME}\n")
}

/// Interface names reach the nft script; restrict them to a safe alphabet.
pub fn is_safe_iface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel() -> Option<TunnelRules> {
        Some(TunnelRules {
            iface: TUNNEL_IFACE.into(),
            endpoints: vec![
                "198.51.100.7:51820".parse().unwrap(),
                "[2001:db8::7]:51820".parse().unwrap(),
            ],
        })
    }

    fn policy(ks: bool) -> NetworkPolicy {
        NetworkPolicy {
            kill_switch: ks,
            ..Default::default()
        }
    }

    #[test]
    fn no_table_when_nothing_enforced() {
        let p = FirewallPlan::new(
            &NetworkPolicy {
                dns_leak_protection: false,
                ..Default::default()
            },
            tunnel(),
        );
        assert!(!p.needs_table());
        assert_eq!(p.render(), render_removal());
    }

    #[test]
    fn script_is_atomic_and_scoped_to_own_table() {
        let r = FirewallPlan::new(&policy(true), tunnel()).render();
        assert!(r.starts_with("table inet alizy\ndelete table inet alizy\ntable inet alizy {"));
        assert!(!r.contains("flush ruleset"));
        for line in r.lines().filter(|l| l.starts_with("table") || l.starts_with("delete")) {
            assert!(line.contains("inet alizy"), "touches foreign table: {line}");
        }
    }

    #[test]
    fn kill_switch_rule_order() {
        let r = FirewallPlan::new(&policy(true), tunnel()).render();
        let pos = |needle: &str| r.find(needle).unwrap_or_else(|| panic!("missing {needle}\n{r}"));
        let lo = pos("oifname \"lo\" accept");
        let ep4 = pos("meta mark 0x4a5a ip daddr 198.51.100.7 udp dport 51820 accept");
        let ep6 = pos("meta mark 0x4a5a ip6 daddr 2001:db8::7 udp dport 51820 accept");
        let dns = pos("oifname != \"alizy0\" udp dport { 53, 853 }");
        let tun = pos("    oifname \"alizy0\" accept");
        let drop = pos("kill-switch\"");
        assert!(lo < ep4 && ep4 < ep6 && ep6 < dns && dns < tun && tun < drop);
    }

    #[test]
    fn protected_mode_without_tunnel_blocks_everything_but_lan() {
        let r = FirewallPlan::new(&policy(true), None).render();
        assert!(!r.contains("alizy0"));
        assert!(!r.contains("meta mark"));
        assert!(r.contains("kill-switch"));
        let no_lan = FirewallPlan::new(
            &NetworkPolicy {
                kill_switch: true,
                allow_lan: false,
                ..Default::default()
            },
            None,
        )
        .render();
        assert!(!no_lan.contains("comment \"lan\""));
        // DHCP exception is limited to broadcast/LAN destinations, never "any".
        assert!(no_lan.contains("udp sport 68 udp dport 67 ip daddr {"));
    }

    #[test]
    fn family_disable_blocks_in_all_directions_but_keeps_transport() {
        let p = NetworkPolicy {
            ipv6_enabled: false,
            ..Default::default()
        };
        let r = FirewallPlan::new(&p, tunnel()).render();
        assert!(r.contains("meta nfproto ipv6 counter reject"));
        assert!(r.contains("chain input"));
        assert!(r.contains("meta nfproto ipv6 counter drop"));
        // the v6 endpoint transport is allowed before the family block
        let ep = r.find("ip6 daddr 2001:db8::7").unwrap();
        let block = r.find("meta nfproto ipv6 counter reject").unwrap();
        assert!(ep < block);
        // ... and the tunnel accept comes after the block, so no v6 inside the tunnel either
        assert!(block < r.find("    oifname \"alizy0\" accept").unwrap());
    }

    #[test]
    fn dns_leak_protection_only_with_tunnel() {
        let r = FirewallPlan::new(&NetworkPolicy::default(), None).render();
        assert!(!r.contains("dns-leak"));
        let r = FirewallPlan::new(&NetworkPolicy::default(), tunnel()).render();
        assert!(r.contains("dns-leak"));
    }

    #[test]
    fn tag_changes_with_plan() {
        let a = FirewallPlan::new(&policy(true), tunnel());
        let b = FirewallPlan::new(&policy(true), None);
        assert_ne!(a.tag(), b.tag());
        assert!(a.render().contains(&a.tag()));
    }

    #[test]
    fn policy_validation() {
        assert!(NetworkPolicy {
            ipv4_enabled: false,
            ipv6_enabled: false,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(NetworkPolicy::default().validate().is_ok());
    }

    #[test]
    fn split_sets_and_ordering() {
        let direct = DirectSets {
            v4: vec![
                ("192.0.2.0".parse().unwrap(), "192.0.2.127".parse().unwrap()),
                ("198.51.100.9".parse().unwrap(), "198.51.100.9".parse().unwrap()),
            ],
            v6: vec![],
        };
        let p = FirewallPlan::with_split(&policy(true), tunnel(), direct.clone());
        let r = p.render();
        assert!(r.contains(
            "set direct4 { type ipv4_addr; flags interval; elements = { 192.0.2.0-192.0.2.127, 198.51.100.9 }; }"
        ));
        assert!(r.contains("set direct6 { type ipv6_addr; flags interval; }"));
        assert!(r.contains("type route hook output priority mangle"));
        assert!(r.contains("meta mark 0x4a5b oifname != \"alizy0\" masquerade"));
        // DNS leak protection precedes the bypass accept: DNS never bypasses.
        assert!(r.find("dns-leak").unwrap() < r.find("split-direct").unwrap());
        assert!(r.find("split-direct").unwrap() < r.find("kill-switch\"").unwrap());
        // Protected mode (no tunnel): direct still allowed, but no marking/NAT.
        let r = FirewallPlan::with_split(&policy(true), None, direct.clone()).render();
        assert!(r.contains("split-direct") && !r.contains("masquerade"));
        // Disabled family drops its ranges.
        let p = FirewallPlan::with_split(
            &NetworkPolicy {
                ipv4_enabled: false,
                kill_switch: true,
                ..Default::default()
            },
            tunnel(),
            direct,
        );
        assert!(p.direct.v4.is_empty());
    }

    #[test]
    fn iface_names() {
        assert!(is_safe_iface_name("alizy0"));
        assert!(!is_safe_iface_name("a\"; flush ruleset"));
        assert!(!is_safe_iface_name("waytoolonginterfacename"));
    }
}
