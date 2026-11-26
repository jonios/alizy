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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelRules {
    pub iface: String,
    /// Resolved WireGuard endpoints (allowed outside the tunnel when marked).
    pub endpoints: Vec<SocketAddr>,
    // SSH-tunnel fields. All are skipped when empty so WireGuard plans keep
    // their exact serialisation (and therefore their tag).
    /// Resolved SSH server addresses; `ssh` (as `ssh_uid`) connects to them over TCP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_endpoints: Vec<SocketAddr>,
    /// uid of the `alizy-ssh` system user that runs `ssh` and `tun2socks`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_uid: Option<u32>,
    /// ssh's local SOCKS port on 127.0.0.1; reachable only by `ssh_uid` and root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_port: Option<u16>,
    /// Reject UDP leaving the tunnel interface (the SSH tunnel cannot carry it).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub block_udp: bool,
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
    /// TCP source port of the HTTP LAN proxy. Its replies to LAN clients must
    /// pass the kill switch even when `allow_lan` is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_proxy_port: Option<u16>,
    /// TCP source port of the SOCKS5 LAN proxy (same rationale as HTTP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_socks_port: Option<u16>,
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
            lan_proxy_port: None,
            lan_socks_port: None,
        }
    }

    /// Allow the LAN proxy's replies to reach the devices that asked for
    /// them, independently of `allow_lan`.
    pub fn with_lan_proxy(mut self, port: Option<u16>) -> Self {
        self.lan_proxy_port = port.filter(|_| self.kill_switch);
        self
    }

    pub fn with_lan_socks(mut self, port: Option<u16>) -> Self {
        self.lan_socks_port = port.filter(|_| self.kill_switch);
        self
    }

    /// Whether any rule needs to be installed at all.
    pub fn needs_table(&self) -> bool {
        self.kill_switch
            || !self.ipv4_enabled
            || !self.ipv6_enabled
            || (self.dns_leak_protection && self.tunnel.is_some())
            || (self.split_active())
            || self
                .tunnel
                .as_ref()
                .is_some_and(|t| t.block_udp || t.ssh_uid.is_some() || !t.endpoints.is_empty())
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
        self.render_ssh_mark(&mut s);
        self.render_wg_mark(&mut s);
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
        // WireGuard transport is UDP; SSH transport is TCP. Both are marked FWMARK.
        let eps = t.endpoints.iter().map(|ep| (ep, "udp"));
        for (ep, proto) in eps.chain(t.tcp_endpoints.iter().map(|ep| (ep, "tcp"))) {
            let fam = if ep.is_ipv4() { "ip" } else { "ip6" };
            if outbound {
                let _ = writeln!(
                    s,
                    "    meta mark {FWMARK:#x} {fam} daddr {} {proto} dport {} accept",
                    ep.ip(),
                    ep.port()
                );
            } else {
                let _ = writeln!(s, "    {fam} saddr {} {proto} sport {} accept", ep.ip(), ep.port());
            }
        }
    }

    /// OpenSSH cannot set SO_MARK, so mark its connections to the server by
    /// socket owner. Route hook: the mark change triggers a re-route, and the
    /// `not fwmark FWMARK` ip rule then sends them via the physical network.
    /// Runs before `split_route` (mangle), whose `meta mark 0` guard then skips them.
    fn render_ssh_mark(&self, s: &mut String) {
        let Some(t) = &self.tunnel else { return };
        let Some(uid) = t.ssh_uid else { return };
        s.push_str("  chain ssh_mark {\n");
        s.push_str("    type route hook output priority mangle - 1; policy accept;\n");
        // Socket-less packets of the connection (timewait ACK/RST) have no
        // skuid: take the mark from conntrack.
        let _ = writeln!(s, "    ct mark {FWMARK:#x} meta mark set ct mark");
        for ep in &t.tcp_endpoints {
            let fam = if ep.is_ipv4() { "ip" } else { "ip6" };
            let _ = writeln!(
                s,
                "    meta skuid {uid} {fam} daddr {} tcp dport {} meta mark set {FWMARK:#x} ct mark set {FWMARK:#x}",
                ep.ip(),
                ep.port()
            );
        }
        s.push_str("  }\n");
        // Replies from the server get the mark back before routing, so strict
        // reverse-path filtering (src_valid_mark) looks them up outside the tunnel.
        s.push_str("  chain ssh_pre {\n");
        s.push_str("    type filter hook prerouting priority mangle; policy accept;\n");
        let _ = writeln!(s, "    ct mark {FWMARK:#x} meta mark set ct mark");
        s.push_str("  }\n");
        // connect() chose the source address from the unmarked lookup (the
        // tunnel), and the re-route after marking keeps it: rewrite it to the
        // outgoing interface's address. Narrowed to the server tuples, which
        // only ssh_mark (alizy-ssh's sockets) marks.
        s.push_str("  chain ssh_nat {\n");
        s.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
        for ep in &t.tcp_endpoints {
            let fam = if ep.is_ipv4() { "ip" } else { "ip6" };
            let _ = writeln!(
                s,
                "    meta mark {FWMARK:#x} oifname != \"{}\" {fam} daddr {} tcp dport {} masquerade",
                t.iface,
                ep.ip(),
                ep.port()
            );
        }
        s.push_str("  }\n");
    }

    /// The WireGuard socket marks its packets FWMARK. Copy that mark to
    /// conntrack and back onto the server's replies, so strict reverse-path
    /// filtering (rp_filter=1, with src_valid_mark) looks the encrypted
    /// replies up outside the tunnel instead of dropping them (as wg-quick does).
    fn render_wg_mark(&self, s: &mut String) {
        let Some(t) = self.tunnel.as_ref().filter(|t| !t.endpoints.is_empty()) else {
            return;
        };
        s.push_str("  chain wg_mark {\n");
        s.push_str("    type filter hook postrouting priority mangle; policy accept;\n");
        for ep in &t.endpoints {
            let fam = if ep.is_ipv4() { "ip" } else { "ip6" };
            let _ = writeln!(
                s,
                "    meta mark {FWMARK:#x} {fam} daddr {} udp dport {} ct mark set meta mark",
                ep.ip(),
                ep.port()
            );
        }
        s.push_str("  }\n");
        s.push_str("  chain wg_pre {\n");
        s.push_str("    type filter hook prerouting priority mangle; policy accept;\n");
        let _ = writeln!(s, "    ct mark {FWMARK:#x} meta mark set ct mark");
        s.push_str("  }\n");
    }

    fn render_output(&self, s: &mut String, tag: &str) {
        s.push_str("  chain output {\n");
        s.push_str("    type filter hook output priority filter - 10; policy accept;\n");
        if let Some(t) = &self.tunnel {
            if let (Some(uid), Some(port)) = (t.ssh_uid, t.socks_port) {
                // ssh's SOCKS port is an open proxy out of the machine: only
                // alizy-ssh (tun2socks) and root may connect to it.
                let _ = writeln!(
                    s,
                    "    oifname \"lo\" tcp dport {port} meta skuid != {uid} meta skuid != 0 reject"
                );
                // ...and only alizy-ssh's listener may answer from it, so a local
                // user who binds the port before (or after) ssh cannot pose as
                // the proxy. SYN-ACKs from a listener carry the listener's uid
                // (skb_to_full_sk); kernel RSTs come from uid-0 control sockets.
                let _ = writeln!(
                    s,
                    "    oifname \"lo\" tcp sport {port} meta skuid != {uid} meta skuid != 0 reject"
                );
            }
        }
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
            if self.tunnel.as_ref().is_some_and(|t| t.block_udp) {
                // The SSH tunnel cannot carry UDP: fail fast (QUIC falls back to TCP).
                let _ = writeln!(s, "    oifname \"{iface}\" meta l4proto udp reject");
            }
            let _ = writeln!(s, "    oifname \"{iface}\" accept");
        }
        if self.kill_switch {
            if let Some(port) = self.lan_proxy_port {
                let _ = writeln!(
                    s,
                    "    tcp sport {port} ip daddr {{ {LAN_V4} }} accept comment \"lan-proxy\""
                );
                let _ = writeln!(
                    s,
                    "    tcp sport {port} ip6 daddr {{ {LAN_V6} }} accept comment \"lan-proxy\""
                );
            }
            if let Some(port) = self.lan_socks_port {
                let _ = writeln!(
                    s,
                    "    tcp sport {port} ip daddr {{ {LAN_V4} }} accept comment \"lan-socks\""
                );
                let _ = writeln!(
                    s,
                    "    tcp sport {port} ip6 daddr {{ {LAN_V6} }} accept comment \"lan-socks\""
                );
            }
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
        let block_udp = self.tunnel.as_ref().filter(|t| t.block_udp);
        if !self.kill_switch && self.ipv4_enabled && self.ipv6_enabled && block_udp.is_none() {
            return;
        }
        s.push_str("  chain forward {\n");
        s.push_str("    type filter hook forward priority filter - 10; policy accept;\n");
        if let Some(t) = block_udp {
            // Forwarded traffic (containers, VMs) cannot use UDP through the SSH tunnel either.
            let _ = writeln!(s, "    oifname \"{}\" meta l4proto udp reject", t.iface);
        }
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
            ..Default::default()
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
        let off = NetworkPolicy {
            dns_leak_protection: false,
            ..Default::default()
        };
        let p = FirewallPlan::new(&off, None);
        assert!(!p.needs_table());
        assert_eq!(p.render(), render_removal());
        // A WireGuard tunnel alone only needs the conntrack-mark chains (strict
        // rp_filter): nothing is filtered.
        let t = FirewallPlan::new(&off, tunnel());
        assert!(t.needs_table());
        let r = t.render();
        assert!(r.contains("  chain wg_mark {") && r.contains("  chain wg_pre {"));
        assert!(!r.contains("reject") && !r.contains("drop"), "{r}");
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
    fn lan_proxy_replies_pass_the_kill_switch() {
        // `allow_lan` off: the proxy's own replies must still reach the LAN.
        let p = NetworkPolicy {
            kill_switch: true,
            allow_lan: false,
            ..Default::default()
        };
        let r = FirewallPlan::new(&p, tunnel()).with_lan_proxy(Some(8080)).render();
        let dns = pos(&r, "oifname != \"alizy0\" udp dport { 53, 853 }");
        let v4 = pos(
            &r,
            "tcp sport 8080 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,",
        );
        let v6 = pos(&r, "tcp sport 8080 ip6 daddr { fe80::/10, fc00::/7, ff00::/8 }");
        let drop = pos(&r, "kill-switch\"");
        // After the DNS-leak rejects, before the final reject: replies pass,
        // DNS still cannot bypass.
        assert!(dns < v4 && v4 < drop && v6 < drop, "{r}");
        // Without a listener there is no rule at all.
        let plan = FirewallPlan::new(&p, tunnel());
        assert!(!plan.render().contains("lan-proxy"));
        // The rule does not depend on `allow_lan` (it exists for the off case).
        let lan_ok = FirewallPlan::new(&policy(true), tunnel())
            .with_lan_proxy(Some(8080))
            .render();
        assert!(lan_ok.contains("tcp sport 8080 ip daddr {"));
        // Kill switch off: the output chain accepts everything anyway.
        let no_ks = FirewallPlan::new(&policy(false), tunnel())
            .with_lan_proxy(Some(8080))
            .render();
        assert!(!no_ks.contains("lan-proxy"));
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

    // ---- SSH tunnels ----

    /// Goldens captured from the renderer before SSH support was added: a
    /// WireGuard plan keeps its tag and renders identically except for the
    /// conntrack-mark chains (wg_mark/wg_pre) added for strict rp_filter.
    #[test]
    fn wg_plan_render_and_tag_unchanged() {
        let ks = FirewallPlan::new(&policy(true), tunnel());
        assert_eq!(ks.tag(), "alizy:9317c868e4bd82fd");
        assert_eq!(ks.render(), "table inet alizy\ndelete table inet alizy\ntable inet alizy {\n  comment \"alizy:9317c868e4bd82fd managed by alizyd; do not edit\"\n  chain wg_mark {\n    type filter hook postrouting priority mangle; policy accept;\n    meta mark 0x4a5a ip daddr 198.51.100.7 udp dport 51820 ct mark set meta mark\n    meta mark 0x4a5a ip6 daddr 2001:db8::7 udp dport 51820 ct mark set meta mark\n  }\n  chain wg_pre {\n    type filter hook prerouting priority mangle; policy accept;\n    ct mark 0x4a5a meta mark set ct mark\n  }\n  chain output {\n    type filter hook output priority filter - 10; policy accept;\n    oifname \"lo\" accept\n    meta mark 0x4a5a ip daddr 198.51.100.7 udp dport 51820 accept\n    meta mark 0x4a5a ip6 daddr 2001:db8::7 udp dport 51820 accept\n    udp sport 68 udp dport 67 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept\n    udp sport 546 udp dport 547 ip6 daddr { ff02::1:2, fe80::/10 } accept\n    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report } accept\n    oifname != \"alizy0\" udp dport { 53, 853 } counter reject with icmpx admin-prohibited comment \"dns-leak\"\n    oifname != \"alizy0\" tcp dport { 53, 853 } counter reject with icmpx admin-prohibited comment \"dns-leak\"\n    oifname \"alizy0\" accept\n    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept comment \"lan\"\n    ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept comment \"lan\"\n    counter reject with icmpx admin-prohibited comment \"alizy:9317c868e4bd82fd kill-switch\"\n  }\n  chain forward {\n    type filter hook forward priority filter - 10; policy accept;\n    oifname \"alizy0\" accept\n    iifname \"alizy0\" accept\n    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept comment \"lan\"\n    ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept comment \"lan\"\n    counter drop comment \"kill-switch\"\n  }\n}\n");
        let nov6 = FirewallPlan::new(
            &NetworkPolicy {
                ipv6_enabled: false,
                ..Default::default()
            },
            tunnel(),
        );
        assert_eq!(nov6.tag(), "alizy:5aa7506c6c07b0f9");
        assert_eq!(nov6.render(), "table inet alizy\ndelete table inet alizy\ntable inet alizy {\n  comment \"alizy:5aa7506c6c07b0f9 managed by alizyd; do not edit\"\n  chain wg_mark {\n    type filter hook postrouting priority mangle; policy accept;\n    meta mark 0x4a5a ip daddr 198.51.100.7 udp dport 51820 ct mark set meta mark\n    meta mark 0x4a5a ip6 daddr 2001:db8::7 udp dport 51820 ct mark set meta mark\n  }\n  chain wg_pre {\n    type filter hook prerouting priority mangle; policy accept;\n    ct mark 0x4a5a meta mark set ct mark\n  }\n  chain output {\n    type filter hook output priority filter - 10; policy accept;\n    oifname \"lo\" accept\n    meta mark 0x4a5a ip daddr 198.51.100.7 udp dport 51820 accept\n    meta mark 0x4a5a ip6 daddr 2001:db8::7 udp dport 51820 accept\n    udp sport 68 udp dport 67 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept\n    udp sport 546 udp dport 547 ip6 daddr { ff02::1:2, fe80::/10 } accept\n    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report } accept\n    meta nfproto ipv6 counter reject with icmpx admin-prohibited comment \"ipv6-disabled\"\n    oifname != \"alizy0\" udp dport { 53, 853 } counter reject with icmpx admin-prohibited comment \"dns-leak\"\n    oifname != \"alizy0\" tcp dport { 53, 853 } counter reject with icmpx admin-prohibited comment \"dns-leak\"\n    oifname \"alizy0\" accept\n  }\n  chain input {\n    type filter hook input priority filter - 10; policy accept;\n    iifname \"lo\" accept\n    ip saddr 198.51.100.7 udp sport 51820 accept\n    ip6 saddr 2001:db8::7 udp sport 51820 accept\n    udp sport 67 udp dport 68 accept\n    udp sport 547 udp dport 546 accept\n    icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect } accept\n    meta nfproto ipv6 counter drop comment \"ipv6-disabled\"\n  }\n  chain forward {\n    type filter hook forward priority filter - 10; policy accept;\n    meta nfproto ipv6 counter drop comment \"ipv6-disabled\"\n  }\n}\n");
        assert_eq!(
            FirewallPlan::new(&NetworkPolicy::default(), tunnel()).tag(),
            "alizy:d3afc8da1335f78f"
        );
        let direct = DirectSets {
            v4: vec![("192.0.2.0".parse().unwrap(), "192.0.2.127".parse().unwrap())],
            v6: vec![],
        };
        assert_eq!(
            FirewallPlan::with_split(&policy(true), tunnel(), direct).tag(),
            "alizy:dda2a1f459040cce"
        );
        // New fields never appear in a WireGuard plan's JSON.
        let json = serde_json::to_string(&ks).unwrap();
        for f in ["tcp_endpoints", "ssh_uid", "socks_port", "block_udp"] {
            assert!(!json.contains(f), "{f} serialised in WG plan: {json}");
        }
    }

    const SSH_UID: u32 = 967;

    fn ssh_tunnel() -> Option<TunnelRules> {
        Some(TunnelRules {
            iface: TUNNEL_IFACE.into(),
            endpoints: vec![],
            tcp_endpoints: vec!["203.0.113.5:22".parse().unwrap(), "[2001:db8::5]:443".parse().unwrap()],
            ssh_uid: Some(SSH_UID),
            socks_port: Some(1080),
            block_udp: true,
        })
    }

    fn pos(r: &str, needle: &str) -> usize {
        r.find(needle).unwrap_or_else(|| panic!("missing {needle:?}\n{r}"))
    }

    #[test]
    fn ssh_plan_allows_tcp_endpoint_marked() {
        let r = FirewallPlan::new(&policy(true), ssh_tunnel()).render();
        let ep4 = pos(&r, "    meta mark 0x4a5a ip daddr 203.0.113.5 tcp dport 22 accept\n");
        let ep6 = pos(&r, "    meta mark 0x4a5a ip6 daddr 2001:db8::5 tcp dport 443 accept\n");
        // Before DNS-leak rejects (an ssh server on tcp/53 must still work) and the kill switch.
        assert!(pos(&r, "    oifname \"lo\" accept") < ep4);
        assert!(ep4 < ep6 && ep6 < pos(&r, "dns-leak") && ep6 < pos(&r, "kill-switch\""));
        assert!(!r.contains("udp dport 22") && !r.contains("udp dport 443"));
        // Input chain (rendered when a family is disabled): replies from the server.
        let r = FirewallPlan::new(
            &NetworkPolicy {
                ipv6_enabled: false,
                kill_switch: true,
                ..Default::default()
            },
            ssh_tunnel(),
        )
        .render();
        let input = pos(&r, "chain input");
        let in4 = pos(&r, "    ip saddr 203.0.113.5 tcp sport 22 accept\n");
        let in6 = pos(&r, "    ip6 saddr 2001:db8::5 tcp sport 443 accept\n");
        let drop = pos(&r, "meta nfproto ipv6 counter drop");
        assert!(input < in4 && in4 < in6 && in6 < drop);
    }

    #[test]
    fn ssh_plan_marks_by_skuid() {
        // Even with nothing else enforced, ssh's packets must be marked or they would loop into the tunnel.
        let p = FirewallPlan::new(
            &NetworkPolicy {
                dns_leak_protection: false,
                ..Default::default()
            },
            ssh_tunnel(),
        );
        assert!(p.needs_table());
        let r = p.render();
        let chain = pos(
            &r,
            "  chain ssh_mark {\n    type route hook output priority mangle - 1; policy accept;\n",
        );
        let m4 = pos(
            &r,
            "    meta skuid 967 ip daddr 203.0.113.5 tcp dport 22 meta mark set 0x4a5a ct mark set 0x4a5a\n",
        );
        let m6 = pos(
            &r,
            "    meta skuid 967 ip6 daddr 2001:db8::5 tcp dport 443 meta mark set 0x4a5a ct mark set 0x4a5a\n",
        );
        assert!(chain < m4 && m4 < m6 && m6 < pos(&r, "  chain output {"));
        // WireGuard plans have no ssh_mark chain.
        assert!(!FirewallPlan::new(&policy(true), tunnel()).render().contains("ssh_mark"));
    }

    #[test]
    fn ssh_plan_restricts_socks_port_to_alizy_ssh() {
        for ks in [true, false] {
            let r = FirewallPlan::new(&policy(ks), ssh_tunnel()).render();
            let rej = pos(
                &r,
                "    oifname \"lo\" tcp dport 1080 meta skuid != 967 meta skuid != 0 reject\n",
            );
            let lo = pos(&r, "    oifname \"lo\" accept\n");
            assert!(pos(&r, "chain output") < rej && rej < lo);
            assert_eq!(r.matches("oifname \"lo\"").count(), 3);
        }
        assert!(!FirewallPlan::new(&policy(true), tunnel()).render().contains("skuid"));
    }

    #[test]
    fn ssh_plan_pins_socks_listener_to_alizy_ssh() {
        // Only alizy-ssh's listener (or a kernel socket, uid 0, e.g. the RST
        // for a closed port) may send from the SOCKS port: another local user
        // who binds the port first cannot impersonate the proxy.
        for ks in [true, false] {
            let r = FirewallPlan::new(&policy(ks), ssh_tunnel()).render();
            let pin = pos(
                &r,
                "    oifname \"lo\" tcp sport 1080 meta skuid != 967 meta skuid != 0 reject\n",
            );
            assert!(pos(&r, "chain output") < pin && pin < pos(&r, "    oifname \"lo\" accept\n"));
        }
        // Without a SOCKS port (e.g. a plan used only for keyscan) there is nothing to pin.
        let mut t = ssh_tunnel().unwrap();
        t.socks_port = None;
        assert!(!FirewallPlan::new(&policy(true), Some(t)).render().contains("tcp sport"));
        assert!(!FirewallPlan::new(&policy(true), tunnel())
            .render()
            .contains("tcp sport"));
    }

    #[test]
    fn ssh_plan_rejects_udp_on_tunnel_even_without_kill_switch() {
        for (ks, dns) in [(false, false), (false, true), (true, true)] {
            let p = FirewallPlan::new(
                &NetworkPolicy {
                    kill_switch: ks,
                    dns_leak_protection: dns,
                    ..Default::default()
                },
                ssh_tunnel(),
            );
            assert!(p.needs_table());
            let r = p.render();
            let udp = pos(&r, "    oifname \"alizy0\" meta l4proto udp reject\n");
            let tun = pos(&r, "    oifname \"alizy0\" accept\n");
            assert!(udp < tun);
            assert_eq!(r.contains("kill-switch"), ks);
        }
        // block_udp alone (no SSH fields) also forces the table and the reject.
        let p = FirewallPlan::new(
            &NetworkPolicy {
                dns_leak_protection: false,
                ..Default::default()
            },
            Some(TunnelRules {
                iface: TUNNEL_IFACE.into(),
                block_udp: true,
                ..Default::default()
            }),
        );
        assert!(p.needs_table());
        assert!(p.render().contains("meta l4proto udp reject"));
        assert!(!FirewallPlan::new(&policy(true), tunnel())
            .render()
            .contains("l4proto udp"));
    }

    /// connect() picks its source address from the unmarked lookup (the
    /// tunnel table), so ssh's marked packets leave the physical NIC with the
    /// tunnel address unless they are masqueraded.
    #[test]
    fn ssh_plan_masquerades_marked_ssh_traffic() {
        for ks in [true, false] {
            let r = FirewallPlan::new(&policy(ks), ssh_tunnel()).render();
            let chain = pos(
                &r,
                "  chain ssh_nat {\n    type nat hook postrouting priority srcnat; policy accept;\n",
            );
            let n4 = pos(
                &r,
                "    meta mark 0x4a5a oifname != \"alizy0\" ip daddr 203.0.113.5 tcp dport 22 masquerade\n",
            );
            let n6 = pos(
                &r,
                "    meta mark 0x4a5a oifname != \"alizy0\" ip6 daddr 2001:db8::5 tcp dport 443 masquerade\n",
            );
            assert!(chain < n4 && n4 < n6);
        }
        let wg = FirewallPlan::new(&policy(true), tunnel()).render();
        assert!(!wg.contains("ssh_nat") && !wg.contains("masquerade"));
    }

    /// Replies from the SSH server must carry the mark for strict rp_filter
    /// (src_valid_mark), and socket-less locally generated packets (timewait
    /// ACK/RST) must get it back from conntrack.
    #[test]
    fn ssh_plan_restores_conntrack_mark() {
        let r = FirewallPlan::new(&policy(false), ssh_tunnel()).render();
        let mark = pos(&r, "  chain ssh_mark {");
        let restore_out = pos(&r, "    ct mark 0x4a5a meta mark set ct mark\n");
        let set = pos(&r, "meta mark set 0x4a5a ct mark set 0x4a5a\n");
        assert!(mark < restore_out && restore_out < set);
        let pre = pos(
            &r,
            "  chain ssh_pre {\n    type filter hook prerouting priority mangle; policy accept;\n    ct mark 0x4a5a meta mark set ct mark\n  }\n",
        );
        assert!(set < pre);
        assert!(!r.contains("wg_mark") && !r.contains("wg_pre"));
        let wg = FirewallPlan::new(&policy(true), tunnel()).render();
        assert!(!wg.contains("ssh_pre") && !wg.contains("ssh_mark"));
        assert!(wg.contains("  chain wg_pre {\n    type filter hook prerouting priority mangle; policy accept;\n    ct mark 0x4a5a meta mark set ct mark\n  }\n"));
    }

    #[test]
    fn ssh_plan_rejects_forwarded_udp_on_tunnel() {
        for ks in [true, false] {
            let r = FirewallPlan::new(&policy(ks), ssh_tunnel()).render();
            let fwd = pos(
                &r,
                "  chain forward {\n    type filter hook forward priority filter - 10; policy accept;\n",
            );
            let udp = r[fwd..]
                .find("    oifname \"alizy0\" meta l4proto udp reject\n")
                .unwrap_or_else(|| panic!("no forward udp reject\n{r}"));
            if let Some(acc) = r[fwd..].find("    oifname \"alizy0\" accept\n") {
                assert!(udp < acc);
            }
            assert_eq!(r.matches("oifname \"alizy0\" meta l4proto udp reject").count(), 2);
        }
        assert!(!FirewallPlan::new(&NetworkPolicy::default(), tunnel())
            .render()
            .contains("chain forward"));
    }
}
