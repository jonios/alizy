//! SSH-tunnel profile model: public (non-secret) fields, the secret password,
//! validation, and stable fingerprints. Pure data; no I/O.

use std::fmt;
use std::net::IpAddr;

use base64::engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NOPAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const DEFAULT_SSH_PORT: u16 = 22;
pub const DEFAULT_SSH_DNS: [IpAddr; 2] = [
    IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 9)),
];

/// Returned by `HostKey::fingerprint_sha256` for undecodable key data; never
/// a valid fingerprint, so it cannot be mistaken for one.
pub const INVALID_FINGERPRINT: &str = "SHA256:invalid";

const ALLOWED_KEY_TYPES: [&str; 7] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// A pinned SSH server host key (as in a known_hosts entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKey {
    pub key_type: String,
    pub key_b64: String,
}

impl HostKey {
    /// Check that the key is safe to interpolate into a known_hosts line.
    pub fn validate(&self) -> Result<(), String> {
        if !ALLOWED_KEY_TYPES.contains(&self.key_type.as_str()) {
            return Err("unsupported host key type".into());
        }
        if self.key_b64.is_empty() || self.key_b64.len() > 8192 {
            return Err("host key must be 1-8192 characters".into());
        }
        if B64.decode(&self.key_b64).is_err() {
            return Err("host key is not valid base64".into());
        }
        Ok(())
    }

    /// OpenSSH-style fingerprint: `SHA256:<base64 without padding>`.
    pub fn fingerprint_sha256(&self) -> String {
        let Ok(raw) = B64.decode(&self.key_b64) else {
            return INVALID_FINGERPRINT.to_string();
        };
        let digest = Sha256::digest(&raw);
        format!("SHA256:{}", B64_NOPAD.encode(digest))
    }

    /// A known_hosts line for `host`/`port`.
    pub fn known_hosts_line(&self, host: IpAddr, port: u16) -> String {
        let h = if port == DEFAULT_SSH_PORT {
            host.to_string()
        } else {
            format!("[{host}]:{port}")
        };
        format!("{h} {} {}", self.key_type, self.key_b64)
    }
}

/// Non-secret SSH profile fields; safe to persist and show.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshPublic {
    pub host: IpAddr,
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub host_key: Option<HostKey>,
    #[serde(default)]
    pub dns: Vec<IpAddr>,
}

impl SshPublic {
    /// Configured DNS servers, or the defaults when none are set.
    pub fn dns_servers(&self) -> Vec<IpAddr> {
        if self.dns.is_empty() {
            DEFAULT_SSH_DNS.to_vec()
        } else {
            self.dns.clone()
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub public: SshPublic,
    pub password: Zeroizing<String>,
}

impl fmt::Debug for SshConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshConfig")
            .field("public", &self.public)
            .field("password", &"[redacted]")
            .finish()
    }
}

pub fn validate_public(p: &SshPublic) -> Result<(), String> {
    if p.host.is_unspecified() || p.host.is_multicast() || p.host.is_loopback() {
        return Err("host must be a routable IP address".into());
    }
    if p.port == 0 {
        return Err("port must be 1-65535".into());
    }
    if let Some(k) = &p.host_key {
        k.validate()?;
    }
    let u = &p.username;
    if u.is_empty() || u.chars().count() > 64 {
        return Err("username must be 1-64 characters".into());
    }
    if u.starts_with('-') {
        return Err("username must not start with '-'".into());
    }
    if u.contains('@') {
        return Err("username must not contain '@'".into());
    }
    if u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("username must not contain whitespace or control characters".into());
    }
    Ok(())
}

pub fn validate(c: &SshConfig) -> Result<(), String> {
    validate_public(&c.public)?;
    let pw = c.password.as_str();
    if pw.is_empty() || pw.len() > 1024 {
        return Err("password must be 1-1024 bytes".into());
    }
    if pw.contains(['\0', '\n', '\r']) {
        return Err("password must not contain NUL or newline characters".into());
    }
    Ok(())
}

/// Stable identity of a profile's endpoint (host, port, username): the first
/// 16 bytes of a domain-separated SHA-256, hex-encoded. Ignores password, DNS
/// and the pinned host key.
pub fn fingerprint(p: &SshPublic) -> String {
    let mut h = Sha256::new();
    h.update(b"alizy-ssh-v1\0");
    h.update(p.host.to_string().as_bytes());
    h.update(b"\0");
    h.update(p.port.to_string().as_bytes());
    h.update(b"\0");
    h.update(p.username.as_bytes());
    hex::encode(&h.finalize()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(host: &str, port: u16, user: &str, pw: &str) -> SshConfig {
        SshConfig {
            public: SshPublic {
                host: host.parse().unwrap(),
                port,
                username: user.into(),
                host_key: None,
                dns: vec![],
            },
            password: zeroize::Zeroizing::new(pw.to_string()),
        }
    }

    #[test]
    fn validate_accepts_minimal() {
        assert!(validate(&cfg("192.0.2.10", 22, "alice", "pw")).is_ok());
    }

    #[test]
    fn validate_rejects_each_bad_field() {
        let long_user = "a".repeat(65);
        let long_pw = "p".repeat(1025);
        let bad = [
            cfg("192.0.2.10", 0, "alice", "pw"),
            cfg("192.0.2.10", 22, "", "pw"),
            cfg("192.0.2.10", 22, "-oProxyCommand=x", "pw"),
            cfg("192.0.2.10", 22, "a b", "pw"),
            cfg("192.0.2.10", 22, "a@b", "pw"),
            cfg("192.0.2.10", 22, &long_user, "pw"),
            cfg("192.0.2.10", 22, "alice", ""),
            cfg("192.0.2.10", 22, "alice", "a\nb"),
            cfg("192.0.2.10", 22, "alice", "a\rb"),
            cfg("192.0.2.10", 22, "alice", "a\0b"),
            cfg("192.0.2.10", 22, "alice", &long_pw),
            cfg("0.0.0.0", 22, "alice", "pw"),
            cfg("127.0.0.1", 22, "alice", "pw"),
            cfg("224.0.0.1", 22, "alice", "pw"),
        ];
        for c in &bad {
            assert!(validate(c).is_err(), "should reject {:?}", c.public);
        }
    }

    #[test]
    fn fingerprint_stable_and_ignores_password_and_dns() {
        let a = cfg("192.0.2.10", 22, "alice", "one");
        let mut b = cfg("192.0.2.10", 22, "alice", "two");
        b.public.dns = vec!["8.8.8.8".parse().unwrap()];
        assert_eq!(fingerprint(&a.public), fingerprint(&b.public));
        assert_eq!(fingerprint(&a.public).len(), 32);
        let c = cfg("192.0.2.10", 2222, "alice", "one");
        assert_ne!(fingerprint(&a.public), fingerprint(&c.public));
    }

    #[test]
    fn debug_redacts_password() {
        let c = cfg("192.0.2.10", 22, "alice", "hunter2");
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn known_hosts_line_formats() {
        let k = HostKey {
            key_type: "ssh-ed25519".into(),
            key_b64: "AAA".into(),
        };
        assert_eq!(
            k.known_hosts_line("192.0.2.1".parse().unwrap(), 22),
            "192.0.2.1 ssh-ed25519 AAA"
        );
        assert_eq!(
            k.known_hosts_line("2001:db8::1".parse().unwrap(), 2222),
            "[2001:db8::1]:2222 ssh-ed25519 AAA"
        );
    }

    #[test]
    fn sha256_fingerprint_matches_openssh() {
        let k = HostKey {
            key_type: "ssh-ed25519".into(),
            key_b64: "AAAAC3NzaC1lZDI1NTE5AAAAICJ9AyQ1/Hf8ky/h28JhISjg1GkKGhTejR6j6uTwPF1l".into(),
        };
        assert_eq!(
            k.fingerprint_sha256(),
            "SHA256:O8fctiFq1xVT6FOLWYX8ZuvndZbyHpgUl6l8Ez7SXSc"
        );
    }

    fn good_key() -> HostKey {
        HostKey {
            key_type: "ssh-ed25519".into(),
            key_b64: "AAAAC3NzaC1lZDI1NTE5AAAAICJ9AyQ1/Hf8ky/h28JhISjg1GkKGhTejR6j6uTwPF1l".into(),
        }
    }

    #[test]
    fn host_key_validation() {
        assert!(good_key().validate().is_ok());
        let mut k = good_key();
        k.key_b64 = "AAAA\nssh-rsa BBBB".into();
        assert!(k.validate().is_err());
        k.key_b64 = "not base64!!".into();
        assert!(k.validate().is_err());
        assert_eq!(k.fingerprint_sha256(), INVALID_FINGERPRINT);
        k.key_b64 = String::new();
        assert!(k.validate().is_err());
        k.key_b64 = "A".repeat(8196);
        assert!(k.validate().is_err());
        let mut k = good_key();
        k.key_type = "ssh-dss".into();
        assert!(k.validate().is_err());
        k.key_type = "ssh-ed25519 evil".into();
        assert!(k.validate().is_err());
    }

    #[test]
    fn validate_public_rejects_bad_host_key() {
        let mut c = cfg("192.0.2.10", 22, "alice", "pw");
        c.public.host_key = Some(good_key());
        assert!(validate(&c).is_ok());
        let mut bad = good_key();
        bad.key_b64 = "AAAA\nevil".into();
        c.public.host_key = Some(bad);
        assert!(validate(&c).is_err());
    }

    #[test]
    fn dns_servers_defaults() {
        let mut p = cfg("192.0.2.10", 22, "alice", "pw").public;
        assert_eq!(p.dns_servers(), DEFAULT_SSH_DNS.to_vec());
        p.dns = vec!["8.8.8.8".parse().unwrap()];
        assert_eq!(p.dns_servers(), vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    }
}
