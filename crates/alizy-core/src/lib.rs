//! Platform-neutral core of Alizy. No Tauri, no I/O side effects: everything
//! here is pure and unit-testable without privileges.

pub mod config;
pub mod dnswire;
pub mod firewall;
pub mod ipc;
pub mod keys;
pub mod platform;
pub mod profile;
pub mod routing;
pub mod split;
pub mod state;
pub mod sysprobe;

pub use config::{parse, ConfigError, ParseOutcome, PublicConfig, WgConfig};
pub use firewall::{FirewallPlan, NetworkPolicy};
pub use state::ConnectionState;

/// Replace anything that looks like a base64 WireGuard key with `[redacted]`.
/// Applied to every external tool's stderr before it is logged or returned.
pub fn redact_keys(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let is_b64 = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/';
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if is_b64(chars[i]) {
            let start = i;
            while i < chars.len() && is_b64(chars[i]) {
                i += 1;
            }
            if i - start == 43 && chars.get(i) == Some(&'=') {
                out.push_str("[redacted]");
                i += 1;
            } else {
                out.extend(&chars[start..i]);
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod redact_tests {
    #[test]
    fn redacts_keys() {
        let s = "Line unrecognized: `PrivateKey=dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo='";
        let r = super::redact_keys(s);
        assert!(!r.contains("dwdt"));
        assert!(r.contains("[redacted]"));
        assert_eq!(
            super::redact_keys("RTNETLINK answers: File exists"),
            "RTNETLINK answers: File exists"
        );
    }
}
