//! Profile identity helpers: fingerprints for duplicate detection and name sanitising.

use crate::config::PublicConfig;
use sha2::{Digest, Sha256};

/// A stable fingerprint of the cryptographic identity of a profile.
///
/// Two configs are duplicates when they use the same interface key and the
/// same set of peers (public key + endpoint). Cosmetic changes (DNS, MTU,
/// comments, ordering) do not change the fingerprint.
pub fn fingerprint(cfg: &PublicConfig) -> String {
    let mut peers: Vec<String> = cfg
        .peers
        .iter()
        .map(|p| {
            format!(
                "{}@{}",
                p.public_key,
                p.endpoint.as_ref().map(ToString::to_string).unwrap_or_default()
            )
        })
        .collect();
    peers.sort();
    let mut h = Sha256::new();
    h.update(b"alizy-fp-v1\0");
    h.update(cfg.interface_public_key.as_bytes());
    for p in peers {
        h.update(b"\0");
        h.update(p.as_bytes());
    }
    hex::encode(&h.finalize()[..16])
}

pub const MAX_NAME_LEN: usize = 64;

/// Normalise a user-supplied profile name. Returns `None` if nothing usable remains.
pub fn sanitize_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let truncated: String = cleaned.chars().take(MAX_NAME_LEN).collect();
    (!truncated.is_empty()).then_some(truncated)
}

/// Derive a profile name from a file name like `/x/de-frankfurt-01.conf`.
pub fn name_from_filename(file_name: &str) -> Option<String> {
    let base = file_name.rsplit(['/', '\\']).next().unwrap_or(file_name);
    let stem = base
        .strip_suffix(".conf")
        .or_else(|| base.strip_suffix(".CONF"))
        .unwrap_or(base);
    sanitize_name(&stem.replace(['_'], " "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse, tests::sample};

    #[test]
    fn fingerprint_ignores_cosmetics() {
        let a = parse(&sample()).unwrap().config.split().0;
        let b = parse(
            &sample()
                .replace("MTU = 1420", "MTU = 1380")
                .replace("# provider config", ""),
        )
        .unwrap()
        .config
        .split()
        .0;
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_with_endpoint() {
        let a = parse(&sample()).unwrap().config.split().0;
        let b = parse(&sample().replace("vpn.example.com", "vpn2.example.com"))
            .unwrap()
            .config
            .split()
            .0;
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn names() {
        assert_eq!(
            name_from_filename("/tmp/de_frankfurt-01.conf").unwrap(),
            "de frankfurt-01"
        );
        assert_eq!(sanitize_name("  a\u{7}  b "), Some("a b".into()));
        assert_eq!(sanitize_name("   "), None);
        assert_eq!(sanitize_name(&"x".repeat(100)).unwrap().len(), MAX_NAME_LEN);
    }
}
