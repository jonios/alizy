//! WireGuard key types.
//!
//! `SecretKey` is zeroized on drop and never prints its value through `Debug`
//! or `Display`. It serialises to base64 only through serde, which is used
//! exclusively for the authenticated daemon IPC and the secret store.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("key is not valid base64")]
    Base64,
    #[error("key must decode to exactly 32 bytes")]
    Length,
}

fn decode32(s: &str) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let s = s.trim();
    // A 32-byte key is always 44 base64 characters with one '=' of padding.
    if s.len() != 44 {
        return Err(KeyError::Length);
    }
    let bytes = Zeroizing::new(B64.decode(s).map_err(|_| KeyError::Base64)?);
    if bytes.len() != 32 {
        return Err(KeyError::Length);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// A public key (not secret). Displayed as base64.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn parse(s: &str) -> Result<Self, KeyError> {
        Ok(Self(*decode32(s)?))
    }
    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_base64())
    }
}
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}
impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64())
    }
}
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PublicKey::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A private key or pre-shared key. Zeroized on drop, redacted in Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    pub fn parse(s: &str) -> Result<Self, KeyError> {
        Ok(Self(decode32(s)?))
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }
    /// Explicitly expose the base64 encoding. Callers must not log the result.
    pub fn expose_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(B64.encode(*self.0))
    }
    /// Derive the X25519 public key (only meaningful for interface private keys).
    pub fn public_key(&self) -> PublicKey {
        let secret = x25519_dalek::StaticSecret::from(*self.0);
        PublicKey(*x25519_dalek::PublicKey::from(&secret).as_bytes())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([redacted])")
    }
}

impl Serialize for SecretKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.expose_base64())
    }
}
impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        SecretKey::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7748 test vector (Alice).
    const ALICE_PRIV: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
    const ALICE_PUB: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";

    #[test]
    fn derives_public_key() {
        let k = SecretKey::parse(ALICE_PRIV).unwrap();
        assert_eq!(k.public_key().to_base64(), ALICE_PUB);
    }

    #[test]
    fn debug_is_redacted() {
        let k = SecretKey::parse(ALICE_PRIV).unwrap();
        let d = format!("{k:?}");
        assert!(!d.contains("dwdt"));
        assert!(d.contains("redacted"));
    }

    #[test]
    fn rejects_bad_keys() {
        assert_eq!(PublicKey::parse("abc"), Err(KeyError::Length));
        assert!(PublicKey::parse(&"!".repeat(44)).is_err());
    }
}
