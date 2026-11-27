//! Durable daemon state (no secrets): network policy, split rules, DNS cache.
//! Written atomically with 0600 permissions.

use crate::resolver::Cache;
use alizy_core::firewall::NetworkPolicy;
use alizy_core::ipc::LanProxyConfig;
use alizy_core::split::SplitConfig;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PersistedState {
    pub version: u32,
    pub policy: NetworkPolicy,
    pub split: SplitConfig,
    pub dns_cache: Cache,
    /// LAN forward proxy (share this machine's VPN with other devices).
    #[serde(default)]
    pub lan_proxy: LanProxyConfig,
    /// Last successfully resolved address for each hostname endpoint
    /// ("host:port"). Used when DNS is unavailable — notably while the kill
    /// switch blocks everything and no tunnel exists yet.
    #[serde(default)]
    pub endpoint_cache: std::collections::BTreeMap<String, std::net::SocketAddr>,
}

pub struct Persist {
    path: PathBuf,
}

impl Persist {
    pub fn new(state_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            path: state_dir.join("state.json"),
        })
    }

    /// Load state. A corrupt file is moved aside and the *safest* defaults are
    /// used: if the old file mentioned an enabled kill switch we keep it on.
    pub fn load(&self) -> PersistedState {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return PersistedState {
                version: 1,
                ..Default::default()
            };
        };
        match serde_json::from_str::<PersistedState>(&text) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("state file is corrupt ({e}); moving it aside");
                let _ = std::fs::rename(&self.path, self.path.with_extension("json.corrupt"));
                let ks = text.contains("\"kill_switch\":true") || text.contains("\"kill_switch\": true");
                PersistedState {
                    version: 1,
                    policy: NetworkPolicy {
                        kill_switch: ks,
                        ..Default::default()
                    },
                    ..Default::default()
                }
            }
        }
    }

    pub fn save(&self, s: &PersistedState) -> Result<(), String> {
        let tmp = self.path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_proxy_survives_a_save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = Persist::new(dir.path()).unwrap();
        let s = PersistedState {
            lan_proxy: LanProxyConfig {
                enabled: true,
                port: 9090,
                socks_port: 1080,
                auth: None,
            },
            ..Default::default()
        };
        p.save(&s).unwrap();
        assert_eq!(p.load().lan_proxy, s.lan_proxy);
    }

    #[test]
    fn a_state_file_without_lan_proxy_still_loads() {
        // Written by an older daemon: no lan_proxy field at all.
        let dir = tempfile::tempdir().unwrap();
        let p = Persist::new(dir.path()).unwrap();
        std::fs::write(
            dir.path().join("state.json"),
            r#"{"version":1,"policy":{"kill_switch":true}}"#,
        )
        .unwrap();
        let s = p.load();
        assert!(s.policy.kill_switch);
        assert_eq!(s.lan_proxy, LanProxyConfig::default());
        assert!(!s.lan_proxy.enabled);
    }
}
