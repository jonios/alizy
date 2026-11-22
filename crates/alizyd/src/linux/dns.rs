//! DNS backends: systemd-resolved (per-link), resolvconf/openresolv
//! (per-interface record), or a backed-up /etc/resolv.conf rewrite.
//! The backend is chosen from detected facts (see `alizy_core::sysprobe`).

use crate::exec::{argv, run};
use alizy_core::routing::DnsPlan;
use alizy_core::sysprobe::{choose_dns_backend, find_exe, DnsBackend};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const RESOLV_CONF: &str = "/etc/resolv.conf";

pub struct Dns {
    backup: PathBuf,
    /// When /etc/resolv.conf was a symlink, its target is saved here so the
    /// link (not just the content) is restored.
    link_backup: PathBuf,
    resolv_conf: PathBuf,
}

pub async fn detect_backend() -> DnsBackend {
    let resolved = run(
        &argv(&["systemctl", "is-active", "--quiet", "systemd-resolved.service"]),
        None,
    )
    .await
    .is_ok();
    let target = std::fs::canonicalize(RESOLV_CONF)
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    choose_dns_backend(resolved, target.as_deref(), find_exe("resolvconf").is_some())
}

impl Dns {
    pub fn new(state_dir: &Path, resolv_conf: Option<PathBuf>) -> Self {
        Self {
            resolv_conf: resolv_conf.unwrap_or_else(|| PathBuf::from(RESOLV_CONF)),
            backup: state_dir.join("resolv.conf.backup"),
            link_backup: state_dir.join("resolv.conf.link"),
        }
    }

    pub async fn apply(&self, backend: DnsBackend, iface: &str, plan: &DnsPlan) -> Result<(), String> {
        if plan.servers.is_empty() {
            return Ok(());
        }
        match backend {
            DnsBackend::SystemdResolved => {
                for cmd in plan.resolvectl_commands(iface) {
                    run(&cmd, None).await.map_err(|e| format!("resolvectl: {e}"))?;
                }
                Ok(())
            }
            DnsBackend::Resolvconf => {
                let body = plan.resolv_conf();
                // `-x` (exclusive) is openresolv-only; try it first, then plain.
                let ex = run(
                    &argv(&["resolvconf", "-a", iface, "-m", "0", "-x"]),
                    Some(body.as_bytes()),
                )
                .await;
                if ex.is_err() {
                    run(&argv(&["resolvconf", "-a", iface, "-m", "0"]), Some(body.as_bytes()))
                        .await
                        .map_err(|e| format!("resolvconf: {e}"))?;
                }
                Ok(())
            }
            DnsBackend::ResolvConfFile => self.write_resolv_conf(plan),
        }
    }

    fn write_resolv_conf(&self, plan: &DnsPlan) -> Result<(), String> {
        let current = std::fs::read(&self.resolv_conf).unwrap_or_default();
        let ours = plan.resolv_conf();
        if !self.backup.exists() && current != ours.as_bytes() {
            if let Ok(target) = std::fs::read_link(&self.resolv_conf) {
                write_private(&self.link_backup, target.to_string_lossy().as_bytes())?;
            }
            write_private(&self.backup, &current)?;
        }
        replace_file(self.resolv_conf.as_path(), ours.as_bytes(), 0o644)
    }

    /// Re-assert our resolv.conf if another manager (e.g. NetworkManager) rewrote it.
    pub fn reassert(&self, backend: DnsBackend, plan: &DnsPlan) -> Result<bool, String> {
        if backend != DnsBackend::ResolvConfFile || plan.servers.is_empty() {
            return Ok(false);
        }
        let current = std::fs::read_to_string(&self.resolv_conf).unwrap_or_default();
        if current == plan.resolv_conf() {
            return Ok(false);
        }
        // The other manager's new content becomes the version to restore.
        write_private(&self.backup, current.as_bytes())?;
        replace_file(self.resolv_conf.as_path(), plan.resolv_conf().as_bytes(), 0o644)?;
        Ok(true)
    }

    pub async fn revert(&self, backend: DnsBackend, iface: &str) -> Result<(), String> {
        match backend {
            // Link-scoped settings vanish with the interface; revert explicitly anyway.
            DnsBackend::SystemdResolved => {
                if super::wireguard::exists(iface) {
                    let _ = run(&argv(&["resolvectl", "revert", iface]), None).await;
                }
            }
            DnsBackend::Resolvconf => {
                let _ = run(&argv(&["resolvconf", "-d", iface, "-f"]), None).await;
            }
            DnsBackend::ResolvConfFile => {}
        }
        // Always restore a pending backup, whatever the current backend
        // (covers a crash followed by a backend change).
        self.restore_backup()
    }

    pub fn restore_backup(&self) -> Result<(), String> {
        if let Ok(target) = std::fs::read_to_string(&self.link_backup) {
            let tmp = self.resolv_conf.as_path().with_extension("alizy-tmp");
            let _ = std::fs::remove_file(&tmp);
            std::os::unix::fs::symlink(target.trim(), &tmp).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &self.resolv_conf).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&self.link_backup);
            let _ = std::fs::remove_file(&self.backup);
            return Ok(());
        }
        if let Ok(original) = std::fs::read(&self.backup) {
            replace_file(self.resolv_conf.as_path(), &original, 0o644)?;
            std::fs::remove_file(&self.backup).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    replace_file(path, data, 0o600)
}

/// Atomic replace (write temp + rename). If `path` is a symlink, the link itself
/// is replaced by a regular file; the original link target is untouched.
fn replace_file(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let tmp = path.with_extension("alizy-tmp");
    std::fs::write(&tmp, data).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replace {}: {e}", path.display()))
}
