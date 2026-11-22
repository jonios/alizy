//! Profile manager: import (text, files, directories, backups), validation,
//! duplicate detection, editing, duplication, export, deletion.
//! Independent of Tauri; used by the GUI shell.

use crate::db::{now, Db, DbError, ProfileRow};
use crate::secrets::{SecretError, SecretStore};
use alizy_core::config::{parse, ProfileSecrets, WgConfig, MAX_CONFIG_BYTES};
use alizy_core::keys::PublicKey;
use alizy_core::profile::{fingerprint, name_from_filename, sanitize_name};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroizing;

pub const MAX_DIR_FILES: usize = 1000;
pub const MAX_BACKUP_BYTES: u64 = 32 * 1024 * 1024;
const REDACTED: &str = "<redacted>";

#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Secret(#[from] SecretError),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ImportReport {
    pub imported: Vec<ProfileRow>,
    pub duplicates: Vec<Duplicate>,
    pub errors: Vec<SourceError>,
    pub warnings: Vec<SourceWarnings>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Duplicate {
    pub source: String,
    pub name: String,
    pub existing_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceError {
    pub source: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceWarnings {
    pub source: String,
    pub messages: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Backup {
    format: String,
    version: u32,
    created_at: i64,
    profiles: Vec<BackupProfile>,
}

#[derive(Serialize, Deserialize)]
struct BackupProfile {
    name: String,
    category: Option<String>,
    favorite: bool,
    config: String,
}

pub struct ProfileManager {
    pub db: Db,
    pub secrets: SecretStore,
}

fn base_fp(fp: &str) -> &str {
    fp.split('~').next().unwrap_or(fp)
}

/// Write a file that may contain secrets: 0600, atomic replace.
pub fn write_private_file(path: &Path, data: &[u8]) -> Result<(), ManagerError> {
    // Fresh, unpredictable temp name, created exclusively and never through a
    // symlink, so a pre-planted file in a shared directory cannot capture keys.
    let tmp = path.with_extension(format!("alizy-{}.partial", uuid::Uuid::new_v4().simple()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| ManagerError::Io(format!("{}: {e}", tmp.display())))?;
    f.write_all(data).map_err(|e| ManagerError::Io(e.to_string()))?;
    f.sync_all().map_err(|e| ManagerError::Io(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| ManagerError::Io(format!("{}: {e}", path.display())))
}

fn read_limited(path: &Path, max: u64) -> Result<String, String> {
    let md = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !md.is_file() {
        return Err("not a regular file".into());
    }
    if md.len() > max {
        return Err(format!("file is larger than {max} bytes"));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|_| "file is not valid UTF-8 text".into())
}

impl ProfileManager {
    pub fn new(db: Db, secrets: SecretStore) -> Self {
        Self { db, secrets }
    }

    async fn find_duplicate(&self, fp: &str, exclude: Option<&str>) -> Result<Option<ProfileRow>, ManagerError> {
        let all = self.db.list_profiles().await?;
        Ok(all
            .into_iter()
            .find(|p| base_fp(&p.fingerprint) == fp && Some(p.id.as_str()) != exclude))
    }

    async fn unique_name(&self, wanted: &str) -> Result<String, ManagerError> {
        if !self.db.name_exists(wanted).await? {
            return Ok(wanted.to_string());
        }
        for i in 2..10_000 {
            let n = format!("{wanted} ({i})");
            if !self.db.name_exists(&n).await? {
                return Ok(n);
            }
        }
        Err(ManagerError::Invalid("too many profiles with this name".into()))
    }

    async fn store_new(&self, cfg: &WgConfig, name: &str, fp: String) -> Result<ProfileRow, ManagerError> {
        let (public, secrets) = cfg.split();
        let id = uuid::Uuid::new_v4().to_string();
        let t = now();
        let row = ProfileRow {
            id: id.clone(),
            name: self.unique_name(name).await?,
            category: None,
            favorite: false,
            fingerprint: fp,
            config: public,
            cached_endpoints: Vec::new(),
            created_at: t,
            updated_at: t,
            last_connected_at: None,
        };
        // Secret first; if the DB insert fails, remove the orphaned secret.
        self.secrets.put(&id, &secrets)?;
        if let Err(e) = self.db.insert_profile(&row).await {
            let _ = self.secrets.delete(&id);
            return Err(e.into());
        }
        Ok(row)
    }

    async fn import_one(&self, source: &str, text: &str, name_hint: Option<&str>, report: &mut ImportReport) {
        let outcome = match parse(text) {
            Ok(o) => o,
            Err(e) => {
                report.errors.push(SourceError {
                    source: source.into(),
                    message: e.to_string(),
                });
                return;
            }
        };
        let (public, _) = outcome.config.split();
        let fp = fingerprint(&public);
        let name = name_hint.and_then(sanitize_name).unwrap_or_else(|| {
            public
                .peers
                .iter()
                .find_map(|p| p.endpoint.as_ref().map(|e| e.to_string()))
                .unwrap_or_else(|| "WireGuard profile".into())
        });
        match self.find_duplicate(&fp, None).await {
            Ok(Some(existing)) => {
                report.duplicates.push(Duplicate {
                    source: source.into(),
                    name: existing.name,
                    existing_id: existing.id,
                });
                return;
            }
            Ok(None) => {}
            Err(e) => {
                report.errors.push(SourceError {
                    source: source.into(),
                    message: e.to_string(),
                });
                return;
            }
        }
        match self.store_new(&outcome.config, &name, fp).await {
            Ok(row) => {
                if !outcome.warnings.is_empty() {
                    report.warnings.push(SourceWarnings {
                        source: source.into(),
                        messages: outcome.warnings,
                    });
                }
                report.imported.push(row);
            }
            Err(e) => report.errors.push(SourceError {
                source: source.into(),
                message: e.to_string(),
            }),
        }
    }

    pub async fn validate(&self, text: &str) -> Result<(alizy_core::PublicConfig, Vec<String>), String> {
        parse(text)
            .map(|o| (o.config.split().0, o.warnings))
            .map_err(|e| e.to_string())
    }

    pub async fn import_text(&self, text: &str, name: Option<&str>) -> ImportReport {
        let mut r = ImportReport::default();
        self.import_one("pasted text", text, name, &mut r).await;
        r
    }

    /// Import files and/or directories (each directory: `*.conf`, non-recursive).
    pub async fn import_paths(&self, paths: &[String]) -> ImportReport {
        let mut r = ImportReport::default();
        for p in paths {
            let path = Path::new(p);
            if path.is_dir() {
                let mut files: Vec<_> = match std::fs::read_dir(path) {
                    Ok(rd) => rd
                        .flatten()
                        .map(|e| e.path())
                        .filter(|f| f.extension().map(|x| x.eq_ignore_ascii_case("conf")).unwrap_or(false))
                        .collect(),
                    Err(e) => {
                        r.errors.push(SourceError {
                            source: p.clone(),
                            message: e.to_string(),
                        });
                        continue;
                    }
                };
                files.sort();
                if files.is_empty() {
                    r.errors.push(SourceError {
                        source: p.clone(),
                        message: "folder contains no .conf files".into(),
                    });
                }
                if files.len() > MAX_DIR_FILES {
                    r.errors.push(SourceError {
                        source: p.clone(),
                        message: format!("only the first {MAX_DIR_FILES} files were imported"),
                    });
                    files.truncate(MAX_DIR_FILES);
                }
                for f in files {
                    self.import_file(&f, &mut r).await;
                }
            } else {
                self.import_file(path, &mut r).await;
            }
        }
        r
    }

    async fn import_file(&self, path: &Path, r: &mut ImportReport) {
        let source = path.display().to_string();
        match read_limited(path, MAX_CONFIG_BYTES as u64) {
            Ok(text) => {
                let text = Zeroizing::new(text);
                let name = path.file_name().and_then(|n| name_from_filename(&n.to_string_lossy()));
                self.import_one(&source, &text, name.as_deref(), r).await
            }
            Err(e) => r.errors.push(SourceError { source, message: e }),
        }
    }

    pub async fn full_config(&self, id: &str) -> Result<WgConfig, ManagerError> {
        let row = self.db.get_profile(id).await?;
        let secrets = self.secrets.get(id)?;
        WgConfig::join(&row.config, &secrets).map_err(|e| ManagerError::Invalid(e.to_string()))
    }

    pub async fn reveal_private_key(&self, id: &str) -> Result<Zeroizing<String>, ManagerError> {
        self.db.get_profile(id).await?;
        Ok(self.secrets.get(id)?.private_key.expose_base64())
    }

    /// Replace `<redacted>` placeholders with stored secrets, section by section.
    fn restore_placeholders(text: &str, stored: &ProfileSecrets) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::new());
        let mut sections: Vec<Vec<&str>> = vec![vec![]];
        for line in text.lines() {
            if line.trim_start().starts_with('[') {
                sections.push(vec![]);
            }
            sections.last_mut().unwrap().push(line);
        }
        for sec in sections {
            let peer_pk = sec.iter().find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim().eq_ignore_ascii_case("publickey"))
                    .then(|| PublicKey::parse(v.trim()).ok())
                    .flatten()
            });
            for line in sec {
                let replaced = line.split_once('=').and_then(|(k, v)| {
                    if v.trim() != REDACTED {
                        return None;
                    }
                    match k.trim().to_ascii_lowercase().as_str() {
                        "privatekey" => Some(format!("PrivateKey = {}", stored.private_key.expose_base64().as_str())),
                        "presharedkey" => peer_pk.and_then(|pk| {
                            stored
                                .preshared_keys
                                .iter()
                                .find(|(p, _)| *p == pk)
                                .map(|(_, k)| format!("PresharedKey = {}", k.expose_base64().as_str()))
                        }),
                        _ => None,
                    }
                });
                out.push_str(replaced.as_deref().unwrap_or(line));
                out.push('\n');
            }
        }
        out
    }

    /// Edit the configuration text. Returns parser warnings.
    pub async fn update_text(&self, id: &str, text: &str) -> Result<Vec<String>, ManagerError> {
        let row = self.db.get_profile(id).await?;
        let stored = self.secrets.get(id)?;
        let text = Self::restore_placeholders(text, &stored);
        if text.contains(REDACTED) {
            return Err(ManagerError::Invalid(
                "a <redacted> placeholder could not be matched to a stored key".into(),
            ));
        }
        let outcome = parse(&text).map_err(|e| ManagerError::Invalid(e.to_string()))?;
        let (public, secrets) = outcome.config.split();
        let fp = fingerprint(&public);
        // Cosmetic edits keep the profile's identity; intentional copies share
        // it with their original. Only refuse an edit that turns this profile
        // into a *different* existing identity.
        if fp != base_fp(&row.fingerprint) {
            if let Some(d) = self.find_duplicate(&fp, Some(id)).await? {
                return Err(ManagerError::Invalid(format!(
                    "this configuration duplicates profile \"{}\"",
                    d.name
                )));
            }
        }
        // keep a "~copy" suffix if this row was an intentional duplicate
        let fp = match row.fingerprint.split_once('~') {
            Some((_, suffix)) => format!("{fp}~{suffix}"),
            None => fp,
        };
        self.secrets.put(id, &secrets)?;
        self.db.update_config(id, &public, &fp).await?;
        Ok(outcome.warnings)
    }

    /// Intentional copy (same keys). Marked so that import still detects the original.
    pub async fn duplicate(&self, id: &str) -> Result<ProfileRow, ManagerError> {
        let row = self.db.get_profile(id).await?;
        let cfg = self.full_config(id).await?;
        let fp = format!(
            "{}~{}",
            base_fp(&row.fingerprint),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let mut new = self.store_new(&cfg, &format!("{} copy", row.name), fp).await?;
        if row.category.is_some() {
            self.db.set_category(&new.id, row.category.as_deref()).await?;
            new.category = row.category;
        }
        Ok(new)
    }

    pub async fn delete(&self, id: &str) -> Result<(), ManagerError> {
        self.db.delete_profile(id).await?;
        self.secrets.delete(id)?;
        Ok(())
    }

    pub async fn export(&self, id: &str, path: &Path, include_private: bool) -> Result<(), ManagerError> {
        let text = if include_private {
            self.full_config(id).await?.to_wg_quick(true)
        } else {
            let row = self.db.get_profile(id).await?;
            // Redacted export does not need secrets from the store.
            redacted_text(&row)
        };
        write_private_file(path, text.as_bytes())
    }

    pub async fn backup(&self, path: &Path) -> Result<usize, ManagerError> {
        let rows = self.db.list_profiles().await?;
        let mut profiles = Vec::with_capacity(rows.len());
        for r in &rows {
            let cfg = self.full_config(&r.id).await?;
            profiles.push(BackupProfile {
                name: r.name.clone(),
                category: r.category.clone(),
                favorite: r.favorite,
                config: cfg.to_wg_quick(true).to_string(),
            });
        }
        let b = Backup {
            format: "alizy-backup".into(),
            version: 1,
            created_at: now(),
            profiles,
        };
        let json = Zeroizing::new(serde_json::to_vec_pretty(&b).map_err(|e| ManagerError::Io(e.to_string()))?);
        write_private_file(path, &json)?;
        Ok(rows.len())
    }

    pub async fn restore(&self, path: &Path) -> Result<ImportReport, ManagerError> {
        let text = Zeroizing::new(read_limited(path, MAX_BACKUP_BYTES).map_err(ManagerError::Io)?);
        let b: Backup =
            serde_json::from_str(&text).map_err(|e| ManagerError::Invalid(format!("not an Alizy backup: {e}")))?;
        if b.format != "alizy-backup" || b.version != 1 {
            return Err(ManagerError::Invalid("unsupported backup format".into()));
        }
        let mut r = ImportReport::default();
        for p in b.profiles {
            let before = r.imported.len();
            self.import_one(&p.name, &p.config, Some(&p.name), &mut r).await;
            if r.imported.len() > before {
                let row = r.imported.last_mut().unwrap();
                if p.favorite {
                    self.db.set_favorite(&row.id, true).await?;
                    row.favorite = true;
                }
                if let Some(c) = p.category.as_deref().and_then(sanitize_name) {
                    self.db.set_category(&row.id, Some(&c)).await?;
                    row.category = Some(c);
                }
            }
        }
        Ok(r)
    }
}

/// wg-quick text from the public projection, secrets shown as `<redacted>`.
pub fn redacted_text(row: &ProfileRow) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::from("[Interface]\nPrivateKey = <redacted>\n"));
    let c = &row.config;
    let join = |v: Vec<String>| v.join(", ");
    s.push_str(&format!(
        "Address = {}\n",
        join(c.addresses.iter().map(ToString::to_string).collect())
    ));
    let mut dns: Vec<String> = c.dns.iter().map(ToString::to_string).collect();
    dns.extend(c.dns_search.iter().cloned());
    if !dns.is_empty() {
        s.push_str(&format!("DNS = {}\n", join(dns)));
    }
    if let Some(m) = c.mtu {
        s.push_str(&format!("MTU = {m}\n"));
    }
    if let Some(p) = c.listen_port {
        s.push_str(&format!("ListenPort = {p}\n"));
    }
    for p in &c.peers {
        s.push_str(&format!("\n[Peer]\nPublicKey = {}\n", p.public_key));
        if p.has_preshared_key {
            s.push_str("PresharedKey = <redacted>\n");
        }
        if !p.allowed_ips.is_empty() {
            s.push_str(&format!(
                "AllowedIPs = {}\n",
                join(p.allowed_ips.iter().map(ToString::to_string).collect())
            ));
        }
        if let Some(e) = &p.endpoint {
            s.push_str(&format!("Endpoint = {e}\n"));
        }
        if let Some(k) = p.persistent_keepalive {
            s.push_str(&format!("PersistentKeepalive = {k}\n"));
        }
    }
    s
}
