//! Secret storage for private keys, pre-shared keys and SSH passwords.
//!
//! SSH passwords are stored under the id `"ssh:" + profile id` in the same
//! backend as WireGuard secrets.
//!
//! Primary backend: the OS credential store (Secret Service on Linux via
//! libsecret/KWallet/GNOME Keyring, through the `keyring` crate). Fallback,
//! only when no Secret Service is reachable: one JSON file per profile in a
//! 0700 directory with 0600 permissions. The active backend is reported to
//! the UI so the user knows which one protects their keys.

use alizy_core::config::ProfileSecrets;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const SERVICE: &str = "io.alizy.app";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    Keyring,
    File(PathBuf),
}

impl Backend {
    pub fn name(&self) -> &'static str {
        match self {
            Backend::Keyring => "keyring",
            Backend::File(_) => "file",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret store: {0}")]
    Store(String),
    #[error("no stored key for this profile")]
    Missing,
}

pub struct SecretStore {
    backend: Backend,
    /// The 0600 file directory: the active store when no Secret Service is
    /// usable, and always consulted as a migration source.
    file_dir: PathBuf,
    fallback_reason: Option<String>,
}

fn user(id: &str) -> String {
    format!("profile:{id}")
}

fn ssh_id(id: &str) -> String {
    format!("ssh:{id}")
}

fn store_err(e: impl std::fmt::Display) -> SecretError {
    SecretError::Store(e.to_string())
}

fn explain(e: &keyring::Error) -> String {
    match e {
        keyring::Error::NoStorageAccess(_) => format!(
            "the Secret Service has no usable default keyring ({e}). Create or set a default keyring (e.g. in \"Passwords and Keys\"/Seahorse) and unlock it"
        ),
        keyring::Error::PlatformFailure(_) => format!("no Secret Service is reachable ({e})"),
        other => other.to_string(),
    }
}

fn file_put(dir: &Path, id: &str, json: &str) -> Result<(), SecretError> {
    std::fs::create_dir_all(dir).map_err(store_err)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(store_err)?;
    let path = dir.join(format!("{id}.json"));
    let tmp = dir.join(format!(".{id}.tmp"));
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(store_err)?;
        f.write_all(json.as_bytes()).map_err(store_err)?;
        f.sync_all().map_err(store_err)?;
    }
    std::fs::rename(&tmp, &path).map_err(store_err)
}

fn file_get(dir: &Path, id: &str) -> Result<Zeroizing<String>, SecretError> {
    match std::fs::read_to_string(dir.join(format!("{id}.json"))) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SecretError::Missing),
        Err(e) => Err(store_err(e)),
    }
}

fn file_delete(dir: &Path, id: &str) -> Result<(), SecretError> {
    match std::fs::remove_file(dir.join(format!("{id}.json"))) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(store_err(e)),
    }
}

fn parse(json: &str) -> Result<ProfileSecrets, SecretError> {
    serde_json::from_str(json).map_err(|e| SecretError::Store(format!("corrupt secret: {e}")))
}

impl SecretStore {
    /// Probe the keyring with a round-trip; fall back to files in `fallback_dir`.
    pub fn detect(fallback_dir: &Path) -> Self {
        let probe = || -> Result<(), keyring::Error> {
            let e = keyring::Entry::new(SERVICE, "probe")?;
            e.set_password("ok")?;
            let ok = e.get_password()? == "ok";
            let _ = e.delete_credential();
            if ok {
                Ok(())
            } else {
                Err(keyring::Error::NoEntry)
            }
        };
        match probe() {
            Ok(()) => Self {
                backend: Backend::Keyring,
                file_dir: fallback_dir.to_path_buf(),
                fallback_reason: None,
            },
            Err(e) => {
                let reason = explain(&e);
                tracing::warn!("keyring unavailable: {reason}; using restricted-permission file storage");
                Self {
                    fallback_reason: Some(reason),
                    ..Self::file(fallback_dir)
                }
            }
        }
    }

    pub fn file(dir: &Path) -> Self {
        Self {
            backend: Backend::File(dir.to_path_buf()),
            file_dir: dir.to_path_buf(),
            fallback_reason: None,
        }
    }

    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    /// Why the keyring is not used (None when it is).
    pub fn fallback_reason(&self) -> Option<&str> {
        self.fallback_reason.as_deref()
    }

    pub fn put(&self, id: &str, secrets: &ProfileSecrets) -> Result<(), SecretError> {
        let json = Zeroizing::new(serde_json::to_string(secrets).map_err(store_err)?);
        match &self.backend {
            Backend::Keyring => {
                keyring::Entry::new(SERVICE, &user(id))
                    .and_then(|e| e.set_password(&json))
                    .map_err(|e| SecretError::Store(explain(&e)))?;
                // A stale fallback copy must not outlive the keyring entry.
                file_delete(&self.file_dir, id)
            }
            Backend::File(dir) => file_put(dir, id, &json),
        }
    }

    pub fn get(&self, id: &str) -> Result<ProfileSecrets, SecretError> {
        match &self.backend {
            Backend::Keyring => match keyring::Entry::new(SERVICE, &user(id)).and_then(|e| e.get_password()) {
                Ok(s) => parse(&Zeroizing::new(s)),
                Err(keyring::Error::NoEntry) => {
                    // Stored while the keyring was unavailable: migrate it now.
                    let json = file_get(&self.file_dir, id)?;
                    let secrets = parse(&json)?;
                    match self.put(id, &secrets) {
                        Ok(()) => tracing::info!("migrated secret for profile {id} from file storage to the keyring"),
                        Err(e) => tracing::warn!("could not migrate secret for profile {id} to the keyring: {e}"),
                    }
                    Ok(secrets)
                }
                Err(e) => Err(SecretError::Store(explain(&e))),
            },
            Backend::File(dir) => parse(&file_get(dir, id)?),
        }
    }

    /// Remove every secret of a profile: WireGuard keys and SSH password.
    /// Both slots are always attempted; the first error is returned.
    pub fn delete(&self, id: &str) -> Result<(), SecretError> {
        let wg = self.delete_slot(id);
        let ssh = self.delete_slot(&ssh_id(id));
        wg.and(ssh)
    }

    fn delete_slot(&self, slot: &str) -> Result<(), SecretError> {
        if let Backend::Keyring = &self.backend {
            match keyring::Entry::new(SERVICE, &user(slot)).and_then(|e| e.delete_credential()) {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => return Err(SecretError::Store(explain(&e))),
            }
        }
        file_delete(&self.file_dir, slot)
    }

    /// Store an SSH profile's password (as a JSON string) under `"ssh:" + id`.
    pub fn put_ssh_password(&self, id: &str, pw: &str) -> Result<(), SecretError> {
        let slot = ssh_id(id);
        let json = Zeroizing::new(serde_json::to_string(pw).map_err(store_err)?);
        match &self.backend {
            Backend::Keyring => {
                keyring::Entry::new(SERVICE, &user(&slot))
                    .and_then(|e| e.set_password(&json))
                    .map_err(|e| SecretError::Store(explain(&e)))?;
                file_delete(&self.file_dir, &slot)
            }
            Backend::File(dir) => file_put(dir, &slot, &json),
        }
    }

    /// The SSH password of profile `id`; `SecretError::Missing` when none is stored.
    pub fn get_ssh_password(&self, id: &str) -> Result<Zeroizing<String>, SecretError> {
        let slot = ssh_id(id);
        let decode = |json: &str| -> Result<Zeroizing<String>, SecretError> {
            serde_json::from_str::<String>(json)
                .map(Zeroizing::new)
                .map_err(|e| SecretError::Store(format!("corrupt secret: {e}")))
        };
        match &self.backend {
            Backend::Keyring => match keyring::Entry::new(SERVICE, &user(&slot)).and_then(|e| e.get_password()) {
                Ok(s) => decode(&Zeroizing::new(s)),
                Err(keyring::Error::NoEntry) => {
                    let pw = decode(&file_get(&self.file_dir, &slot)?)?;
                    match self.put_ssh_password(id, &pw) {
                        Ok(()) => {
                            tracing::info!("migrated SSH password for profile {id} from file storage to the keyring")
                        }
                        Err(e) => tracing::warn!("could not migrate SSH password for profile {id} to the keyring: {e}"),
                    }
                    Ok(pw)
                }
                Err(e) => Err(SecretError::Store(explain(&e))),
            },
            Backend::File(dir) => decode(&file_get(dir, &slot)?),
        }
    }
}
