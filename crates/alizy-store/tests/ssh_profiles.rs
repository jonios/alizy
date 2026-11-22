//! SSH-tunnel profile storage: the password lives only in the secret store,
//! never in SQLite or backups.

use alizy_core::ssh::{HostKey, SshPublic};
use alizy_store::{Db, ManagerError, ProfileKind, ProfileManager, SecretStore};
use zeroize::Zeroizing;

const PW: &str = "hunter2-Sup3r-Secret-pw";
const PW2: &str = "an0ther-Secret-pw";
const PRIV: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
const PEER: &str = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";

fn wg_conf() -> String {
    format!("[Interface]\nPrivateKey = {PRIV}\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = {PEER}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.5:51820\n")
}

fn public(host: &str, port: u16, user: &str) -> SshPublic {
    SshPublic {
        host: host.parse().unwrap(),
        port,
        username: user.into(),
        host_key: None,
        dns: Vec::new(),
    }
}

fn key() -> HostKey {
    HostKey {
        key_type: "ssh-ed25519".into(),
        key_b64: "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl".into(),
    }
}

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

async fn setup() -> (tempfile::TempDir, ProfileManager) {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("data/alizy.db")).await.unwrap();
    let m = ProfileManager::new(db, SecretStore::file(&dir.path().join("secrets")));
    (dir, m)
}

fn db_text(dir: &tempfile::TempDir) -> String {
    let mut s = String::new();
    for f in ["alizy.db", "alizy.db-wal", "alizy.db-shm"] {
        let b = std::fs::read(dir.path().join("data").join(f)).unwrap_or_default();
        s.push_str(&String::from_utf8_lossy(&b));
    }
    s
}

#[tokio::test]
async fn create_and_load_ssh_profile() {
    let (_d, m) = setup().await;
    let row = m
        .create_ssh("  My Server  ", public("203.0.113.10", 2222, "alice"), pw(PW))
        .await
        .unwrap();
    assert_eq!(row.kind, ProfileKind::Ssh);
    assert_eq!(row.name, "My Server");
    assert!(!row.password_needed);
    assert_eq!(row.ssh.as_ref().unwrap().username, "alice");

    let loaded = m.db.get_profile(&row.id).await.unwrap();
    assert_eq!(loaded.kind, ProfileKind::Ssh);
    assert_eq!(loaded.ssh, Some(public("203.0.113.10", 2222, "alice")));
    assert_eq!(
        loaded.fingerprint,
        alizy_core::ssh::fingerprint(loaded.ssh.as_ref().unwrap())
    );

    let cfg = m.full_ssh_config(&row.id).await.unwrap();
    assert_eq!(cfg.password.as_str(), PW);
    assert_eq!(cfg.public.port, 2222);

    // WG-only paths refuse SSH rows with a clear error.
    assert!(matches!(
        m.full_config(&row.id).await,
        Err(ManagerError::Unsupported(_))
    ));
    assert!(matches!(
        m.reveal_private_key(&row.id).await,
        Err(ManagerError::Unsupported(_))
    ));
    assert!(matches!(
        m.update_text(&row.id, &wg_conf()).await,
        Err(ManagerError::Unsupported(_))
    ));
    let row = m.db.get_profile(&row.id).await.unwrap();
    assert!(matches!(
        alizy_store::manager::try_redacted_text(&row),
        Err(ManagerError::Unsupported(_))
    ));
    let out = _d.path().join("out.conf");
    let err = m.export(&row.id, &out, true).await.unwrap_err();
    assert_eq!(err.to_string(), "SSH profiles cannot be exported as .conf");
    assert!(!out.exists());

    // Invalid input rejected.
    assert!(m.create_ssh("x", public("127.0.0.1", 22, "bob"), pw(PW)).await.is_err());
    assert!(m
        .create_ssh("x", public("203.0.113.11", 22, "bob"), pw(""))
        .await
        .is_err());

    // A WireGuard profile on a WG-only path still works alongside.
    let r = m.import_text(&wg_conf(), Some("WG")).await;
    assert_eq!(r.imported.len(), 1);
    assert_eq!(r.imported[0].kind, ProfileKind::Wireguard);
    assert!(m.full_config(&r.imported[0].id).await.is_ok());
    assert!(matches!(
        m.full_ssh_config(&r.imported[0].id).await,
        Err(ManagerError::Unsupported(_))
    ));
}

#[tokio::test]
async fn password_not_in_sqlite() {
    let (dir, m) = setup().await;
    let row = m
        .create_ssh("S", public("203.0.113.10", 22, "alice"), pw(PW))
        .await
        .unwrap();
    m.update_ssh(&row.id, "S", public("203.0.113.10", 22, "alice"), Some(pw(PW2)))
        .await
        .unwrap();
    m.duplicate(&row.id).await.unwrap();
    let hay = db_text(&dir);
    assert!(hay.contains("alice"), "sanity: the row is in the file");
    assert!(!hay.contains(PW) && !hay.contains(PW2));
}

#[tokio::test]
async fn duplicate_ssh_rejected() {
    let (_d, m) = setup().await;
    let a = m
        .create_ssh("A", public("203.0.113.10", 22, "alice"), pw(PW))
        .await
        .unwrap();
    let err = m
        .create_ssh("B", public("203.0.113.10", 22, "alice"), pw(PW2))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("duplicates profile \"A\""), "{err}");

    // An update that collides with another profile is refused.
    let b = m
        .create_ssh("B", public("203.0.113.10", 22, "bob"), pw(PW2))
        .await
        .unwrap();
    let err = m
        .update_ssh(&b.id, "B", public("203.0.113.10", 22, "alice"), None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("duplicates profile \"A\""), "{err}");

    // An intentional copy is allowed, keeps the password, and is still
    // recognised as the same identity on create.
    let copy = m.duplicate(&a.id).await.unwrap();
    assert_eq!(copy.name, "A copy");
    assert_eq!(copy.kind, ProfileKind::Ssh);
    assert_ne!(copy.fingerprint, a.fingerprint);
    assert_eq!(m.full_ssh_config(&copy.id).await.unwrap().password.as_str(), PW);
    // Editing the copy cosmetically is not a duplicate.
    m.update_ssh(&copy.id, "A copy", public("203.0.113.10", 22, "alice"), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn update_without_password_keeps_it() {
    let (_d, m) = setup().await;
    let row = m
        .create_ssh("S", public("203.0.113.10", 22, "alice"), pw(PW))
        .await
        .unwrap();
    let mut p = public("203.0.113.10", 22, "alice");
    p.dns = vec!["9.9.9.9".parse().unwrap()];
    let up = m.update_ssh(&row.id, "Renamed", p.clone(), None).await.unwrap();
    assert_eq!(up.name, "Renamed");
    assert_eq!(up.ssh, Some(p));
    assert_eq!(m.full_ssh_config(&row.id).await.unwrap().password.as_str(), PW);

    m.update_ssh(&row.id, "Renamed", public("203.0.113.10", 22, "alice"), Some(pw(PW2)))
        .await
        .unwrap();
    assert_eq!(m.full_ssh_config(&row.id).await.unwrap().password.as_str(), PW2);
}

#[tokio::test]
async fn host_change_clears_host_key() {
    let (_d, m) = setup().await;
    let row = m
        .create_ssh("S", public("203.0.113.10", 22, "alice"), pw(PW))
        .await
        .unwrap();
    m.set_ssh_host_key(&row.id, Some(key())).await.unwrap();
    assert_eq!(
        m.db.get_profile(&row.id).await.unwrap().ssh.unwrap().host_key,
        Some(key())
    );
    // Bad keys rejected.
    let bad = HostKey {
        key_type: "ssh-dss".into(),
        key_b64: "AAAA".into(),
    };
    assert!(m.set_ssh_host_key(&row.id, Some(bad)).await.is_err());

    // Same host/port: pinned key preserved.
    let mut same = public("203.0.113.10", 22, "alice");
    same.host_key = Some(key());
    let up = m.update_ssh(&row.id, "S", same, None).await.unwrap();
    assert_eq!(up.ssh.unwrap().host_key, Some(key()));

    // Different host: pin cleared even if the caller passed one.
    let mut moved = public("203.0.113.20", 22, "alice");
    moved.host_key = Some(key());
    let up = m.update_ssh(&row.id, "S", moved, None).await.unwrap();
    assert_eq!(up.ssh.as_ref().unwrap().host_key, None);
    assert_eq!(m.db.get_profile(&row.id).await.unwrap().ssh.unwrap().host_key, None);

    // Different port also clears it.
    m.set_ssh_host_key(&row.id, Some(key())).await.unwrap();
    let up = m
        .update_ssh(&row.id, "S", public("203.0.113.20", 2200, "alice"), None)
        .await
        .unwrap();
    assert_eq!(up.ssh.unwrap().host_key, None);

    // Clearing explicitly.
    m.set_ssh_host_key(&row.id, Some(key())).await.unwrap();
    m.set_ssh_host_key(&row.id, None).await.unwrap();
    assert_eq!(m.db.get_profile(&row.id).await.unwrap().ssh.unwrap().host_key, None);
}

#[tokio::test]
async fn backup_excludes_password_and_restore_flags_needed() {
    let (dir, m) = setup().await;
    let mut p = public("203.0.113.10", 22, "alice");
    p.host_key = Some(key());
    let s = m.create_ssh("SSH", p.clone(), pw(PW)).await.unwrap();
    m.db.set_favorite(&s.id, true).await.unwrap();
    let wg = m.import_text(&wg_conf(), Some("WG")).await.imported[0].clone();

    let backup = dir.path().join("backup.json");
    assert_eq!(m.backup(&backup).await.unwrap(), 2);
    let text = std::fs::read_to_string(&backup).unwrap();
    assert!(!text.contains(PW), "backup must not contain the SSH password");
    assert!(text.contains("alice"));
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["version"], 1);
    // WG entries are unchanged: no `ssh` key at all.
    let entries = json["profiles"].as_array().unwrap();
    let wg_entry = entries.iter().find(|e| e["name"] == "WG").unwrap();
    assert!(wg_entry.get("ssh").is_none());
    assert!(wg_entry["config"].as_str().unwrap().contains(PRIV));

    // Restoring onto the same DB reports both as duplicates.
    let r = m.restore(&backup).await.unwrap();
    assert_eq!(r.imported.len(), 0);
    assert_eq!(r.duplicates.len(), 2);

    m.delete(&s.id).await.unwrap();
    m.delete(&wg.id).await.unwrap();
    let r = m.restore(&backup).await.unwrap();
    assert_eq!(r.imported.len(), 2, "{:?}", r.errors);
    let restored = r.imported.iter().find(|x| x.kind == ProfileKind::Ssh).unwrap();
    assert!(restored.password_needed);
    assert!(restored.favorite);
    assert_eq!(restored.ssh, Some(p.clone()));
    let loaded = m.db.get_profile(&restored.id).await.unwrap();
    assert!(loaded.password_needed);
    assert!(matches!(
        m.full_ssh_config(&restored.id).await,
        Err(ManagerError::PasswordNeeded)
    ));
    // Supplying a password clears the flag.
    let up = m.update_ssh(&restored.id, "SSH", p, Some(pw(PW2))).await.unwrap();
    assert!(!up.password_needed);
    assert_eq!(m.full_ssh_config(&restored.id).await.unwrap().password.as_str(), PW2);
}

#[tokio::test]
async fn delete_removes_secret() {
    let (dir, m) = setup().await;
    let row = m
        .create_ssh("S", public("203.0.113.10", 22, "alice"), pw(PW))
        .await
        .unwrap();
    let secrets = dir.path().join("secrets");
    let holds_pw = || {
        std::fs::read_dir(&secrets)
            .map(|rd| {
                rd.flatten()
                    .any(|e| String::from_utf8_lossy(&std::fs::read(e.path()).unwrap_or_default()).contains(PW))
            })
            .unwrap_or(false)
    };
    assert!(holds_pw());
    assert_eq!(m.secrets.get_ssh_password(&row.id).unwrap().as_str(), PW);
    m.delete(&row.id).await.unwrap();
    assert!(!holds_pw());
    assert!(m.secrets.get_ssh_password(&row.id).is_err());
    assert!(m.db.get_profile(&row.id).await.is_err());
}

#[tokio::test]
async fn existing_wireguard_rows_get_kind_wireguard_after_migration() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let db_path = data.join("alizy.db");

    // Build a database at schema version 1 only, holding one WG row.
    {
        let only_v1 = dir.path().join("mig");
        std::fs::create_dir(&only_v1).unwrap();
        std::fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/migrations/0001_initial.sql"),
            only_v1.join("0001_initial.sql"),
        )
        .unwrap();
        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();
        sqlx::migrate::Migrator::new(only_v1.as_path())
            .await
            .unwrap()
            .run(&pool)
            .await
            .unwrap();
        let public = serde_json::to_string(&alizy_core::parse(&wg_conf()).unwrap().config.split().0).unwrap();
        sqlx::query(
            "INSERT INTO profiles (id, name, fingerprint, public_config, created_at, updated_at)
             VALUES ('old-id', 'Old', 'oldfp', ?, 1, 1)",
        )
        .bind(public)
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }

    let db = Db::open(&db_path).await.unwrap();
    let row = db.get_profile("old-id").await.unwrap();
    assert_eq!(row.kind, ProfileKind::Wireguard);
    assert_eq!(row.ssh, None);
    assert!(!row.password_needed);
    assert_eq!(row.name, "Old");

    // Serde default: a ProfileRow JSON without the new fields is WireGuard.
    let mut v = serde_json::to_value(&row).unwrap();
    let o = v.as_object_mut().unwrap();
    o.remove("kind");
    o.remove("ssh");
    o.remove("password_needed");
    let back: alizy_store::ProfileRow = serde_json::from_value(v).unwrap();
    assert_eq!(back.kind, ProfileKind::Wireguard);
}
