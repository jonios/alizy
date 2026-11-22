//! Profile management integration tests against a real SQLite file and the
//! file secret backend (the keyring backend needs a desktop session).

use alizy_store::{Db, ProfileManager, SecretStore};
use std::os::unix::fs::PermissionsExt;

const PRIV: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
const PRIV2: &str = "XDnhSwHmuXzMhW9ffSo/KQPg8f8ihQ0p0AeHPd5L6kI=";
const PEER: &str = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";
const PSK: &str = "GH5lQWLhwVA0Lw7yVnB3l8ExlY+uqvQh4jvvcbvTRG4=";

fn conf(key: &str, endpoint: &str) -> String {
    format!("[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\nPostUp = rm -rf /\n\n[Peer]\nPublicKey = {PEER}\nPresharedKey = {PSK}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}\n")
}

async fn setup() -> (tempfile::TempDir, ProfileManager) {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("data/alizy.db")).await.unwrap();
    let m = ProfileManager::new(db, SecretStore::file(&dir.path().join("secrets")));
    (dir, m)
}

#[tokio::test]
async fn import_valid_reject_invalid_and_detect_duplicates() {
    let (dir, m) = setup().await;
    let r = m.import_text(&conf(PRIV, "203.0.113.5:51820"), Some("Frankfurt")).await;
    assert_eq!(r.imported.len(), 1, "{:?}", r.errors);
    assert!(r.warnings[0].messages.iter().any(|w| w.contains("postup")));
    let id = r.imported[0].id.clone();

    // Same config again → duplicate, not imported.
    let r2 = m.import_text(&conf(PRIV, "203.0.113.5:51820"), None).await;
    assert_eq!(r2.imported.len(), 0);
    assert_eq!(r2.duplicates[0].existing_id, id);

    // Invalid config rejected with a reason, no key echoed.
    let r3 = m.import_text("[Interface]\nPrivateKey = garbage\n", None).await;
    assert_eq!(r3.errors.len(), 1);
    assert!(!r3.errors[0].message.contains("garbage") || r3.errors[0].message.contains("PrivateKey"));

    // Private key is NOT in the database file.
    let db_bytes = std::fs::read(dir.path().join("data/alizy.db")).unwrap();
    let hay = String::from_utf8_lossy(&db_bytes);
    assert!(!hay.contains(PRIV) && !hay.contains(PSK));
    let wal = std::fs::read(dir.path().join("data/alizy.db-wal")).unwrap_or_default();
    assert!(!String::from_utf8_lossy(&wal).contains(PRIV));

    // Secret file has restrictive permissions; db dir is 0700.
    let mode = std::fs::metadata(dir.path().join(format!("secrets/{id}.json")))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(dir.path().join("data")).unwrap().permissions().mode() & 0o777,
        0o700
    );

    // Full config reassembles with secrets.
    let full = m.full_config(&id).await.unwrap();
    assert!(full.to_wg_quick(true).contains(PSK));
}

#[tokio::test]
async fn bulk_import_directory() {
    let (dir, m) = setup().await;
    let d = dir.path().join("confs");
    std::fs::create_dir(&d).unwrap();
    std::fs::write(d.join("de_fra.conf"), conf(PRIV, "203.0.113.5:51820")).unwrap();
    std::fs::write(d.join("nl-ams.conf"), conf(PRIV2, "203.0.113.6:51820")).unwrap();
    std::fs::write(d.join("broken.conf"), "nope").unwrap();
    std::fs::write(d.join("readme.txt"), "ignored").unwrap();
    let r = m.import_paths(&[d.display().to_string()]).await;
    assert_eq!(r.imported.len(), 2);
    assert_eq!(r.errors.len(), 1);
    let mut names: Vec<_> = r.imported.iter().map(|p| p.name.clone()).collect();
    names.sort();
    assert_eq!(names, vec!["de fra", "nl-ams"]);
}

#[tokio::test]
async fn edit_with_redacted_placeholders_keeps_keys() {
    let (_d, m) = setup().await;
    let id = m
        .import_text(&conf(PRIV, "203.0.113.5:51820"), Some("A"))
        .await
        .imported[0]
        .id
        .clone();
    let row = m.db.get_profile(&id).await.unwrap();
    let text = alizy_store::manager::redacted_text(&row).replace("10.0.0.2/32", "10.0.0.3/32");
    assert!(!text.contains(PRIV));
    m.update_text(&id, &text).await.unwrap();
    let full = m.full_config(&id).await.unwrap();
    assert_eq!(full.interface.addresses[0].to_string(), "10.0.0.3/32");
    assert_eq!(full.interface.private_key.expose_base64().as_str(), PRIV);
    assert_eq!(
        full.peers[0].preshared_key.as_ref().unwrap().expose_base64().as_str(),
        PSK
    );
}

#[tokio::test]
async fn rename_duplicate_delete_and_backup_restore() {
    let (dir, m) = setup().await;
    let id = m
        .import_text(&conf(PRIV, "203.0.113.5:51820"), Some("A"))
        .await
        .imported[0]
        .id
        .clone();
    m.db.rename_profile(&id, "Home").await.unwrap();
    m.db.set_favorite(&id, true).await.unwrap();
    let copy = m.duplicate(&id).await.unwrap();
    assert_eq!(copy.name, "Home copy");
    // Importing the original again is still detected as a duplicate.
    assert_eq!(
        m.import_text(&conf(PRIV, "203.0.113.5:51820"), None)
            .await
            .duplicates
            .len(),
        1
    );

    let backup = dir.path().join("backup.json");
    assert_eq!(m.backup(&backup).await.unwrap(), 2);
    assert_eq!(std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777, 0o600);

    // Deletion removes row and secret.
    m.delete(&copy.id).await.unwrap();
    assert!(m.db.get_profile(&copy.id).await.is_err());
    assert!(!dir.path().join(format!("secrets/{}.json", copy.id)).exists());
    m.delete(&id).await.unwrap();
    assert!(m.db.list_profiles().await.unwrap().is_empty());

    let r = m.restore(&backup).await.unwrap();
    assert_eq!(
        r.imported.len(),
        1,
        "copy shares identity with original → duplicate on restore"
    );
    assert!(r.imported[0].favorite);

    // Export without private key never contains it.
    let out = dir.path().join("out.conf");
    m.export(&r.imported[0].id, &out, false).await.unwrap();
    let t = std::fs::read_to_string(&out).unwrap();
    assert!(!t.contains(PRIV) && t.contains("<redacted>"));
}

#[tokio::test]
async fn events_are_redacted_and_filterable() {
    let (_d, m) = setup().await;
    m.db.add_event(1, "error", "connection", "app", &format!("failed with key {PRIV}"))
        .await
        .unwrap();
    m.db.add_event(2, "info", "firewall", "daemon", "kill switch enabled")
        .await
        .unwrap();
    let all = m.db.query_events(&Default::default()).await.unwrap();
    assert_eq!(all.len(), 2);
    assert!(!all.iter().any(|e| e.message.contains(PRIV)));
    let f = alizy_store::EventFilter {
        category: Some("firewall".into()),
        ..Default::default()
    };
    assert_eq!(m.db.query_events(&f).await.unwrap().len(), 1);
    let s = alizy_store::EventFilter {
        search: Some("kill".into()),
        ..Default::default()
    };
    assert_eq!(m.db.query_events(&s).await.unwrap()[0].ts, 2);
}

#[tokio::test]
async fn editing_original_or_copy_is_not_a_duplicate_but_identity_collision_is() {
    let (_d, m) = setup().await;
    let a = m
        .import_text(&conf(PRIV, "203.0.113.5:51820"), Some("A"))
        .await
        .imported[0]
        .id
        .clone();
    let b = m
        .import_text(&conf(PRIV2, "203.0.113.6:51820"), Some("B"))
        .await
        .imported[0]
        .id
        .clone();
    let copy = m.duplicate(&a).await.unwrap().id;
    // Cosmetic edits on the copy and on the original succeed (regression: both used to fail).
    for id in [&copy, &a] {
        let row = m.db.get_profile(id).await.unwrap();
        let text = alizy_store::manager::redacted_text(&row).replace("DNS = 10.0.0.1", "DNS = 10.0.0.1\nMTU = 1380");
        m.update_text(id, &text).await.expect("cosmetic edit must succeed");
        assert_eq!(m.db.get_profile(id).await.unwrap().config.mtu, Some(1380));
    }
    // Turning A into B's identity (B's key + endpoint) is still refused.
    let err = m
        .update_text(&a, &conf(PRIV2, "203.0.113.6:51820"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("duplicates profile \"B\""), "{err}");
    let _ = b;
}
