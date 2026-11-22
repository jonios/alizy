//! SQLite access (SQLx, runtime queries, embedded migrations).

use alizy_core::config::PublicConfig;
use alizy_core::ssh::SshPublic;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("data: {0}")]
    Data(String),
    #[error("not found")]
    NotFound,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What a profile tunnels through.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    #[default]
    Wireguard,
    Ssh,
}

impl ProfileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileKind::Wireguard => "wireguard",
            ProfileKind::Ssh => "ssh",
        }
    }

    fn parse(s: &str) -> Result<Self, DbError> {
        match s {
            "wireguard" => Ok(ProfileKind::Wireguard),
            "ssh" => Ok(ProfileKind::Ssh),
            other => Err(DbError::Data(format!("unknown profile kind {other:?}"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRow {
    pub id: String,
    pub name: String,
    pub category: Option<String>,
    pub favorite: bool,
    pub fingerprint: String,
    pub config: PublicConfig,
    pub cached_endpoints: Vec<Option<SocketAddr>>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_connected_at: Option<i64>,
    /// WireGuard rows hold their real config in `config`; SSH rows hold a
    /// placeholder there and their endpoint in `ssh`.
    #[serde(default)]
    pub kind: ProfileKind,
    /// Non-secret SSH fields (never the password). `Some` iff `kind == Ssh`.
    #[serde(default)]
    pub ssh: Option<SshPublic>,
    /// SSH only: no usable password is stored (e.g. restored from a backup).
    #[serde(default)]
    pub password_needed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRow {
    pub id: i64,
    pub profile_id: String,
    pub profile_name: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub end_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRow {
    pub id: i64,
    pub ts: i64,
    pub level: String,
    pub category: String,
    pub source: String,
    pub message: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventFilter {
    pub level: Option<String>,
    pub category: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

const PROFILE_COLS: &str =
    "id, name, category, favorite, fingerprint, public_config, cached_endpoints, created_at, updated_at, last_connected_at, kind, ssh_public, password_needed";

fn row_to_profile(r: &sqlx::sqlite::SqliteRow) -> Result<ProfileRow, DbError> {
    let cfg: String = r.get("public_config");
    let eps: String = r.get("cached_endpoints");
    let kind: String = r.get("kind");
    let ssh: Option<String> = r.get("ssh_public");
    Ok(ProfileRow {
        id: r.get("id"),
        name: r.get("name"),
        category: r.get("category"),
        favorite: r.get::<i64, _>("favorite") != 0,
        fingerprint: r.get("fingerprint"),
        config: serde_json::from_str(&cfg).map_err(|e| DbError::Data(e.to_string()))?,
        cached_endpoints: serde_json::from_str(&eps).unwrap_or_default(),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        last_connected_at: r.get("last_connected_at"),
        kind: ProfileKind::parse(&kind)?,
        ssh: ssh
            .map(|s| serde_json::from_str(&s).map_err(|e| DbError::Data(e.to_string())))
            .transpose()?,
        password_needed: r.get::<i64, _>("password_needed") != 0,
    })
}

fn ssh_json(p: &SshPublic) -> Result<String, DbError> {
    serde_json::to_string(p).map_err(|e| DbError::Data(e.to_string()))
}

impl Db {
    /// Open (creating if needed) with restrictive permissions and run migrations.
    pub async fn open(path: &Path) -> Result<Self, DbError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new().max_connections(4).connect_with(opts).await?;
        for p in [
            path.to_path_buf(),
            path.with_extension("db-wal"),
            path.with_extension("db-shm"),
        ] {
            if p.exists() {
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    // ── profiles ──
    pub async fn insert_profile(&self, p: &ProfileRow) -> Result<(), DbError> {
        sqlx::query(&format!(
            "INSERT INTO profiles ({PROFILE_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ))
        .bind(&p.id)
        .bind(&p.name)
        .bind(&p.category)
        .bind(p.favorite as i64)
        .bind(&p.fingerprint)
        .bind(serde_json::to_string(&p.config).map_err(|e| DbError::Data(e.to_string()))?)
        .bind(serde_json::to_string(&p.cached_endpoints).map_err(|e| DbError::Data(e.to_string()))?)
        .bind(p.created_at)
        .bind(p.updated_at)
        .bind(p.last_connected_at)
        .bind(p.kind.as_str())
        .bind(p.ssh.as_ref().map(ssh_json).transpose()?)
        .bind(p.password_needed as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_profiles(&self) -> Result<Vec<ProfileRow>, DbError> {
        let rows = sqlx::query(&format!(
            "SELECT {PROFILE_COLS} FROM profiles ORDER BY favorite DESC, name COLLATE NOCASE"
        ))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_profile).collect()
    }

    pub async fn get_profile(&self, id: &str) -> Result<ProfileRow, DbError> {
        let r = sqlx::query(&format!("SELECT {PROFILE_COLS} FROM profiles WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DbError::NotFound)?;
        row_to_profile(&r)
    }

    pub async fn find_by_fingerprint(&self, fp: &str) -> Result<Option<ProfileRow>, DbError> {
        let r = sqlx::query(&format!("SELECT {PROFILE_COLS} FROM profiles WHERE fingerprint = ?"))
            .bind(fp)
            .fetch_optional(&self.pool)
            .await?;
        r.as_ref().map(row_to_profile).transpose()
    }

    pub async fn name_exists(&self, name: &str) -> Result<bool, DbError> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM profiles WHERE name = ? COLLATE NOCASE")
            .bind(name)
            .fetch_one(&self.pool)
            .await?;
        Ok(n > 0)
    }

    async fn exec<'q>(
        &self,
        q: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    ) -> Result<(), DbError> {
        let res = q.execute(&self.pool).await?;
        if res.rows_affected() == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    pub async fn rename_profile(&self, id: &str, name: &str) -> Result<(), DbError> {
        let t = now();
        self.exec(
            sqlx::query("UPDATE profiles SET name = ?, updated_at = ? WHERE id = ?")
                .bind(name)
                .bind(t)
                .bind(id),
        )
        .await
    }

    pub async fn set_category(&self, id: &str, cat: Option<&str>) -> Result<(), DbError> {
        let t = now();
        self.exec(
            sqlx::query("UPDATE profiles SET category = ?, updated_at = ? WHERE id = ?")
                .bind(cat)
                .bind(t)
                .bind(id),
        )
        .await
    }

    pub async fn set_favorite(&self, id: &str, fav: bool) -> Result<(), DbError> {
        let t = now();
        self.exec(
            sqlx::query("UPDATE profiles SET favorite = ?, updated_at = ? WHERE id = ?")
                .bind(fav as i64)
                .bind(t)
                .bind(id),
        )
        .await
    }

    pub async fn update_config(&self, id: &str, cfg: &PublicConfig, fingerprint: &str) -> Result<(), DbError> {
        let t = now();
        let json = serde_json::to_string(cfg).map_err(|e| DbError::Data(e.to_string()))?;
        self.exec(
            sqlx::query("UPDATE profiles SET public_config = ?, fingerprint = ?, cached_endpoints = '[]', updated_at = ? WHERE id = ?")
                .bind(json)
                .bind(fingerprint)
                .bind(t)
                .bind(id),
        )
        .await
    }

    /// Replace an SSH row's name, endpoint and identity fingerprint.
    pub async fn update_ssh_profile(
        &self,
        id: &str,
        name: &str,
        public: &SshPublic,
        fingerprint: &str,
        password_needed: bool,
    ) -> Result<(), DbError> {
        let t = now();
        self.exec(
            sqlx::query(
                "UPDATE profiles SET name = ?, ssh_public = ?, fingerprint = ?, password_needed = ?, cached_endpoints = '[]', updated_at = ? WHERE id = ? AND kind = 'ssh'",
            )
            .bind(name)
            .bind(ssh_json(public)?)
            .bind(fingerprint)
            .bind(password_needed as i64)
            .bind(t)
            .bind(id),
        )
        .await
    }

    /// Replace an SSH row's public fields only (e.g. pinning a host key).
    pub async fn set_ssh_public(&self, id: &str, public: &SshPublic) -> Result<(), DbError> {
        let t = now();
        self.exec(
            sqlx::query("UPDATE profiles SET ssh_public = ?, updated_at = ? WHERE id = ? AND kind = 'ssh'")
                .bind(ssh_json(public)?)
                .bind(t)
                .bind(id),
        )
        .await
    }

    /// Record a successful connection and remember resolved endpoints (used
    /// when the kill switch blocks DNS on the next connect).
    pub async fn mark_connected(&self, id: &str, endpoints: &[Option<SocketAddr>]) -> Result<(), DbError> {
        let t = now();
        let json = serde_json::to_string(endpoints).map_err(|e| DbError::Data(e.to_string()))?;
        let keep_old = endpoints.iter().all(Option::is_none);
        let sql = if keep_old {
            "UPDATE profiles SET last_connected_at = ? WHERE id = ?"
        } else {
            "UPDATE profiles SET last_connected_at = ?, cached_endpoints = ? WHERE id = ?"
        };
        let q = sqlx::query(sql).bind(t);
        let q = if keep_old { q } else { q.bind(json) };
        self.exec(q.bind(id)).await
    }

    pub async fn delete_profile(&self, id: &str) -> Result<(), DbError> {
        self.exec(sqlx::query("DELETE FROM profiles WHERE id = ?").bind(id))
            .await
    }

    // ── settings ──
    pub async fn get_setting<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, DbError> {
        let v: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        v.map(|s| serde_json::from_str(&s).map_err(|e| DbError::Data(e.to_string())))
            .transpose()
    }

    pub async fn set_setting<T: Serialize>(&self, key: &str, value: &T) -> Result<(), DbError> {
        let json = serde_json::to_string(value).map_err(|e| DbError::Data(e.to_string()))?;
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── history ──
    pub async fn history_start(&self, profile_id: &str, name: &str, started_at: i64) -> Result<i64, DbError> {
        let r = sqlx::query("INSERT INTO history (profile_id, profile_name, started_at) VALUES (?, ?, ?)")
            .bind(profile_id)
            .bind(name)
            .bind(started_at)
            .execute(&self.pool)
            .await?;
        Ok(r.last_insert_rowid())
    }

    pub async fn history_end(&self, id: i64, rx: u64, tx: u64, reason: &str) -> Result<(), DbError> {
        let t = now();
        self.exec(
            sqlx::query("UPDATE history SET ended_at = ?, rx_bytes = ?, tx_bytes = ?, end_reason = ? WHERE id = ?")
                .bind(t)
                .bind(rx as i64)
                .bind(tx as i64)
                .bind(reason)
                .bind(id),
        )
        .await
    }

    /// Close entries left open by a crash of the UI.
    pub async fn history_close_dangling(&self) -> Result<(), DbError> {
        sqlx::query("UPDATE history SET ended_at = started_at, end_reason = 'unknown (app was not running)' WHERE ended_at IS NULL")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn history_list(&self, limit: i64, profile_id: Option<&str>) -> Result<Vec<HistoryRow>, DbError> {
        let rows = sqlx::query(
            "SELECT id, profile_id, profile_name, started_at, ended_at, rx_bytes, tx_bytes, end_reason FROM history
             WHERE (?1 IS NULL OR profile_id = ?1) ORDER BY started_at DESC LIMIT ?2",
        )
        .bind(profile_id)
        .bind(limit.clamp(1, 1000))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| HistoryRow {
                id: r.get("id"),
                profile_id: r.get("profile_id"),
                profile_name: r.get("profile_name"),
                started_at: r.get("started_at"),
                ended_at: r.get("ended_at"),
                rx_bytes: r.get("rx_bytes"),
                tx_bytes: r.get("tx_bytes"),
                end_reason: r.get("end_reason"),
            })
            .collect())
    }

    // ── events (logs) ──
    pub async fn add_event(
        &self,
        ts: i64,
        level: &str,
        category: &str,
        source: &str,
        message: &str,
    ) -> Result<(), DbError> {
        // Defence in depth: never persist anything that looks like a key.
        let msg = alizy_core::redact_keys(message);
        sqlx::query("INSERT INTO events (ts, level, category, source, message) VALUES (?, ?, ?, ?, ?)")
            .bind(ts)
            .bind(level)
            .bind(category)
            .bind(source)
            .bind(msg)
            .execute(&self.pool)
            .await?;
        // Retention: keep the newest 20k events.
        sqlx::query("DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET 20000)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn query_events(&self, f: &EventFilter) -> Result<Vec<EventRow>, DbError> {
        let search = f
            .search
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("%{}%", s.replace('%', "\\%").replace('_', "\\_")));
        let rows = sqlx::query(
            "SELECT id, ts, level, category, source, message FROM events
             WHERE (?1 IS NULL OR level = ?1) AND (?2 IS NULL OR category = ?2) AND (?3 IS NULL OR message LIKE ?3 ESCAPE '\\')
             ORDER BY id DESC LIMIT ?4",
        )
        .bind(&f.level)
        .bind(&f.category)
        .bind(search)
        .bind(f.limit.unwrap_or(500).clamp(1, 20000))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| EventRow {
                id: r.get("id"),
                ts: r.get("ts"),
                level: r.get("level"),
                category: r.get("category"),
                source: r.get("source"),
                message: r.get("message"),
            })
            .collect())
    }

    pub async fn clear_events(&self) -> Result<(), DbError> {
        sqlx::query("DELETE FROM events").execute(&self.pool).await?;
        Ok(())
    }
}
