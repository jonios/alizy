//! Allow-listed Tauri commands. Every argument is validated here or in the
//! layers below; nothing is ever passed to a shell; privileged operations go
//! to alizyd through explicit IPC commands only.

use crate::daemon_client::CallError;
use crate::state::{AppSettings, AppState, SETTINGS_KEY};
use alizy_core::firewall::NetworkPolicy;
use alizy_core::ipc::ErrorCode;
use alizy_core::ipc::{
    Command, DaemonStatus, LanProxyConfig, LanProxyStatus, Payload, RouteTest, SplitStatus, TunnelSpec,
};
use alizy_core::protocol::TunnelConfig;
use alizy_core::routing::compatibility_warnings;
use alizy_core::split::{import_rules, Action, ImportResult, SplitConfig};
use alizy_core::ssh::{HostKey, SshPublic};
use alizy_core::sysprobe::SystemReport;
use alizy_store::manager::ManagerError;
use alizy_store::{ProfileKind, ProfileRow};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_autostart::ManagerExt;

type S<'a> = State<'a, Arc<AppState>>;
type R<T> = Result<T, String>;

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

pub const PROFILES_CHANGED: &str = "alizy://profiles-changed";

#[derive(Serialize)]
pub struct ProfileSummary {
    id: String,
    name: String,
    category: Option<String>,
    favorite: bool,
    endpoint: Option<String>,
    addresses: Vec<String>,
    has_ipv4: bool,
    has_ipv6: bool,
    full_tunnel: bool,
    created_at: i64,
    updated_at: i64,
    last_connected_at: Option<i64>,
    fingerprint: String,
    /// "wireguard" | "ssh".
    kind: ProfileKind,
    /// Non-secret SSH fields; `None` for WireGuard profiles.
    ssh: Option<SshSummary>,
    /// SSH only: the stored password is unusable and must be re-entered.
    password_needed: bool,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct SshSummary {
    host: String,
    port: u16,
    username: String,
    host_key_fingerprint: Option<String>,
}

impl From<&SshPublic> for SshSummary {
    fn from(p: &SshPublic) -> Self {
        Self {
            host: p.host.to_string(),
            port: p.port,
            username: p.username.clone(),
            host_key_fingerprint: p.host_key.as_ref().map(HostKey::fingerprint_sha256),
        }
    }
}

/// Endpoint of the first peer that has one — the address the UI shows and
/// the address the ping column measures.
fn first_endpoint(cfg: &alizy_core::PublicConfig) -> Option<&alizy_core::config::Endpoint> {
    cfg.peers.iter().find_map(|p| p.endpoint.as_ref())
}

impl From<&ProfileRow> for ProfileSummary {
    fn from(r: &ProfileRow) -> Self {
        if let (ProfileKind::Ssh, Some(p)) = (&r.kind, &r.ssh) {
            // SSH rows keep a placeholder WireGuard config; derive everything
            // from the SSH endpoint. The tunnel always carries all traffic;
            // has_ipv4 is always true (the tunnel provides IPv4) and has_ipv6
            // follows the server's address family.
            return Self {
                id: r.id.clone(),
                name: r.name.clone(),
                category: r.category.clone(),
                favorite: r.favorite,
                endpoint: Some(std::net::SocketAddr::new(p.host, p.port).to_string()),
                addresses: vec![],
                has_ipv4: true,
                has_ipv6: p.host.is_ipv6(),
                full_tunnel: true,
                created_at: r.created_at,
                updated_at: r.updated_at,
                last_connected_at: r.last_connected_at,
                fingerprint: r.fingerprint.clone(),
                kind: ProfileKind::Ssh,
                ssh: Some(p.into()),
                password_needed: r.password_needed,
            };
        }
        let fam = r.config.tunnel_families();
        Self {
            id: r.id.clone(),
            name: r.name.clone(),
            category: r.category.clone(),
            favorite: r.favorite,
            endpoint: first_endpoint(&r.config).map(ToString::to_string),
            addresses: r.config.addresses.iter().map(ToString::to_string).collect(),
            has_ipv4: fam.ipv4,
            has_ipv6: fam.ipv6,
            full_tunnel: r.config.is_full_tunnel(true) || r.config.is_full_tunnel(false),
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_connected_at: r.last_connected_at,
            fingerprint: r.fingerprint.clone(),
            kind: ProfileKind::Wireguard,
            ssh: None,
            password_needed: false,
        }
    }
}

#[derive(Serialize)]
pub struct ImportReportDto {
    imported: Vec<ProfileSummary>,
    duplicates: Vec<alizy_store::manager::Duplicate>,
    errors: Vec<alizy_store::manager::SourceError>,
    warnings: Vec<alizy_store::manager::SourceWarnings>,
}

impl From<alizy_store::ImportReport> for ImportReportDto {
    fn from(r: alizy_store::ImportReport) -> Self {
        Self {
            imported: r.imported.iter().map(ProfileSummary::from).collect(),
            duplicates: r.duplicates,
            errors: r.errors,
            warnings: r.warnings,
        }
    }
}

async fn after_import(app: &AppHandle, st: &AppState, r: &alizy_store::ImportReport) {
    if !r.imported.is_empty() {
        let _ = app.emit(PROFILES_CHANGED, ());
    }
    st.log(
        if r.errors.is_empty() { "info" } else { "warn" },
        "app",
        format!(
            "Import: {} imported, {} duplicates, {} errors.",
            r.imported.len(),
            r.duplicates.len(),
            r.errors.len()
        ),
    )
    .await;
}

fn check_path(p: &str) -> R<PathBuf> {
    let path = PathBuf::from(p);
    if !path.is_absolute() || p.contains('\0') {
        return Err("expected an absolute path".into());
    }
    Ok(path)
}

async fn current_policy(st: &AppState) -> NetworkPolicy {
    match st.daemon.quick(Command::GetPolicy).await {
        Ok(Payload::Policy(p)) => p,
        _ => NetworkPolicy::default(),
    }
}

// ───────────────────────────── app / system ─────────────────────────────

#[derive(Serialize)]
pub struct DaemonInfo {
    reachable: bool,
    version: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct AppInfo {
    version: String,
    platform: String,
    secret_backend: String,
    tray_available: bool,
    desktop: Option<String>,
    daemon: DaemonInfo,
}

#[tauri::command]
pub async fn app_info(st: S<'_>) -> R<AppInfo> {
    let daemon = match st
        .daemon
        .quick(Command::Hello {
            protocol: alizy_core::ipc::PROTOCOL_VERSION,
        })
        .await
    {
        Ok(Payload::Hello { version, .. }) => DaemonInfo {
            reachable: true,
            version: Some(version),
            error: None,
        },
        Ok(_) => DaemonInfo {
            reachable: false,
            version: None,
            error: Some("unexpected reply".into()),
        },
        Err(err) => DaemonInfo {
            reachable: false,
            version: None,
            error: Some(err),
        },
    };
    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        platform: std::env::consts::OS.into(),
        secret_backend: st.profiles.secrets.backend().name().into(),
        tray_available: st.tray_available,
        desktop: std::env::var("XDG_CURRENT_DESKTOP").ok(),
        daemon,
    })
}

#[tauri::command]
pub async fn system_report(st: S<'_>) -> R<SystemReport> {
    match st.daemon.call(Command::GetSystemReport, Duration::from_secs(15)).await {
        Ok(Payload::System(r)) => Ok(*r),
        // Daemon unreachable: run the same (unprivileged) probe locally.
        _ => tokio::task::spawn_blocking(alizy_core::sysprobe::probe)
            .await
            .map_err(e),
    }
}

#[tauri::command]
pub async fn status(st: S<'_>) -> R<Option<DaemonStatus>> {
    match st.daemon.quick(Command::GetStatus).await {
        Ok(Payload::Status(s)) => Ok(Some(*s)),
        Ok(_) => Err("unexpected reply".into()),
        Err(_) => Ok(None),
    }
}

#[tauri::command]
pub fn quit_ui(app: AppHandle) {
    // Only the UI exits. alizyd keeps enforcing the kill switch.
    app.exit(0);
}

// ───────────────────────────── profiles ─────────────────────────────

#[tauri::command]
pub async fn profiles_list(st: S<'_>) -> R<Vec<ProfileSummary>> {
    Ok(st
        .profiles
        .db
        .list_profiles()
        .await
        .map_err(e)?
        .iter()
        .map(ProfileSummary::from)
        .collect())
}

/// ICMP-echo every profile's target host — the WireGuard endpoint, or the
/// SSH server address — and report the round trip. Profiles sharing a host
/// are probed once; results are not stored anywhere.
#[tauri::command]
pub async fn profiles_ping(st: S<'_>) -> R<Vec<crate::ping::PingResult>> {
    Ok(crate::ping::ping_all(profile_hosts(&st).await?).await)
}

/// Every profile's target host as configured: the WireGuard endpoint, or the
/// SSH server address.
async fn profile_hosts(st: &AppState) -> R<Vec<(String, String)>> {
    let rows = st.profiles.db.list_profiles().await.map_err(e)?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            // SSH rows carry a placeholder WireGuard config and keep their
            // (literal) address in `ssh`, so they need no endpoint parsing.
            let host = if let Some(ssh) = &r.ssh {
                ssh.host.to_string()
            } else {
                match &first_endpoint(&r.config)?.host {
                    alizy_core::config::Host::Ip(ip) => ip.to_string(),
                    alizy_core::config::Host::Name(name) => name.clone(),
                }
            };
            Some((r.id.clone(), host))
        })
        .collect())
}

/// Country of every profile's server, from the offline table in `geo`.
#[tauri::command]
pub async fn profiles_geo(st: S<'_>) -> R<Vec<crate::geo::GeoResult>> {
    Ok(crate::geo::locate_all(profile_hosts(&st).await?).await)
}

#[derive(Serialize)]
pub struct ProfileDetail {
    /// For `summary.kind == "ssh"`, `config` is a meaningless placeholder and
    /// `config_text_redacted` is a short secret-free description.
    summary: ProfileSummary,
    config: alizy_core::PublicConfig,
    config_text_redacted: String,
    warnings: Vec<String>,
}

#[tauri::command]
pub async fn profile_get(st: S<'_>, id: String) -> R<ProfileDetail> {
    let row = st.profiles.db.get_profile(&id).await.map_err(e)?;
    let policy = current_policy(&st).await;
    Ok(ProfileDetail {
        summary: ProfileSummary::from(&row),
        // SSH rows hold a placeholder WireGuard config: no compatibility
        // warnings, and `config` must be ignored by the UI (use summary.ssh).
        warnings: if row.kind == ProfileKind::Ssh {
            vec![]
        } else {
            compatibility_warnings(&row.config, &policy)
        },
        config_text_redacted: alizy_store::manager::redacted_text(&row).to_string(),
        config: row.config,
    })
}

#[derive(Serialize)]
pub struct ValidationResult {
    ok: bool,
    error: Option<String>,
    warnings: Vec<String>,
    config: Option<alizy_core::PublicConfig>,
}

#[tauri::command]
pub async fn profile_validate_text(st: S<'_>, text: String) -> R<ValidationResult> {
    let text = zeroize::Zeroizing::new(text);
    Ok(match st.profiles.validate(&text).await {
        Ok((cfg, warnings)) => ValidationResult {
            ok: true,
            error: None,
            warnings,
            config: Some(cfg),
        },
        Err(err) => ValidationResult {
            ok: false,
            error: Some(err),
            warnings: vec![],
            config: None,
        },
    })
}

#[tauri::command]
pub async fn profile_import_text(app: AppHandle, st: S<'_>, text: String, name: Option<String>) -> R<ImportReportDto> {
    let text = zeroize::Zeroizing::new(text);
    let r = st.profiles.import_text(&text, name.as_deref()).await;
    after_import(&app, &st, &r).await;
    Ok(r.into())
}

#[tauri::command]
pub async fn profile_import_paths(app: AppHandle, st: S<'_>, paths: Vec<String>) -> R<ImportReportDto> {
    if paths.len() > 1000 {
        return Err("too many paths".into());
    }
    for p in &paths {
        check_path(p)?;
    }
    let r = st.profiles.import_paths(&paths).await;
    after_import(&app, &st, &r).await;
    Ok(r.into())
}

#[tauri::command]
pub async fn profile_rename(app: AppHandle, st: S<'_>, id: String, name: String) -> R<()> {
    let name = alizy_core::profile::sanitize_name(&name).ok_or("name must not be empty")?;
    st.profiles.db.rename_profile(&id, &name).await.map_err(e)?;
    let _ = app.emit(PROFILES_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub async fn profile_set_category(app: AppHandle, st: S<'_>, id: String, category: Option<String>) -> R<()> {
    let c = category.as_deref().and_then(alizy_core::profile::sanitize_name);
    st.profiles.db.set_category(&id, c.as_deref()).await.map_err(e)?;
    let _ = app.emit(PROFILES_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub async fn profile_set_favorite(app: AppHandle, st: S<'_>, id: String, favorite: bool) -> R<()> {
    st.profiles.db.set_favorite(&id, favorite).await.map_err(e)?;
    let _ = app.emit(PROFILES_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub async fn profile_update_text(app: AppHandle, st: S<'_>, id: String, text: String) -> R<Vec<String>> {
    let text = zeroize::Zeroizing::new(text);
    let w = st.profiles.update_text(&id, &text).await.map_err(manager_err)?;
    st.log("info", "app", format!("Profile {id} configuration edited."))
        .await;
    let _ = app.emit(PROFILES_CHANGED, ());
    Ok(w)
}

#[tauri::command]
pub async fn profile_duplicate(app: AppHandle, st: S<'_>, id: String) -> R<ProfileSummary> {
    let row = st.profiles.duplicate(&id).await.map_err(e)?;
    let _ = app.emit(PROFILES_CHANGED, ());
    Ok(ProfileSummary::from(&row))
}

/// Parse the server address. An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`)
/// is stored as the plain IPv4 address: ssh would connect over IPv4 anyway,
/// and the core validation (which rejects mapped addresses) then applies the
/// IPv4 rules, e.g. to a mapped loopback.
fn parse_host(host: &str) -> R<std::net::IpAddr> {
    host.trim()
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_canonical())
        .map_err(|_| "Server IP Address must be an IPv4 or IPv6 address".to_string())
}

fn manager_err(err: ManagerError) -> String {
    err.to_string()
}

#[tauri::command]
pub async fn profile_create_ssh(
    app: AppHandle,
    st: S<'_>,
    name: String,
    host: String,
    port: u16,
    username: String,
    password: String,
) -> R<ProfileSummary> {
    let password = zeroize::Zeroizing::new(password);
    let public = SshPublic {
        host: parse_host(&host)?,
        port,
        username,
        host_key: None,
        dns: vec![],
    };
    let row = st
        .profiles
        .create_ssh(&name, public, password)
        .await
        .map_err(manager_err)?;
    st.log("info", "app", format!("SSH profile \"{}\" created.", row.name))
        .await;
    let _ = app.emit(PROFILES_CHANGED, ());
    Ok(ProfileSummary::from(&row))
}

/// `password`: `None` or an empty string keeps the stored password.
#[allow(clippy::too_many_arguments)] // mirrors the frontend call shape
#[tauri::command]
pub async fn profile_update_ssh(
    app: AppHandle,
    st: S<'_>,
    id: String,
    name: String,
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
) -> R<ProfileSummary> {
    let password = password.filter(|p| !p.is_empty()).map(zeroize::Zeroizing::new);
    let existing = st.profiles.db.get_profile(&id).await.map_err(e)?;
    let old = existing.ssh.ok_or_else(|| "this is not an SSH profile".to_string())?;
    let public = SshPublic {
        host: parse_host(&host)?,
        port,
        username,
        // The store drops the pinned key itself if the endpoint changed.
        host_key: old.host_key,
        dns: old.dns,
    };
    let row = st
        .profiles
        .update_ssh(&id, &name, public, password)
        .await
        .map_err(manager_err)?;
    st.log("info", "app", format!("SSH profile \"{}\" updated.", row.name))
        .await;
    let _ = app.emit(PROFILES_CHANGED, ());
    Ok(ProfileSummary::from(&row))
}

#[tauri::command]
pub async fn profile_trust_host_key(app: AppHandle, st: S<'_>, id: String, key: HostKey) -> R<()> {
    key.validate()?;
    st.profiles
        .set_ssh_host_key(&id, Some(key.clone()))
        .await
        .map_err(manager_err)?;
    st.log(
        "info",
        "app",
        format!("Pinned SSH host key {} for profile {id}.", key.fingerprint_sha256()),
    )
    .await;
    let _ = app.emit(PROFILES_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub async fn profile_clear_host_key(app: AppHandle, st: S<'_>, id: String) -> R<()> {
    st.profiles.set_ssh_host_key(&id, None).await.map_err(manager_err)?;
    st.log(
        "info",
        "app",
        format!("Cleared the pinned SSH host key for profile {id}."),
    )
    .await;
    let _ = app.emit(PROFILES_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub async fn profile_delete(app: AppHandle, st: S<'_>, id: String) -> R<()> {
    if let Ok(Payload::Status(s)) = st.daemon.quick(Command::GetStatus).await {
        if s.profile_id.as_deref() == Some(id.as_str()) && s.state.has_tunnel() {
            return Err("disconnect this profile before deleting it".into());
        }
    }
    let name = st
        .profiles
        .db
        .get_profile(&id)
        .await
        .map(|p| p.name)
        .unwrap_or_default();
    st.profiles.delete(&id).await.map_err(e)?;
    {
        let mut s = st.settings.write().await;
        if s.auto_connect_profile_id.as_deref() == Some(id.as_str()) {
            s.auto_connect_profile_id = None;
            st.profiles.db.set_setting(SETTINGS_KEY, &*s).await.map_err(e)?;
        }
    }
    st.log(
        "info",
        "app",
        format!("Profile \"{name}\" deleted (including its stored keys)."),
    )
    .await;
    let _ = app.emit(PROFILES_CHANGED, ());
    Ok(())
}

#[tauri::command]
pub async fn profile_export(st: S<'_>, id: String, path: String, include_private: bool) -> R<()> {
    st.profiles
        .export(&id, &check_path(&path)?, include_private)
        .await
        .map_err(manager_err)
}

#[tauri::command]
pub async fn profile_reveal_private_key(st: S<'_>, id: String) -> R<String> {
    st.log(
        "warn",
        "app",
        format!("Private key of profile {id} was revealed in the UI."),
    )
    .await;
    Ok(st
        .profiles
        .reveal_private_key(&id)
        .await
        .map_err(manager_err)?
        .to_string())
}

#[tauri::command]
pub async fn backup_export(st: S<'_>, path: String) -> R<usize> {
    let n = st.profiles.backup(&check_path(&path)?).await.map_err(e)?;
    st.log("info", "app", format!("Backup of {n} profiles written.")).await;
    Ok(n)
}

#[tauri::command]
pub async fn backup_import(app: AppHandle, st: S<'_>, path: String) -> R<ImportReportDto> {
    let r = st.profiles.restore(&check_path(&path)?).await.map_err(e)?;
    after_import(&app, &st, &r).await;
    Ok(r.into())
}

// ───────────────────────────── connection ─────────────────────────────

/// Structured connect failure. The GUI branches on `code`; `host_key` and
/// `fingerprint` are set for host-key errors so the user can verify and trust.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ConnectError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key: Option<HostKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl ConnectError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            host_key: None,
            fingerprint: None,
        }
    }
}

impl From<alizy_core::ipc::IpcError> for ConnectError {
    fn from(err: alizy_core::ipc::IpcError) -> Self {
        let code = match err.code {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::InvalidConfig => "invalid_config",
            ErrorCode::Firewall => "firewall",
            ErrorCode::Tunnel => "tunnel",
            ErrorCode::Busy => "busy",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::Internal => "internal",
            ErrorCode::HostKeyUnknown => "host_key_unknown",
            ErrorCode::HostKeyChanged => "host_key_changed",
            ErrorCode::AuthFailed => "auth_failed",
            ErrorCode::MissingDependency => "missing_dependency",
            ErrorCode::Cancelled => "cancelled",
        };
        let fingerprint = err.host_key.as_ref().map(HostKey::fingerprint_sha256);
        Self {
            code: code.into(),
            message: err.message,
            host_key: err.host_key,
            fingerprint,
        }
    }
}

impl From<CallError> for ConnectError {
    fn from(err: CallError) -> Self {
        match err {
            CallError::Ipc(i) => i.into(),
            CallError::Local(m) => Self::new("other", m),
        }
    }
}

impl From<ManagerError> for ConnectError {
    fn from(err: ManagerError) -> Self {
        match err {
            ManagerError::PasswordNeeded => Self::new("password_needed", err.to_string()),
            other => Self::new("other", other.to_string()),
        }
    }
}

#[tauri::command]
pub async fn connect(st: S<'_>, id: String) -> Result<(), ConnectError> {
    connect_profile(&st, &id).await
}

pub async fn connect_profile(st: &AppState, id: &str) -> Result<(), ConnectError> {
    let row = st
        .profiles
        .db
        .get_profile(id)
        .await
        .map_err(|err| ConnectError::new("other", err.to_string()))?;
    let (tunnel, cached_endpoints) = if row.kind == ProfileKind::Ssh {
        (TunnelConfig::Ssh(st.profiles.full_ssh_config(id).await?), vec![])
    } else {
        let config = st
            .profiles
            .full_config(id)
            .await
            .map_err(|err| ConnectError::new("other", err.to_string()))?;
        (TunnelConfig::WireGuard(config), row.cached_endpoints.clone())
    };
    let spec = TunnelSpec {
        profile_id: row.id.clone(),
        profile_name: row.name.clone(),
        tunnel,
        cached_endpoints,
    };
    st.log("info", "connection", format!("Connecting to \"{}\"…", row.name))
        .await;
    match st
        .daemon
        .call_ipc(Command::Connect { spec: Box::new(spec) }, Duration::from_secs(60))
        .await
    {
        Ok(_) => Ok(()),
        Err(err) => {
            let err = ConnectError::from(err);
            st.log(
                "error",
                "connection",
                format!("Connecting to \"{}\" failed: {}", row.name, err.message),
            )
            .await;
            Err(err)
        }
    }
}

#[tauri::command]
pub async fn disconnect(st: S<'_>) -> R<()> {
    st.daemon
        .call(Command::Disconnect, Duration::from_secs(30))
        .await
        .map(|_| ())
}

#[tauri::command]
pub async fn policy_get(st: S<'_>) -> R<NetworkPolicy> {
    match st.daemon.quick(Command::GetPolicy).await? {
        Payload::Policy(p) => Ok(p),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn policy_set(st: S<'_>, policy: NetworkPolicy) -> R<()> {
    policy.validate()?;
    st.daemon
        .call(Command::SetPolicy { policy }, Duration::from_secs(60))
        .await
        .map(|_| ())
}

// ───────────────────────────── settings / logs ─────────────────────────────

#[tauri::command]
pub async fn settings_get(st: S<'_>) -> R<AppSettings> {
    Ok(st.settings.read().await.clone())
}

#[tauri::command]
pub async fn settings_set(app: AppHandle, st: S<'_>, settings: AppSettings) -> R<()> {
    settings.validate()?;
    if let Some(id) = &settings.auto_connect_profile_id {
        st.profiles
            .db
            .get_profile(id)
            .await
            .map_err(|_| "auto-connect profile does not exist")?;
    }
    let old = st.settings.read().await.clone();
    if old.launch_at_startup != settings.launch_at_startup {
        let al = app.autolaunch();
        let r = if settings.launch_at_startup {
            al.enable()
        } else {
            al.disable()
        };
        r.map_err(|err| format!("could not change autostart: {err}"))?;
    }
    st.profiles.db.set_setting(SETTINGS_KEY, &settings).await.map_err(e)?;
    *st.settings.write().await = settings;
    Ok(())
}

#[derive(Serialize)]
pub struct LogEntry {
    id: i64,
    ts: i64,
    level: String,
    category: String,
    source: String,
    message: String,
}

#[tauri::command]
pub async fn logs_query(st: S<'_>, query: alizy_store::EventFilter) -> R<Vec<LogEntry>> {
    Ok(st
        .profiles
        .db
        .query_events(&query)
        .await
        .map_err(e)?
        .into_iter()
        .map(|r| LogEntry {
            id: r.id,
            ts: r.ts,
            level: r.level,
            category: r.category,
            source: r.source,
            message: r.message,
        })
        .collect())
}

#[tauri::command]
pub async fn logs_export(st: S<'_>, path: String) -> R<usize> {
    let rows = st
        .profiles
        .db
        .query_events(&alizy_store::EventFilter {
            limit: Some(20000),
            ..Default::default()
        })
        .await
        .map_err(e)?;
    let mut out = String::new();
    for r in rows.iter().rev() {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            r.ts, r.level, r.category, r.source, r.message
        ));
    }
    alizy_store::manager::write_private_file(&check_path(&path)?, out.as_bytes()).map_err(e)?;
    Ok(rows.len())
}

#[tauri::command]
pub async fn logs_clear(st: S<'_>) -> R<()> {
    st.profiles.db.clear_events().await.map_err(e)
}

#[tauri::command]
pub async fn history_list(st: S<'_>, limit: i64) -> R<Vec<alizy_store::HistoryRow>> {
    st.profiles.db.history_list(limit, None).await.map_err(e)
}

#[tauri::command]
pub async fn public_ip(st: S<'_>) -> R<String> {
    if !st.settings.read().await.show_public_ip {
        return Err("public IP lookup is disabled in settings".into());
    }
    tokio::task::spawn_blocking(|| {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(6))
            .user_agent("Alizy")
            .build();
        let body = agent
            .get("https://api.ipify.org")
            .call()
            .map_err(e)?
            .into_string()
            .map_err(e)?;
        let ip: std::net::IpAddr = body
            .trim()
            .parse()
            .map_err(|_| "unexpected answer from api.ipify.org".to_string())?;
        Ok(ip.to_string())
    })
    .await
    .map_err(e)?
}

// ───────────────────────────── split tunnelling ─────────────────────────────

#[tauri::command]
pub async fn split_get(st: S<'_>) -> R<SplitStatus> {
    match st.daemon.quick(Command::GetSplitStatus).await? {
        Payload::Split(s) => Ok(*s),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn split_set(st: S<'_>, config: SplitConfig) -> R<()> {
    let n = config.rules.len();
    st.daemon
        .call(Command::SetSplit { config }, Duration::from_secs(30))
        .await?;
    st.log("info", "network", format!("Split-tunnel rules updated ({n} rules)."))
        .await;
    Ok(())
}

#[tauri::command]
pub async fn split_parse_import(st: S<'_>, text: String, default_action: Action) -> R<ImportResult> {
    if text.len() > 4 * 1024 * 1024 {
        return Err("import is larger than 4 MiB".into());
    }
    let existing = match st.daemon.quick(Command::GetSplitStatus).await {
        Ok(Payload::Split(s)) => s.config.rules,
        _ => Vec::new(),
    };
    Ok(import_rules(&text, default_action, &existing))
}

#[tauri::command]
pub async fn split_export(st: S<'_>, path: String) -> R<usize> {
    let status = split_get(st).await?;
    let json = serde_json::to_vec_pretty(
        &serde_json::json!({ "rules": status.config.rules.iter().map(|r| serde_json::json!({
        "target": export_target(&r.target),
        "action": r.action,
        "category": r.category,
        "enabled": r.enabled,
        "priority": r.priority,
    })).collect::<Vec<_>>() }),
    )
    .map_err(e)?;
    std::fs::write(check_path(&path)?, json).map_err(e)?;
    Ok(status.config.rules.len())
}

#[tauri::command]
pub async fn route_test(st: S<'_>, query: String) -> R<RouteTest> {
    match st
        .daemon
        .call(Command::TestRoute { query }, Duration::from_secs(15))
        .await?
    {
        Payload::RouteTest(r) => Ok(*r),
        _ => Err("unexpected reply".into()),
    }
}

// ───────────────────────────── LAN forward proxy ─────────────────────────────

#[tauri::command]
pub async fn lan_proxy_get(st: S<'_>) -> R<LanProxyStatus> {
    match st.daemon.quick(Command::GetLanProxy).await? {
        Payload::LanProxy(s) => Ok(s),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn lan_proxy_set(st: S<'_>, config: LanProxyConfig) -> R<LanProxyStatus> {
    config.validate().map_err(e)?;
    let status = match st
        .daemon
        .call(Command::SetLanProxy { config }, Duration::from_secs(15))
        .await?
    {
        Payload::LanProxy(s) => s,
        _ => return Err("unexpected reply".into()),
    };
    // A failed listener start is reported in the status, not as an error:
    // the UI shows `error` next to the (still enabled) setting.
    Ok(status)
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Round-trippable textual form accepted by `import_rules`.
fn export_target(t: &alizy_core::split::Target) -> String {
    use alizy_core::split::{DomainMatch, Target};
    match t {
        Target::Domain {
            domain,
            mode: DomainMatch::Exact,
        } => domain.clone(),
        Target::Domain {
            domain,
            mode: DomainMatch::Wildcard,
        } => format!("*.{domain}"),
        Target::Domain {
            domain,
            mode: DomainMatch::Parent,
        } => format!(".{domain}"),
        Target::Ip { net } => net.to_string(),
        Target::App { path, .. } => path.clone(),
    }
}

#[cfg(test)]
mod ssh_tests {
    use super::*;
    use alizy_core::ipc::IpcError;
    use serde_json::json;

    fn key() -> HostKey {
        HostKey {
            key_type: "ssh-ed25519".into(),
            key_b64: "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl".into(),
        }
    }

    fn ssh_row(host: &str, hk: Option<HostKey>, pw_needed: bool) -> ProfileRow {
        ProfileRow {
            id: "id1".into(),
            name: "box".into(),
            category: None,
            favorite: false,
            fingerprint: "fp".into(),
            config: alizy_core::WgConfig::placeholder().split().0,
            cached_endpoints: vec![],
            created_at: 1,
            updated_at: 2,
            last_connected_at: None,
            kind: ProfileKind::Ssh,
            ssh: Some(SshPublic {
                host: host.parse().unwrap(),
                port: 2222,
                username: "root".into(),
                host_key: hk,
                dns: vec![],
            }),
            password_needed: pw_needed,
        }
    }

    #[test]
    fn ssh_summary_v4() {
        let v = serde_json::to_value(ProfileSummary::from(&ssh_row("203.0.113.5", Some(key()), true))).unwrap();
        assert_eq!(v["kind"], "ssh");
        assert_eq!(v["endpoint"], "203.0.113.5:2222");
        assert_eq!(v["addresses"], json!([]));
        assert_eq!(v["full_tunnel"], true);
        assert_eq!(v["has_ipv4"], true);
        assert_eq!(v["has_ipv6"], false);
        assert_eq!(v["password_needed"], true);
        assert_eq!(v["ssh"]["host"], "203.0.113.5");
        assert_eq!(v["ssh"]["port"], 2222);
        assert_eq!(v["ssh"]["username"], "root");
        assert_eq!(v["ssh"]["host_key_fingerprint"], key().fingerprint_sha256());
        assert!(!v.to_string().contains("password\":"));
    }

    #[test]
    fn ssh_summary_v6_brackets_and_no_key() {
        let v = serde_json::to_value(ProfileSummary::from(&ssh_row("2001:db8::1", None, false))).unwrap();
        assert_eq!(v["endpoint"], "[2001:db8::1]:2222");
        assert_eq!(v["has_ipv6"], true);
        assert_eq!(v["ssh"]["host_key_fingerprint"], serde_json::Value::Null);
    }

    #[test]
    fn wg_summary_gets_only_the_three_new_fields() {
        let mut row = ssh_row("203.0.113.5", None, false);
        row.kind = ProfileKind::Wireguard;
        row.ssh = None;
        let v = serde_json::to_value(ProfileSummary::from(&row)).unwrap();
        assert_eq!(v["kind"], "wireguard");
        assert_eq!(v["ssh"], serde_json::Value::Null);
        assert_eq!(v["password_needed"], false);
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        let mut want = vec![
            "id",
            "name",
            "category",
            "favorite",
            "endpoint",
            "addresses",
            "has_ipv4",
            "has_ipv6",
            "full_tunnel",
            "created_at",
            "updated_at",
            "last_connected_at",
            "fingerprint",
            "kind",
            "ssh",
            "password_needed",
        ];
        want.sort();
        assert_eq!(keys, want);
    }

    #[test]
    fn connect_error_maps_every_code() {
        use ErrorCode::*;
        let cases = [
            (BadRequest, "bad_request"),
            (Unauthorized, "unauthorized"),
            (InvalidConfig, "invalid_config"),
            (Firewall, "firewall"),
            (Tunnel, "tunnel"),
            (Busy, "busy"),
            (Unsupported, "unsupported"),
            (Internal, "internal"),
            (HostKeyUnknown, "host_key_unknown"),
            (HostKeyChanged, "host_key_changed"),
            (AuthFailed, "auth_failed"),
            (MissingDependency, "missing_dependency"),
            (Cancelled, "cancelled"),
        ];
        for (code, name) in cases {
            // must agree with the daemon's serde name
            assert_eq!(serde_json::to_value(code).unwrap(), name);
            assert_eq!(ConnectError::from(IpcError::new(code, "m")).code, name);
        }
    }

    #[test]
    fn connect_error_carries_host_key_and_fingerprint() {
        let mut ie = IpcError::new(ErrorCode::HostKeyChanged, "changed");
        ie.host_key = Some(key());
        let ce = ConnectError::from(ie);
        assert_eq!(ce.fingerprint.as_deref(), Some(key().fingerprint_sha256().as_str()));
        let v = serde_json::to_value(&ce).unwrap();
        assert_eq!(v["host_key"]["key_type"], "ssh-ed25519");
        let plain = serde_json::to_value(ConnectError::from(IpcError::new(ErrorCode::AuthFailed, "x"))).unwrap();
        assert!(plain.get("host_key").is_none() && plain.get("fingerprint").is_none());
    }

    #[test]
    fn connect_error_other_sources() {
        assert_eq!(ConnectError::from(ManagerError::PasswordNeeded).code, "password_needed");
        assert_eq!(ConnectError::from(CallError::Local("down".into())).code, "other");
        assert_eq!(ConnectError::from(ManagerError::Invalid("x".into())).code, "other");
    }

    #[test]
    fn host_parse() {
        assert!(parse_host(" 192.0.2.1 ").is_ok());
        assert!(parse_host("::1").is_ok());
        let err = parse_host("example.com").unwrap_err();
        assert_eq!(err, "Server IP Address must be an IPv4 or IPv6 address");
    }

    #[test]
    fn host_parse_canonicalises_ipv4_mapped() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert_eq!(parse_host("::ffff:192.0.2.1").unwrap(), ip("192.0.2.1"));
        assert_eq!(parse_host(" ::FFFF:c000:0201 ").unwrap(), ip("192.0.2.1"));
        // Real IPv6 stays IPv6.
        assert_eq!(parse_host("2001:db8::1").unwrap(), ip("2001:db8::1"));
        // A mapped loopback becomes 127.0.0.1 and is then rejected by the core rules.
        let public = SshPublic {
            host: parse_host("::ffff:127.0.0.1").unwrap(),
            port: 22,
            username: "alice".into(),
            host_key: None,
            dns: vec![],
        };
        assert_eq!(public.host, ip("127.0.0.1"));
        assert!(alizy_core::ssh::validate_public(&public).is_err());
        // Without canonicalisation core refuses the mapped form outright.
        let mapped = SshPublic {
            host: ip("::ffff:192.0.2.1"),
            ..public
        };
        assert_eq!(
            alizy_core::ssh::validate_public(&mapped).unwrap_err(),
            alizy_core::ssh::MAPPED_HOST_ERROR
        );
    }
}

// ───────────────────────────── updates ─────────────────────────────

#[tauri::command]
pub async fn check_update() -> R<crate::update::UpdateInfo> {
    tokio::task::spawn_blocking(|| crate::update::check(env!("CARGO_PKG_VERSION")))
        .await
        .map_err(e)?
}

#[tauri::command]
pub fn open_releases_page() -> R<()> {
    crate::update::open_releases_page()
}
