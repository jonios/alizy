//! Allow-listed Tauri commands. Every argument is validated here or in the
//! layers below; nothing is ever passed to a shell; privileged operations go
//! to alizyd through explicit IPC commands only.

use crate::state::{AppSettings, AppState, SETTINGS_KEY};
use alizy_core::firewall::NetworkPolicy;
use alizy_core::ipc::{Command, DaemonStatus, Payload, RouteTest, SplitStatus, TunnelSpec};
use alizy_core::routing::compatibility_warnings;
use alizy_core::split::{import_rules, Action, ImportResult, SplitConfig};
use alizy_core::sysprobe::SystemReport;
use alizy_store::ProfileRow;
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
}

impl From<&ProfileRow> for ProfileSummary {
    fn from(r: &ProfileRow) -> Self {
        let fam = r.config.tunnel_families();
        Self {
            id: r.id.clone(),
            name: r.name.clone(),
            category: r.category.clone(),
            favorite: r.favorite,
            endpoint: r
                .config
                .peers
                .iter()
                .find_map(|p| p.endpoint.as_ref().map(|e| e.to_string())),
            addresses: r.config.addresses.iter().map(ToString::to_string).collect(),
            has_ipv4: fam.ipv4,
            has_ipv6: fam.ipv6,
            full_tunnel: r.config.is_full_tunnel(true) || r.config.is_full_tunnel(false),
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_connected_at: r.last_connected_at,
            fingerprint: r.fingerprint.clone(),
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

#[derive(Serialize)]
pub struct ProfileDetail {
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
        warnings: compatibility_warnings(&row.config, &policy),
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
    let w = st.profiles.update_text(&id, &text).await.map_err(e)?;
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
        .map_err(e)
}

#[tauri::command]
pub async fn profile_reveal_private_key(st: S<'_>, id: String) -> R<String> {
    st.log(
        "warn",
        "app",
        format!("Private key of profile {id} was revealed in the UI."),
    )
    .await;
    Ok(st.profiles.reveal_private_key(&id).await.map_err(e)?.to_string())
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

#[tauri::command]
pub async fn connect(st: S<'_>, id: String) -> R<()> {
    connect_profile(&st, &id).await
}

pub async fn connect_profile(st: &AppState, id: &str) -> R<()> {
    let row = st.profiles.db.get_profile(id).await.map_err(e)?;
    let config = st.profiles.full_config(id).await.map_err(e)?;
    let spec = TunnelSpec {
        profile_id: row.id.clone(),
        profile_name: row.name.clone(),
        config,
        cached_endpoints: row.cached_endpoints.clone(),
    };
    st.log("info", "connection", format!("Connecting to \"{}\"…", row.name))
        .await;
    match st
        .daemon
        .call(Command::Connect { spec: Box::new(spec) }, Duration::from_secs(60))
        .await
    {
        Ok(_) => Ok(()),
        Err(err) => {
            st.log(
                "error",
                "connection",
                format!("Connecting to \"{}\" failed: {err}", row.name),
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
