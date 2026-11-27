//! System tray. Degrades gracefully: if no StatusNotifier/AppIndicator support
//! is available the app runs without a tray and closing the window quits the UI.
//! Quitting the UI never touches the kill switch (alizyd owns it).

use crate::state::AppState;
use alizy_core::ipc::DaemonStatus;
use alizy_core::state::ConnectionState as St;
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};

const TRAY_ID: &str = "alizy-tray";

/// (state, profile, profile-list signature, Persian) of the last rendered menu.
type MenuKey = (Option<St>, Option<String>, String, bool);
static LAST: Mutex<Option<MenuKey>> = Mutex::new(None);

/// Libraries the tray backend loads at runtime on Linux.
pub fn tray_supported() -> bool {
    if !cfg!(target_os = "linux") {
        return true;
    }
    const LIBS: &[&str] = &["libayatana-appindicator3.so.1", "libappindicator3.so.1"];
    const DIRS: &[&str] = &[
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/lib/x86_64-linux-gnu",
    ];
    LIBS.iter()
        .any(|l| DIRS.iter().any(|d| std::path::Path::new(d).join(l).exists()))
}

pub fn create(app: &AppHandle) -> bool {
    if !tray_supported() {
        tracing::warn!("no AppIndicator library found; running without a system tray");
        return false;
    }
    let menu = match Menu::with_items(
        app,
        &[&MenuItem::with_id(app, "open", "Open Alizy", true, None::<&str>).unwrap()],
    ) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("tray menu: {e}");
            return false;
        }
    };
    let built = TrayIconBuilder::with_id(TRAY_ID)
        .icon(app.default_window_icon().cloned().expect("bundle icon"))
        .tooltip("Alizy")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| handle_menu(app, ev.id().as_ref()))
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = ev
            {
                crate::commands::show_main(tray.app_handle());
            }
        })
        .build(app);
    match built {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("system tray unavailable: {e}");
            false
        }
    }
}

fn handle_menu(app: &AppHandle, id: &str) {
    let st = app.state::<Arc<AppState>>().inner().clone();
    match id {
        "open" => crate::commands::show_main(app),
        "quit" => app.exit(0),
        "disconnect" => {
            tauri::async_runtime::spawn(async move {
                if let Err(e) = st
                    .daemon
                    .call(alizy_core::ipc::Command::Disconnect, std::time::Duration::from_secs(30))
                    .await
                {
                    st.log("error", "connection", format!("Disconnect from tray failed: {e}"))
                        .await;
                }
            });
        }
        "settings" => {
            crate::commands::show_main(app);
            let _ = app.emit("alizy://navigate", "settings");
        }
        other => {
            if let Some(pid) = other.strip_prefix("connect:") {
                let pid = pid.to_string();
                tauri::async_runtime::spawn(async move {
                    let _ = crate::commands::connect_profile(&st, &pid).await;
                });
            }
        }
    }
}

/// The tray's few strings; the GUI's own translations live in src/i18n.
fn tr(fa: bool, en: &'static str) -> &'static str {
    if !fa {
        return en;
    }
    match en {
        "Service unavailable" => "سرویس در دسترس نیست",
        "Connected" => "متصل",
        "Connecting…" => "در حال اتصال…",
        "Reconnecting…" => "در حال اتصال دوباره…",
        "Disconnecting…" => "در حال قطع اتصال…",
        "Protected · kill switch active" => "محافظت‌شده · کیل‌سوییچ فعال است",
        "Error" => "خطا",
        "Disconnected" => "قطع",
        "Switch profile" => "تغییر پروفایل",
        "Connect" => "اتصال",
        "Disconnect" => "قطع اتصال",
        "Open Alizy" => "باز کردن Alizy",
        "Settings…" => "تنظیمات…",
        "Quit Alizy (protection keeps running)" => "خروج از Alizy (محافظت ادامه دارد)",
        other => other,
    }
}

fn state_label(s: Option<&DaemonStatus>, fa: bool) -> String {
    match s {
        None => tr(fa, "Service unavailable").into(),
        Some(s) => {
            let name = s.profile_name.as_deref().unwrap_or("");
            match s.state {
                St::Connected => format!("{} · {name}", tr(fa, "Connected")),
                St::Connecting => tr(fa, "Connecting…").into(),
                St::Reconnecting => tr(fa, "Reconnecting…").into(),
                St::Disconnecting => tr(fa, "Disconnecting…").into(),
                St::Protected => tr(fa, "Protected · kill switch active").into(),
                St::Error => tr(fa, "Error").into(),
                St::Disconnected => tr(fa, "Disconnected").into(),
            }
        }
    }
}

/// Rebuild the menu when state or profiles change.
pub async fn update(app: &AppHandle, status: Option<&DaemonStatus>) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else { return };
    let st = app.state::<Arc<AppState>>().inner().clone();
    let profiles = st.profiles.db.list_profiles().await.unwrap_or_default();
    let sig: String = profiles
        .iter()
        .map(|p| format!("{}:{}:{};", p.id, p.name, p.favorite))
        .collect();
    let fa = st.settings.read().await.language == "fa";
    let key = (
        status.map(|s| s.state),
        status.and_then(|s| s.profile_id.clone()),
        sig,
        fa,
    );
    {
        let mut last = LAST.lock().unwrap();
        if last.as_ref() == Some(&key) {
            return;
        }
        *last = Some(key);
    }
    let label = state_label(status, fa);
    let _ = tray.set_tooltip(Some(format!("Alizy — {label}")));
    let build = || -> tauri::Result<Menu<tauri::Wry>> {
        let header = MenuItem::with_id(app, "status", &label, false, None::<&str>)?;
        let connected = status.map(|s| s.state.has_tunnel()).unwrap_or(false);
        let active = status.and_then(|s| s.profile_id.clone());
        let sub = Submenu::with_id(
            app,
            "profiles",
            tr(fa, if connected { "Switch profile" } else { "Connect" }),
            !profiles.is_empty(),
        )?;
        let mut sorted: Vec<_> = profiles.iter().collect();
        sorted.sort_by_key(|p| (!p.favorite, std::cmp::Reverse(p.last_connected_at.unwrap_or(0))));
        for p in sorted.into_iter().take(15) {
            let mark = if active.as_deref() == Some(p.id.as_str()) {
                "● "
            } else if p.favorite {
                "★ "
            } else {
                ""
            };
            sub.append(&MenuItem::with_id(
                app,
                format!("connect:{}", p.id),
                format!("{mark}{}", p.name),
                true,
                None::<&str>,
            )?)?;
        }
        let disc = MenuItem::with_id(
            app,
            "disconnect",
            tr(fa, "Disconnect"),
            connected || status.map(|s| s.state == St::Error).unwrap_or(false),
            None::<&str>,
        )?;
        let open = MenuItem::with_id(app, "open", tr(fa, "Open Alizy"), true, None::<&str>)?;
        let settings = MenuItem::with_id(app, "settings", tr(fa, "Settings…"), true, None::<&str>)?;
        let quit = MenuItem::with_id(
            app,
            "quit",
            tr(fa, "Quit Alizy (protection keeps running)"),
            true,
            None::<&str>,
        )?;
        Menu::with_items(
            app,
            &[
                &header,
                &PredefinedMenuItem::separator(app)?,
                &sub,
                &disc,
                &PredefinedMenuItem::separator(app)?,
                &open,
                &settings,
                &PredefinedMenuItem::separator(app)?,
                &quit,
            ],
        )
    };
    match build() {
        Ok(menu) => {
            let _ = tray.set_menu(Some(menu));
        }
        Err(e) => tracing::warn!("tray menu update failed: {e}"),
    }
}
