//! Alizy GUI shell (unprivileged). All networking is performed by alizyd.

mod commands;
mod daemon_client;
mod ping;
mod poller;
mod state;
mod tray;

use state::{AppSettings, AppState, SETTINGS_KEY};
use std::sync::Arc;
use tauri::{Manager, WindowEvent};

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("ALIZY_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    if nix::unistd::geteuid().is_root() {
        eprintln!(
            "Alizy must not run as root. Start it as your normal user; privileged work is done by the alizyd service."
        );
        std::process::exit(1);
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            commands::show_main(app)
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(|app| {
            let handle = app.handle().clone();
            let data_dir = app.path().app_data_dir()?;
            let state = tauri::async_runtime::block_on(async {
                let db = alizy_store::Db::open(&data_dir.join("alizy.db")).await?;
                let secrets = alizy_store::SecretStore::detect(&data_dir.join("secrets"));
                let settings: AppSettings = db.get_setting(SETTINGS_KEY).await?.unwrap_or_default();
                Ok::<_, alizy_store::DbError>((db, secrets, settings))
            });
            let (db, secrets, settings) = state.map_err(|e| format!("could not open the Alizy database: {e}"))?;
            let tray_available = tray::create(&handle);
            let start_hidden = settings.start_minimized && tray_available;
            let auto = settings.auto_connect_profile_id.clone();
            let st = Arc::new(AppState {
                profiles: alizy_store::ProfileManager::new(db, secrets),
                daemon: Default::default(),
                settings: tokio::sync::RwLock::new(settings),
                tray_available,
            });
            app.manage(st.clone());
            if let Some(reason) = st.profiles.secrets.fallback_reason().map(String::from) {
                let st4 = st.clone();
                tauri::async_runtime::spawn(async move {
                    st4.log(
                        "warn",
                        "app",
                        format!("Private keys are stored in 0600 files instead of the system keyring: {reason}."),
                    )
                    .await;
                });
            }
            if !start_hidden {
                commands::show_main(&handle);
            }
            poller::spawn(handle.clone(), st.clone());

            // Auto-connect when idle.
            if let Some(id) = auto {
                let st2 = st.clone();
                tauri::async_runtime::spawn(async move {
                    if let Ok(alizy_core::ipc::Payload::Status(s)) =
                        st2.daemon.quick(alizy_core::ipc::Command::GetStatus).await
                    {
                        if matches!(
                            s.state,
                            alizy_core::ConnectionState::Disconnected | alizy_core::ConnectionState::Protected
                        ) {
                            st2.log("info", "connection", "Auto-connect at startup.").await;
                            let _ = commands::connect_profile(&st2, &id).await;
                        }
                    }
                });
            }

            // Closing the window hides to tray (if available and enabled). It never
            // disconnects and never touches the kill switch.
            let st3 = st.clone();
            if let Some(w) = app.get_webview_window("main") {
                let w2 = w.clone();
                w.on_window_event(move |ev| {
                    if let WindowEvent::CloseRequested { api, .. } = ev {
                        let close_to_tray =
                            st3.tray_available && st3.settings.try_read().map(|s| s.close_to_tray).unwrap_or(true);
                        if close_to_tray {
                            api.prevent_close();
                            // Hiding from inside the close-request handler is ignored on
                            // GTK/Wayland (e.g. Hyprland): defer it until the event returns.
                            let w3 = w2.clone();
                            let r = w2.run_on_main_thread(move || {
                                if let Err(e) = w3.hide() {
                                    tracing::error!("could not hide window to tray: {e}; minimizing instead");
                                    if let Err(e) = w3.minimize() {
                                        tracing::error!("could not minimize window: {e}");
                                    }
                                }
                            });
                            if let Err(e) = r {
                                tracing::error!("could not schedule hide-to-tray: {e}");
                            }
                        }
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::system_report,
            commands::status,
            commands::quit_ui,
            commands::profiles_list,
            commands::profiles_ping,
            commands::profile_get,
            commands::profile_validate_text,
            commands::profile_import_text,
            commands::profile_import_paths,
            commands::profile_rename,
            commands::profile_set_category,
            commands::profile_set_favorite,
            commands::profile_update_text,
            commands::profile_create_ssh,
            commands::profile_update_ssh,
            commands::profile_trust_host_key,
            commands::profile_clear_host_key,
            commands::profile_duplicate,
            commands::profile_delete,
            commands::profile_export,
            commands::profile_reveal_private_key,
            commands::backup_export,
            commands::backup_import,
            commands::connect,
            commands::disconnect,
            commands::policy_get,
            commands::policy_set,
            commands::settings_get,
            commands::settings_set,
            commands::logs_query,
            commands::logs_export,
            commands::logs_clear,
            commands::history_list,
            commands::public_ip,
            commands::split_get,
            commands::split_set,
            commands::split_parse_import,
            commands::split_export,
            commands::route_test,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Alizy");
}
