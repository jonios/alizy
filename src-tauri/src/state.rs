//! Shared application state and settings.

use crate::daemon_client::DaemonClient;
use alizy_store::ProfileManager;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppSettings {
    pub theme: String,
    pub language: String,
    pub launch_at_startup: bool,
    pub start_minimized: bool,
    pub close_to_tray: bool,
    pub notifications: bool,
    pub auto_connect_profile_id: Option<String>,
    pub auto_updates: bool,
    pub show_public_ip: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
            language: "en".into(),
            launch_at_startup: false,
            start_minimized: false,
            close_to_tray: true,
            notifications: true,
            auto_connect_profile_id: None,
            auto_updates: false,
            show_public_ip: false,
        }
    }
}

impl AppSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !["dark", "light", "system"].contains(&self.theme.as_str()) {
            return Err("invalid theme".into());
        }
        if !["en", "fa"].contains(&self.language.as_str()) {
            return Err("unsupported language".into());
        }
        if self.auto_updates {
            return Err("no update channel is configured for this build".into());
        }
        Ok(())
    }
}

pub const SETTINGS_KEY: &str = "app_settings";

pub struct AppState {
    pub profiles: ProfileManager,
    pub daemon: DaemonClient,
    pub settings: RwLock<AppSettings>,
    pub tray_available: bool,
}

impl AppState {
    pub async fn log(&self, level: &str, category: &str, message: impl AsRef<str>) {
        let msg = message.as_ref();
        match level {
            "error" => tracing::error!(category, "{msg}"),
            "warn" => tracing::warn!(category, "{msg}"),
            _ => tracing::info!(category, "{msg}"),
        }
        if let Err(e) = self
            .profiles
            .db
            .add_event(alizy_store::db::now(), level, category, "app", msg)
            .await
        {
            tracing::error!("could not write log event: {e}");
        }
    }
}
