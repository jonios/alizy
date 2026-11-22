//! Background status poller (statistics_manager + logging bridge):
//! * polls alizyd once per second and emits `alizy://status`;
//! * records connection history on state transitions;
//! * copies daemon events into the local log database;
//! * sends desktop notifications and refreshes the tray.

use crate::state::AppState;
use alizy_core::ipc::{Command, DaemonStatus, Payload};
use alizy_core::state::ConnectionState as St;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tauri_plugin_notification::NotificationExt;

pub const STATUS_EVENT: &str = "alizy://status";

#[derive(Serialize, Clone)]
struct StatusEvent {
    status: Option<DaemonStatus>,
    daemon_error: Option<String>,
}

struct Tracker {
    last_state: Option<St>,
    last_profile: Option<String>,
    history_id: Option<i64>,
    last_stats: (u64, u64),
    event_seq: u64,
    reachable: Option<bool>,
    /// Start time of the daemon process we last saw (detects service restarts).
    daemon_started: Option<u64>,
    /// Profile that was connected and not disconnected by the user.
    connected_profile: Option<String>,
}

pub fn spawn(app: AppHandle, st: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let _ = st.profiles.db.history_close_dangling().await;
        let mut t = Tracker {
            last_state: None,
            last_profile: None,
            history_id: None,
            last_stats: (0, 0),
            event_seq: 0,
            reachable: None,
            daemon_started: None,
            connected_profile: None,
        };
        let mut tick: u64 = 0;
        loop {
            let res = st.daemon.quick(Command::GetStatus).await;
            let (status, err) = match res {
                Ok(Payload::Status(s)) => (Some(*s), None),
                Ok(_) => (None, Some("unexpected reply from service".to_string())),
                Err(e) => (None, Some(e)),
            };
            if t.reachable != Some(status.is_some()) {
                t.reachable = Some(status.is_some());
                match &err {
                    Some(e) => st.log("error", "service", format!("Service unreachable: {e}")).await,
                    None => st.log("info", "service", "Connected to the Alizy service.").await,
                }
            }
            if let Some(s) = &status {
                on_status(&app, &st, &mut t, s).await;
            }
            let _ = app.emit(
                STATUS_EVENT,
                StatusEvent {
                    status: status.clone(),
                    daemon_error: err,
                },
            );
            crate::tray::update(&app, status.as_ref()).await;
            if tick.is_multiple_of(3) && status.is_some() {
                sync_events(&st, &mut t).await;
            }
            tick += 1;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

async fn on_status(app: &AppHandle, st: &Arc<AppState>, t: &mut Tracker, s: &DaemonStatus) {
    // Service restart (package upgrade, crash + systemd restart): the daemon
    // cannot keep a tunnel across restarts because it never stores keys. If we
    // were connected and the user did not disconnect, reconnect the same
    // profile (only when auto-reconnect is enabled in the network policy).
    let restarted = t.daemon_started.is_some_and(|d| d != s.daemon_started);
    t.daemon_started = Some(s.daemon_started);
    if restarted {
        st.log("warn", "service", "The Alizy service restarted.").await;
        if let Some(pid) = t.connected_profile.clone() {
            if matches!(s.state, St::Protected | St::Disconnected) && s.policy.auto_reconnect {
                st.log(
                    "info",
                    "connection",
                    "Reconnecting the previous profile after the service restart.",
                )
                .await;
                let st2 = st.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = crate::commands::connect_profile(&st2, &pid).await;
                });
            }
        }
    }
    match s.state {
        St::Connected => t.connected_profile = s.profile_id.clone(),
        St::Disconnected | St::Protected | St::Error if !restarted => t.connected_profile = None,
        _ => {}
    }
    if let Some(stats) = &s.stats {
        t.last_stats = (stats.rx_bytes, stats.tx_bytes);
    }
    let changed = t.last_state != Some(s.state) || (s.state == St::Connected && t.last_profile != s.profile_id);
    if !changed {
        return;
    }
    // Close the previous history entry.
    if let Some(hid) = t.history_id.take() {
        let reason = match s.state {
            St::Connected => "switched profile",
            St::Disconnected | St::Protected | St::Disconnecting => "disconnected",
            St::Reconnecting => "connection lost",
            St::Error => "error",
            St::Connecting => "switching",
        };
        let _ = st
            .profiles
            .db
            .history_end(hid, t.last_stats.0, t.last_stats.1, reason)
            .await;
    }
    if s.state == St::Connected {
        if let (Some(id), Some(name)) = (&s.profile_id, &s.profile_name) {
            let since = s.connected_since.unwrap_or(0) as i64;
            t.history_id = st.profiles.db.history_start(id, name, since).await.ok();
            let eps = vec![s.stats.as_ref().and_then(|x| x.endpoint)];
            let _ = st.profiles.db.mark_connected(id, &eps).await;
        }
    }
    let prev = t.last_state;
    t.last_state = Some(s.state);
    t.last_profile = s.profile_id.clone();
    t.last_stats = (0, 0);
    if prev.is_none() {
        return; // first observation, not a transition
    }
    let msg = match s.state {
        St::Connected => Some(format!("Connected to {}", s.profile_name.as_deref().unwrap_or("VPN"))),
        St::Reconnecting => Some("Connection lost — reconnecting".to_string()),
        St::Protected if prev != Some(St::Disconnecting) => {
            Some("VPN down — kill switch is blocking traffic".to_string())
        }
        St::Disconnected => Some("Disconnected".to_string()),
        St::Error => Some(format!(
            "Connection error: {}",
            s.last_error.as_deref().unwrap_or("unknown")
        )),
        _ => None,
    };
    if let Some(m) = msg {
        if st.settings.read().await.notifications {
            let _ = app.notification().builder().title("Alizy").body(&m).show();
        }
    }
}

async fn sync_events(st: &AppState, t: &mut Tracker) {
    let Ok(Payload::Events(evs)) = st.daemon.quick(Command::GetEvents { since: 0 }).await else {
        return;
    };
    let max = evs.iter().map(|e| e.seq).max().unwrap_or(0);
    if max < t.event_seq {
        t.event_seq = 0; // daemon restarted; its sequence starts over
    }
    for ev in evs.iter().filter(|e| e.seq > t.event_seq) {
        let level = serde_json::to_value(ev.level)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "info".into());
        let cat = serde_json::to_value(ev.category)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "service".into());
        let _ = st
            .profiles
            .db
            .add_event(ev.ts as i64, &level, &cat, "daemon", &ev.message)
            .await;
    }
    t.event_seq = t.event_seq.max(max);
}
