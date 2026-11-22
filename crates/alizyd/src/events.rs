//! In-memory ring buffer of daemon events, polled by the GUI. Messages are
//! passed through key redaction before they are stored.

use alizy_core::ipc::{DaemonEvent, EventCategory, EventLevel};
use std::collections::VecDeque;
use std::sync::Mutex;

const CAP: usize = 1000;

#[derive(Default)]
pub struct Events {
    inner: Mutex<(u64, VecDeque<DaemonEvent>)>,
}

impl Events {
    pub fn push(&self, level: EventLevel, category: EventCategory, message: impl Into<String>) {
        let message = alizy_core::redact_keys(&message.into());
        match level {
            EventLevel::Info => tracing::info!(?category, "{message}"),
            EventLevel::Warn => tracing::warn!(?category, "{message}"),
            EventLevel::Error => tracing::error!(?category, "{message}"),
        }
        let mut g = self.inner.lock().unwrap();
        g.0 += 1;
        let seq = g.0;
        g.1.push_back(DaemonEvent {
            seq,
            ts: crate::resolver::now(),
            level,
            category,
            message,
        });
        if g.1.len() > CAP {
            g.1.pop_front();
        }
    }

    pub fn since(&self, seq: u64) -> Vec<DaemonEvent> {
        self.inner
            .lock()
            .unwrap()
            .1
            .iter()
            .filter(|e| e.seq > seq)
            .cloned()
            .collect()
    }
}
