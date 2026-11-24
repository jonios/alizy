//! Lock-free cancellation of slow tunnel bring-up steps.
//!
//! An SSH bring-up runs under the engine lock and can take tens of seconds
//! (ssh-keyscan, waiting for ssh to authenticate). `disconnect` and `connect`
//! call [`CancelSource::cancel_all`] *before* they wait for that lock; the
//! bring-up polls its [`CancelToken`] and gives up promptly, so the waiting
//! command gets the lock within about one poll interval.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How often a waiting step re-checks its token.
pub const CANCEL_POLL: Duration = Duration::from_millis(100);

/// A generation counter; bumping it cancels every token taken before. Also
/// counts user commands that are waiting for the engine lock, so background
/// work (reconnects) doesn't start a new slow attempt in front of them.
#[derive(Debug, Clone, Default)]
pub struct CancelSource {
    gen: Arc<AtomicU64>,
    waiting: Arc<AtomicUsize>,
}

/// Held by a user command from before it waits for the engine lock until it
/// holds it; see [`CancelSource::preempt`].
#[must_use]
pub struct Preempt(Arc<AtomicUsize>);

impl Drop for Preempt {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl CancelSource {
    /// Cancel every token taken so far and mark a user command as waiting
    /// until the returned guard is dropped (once it holds the lock). Never blocks.
    pub fn preempt(&self) -> Preempt {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        self.gen.fetch_add(1, Ordering::SeqCst);
        Preempt(self.waiting.clone())
    }

    /// Whether a user command is waiting for the lock (see [`preempt`](Self::preempt)).
    pub fn preempt_pending(&self) -> bool {
        self.waiting.load(Ordering::SeqCst) > 0
    }

    /// A token cancelled by the next [`preempt`](Self::preempt).
    pub fn token(&self) -> CancelToken {
        CancelToken {
            gen: self.gen.clone(),
            at: self.gen.load(Ordering::SeqCst),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CancelToken {
    gen: Arc<AtomicU64>,
    at: u64,
}

impl CancelToken {
    pub fn is_cancelled(&self) -> bool {
        self.gen.load(Ordering::SeqCst) != self.at
    }

    /// Resolves once the token is cancelled (checked every [`CANCEL_POLL`]).
    pub async fn cancelled(&self) {
        while !self.is_cancelled() {
            tokio::time::sleep(CANCEL_POLL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tokens_taken_before_a_bump_are_cancelled() {
        let src = CancelSource::default();
        let old = src.token();
        assert!(!old.is_cancelled());
        assert!(!src.preempt_pending());
        let p = src.preempt();
        assert!(old.is_cancelled());
        assert!(src.preempt_pending());
        drop(p);
        assert!(!src.preempt_pending());
        let new = src.token();
        assert!(!new.is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), old.cancelled())
            .await
            .expect("resolves at once");
        assert!(tokio::time::timeout(Duration::from_millis(250), new.cancelled())
            .await
            .is_err());
    }
}
