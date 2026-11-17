//! Test-only pause points in the approved-request path. Compiled for unit tests and for the
//! `matrix-upstream` feature only; a default build has none of it.
//!
//! A [`Gate`] lets a test see that the handler reached a point and then hold it there. The
//! blocking wait is for a point inside a poll of the request body stream, where an `.await`
//! would let the HTTP client flush buffered bytes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

/// A rendezvous: the handler calls `arrive` and waits; the test waits for `arrived` and calls
/// `release`.
#[derive(Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct Gate {
    arrived: Notify,
    open: Mutex<bool>,
    cv: Condvar,
    opened: Notify,
}

#[cfg_attr(not(test), allow(dead_code))]
impl Gate {
    pub fn new() -> Arc<Gate> {
        Arc::new(Gate::default())
    }

    /// Wait until the handler has reached the gate.
    pub async fn arrived(&self) {
        self.arrived.notified().await;
    }

    /// Let the handler go.
    pub fn release(&self) {
        if let Ok(mut open) = self.open.lock() {
            *open = true;
        }
        self.cv.notify_all();
        self.opened.notify_waiters();
    }

    fn is_open(&self) -> bool {
        self.open.lock().map(|g| *g).unwrap_or(true)
    }

    pub(super) async fn pass_async(&self) {
        self.arrived.notify_one();
        loop {
            let n = self.opened.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if self.is_open() {
                return;
            }
            n.await;
        }
    }

    pub(super) fn pass_blocking(&self) {
        self.arrived.notify_one();
        let Ok(mut open) = self.open.lock() else {
            return;
        };
        while !*open {
            match self.cv.wait(open) {
                Ok(g) => open = g,
                Err(_) => return,
            }
        }
    }
}

#[derive(Default)]
pub struct Pause {
    after_approve: Mutex<Option<Arc<Gate>>>,
    between_milestones: Mutex<Option<Arc<Gate>>>,
    in_claim: Mutex<Option<Arc<Gate>>>,
    after_approve_ms: AtomicU64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl Pause {
    pub fn new() -> Pause {
        let p = Pause::default();
        #[cfg(feature = "matrix-upstream")]
        p.after_approve_ms
            .store(crate::matrix_hooks::hold_pause_ms(), Ordering::Relaxed);
        p
    }

    /// Hold the handler between the `Approved` transition and the upstream send.
    pub fn set_after_approve(&self, gate: Arc<Gate>) {
        if let Ok(mut g) = self.after_approve.lock() {
            *g = Some(gate);
        }
    }

    /// Hold the handler between the two milestones: after `forward_started` is written and before
    /// the first request body chunk is handed over. The wait blocks the polling thread.
    pub fn set_between_milestones(&self, gate: Arc<Gate>) {
        if let Ok(mut g) = self.between_milestones.lock() {
            *g = Some(gate);
        }
    }

    /// Hold the handler inside the start claim: after the table-closed check, before the
    /// `forward_started` write. The wait blocks the polling thread and the table lock.
    pub fn set_in_claim(&self, gate: Arc<Gate>) {
        if let Ok(mut g) = self.in_claim.lock() {
            *g = Some(gate);
        }
    }

    pub(super) fn in_claim(&self) {
        let gate = self.in_claim.lock().ok().and_then(|g| g.clone());
        if let Some(g) = gate {
            g.pass_blocking();
        }
    }

    pub(super) async fn after_approve(&self) {
        let gate = self.after_approve.lock().ok().and_then(|g| g.clone());
        if let Some(g) = gate {
            g.pass_async().await;
        }
        let ms = self.after_approve_ms.load(Ordering::Relaxed);
        if ms > 0 {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
    }

    pub(super) fn between_milestones(&self) {
        let gate = self.between_milestones.lock().ok().and_then(|g| g.clone());
        if let Some(g) = gate {
            g.pass_blocking();
        }
    }
}
