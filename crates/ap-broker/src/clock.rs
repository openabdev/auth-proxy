//! Time source for the registry. Every lease and lock is measured in whole seconds from
//! `Clock::now`, so tests can drive time with [`ManualClock`] instead of sleeping.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of wall-clock time in whole Unix seconds.
pub trait Clock {
    /// Seconds since the Unix epoch.
    fn now(&self) -> u64;
}

/// Reads the operating system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A clock set by hand. Clones share the same time, so a test can keep one handle and give
/// another to the registry.
#[derive(Debug, Clone)]
pub struct ManualClock {
    now: Arc<AtomicU64>,
}

impl ManualClock {
    pub fn new(start: u64) -> Self {
        ManualClock {
            now: Arc::new(AtomicU64::new(start)),
        }
    }

    /// Move time forward by `secs` seconds.
    pub fn advance(&self, secs: u64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }

    /// Set the current time.
    pub fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_clones_share_time() {
        let a = ManualClock::new(100);
        let b = a.clone();
        a.advance(5);
        assert_eq!(b.now(), 105);
        b.set(7);
        assert_eq!(a.now(), 7);
    }

    #[test]
    fn system_clock_is_after_2020() {
        assert!(SystemClock.now() > 1_577_836_800);
    }
}
