//! Injectable monotonic clock, so lease tests do not sleep.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Time since an arbitrary origin. Monotonic; never compared across processes.
pub trait Clock: Send + Sync {
    fn now(&self) -> Duration;
}

pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub fn new() -> SystemClock {
        SystemClock {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// A clock that only moves when told to.
#[derive(Default)]
pub struct FakeClock {
    ms: AtomicU64,
}

impl FakeClock {
    pub fn new() -> FakeClock {
        FakeClock::default()
    }

    pub fn advance(&self, d: Duration) {
        self.ms.fetch_add(d.as_millis() as u64, Ordering::SeqCst);
    }

    pub fn advance_secs(&self, s: u64) {
        self.advance(Duration::from_secs(s));
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.ms.load(Ordering::SeqCst))
    }
}
