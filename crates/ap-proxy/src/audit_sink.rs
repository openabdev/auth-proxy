//! Audit sink: one JSON line per decision. The pipeline holds one sink for the process.
//!
//! A write failure is counted and never refuses a request. Durable, fail-closed audit is out of
//! Phase 1 (RFC Q5).

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ap_core::audit::AuditRec;

pub struct AuditSink {
    writer: Mutex<Box<dyn Write + Send>>,
    failures: AtomicU64,
}

impl AuditSink {
    /// A sink over any writer. The binary passes stdout; tests pass a buffer.
    pub fn new(writer: Box<dyn Write + Send>) -> Self {
        AuditSink {
            writer: Mutex::new(writer),
            failures: AtomicU64::new(0),
        }
    }

    /// Write one decision line. A newline is added when `line` lacks one.
    pub fn write_line(&self, line: &str) {
        let mut w = match self.writer.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut ok = w.write_all(line.as_bytes()).is_ok();
        if ok && !line.ends_with('\n') {
            ok = w.write_all(b"\n").is_ok();
        }
        if !(ok && w.flush().is_ok()) {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Write a request decision.
    pub fn write_rec(&self, rec: &AuditRec) {
        self.write_line(&rec.to_json_line());
    }

    /// Number of audit lines that failed to write since start.
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}
