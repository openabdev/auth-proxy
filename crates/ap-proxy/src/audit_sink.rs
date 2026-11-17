//! Audit sink: one JSON line per decision. The pipeline holds one sink for the process.
//!
//! `write_line` and `write_rec` count a write failure and never refuse a request. The `try_`
//! methods return the failure, for the held (write) routes whose `held` and `forward_started`
//! records must exist before the action (design 3.9).

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ap_core::audit::{AuditRec, HoldRec};

/// Standard output, locked for each write.
struct Stdout;

impl Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stdout().lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().lock().flush()
    }
}

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

    /// A sink on the process's standard output, the Phase 1 audit destination.
    pub fn stdout() -> Self {
        AuditSink::new(Box::new(Stdout))
    }

    /// Write one line and report whether the write and the flush both succeeded.
    fn write_checked(&self, line: &str) -> io::Result<()> {
        let mut w = match self.writer.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut result = w.write_all(line.as_bytes());
        if result.is_ok() && !line.ends_with('\n') {
            result = w.write_all(b"\n");
        }
        let result = result.and_then(|()| w.flush());
        if result.is_err() {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Write one decision line. A newline is added when `line` lacks one. A failure is counted
    /// and otherwise ignored.
    pub fn write_line(&self, line: &str) {
        let _ = self.write_checked(line);
    }

    /// Write one line and return the error when the write or the flush fails. The failure is
    /// counted as well.
    pub fn try_write_line(&self, line: &str) -> io::Result<()> {
        self.write_checked(line)
    }

    /// Write a held-request transition, ignoring a failure (counted).
    pub fn write_hold(&self, rec: &HoldRec) {
        self.write_line(&rec.to_json_line());
    }

    /// Write a held-request transition and return the error when it did not reach the sink.
    pub fn try_write_hold(&self, rec: &HoldRec) -> io::Result<()> {
        self.try_write_line(&rec.to_json_line())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Fails the write, the flush, or neither.
    struct Faulty {
        fail_write: bool,
        fail_flush: bool,
    }

    impl Write for Faulty {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                Err(io::Error::other("write"))
            } else {
                Ok(buf.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("flush"))
            } else {
                Ok(())
            }
        }
    }

    fn hold_rec() -> HoldRec {
        HoldRec {
            request_id: "id1".into(),
            identity: "muse".into(),
            route: Some("discord".into()),
            method: "POST".into(),
            path: "/channels/1/messages".into(),
            digest: None,
            transition: "held",
            approver: None,
            code: None,
            status: None,
            duration_ms: 0,
            auth_present: true,
            upstream: None,
            policy_generation: None,
        }
    }

    #[test]
    fn try_write_succeeds_and_writes_one_line() {
        let buf = Shared::default();
        let sink = AuditSink::new(Box::new(buf.clone()));
        sink.try_write_hold(&hold_rec()).unwrap();
        sink.try_write_line("{\"a\":1}").unwrap();
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.ends_with('\n'));
        assert_eq!(sink.failures(), 0);
    }

    #[test]
    fn try_write_returns_err_on_write_failure() {
        let sink = AuditSink::new(Box::new(Faulty {
            fail_write: true,
            fail_flush: false,
        }));
        assert!(sink.try_write_hold(&hold_rec()).is_err());
        assert!(sink.try_write_line("x").is_err());
        assert_eq!(sink.failures(), 2);
    }

    #[test]
    fn try_write_returns_err_on_flush_failure() {
        let sink = AuditSink::new(Box::new(Faulty {
            fail_write: false,
            fail_flush: true,
        }));
        assert!(sink.try_write_hold(&hold_rec()).is_err());
        assert_eq!(sink.failures(), 1);
    }

    #[test]
    fn best_effort_writes_swallow_the_failure() {
        let sink = AuditSink::new(Box::new(Faulty {
            fail_write: true,
            fail_flush: false,
        }));
        sink.write_hold(&hold_rec());
        sink.write_line("x");
        assert_eq!(sink.failures(), 2);
    }
}
