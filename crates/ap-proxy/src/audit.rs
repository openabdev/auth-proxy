//! The audit sink: one JSON line per decision on stdout.
//!
//! Request lines come from `ap_core::AuditRec`, which cannot hold the
//! `/ap/<caller-key>` prefix, a surrogate, a token or a credential. Session-
//! plane and admin lines are built here from fixed labels, counts, and ids that
//! passed `safe_field`. A failed write is counted and never refuses a request
//! (durable, fail-closed audit belongs to RFC Q5).

use ap_core::canon::safe_field;
use ap_core::AuditRec;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub struct Audit {
    write_failures: AtomicU64,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// First 8 hex characters of a well-formed `surrogate_sha256`, else `None`.
/// The hash prefix identifies a registration in the log; it is not the
/// surrogate and cannot be turned into one.
pub fn hash8(h: &str) -> Option<String> {
    let ok = h.len() == 64
        && h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    ok.then(|| h[..8].to_string())
}

/// What a session-plane or admin call tells the log.
#[derive(Default)]
pub struct PlaneEvent<'a> {
    /// Fixed label: `hello`, `register`, `renew`, `revoke`, `resync`, `revoke-all`, `status`.
    pub call: &'static str,
    pub session: Option<&'a str>,
    pub generation: Option<u64>,
    pub hash8: Option<&'a str>,
    /// Entries in a renew or resync list.
    pub count: Option<usize>,
    pub status: u16,
    /// `ok` or a fixed error code.
    pub result: &'a str,
}

impl PlaneEvent<'_> {
    pub fn to_line(&self, t_ms: u64) -> String {
        serde_json::json!({
            "t": t_ms,
            "plane": self.call,
            "session": self.session.map(safe_field).unwrap_or_else(|| "-".into()),
            "generation": self.generation,
            "hash8": self.hash8.unwrap_or("-"),
            "count": self.count,
            "status": self.status,
            "result": safe_field(self.result),
        })
        .to_string()
    }
}

impl Audit {
    fn write_line(&self, line: &str) {
        let mut out = std::io::stdout().lock();
        if writeln!(out, "{line}").is_err() {
            self.write_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn request(&self, rec: &AuditRec) {
        self.write_line(&rec.to_line(now_ms()));
    }

    pub fn plane(&self, ev: &PlaneEvent<'_>) {
        self.write_line(&ev.to_line(now_ms()));
    }

    #[allow(dead_code)]
    pub fn write_failures(&self) -> u64 {
        self.write_failures.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plane_line_has_ids_and_no_free_text() {
        let line = PlaneEvent {
            call: "register",
            session: Some("sess-1"),
            generation: Some(4),
            hash8: Some("deadbeef"),
            count: None,
            status: 201,
            result: "ok",
        }
        .to_line(7);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["plane"], "register");
        assert_eq!(v["session"], "sess-1");
        assert_eq!(v["hash8"], "deadbeef");
        assert_eq!(v["generation"], 4);
        assert_eq!(v["status"], 201);
    }

    #[test]
    fn key_looking_ids_are_masked() {
        let bad = format!("aps_{}", "0".repeat(64));
        let line = PlaneEvent {
            call: "revoke",
            session: Some(&bad),
            result: "ok",
            ..Default::default()
        }
        .to_line(1);
        assert!(!line.contains("aps_"), "{line}");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["session"], "-");
    }

    #[test]
    fn hash8_only_for_well_formed_hashes() {
        assert_eq!(hash8(&"ab".repeat(32)).as_deref(), Some("abababab"));
        assert_eq!(hash8("abc"), None);
        assert_eq!(hash8(&"AB".repeat(32)), None);
        assert_eq!(hash8(&format!("{}g", "a".repeat(63))), None);
    }
}
