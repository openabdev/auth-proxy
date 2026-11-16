//! The audit record: one JSON line per decision, identities and codes only.
//!
//! The record cannot carry the `/ap/<caller-key>` prefix. The only path type
//! its constructor takes is `RoutePath`, which is the route-relative path and
//! refuses anything that starts with `/ap/`, has a query, or contains a
//! key-looking string. Every other text field is passed through `safe_field`.
//! There is no field for the caller key, the surrogate, the authority token or
//! a credential, and no way to add free-form text.

use crate::canon::{safe_field, RoutePath};
use crate::code::Code;
use serde::Serialize;

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct AuditRec {
    identity: String,
    session: String,
    generation: Option<u64>,
    route: String,
    method: String,
    path: String,
    aws_target: String,
    decision: &'static str,
    code: &'static str,
    status: u16,
    duration_ms: u64,
}

/// What the caller knows when it writes the line. All text is optional: a
/// refusal before the caller key is verified knows no route or session.
#[derive(Default, Debug, Clone)]
pub struct AuditInput<'a> {
    pub identity: Option<&'a str>,
    pub session: Option<&'a str>,
    pub generation: Option<u64>,
    pub route: Option<&'a str>,
    pub method: &'a str,
    pub aws_target: Option<&'a str>,
    pub duration_ms: u64,
}

impl AuditRec {
    /// An allowed request. `path` is route-relative.
    pub fn allowed(input: &AuditInput<'_>, path: &RoutePath, status: u16) -> AuditRec {
        AuditRec::build(input, path, "allow", "ok", status)
    }

    /// A refused request. Pass `RoutePath::none()` for refusals before the
    /// caller key was verified.
    pub fn refused(input: &AuditInput<'_>, path: &RoutePath, code: Code) -> AuditRec {
        AuditRec::build(input, path, "deny", code.as_str(), code.status().as_u16())
    }

    /// An admitted request that failed after admission (upstream failure,
    /// reset mid-stream). `code` is a fixed label such as `upstream_reset`.
    pub fn failed(
        input: &AuditInput<'_>,
        path: &RoutePath,
        code: &'static str,
        status: u16,
    ) -> AuditRec {
        AuditRec::build(input, path, "error", code, status)
    }

    fn build(
        input: &AuditInput<'_>,
        path: &RoutePath,
        decision: &'static str,
        code: &'static str,
        status: u16,
    ) -> AuditRec {
        let f = |s: Option<&str>| s.map(safe_field).unwrap_or_else(|| "-".into());
        AuditRec {
            identity: f(input.identity),
            session: f(input.session),
            generation: input.generation,
            route: f(input.route),
            method: safe_field(input.method),
            path: path.as_str().to_string(),
            aws_target: f(input.aws_target),
            decision,
            code,
            status,
            duration_ms: input.duration_ms,
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// One JSON line (no trailing newline). `t_ms` is the Unix time in ms.
    pub fn to_line(&self, t_ms: u64) -> String {
        let mut v = serde_json::to_value(self).expect("audit record serializes");
        v.as_object_mut()
            .expect("object")
            .insert("t".into(), t_ms.into());
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_input() -> AuditInput<'static> {
        AuditInput {
            identity: Some("pty-team-a"),
            session: Some("sess-1"),
            generation: Some(3),
            route: Some("kiro-krs"),
            method: "POST",
            aws_target: Some("Svc.Op"),
            duration_ms: 12,
        }
    }

    #[test]
    fn fully_populated_record_has_no_key_or_prefix() {
        let rec = AuditRec::allowed(&full_input(), &RoutePath::new("/v1/messages"), 200);
        let line = rec.to_line(1);
        assert!(!line.contains("apk_") && !line.contains("aps_") && !line.contains("apt_"));
        assert!(!line.contains("/ap/"), "{line}");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        for k in [
            "identity",
            "session",
            "generation",
            "route",
            "method",
            "path",
            "aws_target",
            "decision",
            "code",
            "status",
            "duration_ms",
            "t",
        ] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
        assert_eq!(
            v.as_object().unwrap().len(),
            12,
            "no field beyond the documented ones"
        );
        assert_eq!(v["path"], "/v1/messages");
    }

    #[test]
    fn prefix_and_keys_are_scrubbed_from_every_text_field() {
        let key = format!("apk_{}", "a".repeat(64));
        let sur = format!("aps_{}", "b".repeat(64));
        let tok = format!("apt_{}", "c".repeat(64));
        let dirty_path = format!("/ap/{key}/kiro-krs/v1/x");
        let query_path = format!("/v1/x?token={sur}");
        let input = AuditInput {
            identity: Some(&key),
            session: Some(&sur),
            generation: None,
            route: Some(&tok),
            method: &key,
            aws_target: Some(&sur),
            duration_ms: 0,
        };
        for path in [&dirty_path, &query_path, &key] {
            for rec in [
                AuditRec::allowed(&input, &RoutePath::new(path), 200),
                AuditRec::refused(&input, &RoutePath::new(path), Code::PolicyDenied),
                AuditRec::failed(&input, &RoutePath::new(path), "upstream_reset", 502),
            ] {
                let line = rec.to_line(0);
                assert!(
                    !line.contains("apk_") && !line.contains("aps_") && !line.contains("apt_"),
                    "{line}"
                );
                assert!(!line.contains("/ap/"), "{line}");
            }
        }
    }

    #[test]
    fn refusal_before_verification_logs_no_path() {
        let rec = AuditRec::refused(
            &AuditInput {
                method: "GET",
                ..Default::default()
            },
            &RoutePath::none(),
            Code::CallerRejected,
        );
        assert_eq!(rec.path(), "-");
        let v: serde_json::Value = serde_json::from_str(&rec.to_line(0)).unwrap();
        assert_eq!(v["code"], "caller_rejected");
        assert_eq!(v["status"], 403);
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["route"], "-");
    }
}
