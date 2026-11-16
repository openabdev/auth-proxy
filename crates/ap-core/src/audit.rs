//! Audit record. One JSON line per request, written to stdout by ap-proxy.
//!
//! The record has no field that can carry a caller key, a surrogate, a credential or a query
//! string. The path is route-relative, and any query or fragment is dropped before it is written.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRec {
    /// Identity name from config.
    pub identity: String,
    /// Session id, when the surrogate resolved to a session.
    pub session: Option<String>,
    /// Session generation, when the surrogate resolved to a session.
    pub generation: Option<u64>,
    /// Route name, when the route was known.
    pub route: Option<String>,
    pub method: String,
    /// Route-relative path without query or fragment.
    pub path: String,
    /// The `X-Amz-Target` value, when the request had exactly one.
    pub aws_target: Option<String>,
    /// `allow` or `deny`.
    pub decision: &'static str,
    /// Refusal code string, when denied.
    pub code: Option<String>,
    pub status: u16,
    pub duration_ms: u64,
}

/// Drop the query string and fragment from a route-relative path.
pub fn path_only(p: &str) -> String {
    p.split(['?', '#']).next().unwrap_or("").to_string()
}

impl AuditRec {
    /// Serialize as one JSON line, with a trailing newline. The path is cut to its path part
    /// again here, so no caller passes a query string through.
    pub fn to_json_line(&self) -> String {
        let mut rec = self.clone();
        rec.path = path_only(&rec.path);
        let mut line = serde_json::to_string(&rec).unwrap_or_else(|_| "{}".to_string());
        line.push('\n');
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditRec {
        AuditRec {
            identity: "pty-team-a".into(),
            session: Some("s1".into()),
            generation: Some(3),
            route: Some("kiro-krs".into()),
            method: "POST".into(),
            path: "/v1/messages?stream=1".into(),
            aws_target: Some("Svc.Op".into()),
            decision: "allow",
            code: None,
            status: 200,
            duration_ms: 12,
        }
    }

    #[test]
    fn json_keys_are_exactly_the_allowed_set() {
        let line = sample().to_json_line();
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "aws_target",
                "code",
                "decision",
                "duration_ms",
                "generation",
                "identity",
                "method",
                "path",
                "route",
                "session",
                "status",
            ]
        );
    }

    #[test]
    fn line_is_newline_terminated_single_line() {
        let line = sample().to_json_line();
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
    }

    #[test]
    fn query_string_never_reaches_the_line() {
        let line = sample().to_json_line();
        assert!(!line.contains("stream=1"));
        assert!(!line.contains('?'));
        assert!(line.contains("\"path\":\"/v1/messages\""));
    }

    #[test]
    fn fragment_is_dropped_too() {
        assert_eq!(path_only("/a/b#frag"), "/a/b");
        assert_eq!(path_only("/a?x=1#f"), "/a");
    }

    #[test]
    fn denied_record_has_code_and_null_target() {
        let mut r = sample();
        r.decision = "deny";
        r.code = Some("policy_denied".into());
        r.aws_target = None;
        let v: serde_json::Value = serde_json::from_str(r.to_json_line().trim_end()).unwrap();
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["code"], "policy_denied");
        assert!(v["aws_target"].is_null());
    }
}
