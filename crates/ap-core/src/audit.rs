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
    /// Response body bytes already forwarded to the agent when the upstream reset mid-stream.
    /// Present only on the `upstream_reset` line, omitted everywhere else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
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

/// Transitions a held request can write (design 3.9). The record type has no free-text field.
pub const HOLD_TRANSITIONS: &[&str] = &[
    "held",
    "approved",
    "denied",
    "expired",
    "abandoned",
    "superseded",
    "dropped_on_reload",
    "forward_started",
    "completed",
    "abandoned_after_approve",
    "connect_failed",
    "audit_unavailable",
    "notify_failed",
];

/// One audit line for a transition of a held request. Every key is always present (null when it
/// has no value), so the key set is fixed. There is no field for a header value, a query, a body,
/// a key or a notification target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HoldRec {
    /// The hold entry id, which names the request across its transitions.
    pub request_id: String,
    pub identity: String,
    pub route: Option<String>,
    pub method: String,
    /// Route-relative path. Query and fragment are dropped and token segments redacted on write.
    pub path: String,
    /// Credential-blind digest of the outbound request (hex sha256).
    pub digest: Option<String>,
    /// One of [`HOLD_TRANSITIONS`].
    pub transition: &'static str,
    /// Approver identity, on decisions only.
    pub approver: Option<String>,
    pub code: Option<String>,
    pub status: Option<u16>,
    pub duration_ms: u64,
    /// Whether the request carried an `Authorization` header.
    pub auth_present: bool,
    /// `scheme://host:port` the request goes to, on the `held` record only.
    pub upstream: Option<String>,
    /// The policy generation the request was admitted under, on the `held` record only.
    pub policy_generation: Option<u64>,
}

impl HoldRec {
    /// Serialize as one JSON line with a trailing newline. The path is cut to its path part and
    /// its `webhooks`/`interactions` token segments are redacted here, so no caller has to.
    pub fn to_json_line(&self) -> String {
        let mut rec = self.clone();
        rec.path = crate::canon::redact_path(&path_only(&rec.path));
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
            bytes_sent: None,
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
    fn bytes_sent_is_omitted_unless_set() {
        let v: serde_json::Value =
            serde_json::from_str(sample().to_json_line().trim_end()).unwrap();
        assert!(v.get("bytes_sent").is_none());
        let mut r = sample();
        r.bytes_sent = Some(8);
        let v: serde_json::Value = serde_json::from_str(r.to_json_line().trim_end()).unwrap();
        assert_eq!(v["bytes_sent"], 8);
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

    fn hold_sample() -> HoldRec {
        HoldRec {
            request_id: "0123abcd".into(),
            identity: "muse".into(),
            route: Some("discord".into()),
            method: "POST".into(),
            path: "/channels/1/messages?x=1".into(),
            digest: Some("ab".repeat(32)),
            transition: "held",
            approver: None,
            code: None,
            status: None,
            duration_ms: 3,
            auth_present: true,
            upstream: Some("https://discord.example.test:443".into()),
            policy_generation: Some(1),
        }
    }

    #[test]
    fn hold_json_keys_are_exactly_the_allowed_set() {
        let v: serde_json::Value =
            serde_json::from_str(hold_sample().to_json_line().trim_end()).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "approver",
                "auth_present",
                "code",
                "digest",
                "duration_ms",
                "identity",
                "method",
                "path",
                "policy_generation",
                "request_id",
                "route",
                "status",
                "transition",
                "upstream",
            ]
        );
    }

    #[test]
    fn hold_line_drops_query_and_redacts_tokens() {
        let mut r = hold_sample();
        r.path = "/webhooks/123/SECRETTOKEN/messages?wait=true#f".into();
        let line = r.to_json_line();
        assert!(!line.contains("SECRETTOKEN"));
        assert!(!line.contains("wait=true"));
        assert!(line.contains("/webhooks/123/<redacted>/messages"));
        assert_eq!(line.matches('\n').count(), 1);
    }

    #[test]
    fn every_hold_transition_serializes() {
        for t in HOLD_TRANSITIONS {
            let mut r = hold_sample();
            r.transition = t;
            let v: serde_json::Value = serde_json::from_str(r.to_json_line().trim_end()).unwrap();
            assert_eq!(v["transition"], *t);
        }
    }
}
