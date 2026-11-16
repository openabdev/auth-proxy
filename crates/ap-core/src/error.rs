//! Refusal codes from design section 4. Each code has one HTTP status and one stable string.

use crate::config::ErrorShape;

/// A refusal code. The string form is what audit lines and error bodies carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    AbsoluteForm,
    HostRejected,
    PathAmbiguous,
    SurrogateAmbiguous,
    CallerRejected,
    SurrogateMissing,
    SurrogateMalformed,
    SurrogateUnknown,
    SurrogateRevoked,
    SurrogateExpired,
    SurrogateWrongCaller,
    SurrogateWrongRoute,
    PolicyEmpty,
    PolicyDenied,
    RouteUnknown,
    ConnectRefused,
    BodyTooLarge,
    WebsocketUnsupported,
    UpstreamUnavailable,
    PolicyUnavailable,
    BrokerUnavailable,
}

impl Code {
    /// Fixed, non-secret sentence for the error body.
    pub fn message(self) -> &'static str {
        match self {
            Code::AbsoluteForm => "request target must be origin-form",
            Code::HostRejected => "host header is missing, duplicated or not the route host",
            Code::PathAmbiguous => "request path is ambiguous",
            Code::SurrogateAmbiguous => "more than one surrogate header",
            Code::CallerRejected => "caller key is missing or unknown",
            Code::SurrogateMissing => "surrogate header is missing",
            Code::SurrogateMalformed => "surrogate header is malformed",
            Code::SurrogateUnknown => "surrogate is not registered",
            Code::SurrogateRevoked => "surrogate was revoked",
            Code::SurrogateExpired => "surrogate lease expired",
            Code::SurrogateWrongCaller => "surrogate belongs to another caller",
            Code::SurrogateWrongRoute => "surrogate is not valid for this route",
            Code::PolicyEmpty => "no policy grants for this caller",
            Code::PolicyDenied => "request is not allowed by policy",
            Code::RouteUnknown => "route is unknown",
            Code::ConnectRefused => "CONNECT is not served here",
            Code::BodyTooLarge => "request body exceeds the configured limit",
            Code::WebsocketUnsupported => "websocket upgrade is not supported",
            Code::UpstreamUnavailable => "upstream is unavailable",
            Code::PolicyUnavailable => "policy is unavailable",
            Code::BrokerUnavailable => "credential store is unavailable",
        }
    }

    /// HTTP status for this refusal.
    pub fn status(self) -> u16 {
        match self {
            Code::AbsoluteForm
            | Code::HostRejected
            | Code::PathAmbiguous
            | Code::SurrogateAmbiguous => 400,
            Code::CallerRejected
            | Code::SurrogateMissing
            | Code::SurrogateMalformed
            | Code::SurrogateUnknown
            | Code::SurrogateRevoked
            | Code::SurrogateExpired
            | Code::SurrogateWrongCaller
            | Code::SurrogateWrongRoute
            | Code::PolicyEmpty
            | Code::PolicyDenied => 403,
            Code::RouteUnknown => 404,
            Code::ConnectRefused => 405,
            Code::BodyTooLarge => 413,
            Code::WebsocketUnsupported => 501,
            Code::UpstreamUnavailable => 502,
            Code::PolicyUnavailable | Code::BrokerUnavailable => 503,
        }
    }

    /// Stable snake_case identifier, as written in audit lines and error bodies.
    pub fn code_str(self) -> &'static str {
        match self {
            Code::AbsoluteForm => "absolute_form",
            Code::HostRejected => "host_rejected",
            Code::PathAmbiguous => "path_ambiguous",
            Code::SurrogateAmbiguous => "surrogate_ambiguous",
            Code::CallerRejected => "caller_rejected",
            Code::SurrogateMissing => "surrogate_missing",
            Code::SurrogateMalformed => "surrogate_malformed",
            Code::SurrogateUnknown => "surrogate_unknown",
            Code::SurrogateRevoked => "surrogate_revoked",
            Code::SurrogateExpired => "surrogate_expired",
            Code::SurrogateWrongCaller => "surrogate_wrong_caller",
            Code::SurrogateWrongRoute => "surrogate_wrong_route",
            Code::PolicyEmpty => "policy_empty",
            Code::PolicyDenied => "policy_denied",
            Code::RouteUnknown => "route_unknown",
            Code::ConnectRefused => "connect_refused",
            Code::BodyTooLarge => "body_too_large",
            Code::WebsocketUnsupported => "websocket_unsupported",
            Code::UpstreamUnavailable => "upstream_unavailable",
            Code::PolicyUnavailable => "policy_unavailable",
            Code::BrokerUnavailable => "broker_unavailable",
        }
    }
}

/// Status and body of a refusal in the route's error dialect.
///
/// `generic` returns `{"error": code, "message": text}`. `aws` returns the AWS JSON protocol
/// shape `{"__type": "AccessDeniedException", "message": "auth-proxy: <code>: <text>"}`, so
/// kiro-cli shows the message as-is. The status is the same in both shapes.
pub fn render(code: Code, shape: ErrorShape) -> (u16, Vec<u8>) {
    let body = match shape {
        ErrorShape::Generic => serde_json::json!({
            "error": code.code_str(),
            "message": code.message(),
        }),
        ErrorShape::Aws => serde_json::json!({
            "__type": "AccessDeniedException",
            "message": format!("auth-proxy: {}: {}", code.code_str(), code.message()),
        }),
    };
    // Serializing a json! value cannot fail.
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    (code.status(), bytes)
}

#[cfg(test)]
mod tests {
    use super::{render, Code};
    use crate::config::ErrorShape;

    #[test]
    fn render_generic_body_is_error_and_message_json() {
        let (status, body) = render(Code::PolicyDenied, ErrorShape::Generic);
        assert_eq!(status, 403);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "policy_denied");
        assert_eq!(v["message"], Code::PolicyDenied.message());
        assert!(v.get("__type").is_none());
    }

    #[test]
    fn render_aws_body_has_access_denied_type() {
        let (status, body) = render(Code::PolicyDenied, ErrorShape::Aws);
        assert_eq!(status, 403);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["__type"], "AccessDeniedException");
        assert!(v["message"].as_str().unwrap().contains("auth-proxy"));
        assert!(v.get("error").is_none());
    }

    #[test]
    fn render_status_follows_code_in_both_shapes() {
        assert_eq!(render(Code::BodyTooLarge, ErrorShape::Aws).0, 413);
        assert_eq!(render(Code::PolicyUnavailable, ErrorShape::Generic).0, 503);
    }

    #[test]
    fn statuses_match_design_table() {
        assert_eq!(Code::AbsoluteForm.status(), 400);
        assert_eq!(Code::HostRejected.status(), 400);
        assert_eq!(Code::PathAmbiguous.status(), 400);
        assert_eq!(Code::SurrogateAmbiguous.status(), 400);
        assert_eq!(Code::CallerRejected.status(), 403);
        assert_eq!(Code::SurrogateMissing.status(), 403);
        assert_eq!(Code::SurrogateMalformed.status(), 403);
        assert_eq!(Code::SurrogateUnknown.status(), 403);
        assert_eq!(Code::SurrogateRevoked.status(), 403);
        assert_eq!(Code::SurrogateExpired.status(), 403);
        assert_eq!(Code::SurrogateWrongCaller.status(), 403);
        assert_eq!(Code::SurrogateWrongRoute.status(), 403);
        assert_eq!(Code::PolicyEmpty.status(), 403);
        assert_eq!(Code::PolicyDenied.status(), 403);
        assert_eq!(Code::RouteUnknown.status(), 404);
        assert_eq!(Code::ConnectRefused.status(), 405);
        assert_eq!(Code::BodyTooLarge.status(), 413);
        assert_eq!(Code::WebsocketUnsupported.status(), 501);
        assert_eq!(Code::UpstreamUnavailable.status(), 502);
        assert_eq!(Code::PolicyUnavailable.status(), 503);
        assert_eq!(Code::BrokerUnavailable.status(), 503);
    }

    #[test]
    fn code_strings_are_snake_case_and_distinct() {
        let all = [
            Code::AbsoluteForm,
            Code::HostRejected,
            Code::PathAmbiguous,
            Code::SurrogateAmbiguous,
            Code::CallerRejected,
            Code::SurrogateMissing,
            Code::SurrogateMalformed,
            Code::SurrogateUnknown,
            Code::SurrogateRevoked,
            Code::SurrogateExpired,
            Code::SurrogateWrongCaller,
            Code::SurrogateWrongRoute,
            Code::PolicyEmpty,
            Code::PolicyDenied,
            Code::RouteUnknown,
            Code::ConnectRefused,
            Code::BodyTooLarge,
            Code::WebsocketUnsupported,
            Code::UpstreamUnavailable,
            Code::PolicyUnavailable,
            Code::BrokerUnavailable,
        ];
        let mut seen = std::collections::HashSet::new();
        for c in all {
            let s = c.code_str();
            assert!(
                s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{s}"
            );
            assert!(seen.insert(s), "duplicate {s}");
        }
        assert_eq!(seen.len(), 21);
    }
}
