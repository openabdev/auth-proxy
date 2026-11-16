//! Refusal codes (design doc section 4 table), status mapping and error dialects.

use http::StatusCode;
use serde::Deserialize;
use std::fmt;

/// Every way a request can be refused. A refusal is final for the request:
/// nothing goes upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
    pub const ALL: [Code; 21] = [
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

    pub const fn as_str(self) -> &'static str {
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

    /// Phase 1 status mapping. Every surrogate state is 403 (backlog item 3):
    /// a 401 makes some CLIs retry for minutes, and an env-delivered
    /// surrogate can never be re-minted inside a running CLI.
    pub const fn status(self) -> StatusCode {
        match self {
            Code::AbsoluteForm
            | Code::HostRejected
            | Code::PathAmbiguous
            | Code::SurrogateAmbiguous => StatusCode::BAD_REQUEST,
            Code::CallerRejected
            | Code::SurrogateMissing
            | Code::SurrogateMalformed
            | Code::SurrogateUnknown
            | Code::SurrogateRevoked
            | Code::SurrogateExpired
            | Code::SurrogateWrongCaller
            | Code::SurrogateWrongRoute
            | Code::PolicyEmpty
            | Code::PolicyDenied => StatusCode::FORBIDDEN,
            Code::RouteUnknown => StatusCode::NOT_FOUND,
            Code::ConnectRefused => StatusCode::METHOD_NOT_ALLOWED,
            Code::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Code::WebsocketUnsupported => StatusCode::NOT_IMPLEMENTED,
            Code::UpstreamUnavailable => StatusCode::BAD_GATEWAY,
            Code::PolicyUnavailable | Code::BrokerUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Code::AbsoluteForm => "absolute-form request target refused",
            Code::HostRejected => "Host must be exactly one listener authority",
            Code::PathAmbiguous => "ambiguous path refused",
            Code::SurrogateAmbiguous => "more than one surrogate presented",
            Code::CallerRejected => "caller key not recognised",
            Code::SurrogateMissing => "no surrogate presented",
            Code::SurrogateMalformed => "surrogate malformed",
            Code::SurrogateUnknown => "surrogate not recognised",
            Code::SurrogateRevoked => "surrogate revoked",
            Code::SurrogateExpired => "surrogate lease lapsed",
            Code::SurrogateWrongCaller => "surrogate belongs to another identity",
            Code::SurrogateWrongRoute => "surrogate not bound to this route",
            Code::PolicyEmpty => "policy is empty; nothing is allowed",
            Code::PolicyDenied => "request not allowed by policy",
            Code::RouteUnknown => "expected /ap/<caller-key>/<route>/ with a known route",
            Code::ConnectRefused => "CONNECT is not supported",
            Code::BodyTooLarge => "request body too large",
            Code::WebsocketUnsupported => "WebSocket upgrade is not supported",
            Code::UpstreamUnavailable => "upstream unavailable",
            Code::PolicyUnavailable => "policy unavailable; refusing",
            Code::BrokerUnavailable => "credential store unavailable; refusing",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Deserialize, Clone, Copy, Default, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ErrorShape {
    #[default]
    Json,
    /// AWS JSON protocol (`__type` + `message`), so kiro-cli shows the message.
    Aws,
}

/// Status, headers and body of a refusal, in the route's error dialect.
pub fn deny_parts(
    shape: ErrorShape,
    code: Code,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    let mut hs = vec![("x-auth-proxy-error", code.as_str().to_string())];
    let body = match shape {
        ErrorShape::Json => {
            hs.push(("content-type", "application/json".into()));
            serde_json::json!({"type": "error", "error": {"type": code.as_str(), "message": format!("auth-proxy: {}", code.message())}})
                .to_string()
        }
        ErrorShape::Aws => {
            let t = if code.status().is_server_error() {
                "ServiceUnavailableException"
            } else {
                "AccessDeniedException"
            };
            hs.push(("content-type", "application/x-amz-json-1.0".into()));
            hs.push(("x-amzn-errortype", t.into()));
            serde_json::json!({"__type": t, "message": format!("auth-proxy: {} ({})", code.message(), code.as_str())}).to_string()
        }
    };
    (code.status(), hs, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_is_complete_and_names_unique() {
        let names: std::collections::HashSet<_> = Code::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), Code::ALL.len());
    }

    #[test]
    fn status_mapping_matches_design_table() {
        use Code::*;
        for c in [
            AbsoluteForm,
            HostRejected,
            PathAmbiguous,
            SurrogateAmbiguous,
        ] {
            assert_eq!(c.status(), 400, "{c}");
        }
        for c in [
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
        ] {
            assert_eq!(c.status(), 403, "{c}");
        }
        assert_eq!(RouteUnknown.status(), 404);
        assert_eq!(ConnectRefused.status(), 405);
        assert_eq!(BodyTooLarge.status(), 413);
        assert_eq!(WebsocketUnsupported.status(), 501);
        assert_eq!(UpstreamUnavailable.status(), 502);
        assert_eq!(PolicyUnavailable.status(), 503);
        assert_eq!(BrokerUnavailable.status(), 503);
    }

    #[test]
    fn dialects() {
        let (st, hs, body) = deny_parts(ErrorShape::Aws, Code::SurrogateRevoked);
        assert_eq!(st, 403);
        assert!(hs.contains(&("x-amzn-errortype", "AccessDeniedException".into())));
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["__type"], "AccessDeniedException");
        assert!(v["message"].as_str().unwrap().contains("surrogate_revoked"));

        let (st, _, body) = deny_parts(ErrorShape::Aws, Code::BrokerUnavailable);
        assert_eq!(st, 503);
        assert!(body.contains("ServiceUnavailableException"));

        let (_, hs, body) = deny_parts(ErrorShape::Json, Code::PolicyDenied);
        assert!(hs.contains(&("content-type", "application/json".into())));
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"]["type"], "policy_denied");
    }
}
