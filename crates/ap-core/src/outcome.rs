//! Outcome contract for passthrough routes (design 3.5).
//!
//! Every refusal the gate generates carries `X-AP-Decision` and a small JSON body. The statuses
//! here differ from the sidecar's (`route_unknown` is 423, `caller_rejected` is 401), so they live
//! in this module and `Code::status` and `error::render` are untouched.

use crate::error::Code;

/// The value of the `X-AP-Decision` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Denied,
    Expired,
    Unavailable,
    Rejected,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Denied => "denied",
            Decision::Expired => "expired",
            Decision::Unavailable => "unavailable",
            Decision::Rejected => "rejected",
        }
    }
}

/// The name of the decision header.
pub const DECISION_HEADER: &str = "x-ap-decision";

/// Status and decision for a gate refusal on a passthrough route.
pub fn passthrough_outcome(code: Code) -> (u16, Decision) {
    match code {
        Code::CallerRejected => (401, Decision::Rejected),
        Code::RouteUnknown | Code::NoGrant | Code::HumanDenied => (423, Decision::Denied),
        Code::Expired => (410, Decision::Expired),
        Code::AbsoluteForm
        | Code::HostRejected
        | Code::PathAmbiguous
        | Code::FramingRefused
        | Code::AuthorizationDuplicate
        | Code::ProbeParams
        | Code::CallerKeyAmbiguous
        | Code::ContentType
        | Code::ContentEncoding
        | Code::CredentialMissing => (400, Decision::Denied),
        Code::ConnectRefused => (405, Decision::Denied),
        Code::WebsocketUnsupported => (501, Decision::Denied),
        Code::BodyTooLarge => (413, Decision::Denied),
        Code::PolicyUnavailable
        | Code::BodyReadTimeout
        | Code::ConnectFailed
        | Code::TableFull
        | Code::IdentityCap
        | Code::Cooldown
        | Code::Superseded
        | Code::Shutdown
        | Code::DroppedOnReload
        | Code::AuditUnavailable => (503, Decision::Unavailable),
        // Not produced by the passthrough pipeline. Fail closed with a generic refusal.
        _ => (503, Decision::Unavailable),
    }
}

/// Status, decision and JSON body `{"ap_decision","code"}`, built from fixed strings only.
pub fn render_passthrough(code: Code) -> (u16, Decision, Vec<u8>) {
    let (status, decision) = passthrough_outcome(code);
    let body = format!(
        "{{\"ap_decision\":\"{}\",\"code\":\"{}\"}}",
        decision.as_str(),
        code.code_str()
    );
    (status, decision, body.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ErrorShape;
    use crate::error::render;

    #[test]
    fn rows_of_the_outcome_table() {
        let rows = [
            (Code::NoGrant, 423, "denied", "no_grant"),
            (Code::RouteUnknown, 423, "denied", "route_unknown"),
            (Code::CallerRejected, 401, "rejected", "caller_rejected"),
            (Code::PathAmbiguous, 400, "denied", "path_ambiguous"),
            (Code::HostRejected, 400, "denied", "host_rejected"),
            (Code::AbsoluteForm, 400, "denied", "absolute_form"),
            (Code::FramingRefused, 400, "denied", "framing_refused"),
            (
                Code::AuthorizationDuplicate,
                400,
                "denied",
                "authorization_duplicate",
            ),
            (Code::ConnectRefused, 405, "denied", "connect_refused"),
            (
                Code::WebsocketUnsupported,
                501,
                "denied",
                "websocket_unsupported",
            ),
            (Code::BodyTooLarge, 413, "denied", "body_too_large"),
            (
                Code::PolicyUnavailable,
                503,
                "unavailable",
                "policy_unavailable",
            ),
            (
                Code::BodyReadTimeout,
                503,
                "unavailable",
                "body_read_timeout",
            ),
            (Code::ConnectFailed, 503, "unavailable", "connect_failed"),
            (Code::ProbeParams, 400, "denied", "probe_params"),
            (
                Code::CallerKeyAmbiguous,
                400,
                "denied",
                "caller_key_ambiguous",
            ),
            (Code::HumanDenied, 423, "denied", "human_denied"),
            (Code::Expired, 410, "expired", "expired"),
            (Code::ContentType, 400, "denied", "content_type"),
            (Code::ContentEncoding, 400, "denied", "content_encoding"),
            (Code::CredentialMissing, 400, "denied", "credential_missing"),
            (Code::TableFull, 503, "unavailable", "table_full"),
            (Code::IdentityCap, 503, "unavailable", "identity_cap"),
            (Code::Cooldown, 503, "unavailable", "cooldown"),
            (Code::Superseded, 503, "unavailable", "superseded"),
            (Code::Shutdown, 503, "unavailable", "shutdown"),
            (
                Code::DroppedOnReload,
                503,
                "unavailable",
                "dropped_on_reload",
            ),
            (
                Code::AuditUnavailable,
                503,
                "unavailable",
                "audit_unavailable",
            ),
        ];
        for (code, status, decision, name) in rows {
            let (s, d, body) = render_passthrough(code);
            assert_eq!((s, d.as_str()), (status, decision), "{name}");
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["ap_decision"], decision);
            assert_eq!(v["code"], name);
            assert_eq!(v.as_object().unwrap().len(), 2);
        }
    }

    #[test]
    fn sidecar_rendering_is_unchanged() {
        assert_eq!(render(Code::CallerRejected, ErrorShape::Generic).0, 403);
        assert_eq!(render(Code::RouteUnknown, ErrorShape::Generic).0, 404);
    }
}
