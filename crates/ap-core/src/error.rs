//! Refusal codes from design section 4. Each code has one HTTP status and one stable string.

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

#[cfg(test)]
mod tests {
    use super::Code;

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
