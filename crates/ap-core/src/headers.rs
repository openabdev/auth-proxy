//! Header lists and request-header stripping, ported from the Phase 0 spike.

use http::{header, HeaderMap, HeaderName};

/// Headers that can carry a credential. All are removed before forwarding;
/// then exactly one (the route's credential header) is set.
pub const AUTH_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-goog-api-key",
    "api-key",
    "cookie",
    "x-amz-security-token",
];

/// Hop-by-hop headers (RFC 9110 section 7.6.1) plus framing headers the
/// forwarder sets itself.
pub const HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// Remove hop-by-hop headers, headers named by `Connection`, and every auth
/// header. Everything else passes (so route `pass_headers` survive by
/// construction).
pub fn strip_request_headers(h: &mut HeaderMap) {
    let named: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in HOP_HEADERS.iter().chain(AUTH_HEADERS) {
        h.remove(*n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn strips_auth_hop_and_connection_named() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("authorization", "Bearer x"),
            ("x-api-key", "k"),
            ("cookie", "c"),
            ("x-amz-security-token", "t"),
            ("connection", "close, x-secret-hop"),
            ("x-secret-hop", "1"),
            ("keep-alive", "5"),
            ("tokentype", "API_KEY"),
            ("x-amz-target", "Svc.Op"),
        ] {
            h.append(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        h.append(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer y"),
        );
        strip_request_headers(&mut h);
        let left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        assert_eq!(left.len(), 2, "{left:?}");
        assert!(h.contains_key("tokentype") && h.contains_key("x-amz-target"));
    }

    #[test]
    fn lists_are_lowercase() {
        for n in AUTH_HEADERS.iter().chain(HOP_HEADERS) {
            assert_eq!(*n, n.to_ascii_lowercase());
            assert!(HeaderName::from_bytes(n.as_bytes()).is_ok());
        }
    }
}
