//! Header sets shared by config validation and request forwarding.

use http::header::CONNECTION;
use http::{HeaderMap, HeaderName};

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

/// Hop-by-hop headers (RFC 9110 section 7.6.1) plus framing headers the forwarder sets itself.
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

/// Remove hop-by-hop headers, headers named by `Connection`, and every credential header.
///
/// Headers listed in `pass_headers` are kept. Config validation refuses `pass_headers` that
/// name a credential or hop-by-hop header, so keeping them cannot carry a credential.
pub fn strip_request_headers(h: &mut HeaderMap, pass_headers: &[String]) {
    let keep = |name: &str| pass_headers.iter().any(|p| p == name);
    let named: Vec<HeaderName> = h
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in named {
        if !keep(n.as_str()) {
            h.remove(&n);
        }
    }
    for n in HOP_HEADERS.iter().chain(AUTH_HEADERS.iter()) {
        if !keep(n) {
            h.remove(*n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn map(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn removes_every_credential_header() {
        for name in AUTH_HEADERS {
            let mut h = map(&[]);
            h.insert(*name, HeaderValue::from_static("secret"));
            strip_request_headers(&mut h, &[]);
            assert!(h.get(*name).is_none(), "{name} survived");
        }
    }

    #[test]
    fn removes_every_hop_header() {
        for name in HOP_HEADERS {
            let mut h = map(&[]);
            h.insert(*name, HeaderValue::from_static("x"));
            strip_request_headers(&mut h, &[]);
            assert!(h.get(*name).is_none(), "{name} survived");
        }
    }

    #[test]
    fn removes_headers_named_by_connection() {
        let mut h = map(&[("connection", "close, x-private"), ("x-private", "1")]);
        strip_request_headers(&mut h, &[]);
        assert!(h.get("x-private").is_none());
        assert!(h.get("connection").is_none());
    }

    #[test]
    fn keeps_pass_headers_and_unrelated_headers() {
        let mut h = map(&[
            ("tokentype", "API_KEY"),
            ("x-amz-target", "Svc.Op"),
            ("content-type", "application/json"),
            ("authorization", "Bearer aps_x"),
        ]);
        strip_request_headers(&mut h, &["tokentype".to_string()]);
        assert_eq!(h.get("tokentype").unwrap(), "API_KEY");
        assert_eq!(h.get("x-amz-target").unwrap(), "Svc.Op");
        assert_eq!(h.get("content-type").unwrap(), "application/json");
        assert!(h.get("authorization").is_none());
    }

    #[test]
    fn keeps_pass_header_even_when_connection_names_it() {
        let mut h = map(&[("connection", "tokentype"), ("tokentype", "API_KEY")]);
        strip_request_headers(&mut h, &["tokentype".to_string()]);
        assert_eq!(h.get("tokentype").unwrap(), "API_KEY");
    }
}
