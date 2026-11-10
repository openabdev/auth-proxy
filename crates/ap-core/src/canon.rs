//! Canonicalization of hosts, paths and surrogates.
//!
//! Every check runs on the raw wire form. No decoding layer may disagree with
//! the policy check about what a path or host is.

use crate::error::Code;
use http::header::HOST;
use http::{HeaderMap, Uri, Version};
use std::net::IpAddr;

/// Validate a host as a canonical lowercase DNS name.
///
/// Rejects IP literals (including IPv4 short and hex spellings), IPv6 brackets,
/// userinfo, ports, trailing dots, uppercase letters, non-LDH characters,
/// single-label names and a numeric last label.
pub fn canonical_host(h: &str) -> Result<(), &'static str> {
    if h.is_empty() || h.len() > 253 {
        return Err("empty or longer than 253 bytes");
    }
    if h.parse::<IpAddr>().is_ok() || h.starts_with('[') {
        return Err("IP literal");
    }
    if h != h.to_ascii_lowercase() {
        return Err("not lowercase");
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() < 2 {
        return Err("single label");
    }
    for l in &labels {
        let ok = !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err("bad label (userinfo, port, trailing dot or non-LDH)");
        }
    }
    // An all-numeric last label is an IPv4 spelling the IpAddr parser misses (127.1, 0x7f.0.0.1).
    if labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("numeric TLD (IPv4 spelling)");
    }
    Ok(())
}

/// Check the request target and Host header against the route host.
///
/// HTTP/1.x requests must use origin-form and carry exactly one Host header
/// equal to `expected_host`. HTTP/2 requests carry the authority in the URI;
/// when present it must equal `expected_host`. Userinfo in any authority is refused.
pub fn check_origin_form(
    uri: &Uri,
    headers: &HeaderMap,
    version: Version,
    expected_host: &str,
) -> Result<(), Code> {
    let uri_authority = uri.authority().map(|a| a.as_str());
    if let Some(a) = uri_authority {
        if version != Version::HTTP_2 {
            return Err(Code::AbsoluteForm);
        }
        if a.contains('@') || a != expected_host {
            return Err(Code::HostRejected);
        }
    } else if uri.scheme().is_some() {
        return Err(Code::AbsoluteForm);
    }

    let mut hosts = headers.get_all(HOST).iter();
    match (hosts.next(), hosts.next()) {
        (Some(_), Some(_)) => Err(Code::HostRejected),
        (None, _) => {
            if version == Version::HTTP_11 && uri_authority.is_none() {
                Err(Code::HostRejected)
            } else {
                Ok(())
            }
        }
        (Some(v), None) => {
            let s = v.to_str().map_err(|_| Code::HostRejected)?;
            if s.contains('@') || s != expected_host {
                Err(Code::HostRejected)
            } else {
                Ok(())
            }
        }
    }
}

/// True when the raw, still-encoded path could be read two ways.
///
/// Flags `..` and `.` segments, empty interior segments (`//`), `%2e` and `%2f`
/// in any case, `%5c`, `%00`, backslash, and `%25` followed by `2e` or `2f`
/// (double encoding).
pub fn path_ambiguous(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    if ["%2e", "%2f", "%5c", "%00"]
        .iter()
        .any(|s| lower.contains(s))
        || p.contains('\\')
    {
        return true;
    }
    if lower.match_indices("%25").any(|(i, _)| {
        let rest = &lower[i + 3..];
        rest.starts_with("2e") || rest.starts_with("2f")
    }) {
        return true;
    }
    let segs: Vec<&str> = p.split('/').skip(1).collect();
    segs.iter()
        .enumerate()
        .any(|(i, s)| *s == "." || *s == ".." || (s.is_empty() && i + 1 != segs.len()))
}

/// The parts of a `/ap/<caller-key>/<route>/<rest>` path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApPath<'a> {
    pub caller_key: &'a str,
    pub route: &'a str,
    /// Route-relative path, always starting with `/`.
    pub route_path: String,
}

/// Split a request path into caller key, route name and route-relative path.
///
/// The caller key must be `apk_` followed by 64 lowercase hex characters.
/// A missing or malformed key is `caller_rejected`. A missing route segment is `route_unknown`.
pub fn parse_ap_path(path: &str) -> Result<ApPath<'_>, Code> {
    let rest = path.strip_prefix("/ap/").ok_or(Code::CallerRejected)?;
    let (key, after) = rest.split_once('/').ok_or(Code::CallerRejected)?;
    if !is_caller_key(key) {
        return Err(Code::CallerRejected);
    }
    let (route, remainder) = match after.split_once('/') {
        Some((r, tail)) => (r, format!("/{tail}")),
        None => (after, "/".to_string()),
    };
    if route.is_empty() {
        return Err(Code::RouteUnknown);
    }
    Ok(ApPath {
        caller_key: key,
        route,
        route_path: remainder,
    })
}

fn is_caller_key(k: &str) -> bool {
    k.strip_prefix("apk_").is_some_and(is_64_lower_hex)
}

fn is_64_lower_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Read the surrogate from exactly one `header` value of the form `Bearer aps_<64 lowercase hex>`.
///
/// Returns the token without the scheme (`aps_...`). Zero values are `surrogate_missing`,
/// two or more are `surrogate_ambiguous`, anything else that does not match is `surrogate_malformed`.
pub fn surrogate_from_headers(headers: &HeaderMap, header: &str) -> Result<String, Code> {
    let mut values = headers.get_all(header).iter();
    let value = match (values.next(), values.next()) {
        (None, _) => return Err(Code::SurrogateMissing),
        (Some(_), Some(_)) => return Err(Code::SurrogateAmbiguous),
        (Some(v), None) => v,
    };
    let s = value.to_str().map_err(|_| Code::SurrogateMalformed)?;
    let token = s.strip_prefix("Bearer ").ok_or(Code::SurrogateMalformed)?;
    let hex = token.strip_prefix("aps_").ok_or(Code::SurrogateMalformed)?;
    if !is_64_lower_hex(hex) {
        return Err(Code::SurrogateMalformed);
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    const KEY: &str = "apk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SUR: &str = "aps_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_canonical_names() {
        for ok in ["api.anthropic.com", "runtime.us-east-1.kiro.dev", "a-b.c"] {
            assert!(canonical_host(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn rejects_ipv4_literal() {
        assert!(canonical_host("127.0.0.1").is_err());
    }

    #[test]
    fn rejects_ipv6_literal() {
        assert!(canonical_host("::1").is_err());
    }

    #[test]
    fn rejects_bracketed_ipv6() {
        assert!(canonical_host("[::1]").is_err());
    }

    #[test]
    fn rejects_ipv4_short_form() {
        assert!(canonical_host("127.1").is_err());
    }

    #[test]
    fn rejects_ipv4_hex_form() {
        assert!(canonical_host("0x7f.0.0.1").is_err());
    }

    #[test]
    fn rejects_trailing_dot() {
        assert!(canonical_host("api.x.com.").is_err());
    }

    #[test]
    fn rejects_uppercase() {
        assert!(canonical_host("API.x.com").is_err());
    }

    #[test]
    fn rejects_userinfo() {
        assert!(canonical_host("user@api.x.com").is_err());
    }

    #[test]
    fn rejects_port() {
        assert!(canonical_host("api.x.com:443").is_err());
    }

    #[test]
    fn rejects_single_label() {
        assert!(canonical_host("localhost").is_err());
    }

    #[test]
    fn rejects_non_ldh_and_empty_labels() {
        assert!(canonical_host("a..b").is_err());
        assert!(canonical_host("-a.b").is_err());
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    const HOSTNAME: &str = "runtime.example.dev";

    #[test]
    fn origin_form_with_matching_host_passes() {
        let uri: Uri = "/v1/x".parse().unwrap();
        let h = headers(&[("host", HOSTNAME)]);
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_11, HOSTNAME),
            Ok(())
        );
    }

    #[test]
    fn rejects_absolute_form_over_http1() {
        let uri: Uri = format!("https://{HOSTNAME}/v1/x").parse().unwrap();
        let h = headers(&[("host", HOSTNAME)]);
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_11, HOSTNAME),
            Err(Code::AbsoluteForm)
        );
    }

    #[test]
    fn rejects_userinfo_in_host_header() {
        let uri: Uri = "/v1/x".parse().unwrap();
        let h = headers(&[("host", &format!("user@{HOSTNAME}"))]);
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_11, HOSTNAME),
            Err(Code::HostRejected)
        );
    }

    #[test]
    fn rejects_two_host_headers() {
        let uri: Uri = "/v1/x".parse().unwrap();
        let h = headers(&[("host", HOSTNAME), ("host", HOSTNAME)]);
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_11, HOSTNAME),
            Err(Code::HostRejected)
        );
    }

    #[test]
    fn rejects_missing_host_on_http11() {
        let uri: Uri = "/v1/x".parse().unwrap();
        let h = HeaderMap::new();
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_11, HOSTNAME),
            Err(Code::HostRejected)
        );
    }

    #[test]
    fn rejects_mismatched_host_header() {
        let uri: Uri = "/v1/x".parse().unwrap();
        let h = headers(&[("host", "other.example.dev")]);
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_11, HOSTNAME),
            Err(Code::HostRejected)
        );
    }

    #[test]
    fn http2_authority_must_match() {
        let uri: Uri = format!("https://{HOSTNAME}/v1/x").parse().unwrap();
        let h = HeaderMap::new();
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_2, HOSTNAME),
            Ok(())
        );
        let other: Uri = "https://other.example.dev/v1/x".parse().unwrap();
        assert_eq!(
            check_origin_form(&other, &h, Version::HTTP_2, HOSTNAME),
            Err(Code::HostRejected)
        );
    }

    #[test]
    fn path_variants_are_ambiguous() {
        // Matrix X2-1 variants.
        for bad in [
            "/ap/k/r/../x",
            "/ap/k/r/%2e%2e/x",
            "/ap/k/r/%2E%2e/x",
            "/ap/k/r/a%2Fb",
            "/ap//r/x",
            "/ap/k/r/%252e%252e/x",
        ] {
            assert!(path_ambiguous(bad), "{bad}");
        }
    }

    #[test]
    fn plain_paths_are_not_ambiguous() {
        for ok in ["/ap/k/r/v1/messages", "/ap/k/r/", "/ap/k/r", "/ap/k/r/%20x"] {
            assert!(!path_ambiguous(ok), "{ok}");
        }
    }

    #[test]
    fn ap_path_splits_key_route_and_rest() {
        let path = format!("/ap/{KEY}/kiro-krs/v1/messages");
        let p = parse_ap_path(&path).unwrap();
        assert_eq!(p.caller_key, KEY);
        assert_eq!(p.route, "kiro-krs");
        assert_eq!(p.route_path, "/v1/messages");
    }

    #[test]
    fn ap_path_without_rest_is_root() {
        let path = format!("/ap/{KEY}/kiro-krs");
        let p = parse_ap_path(&path).unwrap();
        assert_eq!(p.route_path, "/");
    }

    #[test]
    fn ap_path_rejects_missing_prefix() {
        assert_eq!(parse_ap_path("/v1/x"), Err(Code::CallerRejected));
    }

    #[test]
    fn ap_path_rejects_bad_caller_key() {
        let upper = KEY.to_uppercase().replace("APK_", "apk_");
        assert_eq!(
            parse_ap_path(&format!("/ap/{upper}/r/x")),
            Err(Code::CallerRejected)
        );
        assert_eq!(
            parse_ap_path("/ap/apk_short/r/x"),
            Err(Code::CallerRejected)
        );
        assert_eq!(
            parse_ap_path(&format!("/ap/aps_{}/r/x", &KEY[4..])),
            Err(Code::CallerRejected)
        );
    }

    #[test]
    fn ap_path_rejects_empty_route() {
        assert_eq!(
            parse_ap_path(&format!("/ap/{KEY}//x")),
            Err(Code::RouteUnknown)
        );
    }

    #[test]
    fn surrogate_reads_single_bearer_value() {
        let bearer = format!("Bearer {SUR}");
        let h = headers(&[("authorization", bearer.as_str())]);
        assert_eq!(
            surrogate_from_headers(&h, "authorization"),
            Ok(SUR.to_string())
        );
    }

    #[test]
    fn surrogate_missing_when_absent() {
        assert_eq!(
            surrogate_from_headers(&HeaderMap::new(), "authorization"),
            Err(Code::SurrogateMissing)
        );
    }

    #[test]
    fn surrogate_ambiguous_when_two_values() {
        let bearer = format!("Bearer {SUR}");
        let h = headers(&[
            ("authorization", bearer.as_str()),
            ("authorization", bearer.as_str()),
        ]);
        assert_eq!(
            surrogate_from_headers(&h, "authorization"),
            Err(Code::SurrogateAmbiguous)
        );
    }

    #[test]
    fn surrogate_malformed_variants() {
        for bad in [
            format!("Basic {SUR}"),
            SUR.to_string(),
            format!("Bearer {}", SUR.to_uppercase().replace("APS_", "aps_")),
            format!("Bearer aps_{}", &SUR[4..60]),
            format!("Bearer apk_{}", &SUR[4..]),
        ] {
            let h = headers(&[("authorization", &bad)]);
            assert_eq!(
                surrogate_from_headers(&h, "authorization"),
                Err(Code::SurrogateMalformed),
                "{bad}"
            );
        }
    }
}
