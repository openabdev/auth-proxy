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
    // A last label that is all digits, or `0x` and hex digits, is an IPv4 spelling the IpAddr
    // parser misses (127.1, 0x7f.0.0.1, 127.0.0.0x1). The WHATWG URL parser, and inet_aton
    // behind getaddrinfo, read every one of them as an address. Uppercase `0X` never gets here.
    if labels.last().is_some_and(|l| {
        l.bytes().all(|b| b.is_ascii_digit())
            || l.strip_prefix("0x")
                .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
    }) {
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
            if version != Version::HTTP_2 && uri_authority.is_none() {
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
/// Flags `..` and `.` segments (also with a `;` parameter, as in `..;x`, which a servlet
/// container reads as `..`), empty interior segments (`//`), `%2e` and `%2f` in any case, `%5c`,
/// `%00`, backslash, double encoding of any of those (`%252f`, `%255c`, `%2500`, `%25%32%66`, up
/// to three layers), and bytes the forwarder would percent-encode (non-ASCII, controls, space,
/// DEL, `"`, `<`, `>`, backtick, `{`, `}`), because for those the path that was matched would
/// not be the path that is sent.
pub fn path_ambiguous(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    if ["%2e", "%2f", "%5c", "%00"]
        .iter()
        .any(|s| lower.contains(s))
        || p.contains('\\')
    {
        return true;
    }
    if p.bytes()
        .any(|b| b <= 0x20 || b >= 0x7f || b"\"<>`{}".contains(&b))
    {
        return true;
    }
    if lower.match_indices("%25").any(|(i, _)| {
        let rest = &lower[i + 3..];
        rest.starts_with("2e") || rest.starts_with("2f")
    }) || encodes_separator_in_layers(lower.as_bytes())
    {
        return true;
    }
    let segs: Vec<&str> = p.split('/').skip(1).collect();
    segs.iter().enumerate().any(|(i, s)| {
        let name = s.split(';').next().unwrap_or_default();
        name == "." || name == ".." || (s.is_empty() && i + 1 != segs.len())
    })
}

/// True when percent-decoding `lower` (already ASCII-lowercased) one to three times exposes
/// `%2e`, `%2f`, `%5c` or `%00`: a second or third decoder would then read a dot, slash,
/// backslash or NUL that the first layer hid.
fn encodes_separator_in_layers(lower: &[u8]) -> bool {
    let mut cur = lower.to_vec();
    for _ in 0..3 {
        let mut out = Vec::with_capacity(cur.len());
        let mut i = 0;
        while i < cur.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if cur[i] == b'%' && i + 2 < cur.len() {
                if let (Some(h), Some(l)) = (hex(cur[i + 1]), hex(cur[i + 2])) {
                    out.push(u8::try_from(h * 16 + l).unwrap_or(b'%'));
                    i += 3;
                    continue;
                }
            }
            out.push(cur[i].to_ascii_lowercase());
            i += 1;
        }
        if [&b"%2e"[..], b"%2f", b"%5c", b"%00"]
            .iter()
            .any(|s| out.windows(s.len()).any(|w| w == *s))
        {
            return true;
        }
        if !out.contains(&b'%') {
            return false;
        }
        cur = out;
    }
    false
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

pub fn is_caller_key(k: &str) -> bool {
    k.strip_prefix("apk_").is_some_and(is_lower_hex_64)
}

/// Split `/<route>/<rest>` into the route name and the route-relative path.
///
/// The first segment must be `[a-z0-9-]{1,32}`, else `route_unknown`. A missing rest is `/`.
pub fn parse_route_path(path: &str) -> Result<(&str, String), Code> {
    let rest = path.strip_prefix('/').ok_or(Code::RouteUnknown)?;
    let (route, tail) = match rest.split_once('/') {
        Some((r, t)) => (r, format!("/{t}")),
        None => (rest, "/".to_string()),
    };
    let ok = !route.is_empty()
        && route.len() <= 32
        && route
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !ok {
        return Err(Code::RouteUnknown);
    }
    Ok((route, tail))
}

/// Read the caller key from exactly one value of `name`, in the form `apk_<64 lowercase hex>`.
///
/// Missing, duplicate, non-UTF-8 and malformed values are all `caller_rejected`. The value is
/// never formatted into a message.
pub fn caller_key_from_header(headers: &HeaderMap, name: &str) -> Result<String, Code> {
    let mut values = headers.get_all(name).iter();
    let value = match (values.next(), values.next()) {
        (Some(v), None) => v,
        _ => return Err(Code::CallerRejected),
    };
    let s = value.to_str().map_err(|_| Code::CallerRejected)?;
    if !is_caller_key(s) {
        return Err(Code::CallerRejected);
    }
    Ok(s.to_string())
}

/// True when the request framing is ambiguous and must be refused before policy runs.
///
/// Refused: `Content-Length` with `Transfer-Encoding`; more than one `Content-Length`; a
/// `Content-Length` that is not plain digits (a comma list, a sign, blanks); a
/// `Transfer-Encoding` other than a single `chunked`; a `Connection` header that nominates a
/// framing header, `Host`, `Authorization` or the caller-key header.
pub fn framing_refused(headers: &HeaderMap, caller_key_header: &str) -> bool {
    let cl: Vec<_> = headers
        .get_all(http::header::CONTENT_LENGTH)
        .iter()
        .collect();
    let te: Vec<_> = headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .collect();
    if !cl.is_empty() && !te.is_empty() {
        return true;
    }
    if cl.len() > 1 {
        return true;
    }
    if let Some(v) = cl.first() {
        let digits = v
            .to_str()
            .map(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .unwrap_or(false);
        if !digits {
            return true;
        }
    }
    if !te.is_empty() {
        let single_chunked = te.len() == 1
            && te[0]
                .to_str()
                .map(|s| s.eq_ignore_ascii_case("chunked"))
                .unwrap_or(false);
        if !single_chunked {
            return true;
        }
    }
    for v in headers.get_all(http::header::CONNECTION) {
        let Ok(s) = v.to_str() else {
            return true;
        };
        for tok in s.split(',') {
            let t = tok.trim().to_ascii_lowercase();
            if matches!(
                t.as_str(),
                "content-length" | "transfer-encoding" | "host" | "authorization"
            ) || t == caller_key_header
            {
                return true;
            }
        }
    }
    false
}

/// Replace the secret token segment of Discord webhook and interaction paths with `<redacted>`.
///
/// Matches `webhooks/<id>/<token>` and `interactions/<id>/<token>` at any depth. The rest of
/// the path is kept. A path with no such prefix is returned unchanged.
pub fn redact_path(path: &str) -> String {
    let segs: Vec<&str> = path.split('/').collect();
    let mut out: Vec<&str> = Vec::with_capacity(segs.len());
    let mut i = 0;
    while i < segs.len() {
        out.push(segs[i]);
        if (segs[i] == "webhooks" || segs[i] == "interactions") && i + 2 < segs.len() {
            out.push(segs[i + 1]);
            out.push("<redacted>");
            i += 3;
        } else {
            i += 1;
        }
    }
    out.join("/")
}

/// True for exactly 64 lowercase hex characters (sha256 hex, or the key and surrogate digests).
pub fn is_lower_hex_64(s: &str) -> bool {
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
    if !is_lower_hex_64(hex) {
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

    #[test]
    fn rejects_ipv4_mapped_ipv6_literal() {
        assert!(canonical_host("::ffff:127.0.0.1").is_err());
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
    fn rejects_missing_host_on_http10() {
        let uri: Uri = "/v1/x".parse().unwrap();
        let h = HeaderMap::new();
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_10, HOSTNAME),
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
    fn rejects_ipv4_short_form_host_header() {
        let uri: Uri = "/v1/x".parse().unwrap();
        let h = headers(&[("host", "127.1")]);
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_11, HOSTNAME),
            Err(Code::HostRejected)
        );
    }

    #[test]
    fn rejects_trailing_dot_host_header() {
        let uri: Uri = "/v1/x".parse().unwrap();
        let h = headers(&[("host", "runtime.example.dev.")]);
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_11, HOSTNAME),
            Err(Code::HostRejected)
        );
    }

    #[test]
    fn rejects_ipv6_mapped_host_header() {
        let uri: Uri = "/v1/x".parse().unwrap();
        let h = headers(&[("host", "::ffff:127.0.0.1")]);
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_11, HOSTNAME),
            Err(Code::HostRejected)
        );
    }

    #[test]
    fn rejects_absolute_form_with_userinfo_over_http1() {
        let uri: Uri = format!("https://user@{HOSTNAME}/v1/x").parse().unwrap();
        let h = headers(&[("host", HOSTNAME)]);
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_11, HOSTNAME),
            Err(Code::AbsoluteForm)
        );
    }

    #[test]
    fn rejects_userinfo_in_http2_authority() {
        let uri: Uri = format!("https://user@{HOSTNAME}/v1/x").parse().unwrap();
        let h = HeaderMap::new();
        assert_eq!(
            check_origin_form(&uri, &h, Version::HTTP_2, HOSTNAME),
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
            "/ap/k/kiro-krs/../kiro-cw/x",
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

    #[test]
    fn route_path_splits_and_refuses() {
        assert_eq!(
            parse_route_path("/discord/api/v10/x"),
            Ok(("discord", "/api/v10/x".to_string()))
        );
        assert_eq!(
            parse_route_path("/discord"),
            Ok(("discord", "/".to_string()))
        );
        assert_eq!(parse_route_path("/"), Err(Code::RouteUnknown));
        assert_eq!(parse_route_path("//x"), Err(Code::RouteUnknown));
        assert_eq!(parse_route_path("/Disc/x"), Err(Code::RouteUnknown));
        assert_eq!(
            parse_route_path(&format!("/{}/x", "a".repeat(33))),
            Err(Code::RouteUnknown)
        );
    }

    #[test]
    fn caller_key_header_rules() {
        let n = "x-ap-caller-key";
        let mut h = HeaderMap::new();
        assert_eq!(caller_key_from_header(&h, n), Err(Code::CallerRejected));
        h.append(n, HeaderValue::from_static(KEY));
        assert_eq!(caller_key_from_header(&h, n), Ok(KEY.to_string()));
        h.append(n, HeaderValue::from_static(KEY));
        assert_eq!(caller_key_from_header(&h, n), Err(Code::CallerRejected));
        let mut m = HeaderMap::new();
        m.insert(n, HeaderValue::from_static("apk_short"));
        assert_eq!(caller_key_from_header(&m, n), Err(Code::CallerRejected));
        let mut m = HeaderMap::new();
        m.insert(n, HeaderValue::from_bytes(b"apk_\xff").unwrap());
        assert_eq!(caller_key_from_header(&m, n), Err(Code::CallerRejected));
    }

    fn hm(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn framing_cases() {
        let k = "x-ap-caller-key";
        assert!(!framing_refused(&hm(&[("content-length", "12")]), k));
        assert!(!framing_refused(
            &hm(&[("transfer-encoding", "chunked")]),
            k
        ));
        assert!(!framing_refused(&hm(&[]), k));
        assert!(!framing_refused(&hm(&[("connection", "keep-alive")]), k));
        for bad in [
            vec![("content-length", "1"), ("transfer-encoding", "chunked")],
            vec![("content-length", "1"), ("content-length", "1")],
            vec![("content-length", "1, 1")],
            vec![("content-length", "+1")],
            vec![("content-length", "")],
            vec![("transfer-encoding", "gzip")],
            vec![("transfer-encoding", "gzip, chunked")],
            vec![
                ("transfer-encoding", "chunked"),
                ("transfer-encoding", "chunked"),
            ],
            vec![("connection", "close, Content-Length")],
            vec![("connection", "x-ap-caller-key")],
            vec![("connection", "authorization")],
        ] {
            assert!(framing_refused(&hm(&bad), k), "{bad:?}");
        }
    }

    #[test]
    fn redacts_webhook_and_interaction_tokens() {
        assert_eq!(
            redact_path("/api/v10/webhooks/1/SECRET/github"),
            "/api/v10/webhooks/1/<redacted>/github"
        );
        assert_eq!(
            redact_path("/api/v10/interactions/1/SECRET/callback"),
            "/api/v10/interactions/1/<redacted>/callback"
        );
        assert_eq!(
            redact_path("/api/v10/webhooks/1/SECRET"),
            "/api/v10/webhooks/1/<redacted>"
        );
        assert_eq!(
            redact_path("/api/v10/channels/1/messages"),
            "/api/v10/channels/1/messages"
        );
        assert_eq!(redact_path("/api/v10/webhooks/1"), "/api/v10/webhooks/1");
        assert_eq!(
            redact_path("/x/webhooks/1/S/interactions/2/T/c"),
            "/x/webhooks/1/<redacted>/interactions/2/<redacted>/c"
        );
    }
}
