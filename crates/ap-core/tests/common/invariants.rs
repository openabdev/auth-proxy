//! Invariant checks for request canonicalization.
//!
//! One source of truth for two callers: the deterministic differential test
//! (`tests/canon_differential.rs`) and the cargo-fuzz targets (`fuzz/fuzz_targets/*.rs`, which
//! include this file by path). Every function panics with the offending input when an
//! invariant breaks, so a fuzz crash and a test failure both name the input.
//!
//! The rules checked here are the ones in `canon.rs`: one pass before any decision, forward
//! exactly what was checked, refuse ambiguity instead of normalising it.
#![allow(dead_code)]

use ap_core::canon::{
    caller_key_from_header, canonical_host, check_origin_form, framing_refused, is_caller_key,
    parse_ap_path, parse_route_path, path_ambiguous, surrogate_from_headers,
};
use ap_core::error::Code;
use http::{HeaderMap, HeaderName, HeaderValue, Uri, Version};
use std::str::FromStr;

/// The caller key and route split must be exact, and must agree with the header-mode splitter.
pub fn check_ap_path(p: &str) {
    match parse_ap_path(p) {
        Ok(ap) => {
            assert!(is_caller_key(ap.caller_key), "key shape: {p:?}");
            assert!(
                !ap.route.is_empty() && !ap.route.contains('/'),
                "route shape: {p:?}"
            );
            assert!(ap.route_path.starts_with('/'), "route_path: {p:?}");
            // The split loses nothing and invents nothing: the pieces rebuild the input, except
            // that `/ap/<k>/<r>` and `/ap/<k>/<r>/` both give route_path `/`.
            let tail = if ap.route_path == "/" {
                ""
            } else {
                ap.route_path.as_str()
            };
            let rebuilt = format!("/ap/{}/{}{}", ap.caller_key, ap.route, tail);
            assert!(
                p == rebuilt || p == format!("{rebuilt}/"),
                "split does not rebuild the input: {p:?} -> {ap:?}"
            );
            // Passthrough strips `/ap/<key>` and splits the rest with `parse_route_path`.
            let suffix = &p["/ap/".len() + ap.caller_key.len()..];
            if let Ok((route, rel)) = parse_route_path(suffix) {
                assert_eq!(
                    route, ap.route,
                    "two splitters disagree on the route: {p:?}"
                );
                assert_eq!(
                    rel, ap.route_path,
                    "two splitters disagree on the path: {p:?}"
                );
            }
        }
        Err(code) => assert!(
            matches!(code, Code::CallerRejected | Code::RouteUnknown),
            "unexpected refusal {code:?} for {p:?}"
        ),
    }
}

/// An accepted path must be one that the `http` crate and the WHATWG `url` crate (which the
/// forwarder builds the upstream URL with) both read as the same bytes. A parser that would
/// rewrite it (dot segments, backslash, percent-encoding of non-ASCII or of `{`, `}`, `"`) is a
/// parser that disagrees with the policy check, and what was matched is not what is sent.
pub fn check_path_against_parsers(p: &str) {
    let Ok(uri) = Uri::from_str(p) else { return };
    // The pipeline matches `uri.path()`, never the raw target.
    let path = uri.path();
    // Every route starts with `/ap/` or `/<route>`; `*` and an empty path never reach a route.
    if !path.starts_with('/') || path_ambiguous(path) {
        return;
    }
    let Ok(url) = url::Url::parse(&format!("https://example.test{path}")) else {
        panic!("url refuses an accepted path: {path:?}");
    };
    assert_eq!(
        url.path(),
        path,
        "url::Url rewrote a path that path_ambiguous accepted"
    );
}

/// Everything about a request path that must hold for any string.
pub fn check_path(p: &str) {
    check_ap_path(p);
    check_path_against_parsers(p);
}

/// An accepted host is already the canonical spelling: the `url` crate's host parser returns
/// the identical domain, never an IP, never a rewritten name (it may refuse a malformed `xn--`
/// label, see below).
pub fn check_host(h: &str) {
    if canonical_host(h).is_err() {
        return;
    }
    assert!(h.is_ascii(), "non-ASCII host accepted: {h:?}");
    assert!(
        h.parse::<std::net::IpAddr>().is_err(),
        "IP literal accepted: {h:?}"
    );
    match url::Host::parse(h) {
        Ok(url::Host::Domain(d)) => assert_eq!(d, h, "url rewrote an accepted host: {h:?}"),
        // A malformed `xn--` label is not a valid IDNA name. `canonical_host` keeps it byte for
        // byte and the egress allowlist compares bytes, so nothing is rewritten; the `url` crate
        // refuses it. That is the one accepted disagreement.
        Err(_) if h.split('.').any(|l| l.starts_with("xn--")) => {}
        other => panic!("url reads accepted host {h:?} as {other:?}"),
    }
    let auth = http::uri::Authority::from_str(h).expect("authority");
    assert_eq!(auth.host(), h, "http::Authority disagrees on host {h:?}");
    assert!(auth.port().is_none(), "port in accepted host {h:?}");
}

/// Build a header map from raw pairs. Pairs that `http` itself refuses are dropped, which is
/// what the wire parser does before our code runs.
pub fn header_map(pairs: &[(Vec<u8>, Vec<u8>)]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for (k, v) in pairs {
        if let (Ok(k), Ok(v)) = (HeaderName::from_bytes(k), HeaderValue::from_bytes(v)) {
            m.append(k, v);
        }
    }
    m
}

/// Caller-key, surrogate and framing decisions over arbitrary headers.
pub fn check_headers(pairs: &[(Vec<u8>, Vec<u8>)], key_header: &str) {
    let h = header_map(pairs);

    if let Ok(k) = caller_key_from_header(&h, key_header) {
        let vals: Vec<_> = h.get_all(key_header).iter().collect();
        assert_eq!(vals.len(), 1, "caller key accepted from several values");
        assert_eq!(vals[0].as_bytes(), k.as_bytes());
        assert!(is_caller_key(&k));
    }

    if let Ok(s) = surrogate_from_headers(&h, "authorization") {
        let vals: Vec<_> = h.get_all("authorization").iter().collect();
        assert_eq!(vals.len(), 1, "surrogate accepted from several values");
        assert_eq!(vals[0].as_bytes(), format!("Bearer {s}").as_bytes());
    }

    if !framing_refused(&h, key_header) {
        let cl: Vec<_> = h.get_all("content-length").iter().collect();
        let te: Vec<_> = h.get_all("transfer-encoding").iter().collect();
        assert!(cl.is_empty() || te.is_empty(), "CL with TE accepted");
        assert!(cl.len() <= 1, "several Content-Length accepted");
        if let Some(v) = cl.first() {
            assert!(
                !v.as_bytes().is_empty() && v.as_bytes().iter().all(u8::is_ascii_digit),
                "non-digit Content-Length accepted: {v:?}"
            );
        }
        if !te.is_empty() {
            assert!(
                te.len() == 1 && te[0].as_bytes().eq_ignore_ascii_case(b"chunked"),
                "Transfer-Encoding other than one chunked accepted"
            );
        }
        for v in h.get_all("connection") {
            let s = v.to_str().expect("non-UTF-8 Connection accepted");
            for t in s.split(',') {
                let t = t.trim().to_ascii_lowercase();
                assert!(
                    !matches!(
                        t.as_str(),
                        "content-length" | "transfer-encoding" | "host" | "authorization"
                    ) && t != key_header,
                    "Connection nominates {t}"
                );
            }
        }
    }
}

/// The request target and Host check. When it accepts, the Host that was compared is the Host
/// that the rest of the pipeline sees: one value, byte-identical to the route authority.
pub fn check_origin(target: &str, hosts: &[Vec<u8>], http2: bool, expected: &str) {
    let Ok(uri) = Uri::from_str(target) else {
        return;
    };
    let mut h = HeaderMap::new();
    for v in hosts {
        if let Ok(v) = HeaderValue::from_bytes(v) {
            h.append(http::header::HOST, v);
        }
    }
    let version = if http2 {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    if check_origin_form(&uri, &h, version, expected).is_err() {
        return;
    }
    let vals: Vec<_> = h.get_all(http::header::HOST).iter().collect();
    assert!(vals.len() <= 1, "several Host values accepted");
    for v in &vals {
        assert_eq!(v.as_bytes(), expected.as_bytes(), "Host differs from route");
    }
    match uri.authority() {
        Some(a) => {
            assert!(http2, "absolute form accepted over HTTP/1");
            assert_eq!(a.as_str(), expected, "URI authority differs from route");
        }
        None => {
            assert!(uri.scheme().is_none(), "scheme without authority accepted");
            if !http2 {
                assert_eq!(vals.len(), 1, "HTTP/1 request accepted without a Host");
            }
        }
    }
    assert!(!expected.contains('@'));
}
