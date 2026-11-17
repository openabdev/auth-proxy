//! Table-driven regression cases for the classes listed in issue #19. Each table names the class
//! and the input; the matrix rows in `tests/matrix` repeat the wire-level ones end to end.

use ap_core::canon::*;
use ap_core::error::Code;
use http::{HeaderMap, HeaderName, HeaderValue, Uri, Version};
use std::str::FromStr;

const KEY: &str = "apk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const AUTH: &str = "127.0.0.1:8443";

fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(
            HeaderName::from_str(k).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    h
}

fn ambiguous_all(class: &str, paths: &[&str]) {
    for p in paths {
        assert!(path_ambiguous(p), "{class}: {p:?} must be refused");
    }
}

#[test]
fn path_encoding_classes_are_refused() {
    ambiguous_all(
        "double percent-encoding",
        &[
            "/v1/%252f",
            "/v1/%252F",
            "/v1/%252e%252e/x",
            "/v1/%252E",
            "/v1/%25%32%66",
            "/v1/%25252f",
        ],
    );
    ambiguous_all(
        "encoded slash",
        &["/v1%2fx", "/v1%2Fx", "/v1/a%2f..%2fb", "/%2f"],
    );
    ambiguous_all(
        "encoded and literal backslash",
        &["/v1%5cx", "/v1%5Cx", "/v1\\x", "/v1/..\\x", "/\\"],
    );
    ambiguous_all(
        "encoded dot and NUL",
        &[
            "/v1/%2e",
            "/v1/%2E%2e/x",
            "/v1/.%2e/x",
            "/v1/%00",
            "/v1/a%00b",
        ],
    );
    ambiguous_all(
        "dot segments",
        &["/v1/..", "/v1/.", "/v1/a/../b", "/./x", "/v1/a/./b", "/.."],
    );
    ambiguous_all(
        "triple and partial double encoding",
        &[
            "/v1/%255c",
            "/v1/%255C",
            "/v1/%2500",
            "/v1/%25%32%66",
            "/v1/%25%32%65",
        ],
    );
    ambiguous_all(
        "bytes the forwarder would percent-encode (matched is not what is sent)",
        &[
            "/v1/{",
            "/v1/}",
            "/v1/\"",
            "/v1/<",
            "/v1/>",
            "/v1/`",
            "/v1/é",
            "/v1/\u{7f}",
        ],
    );
    ambiguous_all("empty interior segment", &["//x", "/v1//x", "/a///b"]);
}

#[test]
fn layered_and_mixed_case_encodings_are_refused() {
    ambiguous_all(
        "layered encodings, any hex case",
        &[
            "/v1/%25%32%46admin",
            "/v1/%25%32%66admin",
            "/v1/%25%32%45%25%32%45/admin",
            "/v1/%25%32%65%25%32%65/admin",
            "/v1/%25%35%43admin",
            "/v1/%25%35%63admin",
            "/v1/%2%45",
            "/v1/%2%65/x",
            "/v1/%2%46x",
            "/v1/%252E%252e/x",
            "/v1/%25252e",
            "/v1/%25%32%35%32%66",
            "/v1/%252525252e%252525252e/admin",
            "/v1/%2525252525x",
            "/v1/%25%33%62",
            "/v1/%2525%33%62",
        ],
    );
    ambiguous_all(
        "encoded NUL and control characters, any layer",
        &[
            "/v1/%00",
            "/v1/%0a",
            "/v1/%0D",
            "/v1/%1f",
            "/v1/%7f",
            "/v1/%7F",
            "/v1/%2500",
            "/v1/%250a",
            "/v1/%25%30%30",
            "/v1/%25%30%61",
            "/v1/%25%37%46",
        ],
    );
    ambiguous_all(
        "overlong, invalid and IIS-style UTF-8",
        &[
            "/v1/%c0%ae",
            "/v1/%C0%AE%C0%AE/x",
            "/v1/%c0%af",
            "/v1/%c1%9c",
            "/v1/%e0%80%ae",
            "/v1/%e0%80%af",
            "/v1/%f0%80%80%ae",
            "/v1/%ff",
            "/v1/%80",
            "/v1/%c3",
            "/v1/%ed%a0%80",
            "/v1/%u002e",
            "/v1/%U002E",
            "/v1/%u002f",
            "/v1/%u005c",
        ],
    );
}

#[test]
fn encoded_semicolon_on_dot_segments_is_refused() {
    ambiguous_all(
        "encoded `;` makes a dot segment carry a parameter",
        &[
            "/v1/..%3b/admin",
            "/v1/..%3B/admin",
            "/v1/.%3b/x",
            "/v1/.%3B",
            "/v1/..%3bx/admin",
            "/v1/..%3Bx",
            "/v1/.%3b.",
            "/v1/.%3b./x",
            "/v1/..%3b%2f",
            "/v1/..%3b%2fadmin",
            "/v1/%2e%2e%3b/admin",
            "/v1/%2e%2e%3B",
            "/v1/..%253b/admin",
            "/v1/..%253B/admin",
            "/v1/.%253b/x",
            "/v1/..%25%33%62/x",
            "/..%3b/x",
            "/v1/a/..%3b/b",
            "/v1/..%3b%3b/x",
        ],
    );
    // `;` in every segment of a path that has no dot segment is data and passes.
    for p in [
        "/a;b/c;d/e;f",
        "/;/;/;",
        "/v1/%3bx",
        "/v1/a%3bb",
        "/v1/a%3b",
        "/v1/%3b..",
    ] {
        assert!(!path_ambiguous(p), "{p:?} must pass");
    }
}

#[test]
fn ordinary_paths_pass_unchanged() {
    for p in [
        "/",
        "/v1/messages",
        "/v1/",
        "/a.b/c-d_e~f",
        "/v1/a..b",
        "/v1/...",
        "/v1/.hidden",
        "/v1/%41",
        "/v1/100%25",
        "/v1/a%20b",
        "/v1/%e2%82%ac",
        "/v1/%zz",
        "/v1/%",
        "/v1/%2",
        "/v1/%c3%a9",
        "/v1/%C3%A9",
        "/v1/%f0%9f%98%80",
        "/v1/%2541",
        "/v1/100%25%25",
    ] {
        assert!(!path_ambiguous(p), "{p:?} must pass");
    }
}

#[test]
fn path_parameters_on_dot_segments_are_refused() {
    // A servlet container reads `..;x` as `..`. A prefix grant on `/v1/` would then cover
    // `/v1/..;/admin` at the policy while the upstream resolves it to `/admin`.
    ambiguous_all(
        "dot segment carrying a path parameter",
        &[
            "/v1/..;/admin",
            "/v1/..;x/admin",
            "/v1/.;/x",
            "/v1/.;x",
            "/v1/..;",
            "/..;/x",
            "/v1/..;a=b;c/x",
        ],
    );
}

#[test]
fn ordinary_path_parameters_pass_and_are_not_rewritten() {
    // `;` on a real segment is data. It is forwarded byte for byte, never stripped.
    for p in ["/v1/a;b", "/v1/a;b=c/d", "/v1/;x", "/v1/a;", "/v1/;;"] {
        assert!(!path_ambiguous(p), "{p:?} must pass");
        let full = format!("/ap/{KEY}/up{p}");
        let ap = parse_ap_path(&full).unwrap();
        assert_eq!(ap.route_path, p, "route path must keep `;` bytes");
    }
}

#[test]
fn caller_key_path_form_table() {
    let k = KEY;
    let upper = KEY.to_uppercase();
    let short = &KEY[..KEY.len() - 1];
    let ok: Vec<(String, &str, String)> = vec![
        (format!("/ap/{k}/up/v1/x"), "up", "/v1/x".into()),
        (format!("/ap/{k}/up"), "up", "/".into()),
        (format!("/ap/{k}/up/"), "up", "/".into()),
        // the key and prefix appearing again later are data, not a second parse
        (format!("/ap/{k}/up/ap/{k}/x"), "up", format!("/ap/{k}/x")),
        (format!("/ap/{k}/up/ap/up/x"), "up", "/ap/up/x".into()),
        (format!("/ap/{k}/ap/{k}/x"), "ap", format!("/{k}/x")),
        // route names and rest are returned raw
        (format!("/ap/{k}/up;x/y"), "up;x", "/y".into()),
        (format!("/ap/{k}/UP/y"), "UP", "/y".into()),
    ];
    for (path, route, rest) in &ok {
        let ap = parse_ap_path(path).unwrap_or_else(|c| panic!("{path}: {c:?}"));
        assert_eq!(
            (ap.caller_key, ap.route, ap.route_path.as_str()),
            (k, *route, rest.as_str())
        );
    }
    let bad_key: Vec<String> = vec![
        "/ap/".into(),
        "/ap//up/x".into(),
        "/ap/up/x".into(),
        format!("/ap/{k}"),
        format!("/ap/{upper}/up/x"),
        format!("/ap/{short}/up/x"),
        format!("/ap/{k}0/up/x"),
        format!("/ap/{k}%2f/up/x"),
        format!("/ap/{k}?/up/x"),
        format!("/ap/{k}#/up/x"),
        format!("/ap/{k};x/up/x"),
        format!("/ap/{k} /up/x"),
        format!("/ap/ {k}/up/x"),
        format!("/ap/{}/up/x", k[..4].to_string() + &"g".repeat(64)),
        format!("/ap/apk_{}/up/x", "é".repeat(32)),
        format!("/AP/{k}/up/x"),
        format!("/ap{k}/up/x"),
        format!("//ap/{k}/up/x"),
        format!("/x/ap/{k}/up/x"),
        "/ap".into(),
        String::new(),
    ];
    for p in &bad_key {
        assert_eq!(parse_ap_path(p), Err(Code::CallerRejected), "{p:?}");
    }
    assert_eq!(parse_ap_path(&format!("/ap/{k}/")), Err(Code::RouteUnknown));
    assert_eq!(
        parse_ap_path(&format!("/ap/{k}//x")),
        Err(Code::RouteUnknown)
    );
}

#[test]
fn over_long_segments_are_not_truncated_or_panicking() {
    let long = "a".repeat(100_000);
    let p = format!("/ap/{KEY}/up/{long}/{long}");
    let ap = parse_ap_path(&p).unwrap();
    assert_eq!(ap.route_path.len(), long.len() * 2 + 2);
    assert!(!path_ambiguous(&p));
    let long_route = format!("/ap/{KEY}/{long}/x");
    assert_eq!(parse_ap_path(&long_route).unwrap().route, long);
    // The header-mode splitter caps the route name at 32 bytes and refuses past it.
    assert_eq!(
        parse_route_path(&format!("/{}/x", "a".repeat(33))),
        Err(Code::RouteUnknown)
    );
    assert!(parse_route_path(&format!("/{}/x", "a".repeat(32))).is_ok());
    // A refusal still wins when the over-long input also carries an ambiguity at the very end.
    assert!(path_ambiguous(&format!("/{long}/..")));
}

#[test]
fn host_name_classes() {
    let ok = [
        "api.example.com",
        "xn--e1afmkfd.xn--p1ai",
        "a.b",
        "1.1.1.1.example.com",
        &format!("{}.com", "a".repeat(63)),
    ];
    for h in ok {
        assert!(canonical_host(h).is_ok(), "{h}");
    }
    let bad: &[(&str, &str)] = &[
        ("mixed case", "Api.Example.com"),
        ("upper", "API.EXAMPLE.COM"),
        ("trailing dot", "api.example.com."),
        ("double trailing dot", "api.example.com.."),
        ("leading dot", ".example.com"),
        ("empty label", "a..example.com"),
        ("unicode", "bücher.example"),
        ("cyrillic homoglyph", "ex\u{0430}mple.com"),
        ("fullwidth", "ｅxample.com"),
        ("dotless i", "ıdentity.example.com"),
        ("sharp s", "straße.example"),
        ("decomposed", "u\u{0308}ber.example"),
        ("ideographic full stop", "example。com"),
        ("zero width", "exa\u{200b}mple.com"),
        ("space", "exa mple.com"),
        ("underscore", "a_b.example.com"),
        ("userinfo", "u@example.com"),
        ("port", "example.com:443"),
        ("path", "example.com/x"),
        ("percent", "exa%6dple.com"),
        ("label 64", &format!("{}.com", "a".repeat(64))),
        ("name over 253", &format!("{}.com", "a.".repeat(130))),
        ("empty", ""),
        ("single label", "localhost"),
        ("leading hyphen", "-a.example.com"),
        ("trailing hyphen", "a-.example.com"),
    ];
    for (class, h) in bad {
        assert!(canonical_host(h).is_err(), "{class}: {h:?}");
    }
}

#[test]
fn ip_literal_classes() {
    let bad = [
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "127.1",
        "127.0.1",
        "0x7f.0.0.1",
        "0x7f000001",
        "0177.0.0.1",
        "0177.0.0.01",
        "0300.0250.0.1",
        "017700000001",
        "2130706433",
        "4294967295",
        "1.1.1.1.",
        "::1",
        "::",
        "[::1]",
        "[::]",
        "::ffff:127.0.0.1",
        "[::ffff:127.0.0.1]",
        "[::ffff:7f00:1]",
        "fe80::1%25eth0",
        "[fe80::1%25eth0]",
        "0:0:0:0:0:0:0:1",
        "1.2.3",
        "1.2.3.4.5",
        "example.1",
        "example.0x1",
        "a.b.0177",
    ];
    for h in bad {
        assert!(canonical_host(h).is_err(), "{h}");
    }
}

#[test]
fn host_header_and_request_target_table() {
    let uri = |s: &str| Uri::from_str(s).unwrap();
    let h1 = Version::HTTP_11;
    let h2 = Version::HTTP_2;
    let good = hm(&[("host", AUTH)]);
    assert_eq!(check_origin_form(&uri("/x"), &good, h1, AUTH), Ok(()));

    let host = |v: &str| hm(&[("host", v)]);
    for (class, v) in [
        ("mixed case", "LOCALHOST:8443"),
        ("trailing dot", "127.0.0.1.:8443"),
        ("no port", "127.0.0.1"),
        ("wrong port", "127.0.0.1:8444"),
        ("userinfo", "u@127.0.0.1:8443"),
        ("userinfo suffix", "127.0.0.1:8443@evil.test"),
        ("comma list", "127.0.0.1:8443,evil.test"),
        ("trailing space", "127.0.0.1:8443 "),
        ("leading space", " 127.0.0.1:8443"),
        ("IPv6 mapped", "[::ffff:127.0.0.1]:8443"),
        ("decimal IP", "2130706433:8443"),
        ("octal IP", "0177.0.0.1:8443"),
        ("hex IP", "0x7f.0.0.1:8443"),
        ("IPv6 loopback", "[::1]:8443"),
        ("punycode", "xn--e1afmkfd.xn--p1ai"),
        ("empty", ""),
    ] {
        assert!(
            check_origin_form(&uri("/x"), &host(v), h1, AUTH).is_err(),
            "{class}: {v:?}"
        );
    }
    // Two Host headers, even equal, are refused: which one is read depends on the reader.
    let two = hm(&[("host", AUTH), ("host", AUTH)]);
    assert_eq!(
        check_origin_form(&uri("/x"), &two, h1, AUTH),
        Err(Code::HostRejected)
    );
    assert_eq!(
        check_origin_form(&uri("/x"), &two, h2, AUTH),
        Err(Code::HostRejected)
    );
    // No Host on HTTP/1.
    assert_eq!(
        check_origin_form(&uri("/x"), &HeaderMap::new(), h1, AUTH),
        Err(Code::HostRejected)
    );
    // Absolute form: refused over HTTP/1 even when it matches Host exactly.
    for t in [
        format!("http://{AUTH}/x"),
        format!("https://{AUTH}/x"),
        "http://evil.test/x".to_string(),
        format!("http://u:p@{AUTH}/x"),
    ] {
        assert_eq!(
            check_origin_form(&uri(&t), &good, h1, AUTH),
            Err(Code::AbsoluteForm),
            "{t}"
        );
    }
    // Absolute form vs Host mismatch over HTTP/2: the authority must equal the route.
    assert_eq!(
        check_origin_form(&uri("https://evil.test/x"), &good, h2, AUTH),
        Err(Code::HostRejected)
    );
    assert_eq!(
        check_origin_form(
            &uri(&format!("https://{AUTH}/x")),
            &host("evil.test"),
            h2,
            AUTH
        ),
        Err(Code::HostRejected)
    );
    assert_eq!(
        check_origin_form(&uri(&format!("https://{AUTH}/x")), &good, h2, AUTH),
        Ok(())
    );
}

#[test]
fn unicode_and_idn_never_reach_the_matcher() {
    // `http::Uri` refuses non-ASCII in a target and in an authority, so a Unicode form of a
    // path or host cannot be normalised into a match: it never parses.
    for t in [
        "/v1/é",
        "/v1/\u{ff0e}\u{ff0e}/x",
        "/v1/\u{2024}\u{2024}",
        "/v1/\u{ff0f}x",
        "/v1/e\u{301}",
    ] {
        // `http::Uri` accepts these bytes, so the refusal has to come from `path_ambiguous`:
        // the forwarder would percent-encode them, and what was matched must be what is sent.
        match Uri::from_str(t) {
            Err(_) => {}
            Ok(u) => assert!(path_ambiguous(u.path()), "{t:?} passes the path check"),
        }
    }
    assert!(Uri::from_str("http://exämple.com/x").is_err());
    // Overlong UTF-8 for `.` and `/` is read as a dot by lenient decoders: refused.
    assert!(path_ambiguous("/v1/%C0%AE%C0%AE/x"));
    // Header values with obs-text are not valid UTF-8 text for our readers.
    let h = {
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-ap-caller-key"),
            HeaderValue::from_bytes(b"apk_\xff").unwrap(),
        );
        h
    };
    assert_eq!(
        caller_key_from_header(&h, "x-ap-caller-key"),
        Err(Code::CallerRejected)
    );
}

#[test]
fn crlf_and_control_bytes_cannot_enter_a_header_value() {
    for v in [
        &b"a\r\nX-Injected: 1"[..],
        b"a\nb",
        b"a\rb",
        b"a\r\n folded",
        b"a\r\n\tfolded",
        b"\0",
        b"a\0b",
        b"a\x7fb",
        b"a\x01b",
    ] {
        assert!(HeaderValue::from_bytes(v).is_err(), "{v:?}");
    }
    assert!(
        HeaderValue::from_bytes(b"a\tb").is_ok(),
        "HTAB is legal inside a value"
    );
    for n in [&b"x y"[..], b"x\r\ny", b"x:y", b"", b"x\0"] {
        assert!(HeaderName::from_bytes(n).is_err(), "{n:?}");
    }
}

#[test]
fn duplicate_and_conflicting_headers_table() {
    let k = "x-ap-caller-key";
    // caller key
    assert_eq!(
        caller_key_from_header(&hm(&[(k, KEY)]), k),
        Ok(KEY.to_string())
    );
    for h in [
        hm(&[(k, KEY), (k, KEY)]),
        hm(&[(k, KEY), ("X-AP-Caller-Key", KEY)]),
        hm(&[(k, &KEY.to_uppercase())]),
        hm(&[(k, &format!("{KEY} "))]),
        hm(&[(k, &format!("{KEY},{KEY}"))]),
        HeaderMap::new(),
    ] {
        assert_eq!(
            caller_key_from_header(&h, k),
            Err(Code::CallerRejected),
            "{h:?}"
        );
    }
    // surrogate
    let sur = format!("Bearer aps_{}", &KEY[4..]);
    assert!(surrogate_from_headers(&hm(&[("authorization", &sur)]), "authorization").is_ok());
    assert_eq!(
        surrogate_from_headers(
            &hm(&[("authorization", &sur), ("authorization", &sur)]),
            "authorization"
        ),
        Err(Code::SurrogateAmbiguous)
    );
    for bad in [
        sur.to_lowercase(),
        sur.replace("Bearer", "bearer"),
        format!("{sur} "),
        format!(" {sur}"),
        format!("{sur}, {sur}"),
    ] {
        assert_eq!(
            surrogate_from_headers(&hm(&[("authorization", &bad)]), "authorization"),
            Err(Code::SurrogateMalformed),
            "{bad:?}"
        );
    }
    // framing
    let refused: &[&[(&str, &str)]] = &[
        &[("content-length", "5"), ("content-length", "5")],
        &[("content-length", "5, 5")],
        &[("content-length", "+5")],
        &[("content-length", "5 ")],
        &[("content-length", "0x5")],
        &[("content-length", "")],
        &[("content-length", "5"), ("transfer-encoding", "chunked")],
        &[
            ("transfer-encoding", "chunked"),
            ("transfer-encoding", "chunked"),
        ],
        &[("transfer-encoding", "chunked, chunked")],
        &[("transfer-encoding", "gzip, chunked")],
        &[("transfer-encoding", "identity")],
        &[("connection", "close, Content-Length")],
        &[("connection", "Transfer-Encoding")],
        &[("connection", "x-ap-caller-key")],
        &[("connection", "host")],
        &[("connection", "authorization")],
    ];
    for h in refused {
        assert!(framing_refused(&hm(h), k), "{h:?}");
    }
    let fine: &[&[(&str, &str)]] = &[
        &[],
        &[("content-length", "5")],
        &[("transfer-encoding", "CHUNKED")],
        &[("connection", "keep-alive")],
    ];
    for h in fine {
        assert!(!framing_refused(&hm(h), k), "{h:?}");
    }
}
