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
    parse_ap_path, parse_route_path, path_ambiguous, path_ambiguous_passthrough,
    surrogate_from_headers,
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
    check_gate("POST", p);
    check_gate("PUT", p);
    check_ap_path(p);
    check_decode_oracle(p);
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

/// Independent oracle for the layered-decode rule. It decodes to a fixed point with a different
/// implementation (char-level, each byte carrying the depth that produced it) and states what
/// must be refused: a dot, slash, backslash, NUL or control byte produced by any decode, a
/// semicolon produced from the second layer on, a `.`/`..` segment (before any `;`) in any
/// layer, and an escape still decodable after four layers. If the oracle demands refusal,
/// `path_ambiguous` must refuse; the reverse is not asserted because the production rule also
/// refuses bytes the forwarder would re-encode, `%u` escapes and invalid UTF-8.
pub fn check_decode_oracle(p: &str) {
    if oracle_must_refuse(p, false) {
        assert!(
            path_ambiguous(p),
            "decode oracle demands refusal but path_ambiguous accepted {p:?}"
        );
    }
    if oracle_must_refuse(p, true) {
        assert!(
            path_ambiguous_passthrough(p),
            "decode oracle demands refusal but path_ambiguous_passthrough accepted {p:?}"
        );
    }
}

/// `strict` adds the passthrough rule: an unreserved byte spelled as an escape names the same
/// resource as its plain form (RFC 3986 6.2.2.2), so match form and forward form would differ.
fn oracle_must_refuse(p: &str, strict: bool) -> bool {
    // (byte, depth that produced it; 0 = literal)
    let mut layer: Vec<(u8, usize)> = p.bytes().map(|b| (b, 0)).collect();
    for depth in 1..=4 {
        if has_dot_segment(&layer) {
            return true;
        }
        let mut next = Vec::new();
        let mut changed = false;
        let mut i = 0;
        while i < layer.len() {
            let esc = (layer[i].0 == b'%' && i + 2 < layer.len())
                .then(|| {
                    let hex: String = layer[i + 1..i + 3].iter().map(|x| x.0 as char).collect();
                    (hex.len() == 2 && hex.chars().all(|c| c.is_ascii_hexdigit()))
                        .then(|| u8::from_str_radix(&hex, 16).unwrap())
                })
                .flatten();
            match esc {
                Some(b) => {
                    if matches!(b, 0 | b'.' | b'/' | b'\\')
                        || b < 0x20
                        || b == 0x7f
                        || (strict
                            && (b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'~')))
                    {
                        return true;
                    }
                    if b == b';' && depth >= 2 {
                        return true;
                    }
                    next.push((b, depth));
                    changed = true;
                    i += 3;
                }
                None => {
                    next.push(layer[i]);
                    i += 1;
                }
            }
        }
        if !changed {
            return false;
        }
        layer = next;
    }
    has_dot_segment(&layer)
        || (0..layer.len()).any(|i| {
            layer[i].0 == b'%'
                && layer.len() > i + 2
                && layer[i + 1].0.is_ascii_hexdigit()
                && layer[i + 2].0.is_ascii_hexdigit()
        })
}

fn has_dot_segment(layer: &[(u8, usize)]) -> bool {
    let text: String = layer.iter().map(|x| x.0 as char).collect();
    text.split('/')
        .skip(1)
        .any(|seg| matches!(seg.split(';').next(), Some(".") | Some("..")))
}

// ---------------------------------------------------------------------------------------------
// Hold-gate oracle
//
// An RFC 3986 normaliser that shares no code with `canon.rs` or `policy.rs` computes the "same
// resource" form of a request path. If that form matches a hold pattern, the gate (the path
// canonicalization refusal, then the policy verdict) must hold the request or refuse it. It must
// never forward it unheld. Two policies are checked: the shipped shape, where the loader keeps
// allow grants disjoint from hold patterns, and an engine-only shape where an allow prefix `/`
// covers everything, which isolates what the matcher and canonicalization guarantee by
// themselves.
// ---------------------------------------------------------------------------------------------

use ap_core::config::{load, Decision};
use ap_core::policy::{Snapshot, Verdict};
use std::sync::OnceLock;

const HOLD_PATTERNS: &[&str] = &[
    "/hold/*/messages",
    "/api/v10/channels/*/messages",
    "/*/pin",
    "/hold/pin/last",
    "/webhooks/*/*",
];

const GATE_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn gate_policy_text() -> String {
    let pats: Vec<String> = HOLD_PATTERNS.iter().map(|p| format!("\"{p}\"")).collect();
    format!(
        "version = 1\n[listen]\nproxy = \"127.0.0.1:8443\"\n[passthrough]\npublic_authority = \"gate.example.test\"\n\
         [[identity]]\nname = \"muse\"\ncaller_key_sha256 = \"{GATE_KEY}\"\n\
         [[route]]\nname = \"discord\"\nhost = \"discord.com\"\nmode = \"passthrough\"\n\
         [[grant]]\nidentity = \"muse\"\nroute = \"discord\"\ndecision = \"hold\"\nmethods = [\"POST\", \"PUT\"]\npath_patterns = [{}]\n\
         [[grant]]\nidentity = \"muse\"\nroute = \"discord\"\nmethods = [\"GET\"]\npaths = [\"/\"]\n\
         [[grant]]\nidentity = \"muse\"\nroute = \"discord\"\nmethods = [\"POST\", \"PUT\"]\npaths = [\"/other/x/\"]\n",
        pats.join(", ")
    )
}

/// (shipped shape, engine-only shape with an allow prefix `/` over the held methods).
fn gate_policies() -> &'static (Snapshot, Snapshot) {
    static P: OnceLock<(Snapshot, Snapshot)> = OnceLock::new();
    P.get_or_init(|| {
        let mut cfg = load(&gate_policy_text()).expect("gate policy loads");
        let shipped = Snapshot::from_config(&cfg);
        for g in cfg
            .grants
            .iter_mut()
            .filter(|g| g.decision == Decision::Allow)
        {
            g.methods = vec!["GET".into(), "POST".into(), "PUT".into()];
            g.paths = vec!["/".into()];
        }
        (shipped, Snapshot::from_config(&cfg))
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum Gate {
    Refused,
    Held,
    Allowed,
    Denied,
}

fn gate(snap: &Snapshot, method: &str, path: &str) -> Gate {
    if path_ambiguous_passthrough(path) {
        return Gate::Refused;
    }
    match snap.evaluate_verdict("muse", "discord", method, path) {
        Ok(Verdict::Hold) => Gate::Held,
        Ok(Verdict::Allow) => Gate::Allowed,
        Err(_) => Gate::Denied,
    }
}

/// RFC 3986 normaliser, written from the RFC alone: decode escapes of unreserved characters
/// (and `%25`, so layered spellings collapse the way a double-decoding hop would read them) to
/// a fixed point, upper-case the hex of the escapes that remain, remove dot segments, collapse
/// empty segments and drop a trailing slash. Returns the path segments.
pub fn rfc3986_segments(path: &str) -> Vec<String> {
    fn escape_at(b: &[u8], i: usize) -> Option<u8> {
        let h = |j: usize| b.get(j).and_then(|c| (*c as char).to_digit(16));
        if b.get(i) != Some(&b'%') {
            return None;
        }
        Some((h(i + 1)? * 16 + h(i + 2)?) as u8)
    }
    let mut cur: Vec<u8> = path.bytes().collect();
    for _ in 0..16 {
        let mut out = Vec::with_capacity(cur.len());
        let mut i = 0;
        let mut changed = false;
        while i < cur.len() {
            match escape_at(&cur, i) {
                Some(b)
                    if b.is_ascii_alphanumeric()
                        || matches!(b, b'-' | b'.' | b'_' | b'~' | b'%') =>
                {
                    out.push(b);
                    i += 3;
                    changed = true;
                }
                _ => {
                    out.push(cur[i]);
                    i += 1;
                }
            }
        }
        cur = out;
        if !changed {
            break;
        }
    }
    // Upper-case the hex digits of the escapes that are left.
    let mut i = 0;
    while i < cur.len() {
        if escape_at(&cur, i).is_some() {
            cur[i + 1] = cur[i + 1].to_ascii_uppercase();
            cur[i + 2] = cur[i + 2].to_ascii_uppercase();
            i += 3;
        } else {
            i += 1;
        }
    }
    let text = String::from_utf8_lossy(&cur).into_owned();
    // remove_dot_segments over the segments, empties collapsed.
    let mut out: Vec<String> = Vec::new();
    for seg in text.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s.to_string()),
        }
    }
    out
}

/// True when the normalised form of `path` is a whole-path match for one of the hold patterns.
pub fn oracle_matches_hold(path: &str) -> bool {
    let segs = rfc3986_segments(path);
    HOLD_PATTERNS.iter().any(|pat| {
        let ps: Vec<&str> = pat.trim_start_matches('/').split('/').collect();
        ps.len() == segs.len() && ps.iter().zip(&segs).all(|(p, s)| *p == "*" || p == s)
    })
}

/// The verdict of the shipped-shape policy, for tests that count outcomes.
pub fn gate_shipped(method: &str, path: &str) -> Gate {
    gate(&gate_policies().0, method, path)
}

/// A request whose same-resource form is held must be held or refused, under both policies.
pub fn check_gate(method: &str, path: &str) {
    if !path.starts_with('/') || !oracle_matches_hold(path) {
        return;
    }
    let (shipped, engine_only) = gate_policies();
    for (name, snap) in [("shipped", shipped), ("engine-only", engine_only)] {
        let g = gate(snap, method, path);
        assert_ne!(
            g,
            Gate::Allowed,
            "{name} policy forwards {method} {path:?} unheld (normalised: {:?})",
            rfc3986_segments(path)
        );
    }
}

/// Build a request aimed at a hold pattern from a stream of choices. `pick(n)` returns a value
/// below `n`. Used by the deterministic test (seeded generator) and by the fuzz target (input
/// bytes), so both explore the same space: every pattern, literal and wildcard segments, the
/// first and last position, each unreserved character written as an escape in either hex case,
/// layered escapes, dot and empty segments, and a trailing slash.
pub fn hold_probe(pick: &mut dyn FnMut(usize) -> usize) -> (&'static str, String) {
    const FILL: &[&str] = &["1", "42", "abc", "Z9", "x-y", "a.b", "a_b", "t~", "m", "M"];
    let method = ["POST", "PUT"][pick(2)];
    let pat = HOLD_PATTERNS[pick(HOLD_PATTERNS.len())];
    // One probe in three is spelled plainly, so the run also reaches the `Held` outcome.
    let plain = pick(3) == 0;
    let mut path = String::new();
    for seg in pat.trim_start_matches('/').split('/') {
        path.push_str(if plain {
            "/"
        } else {
            ["/", "/", "/", "//", "/./", "/x/../"][pick(6)]
        });
        let text = if seg == "*" {
            FILL[pick(FILL.len())]
        } else {
            seg
        };
        for ch in text.chars() {
            // 0..=3: plain; otherwise an escape in one of four spellings.
            match if plain { 0 } else { pick(8) } {
                0..=3 => path.push(ch),
                n => {
                    let hex = if n % 2 == 0 {
                        format!("{:02X}", ch as u32)
                    } else {
                        format!("{:02x}", ch as u32)
                    };
                    let esc = format!("%{hex}");
                    match pick(6) {
                        0 => path.push_str(&esc.replace('%', "%25")),
                        1 => path.push_str(&esc.replace('%', "%2525")),
                        2 => path.push_str(&format!("%{:02x}{}", b'%', hex)),
                        _ => path.push_str(&esc),
                    }
                }
            }
        }
    }
    if pick(4) == 0 {
        path.push('/');
    }
    (method, path)
}

/// Fuzz entry: shape the input bytes into a hold probe and run the oracle on it.
pub fn check_gate_bytes(data: &[u8]) {
    let mut i = 0;
    let mut pick = |n: usize| {
        let b = data.get(i).copied().unwrap_or(0) as usize;
        i += 1;
        b % n
    };
    let (method, path) = hold_probe(&mut pick);
    check_gate(method, &path);
}
