//! Canonicalization: upstream host validation, ambiguous-path refusal, and the
//! one place the `/ap/<caller-key>/<route>/` prefix is taken apart.
//!
//! The prefix carries the caller key. The types here make sure it cannot reach
//! a log line: `ApPath::verify` is the only way to get at the route and the
//! rest, it consumes the caller key, and `RoutePath` (the only path type the
//! audit record accepts) refuses to hold anything that looks like the prefix.

use std::net::IpAddr;

/// Validate an upstream host: lowercase DNS name, no IP literal, no userinfo,
/// no port, no trailing dot, LDH labels, at least two labels.
pub fn canonical_host(h: &str) -> Result<(), String> {
    if h.is_empty() || h.len() > 253 {
        return Err("empty or too long".into());
    }
    if h.parse::<IpAddr>().is_ok() || h.starts_with('[') {
        return Err("IP literal".into());
    }
    if h != h.to_ascii_lowercase() {
        return Err("not lowercase".into());
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() < 2 {
        return Err("single label".into());
    }
    for l in &labels {
        let ok = !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err("bad label (userinfo, port, trailing dot or non-LDH)".into());
        }
    }
    // An all-numeric last label is an IPv4 spelling the IpAddr parser misses
    // (127.1, 0x7f.0.0.1).
    if labels.last().unwrap().bytes().all(|b| b.is_ascii_digit()) {
        return Err("numeric TLD (IPv4 spelling)".into());
    }
    Ok(())
}

/// Raw path checks. Run on the still-encoded path so that no decoding layer
/// can disagree with the policy check about what the path is.
pub fn path_ambiguous(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    if ["%2e", "%2f", "%5c", "%00", "%25"]
        .iter()
        .any(|s| lower.contains(s))
        || p.contains('\\')
    {
        return true;
    }
    let segs: Vec<&str> = p.split('/').skip(1).collect();
    segs.iter()
        .enumerate()
        .any(|(i, s)| *s == "." || *s == ".." || (s.is_empty() && i + 1 != segs.len()))
}

/// `/ap/<caller-key>/<route>/<rest>`, split but not yet trusted. Holds the
/// caller key, so it has no `Debug` and no accessor for the key.
pub struct ApPath<'a> {
    caller_key: &'a str,
    route: &'a str,
    rest: &'a str,
}

impl<'a> ApPath<'a> {
    /// Split a request path. `None` when the shape is wrong. Callers must have
    /// run `path_ambiguous` first.
    pub fn split(path: &'a str) -> Option<ApPath<'a>> {
        let mut it = path.splitn(5, '/');
        let (empty, ap, key, route, rest) = (it.next(), it.next(), it.next(), it.next(), it.next());
        if empty != Some("") || ap != Some("ap") {
            return None;
        }
        let (key, route) = (
            key.filter(|k| !k.is_empty())?,
            route.filter(|r| !r.is_empty())?,
        );
        Some(ApPath {
            caller_key: key,
            route,
            rest: rest.unwrap_or(""),
        })
    }

    /// Check the caller key with `ok` (the policy's constant-time compare) and
    /// drop it. Only a verified path can produce a route name or a
    /// route-relative path.
    pub fn verify(self, ok: impl FnOnce(&str) -> bool) -> Option<VerifiedPath<'a>> {
        ok(self.caller_key).then_some(VerifiedPath {
            route: self.route,
            rest: self.rest,
        })
    }

    /// The route segment of a path whose caller key is not (yet) verified.
    /// Only for choosing an error dialect; never log it.
    pub fn unverified_route(&self) -> &'a str {
        self.route
    }
}

/// A path whose caller key has been verified and discarded.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedPath<'a> {
    route: &'a str,
    rest: &'a str,
}

impl<'a> VerifiedPath<'a> {
    pub fn route(&self) -> &'a str {
        self.route
    }

    /// The upstream path, `/` + rest, without the query.
    pub fn rest_path(&self) -> String {
        format!("/{}", self.rest)
    }

    /// The loggable form of the route-relative path.
    pub fn route_relative(&self) -> RoutePath {
        RoutePath::new(&self.rest_path())
    }
}

const MAX_FIELD: usize = 256;
/// Substrings that must never appear in any log field: caller key, surrogate
/// and authority-token prefixes.
const FORBIDDEN: &[&str] = &["apk_", "aps_", "apt_"];

/// Clean a value for an audit line: printable ASCII only, bounded, and never
/// anything that looks like a caller key, surrogate or authority token.
/// Returns `-` otherwise.
pub fn safe_field(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    if s.is_empty()
        || s.len() > MAX_FIELD
        || !s.bytes().all(|b| (0x21..=0x7e).contains(&b))
        || FORBIDDEN.iter().any(|f| lower.contains(f))
    {
        "-".into()
    } else {
        s.to_string()
    }
}

/// A route-relative request path (no `/ap/<caller-key>` prefix, no query), the
/// only path type an `AuditRec` accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePath(String);

impl RoutePath {
    /// Never fails and never carries a prefix: a value that starts with `/ap/`,
    /// has a query, or looks like a key becomes `-`.
    pub fn new(path: &str) -> RoutePath {
        if path.starts_with("/ap/") || path.contains(['?', '#']) {
            return RoutePath::none();
        }
        RoutePath(safe_field(path))
    }

    /// For refusals before the caller key is verified.
    pub fn none() -> RoutePath {
        RoutePath("-".into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        for ok in ["api.anthropic.com", "runtime.us-east-1.kiro.dev", "a-b.c"] {
            assert!(canonical_host(ok).is_ok(), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "::1",
            "[::1]",
            "127.1",
            "user@api.x.com",
            "api.x.com.",
            "API.x.com",
            "api.x.com:443",
            "localhost",
            "0x7f.0.0.1",
            "a..b",
            "-a.b",
            "",
        ] {
            assert!(canonical_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn paths() {
        for bad in [
            "/ap/k/r/../x",
            "/ap/k/r/%2e%2e/x",
            "/ap/k/r/a%2Fb",
            "/ap//r/x",
            "/ap/k/r/./x",
            "/ap/k/r/a\\b",
            "/ap/k/r/%252e",
        ] {
            assert!(path_ambiguous(bad), "{bad}");
        }
        for ok in ["/ap/k/r/v1/messages", "/ap/k/r/", "/ap/k/r"] {
            assert!(!path_ambiguous(ok), "{ok}");
        }
    }

    #[test]
    fn split_and_verify() {
        let p = ApPath::split("/ap/apk_KEY/anthropic/v1/messages").unwrap();
        assert_eq!(p.unverified_route(), "anthropic");
        assert!(p.verify(|k| k == "wrong").is_none());
        let v = ApPath::split("/ap/apk_KEY/anthropic/v1/messages")
            .unwrap()
            .verify(|k| k == "apk_KEY")
            .unwrap();
        assert_eq!(v.route(), "anthropic");
        assert_eq!(v.rest_path(), "/v1/messages");
        assert_eq!(v.route_relative().as_str(), "/v1/messages");

        let v = ApPath::split("/ap/k/r").unwrap().verify(|_| true).unwrap();
        assert_eq!(v.rest_path(), "/");
        for bad in ["/ap/k", "/ap//r/x", "/x/k/r/", "ap/k/r", "/ap", "/apx/k/r/"] {
            assert!(ApPath::split(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn route_path_never_carries_the_prefix() {
        for bad in [
            "/ap/apk_00/anthropic/v1/messages",
            "/v1/x?key=apk_00",
            "/v1/apk_deadbeef",
            "/v1/APS_deadbeef",
            "/v1/apt_deadbeef/x",
            "/v1/\u{7f}x",
            "/v1/ünï",
            "",
        ] {
            assert_eq!(RoutePath::new(bad).as_str(), "-", "{bad:?}");
        }
        assert_eq!(RoutePath::new("/v1/messages").as_str(), "/v1/messages");
        assert_eq!(RoutePath::none().as_str(), "-");
        assert_eq!(RoutePath::new(&"/a".repeat(200)).as_str(), "-");
    }
}
