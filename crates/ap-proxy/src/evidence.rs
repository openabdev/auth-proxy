//! Stage 1 evidence (design section 7): fixed fields about how a real Muse connector calls the
//! gate. No header value, no header length, no key, no body. One JSON line per request that
//! carried a valid caller key, written through the audit sink.
//!
//! The manually observed list of candidate non-secret header names is collected by hand, not
//! here (docs/runbooks/muse-stage1.md).

use ap_broker::registry::sha256_hex;
use ap_core::config::Passthrough;
use http::{header, HeaderMap, Version};
use serde::Serialize;

/// Which front-added header families were present. Booleans only.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct FrontFamilies {
    pub forwarded: bool,
    pub x_forwarded: bool,
    pub x_real_ip: bool,
    pub via: bool,
    pub tailscale: bool,
    pub cf: bool,
}

/// Fixed fields only. Every field is a name, a boolean, a class or a status, so the derived
/// `Debug` cannot print a secret.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Evidence {
    pub identity: String,
    pub route: Option<String>,
    pub method: String,
    /// Route-relative, redacted, no query.
    pub path: String,
    pub status: u16,
    pub http_version: &'static str,
    pub auth_present: bool,
    pub caller_key_header_present: bool,
    pub host_matches_public_authority: bool,
    pub chunked: bool,
    pub compressed: bool,
    pub content_type_class: &'static str,
    pub expect_continue: bool,
    pub front_headers_present: FrontFamilies,
    /// sha256 over the sorted, lowercased, de-duplicated request header NAMES. Values never enter it.
    pub fwd_names_digest: String,
}

impl Evidence {
    /// Collect the fixed fields from a request head. `route`, `path` and `status` are filled in
    /// by the caller as the pipeline learns them.
    pub fn collect(
        identity: &str,
        method: &str,
        version: Version,
        headers: &HeaderMap,
        pt: &Passthrough,
    ) -> Evidence {
        let host_matches = {
            let mut it = headers.get_all(header::HOST).iter();
            match (it.next(), it.next()) {
                (Some(v), None) => v.to_str().is_ok_and(|s| s == pt.public_authority),
                _ => false,
            }
        };
        let chunked = headers.get_all(header::TRANSFER_ENCODING).iter().any(|v| {
            v.to_str()
                .is_ok_and(|s| s.to_ascii_lowercase().contains("chunked"))
        });
        let compressed = headers.get(header::CONTENT_ENCODING).is_some_and(|v| {
            v.to_str()
                .map(|s| !s.trim().eq_ignore_ascii_case("identity"))
                .unwrap_or(true)
        });
        let content_type_class = match headers.get(header::CONTENT_TYPE) {
            None => "none",
            Some(v) => {
                let s = v.to_str().unwrap_or("").to_ascii_lowercase();
                if s.starts_with("application/json") {
                    "json"
                } else if s.starts_with("multipart/") {
                    "multipart"
                } else {
                    "other"
                }
            }
        };
        let has = |pred: &dyn Fn(&str) -> bool| headers.keys().any(|k| pred(k.as_str()));
        let front = FrontFamilies {
            forwarded: has(&|n| n == "forwarded"),
            x_forwarded: has(&|n| n.starts_with("x-forwarded-")),
            x_real_ip: has(&|n| n == "x-real-ip"),
            via: has(&|n| n == "via"),
            tailscale: has(&|n| n.starts_with("tailscale-")),
            cf: has(&|n| n.starts_with("cf-")),
        };
        let mut names: Vec<&str> = headers.keys().map(|k| k.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        Evidence {
            identity: identity.to_string(),
            route: None,
            method: method.to_string(),
            path: String::new(),
            status: 0,
            http_version: match version {
                Version::HTTP_10 => "1.0",
                Version::HTTP_11 => "1.1",
                Version::HTTP_2 => "2",
                _ => "other",
            },
            auth_present: headers.contains_key(header::AUTHORIZATION),
            caller_key_header_present: headers.contains_key(pt.caller_key_header.as_str()),
            host_matches_public_authority: host_matches,
            chunked,
            compressed,
            content_type_class,
            expect_continue: headers.contains_key(header::EXPECT),
            front_headers_present: front,
            fwd_names_digest: sha256_hex(&names.join("\n")),
        }
    }

    /// `{"evidence":{...}}` with a trailing newline.
    pub fn to_json_line(&self) -> String {
        let mut line = serde_json::json!({ "evidence": self }).to_string();
        line.push('\n');
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_core::config::load;
    use http::HeaderValue;

    fn pt() -> Passthrough {
        load(
            r#"version = 1
[listen]
proxy = "127.0.0.1:8443"
[passthrough]
public_authority = "gate.example.test"
[[identity]]
name = "m"
caller_key_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
[[route]]
name = "discord"
host = "discord.com"
mode = "passthrough"
"#,
        )
        .unwrap()
        .passthrough
        .unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn json_key_set_is_the_fixed_list() {
        let e = Evidence::collect("m", "GET", Version::HTTP_11, &headers(&[]), &pt());
        let v: serde_json::Value = serde_json::from_str(e.to_json_line().trim_end()).unwrap();
        let inner = v["evidence"].as_object().unwrap();
        let mut keys: Vec<&str> = inner.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "auth_present",
                "caller_key_header_present",
                "chunked",
                "compressed",
                "content_type_class",
                "expect_continue",
                "front_headers_present",
                "fwd_names_digest",
                "host_matches_public_authority",
                "http_version",
                "identity",
                "method",
                "path",
                "route",
                "status"
            ]
        );
        assert_eq!(v.as_object().unwrap().len(), 1);
    }

    #[test]
    fn no_value_reaches_the_line_and_digest_ignores_values() {
        let a = headers(&[
            ("authorization", "Bot SENTINEL-AUTH"),
            ("x-custom", "SENTINEL-CUSTOM"),
            ("cookie", "SENTINEL-COOKIE"),
            ("x-ap-caller-key", "SENTINEL-KEY"),
            ("host", "gate.example.test"),
            ("content-type", "application/json"),
        ]);
        let b = headers(&[
            ("authorization", "other"),
            ("x-custom", "other"),
            ("cookie", "other"),
            ("x-ap-caller-key", "other"),
            ("host", "gate.example.test"),
            ("content-type", "application/json"),
        ]);
        let ea = Evidence::collect("m", "POST", Version::HTTP_11, &a, &pt());
        let eb = Evidence::collect("m", "POST", Version::HTTP_11, &b, &pt());
        let line = ea.to_json_line();
        assert!(!line.contains("SENTINEL"), "{line}");
        assert!(!format!("{ea:?}").contains("SENTINEL"));
        assert_eq!(ea.fwd_names_digest, eb.fwd_names_digest);
        assert!(ea.auth_present && ea.host_matches_public_authority);
        assert_eq!(ea.content_type_class, "json");
        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn booleans_and_classes() {
        let h = headers(&[
            ("transfer-encoding", "chunked"),
            ("content-encoding", "gzip"),
            ("content-type", "multipart/form-data; boundary=x"),
            ("expect", "100-continue"),
            ("x-forwarded-for", "1"),
            ("tailscale-user-login", "x"),
            ("host", "wrong"),
        ]);
        let e = Evidence::collect("m", "POST", Version::HTTP_10, &h, &pt());
        assert!(e.chunked && e.compressed && e.expect_continue);
        assert_eq!(e.content_type_class, "multipart");
        assert_eq!(e.http_version, "1.0");
        assert!(e.front_headers_present.x_forwarded && e.front_headers_present.tailscale);
        assert!(!e.front_headers_present.cf);
        assert!(!e.host_matches_public_authority);
        assert!(!e.auth_present);
    }
}
