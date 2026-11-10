//! Canonicalization of hosts, paths and surrogates.

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

#[cfg(test)]
mod tests {
    use super::canonical_host;

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
}
