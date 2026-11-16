//! Allowlist check for CONNECT targets (design Q3-E2).

/// True when `host:port` equals one entry of `list` exactly.
///
/// Both sides are compared as written. Config validation already requires canonical lowercase
/// hosts in `[egress].allow`, so a differently cased target never matches.
pub fn allowed(list: &[String], host: &str, port: u16) -> bool {
    list.iter().any(|entry| match entry.rsplit_once(':') {
        Some((h, p)) => h == host && p.parse::<u16>() == Ok(port),
        None => false,
    })
}
