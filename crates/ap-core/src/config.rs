//! Strict TOML config model and load-time validation (design Q3-A).
//!
//! Any failure makes the whole file unusable: `load` returns an error and
//! nothing from the file is applied.

use crate::canon::canonical_host;
use crate::headers::{AUTH_HEADERS, HOP_HEADERS};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;

/// Maximum number of `[[grant]]` entries.
pub const MAX_GRANTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The text is not valid TOML for this schema (unknown key, wrong type, bad enum value).
    Parse(String),
    /// The schema parsed, but a validation rule failed. The message names the rule.
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Parse(m) => write!(f, "config parse error: {m}"),
            ConfigError::Invalid(m) => write!(f, "config invalid: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Error body shape for a route. `aws` renders AWS JSON protocol errors.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ErrorShape {
    #[default]
    Generic,
    Aws,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub listen: Listen,
    #[serde(default)]
    pub sessions: Sessions,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default, rename = "identity")]
    pub identities: Vec<Identity>,
    #[serde(default, rename = "route")]
    pub routes: Vec<Route>,
    #[serde(default, rename = "credential")]
    pub credentials: Vec<Credential>,
    #[serde(default, rename = "grant")]
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub egress: Egress,
}

/// The single loopback listener of the credential proxy.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    pub proxy: SocketAddr,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Sessions {
    /// Session lease in seconds, 1..=3600.
    pub lease_secs: u64,
    /// Authority token lease in seconds, 1..=600.
    pub authority_lease_secs: u64,
    /// Maximum live sessions, 1..=1024.
    pub max_sessions: u32,
}

impl Default for Sessions {
    fn default() -> Self {
        Sessions {
            lease_secs: 900,
            authority_lease_secs: 90,
            max_sessions: 64,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Request body cap in bytes. Default 32 MiB.
    pub max_body_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_body_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Audit name of the caller.
    pub name: String,
    /// Lowercase hex sha256 of the caller key. The raw key never enters the config.
    pub caller_key_sha256: String,
    /// Standard base64 of the runtime's Ed25519 public key (32 bytes). Not a secret. Without it,
    /// hello for this identity is refused with 403 `runtime_key_missing`.
    #[serde(default)]
    pub runtime_pubkey: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub error_shape: ErrorShape,
    #[serde(default = "default_auth_header")]
    pub surrogate_header: String,
    #[serde(default = "default_auth_header")]
    pub credential_header: String,
    #[serde(default)]
    pub pass_headers: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub id: String,
    /// Reference to the secret, in octobroker reference syntax. Not resolved here.
    pub source: String,
    pub routes: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub identity: String,
    pub credential: String,
    pub route: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    #[serde(default)]
    pub aws_targets: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Egress {
    /// `host:port` entries read by ap-egress only.
    pub allow: Vec<String>,
    /// Permit egress hosts that are also credential route hosts. Off by default.
    pub allow_route_hosts: bool,
}

fn default_port() -> u16 {
    443
}

fn default_auth_header() -> String {
    "authorization".to_string()
}

/// Parse and validate a config file. Returns the validated config or the first failing rule.
pub fn load(text: &str) -> Result<Config, ConfigError> {
    let cfg: Config = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
    cfg.validate()?;
    Ok(cfg)
}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

/// `[a-z0-9-]`, 1 to `max` bytes.
fn valid_slug(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Identity names are audit labels: `[A-Za-z0-9._-]`, 1 to 64 bytes.
fn valid_identity_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Lowercase hex of exactly 64 characters.
fn is_hex64_lower(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Lowercase HTTP header token (letters, digits, `-`).
fn valid_header_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Path rules: starts with `/`, no `%`, no `//`, no `.` or `..` segment, and a trailing `/`.
/// A trailing `/` makes the entry a prefix; `/` alone matches every path.
fn valid_path(p: &str) -> Result<(), &'static str> {
    if !p.starts_with('/') {
        return Err("must start with /");
    }
    if p.contains('%') {
        return Err("must not contain %");
    }
    if p.contains("//") {
        return Err("must not contain //");
    }
    if p.split('/').any(|s| s == "." || s == "..") {
        return Err("must not contain a dot segment");
    }
    if !p.ends_with('/') {
        return Err("must end with / (exact paths other than / are not allowed)");
    }
    Ok(())
}

impl Config {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(invalid("version must be 1"));
        }
        if !self.listen.proxy.ip().is_loopback() {
            return Err(invalid("listen.proxy must be a loopback address"));
        }
        let s = &self.sessions;
        if !(1..=3600).contains(&s.lease_secs) {
            return Err(invalid("sessions.lease_secs must be in 1..=3600"));
        }
        if !(1..=600).contains(&s.authority_lease_secs) {
            return Err(invalid("sessions.authority_lease_secs must be in 1..=600"));
        }
        if !(1..=1024).contains(&s.max_sessions) {
            return Err(invalid("sessions.max_sessions must be in 1..=1024"));
        }
        if self.limits.max_body_bytes == 0 {
            return Err(invalid("limits.max_body_bytes must be at least 1"));
        }

        if self.identities.is_empty() {
            return Err(invalid("at least one [[identity]] is required"));
        }
        let mut identity_names = HashSet::new();
        let mut caller_keys = HashSet::new();
        for i in &self.identities {
            if !valid_identity_name(&i.name) {
                return Err(invalid(format!("identity name {:?} is invalid", i.name)));
            }
            if !identity_names.insert(i.name.as_str()) {
                return Err(invalid(format!("duplicate identity name {:?}", i.name)));
            }
            if !is_hex64_lower(&i.caller_key_sha256) {
                return Err(invalid(format!(
                    "identity {:?}: caller_key_sha256 must be 64 lowercase hex characters",
                    i.name
                )));
            }
            if !caller_keys.insert(i.caller_key_sha256.as_str()) {
                return Err(invalid(format!(
                    "duplicate caller_key_sha256 for identity {:?}",
                    i.name
                )));
            }
        }

        let mut route_hosts: HashMap<&str, &str> = HashMap::new();
        for r in &self.routes {
            if !valid_slug(&r.name, 32) {
                return Err(invalid(format!(
                    "route name {:?} must match [a-z0-9-]{{1,32}}",
                    r.name
                )));
            }
            if route_hosts.contains_key(r.name.as_str()) {
                return Err(invalid(format!("duplicate route name {:?}", r.name)));
            }
            canonical_host(&r.host)
                .map_err(|why| invalid(format!("route {:?} host {:?}: {why}", r.name, r.host)))?;
            if r.port == 0 {
                return Err(invalid(format!(
                    "route {:?}: port must be 1..=65535",
                    r.name
                )));
            }
            for (field, h) in [
                ("surrogate_header", &r.surrogate_header),
                ("credential_header", &r.credential_header),
            ] {
                if !valid_header_name(h) {
                    return Err(invalid(format!(
                        "route {:?}: {field} must be a lowercase header name",
                        r.name
                    )));
                }
                if !AUTH_HEADERS.contains(&h.as_str()) {
                    return Err(invalid(format!(
                        "route {:?}: {field} {h:?} must be a credential header (AUTH_HEADERS) so stripping removes it",
                        r.name
                    )));
                }
            }
            for h in &r.pass_headers {
                if !valid_header_name(h) {
                    return Err(invalid(format!(
                        "route {:?}: pass_headers entry {h:?} must be a lowercase header name",
                        r.name
                    )));
                }
                if AUTH_HEADERS.contains(&h.as_str()) || HOP_HEADERS.contains(&h.as_str()) {
                    return Err(invalid(format!(
                        "route {:?}: pass_headers entry {h:?} is a credential or hop-by-hop header",
                        r.name
                    )));
                }
            }
            route_hosts.insert(r.name.as_str(), r.host.as_str());
        }

        let mut credential_ids = HashSet::new();
        let mut credential_routes: HashMap<&str, HashSet<&str>> = HashMap::new();
        for c in &self.credentials {
            if !valid_slug(&c.id, 32) {
                return Err(invalid(format!(
                    "credential id {:?} must match [a-z0-9-]{{1,32}}",
                    c.id
                )));
            }
            if !credential_ids.insert(c.id.as_str()) {
                return Err(invalid(format!("duplicate credential id {:?}", c.id)));
            }
            if c.source.trim().is_empty() {
                return Err(invalid(format!(
                    "credential {:?}: source must not be empty",
                    c.id
                )));
            }
            if c.routes.is_empty() {
                return Err(invalid(format!(
                    "credential {:?}: routes must not be empty",
                    c.id
                )));
            }
            let mut set = HashSet::new();
            for r in &c.routes {
                if !route_hosts.contains_key(r.as_str()) {
                    return Err(invalid(format!(
                        "credential {:?} names unknown route {r:?}",
                        c.id
                    )));
                }
                if !set.insert(r.as_str()) {
                    return Err(invalid(format!(
                        "credential {:?} lists route {r:?} twice",
                        c.id
                    )));
                }
            }
            credential_routes.insert(c.id.as_str(), set);
        }

        if self.grants.len() > MAX_GRANTS {
            return Err(invalid(format!("at most {MAX_GRANTS} grants are allowed")));
        }
        for g in &self.grants {
            if !identity_names.contains(g.identity.as_str()) {
                return Err(invalid(format!(
                    "grant names unknown identity {:?}",
                    g.identity
                )));
            }
            let routes = credential_routes
                .get(g.credential.as_str())
                .ok_or_else(|| {
                    invalid(format!("grant names unknown credential {:?}", g.credential))
                })?;
            if !route_hosts.contains_key(g.route.as_str()) {
                return Err(invalid(format!("grant names unknown route {:?}", g.route)));
            }
            if !routes.contains(g.route.as_str()) {
                return Err(invalid(format!(
                    "grant route {:?} is not in the route set of credential {:?}",
                    g.route, g.credential
                )));
            }
            if g.methods.is_empty() {
                return Err(invalid("grant methods must not be empty"));
            }
            for m in &g.methods {
                let ok =
                    !m.is_empty() && m.len() <= 16 && m.bytes().all(|b| b.is_ascii_uppercase());
                if !ok {
                    return Err(invalid(format!(
                        "grant method {m:?} must be an upper-case token"
                    )));
                }
            }
            if g.paths.is_empty() {
                return Err(invalid("grant paths must not be empty"));
            }
            for p in &g.paths {
                valid_path(p).map_err(|why| invalid(format!("grant path {p:?}: {why}")))?;
            }
            for t in &g.aws_targets {
                let ok = !t.is_empty() && t.len() <= 256 && t.bytes().all(|b| b.is_ascii_graphic());
                if !ok {
                    return Err(invalid(format!(
                        "grant aws_target {t:?} must be a non-empty token"
                    )));
                }
            }
        }

        let credential_hosts: HashSet<&str> = self
            .credentials
            .iter()
            .flat_map(|c| c.routes.iter())
            .filter_map(|r| route_hosts.get(r.as_str()).copied())
            .collect();
        for entry in &self.egress.allow {
            let (host, port) = entry
                .rsplit_once(':')
                .ok_or_else(|| invalid(format!("egress entry {entry:?} must be host:port")))?;
            canonical_host(host).map_err(|why| invalid(format!("egress host {host:?}: {why}")))?;
            match port.parse::<u16>() {
                Ok(p) if p >= 1 => {}
                _ => {
                    return Err(invalid(format!(
                        "egress entry {entry:?}: port must be 1..=65535"
                    )))
                }
            }
            if !self.egress.allow_route_hosts && credential_hosts.contains(host) {
                return Err(invalid(format!(
                    "egress host {host:?} is a credential route host (set egress.allow_route_hosts = true to permit)"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const H64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    pub(crate) fn base() -> String {
        format!(
            r#"version = 1

[listen]
proxy = "127.0.0.1:8443"

[[identity]]
name = "pty-team-a"
caller_key_sha256 = "{H64}"

[[route]]
name = "kiro-krs"
host = "runtime.us-east-1.kiro.dev"
error_shape = "aws"
pass_headers = ["tokentype"]

[[credential]]
id = "kiro"
source = "k8s:auth-proxy-kiro:api_key"
routes = ["kiro-krs"]

[[grant]]
identity = "pty-team-a"
credential = "kiro"
route = "kiro-krs"
methods = ["POST"]
paths = ["/"]
aws_targets = ["AmazonCodeWhispererStreamingService.GenerateAssistantResponse"]

[egress]
allow = ["github.com:443"]
"#
        )
    }

    fn expect_invalid(text: &str, needle: &str) {
        match load(text) {
            Err(ConfigError::Invalid(m)) => {
                assert!(m.contains(needle), "message {m:?} lacks {needle:?}")
            }
            other => panic!("expected Invalid containing {needle:?}, got {other:?}"),
        }
    }

    fn expect_parse_error(text: &str) {
        match load(text) {
            Err(ConfigError::Parse(_)) => {}
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn base_config_loads_with_defaults() {
        let cfg = load(&base()).expect("base config is valid");
        assert_eq!(cfg.routes[0].port, 443);
        assert_eq!(cfg.routes[0].surrogate_header, "authorization");
        assert_eq!(cfg.routes[0].error_shape, ErrorShape::Aws);
        assert_eq!(cfg.sessions, Sessions::default());
        assert_eq!(cfg.sessions.lease_secs, 900);
        assert_eq!(cfg.sessions.authority_lease_secs, 90);
        assert_eq!(cfg.sessions.max_sessions, 64);
        assert_eq!(cfg.limits.max_body_bytes, 33_554_432);
        assert!(!cfg.egress.allow_route_hosts);
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        expect_parse_error(&format!("bogus = 1\n{}", base()));
    }

    #[test]
    fn rejects_unknown_nested_key() {
        expect_parse_error(&base().replace(
            "error_shape = \"aws\"",
            "error_shape = \"aws\"\nextra = true",
        ));
    }

    #[test]
    fn rejects_unknown_error_shape_value() {
        expect_parse_error(&base().replace("\"aws\"", "\"xml\""));
    }

    #[test]
    fn rejects_wrong_version() {
        expect_invalid(
            &base().replace("version = 1", "version = 2"),
            "version must be 1",
        );
    }

    #[test]
    fn rejects_empty_identity_table() {
        let text = base().replace("[[identity]]\nname = \"pty-team-a\"\ncaller_key_sha256 = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n", "");
        expect_invalid(&text, "at least one [[identity]]");
    }

    #[test]
    fn rejects_duplicate_identity_name() {
        let dup = format!("\n[[identity]]\nname = \"pty-team-a\"\ncaller_key_sha256 = \"{H64}\"\n");
        expect_invalid(&(base() + &dup), "duplicate identity name");
    }

    #[test]
    fn rejects_duplicate_caller_key_across_identities() {
        let dup = format!("\n[[identity]]\nname = \"pty-team-b\"\ncaller_key_sha256 = \"{H64}\"\n");
        expect_invalid(&(base() + &dup), "duplicate caller_key_sha256");
    }

    #[test]
    fn rejects_identity_name_over_64_bytes() {
        let long = "a".repeat(65);
        expect_invalid(
            &base().replace("name = \"pty-team-a\"", &format!("name = \"{long}\"")),
            "identity name",
        );
    }

    #[test]
    fn rejects_method_over_16_bytes() {
        expect_invalid(
            &base().replace("methods = [\"POST\"]", "methods = [\"AAAAAAAAAAAAAAAAA\"]"),
            "upper-case token",
        );
    }

    #[test]
    fn rejects_zero_authority_lease() {
        expect_invalid(
            &base().replace(
                "[listen]",
                "[sessions]\nauthority_lease_secs = 0\n\n[listen]",
            ),
            "authority_lease_secs must be in 1..=600",
        );
    }

    #[test]
    fn rejects_zero_max_sessions() {
        expect_invalid(
            &base().replace("[listen]", "[sessions]\nmax_sessions = 0\n\n[listen]"),
            "max_sessions must be in 1..=1024",
        );
    }

    #[test]
    fn identity_without_runtime_pubkey_still_loads() {
        let cfg = load(&base()).expect("config without runtime_pubkey loads");
        assert_eq!(cfg.identities[0].runtime_pubkey, None);
    }

    #[test]
    fn identity_keeps_its_runtime_pubkey() {
        let text = base().replace(
            "caller_key_sha256 = \"",
            "runtime_pubkey = \"AAAA\"\ncaller_key_sha256 = \"",
        );
        let cfg = load(&text).expect("config with runtime_pubkey loads");
        assert_eq!(cfg.identities[0].runtime_pubkey.as_deref(), Some("AAAA"));
    }

    #[test]
    fn rejects_identity_key_not_64_lower_hex() {
        expect_invalid(
            &base().replace(H64, &H64.to_uppercase()),
            "caller_key_sha256 must be 64 lowercase hex",
        );
    }

    #[test]
    fn rejects_duplicate_route_names() {
        let dup = "\n[[route]]\nname = \"kiro-krs\"\nhost = \"other.example.com\"\n";
        expect_invalid(&(base() + dup), "duplicate route name");
    }

    #[test]
    fn rejects_route_name_outside_slug() {
        expect_invalid(
            &base().replace("name = \"kiro-krs\"", "name = \"Kiro_KRS\""),
            "route name",
        );
    }

    #[test]
    fn rejects_ip_literal_route_host() {
        expect_invalid(
            &base().replace("runtime.us-east-1.kiro.dev", "127.0.0.1"),
            "IP literal",
        );
    }

    #[test]
    fn rejects_route_host_with_port() {
        expect_invalid(
            &base().replace(
                "runtime.us-east-1.kiro.dev",
                "runtime.us-east-1.kiro.dev:443",
            ),
            "route \"kiro-krs\" host",
        );
    }

    #[test]
    fn rejects_route_port_zero() {
        expect_invalid(
            &base().replace("error_shape = \"aws\"", "port = 0"),
            "port must be 1..=65535",
        );
    }

    #[test]
    fn rejects_pass_header_that_is_auth() {
        expect_invalid(
            &base().replace(
                "pass_headers = [\"tokentype\"]",
                "pass_headers = [\"authorization\"]",
            ),
            "credential or hop-by-hop",
        );
    }

    #[test]
    fn rejects_surrogate_header_not_in_auth_set() {
        expect_invalid(
            &base().replace(
                "error_shape = \"aws\"",
                "error_shape = \"aws\"\n    surrogate_header = \"x-custom\"",
            ),
            "must be a credential header",
        );
    }

    #[test]
    fn rejects_credential_header_not_in_auth_set() {
        expect_invalid(
            &base().replace(
                "error_shape = \"aws\"",
                "error_shape = \"aws\"\n    credential_header = \"x-custom\"",
            ),
            "must be a credential header",
        );
    }

    #[test]
    fn rejects_pass_header_that_is_hop_by_hop() {
        expect_invalid(
            &base().replace(
                "pass_headers = [\"tokentype\"]",
                "pass_headers = [\"connection\"]",
            ),
            "credential or hop-by-hop",
        );
    }

    #[test]
    fn rejects_credential_route_not_defined() {
        expect_invalid(
            &base().replace("routes = [\"kiro-krs\"]", "routes = [\"nope\"]"),
            "unknown route",
        );
    }

    #[test]
    fn rejects_grant_unknown_route() {
        expect_invalid(
            &base().replace("route = \"kiro-krs\"\nmethods", "route = \"nope\"\nmethods"),
            "unknown route",
        );
    }

    #[test]
    fn rejects_grant_unknown_identity() {
        expect_invalid(
            &base().replace(
                "identity = \"pty-team-a\"\ncredential",
                "identity = \"nobody\"\ncredential",
            ),
            "unknown identity",
        );
    }

    #[test]
    fn rejects_grant_unknown_credential() {
        expect_invalid(
            &base().replace(
                "credential = \"kiro\"\nroute",
                "credential = \"nope\"\nroute",
            ),
            "unknown credential",
        );
    }

    #[test]
    fn rejects_grant_route_outside_credential_route_set() {
        let text = base().replace(
            "route = \"kiro-krs\"\nmethods",
            "route = \"kiro-cw\"\nmethods",
        ) + "\n[[route]]\nname = \"kiro-cw\"\nhost = \"cw.example.dev\"\n";
        expect_invalid(&text, "not in the route set");
    }

    #[test]
    fn rejects_lowercase_method_token() {
        expect_invalid(
            &base().replace("methods = [\"POST\"]", "methods = [\"post\"]"),
            "upper-case token",
        );
    }

    #[test]
    fn rejects_empty_methods() {
        expect_invalid(
            &base().replace("methods = [\"POST\"]", "methods = []"),
            "methods must not be empty",
        );
    }

    #[test]
    fn rejects_path_without_leading_slash() {
        expect_invalid(
            &base().replace("paths = [\"/\"]", "paths = [\"v1/\"]"),
            "must start with /",
        );
    }

    #[test]
    fn rejects_path_with_dot_dot_segment() {
        expect_invalid(
            &base().replace("paths = [\"/\"]", "paths = [\"/a/../\"]"),
            "dot segment",
        );
    }

    #[test]
    fn rejects_path_with_single_dot_segment() {
        expect_invalid(
            &base().replace("paths = [\"/\"]", "paths = [\"/a/./\"]"),
            "dot segment",
        );
    }

    #[test]
    fn rejects_path_with_percent() {
        expect_invalid(
            &base().replace("paths = [\"/\"]", "paths = [\"/a%2f/\"]"),
            "must not contain %",
        );
    }

    #[test]
    fn rejects_path_with_double_slash() {
        expect_invalid(
            &base().replace("paths = [\"/\"]", "paths = [\"/a//\"]"),
            "must not contain //",
        );
    }

    #[test]
    fn rejects_exact_path_that_is_not_slash_terminated() {
        expect_invalid(
            &base().replace("paths = [\"/\"]", "paths = [\"/v1/messages\"]"),
            "must end with /",
        );
    }

    #[test]
    fn accepts_prefix_path() {
        assert!(load(&base().replace("paths = [\"/\"]", "paths = [\"/v1/\"]")).is_ok());
    }

    #[test]
    fn rejects_empty_aws_target() {
        expect_invalid(
            &base().replace(
                "aws_targets = [\"AmazonCodeWhispererStreamingService.GenerateAssistantResponse\"]",
                "aws_targets = [\"\"]",
            ),
            "aws_target",
        );
    }

    #[test]
    fn rejects_more_than_256_grants() {
        let one = "\n[[grant]]\nidentity = \"pty-team-a\"\ncredential = \"kiro\"\nroute = \"kiro-krs\"\nmethods = [\"POST\"]\npaths = [\"/\"]\n";
        let text = base() + &one.repeat(256);
        expect_invalid(&text, "at most 256 grants");
    }

    #[test]
    fn accepts_exactly_256_grants() {
        let one = "\n[[grant]]\nidentity = \"pty-team-a\"\ncredential = \"kiro\"\nroute = \"kiro-krs\"\nmethods = [\"POST\"]\npaths = [\"/\"]\n";
        assert!(load(&(base() + &one.repeat(255))).is_ok());
    }

    #[test]
    fn rejects_egress_without_port() {
        expect_invalid(
            &base().replace("github.com:443", "github.com"),
            "must be host:port",
        );
    }

    #[test]
    fn rejects_egress_port_zero() {
        expect_invalid(
            &base().replace("github.com:443", "github.com:0"),
            "port must be 1..=65535",
        );
    }

    #[test]
    fn rejects_egress_port_out_of_range() {
        expect_invalid(
            &base().replace("github.com:443", "github.com:70000"),
            "port must be 1..=65535",
        );
    }

    #[test]
    fn rejects_egress_non_canonical_host() {
        expect_invalid(
            &base().replace("github.com:443", "GitHub.com:443"),
            "egress host",
        );
    }

    #[test]
    fn rejects_egress_host_equal_to_credential_route_host() {
        expect_invalid(
            &base().replace("github.com:443", "runtime.us-east-1.kiro.dev:443"),
            "credential route host",
        );
    }

    #[test]
    fn allows_credential_route_host_in_egress_with_opt_in() {
        let text = base()
            .replace("github.com:443", "runtime.us-east-1.kiro.dev:443")
            .replace("[egress]\n", "[egress]\nallow_route_hosts = true\n");
        assert!(load(&text).is_ok());
    }

    #[test]
    fn rejects_non_loopback_listener() {
        expect_invalid(
            &base().replace("127.0.0.1:8443", "0.0.0.0:8443"),
            "loopback",
        );
    }

    #[test]
    fn rejects_unknown_listen_key_second_listener() {
        expect_parse_error(&base().replace(
            "proxy = \"127.0.0.1:8443\"",
            "proxy = \"127.0.0.1:8443\"\negress = \"127.0.0.1:8444\"",
        ));
    }

    #[test]
    fn accepts_ipv6_loopback_listener() {
        assert!(load(&base().replace("127.0.0.1:8443", "[::1]:8443")).is_ok());
    }

    #[test]
    fn rejects_lease_secs_zero() {
        expect_invalid(
            &base().replace("[listen]", "[sessions]\nlease_secs = 0\n\n[listen]"),
            "lease_secs must be in 1..=3600",
        );
    }

    #[test]
    fn rejects_lease_secs_above_max() {
        expect_invalid(
            &base().replace("[listen]", "[sessions]\nlease_secs = 3601\n\n[listen]"),
            "lease_secs must be in 1..=3600",
        );
    }

    #[test]
    fn rejects_authority_lease_above_max() {
        expect_invalid(
            &base().replace(
                "[listen]",
                "[sessions]\nauthority_lease_secs = 601\n\n[listen]",
            ),
            "authority_lease_secs must be in 1..=600",
        );
    }

    #[test]
    fn rejects_max_sessions_out_of_range() {
        expect_invalid(
            &base().replace("[listen]", "[sessions]\nmax_sessions = 1025\n\n[listen]"),
            "max_sessions must be in 1..=1024",
        );
    }

    #[test]
    fn rejects_zero_body_cap() {
        expect_invalid(
            &base().replace("[listen]", "[limits]\nmax_body_bytes = 0\n\n[listen]"),
            "max_body_bytes must be at least 1",
        );
    }

    #[test]
    fn rejects_invalid_identity_name() {
        expect_invalid(
            &base().replace("name = \"pty-team-a\"", "name = \"bad name\""),
            "identity name",
        );
    }

    #[test]
    fn rejects_duplicate_credential_id() {
        let dup =
            "\n[[credential]]\nid = \"kiro\"\nsource = \"k8s:x:y\"\nroutes = [\"kiro-krs\"]\n";
        expect_invalid(&(base() + dup), "duplicate credential id");
    }

    #[test]
    fn rejects_invalid_credential_id() {
        expect_invalid(
            &base().replace("id = \"kiro\"", "id = \"Kiro\""),
            "credential id",
        );
    }

    #[test]
    fn rejects_empty_credential_source() {
        expect_invalid(
            &base().replace("source = \"k8s:auth-proxy-kiro:api_key\"", "source = \" \""),
            "source must not be empty",
        );
    }

    #[test]
    fn rejects_credential_without_routes() {
        expect_invalid(
            &base().replace("routes = [\"kiro-krs\"]", "routes = []"),
            "routes must not be empty",
        );
    }

    #[test]
    fn rejects_credential_route_listed_twice() {
        expect_invalid(
            &base().replace(
                "routes = [\"kiro-krs\"]",
                "routes = [\"kiro-krs\", \"kiro-krs\"]",
            ),
            "twice",
        );
    }

    #[test]
    fn rejects_non_lowercase_header_name() {
        expect_invalid(
            &base().replace(
                "error_shape = \"aws\"",
                "error_shape = \"aws\"\n    surrogate_header = \"Authorization\"",
            ),
            "must be a lowercase header name",
        );
    }

    #[test]
    fn rejects_invalid_pass_header_name() {
        expect_invalid(
            &base().replace(
                "pass_headers = [\"tokentype\"]",
                "pass_headers = [\"Token Type\"]",
            ),
            "pass_headers entry",
        );
    }

    #[test]
    fn rejects_grant_without_paths() {
        expect_invalid(
            &base().replace("paths = [\"/\"]", "paths = []"),
            "grant paths must not be empty",
        );
    }

    #[test]
    fn rejects_invalid_toml_syntax() {
        expect_parse_error("version = ");
    }
}
