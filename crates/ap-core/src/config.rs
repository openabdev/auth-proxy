//! The Q3-A policy file: one TOML file per identity, validated as a whole.
//!
//! Any validation failure makes the whole file unusable (exit code 2 at
//! startup, `policy_unavailable` at reload). Unknown keys are errors.

use crate::canon::canonical_host;
use crate::code::ErrorShape;
use crate::headers::{AUTH_HEADERS, HOP_HEADERS};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

pub const MAX_GRANTS: usize = 256;
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_PASS_HEADERS: usize = 16;

/// All validation failures of one file, reported together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub Vec<String>);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("; "))
    }
}

impl std::error::Error for ConfigError {}

impl ConfigError {
    fn one(msg: impl Into<String>) -> ConfigError {
        ConfigError(vec![msg.into()])
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    /// Audit name of the identity.
    pub identity: String,
    /// sha256 of the caller key, 64 lowercase hex. The key itself is never stored.
    pub caller_key_sha256: String,
    /// The single agent-facing listener. Optional: the binary may take it from
    /// its command line. There is no way to configure a second one.
    #[serde(default)]
    pub listener: Option<ListenerCfg>,
    #[serde(default, rename = "route")]
    pub routes: Vec<RouteCfg>,
    #[serde(default, rename = "credential")]
    pub credentials: Vec<CredentialCfg>,
    #[serde(default, rename = "grant")]
    pub grants: Vec<GrantCfg>,
    #[serde(default)]
    pub egress: EgressCfg,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ListenerCfg {
    /// Must be a loopback address with a non-zero port (`P`).
    pub listen: SocketAddr,
    /// Exact `Host` values a client may send (DNS-rebinding defence). Default:
    /// `127.0.0.1:P` and `localhost:P`.
    #[serde(default)]
    pub authorities: Vec<String>,
}

impl ListenerCfg {
    pub fn effective_authorities(&self) -> Vec<String> {
        if self.authorities.is_empty() {
            let p = self.listen.port();
            vec![format!("127.0.0.1:{p}"), format!("localhost:{p}")]
        } else {
            self.authorities.clone()
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RouteCfg {
    pub name: String,
    pub host: String,
    #[serde(default = "d_port")]
    pub port: u16,
    /// Test-only resolver override (like curl --resolve). The destination
    /// identity (SNI, Host, certificate name) is still `host`. The field exists
    /// only in builds with the `test-resolve` feature; in every shipped build a
    /// policy that sets it is rejected as an unknown key.
    #[cfg(feature = "test-resolve")]
    #[serde(default)]
    pub connect_to: Option<SocketAddr>,
    #[serde(default)]
    pub error_shape: ErrorShape,
    #[serde(default = "d_auth")]
    pub surrogate_header: String,
    #[serde(default = "d_bearer")]
    pub surrogate_scheme: String,
    #[serde(default = "d_auth")]
    pub credential_header: String,
    #[serde(default = "d_bearer")]
    pub credential_scheme: String,
    /// Request headers that must reach the upstream untouched. Stripping is a
    /// deny list (auth and hop-by-hop headers), so these pass by construction;
    /// the list is validated so it cannot name a stripped header.
    #[serde(default)]
    pub pass_headers: Vec<String>,
}

fn d_port() -> u16 {
    443
}
fn d_auth() -> String {
    "authorization".into()
}
fn d_bearer() -> String {
    "Bearer".into()
}

impl RouteCfg {
    /// The resolver override of a `test-resolve` build; always `None` otherwise.
    pub fn resolve_override(&self) -> Option<SocketAddr> {
        #[cfg(feature = "test-resolve")]
        {
            self.connect_to
        }
        #[cfg(not(feature = "test-resolve"))]
        {
            None
        }
    }

    /// `Host` header value the upstream sees (port only when not 443).
    pub fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialCfg {
    pub id: String,
    pub source: CredentialSource,
    pub routes: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrantCfg {
    pub credential: String,
    pub route: String,
    pub methods: Vec<String>,
    /// Each entry starts and ends with `/` and matches by prefix. `/` alone
    /// allows every path on the route.
    pub paths: Vec<String>,
    /// Empty = no constraint. Otherwise exactly one `X-Amz-Target` header,
    /// equal to one of these.
    #[serde(default)]
    pub aws_targets: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct EgressCfg {
    /// `host:port` entries for ap-egress.
    #[serde(default)]
    pub allow: Vec<String>,
}

impl EgressCfg {
    /// Parsed entries. Only meaningful on a validated config.
    pub fn entries(&self) -> Vec<(String, u16)> {
        self.allow
            .iter()
            .filter_map(|e| parse_host_port(e).ok())
            .collect()
    }
}

/// Where a credential value comes from. Reference syntax follows octobroker:
/// `k8s:<secret>:<key>`, `file:<absolute path>`, `env:<NAME>`. Phase 1 resolves
/// `k8s:` and `file:` (Secret files); `env:` parses only. `aws:secretsmanager:`
/// is deferred with the ECS rollout and rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSource {
    K8s { secret: String, key: String },
    File(PathBuf),
    Env(String),
}

impl FromStr for CredentialSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        if let Some(rest) = s.strip_prefix("k8s:") {
            let (secret, key) = rest
                .split_once(':')
                .ok_or("k8s source must be k8s:<secret>:<key>")?;
            let secret_ok = !secret.is_empty()
                && secret.len() <= 253
                && secret.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'
                })
                && !secret.starts_with(['-', '.'])
                && !secret.ends_with(['-', '.']);
            let key_ok = !key.is_empty()
                && key.len() <= 253
                && key != "."
                && key != ".."
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
            if !secret_ok {
                return Err("k8s source: bad secret name".into());
            }
            if !key_ok {
                return Err("k8s source: bad key name".into());
            }
            Ok(CredentialSource::K8s {
                secret: secret.into(),
                key: key.into(),
            })
        } else if let Some(p) = s.strip_prefix("file:") {
            let ok = p.starts_with('/')
                && p.len() <= 4096
                && !p.bytes().any(|b| b < 0x20 || b == 0x7f)
                && !p.split('/').any(|seg| seg == "..");
            if !ok {
                return Err("file source must be an absolute path without '..'".into());
            }
            Ok(CredentialSource::File(PathBuf::from(p)))
        } else if let Some(n) = s.strip_prefix("env:") {
            let ok = !n.is_empty()
                && n.len() <= 128
                && !n.as_bytes()[0].is_ascii_digit()
                && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if !ok {
                return Err("env source must be env:<NAME> ([A-Za-z_][A-Za-z0-9_]*)".into());
            }
            Ok(CredentialSource::Env(n.into()))
        } else if s.starts_with("aws:") {
            Err(
                "aws: sources are deferred with the ECS rollout and not supported in Phase 1"
                    .into(),
            )
        } else {
            Err("unknown source scheme (expected k8s:, file: or env:)".into())
        }
    }
}

impl<'de> Deserialize<'de> for CredentialSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// `host:port` with a canonical host and a port from 1 to 65535.
pub fn parse_host_port(e: &str) -> Result<(String, u16), String> {
    let (host, port) = e.rsplit_once(':').ok_or("expected host:port")?;
    canonical_host(host).map_err(|m| format!("host rejected: {m}"))?;
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err("port must be digits".into());
    }
    match port.parse::<u16>() {
        Ok(p) if p >= 1 => Ok((host.to_string(), p)),
        _ => Err("port must be 1..=65535".into()),
    }
}

fn ident_ok(s: &str, max: usize, extra: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

fn route_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn http_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn grant_path_err(p: &str) -> Option<&'static str> {
    if !p.starts_with('/') {
        return Some("must start with '/'");
    }
    if !p.ends_with('/') {
        return Some("must end with '/' (exact '/' or a prefix ending in '/')");
    }
    if p.len() > 512 || !p.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Some("must be printable ASCII, at most 512 bytes");
    }
    if p.contains(['%', '\\', '?', '#']) {
        return Some("must not contain '%', '\\', '?' or '#'");
    }
    if p.contains("//") {
        return Some("must not contain '//'");
    }
    if p.split('/').any(|s| s == "." || s == "..") {
        return Some("must not contain a dot segment");
    }
    None
}

impl Config {
    /// Parse and validate. Never returns a config that failed validation.
    pub fn parse(raw: &[u8]) -> Result<Config, ConfigError> {
        if raw.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::one("config larger than 1 MiB"));
        }
        let text = std::str::from_utf8(raw).map_err(|_| ConfigError::one("config is not UTF-8"))?;
        let cfg: Config =
            toml::from_str(text).map_err(|e| ConfigError::one(format!("parse: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn route(&self, name: &str) -> Option<&RouteCfg> {
        self.routes.iter().find(|r| r.name == name)
    }

    pub fn credential(&self, id: &str) -> Option<&CredentialCfg> {
        self.credentials.iter().find(|c| c.id == id)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errs: Vec<String> = Vec::new();
        let mut e = |m: String| errs.push(m);

        if self.version != 1 {
            e(format!("version must be 1, got {}", self.version));
        }
        if !ident_ok(&self.identity, 64, b"._:-") {
            e("identity must be 1-64 characters of [A-Za-z0-9._:-]".into());
        }
        if !lower_hex64(&self.caller_key_sha256) {
            e("caller_key_sha256 must be 64 lowercase hex characters".into());
        }

        if let Some(l) = &self.listener {
            if !l.listen.ip().is_loopback() {
                e(format!(
                    "listener.listen {} is not a loopback address",
                    l.listen
                ));
            }
            if l.listen.port() == 0 {
                e("listener.listen port must not be 0".into());
            }
            for a in &l.authorities {
                if a.is_empty() || a.len() > 255 || !a.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                    e(format!(
                        "listener.authorities entry {a:?} is not a plain Host value"
                    ));
                }
            }
        }

        // routes
        let mut route_names = HashSet::new();
        for r in &self.routes {
            if !route_name_ok(&r.name) {
                e(format!(
                    "route name {:?} must match [a-z0-9-]{{1,32}}",
                    r.name
                ));
            } else if !route_names.insert(r.name.as_str()) {
                e(format!("route name {:?} is not unique", r.name));
            }
            if let Err(m) = canonical_host(&r.host) {
                e(format!("route {}: upstream host rejected: {m}", r.name));
            }
            if r.port == 0 {
                e(format!("route {}: port 0", r.name));
            }
            for (what, h) in [
                ("surrogate_header", &r.surrogate_header),
                ("credential_header", &r.credential_header),
            ] {
                if !AUTH_HEADERS.contains(&h.as_str()) {
                    e(format!(
                        "route {}: {what} {h:?} is not a known auth header",
                        r.name
                    ));
                }
            }
            for (what, s) in [
                ("surrogate_scheme", &r.surrogate_scheme),
                ("credential_scheme", &r.credential_scheme),
            ] {
                if !(s.is_empty() || http_token(s)) {
                    e(format!("route {}: {what} must be empty or a token", r.name));
                }
            }
            if r.pass_headers.len() > MAX_PASS_HEADERS {
                e(format!(
                    "route {}: more than {MAX_PASS_HEADERS} pass_headers",
                    r.name
                ));
            }
            for h in &r.pass_headers {
                let lower_ok = *h == h.to_ascii_lowercase() && http_token(h);
                if !lower_ok {
                    e(format!(
                        "route {}: pass_headers entry {h:?} must be a lowercase header name",
                        r.name
                    ));
                } else if AUTH_HEADERS.contains(&h.as_str()) || HOP_HEADERS.contains(&h.as_str()) {
                    e(format!(
                        "route {}: pass_headers entry {h:?} is stripped by design",
                        r.name
                    ));
                }
            }
        }

        // credentials
        let mut cred_ids = HashSet::new();
        let route_host: HashMap<&str, &str> = self
            .routes
            .iter()
            .map(|r| (r.name.as_str(), r.host.as_str()))
            .collect();
        let mut credential_hosts: HashSet<&str> = HashSet::new();
        for c in &self.credentials {
            if !ident_ok(&c.id, 64, b"._-") {
                e(format!(
                    "credential id {:?} must be 1-64 characters of [A-Za-z0-9._-]",
                    c.id
                ));
            } else if !cred_ids.insert(c.id.as_str()) {
                e(format!("credential id {:?} is not unique", c.id));
            }
            if c.routes.is_empty() {
                e(format!("credential {}: routes is empty", c.id));
            }
            let mut seen = HashSet::new();
            for rn in &c.routes {
                if !seen.insert(rn.as_str()) {
                    e(format!("credential {}: route {rn:?} listed twice", c.id));
                }
                match route_host.get(rn.as_str()) {
                    Some(h) => {
                        credential_hosts.insert(*h);
                    }
                    None => e(format!("credential {}: route {rn:?} does not exist", c.id)),
                }
            }
        }

        // grants
        if self.grants.len() > MAX_GRANTS {
            e(format!(
                "more than {MAX_GRANTS} grants ({})",
                self.grants.len()
            ));
        }
        for (i, g) in self.grants.iter().enumerate() {
            let at = format!("grant #{}", i + 1);
            match self.credential(&g.credential) {
                None => e(format!(
                    "{at}: credential {:?} does not exist",
                    g.credential
                )),
                Some(c) if !c.routes.contains(&g.route) => e(format!(
                    "{at}: route {:?} is not one of credential {:?}'s routes",
                    g.route, g.credential
                )),
                Some(_) => {}
            }
            if g.methods.is_empty() {
                e(format!("{at}: methods is empty"));
            }
            for m in &g.methods {
                let ok = !m.is_empty()
                    && m.len() <= 16
                    && m.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-');
                if !ok {
                    e(format!("{at}: method {m:?} must be an upper-case token"));
                }
            }
            if g.paths.is_empty() {
                e(format!("{at}: paths is empty"));
            }
            for p in &g.paths {
                if let Some(why) = grant_path_err(p) {
                    e(format!("{at}: path {p:?} {why}"));
                }
            }
            for t in &g.aws_targets {
                let ok = !t.is_empty()
                    && t.len() <= 128
                    && t.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b',');
                if !ok {
                    e(format!(
                        "{at}: aws_targets entry {t:?} must be a plain token without ','"
                    ));
                }
            }
        }

        // egress
        for ent in &self.egress.allow {
            match parse_host_port(ent) {
                Err(m) => e(format!("egress.allow entry {ent:?}: {m}")),
                Ok((h, _)) => {
                    // Baseline rule, no opt-out: a CONNECT tunnel to a credential
                    // route host could carry another credential the agent found
                    // straight to that host.
                    if credential_hosts.contains(h.as_str()) {
                        e(format!(
                            "egress.allow entry {ent:?}: host is a credential route host"
                        ));
                    }
                }
            }
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(ConfigError(errs))
        }
    }
}
