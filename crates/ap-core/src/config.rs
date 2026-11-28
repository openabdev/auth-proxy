//! Strict TOML config model and load-time validation (design Q3-A).
//!
//! Any failure makes the whole file unusable: `load` returns an error and
//! nothing from the file is applied.

use crate::canon::canonical_host;
use crate::headers::{AUTH_HEADERS, HOP_HEADERS};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
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
    /// Option B pilot (design 4.5): identities that authenticate by an `Authorization` token
    /// instead of a caller key. Each is bound to one passthrough route.
    #[serde(default, rename = "token_identity")]
    pub token_identities: Vec<TokenIdentity>,
    #[serde(default, rename = "route")]
    pub routes: Vec<Route>,
    #[serde(default, rename = "credential")]
    pub credentials: Vec<Credential>,
    #[serde(default, rename = "grant")]
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub egress: Egress,
    /// Passthrough settings. Required when any route has `mode = "passthrough"`.
    #[serde(default)]
    pub passthrough: Option<Passthrough>,
    #[serde(default)]
    pub probe: Probe,
    /// Approval plane (design 3.6). Passthrough deployments only.
    #[serde(default)]
    pub approval: Option<Approval>,
    /// Notifier (design 3.4 step 5). Absent means holds are not announced and simply expire.
    #[serde(default)]
    pub notify: Option<Notify>,
}

/// How a route treats the request credential.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    /// Phase 1: swap the surrogate for the stored credential.
    #[default]
    Swap,
    /// Muse gate: the caller's own `Authorization` is forwarded unchanged.
    Passthrough,
}

/// What a matching grant does. `hold` is valid only on passthrough grants with `path_patterns`.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    #[default]
    Allow,
    Hold,
}

/// Settings for the public passthrough listener (design 3.1, 3.2, 3.7).
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Passthrough {
    /// The `Host` the front passes to the loopback listener. Replaces `listen.proxy` in the Host check.
    pub public_authority: String,
    #[serde(default = "default_caller_key_header")]
    pub caller_key_header: String,
    /// Lowercase header names the front adds. A trailing `*` makes the entry a prefix.
    #[serde(default = "default_front_strip_headers")]
    pub front_strip_headers: Vec<String>,
    /// Concurrent connections, 1..=65535.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Header read timeout, 1..=300.
    #[serde(default = "default_header_read_secs")]
    pub header_read_secs: u64,
    /// Per-chunk stall limit on request bodies, 1..=300.
    #[serde(default = "default_body_read_secs")]
    pub body_read_secs: u64,
    /// First byte to last response byte, 1..=3600.
    #[serde(default = "default_request_deadline_secs")]
    pub request_deadline_secs: u64,
    /// No byte from upstream, 1..=3600.
    #[serde(default = "default_upstream_idle_secs")]
    pub upstream_idle_secs: u64,
    /// How long a held request waits for a human, 5..=600.
    #[serde(default = "default_hold_secs")]
    pub hold_secs: u64,
    /// Largest body a held request may carry, 1..=8 MiB.
    #[serde(default = "default_held_body_max_bytes")]
    pub held_body_max_bytes: u64,
    /// Held requests at once, 1..=1024.
    #[serde(default = "default_max_held_total")]
    pub max_held_total: usize,
    /// Held requests at once per identity, 1..=`max_held_total`.
    #[serde(default = "default_max_held_per_identity")]
    pub max_held_per_identity: usize,
    /// Seconds an identity is refused after a human deny, 0..=3600 (0 disables).
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
    /// Optional display labels for channel ids, shown next to the id on the approval view page.
    /// At most 64 entries; each id is 1..=20 digits and each label 1..=64 printable characters
    /// without `<`, `>` or `&`. Display only: never read by routing, grants or approval.
    #[serde(default)]
    pub channel_labels: BTreeMap<String, String>,
}

/// How a held request is answered to its caller.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HoldMode {
    #[default]
    Blocking,
    Async,
}

fn default_hold_secs() -> u64 {
    120
}

fn default_held_body_max_bytes() -> u64 {
    1024 * 1024
}

fn default_max_held_total() -> usize {
    32
}

fn default_max_held_per_identity() -> usize {
    4
}

fn default_cooldown_secs() -> u64 {
    60
}

/// The approval listener and its single approver credential (design 3.6). No secret lives here:
/// the password is stored as a hash.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    /// Loopback address of the approval listener. Must differ from `listen.proxy`.
    pub listen: SocketAddr,
    /// Basic-auth user name.
    pub user: String,
    /// Lowercase hex sha256 of the approver password.
    pub password_sha256: String,
    /// Base URL the notification link is built from. http or https, no userinfo, query or fragment.
    pub public_base_url: String,
    /// Basic-auth realm.
    #[serde(default = "default_realm")]
    pub realm: String,
}

fn default_realm() -> String {
    "auth-proxy approval".to_string()
}

/// How the owner is told that a request is waiting.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NotifyKind {
    Telegram,
}

/// Notifier settings. The bot token is read from a file at startup, never from this file.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Notify {
    pub kind: NotifyKind,
    /// Absolute path of a regular file (mode 0600) holding the Telegram bot token.
    pub token_file: String,
    /// Telegram chat id: a number (negative for groups) or an `@channelusername`. Not a secret.
    pub chat_id: String,
    /// Base URL the notification link is built from. Same rules as `public_base_url`.
    pub approval_url_base: String,
    /// Telegram approve and deny buttons, with a no-login one-time view link (stage 2). When
    /// false, the notification is the option C text and link only.
    #[serde(default)]
    pub buttons: bool,
    /// Telegram user id allowed to press the buttons. Required with `buttons`. Not a secret.
    #[serde(default)]
    pub owner_chat_id: Option<i64>,
    /// Base URL of the one-time view link (`{base}/view/<token>`). Required with `buttons`.
    #[serde(default)]
    pub view_base_url: Option<String>,
}

fn default_caller_key_header() -> String {
    "x-ap-caller-key".to_string()
}

fn default_front_strip_headers() -> Vec<String> {
    [
        "forwarded",
        "x-forwarded-*",
        "x-real-ip",
        "via",
        "cf-*",
        "tailscale-*",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

fn default_max_connections() -> usize {
    256
}

fn default_header_read_secs() -> u64 {
    10
}

fn default_body_read_secs() -> u64 {
    15
}

fn default_request_deadline_secs() -> u64 {
    300
}

fn default_upstream_idle_secs() -> u64 {
    30
}

/// The stage 1 hold-tolerance probe. Off unless `enabled`, and only built with the
/// `stage1-probe` feature of ap-proxy.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Probe {
    pub enabled: bool,
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

/// Option B pilot (design 4.5). A request with no caller key authenticates as this identity when
/// its `Authorization` header hashes to `token_sha256` on `route`, and only for a `hold` verdict.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TokenIdentity {
    /// Audit name and grant identity label. Not a secret.
    pub name: String,
    /// The passthrough route this token may reach. Nothing else.
    pub route: String,
    /// Lowercase hex sha256 of the exact `Authorization` header value, `Bot <token>` for Discord.
    /// The token itself never enters the config.
    pub token_sha256: String,
    /// Last UTC day the token is accepted, `YYYY-MM-DD`. Refused from the next day on.
    pub expires: String,
}

impl TokenIdentity {
    /// True when `now` (Unix seconds) is at or past the first second after `expires`. A malformed
    /// date counts as expired.
    pub fn expired_at(&self, now: u64) -> bool {
        match day_after_secs(&self.expires) {
            Some(cut) => now >= cut,
            None => true,
        }
    }
}

/// The Unix second at which the UTC day after `date` (`YYYY-MM-DD`) begins. `None` when `date` is
/// not a real calendar date.
pub fn day_after_secs(date: &str) -> Option<u64> {
    if date.len() != 10 || date.as_bytes()[4] != b'-' || date.as_bytes()[7] != b'-' {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = date.get(r)?;
        if s.bytes().all(|c| c.is_ascii_digit()) {
            s.parse().ok()
        } else {
            None
        }
    };
    let y = digits(0..4)?;
    let m = u32::try_from(digits(5..7)?).ok()?;
    let d = u32::try_from(digits(8..10)?).ok()?;
    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    u64::try_from((days_from_civil(y, m, d) + 1) * 86_400).ok()
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// Days from 1970-01-01 to the given proleptic Gregorian date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
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
    #[serde(default)]
    pub mode: RouteMode,
    /// Passthrough routes only: members of `AUTH_HEADERS` (other than `authorization`) that are
    /// forwarded. Default empty.
    #[serde(default)]
    pub keep_auth_headers: Vec<String>,
    /// Passthrough routes with a hold grant only. `blocking` (default) keeps the caller's
    /// connection open while a request is held. `async` answers 202 with a poll token and the
    /// caller polls `GET /poll/<token>` (design `muse-async-poll.md`). Applies to this route only.
    #[serde(default)]
    pub hold_mode: HoldMode,
    /// With `hold_mode = "async"`: seconds an unapproved entry stays pending before it ends as
    /// `expired`, 5..=600. Ignored in `blocking` mode, where `[passthrough].hold_secs` applies.
    #[serde(default = "default_hold_secs")]
    pub async_hold_secs: u64,
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
    /// Required on swap routes, forbidden on passthrough routes (empty).
    #[serde(default)]
    pub credential: String,
    pub route: String,
    pub methods: Vec<String>,
    /// Prefix paths. At least one of `paths` and `path_patterns` is required.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Whole-path segment patterns (`/a/*/b`): a segment is a literal or `*` for exactly one
    /// non-empty segment. Passthrough routes only. Required for `hold`.
    #[serde(default)]
    pub path_patterns: Vec<String>,
    #[serde(default)]
    pub aws_targets: Vec<String>,
    /// `allow` (default) or `hold` (passthrough routes, `path_patterns` only).
    #[serde(default)]
    pub decision: Decision,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct Egress {
    /// `host:port` entries read by ap-egress only.
    pub allow: Vec<String>,
    /// Maximum CONNECT connections ap-egress serves at once, at least 1. Default 256. A
    /// connection accepted over the cap is closed at once.
    pub max_connections: usize,
}

impl Default for Egress {
    fn default() -> Self {
        Egress {
            allow: Vec::new(),
            max_connections: 256,
        }
    }
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

/// Passthrough grant paths are plain prefixes (`starts_with`), so no trailing `/` is required.
/// Every other path rule still applies.
fn valid_prefix_path(p: &str) -> Result<(), &'static str> {
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
    Ok(())
}

/// A whole-path pattern: `/`, then one or more segments, each a literal or `*`. No `%`, no
/// empty segment (so no `//` and no trailing `/`), no dot segment, and `*` only as a full segment.
fn valid_path_pattern(p: &str) -> Result<(), &'static str> {
    if !p.starts_with('/') {
        return Err("must start with /");
    }
    if p.contains('%') {
        return Err("must not contain %");
    }
    for seg in p[1..].split('/') {
        if seg.is_empty() {
            return Err("must not contain an empty segment");
        }
        if seg == "." || seg == ".." {
            return Err("must not contain a dot segment");
        }
        if seg.contains('*') && seg != "*" {
            return Err("* is only allowed as a whole segment");
        }
        if !seg.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("must be printable ASCII without spaces");
        }
    }
    Ok(())
}

/// `http(s)://host[:port][/path]` with no userinfo, query, fragment or whitespace.
fn valid_base_url(u: &str) -> bool {
    let rest = match u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
    {
        Some(r) => r,
        None => return false,
    };
    let host = rest.split('/').next().unwrap_or("");
    !host.is_empty()
        && u.len() <= 512
        && !u.contains(['@', '?', '#'])
        && u.bytes().all(|b| b.is_ascii_graphic())
}

/// A lowercase header token, or one followed by a single `*` (prefix match).
fn valid_header_pattern(s: &str) -> bool {
    let token = s.strip_suffix('*').unwrap_or(s);
    valid_header_name(token)
}

fn validate_passthrough(p: &Passthrough) -> Result<(), ConfigError> {
    let a = &p.public_authority;
    if a.is_empty()
        || a.len() > 255
        || a.contains('@')
        || a.contains('/')
        || a.chars().any(char::is_whitespace)
    {
        return Err(invalid(
            "passthrough.public_authority must be a non-empty host[:port] without @, / or whitespace",
        ));
    }
    let h = &p.caller_key_header;
    if !valid_header_name(h)
        || AUTH_HEADERS.contains(&h.as_str())
        || HOP_HEADERS.contains(&h.as_str())
    {
        return Err(invalid(
            "passthrough.caller_key_header must be a lowercase header name that is not a credential or hop-by-hop header",
        ));
    }
    if p.front_strip_headers.len() > 64 {
        return Err(invalid(
            "passthrough.front_strip_headers has too many entries",
        ));
    }
    for e in &p.front_strip_headers {
        if !valid_header_pattern(e) {
            return Err(invalid(format!(
                "passthrough.front_strip_headers entry {e:?} must be a lowercase header name, optionally ending in *"
            )));
        }
    }
    if !(1..=65535).contains(&p.max_connections) {
        return Err(invalid("passthrough.max_connections must be in 1..=65535"));
    }
    for (field, v, max) in [
        ("header_read_secs", p.header_read_secs, 300),
        ("body_read_secs", p.body_read_secs, 300),
        ("request_deadline_secs", p.request_deadline_secs, 3600),
        ("upstream_idle_secs", p.upstream_idle_secs, 3600),
    ] {
        if !(1..=max).contains(&v) {
            return Err(invalid(format!("passthrough.{field} must be in 1..={max}")));
        }
    }
    for (field, v, min, max) in [
        ("hold_secs", p.hold_secs, 5, 600),
        (
            "held_body_max_bytes",
            p.held_body_max_bytes,
            1,
            8 * 1024 * 1024,
        ),
        ("cooldown_secs", p.cooldown_secs, 0, 3600),
    ] {
        if !(min..=max).contains(&v) {
            return Err(invalid(format!(
                "passthrough.{field} must be in {min}..={max}"
            )));
        }
    }
    if p.channel_labels.len() > 64 {
        return Err(invalid("passthrough.channel_labels has too many entries"));
    }
    for (id, label) in &p.channel_labels {
        if !(1..=20).contains(&id.len()) || !id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid(
                "passthrough.channel_labels ids must be 1..=20 digits",
            ));
        }
        if label.is_empty()
            || label.chars().count() > 64
            || label
                .chars()
                .any(|c| c.is_control() || matches!(c, '<' | '>' | '&'))
        {
            return Err(invalid(format!(
                "passthrough.channel_labels label for {id} must be 1..=64 printable characters without <, > or &"
            )));
        }
    }
    if !(1..=1024).contains(&p.max_held_total) {
        return Err(invalid("passthrough.max_held_total must be in 1..=1024"));
    }
    if !(1..=p.max_held_total).contains(&p.max_held_per_identity) {
        return Err(invalid(
            "passthrough.max_held_per_identity must be in 1..=max_held_total",
        ));
    }
    Ok(())
}

fn validate_approval(a: &Approval, proxy: SocketAddr) -> Result<(), ConfigError> {
    if !a.listen.ip().is_loopback() {
        return Err(invalid("approval.listen must be a loopback address"));
    }
    if a.listen.port() == 0 || a.listen.port() == proxy.port() {
        return Err(invalid(
            "approval.listen must have a port other than 0 and other than listen.proxy",
        ));
    }
    if a.user.is_empty()
        || a.user.len() > 64
        || !a.user.bytes().all(|b| b.is_ascii_graphic() && b != b':')
    {
        return Err(invalid(
            "approval.user must be 1..=64 printable ASCII bytes without ':'",
        ));
    }
    if !is_hex64_lower(&a.password_sha256) {
        return Err(invalid(
            "approval.password_sha256 must be 64 lowercase hex characters",
        ));
    }
    if !valid_base_url(&a.public_base_url) {
        return Err(invalid(
            "approval.public_base_url must be an http(s) URL without userinfo, query or fragment",
        ));
    }
    let realm_ok = !a.realm.is_empty()
        && a.realm.len() <= 64
        && a.realm
            .bytes()
            .all(|b| (b == b' ' || b.is_ascii_graphic()) && b != b'"' && b != b'\\');
    if !realm_ok {
        return Err(invalid(
            "approval.realm must be 1..=64 printable ASCII bytes without quote or backslash",
        ));
    }
    Ok(())
}

/// A numeric chat id (optionally negative) or a channel username: `@` then 5 to 32 letters, digits
/// or underscores.
fn valid_chat_id(c: &str) -> bool {
    let digits = c.strip_prefix('-').unwrap_or(c);
    let numeric =
        !digits.is_empty() && digits.len() <= 20 && digits.bytes().all(|b| b.is_ascii_digit());
    let channel = c.strip_prefix('@').is_some_and(|name| {
        (5..=32).contains(&name.len())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    });
    numeric || channel
}

fn validate_notify(n: &Notify) -> Result<(), ConfigError> {
    if !valid_base_url(&n.approval_url_base) {
        return Err(invalid(
            "notify.approval_url_base must be an http(s) URL without userinfo, query or fragment",
        ));
    }
    if !valid_chat_id(&n.chat_id) {
        return Err(invalid(
            "notify.chat_id must be a numeric id or an @channelusername",
        ));
    }
    let p = &n.token_file;
    if !p.starts_with('/') || p.len() > 1024 || p.bytes().any(|b| b == 0) {
        return Err(invalid("notify.token_file must be an absolute path"));
    }
    if n.buttons {
        if !n.owner_chat_id.is_some_and(|id| id > 0) {
            return Err(invalid(
                "notify.owner_chat_id must be a positive id when notify.buttons is true",
            ));
        }
        if !n.view_base_url.as_deref().is_some_and(valid_base_url) {
            return Err(invalid(
                "notify.view_base_url must be an http(s) URL without userinfo, query or fragment, \
and is required when notify.buttons is true",
            ));
        }
    } else if n.owner_chat_id.is_some() || n.view_base_url.is_some() {
        return Err(invalid(
            "notify.owner_chat_id and notify.view_base_url need notify.buttons = true",
        ));
    }
    Ok(())
}

impl Config {
    /// True when every route is a passthrough route (and there is at least one). Such a
    /// deployment runs without the session machinery.
    pub fn is_passthrough_only(&self) -> bool {
        !self.routes.is_empty() && self.routes.iter().all(|r| r.mode == RouteMode::Passthrough)
    }

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
        // The upstream resource is `https://{host}:{port}{path}`, not the route name, so two
        // passthrough routes on one authority would let the caller pick the route name that
        // carries the weaker verdict. Refused outright.
        let mut passthrough_authorities: HashMap<(String, u16), &str> = HashMap::new();
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
            match r.mode {
                RouteMode::Swap => {
                    if !r.keep_auth_headers.is_empty() {
                        return Err(invalid(format!(
                            "route {:?}: keep_auth_headers is only for passthrough routes",
                            r.name
                        )));
                    }
                }
                RouteMode::Passthrough => {
                    let authority = (r.host.trim_end_matches('.').to_ascii_lowercase(), r.port);
                    if let Some(first) = passthrough_authorities.insert(authority, r.name.as_str())
                    {
                        return Err(invalid(format!(
                            "passthrough routes {first:?} and {:?} share one host and port; a held resource must have one route",
                            r.name
                        )));
                    }
                    if r.name == "ap" {
                        return Err(invalid(format!(
                            "passthrough route name {:?} is reserved",
                            r.name
                        )));
                    }
                    if r.error_shape != ErrorShape::Generic {
                        return Err(invalid(format!(
                            "route {:?}: a passthrough route needs error_shape generic",
                            r.name
                        )));
                    }
                    if !r.pass_headers.is_empty() {
                        return Err(invalid(format!(
                            "route {:?}: a passthrough route must not set pass_headers",
                            r.name
                        )));
                    }
                    for h in &r.keep_auth_headers {
                        if h == "authorization" || !AUTH_HEADERS.contains(&h.as_str()) {
                            return Err(invalid(format!(
                                "route {:?}: keep_auth_headers entry {h:?} must be a member of the credential header set other than authorization",
                                r.name
                            )));
                        }
                    }
                }
            }
            route_hosts.insert(r.name.as_str(), r.host.as_str());
        }

        for r in &self.routes {
            if !(5..=600).contains(&r.async_hold_secs) {
                return Err(invalid(format!(
                    "route {:?}: async_hold_secs must be in 5..=600",
                    r.name
                )));
            }
            if r.hold_mode == HoldMode::Async
                && !(r.mode == RouteMode::Passthrough
                    && self
                        .grants
                        .iter()
                        .any(|g| g.route == r.name && g.decision == Decision::Hold))
            {
                return Err(invalid(format!(
                    "route {:?}: hold_mode \"async\" needs a passthrough route with a hold grant",
                    r.name
                )));
            }
        }

        let passthrough_routes: HashSet<&str> = self
            .routes
            .iter()
            .filter(|r| r.mode == RouteMode::Passthrough)
            .map(|r| r.name.as_str())
            .collect();
        if !passthrough_routes.is_empty() && passthrough_routes.len() != self.routes.len() {
            return Err(invalid(
                "swap and passthrough routes cannot be mixed in one config in stage 1",
            ));
        }
        match (&self.passthrough, passthrough_routes.is_empty()) {
            (None, false) => {
                return Err(invalid(
                    "a passthrough route needs a [passthrough] table with public_authority",
                ))
            }
            (Some(_), true) => {
                return Err(invalid(
                    "[passthrough] is only valid with a passthrough route",
                ))
            }
            (Some(p), false) => validate_passthrough(p)?,
            (None, true) => {}
        }
        if self.probe.enabled && passthrough_routes.is_empty() {
            return Err(invalid("[probe] needs a passthrough deployment"));
        }
        if passthrough_routes.is_empty() && (self.approval.is_some() || self.notify.is_some()) {
            return Err(invalid(
                "[approval] and [notify] need a passthrough deployment",
            ));
        }
        if let Some(a) = &self.approval {
            validate_approval(a, self.listen.proxy)?;
        }
        if let Some(n) = &self.notify {
            validate_notify(n)?;
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
                if passthrough_routes.contains(r.as_str()) {
                    return Err(invalid(format!(
                        "credential {:?} lists passthrough route {r:?}",
                        c.id
                    )));
                }
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
        // Option B token identities (design 4.5). Their names share the audit namespace with the
        // keyed identities, each token is bound to one passthrough route, and each needs a hold
        // grant there, since a keyless request is only ever a hold.
        let mut token_hashes = HashSet::new();
        // Single caller (design 4.5): one token identity in the whole policy, on one route.
        if self.token_identities.len() > 1 {
            return Err(invalid(
                "the pilot allows one token identity in total, on one route; remove the extra [[token_identity]]"
                    .to_string(),
            ));
        }
        for t in &self.token_identities {
            if !valid_identity_name(&t.name) || !identity_names.insert(t.name.as_str()) {
                return Err(invalid(format!(
                    "token identity name {:?} is invalid or already used",
                    t.name
                )));
            }
            if !is_hex64_lower(&t.token_sha256) || !token_hashes.insert(t.token_sha256.as_str()) {
                return Err(invalid(format!(
                    "token identity {:?}: token_sha256 must be 64 lowercase hex characters, unique",
                    t.name
                )));
            }
            if day_after_secs(&t.expires).is_none() {
                return Err(invalid(format!(
                    "token identity {:?}: expires must be a YYYY-MM-DD calendar date",
                    t.name
                )));
            }
            if !self
                .routes
                .iter()
                .any(|r| r.name == t.route && r.mode == RouteMode::Passthrough)
            {
                return Err(invalid(format!(
                    "token identity {:?}: route {:?} is not a passthrough route",
                    t.name, t.route
                )));
            }
            if !self
                .grants
                .iter()
                .any(|g| g.identity == t.name && g.route == t.route && g.decision == Decision::Hold)
            {
                return Err(invalid(format!(
                    "token identity {:?} needs a hold grant on route {:?}",
                    t.name, t.route
                )));
            }
            // A keyless request is only ever a hold (design 4.5), so any other grant for this
            // identity could never authorize a request. Refused here instead of ignored at runtime.
            if let Some(g) = self.grants.iter().find(|g| {
                g.identity == t.name && (g.route != t.route || g.decision != Decision::Hold)
            }) {
                return Err(invalid(format!(
                    "token identity {:?} may hold only: grant on route {:?} with decision {:?} is not a hold on route {:?}",
                    t.name, g.route, g.decision, t.route
                )));
            }
        }
        // A hold pattern must not share a request with an allow grant of the same identity,
        // route and method. Hold wins when both match, but a spelling of the held resource that
        // the pattern does not claim (a trailing `/`, a path parameter) would still reach the
        // allow grant, so the overlap is refused instead of relied on.
        for h in self.grants.iter().filter(|g| g.decision == Decision::Hold) {
            for a in self.grants.iter().filter(|g| {
                g.decision == Decision::Allow
                    && g.identity == h.identity
                    && g.route == h.route
                    && g.methods.iter().any(|m| h.methods.contains(m))
            }) {
                for hp in &h.path_patterns {
                    let clash = a
                        .paths
                        .iter()
                        .find(|p| crate::policy::prefix_overlaps_pattern(p, hp))
                        .or_else(|| {
                            a.path_patterns
                                .iter()
                                .find(|p| crate::policy::patterns_overlap(p, hp))
                        });
                    if let Some(ap) = clash {
                        return Err(invalid(format!(
                            "grant for identity {:?} on route {:?}: allow path {:?} overlaps hold pattern {:?} for the same method; an allow grant must not cover a held resource",
                            a.identity, a.route, ap, hp
                        )));
                    }
                }
            }
        }
        for g in &self.grants {
            if !identity_names.contains(g.identity.as_str()) {
                return Err(invalid(format!(
                    "grant names unknown identity {:?}",
                    g.identity
                )));
            }
            let on_passthrough = passthrough_routes.contains(g.route.as_str());
            if on_passthrough {
                if !g.credential.is_empty() {
                    return Err(invalid(format!(
                        "grant on passthrough route {:?} must not name a credential",
                        g.route
                    )));
                }
                if !g.aws_targets.is_empty() {
                    return Err(invalid(format!(
                        "grant on passthrough route {:?} must not set aws_targets",
                        g.route
                    )));
                }
                if g.decision == Decision::Hold {
                    if g.path_patterns.is_empty() {
                        return Err(invalid("grant decision \"hold\" needs path_patterns"));
                    }
                    if !g.paths.is_empty() {
                        return Err(invalid(
                            "grant decision \"hold\" must not use prefix paths, only path_patterns",
                        ));
                    }
                }
            } else {
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
                if g.decision != Decision::Allow {
                    return Err(invalid(
                        "grant decision \"hold\" is only valid on passthrough routes",
                    ));
                }
                if !g.path_patterns.is_empty() {
                    return Err(invalid(
                        "grant path_patterns are only valid on passthrough routes",
                    ));
                }
            }
            if on_passthrough && !route_hosts.contains_key(g.route.as_str()) {
                return Err(invalid(format!("grant names unknown route {:?}", g.route)));
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
            if g.paths.is_empty() && g.path_patterns.is_empty() {
                return Err(invalid("grant paths must not be empty"));
            }
            if g.path_patterns.len() > 64 {
                return Err(invalid("grant has too many path_patterns"));
            }
            for p in &g.path_patterns {
                valid_path_pattern(p)
                    .map_err(|why| invalid(format!("grant path_pattern {p:?}: {why}")))?;
            }
            for p in &g.paths {
                let checked = if on_passthrough {
                    valid_prefix_path(p)
                } else {
                    valid_path(p)
                };
                checked.map_err(|why| invalid(format!("grant path {p:?}: {why}")))?;
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
        if self.egress.max_connections == 0 {
            return Err(invalid("egress max_connections must be at least 1"));
        }
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
            if credential_hosts.contains(host) {
                return Err(invalid(format!(
                    "egress host {host:?} is a credential route host"
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
    fn rejects_removed_allow_route_hosts_key() {
        expect_parse_error(&base().replace("[egress]\n", "[egress]\nallow_route_hosts = true\n"));
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

    fn pt_base() -> String {
        format!(
            r#"version = 1

[listen]
proxy = "127.0.0.1:8443"

[passthrough]
public_authority = "gate.example.test"

[[identity]]
name = "muse-pilot"
caller_key_sha256 = "{H64}"

[[route]]
name = "discord"
host = "discord.com"
mode = "passthrough"

[[grant]]
identity = "muse-pilot"
route = "discord"
methods = ["GET"]
paths = ["/api/v10/channels/", "/api/v10/users/@me"]
"#
        )
    }

    #[test]
    fn passthrough_only_config_loads() {
        let cfg = load(&pt_base()).expect("valid");
        assert!(cfg.is_passthrough_only());
        let p = cfg.passthrough.as_ref().unwrap();
        assert_eq!(p.caller_key_header, "x-ap-caller-key");
        assert_eq!(p.max_connections, 256);
        assert_eq!(p.header_read_secs, 10);
        assert_eq!(p.body_read_secs, 15);
        assert_eq!(p.request_deadline_secs, 300);
        assert_eq!(p.upstream_idle_secs, 30);
        assert!(p.front_strip_headers.iter().any(|h| h == "tailscale-*"));
        assert_eq!(cfg.routes[0].mode, RouteMode::Passthrough);
        assert_eq!(cfg.grants[0].decision, Decision::Allow);
        assert!(cfg.grants[0].credential.is_empty());
        assert!(!cfg.probe.enabled);
    }

    /// `pt_base()` plus a pilot token bound to `discord` with a hold grant.
    fn pilot_text() -> String {
        format!(
            "{}\n[[token_identity]]\nname = \"pilot-b\"\nroute = \"discord\"\ntoken_sha256 = \"{}\"\nexpires = \"2026-12-20\"\n\n[[grant]]\nidentity = \"pilot-b\"\nroute = \"discord\"\nmethods = [\"POST\"]\ndecision = \"hold\"\npath_patterns = [\"/api/v10/channels/*/messages\"]\n",
            pt_base(),
            "ab".repeat(32)
        )
    }

    #[test]
    fn token_identity_loads_with_its_hold_grant() {
        let cfg = load(&pilot_text()).expect("valid");
        assert_eq!(cfg.token_identities.len(), 1);
        assert_eq!(cfg.token_identities[0].name, "pilot-b");
        assert_eq!(cfg.token_identities[0].route, "discord");
    }

    #[test]
    fn token_identity_expiry_must_be_a_calendar_date() {
        for bad in [
            "2026-02-30",
            "2026-13-01",
            "2026-00-10",
            "2025-02-29",
            "2026-1-01",
            "20261220",
        ] {
            let text =
                pilot_text().replace("expires = \"2026-12-20\"", &format!("expires = \"{bad}\""));
            expect_invalid(&text, "expires must be a YYYY-MM-DD calendar date");
        }
        let leap = pilot_text().replace("2026-12-20", "2028-02-29");
        assert!(load(&leap).is_ok());
    }

    #[test]
    fn token_identity_needs_a_passthrough_route() {
        let text = pilot_text().replace(
            "route = \"discord\"\ntoken_sha256",
            "route = \"nowhere\"\ntoken_sha256",
        );
        expect_invalid(&text, "is not a passthrough route");
    }

    #[test]
    fn token_identity_needs_a_hold_grant_on_its_route() {
        let text = pilot_text().replace("decision = \"hold\"", "decision = \"allow\"");
        expect_invalid(&text, "needs a hold grant");
    }

    #[test]
    fn token_identity_may_hold_only_on_its_bound_route() {
        // An allow grant for the token identity on its own route: never reached, since a keyless
        // request is only ever a hold.
        let allow = format!(
            "{}\n[[grant]]\nidentity = \"pilot-b\"\nroute = \"discord\"\nmethods = [\"GET\"]\ndecision = \"allow\"\npath_patterns = [\"/api/v10/users/*\"]\n",
            pilot_text()
        );
        expect_invalid(&allow, "may hold only");
        // A hold grant for the token identity on another passthrough route: also never reached.
        let other_route = format!(
            "{}\n[[route]]\nname = \"other\"\nhost = \"example.com\"\nmode = \"passthrough\"\n\n[[grant]]\nidentity = \"pilot-b\"\nroute = \"other\"\nmethods = [\"POST\"]\ndecision = \"hold\"\npath_patterns = [\"/x/*\"]\n",
            pilot_text()
        );
        expect_invalid(&other_route, "may hold only");
        // The hold grant on the bound route alone still loads.
        assert!(load(&pilot_text()).is_ok());
    }

    #[test]
    fn token_identity_name_cannot_reuse_a_name() {
        let text = pilot_text().replace("name = \"pilot-b\"", "name = \"muse-pilot\"");
        expect_invalid(&text, "already used");
    }

    #[test]
    fn token_sha256_must_be_64_lowercase_hex() {
        let text = pilot_text().replace(&"ab".repeat(32), "AB");
        expect_invalid(&text, "token_sha256 must be 64 lowercase hex");
    }

    #[test]
    fn pilot_allows_one_token_identity_in_total() {
        let same_route = format!(
            "{}\n[[token_identity]]\nname = \"pilot-c\"\nroute = \"discord\"\ntoken_sha256 = \"{}\"\nexpires = \"2026-12-20\"\n",
            pilot_text(),
            "cd".repeat(32)
        );
        expect_invalid(&same_route, "one token identity");
        // A second route is refused too: the pilot has one caller on one route.
        let other_route = format!(
            "{}\n[[route]]\nname = \"other\"\nhost = \"example.com\"\nmode = \"passthrough\"\n\n[[token_identity]]\nname = \"pilot-c\"\nroute = \"other\"\ntoken_sha256 = \"{}\"\nexpires = \"2026-12-20\"\n\n[[grant]]\nidentity = \"pilot-c\"\nroute = \"other\"\nmethods = [\"POST\"]\ndecision = \"hold\"\npath_patterns = [\"/x/*\"]\n",
            pilot_text(),
            "cd".repeat(32)
        );
        expect_invalid(&other_route, "one token identity");
    }

    #[test]
    fn day_after_secs_follows_the_utc_calendar() {
        assert_eq!(day_after_secs("1970-01-01"), Some(86_400));
        assert_eq!(day_after_secs("2000-02-29"), Some(951_868_800));
        assert_eq!(day_after_secs("2026-12-20"), Some(1_797_811_200));
        for bad in ["2026-02-29", "2026-04-31", "2026-12-00", "2026-12-20T"] {
            assert_eq!(day_after_secs(bad), None, "{bad}");
        }
    }

    #[test]
    fn token_identity_expires_from_the_first_second_of_the_next_day() {
        let t = TokenIdentity {
            name: "pilot-b".into(),
            route: "discord".into(),
            token_sha256: "ab".repeat(32),
            expires: "2026-12-20".into(),
        };
        assert!(!t.expired_at(1_797_811_199));
        assert!(t.expired_at(1_797_811_200));
        let malformed = TokenIdentity {
            expires: "2026-02-30".into(),
            ..t
        };
        assert!(malformed.expired_at(0));
    }

    #[test]
    fn swap_config_is_not_passthrough_only() {
        assert!(!load(&base()).unwrap().is_passthrough_only());
    }

    #[test]
    fn rejects_mixed_modes() {
        let text = format!(
            "{}\n[[route]]\nname = \"other\"\nhost = \"other.example.test\"\n",
            pt_base()
        );
        expect_invalid(&text, "cannot be mixed");
    }

    #[test]
    fn rejects_credential_listing_a_passthrough_route() {
        let text = format!(
            "{}\n[[credential]]\nid = \"c\"\nsource = \"k8s:a:b\"\nroutes = [\"discord\"]\n",
            pt_base()
        );
        expect_invalid(&text, "lists passthrough route");
    }

    #[test]
    fn rejects_passthrough_grant_with_credential() {
        let text = pt_base().replace(
            "methods = [\"GET\"]",
            "credential = \"c\"\nmethods = [\"GET\"]",
        );
        expect_invalid(&text, "must not name a credential");
    }

    #[test]
    fn rejects_hold_decision_in_stage_1() {
        // Hold on prefix paths is refused: a hold grant needs path_patterns.
        let text = pt_base().replace(
            "methods = [\"GET\"]",
            "decision = \"hold\"\nmethods = [\"GET\"]",
        );
        expect_invalid(&text, "needs path_patterns");
        // Hold on a swap route is refused.
        let swap = base().replace(
            "methods = [",
            "decision = \"hold\"\npath_patterns = [\"/a\"]\nmethods = [",
        );
        expect_invalid(&swap, "only valid on passthrough routes");
    }

    fn hold_text() -> String {
        pt_base().replace(
            "methods = [\"GET\"]\npaths = [\"/api/v10/channels/\", \"/api/v10/users/@me\"]",
            "decision = \"hold\"\nmethods = [\"POST\"]\npath_patterns = [\"/api/v10/channels/*/messages\"]",
        )
    }

    #[test]
    fn hold_grant_on_path_patterns_loads_with_defaults() {
        let cfg = load(&hold_text()).unwrap();
        assert_eq!(cfg.grants[0].decision, Decision::Hold);
        assert!(cfg.grants[0].paths.is_empty());
        let p = cfg.passthrough.unwrap();
        assert_eq!(p.hold_secs, 120);
        assert_eq!(p.held_body_max_bytes, 1024 * 1024);
        assert_eq!(p.max_held_total, 32);
        assert_eq!(p.max_held_per_identity, 4);
        assert_eq!(p.cooldown_secs, 60);
        assert!(cfg.approval.is_none() && cfg.notify.is_none());
    }

    fn second_route(host: &str, port: Option<u16>) -> String {
        let port = port.map_or(String::new(), |p| format!("port = {p}\n"));
        format!(
            "{}\n[[route]]\nname = \"discord2\"\nhost = \"{host}\"\n{port}mode = \"passthrough\"\n\n[[grant]]\nidentity = \"muse-pilot\"\nroute = \"discord2\"\nmethods = [\"POST\"]\npaths = [\"/\"]\n",
            hold_text()
        )
    }

    #[test]
    fn two_passthrough_routes_on_one_host_and_port_are_refused() {
        // The reproduced bypass: `discord2` shares the authority and allows POST on `/`.
        expect_invalid(
            &second_route("discord.com", None),
            "share one host and port",
        );
        // The default port spelled out is the same authority.
        expect_invalid(
            &second_route("discord.com", Some(443)),
            "share one host and port",
        );
    }

    #[test]
    fn host_spellings_of_one_authority_are_still_refused() {
        // Uppercase and a trailing dot never reach the authority check: the host rule refuses
        // them first. Either way the config does not load.
        for host in ["DISCORD.com", "discord.com."] {
            assert!(load(&second_route(host, None)).is_err(), "{host}");
        }
    }

    #[test]
    fn passthrough_routes_on_different_ports_or_hosts_load() {
        assert!(load(&second_route("discord.com", Some(8443))).is_ok());
        assert!(load(&second_route("other.example.test", None)).is_ok());
    }

    #[test]
    fn hold_grant_rejects_prefix_paths_alongside_patterns() {
        let text = hold_text().replace("path_patterns =", "paths = [\"/api/\"]\npath_patterns =");
        expect_invalid(&text, "must not use prefix paths");
    }

    #[test]
    fn rejects_bad_path_patterns() {
        for bad in [
            "channels/*",
            "/a//b",
            "/a/",
            "/",
            "/a/b*",
            "/a/*x",
            "/a/../b",
            "/a/./b",
            "/a/%2f",
            "/a b",
        ] {
            let text = hold_text().replace("/api/v10/channels/*/messages", bad);
            expect_invalid(&text, "path_pattern");
        }
    }

    #[test]
    fn allow_grant_may_use_path_patterns_and_swap_may_not() {
        let text = pt_base().replace(
            "paths = [\"/api/v10/channels/\", \"/api/v10/users/@me\"]",
            "path_patterns = [\"/api/v10/users/*\"]",
        );
        assert!(load(&text).is_ok());
        let swap = base().replace(
            "paths = [\"/\"]",
            "paths = [\"/\"]\npath_patterns = [\"/a\"]",
        );
        expect_invalid(&swap, "only valid on passthrough routes");
    }

    #[test]
    fn rejects_grant_without_paths_or_patterns() {
        let text = pt_base().replace(
            "paths = [\"/api/v10/channels/\", \"/api/v10/users/@me\"]",
            "",
        );
        expect_invalid(&text, "paths must not be empty");
    }

    #[test]
    fn channel_labels_load_and_are_validated() {
        let with = |extra: &str| {
            pt_base().replace(
                "public_authority = \"gate.example.test\"",
                &format!("public_authority = \"gate.example.test\"\n{extra}"),
            )
        };
        assert!(load(&pt_base())
            .unwrap()
            .passthrough
            .unwrap()
            .channel_labels
            .is_empty());
        let ok = load(&with("channel_labels = { \"123\" = \"ops-alerts\" }")).unwrap();
        assert_eq!(ok.passthrough.unwrap().channel_labels["123"], "ops-alerts");
        for bad in [
            "channel_labels = { \"12a\" = \"x\" }",
            "channel_labels = { \"\" = \"x\" }",
            "channel_labels = { \"123456789012345678901\" = \"x\" }",
            "channel_labels = { \"1\" = \"\" }",
            "channel_labels = { \"1\" = \"<b>x</b>\" }",
            "channel_labels = { \"1\" = \"a&b\" }",
            "channel_labels = { \"1\" = \"a\\nb\" }",
        ] {
            expect_invalid(&with(bad), "channel_labels");
        }
        let long = "x".repeat(65);
        expect_invalid(
            &with(&format!("channel_labels = {{ \"1\" = \"{long}\" }}")),
            "channel_labels",
        );
        let many: Vec<String> = (1..=65).map(|i| format!("\"{i}\" = \"l\"")).collect();
        expect_invalid(
            &with(&format!("channel_labels = {{ {} }}", many.join(", "))),
            "too many",
        );
    }

    #[test]
    fn rejects_hold_limits_out_of_range() {
        for (k, v) in [
            ("hold_secs", "4"),
            ("hold_secs", "601"),
            ("held_body_max_bytes", "0"),
            ("held_body_max_bytes", "8388609"),
            ("max_held_total", "0"),
            ("max_held_total", "1025"),
            ("max_held_per_identity", "0"),
            ("max_held_per_identity", "33"),
            ("cooldown_secs", "3601"),
        ] {
            let text = hold_text().replace(
                "public_authority = \"gate.example.test\"",
                &format!("public_authority = \"gate.example.test\"\n{k} = {v}"),
            );
            expect_invalid(&text, k);
        }
        let ok = hold_text().replace(
            "public_authority = \"gate.example.test\"",
            "public_authority = \"gate.example.test\"\nhold_secs = 5\ncooldown_secs = 0",
        );
        assert!(load(&ok).is_ok());
    }

    #[test]
    fn hold_mode_is_per_route_and_needs_a_hold_grant() {
        let route = "mode = \"passthrough\"\n";
        let c = load(&hold_text()).unwrap();
        assert_eq!(c.routes[0].hold_mode, HoldMode::Blocking);
        assert_eq!(c.routes[0].async_hold_secs, 120);
        let on = hold_text().replacen(
            route,
            &format!("{route}hold_mode = \"async\"\nasync_hold_secs = 30\n"),
            1,
        );
        let c = load(&on).unwrap();
        assert_eq!(c.routes[0].hold_mode, HoldMode::Async);
        assert_eq!(c.routes[0].async_hold_secs, 30);
        // The old global spelling is gone.
        let global = hold_text().replace(
            "public_authority = \"gate.example.test\"",
            "public_authority = \"gate.example.test\"\nhold_mode = \"async\"",
        );
        assert!(load(&global).is_err());
        let bad = hold_text().replacen(route, &format!("{route}hold_mode = \"sync\"\n"), 1);
        assert!(load(&bad).is_err());
        for secs in ["4", "601"] {
            let t = on.replace("async_hold_secs = 30", &format!("async_hold_secs = {secs}"));
            expect_invalid(&t, "async_hold_secs");
        }
        // No hold grant on the route: refused.
        let allow = on.replace("decision = \"hold\"", "decision = \"allow\"");
        expect_invalid(&allow, "hold_mode");
    }

    fn approval_block() -> String {
        format!(
            "\n[approval]\nlisten = \"127.0.0.1:8444\"\nuser = \"owner\"\npassword_sha256 = \"{H64}\"\npublic_base_url = \"https://approve.example.test\"\n\n[notify]\nkind = \"telegram\"\ntoken_file = \"/etc/ap/telegram-token\"\nchat_id = \"-1001234567890\"\napproval_url_base = \"https://approve.example.test\"\n"
        )
    }

    #[test]
    fn approval_and_notify_load() {
        let cfg = load(&(hold_text() + &approval_block())).unwrap();
        let a = cfg.approval.unwrap();
        assert_eq!(a.realm, "auth-proxy approval");
        let n = cfg.notify.unwrap();
        assert_eq!(n.kind, NotifyKind::Telegram);
        assert_eq!(n.chat_id, "-1001234567890");
        assert_eq!(n.token_file, "/etc/ap/telegram-token");
    }

    #[test]
    fn notify_buttons_need_owner_and_view_base_and_leftovers_are_refused() {
        let base = hold_text() + &approval_block();
        let with_buttons = base.replace(
            "approval_url_base = \"https://approve.example.test\"\n",
            "approval_url_base = \"https://approve.example.test\"\nbuttons = true\nowner_chat_id = 176096071\nview_base_url = \"https://view.example.test\"\n",
        );
        let n = load(&with_buttons).unwrap().notify.unwrap();
        assert!(n.buttons);
        assert_eq!(n.owner_chat_id, Some(176_096_071));
        for (from, to) in [
            ("owner_chat_id = 176096071\n", ""),
            ("owner_chat_id = 176096071\n", "owner_chat_id = 0\n"),
            ("view_base_url = \"https://view.example.test\"\n", ""),
            (
                "view_base_url = \"https://view.example.test\"\n",
                "view_base_url = \"https://view.example.test/?q=1\"\n",
            ),
        ] {
            let text = with_buttons.replace(from, to);
            assert!(load(&text).is_err(), "accepted: {to:?}");
        }
        let leftover = base.replace(
            "approval_url_base = \"https://approve.example.test\"\n",
            "approval_url_base = \"https://approve.example.test\"\nowner_chat_id = 176096071\n",
        );
        assert!(load(&leftover).is_err(), "owner id without buttons");
    }

    #[test]
    fn rejects_bad_approval_and_notify() {
        for (from, to, needle) in [
            (
                "127.0.0.1:8444",
                "127.0.0.1:8443",
                "other than listen.proxy",
            ),
            ("127.0.0.1:8444", "0.0.0.0:8444", "loopback"),
            ("user = \"owner\"", "user = \"a:b\"", "approval.user"),
            (H64, "ABC", "password_sha256"),
            (
                "https://approve.example.test\"\n\n[notify]",
                "https://u:p@x.test\"\n\n[notify]",
                "public_base_url",
            ),
            (
                "https://approve.example.test\"\n\n[notify]",
                "https://x.test/?q=1\"\n\n[notify]",
                "public_base_url",
            ),
            (
                "https://approve.example.test\"\n\n[notify]",
                "ftp://x.test\"\n\n[notify]",
                "public_base_url",
            ),
            (
                "approval_url_base = \"https://approve.example.test\"",
                "approval_url_base = \"https://u:p@x.test\"",
                "notify.approval_url_base",
            ),
            (
                "approval_url_base = \"https://approve.example.test\"",
                "approval_url_base = \"approve.example.test\"",
                "notify.approval_url_base",
            ),
            (
                "chat_id = \"-1001234567890\"",
                "chat_id = \"12a\"",
                "notify.chat_id",
            ),
            (
                "chat_id = \"-1001234567890\"",
                "chat_id = \"@abc\"",
                "notify.chat_id",
            ),
            (
                "chat_id = \"-1001234567890\"",
                "chat_id = \"\"",
                "notify.chat_id",
            ),
            ("/etc/ap/telegram-token", "telegram-token", "token_file"),
        ] {
            let text = hold_text() + &approval_block().replacen(from, to, 1);
            expect_invalid(&text, needle);
        }
        let text = hold_text() + &approval_block() + "extra = 1\n";
        expect_parse_error(&text);
    }

    #[test]
    fn stale_ntfy_keys_are_refused() {
        for stale in [
            "kind = \"ntfy\"",
            "base_url = \"https://ntfy.example.test\"\n",
            "topic_file = \"/etc/ap/topic\"\n",
        ] {
            let text = hold_text() + &approval_block().replacen("kind = \"telegram\"", stale, 1);
            expect_parse_error(&text);
        }
        let text = hold_text() + &approval_block() + "topic_file = \"/etc/ap/topic\"\n";
        expect_parse_error(&text);
    }

    #[test]
    fn approval_needs_a_passthrough_deployment() {
        expect_invalid(
            &(base() + &approval_block()),
            "need a passthrough deployment",
        );
    }

    #[test]
    fn rejects_unknown_decision_value() {
        let text = pt_base().replace(
            "methods = [\"GET\"]",
            "decision = \"maybe\"\nmethods = [\"GET\"]",
        );
        expect_parse_error(&text);
    }

    #[test]
    fn rejects_missing_passthrough_table() {
        let text = pt_base().replace(
            "[passthrough]\npublic_authority = \"gate.example.test\"\n",
            "",
        );
        expect_invalid(&text, "needs a [passthrough] table");
    }

    #[test]
    fn rejects_passthrough_table_without_passthrough_route() {
        let text = format!(
            "{}\n[passthrough]\npublic_authority = \"gate.example.test\"\n",
            base()
        );
        expect_invalid(&text, "only valid with a passthrough route");
    }

    #[test]
    fn rejects_unknown_key_under_passthrough() {
        let text = pt_base().replace(
            "public_authority = \"gate.example.test\"",
            "public_authority = \"gate.example.test\"\nbogus = 1",
        );
        expect_parse_error(&text);
    }

    #[test]
    fn passthrough_grant_path_needs_no_trailing_slash_but_swap_grant_does() {
        assert!(load(&pt_base()).is_ok());
        let swap = base().replace("paths = [\"/\"]", "paths = [\"/v1/x\"]");
        expect_invalid(&swap, "must end with /");
        let pt = pt_base().replace("\"/api/v10/users/@me\"", "\"/api/v10/a/../b\"");
        expect_invalid(&pt, "dot segment");
    }

    #[test]
    fn swap_grant_without_credential_is_invalid() {
        let text = base().replace(
            "credential = \"kiro\"\nroute = \"kiro-krs\"\nmethods",
            "route = \"kiro-krs\"\nmethods",
        );
        expect_invalid(&text, "unknown credential");
    }

    #[test]
    fn rejects_passthrough_limits_out_of_range() {
        for (field, bad) in [
            ("max_connections", "0"),
            ("max_connections", "65536"),
            ("header_read_secs", "0"),
            ("header_read_secs", "301"),
            ("body_read_secs", "301"),
            ("request_deadline_secs", "3601"),
            ("upstream_idle_secs", "0"),
        ] {
            let text = pt_base().replace(
                "public_authority = \"gate.example.test\"",
                &format!("public_authority = \"gate.example.test\"\n{field} = {bad}"),
            );
            expect_invalid(&text, field);
        }
    }

    #[test]
    fn rejects_bad_public_authority_and_headers() {
        for bad in ["", "a@b", "a/b", "a b"] {
            let text = pt_base().replace("gate.example.test", bad);
            expect_invalid(&text, "public_authority");
        }
        let text = pt_base().replace(
            "public_authority = \"gate.example.test\"",
            "public_authority = \"gate.example.test\"\ncaller_key_header = \"authorization\"",
        );
        expect_invalid(&text, "caller_key_header");
        let text = pt_base().replace(
            "public_authority = \"gate.example.test\"",
            "public_authority = \"gate.example.test\"\nfront_strip_headers = [\"Via\"]",
        );
        expect_invalid(&text, "front_strip_headers");
    }

    #[test]
    fn rejects_bad_passthrough_route_fields() {
        let text = pt_base().replace(
            "mode = \"passthrough\"",
            "mode = \"passthrough\"\nerror_shape = \"aws\"",
        );
        expect_invalid(&text, "error_shape generic");
        let text = pt_base().replace(
            "mode = \"passthrough\"",
            "mode = \"passthrough\"\npass_headers = [\"x-a\"]",
        );
        expect_invalid(&text, "pass_headers");
        let text = pt_base().replace(
            "mode = \"passthrough\"",
            "mode = \"passthrough\"\nkeep_auth_headers = [\"authorization\"]",
        );
        expect_invalid(&text, "keep_auth_headers");
        let ok = pt_base().replace(
            "mode = \"passthrough\"",
            "mode = \"passthrough\"\nkeep_auth_headers = [\"x-api-key\"]",
        );
        assert!(load(&ok).is_ok());
        let text = pt_base()
            .replace("name = \"discord\"", "name = \"ap\"")
            .replace("route = \"discord\"", "route = \"ap\"");
        expect_invalid(&text, "reserved");
    }

    #[test]
    fn probe_defaults_off_and_needs_passthrough() {
        let on = format!("{}\n[probe]\nenabled = true\n", pt_base());
        assert!(load(&on).unwrap().probe.enabled);
        let bad = format!("{}\n[probe]\nenabled = true\n", base());
        expect_invalid(&bad, "[probe]");
    }

    #[test]
    fn pilot_example_policy_validates() {
        let text = include_str!("../../../deploy/muse/pilot-policy.example.toml")
            .replace("<64 lowercase hex, sha256 of the issued apk_ key>", H64);
        let cfg = load(&text).expect("the committed example must validate");
        assert!(cfg.is_passthrough_only());
        assert!(cfg.probe.enabled);
        assert_eq!(cfg.grants[0].methods, vec!["GET".to_string()]);
    }
}
