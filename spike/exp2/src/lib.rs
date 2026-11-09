//! Shared admission core for both Experiment 2 options.
//!
//! Option A (`ap-proxy`) calls [`Core::admit`] and then forwards the request
//! itself. Option B (`ap-authz`) calls the same function as an Envoy
//! `ext_authz` HTTP service and lets Envoy forward. Keeping one core means the
//! two options differ only in the forwarding layer, which is what the bake-off
//! compares.
//!
//! Pipeline (RFC #1, fail-closed, in order):
//!   1. caller key (constant time) + surrogate format
//!   2. canonicalize: origin-form only, exact listener Host, unambiguous path
//!   3. policy (caller + route + method + path prefix); empty or unavailable = deny
//!   4. resolve the surrogate at the broker, only now, never cached
//!   5. (caller) strip client auth, apply exactly one upstream credential
//!   6. audit, never a secret
//!
//! Spike code: not production. No secret value is ever formatted into a log
//! line, an error body, or a panic message.

use http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Headers that can carry a credential. All are removed before forwarding;
/// then exactly one (the route's credential header) is set.
pub const AUTH_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-goog-api-key",
    "api-key",
    "cookie",
    "x-amz-security-token",
];

/// Hop-by-hop headers (RFC 9110 §7.6.1) plus framing headers the forwarder sets itself.
pub const HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

#[derive(Deserialize, Clone, Copy, Default, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ErrorShape {
    #[default]
    Json,
    /// AWS JSON protocol (`__type` + `message`), so kiro-cli shows the message.
    Aws,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    pub host: String,
    #[serde(default = "d_port")]
    pub port: u16,
    /// Test-only resolver override (like curl --resolve). The destination
    /// identity (SNI, Host, certificate name) is still `host`.
    #[serde(default)]
    pub connect_to: Option<SocketAddr>,
    #[serde(default = "d_auth")]
    pub surrogate_header: String,
    #[serde(default = "d_bearer")]
    pub surrogate_scheme: String,
    #[serde(default = "d_auth")]
    pub credential_header: String,
    #[serde(default = "d_bearer")]
    pub credential_scheme: String,
    #[serde(default)]
    pub error_shape: ErrorShape,
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

impl Route {
    /// Host header value the upstream sees (port only when not 443).
    pub fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub id: String,
    /// sha256 of the caller key, hex. The key itself is never stored.
    pub key_sha256: String,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    /// Option B only: where ap-authz listens for Envoy's check requests.
    #[serde(default)]
    pub authz_listen: Option<SocketAddr>,
    /// Exact Host values a client may send (DNS-rebinding defence). Anything
    /// else, including other spellings of the same address, is refused.
    pub listener_authorities: Vec<String>,
    pub broker_url: String,
    pub policy_file: PathBuf,
    /// Trust only this CA bundle upstream (tests). Unset = public web PKI roots.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub audit_file: Option<PathBuf>,
    pub callers: Vec<Caller>,
    pub routes: Vec<Route>,
}

/// A refusal. Every refusal is final for this request: nothing goes upstream.
#[derive(Debug, Clone)]
pub struct Deny {
    pub status: StatusCode,
    pub code: &'static str,
    pub msg: &'static str,
}
const fn deny(status: StatusCode, code: &'static str, msg: &'static str) -> Deny {
    Deny { status, code, msg }
}

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
    // An all-numeric last label is an IPv4 spelling the IpAddr parser misses (127.1, 0x7f.0.0.1).
    if labels.last().unwrap().bytes().all(|b| b.is_ascii_digit()) {
        return Err("numeric TLD (IPv4 spelling)".into());
    }
    Ok(())
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let raw = std::fs::read(path).map_err(|e| format!("read config: {e}"))?;
        let c: Config = serde_json::from_slice(&raw).map_err(|e| format!("parse config: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.listener_authorities.is_empty() {
            return Err("listener_authorities is empty".into());
        }
        let mut names = std::collections::HashSet::new();
        for r in &self.routes {
            let name_ok = !r.name.is_empty()
                && r.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !name_ok || !names.insert(r.name.clone()) {
                return Err(format!("route name invalid or duplicate: {:?}", r.name));
            }
            canonical_host(&r.host)
                .map_err(|e| format!("route {}: upstream host rejected: {e}", r.name))?;
            if r.port == 0 {
                return Err(format!("route {}: port 0", r.name));
            }
            for h in [&r.surrogate_header, &r.credential_header] {
                if !AUTH_HEADERS.contains(&h.as_str()) {
                    return Err(format!("route {}: {h} is not a known auth header", r.name));
                }
            }
        }
        for c in &self.callers {
            if c.key_sha256.len() != 64 || hex::decode(&c.key_sha256).is_err() {
                return Err(format!("caller {}: key_sha256 must be 64 hex chars", c.id));
            }
        }
        if !self.broker_url.starts_with("http://127.0.0.1:")
            && !self.broker_url.starts_with("https://")
        {
            return Err("broker_url must be https:// or loopback http".into());
        }
        Ok(())
    }

    pub fn route(&self, name: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.name == name)
    }
}

// ---------------------------------------------------------------- policy

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub caller: String,
    pub route: String,
    pub methods: Vec<String>,
    pub path_prefixes: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub rules: Vec<Rule>,
}

/// Re-reads the policy file when its mtime or size changes. Any stat, read or
/// parse failure makes the policy unavailable, which denies every request: a
/// stale policy is never kept after the file has gone bad.
pub struct PolicyStore {
    path: PathBuf,
    cache: Mutex<Option<(SystemTime, u64, Arc<Policy>)>>,
}

impl PolicyStore {
    pub fn new(path: PathBuf) -> Self {
        PolicyStore {
            path,
            cache: Mutex::new(None),
        }
    }

    pub fn current(&self) -> Result<Arc<Policy>, Deny> {
        const UNAVAILABLE: Deny = deny(
            StatusCode::SERVICE_UNAVAILABLE,
            "policy_unavailable",
            "policy unavailable; refusing",
        );
        let mut cache = self.cache.lock().unwrap();
        let md = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => {
                *cache = None;
                return Err(UNAVAILABLE);
            }
        };
        let key = (md.modified().unwrap_or(UNIX_EPOCH), md.len());
        if let Some((m, l, p)) = cache.as_ref() {
            if (*m, *l) == key {
                return Ok(p.clone());
            }
        }
        let parsed = std::fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Policy>(&b).ok());
        match parsed {
            Some(p) => {
                let p = Arc::new(p);
                *cache = Some((key.0, key.1, p.clone()));
                Ok(p)
            }
            None => {
                *cache = None;
                Err(UNAVAILABLE)
            }
        }
    }
}

// ---------------------------------------------------------------- admission

/// What a successful admission hands to the forwarder.
pub struct Admitted {
    pub caller: String,
    pub route: Route,
    /// Upstream path + query (the `/ap/<key>/<route>` prefix removed).
    pub rest: String,
    pub credential_id: String,
    /// `<scheme> <credential>` ready for the route's credential header.
    pub credential_value: HeaderValue,
}

pub struct Core {
    pub cfg: Config,
    pub policy: PolicyStore,
    broker: reqwest::Client,
    callers: Vec<(String, [u8; 32])>,
    audit: Mutex<Option<std::fs::File>>,
    pub impl_name: &'static str,
}

#[derive(Deserialize)]
struct Resolved {
    credential: String,
    credential_id: String,
    expires_at: u64,
}
#[derive(Deserialize)]
struct BrokerErr {
    error: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Raw path checks. Run on the still-encoded path so that no decoding layer
/// can disagree with the policy check about what the path is.
fn path_ambiguous(p: &str) -> bool {
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

impl Core {
    pub fn new(cfg: Config, impl_name: &'static str) -> Result<Core, String> {
        let callers = cfg
            .callers
            .iter()
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(&hex::decode(&c.key_sha256).unwrap());
                (c.id.clone(), h)
            })
            .collect();
        let audit = match &cfg.audit_file {
            Some(p) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map_err(|e| format!("open audit file: {e}"))?,
            ),
            None => None,
        };
        let broker = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .tcp_nodelay(true)
            .build()
            .map_err(|e| format!("broker client: {e}"))?;
        Ok(Core {
            policy: PolicyStore::new(cfg.policy_file.clone()),
            cfg,
            broker,
            callers,
            audit: Mutex::new(audit),
            impl_name,
        })
    }

    /// Error shape for a refusal: the route's, once the route name is known.
    pub fn shape_for(&self, uri: &Uri) -> ErrorShape {
        uri.path()
            .split('/')
            .nth(3)
            .and_then(|n| self.cfg.route(n))
            .map(|r| r.error_shape)
            .unwrap_or_default()
    }

    fn caller_for_key(&self, key: &str) -> Option<String> {
        let h: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        let mut found = None;
        for (id, want) in &self.callers {
            // Compare against every caller, no early exit.
            if bool::from(h.ct_eq(want)) {
                found = Some(id.clone());
            }
        }
        found
    }

    pub async fn admit(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<Admitted, Deny> {
        use StatusCode as S;
        if method == Method::CONNECT {
            return Err(deny(
                S::METHOD_NOT_ALLOWED,
                "connect_refused",
                "CONNECT is not supported",
            ));
        }
        // 2a. canonicalize the client side: origin-form + one exact Host.
        if uri.scheme().is_some() || uri.authority().is_some() {
            return Err(deny(
                S::BAD_REQUEST,
                "absolute_form",
                "absolute-form request target refused",
            ));
        }
        let hosts: Vec<&HeaderValue> = headers.get_all(header::HOST).iter().collect();
        let host_ok = hosts.len() == 1
            && hosts[0]
                .to_str()
                .map(|h| self.cfg.listener_authorities.iter().any(|a| a == h))
                .unwrap_or(false);
        if !host_ok {
            return Err(deny(
                S::BAD_REQUEST,
                "host_rejected",
                "Host must be exactly one listener authority",
            ));
        }
        let path = uri.path();
        if path_ambiguous(path) {
            return Err(deny(
                S::BAD_REQUEST,
                "path_ambiguous",
                "ambiguous path refused",
            ));
        }
        // /ap/<caller-key>/<route>/<rest>
        let mut it = path.splitn(5, '/');
        let (_, ap, key, rname) = (it.next(), it.next(), it.next(), it.next());
        let rest_path = format!("/{}", it.next().unwrap_or(""));
        if ap != Some("ap") || key.is_none() || rname.is_none() {
            return Err(deny(
                S::NOT_FOUND,
                "route_unknown",
                "expected /ap/<caller-key>/<route>/",
            ));
        }
        // 1. caller key, then surrogate format.
        let caller = self.caller_for_key(key.unwrap()).ok_or(deny(
            S::FORBIDDEN,
            "caller_rejected",
            "caller key not recognised",
        ))?;
        let route = self
            .cfg
            .route(rname.unwrap())
            .ok_or(deny(S::NOT_FOUND, "route_unknown", "unknown route"))?
            .clone();
        let sv: Vec<&HeaderValue> = headers
            .get_all(route.surrogate_header.as_str())
            .iter()
            .collect();
        if sv.is_empty() {
            return Err(deny(
                S::UNAUTHORIZED,
                "surrogate_missing",
                "no surrogate presented",
            ));
        }
        if sv.len() > 1 || sv[0].as_bytes().contains(&b',') {
            return Err(deny(
                S::BAD_REQUEST,
                "surrogate_ambiguous",
                "more than one surrogate presented",
            ));
        }
        let raw = sv[0].to_str().unwrap_or("");
        let tok = if route.surrogate_scheme.is_empty() {
            Some(raw)
        } else {
            let p = format!("{} ", route.surrogate_scheme);
            (raw.len() > p.len() && raw[..p.len()].eq_ignore_ascii_case(&p))
                .then(|| &raw[p.len()..])
        };
        let tok = match tok {
            Some(t)
                if t.len() == 36
                    && t.starts_with("aps_")
                    && t[4..]
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) =>
            {
                t
            }
            _ => {
                return Err(deny(
                    S::UNAUTHORIZED,
                    "surrogate_malformed",
                    "surrogate malformed",
                ))
            }
        };
        // 3. policy.
        let pol = self.policy.current()?;
        if pol.rules.is_empty() {
            return Err(deny(
                S::FORBIDDEN,
                "policy_empty",
                "policy is empty; nothing is allowed",
            ));
        }
        let allowed = pol.rules.iter().any(|r| {
            r.caller == caller
                && r.route == route.name
                && r.methods.iter().any(|m| m == method.as_str())
                && r.path_prefixes
                    .iter()
                    .any(|p| rest_path.starts_with(p.as_str()))
        });
        if !allowed {
            return Err(deny(
                S::FORBIDDEN,
                "policy_denied",
                "request not allowed by policy",
            ));
        }
        // 4. resolve, only now. No cache: broker down means refuse.
        const BROKER_DOWN: Deny = deny(
            S::SERVICE_UNAVAILABLE,
            "broker_unavailable",
            "credential broker unavailable; refusing",
        );
        let resp = self
            .broker
            .post(format!("{}/v1/resolve", self.cfg.broker_url))
            .json(&serde_json::json!({"caller": caller, "route": route.name, "surrogate": tok}))
            .send()
            .await
            .map_err(|_| BROKER_DOWN)?;
        let st = resp.status();
        if st == S::UNAUTHORIZED || st == S::FORBIDDEN {
            let code = resp
                .json::<BrokerErr>()
                .await
                .map(|e| e.error)
                .unwrap_or_default();
            return Err(match code.as_str() {
                "surrogate_expired" => deny(
                    S::UNAUTHORIZED,
                    "surrogate_expired",
                    "surrogate expired; re-mint",
                ),
                "surrogate_revoked" => {
                    deny(S::UNAUTHORIZED, "surrogate_revoked", "surrogate revoked")
                }
                "surrogate_wrong_caller" => deny(
                    S::FORBIDDEN,
                    "surrogate_wrong_caller",
                    "surrogate belongs to another caller",
                ),
                "surrogate_wrong_route" => deny(
                    S::FORBIDDEN,
                    "surrogate_wrong_route",
                    "surrogate not bound to this route",
                ),
                _ => deny(
                    S::UNAUTHORIZED,
                    "surrogate_unknown",
                    "surrogate not recognised",
                ),
            });
        }
        if st != S::OK {
            return Err(BROKER_DOWN);
        }
        let r: Resolved = resp.json().await.map_err(|_| BROKER_DOWN)?;
        if r.expires_at <= now_secs() {
            return Err(deny(
                S::UNAUTHORIZED,
                "surrogate_expired",
                "surrogate expired; re-mint",
            ));
        }
        let v = if route.credential_scheme.is_empty() {
            r.credential
        } else {
            format!("{} {}", route.credential_scheme, r.credential)
        };
        let mut credential_value = HeaderValue::from_str(&v).map_err(|_| BROKER_DOWN)?;
        credential_value.set_sensitive(true);
        let rest = match uri.query() {
            Some(q) => format!("{rest_path}?{q}"),
            None => rest_path,
        };
        Ok(Admitted {
            caller,
            route,
            rest,
            credential_id: r.credential_id,
            credential_value,
        })
    }

    /// One JSON line per decision. Fields are identities and codes only.
    pub fn audit(&self, a: &AuditRec) {
        let line = serde_json::json!({
            "t": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            "impl": self.impl_name,
            "caller": a.caller, "route": a.route, "method": a.method, "path": a.path,
            "decision": a.decision, "code": a.code, "status": a.status,
            "credential_id": a.credential_id, "ms": a.ms,
        })
        .to_string();
        let mut g = self.audit.lock().unwrap();
        match g.as_mut() {
            Some(f) => {
                let _ = writeln!(f, "{line}");
            }
            None => eprintln!("{line}"),
        }
    }
}

#[derive(Default)]
pub struct AuditRec {
    pub caller: Option<String>,
    pub route: Option<String>,
    pub method: String,
    /// Route-relative path, no query (the caller key is never in it).
    pub path: Option<String>,
    pub decision: &'static str,
    pub code: &'static str,
    pub status: u16,
    pub credential_id: Option<String>,
    pub ms: u64,
}

/// Remove hop-by-hop headers, headers named by `Connection`, and every auth header.
pub fn strip_request_headers(h: &mut HeaderMap) {
    let named: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in HOP_HEADERS.iter().chain(AUTH_HEADERS) {
        h.remove(*n);
    }
}

/// Status, headers and body of a refusal, in the route's error dialect.
pub fn deny_parts(
    shape: ErrorShape,
    d: &Deny,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    let mut hs = vec![("x-auth-proxy-error", d.code.to_string())];
    let body = match shape {
        ErrorShape::Json => {
            hs.push(("content-type", "application/json".into()));
            serde_json::json!({"type": "error", "error": {"type": d.code, "message": format!("auth-proxy: {}", d.msg)}})
                .to_string()
        }
        ErrorShape::Aws => {
            let t = if d.status == StatusCode::SERVICE_UNAVAILABLE {
                "ServiceUnavailableException"
            } else {
                "AccessDeniedException"
            };
            hs.push(("content-type", "application/x-amz-json-1.0".into()));
            hs.push(("x-amzn-errortype", t.into()));
            serde_json::json!({"__type": t, "message": format!("auth-proxy: {} ({})", d.msg, d.code)}).to_string()
        }
    };
    (d.status, hs, body)
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
}
