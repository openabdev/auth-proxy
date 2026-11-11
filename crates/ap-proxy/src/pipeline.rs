//! The request pipeline from design section 4, in order:
//!
//! 1. refuse CONNECT (405) and WebSocket upgrades (501)
//! 2. canonicalize: origin form, one Host equal to the listener authority, no ambiguous path
//! 3. policy snapshot (reloaded on file change), caller key, route
//! 4. exactly one surrogate in the route's surrogate header
//! 5. registry lookup of the surrogate
//! 6. policy grant for method, path and AWS target
//! 7. credential read from the store
//! 8. strip and swap headers, stream the request and response, no redirects
//! 9. one audit line
//!
//! Every refusal writes an audit line and sends nothing upstream. A policy file that fails to
//! load drops the snapshot, and every request that needs it gets 503 until a valid file appears.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime};

use ap_broker::broker::Broker;
use ap_broker::clock::SystemClock;
use ap_broker::expiry::FileExpiryStore;
use ap_broker::proof::NonceTable;
use ap_broker::registry::{sha256_hex, Access, Registry, RegistryCfg};
use ap_core::audit::{path_only, AuditRec};
use ap_core::canon;
use ap_core::config::{self, Config, ErrorShape, Grant, Identity, Route};
use ap_core::error::{render, Code};
use ap_core::policy::Snapshot;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http::{header, HeaderValue, Method, StatusCode};
use subtle::ConstantTimeEq;

use crate::audit_sink::AuditSink;
use crate::forward;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    modified: SystemTime,
    len: u64,
}

fn stamp_of(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    Some(Stamp {
        modified: meta.modified().ok()?,
        len: meta.len(),
    })
}

/// A policy file that loaded and validated, with the stamp it was read under.
#[derive(Clone)]
struct Loaded {
    stamp: Stamp,
    cfg: Arc<Config>,
    snap: Arc<Snapshot>,
}

/// Shared state for the agent listener and the session plane.
pub struct App {
    policy_path: PathBuf,
    policy: RwLock<Option<Loaded>>,
    listen_authority: String,
    max_body: u64,
    pub(crate) token_dir: PathBuf,
    pub(crate) identity_names: Vec<String>,
    pub(crate) authority_lease_secs: u64,
    pub(crate) registry: Arc<Mutex<Registry<SystemClock>>>,
    /// Nonces handed out by `GET /v1/hello/challenge` and not yet spent by a hello.
    pub(crate) nonces: Mutex<NonceTable>,
    broker: Arc<dyn Broker>,
    pub(crate) audit: AuditSink,
    client: reqwest::Client,
}

impl App {
    /// Build the shared state. `cfg` is the config read from `policy_path` at startup, and
    /// `token_dir` holds the authority token hashes. `expiry_store` is the session expiry store
    /// file. Fails when the expiry store cannot be read, so the proxy never serves sessions
    /// without it.
    pub fn new(
        policy_path: PathBuf,
        cfg: Config,
        token_dir: PathBuf,
        expiry_store: PathBuf,
        broker: Arc<dyn Broker>,
        audit: AuditSink,
        client: reqwest::Client,
    ) -> Result<Arc<App>, String> {
        let registry = Registry::new(
            SystemClock,
            RegistryCfg::from_sessions(&cfg.sessions),
            Access::from_config(&cfg),
            Some(token_dir.clone()),
            Box::new(FileExpiryStore::new(expiry_store)),
        )
        .map_err(|e| format!("cannot load the session expiry store: {e}"))?;
        let listen_authority = cfg.listen.proxy.to_string();
        let max_body = cfg.limits.max_body_bytes;
        let identity_names = cfg.identities.iter().map(|i| i.name.clone()).collect();
        let authority_lease_secs = cfg.sessions.authority_lease_secs;
        let snap = Arc::new(Snapshot::from_config(&cfg));
        let policy = stamp_of(&policy_path).map(|stamp| Loaded {
            stamp,
            snap,
            cfg: Arc::new(cfg),
        });
        Ok(Arc::new(App {
            policy_path,
            policy: RwLock::new(policy),
            listen_authority,
            max_body,
            token_dir,
            identity_names,
            authority_lease_secs,
            registry: Arc::new(Mutex::new(registry)),
            nonces: Mutex::new(NonceTable::new()),
            broker,
            audit,
            client,
        }))
    }

    /// The policy in force now. The file's stamp (mtime and size) is checked on every call. A
    /// change triggers a reload. A file that cannot be read or validated drops the snapshot and
    /// returns `None`, so the caller answers 503.
    fn policy(&self) -> Option<Loaded> {
        let Some(stamp) = stamp_of(&self.policy_path) else {
            self.drop_policy();
            return None;
        };
        if let Ok(guard) = self.policy.read() {
            if let Some(l) = guard.as_ref() {
                if l.stamp == stamp {
                    return Some(l.clone());
                }
            }
        }
        let loaded = std::fs::read_to_string(&self.policy_path)
            .ok()
            .and_then(|text| config::load(&text).ok())
            .map(|cfg| Loaded {
                stamp,
                snap: Arc::new(Snapshot::from_config(&cfg)),
                cfg: Arc::new(cfg),
            });
        match self.policy.write() {
            Ok(mut slot) => *slot = loaded.clone(),
            Err(_) => return None,
        }
        loaded
    }

    fn drop_policy(&self) {
        if let Ok(mut slot) = self.policy.write() {
            *slot = None;
        }
    }
}

/// What the audit line knows so far. Filled in as the pipeline goes. The caller key and the
/// surrogate never enter it.
#[derive(Clone)]
struct Trail {
    started: Instant,
    method: String,
    identity: String,
    session: Option<String>,
    generation: Option<u64>,
    route: Option<String>,
    path: String,
    aws_target: Option<String>,
}

impl Trail {
    fn new(started: Instant, method: &str) -> Self {
        Trail {
            started,
            method: method.to_string(),
            identity: String::new(),
            session: None,
            generation: None,
            route: None,
            path: String::new(),
            aws_target: None,
        }
    }

    fn rec(&self, decision: &'static str, code: Option<String>, status: u16) -> AuditRec {
        AuditRec {
            identity: self.identity.clone(),
            session: self.session.clone(),
            generation: self.generation,
            route: self.route.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            aws_target: self.aws_target.clone(),
            decision,
            code,
            status,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }
}

fn respond(status: u16, body: Body, content_type: Option<&'static str>) -> Response {
    let mut r = Response::new(body);
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if let Some(ct) = content_type {
        r.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(ct));
    }
    r
}

/// Write the refusal audit line and answer with the error body in the given dialect.
fn refuse(app: &App, trail: &Trail, code: Code, shape: ErrorShape) -> Response {
    let rec = trail.rec("deny", Some(code.code_str().to_string()), code.status());
    app.audit.write_rec(&rec);
    let (status, body) = render(code, shape);
    respond(status, Body::from(body), Some("application/json"))
}

/// The caller whose key hashes to the presented key. Every identity is compared, so the time
/// taken does not show which identity matched.
fn caller_identity<'a>(cfg: &'a Config, caller_key: &str) -> Option<&'a Identity> {
    let presented = sha256_hex(caller_key);
    let mut found = None;
    for id in &cfg.identities {
        let same: bool = presented
            .as_bytes()
            .ct_eq(id.caller_key_sha256.as_bytes())
            .into();
        if same && found.is_none() {
            found = Some(id);
        }
    }
    found
}

/// Whether a grant covers this method, route-relative path and AWS target. This mirrors
/// `Snapshot::evaluate`, so the credential chosen is the one the matching grant names.
fn grant_matches(g: &Grant, route: &str, method: &str, path: &str, targets: &[&str]) -> bool {
    g.route == route
        && g.methods.iter().any(|m| m == method)
        && g.paths.iter().any(|p| path.starts_with(p.as_str()))
        && (g.aws_targets.is_empty()
            || matches!(targets, [t] if g.aws_targets.iter().any(|a| a == t)))
}

/// The one credential that a matching grant names, restricted to the credentials the
/// registry bound to this surrogate. Zero or several candidates is refused.
fn granted_credential(
    cfg: &Config,
    identity: &str,
    route: &str,
    method: &str,
    path: &str,
    targets: &[&str],
    bound: &[String],
) -> Option<String> {
    let mut picked: Vec<&str> = Vec::new();
    for g in &cfg.grants {
        if g.identity == identity
            && bound.iter().any(|c| c == &g.credential)
            && grant_matches(g, route, method, path, targets)
            && !picked.contains(&g.credential.as_str())
        {
            picked.push(g.credential.as_str());
        }
    }
    match picked.as_slice() {
        [only] => Some((*only).to_string()),
        _ => None,
    }
}

/// Collect every `X-Amz-Target` value. A non-UTF-8 value makes the list unusable: `None`.
fn aws_targets(headers: &http::HeaderMap) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    for v in headers.get_all("x-amz-target") {
        out.push(v.to_str().ok()?);
    }
    Some(out)
}

/// Writes the allow line when the response body ends, or when the client drops it. An
/// upstream error mid-stream is recorded as `upstream_reset`.
struct StreamAudit {
    app: Arc<App>,
    trail: Trail,
    status: u16,
    reset: bool,
}

impl Drop for StreamAudit {
    fn drop(&mut self) {
        let code = self.reset.then(|| "upstream_reset".to_string());
        let rec = self.trail.rec("allow", code, self.status);
        self.app.audit.write_rec(&rec);
    }
}

fn audited<S>(stream: S, audit: StreamAudit) -> impl Stream<Item = Result<Bytes, io::Error>>
where
    S: Stream<Item = reqwest::Result<Bytes>> + Send + Unpin + 'static,
{
    futures_util::stream::unfold((Box::pin(stream), audit), |(mut s, mut a)| async move {
        match s.next().await {
            Some(Ok(bytes)) => Some((Ok(bytes), (s, a))),
            Some(Err(e)) => {
                a.reset = true;
                Some((Err(io::Error::other(e)), (s, a)))
            }
            None => None,
        }
    })
}

/// Handle one request on the agent listener.
pub async fn handle(app: Arc<App>, req: Request) -> Response {
    let started = Instant::now();
    let (parts, body) = req.into_parts();
    let mut trail = Trail::new(started, parts.method.as_str());

    // 1. CONNECT and WebSocket upgrades are refused before anything else is read.
    if parts.method == Method::CONNECT {
        return refuse(&app, &trail, Code::ConnectRefused, ErrorShape::Generic);
    }
    if parts.headers.contains_key(header::UPGRADE) {
        return refuse(
            &app,
            &trail,
            Code::WebsocketUnsupported,
            ErrorShape::Generic,
        );
    }

    // 2. Canonical request target and host, then the path ambiguity check.
    if let Err(code) = canon::check_origin_form(
        &parts.uri,
        &parts.headers,
        parts.version,
        &app.listen_authority,
    ) {
        return refuse(&app, &trail, code, ErrorShape::Generic);
    }
    if canon::path_ambiguous(parts.uri.path()) {
        return refuse(&app, &trail, Code::PathAmbiguous, ErrorShape::Generic);
    }

    // 3. Policy, caller key, route.
    let Some(policy) = app.policy() else {
        return refuse(&app, &trail, Code::PolicyUnavailable, ErrorShape::Generic);
    };
    let ap = match canon::parse_ap_path(parts.uri.path()) {
        Ok(p) => p,
        Err(code) => return refuse(&app, &trail, code, ErrorShape::Generic),
    };
    let Some(identity) = caller_identity(&policy.cfg, ap.caller_key) else {
        return refuse(&app, &trail, Code::CallerRejected, ErrorShape::Generic);
    };
    let Some(route): Option<&Route> = policy.snap.route(ap.route) else {
        return refuse(&app, &trail, Code::RouteUnknown, ErrorShape::Generic);
    };
    trail.identity = identity.name.clone();
    trail.route = Some(route.name.clone());
    trail.path = path_only(&ap.route_path);
    let shape = route.error_shape;

    // 4. Exactly one surrogate.
    let surrogate = match canon::surrogate_from_headers(&parts.headers, &route.surrogate_header) {
        Ok(s) => s,
        Err(code) => return refuse(&app, &trail, code, shape),
    };
    let surrogate_sha = sha256_hex(&surrogate);

    // 5. Registry lookup, bound to this caller and this route.
    let bound = {
        let Ok(reg) = app.registry.lock() else {
            return refuse(&app, &trail, Code::BrokerUnavailable, shape);
        };
        let now = reg.now();
        reg.authorize(&surrogate_sha, &identity.name, &route.name, now)
    };
    let bound = match bound {
        Ok(b) => b,
        Err(deny) => return refuse(&app, &trail, deny.code(), shape),
    };
    trail.session = Some(bound.session.clone());
    trail.generation = Some(bound.generation);

    // 6. Policy: the grant must cover method, path and AWS target.
    let Some(targets) = aws_targets(&parts.headers) else {
        return refuse(&app, &trail, Code::PolicyDenied, shape);
    };
    let method = parts.method.as_str();
    if let [only] = targets.as_slice() {
        trail.aws_target = Some((*only).to_string());
    }
    if let Err(code) = policy.snap.evaluate(
        &identity.name,
        &route.name,
        method,
        &ap.route_path,
        &targets,
    ) {
        return refuse(&app, &trail, code, shape);
    }
    let Some(credential_id) = granted_credential(
        &policy.cfg,
        &identity.name,
        &route.name,
        method,
        &ap.route_path,
        &targets,
        &bound.credentials,
    ) else {
        return refuse(&app, &trail, Code::PolicyDenied, shape);
    };

    // 7. Credential read. The value is held only for this request.
    let source = policy
        .cfg
        .credentials
        .iter()
        .find(|c| c.id == credential_id)
        .map(|c| c.source.clone());
    let secret = match source.map(|s| app.broker.credential(&s)) {
        Some(Ok(secret)) => secret,
        _ => return refuse(&app, &trail, Code::BrokerUnavailable, shape),
    };

    // 8. Strip, swap, stream. A declared length over the cap is refused before any connection.
    if forward::declared_length(&parts.headers).is_some_and(|n| n > app.max_body) {
        return refuse(&app, &trail, Code::BodyTooLarge, shape);
    }
    let Ok(headers) = forward::outbound_headers(&parts.headers, route, &secret) else {
        return refuse(&app, &trail, Code::BrokerUnavailable, shape);
    };
    let rest = match parts.uri.query() {
        Some(q) => format!("{}?{q}", ap.route_path),
        None => ap.route_path.clone(),
    };
    let url = forward::upstream_url(route, &rest);
    let overflow = Arc::new(AtomicBool::new(false));
    let upstream_body = forward::capped_body(body, app.max_body, Arc::clone(&overflow));
    let upstream = forward::send(
        &app.client,
        parts.method.clone(),
        &url,
        headers,
        upstream_body,
    )
    .await;
    let upstream = match upstream {
        Ok(r) => r,
        Err(_) if overflow.load(Ordering::SeqCst) => {
            return refuse(&app, &trail, Code::BodyTooLarge, shape);
        }
        Err(_) => return refuse(&app, &trail, Code::UpstreamUnavailable, shape),
    };

    // 9. The response streams back. The allow line is written when the body ends.
    let status = upstream.status();
    let out_headers = forward::response_headers(upstream.headers());
    let audit = StreamAudit {
        app: Arc::clone(&app),
        trail,
        status: status.as_u16(),
        reset: false,
    };
    let mut response = Response::new(Body::from_stream(audited(upstream.bytes_stream(), audit)));
    *response.status_mut() = status;
    *response.headers_mut() = out_headers;
    response
}
