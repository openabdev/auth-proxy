//! The passthrough pipeline (design 3.1) for the Muse gate, stage 1.
//!
//! In order: refuse CONNECT and Upgrade, canonicalize (origin form, public `Host`, ambiguous
//! path), refuse ambiguous framing, read the caller key from its header or the `/ap/<caller-key>/` path prefix (exactly one), resolve the route name
//! in the path to a fixed host, refuse a duplicate `Authorization`, evaluate the grant (anything
//! not granted, writes included, is 423 `no_grant`), forward with the caller's own
//! `Authorization` unchanged, and stream the response back. Every gate refusal carries
//! `X-AP-Decision` and writes one audit line. Nothing request-supplied selects the upstream host.
//!
//! Stage 2: a grant with `decision = "hold"` sends the request to [`hold_path`], which buffers it,
//! parks it in the hold table and forwards it only after a human approves it.

use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ap_broker::clock::{Clock, SystemClock};
use ap_broker::registry::sha256_hex;
use ap_core::audit::{path_only, AuditRec};
use ap_core::canon;
use ap_core::config::{Config, Identity};
use ap_core::error::Code;
use ap_core::outcome::{render_passthrough, DECISION_HEADER};
use ap_core::policy::{Snapshot, Verdict};
use axum::body::Body;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http::{header, HeaderValue, Method, Request, Response, StatusCode};
use subtle::ConstantTimeEq;

use crate::audit_sink::AuditSink;
use crate::evidence::Evidence;
use crate::forward::{self, BodyFlags};
use crate::hold;
use crate::notify::Notifier;
use crate::policy_store::PolicyStore;

mod hold_path;
#[cfg(test)]
mod hold_tests;
#[cfg(any(test, feature = "matrix-upstream"))]
pub(crate) mod pause;
#[cfg(test)]
mod tests;

/// Returned instead of a response: the connection is closed with no synthetic decision.
#[derive(Debug)]
pub struct ConnAbort;

impl std::fmt::Display for ConnAbort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connection aborted after the first upstream byte")
    }
}

impl std::error::Error for ConnAbort {}

/// Shared state of the passthrough listener.
pub struct PtApp {
    pub(crate) policy: PolicyStore,
    pub(crate) audit: AuditSink,
    client: reqwest::Client,
    /// Sends approved requests: HTTP/1.1, one connection per request.
    held_client: reqwest::Client,
    /// Held requests waiting for a decision.
    pub hold: Arc<hold::Table>,
    /// Told about each new distinct hold entry. `None` until a notifier is configured.
    pub notifier: Option<Arc<dyn Notifier>>,
    /// `[approval].public_base_url` without a trailing slash: the notification link is
    /// `{approval_base}/pending/{id}`.
    pub(crate) approval_base: Option<String>,
    /// Source of "now" for the option B pilot expiry (design 4.5). Tests replace it.
    pub(crate) clock: Arc<dyn Clock + Send + Sync>,
    #[cfg(any(test, feature = "matrix-upstream"))]
    pub(crate) pause: pause::Pause,
}

impl PtApp {
    /// An app that sends approved requests through `client` too. The hold table takes its limits
    /// from the policy read at startup.
    #[cfg(test)]
    pub(crate) fn new(
        policy_path: std::path::PathBuf,
        cfg: Config,
        policy_text: &str,
        audit: AuditSink,
        client: reqwest::Client,
    ) -> Arc<PtApp> {
        let held_client = client.clone();
        Self::with_held_client(policy_path, cfg, policy_text, audit, client, held_client)
    }

    /// An app with a separate client for approved requests (see `forward::held_client`).
    pub(crate) fn with_held_client(
        policy_path: std::path::PathBuf,
        cfg: Config,
        policy_text: &str,
        audit: AuditSink,
        client: reqwest::Client,
        held_client: reqwest::Client,
    ) -> Arc<PtApp> {
        let limits = cfg
            .passthrough
            .as_ref()
            .map_or_else(default_limits, hold::Limits::from_config);
        Self::build(
            policy_path,
            cfg,
            policy_text,
            audit,
            client,
            held_client,
            limits,
        )
    }

    /// Announce new hold entries through `notifier`, linking to `{base}/pending/{id}`. Called
    /// right after construction, while this is the only handle.
    pub(crate) fn set_notifier(app: &mut Arc<PtApp>, notifier: Arc<dyn Notifier>, base: &str) {
        let inner = Arc::get_mut(app).expect("notifier is set before the app is shared");
        inner.notifier = Some(notifier);
        inner.approval_base = Some(base.trim_end_matches('/').to_string());
    }

    /// Replace the clock that the option B pilot expiry reads. Called right after construction,
    /// while this is the only handle.
    #[cfg(test)]
    pub(crate) fn set_clock(app: &mut Arc<PtApp>, clock: Arc<dyn Clock + Send + Sync>) {
        Arc::get_mut(app)
            .expect("clock is set before the app is shared")
            .clock = clock;
    }

    /// One step of the policy-reload watch (design 3.9), run about once a second. The policy is
    /// re-read if its file changed. A file that is gone or no longer valid drops every pending
    /// hold; a valid file drops every hold the new policy no longer yields `hold` for (identity,
    /// route, method or path). Returns the number dropped. Entries already approved are past the table and are not touched.
    pub fn reload_tick(&self) -> usize {
        match self.policy.current() {
            None => self.hold.drop_all(),
            Some(l) => self
                .hold
                .drop_unless(|identity, req| still_held(&l.snap, identity, req)),
        }
    }

    /// Whether the policy in force now still holds `req` for `identity`, for the same upstream,
    /// and a token identity is still inside its pilot window. Reads the policy at the call. No
    /// valid policy answers `false`.
    pub(crate) fn still_holds(&self, identity: &str, req: &hold::HeldRequest) -> bool {
        self.policy.current().is_some_and(|l| {
            still_held(&l.snap, identity, req)
                && !token_expired(&l.cfg, identity, self.clock.now())
                && token_bound(&l.cfg, identity, req)
        })
    }

    /// The snapshot of the policy in force now, for the approval plane's re-check.
    pub fn policy_source(self: &Arc<Self>) -> crate::approval::PolicySource {
        let app = Arc::clone(self);
        Arc::new(move || app.policy.current().map(|l| l.snap))
    }

    pub(crate) fn build(
        policy_path: std::path::PathBuf,
        cfg: Config,
        policy_text: &str,
        audit: AuditSink,
        client: reqwest::Client,
        held_client: reqwest::Client,
        limits: hold::Limits,
    ) -> Arc<PtApp> {
        Arc::new(PtApp {
            policy: PolicyStore::new(policy_path, cfg, policy_text),
            audit,
            client,
            held_client,
            hold: Arc::new(hold::Table::new(limits)),
            notifier: None,
            approval_base: None,
            clock: Arc::new(SystemClock),
            #[cfg(any(test, feature = "matrix-upstream"))]
            pause: pause::Pause::new(),
        })
    }
}

/// Whether `snap` still holds this request: the route exists, still names the upstream (scheme,
/// host, port) and the forwarding settings the request was built with, and the identity's grants
/// give `hold` for its method and route-relative path. Anything else (no grant, an allow, a
/// deny, another destination) means the permission the owner reviewed is gone.
pub(crate) fn still_held(snap: &Snapshot, identity: &str, req: &hold::HeldRequest) -> bool {
    snap.route(&req.route)
        .is_some_and(|r| hold::Upstream::from_route(r) == req.upstream)
        && matches!(
            snap.evaluate_verdict(identity, &req.route, &req.method, &req.path),
            Ok(Verdict::Hold)
        )
}

fn default_limits() -> hold::Limits {
    hold::Limits {
        hold: Duration::from_secs(120),
        max_total: 32,
        max_per_identity: 4,
        cooldown: Duration::from_secs(60),
    }
}

/// What the audit line knows so far. The caller key and `Authorization` never enter it.
pub(crate) struct Trail {
    started: Instant,
    method: String,
    identity: String,
    route: Option<String>,
    path: String,
    evidence: Option<Evidence>,
}

impl Trail {
    fn new(method: &str) -> Trail {
        Trail {
            started: Instant::now(),
            method: method.to_string(),
            identity: String::new(),
            route: None,
            path: String::new(),
            evidence: None,
        }
    }

    pub(crate) fn rec(&self, decision: &'static str, code: Option<&str>, status: u16) -> AuditRec {
        AuditRec {
            identity: self.identity.clone(),
            session: None,
            generation: None,
            route: self.route.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            aws_target: None,
            decision,
            code: code.map(str::to_string),
            status,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            bytes_sent: None,
        }
    }

    fn write_evidence(&self, audit: &AuditSink, status: u16) {
        if let Some(e) = &self.evidence {
            let mut e = e.clone();
            e.status = status;
            e.route.clone_from(&self.route);
            e.path.clone_from(&self.path);
            audit.write_line(&e.to_json_line());
        }
    }
}

impl std::fmt::Debug for Trail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trail")
            .field("method", &self.method)
            .field("identity", &self.identity)
            .field("route", &self.route)
            .field("path", &self.path)
            .finish()
    }
}

/// A gate refusal: audit line, evidence line, status, `X-AP-Decision` and JSON body.
pub(crate) fn refuse(app: &PtApp, trail: &Trail, code: Code) -> Response<Body> {
    let (status, _, _) = render_passthrough(code);
    app.audit
        .write_rec(&trail.rec("deny", Some(code.code_str()), status));
    trail.write_evidence(&app.audit, status);
    refusal_response(code)
}

/// The answer for a refusal, without any audit line.
pub(crate) fn refusal_response(code: Code) -> Response<Body> {
    let (status, decision, body) = render_passthrough(code);
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r.headers_mut()
        .insert(DECISION_HEADER, HeaderValue::from_static(decision.as_str()));
    r
}

/// How to drain an unread request body before a refusal (design 3.4 step 1).
pub(crate) struct Drain {
    max: u64,
    total: Duration,
    skip: bool,
}

impl Drain {
    /// `skip` when no body will arrive: none declared, or `Expect: 100-continue` (hyper has not
    /// sent `100 Continue`, so the client is waiting and the drain would only run out its timer).
    pub(crate) fn new(
        headers: &http::HeaderMap,
        declared: Option<u64>,
        pt: &ap_core::config::Passthrough,
    ) -> Drain {
        let has_body =
            headers.contains_key(header::TRANSFER_ENCODING) || declared.is_some_and(|n| n > 0);
        let expect = headers
            .get_all(header::EXPECT)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.trim().eq_ignore_ascii_case("100-continue"));
        Drain {
            max: pt.held_body_max_bytes,
            total: Duration::from_secs(pt.body_read_secs),
            skip: !has_body || expect,
        }
    }

    async fn run(&self, body: Body) {
        if !self.skip {
            forward::drain_body(body, self.max, self.total).await;
        }
    }
}

/// A refusal for a request whose body has not been read: drain it first, so a client still
/// writing can read the answer instead of seeing a reset.
pub(crate) async fn refuse_unread(
    app: &PtApp,
    trail: &Trail,
    code: Code,
    body: Body,
    drain: &Drain,
) -> Response<Body> {
    drain.run(body).await;
    refuse(app, trail, code)
}

/// A failure after the first upstream request byte: one audit line, then the caller's
/// connection is closed with no synthetic answer.
fn abort(app: &PtApp, trail: &Trail, code: &str) -> ConnAbort {
    app.audit.write_rec(&trail.rec("allow", Some(code), 0));
    trail.write_evidence(&app.audit, 0);
    ConnAbort
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

/// Whether `identity` is an option B token identity whose last accepted second has passed at `now`.
fn token_expired(cfg: &Config, identity: &str, now: u64) -> bool {
    cfg.token_identities
        .iter()
        .any(|t| t.name == identity && t.expired_at(now))
}

/// Whether a token identity's held request still carries the token the policy binds to it. The
/// held `Authorization` value must be the only one and hash, as admission hashed it, to the
/// identity's current `token_sha256`. A keyed hold has no token identity and passes, unless it was
/// admitted with a token: then the token identity must still exist under the same name, or the
/// hold is refused.
fn token_bound(cfg: &Config, identity: &str, req: &hold::HeldRequest) -> bool {
    let Some(token) = cfg.token_identities.iter().find(|t| t.name == identity) else {
        return !req.token_admitted;
    };
    let mut values = req
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(header::AUTHORIZATION.as_str()))
        .map(|(_, v)| v);
    let value = match (values.next(), values.next()) {
        (Some(v), None) => v,
        _ => return false,
    };
    let Ok(value) = http::HeaderValue::from_bytes(value) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let presented = sha256_hex(value);
    presented
        .as_bytes()
        .ct_eq(token.token_sha256.as_bytes())
        .into()
}

/// Whether the pilot token is repeated in the route-relative path or the query, in any percent-encoded
/// spelling. The token is the `Authorization` value without its `Bot ` scheme, and the same
/// detection that checks the caller key applies to it.
fn token_echoed(headers: &http::HeaderMap, path: &str, query: Option<&str>) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let token = value.strip_prefix("Bot ").unwrap_or(value);
    canon::echoes_caller_key(path, token)
        || query.is_some_and(|q| canon::echoes_caller_key(q, token))
}

/// Option B (design 4.5): the token identity that a request with no caller key presents. The
/// `Authorization` value must be the single one and hash to the token bound to this route, the
/// day must be inside the pilot window, and the policy must give `hold` for that identity on this
/// request. Anything else is `caller_rejected`, the answer a missing caller key gets.
fn pilot_identity(
    cfg: &Config,
    snap: &Snapshot,
    path: &str,
    method: &Method,
    headers: &http::HeaderMap,
    now: u64,
) -> Result<String, Code> {
    let (route, rel) = canon::parse_route_path(path).map_err(|_| Code::CallerRejected)?;
    let token = cfg
        .token_identities
        .iter()
        .find(|t| t.route == route)
        .ok_or(Code::CallerRejected)?;
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().map_err(|_| Code::CallerRejected)?,
        _ => return Err(Code::CallerRejected),
    };
    let presented = sha256_hex(value);
    let same: bool = presented
        .as_bytes()
        .ct_eq(token.token_sha256.as_bytes())
        .into();
    if !same || token.expired_at(now) {
        return Err(Code::CallerRejected);
    }
    match snap.evaluate_verdict(&token.name, route, method.as_str(), &rel) {
        Ok(Verdict::Hold) => Ok(token.name.clone()),
        _ => Err(Code::CallerRejected),
    }
}

/// What the stream audit writes when the response ends.
enum End {
    /// An allowed request: the single `allow` line.
    Allow,
    /// An approved request: a `completed` transition, unless the upstream reset.
    Held(hold_path::HeldEnd),
}

/// Writes the final line when the response body ends, or when the client drops it.
struct StreamAudit {
    app: Arc<PtApp>,
    trail: Trail,
    status: u16,
    reset: bool,
    end: End,
}

impl Drop for StreamAudit {
    fn drop(&mut self) {
        match &self.end {
            End::Allow => {
                let code = self.reset.then_some("upstream_reset");
                self.app
                    .audit
                    .write_rec(&self.trail.rec("allow", code, self.status));
            }
            End::Held(h) => {
                if !self.reset {
                    self.app.audit.write_hold(&h.completed(self.status));
                }
            }
        }
        self.trail.write_evidence(&self.app.audit, self.status);
    }
}

fn audited<S>(
    stream: S,
    audit: StreamAudit,
    deadline: Instant,
    idle: Duration,
) -> impl Stream<Item = Result<Bytes, io::Error>>
where
    S: Stream<Item = reqwest::Result<Bytes>> + Send + Unpin + 'static,
{
    futures_util::stream::unfold(
        (Box::pin(stream), audit, false),
        move |(mut s, mut a, done)| async move {
            if done {
                return None;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            let wait = left.min(idle);
            match tokio::time::timeout(wait, s.next()).await {
                Ok(Some(Ok(bytes))) => Some((Ok(bytes), (s, a, false))),
                Ok(Some(Err(e))) => {
                    a.reset = true;
                    Some((Err(io::Error::other(e)), (s, a, true)))
                }
                Ok(None) => None,
                Err(_) => {
                    a.reset = true;
                    Some((
                        Err(io::Error::new(io::ErrorKind::TimedOut, "upstream stalled")),
                        (s, a, true),
                    ))
                }
            }
        },
    )
}

/// Handle one request on the public listener.
pub async fn handle(app: Arc<PtApp>, req: Request<Body>) -> Result<Response<Body>, ConnAbort> {
    let (mut parts, body) = req.into_parts();
    let mut trail = Trail::new(parts.method.as_str());

    // 1. CONNECT and Upgrade.
    if parts.method == Method::CONNECT {
        return Ok(refuse(&app, &trail, Code::ConnectRefused));
    }
    if parts.headers.contains_key(header::UPGRADE) {
        return Ok(refuse(&app, &trail, Code::WebsocketUnsupported));
    }

    // 2. Policy snapshot, which also holds the public authority.
    let Some(policy) = app.policy.current() else {
        return Ok(refuse(&app, &trail, Code::PolicyUnavailable));
    };
    let Some(pt) = policy.cfg.passthrough.as_ref() else {
        return Ok(refuse(&app, &trail, Code::PolicyUnavailable));
    };

    // 3. Canonical request target, host and path.
    if let Err(code) = canon::check_origin_form(
        &parts.uri,
        &parts.headers,
        parts.version,
        &pt.public_authority,
    ) {
        return Ok(refuse(&app, &trail, code));
    }
    if canon::path_ambiguous_passthrough(parts.uri.path()) {
        return Ok(refuse(&app, &trail, Code::PathAmbiguous));
    }
    // 4. Framing.
    if canon::framing_refused(&parts.headers, &pt.caller_key_header) {
        return Ok(refuse(&app, &trail, Code::FramingRefused));
    }

    // 5. Caller key: from its header OR from a `/ap/<caller-key>/` path prefix, exactly one.
    // Mark every header value sensitive first so no Debug print of the request or its headers
    // can show it. The prefix is stripped here: everything after this point sees `eff_path`.
    let mut header_present = false;
    if let Ok(name) = http::HeaderName::from_bytes(pt.caller_key_header.as_bytes()) {
        if let http::header::Entry::Occupied(mut e) = parts.headers.entry(name) {
            header_present = true;
            for v in e.iter_mut() {
                v.set_sensitive(true);
            }
        }
    }
    let path_form = parts.uri.path().starts_with("/ap/");
    if header_present && path_form {
        return Ok(refuse(&app, &trail, Code::CallerKeyAmbiguous));
    }
    // Option B (design 4.5): a request with no caller key at all may authenticate by the token
    // bound to its route, and only for a hold. Every other keyless request is refused as before.
    let pilot = !path_form && !header_present;
    let (identity_name, eff_path, key_echoed) = if pilot {
        match pilot_identity(
            &policy.cfg,
            &policy.snap,
            parts.uri.path(),
            &parts.method,
            &parts.headers,
            app.clock.now(),
        ) {
            Ok(name) => {
                let echoed = token_echoed(&parts.headers, parts.uri.path(), parts.uri.query());
                (name, parts.uri.path().to_string(), echoed)
            }
            Err(code) => return Ok(refuse(&app, &trail, code)),
        }
    } else {
        let (key, eff_path) = if path_form {
            // `parse_ap_path` validates the prefix. Whatever follows the key, byte for byte, is the
            // path the rest of the pipeline sees.
            let path = parts.uri.path();
            let key = match canon::parse_ap_path(path) {
                Ok(ap) => ap.caller_key,
                // The key is well formed but the route segment is empty: authenticate the key
                // first, so an unknown key is still 401; `/` then names no route.
                Err(Code::RouteUnknown) => path
                    .strip_prefix("/ap/")
                    .and_then(|r| r.split('/').next())
                    .unwrap_or_default(),
                Err(code) => return Ok(refuse(&app, &trail, code)),
            };
            (
                key.to_string(),
                path["/ap/".len() + key.len()..].to_string(),
            )
        } else {
            match canon::caller_key_from_header(&parts.headers, &pt.caller_key_header) {
                Ok(k) => (k, parts.uri.path().to_string()),
                Err(code) => return Ok(refuse(&app, &trail, code)),
            }
        };
        let Some(identity) = caller_identity(&policy.cfg, &key) else {
            return Ok(refuse(&app, &trail, Code::CallerRejected));
        };
        // The key authenticates the request and goes no further. A route-relative path or query
        // that carries it again, in any percent-encoded spelling, would be matched, held, shown to
        // the approver, audited and sent upstream: refused here, before the Trail has a path.
        let key_echoed = canon::echoes_caller_key(&eff_path, &key)
            || parts
                .uri
                .query()
                .is_some_and(|q| canon::echoes_caller_key(q, &key));
        (identity.name.clone(), eff_path, key_echoed)
    };
    trail.identity.clone_from(&identity_name);
    trail.evidence = Some(Evidence::collect(
        &identity_name,
        parts.method.as_str(),
        parts.version,
        &parts.headers,
    ));

    // Every refusal from here on has an authenticated caller, so a body still in flight is
    // drained (bounded) before the answer.
    let max_body = policy.cfg.limits.max_body_bytes;
    let declared = forward::declared_length(&parts.headers);
    let drain = Drain::new(&parts.headers, declared, pt);

    if key_echoed {
        return Ok(refuse_unread(&app, &trail, Code::CallerKeyAmbiguous, body, &drain).await);
    }

    #[cfg(feature = "matrix-upstream")]
    if eff_path == crate::matrix_hooks::PANIC_PATH {
        let auth = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        panic!("test panic injection {auth}");
    }

    #[cfg(feature = "stage1-probe")]
    if policy.cfg.probe.enabled && eff_path.starts_with(crate::probe::PREFIX) {
        return Ok(crate::probe::handle(&app, &trail, &parts.method, &eff_path, body, pt).await);
    }

    // 6. Route name in the path, mapped by policy to a fixed host.
    let (route_name, rel) = match canon::parse_route_path(&eff_path) {
        Ok(r) => r,
        Err(code) => return Ok(refuse_unread(&app, &trail, code, body, &drain).await),
    };
    let Some(route) = policy.snap.route(route_name) else {
        return Ok(refuse_unread(&app, &trail, Code::RouteUnknown, body, &drain).await);
    };
    trail.route = Some(route.name.clone());
    trail.path = canon::redact_path(&path_only(&rel));

    // 7. More than one Authorization header is refused: the gate cannot say which one is read.
    if parts.headers.get_all(header::AUTHORIZATION).iter().count() > 1 {
        return Ok(refuse_unread(&app, &trail, Code::AuthorizationDuplicate, body, &drain).await);
    }

    // 8. Grant. Everything not granted is 423 no_grant. A hold grant sends the request down the
    // hold path.
    let verdict =
        match policy
            .snap
            .evaluate_verdict(&identity_name, &route.name, parts.method.as_str(), &rel)
        {
            Ok(v) => v,
            Err(_) => return Ok(refuse_unread(&app, &trail, Code::NoGrant, body, &drain).await),
        };
    if verdict == Verdict::Hold {
        return hold_path::run(hold_path::Request {
            app,
            trail,
            parts,
            body,
            pt,
            route,
            generation: policy.generation,
            rel: &rel,
            identity: &identity_name,
            drain,
            token_admitted: pilot,
        })
        .await;
    }

    // 9. Declared length over the cap.
    if declared.is_some_and(|n| n > max_body) {
        return Ok(refuse_unread(&app, &trail, Code::BodyTooLarge, body, &drain).await);
    }

    // 10. Forward. The path goes upstream raw, with the query raw.
    let headers = forward::passthrough_headers(&parts.headers, route, pt);
    let rest = match parts.uri.query() {
        Some(q) => format!("{rel}?{q}"),
        None => rel.clone(),
    };
    let url = forward::upstream_url(route, &rest);
    let has_body =
        parts.headers.contains_key(header::TRANSFER_ENCODING) || declared.is_some_and(|n| n > 0);
    let flags = BodyFlags::default();
    let mut builder = app
        .client
        .request(parts.method.clone(), url)
        .headers(headers);
    if has_body {
        builder = builder.body(forward::guarded_body(
            body,
            max_body,
            Duration::from_secs(pt.body_read_secs),
            flags.clone(),
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(pt.request_deadline_secs);
    let sent = tokio::time::timeout_at(deadline.into(), builder.send()).await;
    let upstream = match sent {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let sent_any = flags.sent_any.load(Ordering::SeqCst);
            if flags.overflow.load(Ordering::SeqCst) {
                return if sent_any {
                    Err(abort(&app, &trail, "body_failed_after_send"))
                } else {
                    Ok(refuse(&app, &trail, Code::BodyTooLarge))
                };
            }
            if flags.stalled.load(Ordering::SeqCst) {
                return if sent_any {
                    Err(abort(&app, &trail, "body_failed_after_send"))
                } else {
                    Ok(refuse(&app, &trail, Code::BodyReadTimeout))
                };
            }
            if e.is_connect() {
                return Ok(refuse(&app, &trail, Code::ConnectFailed));
            }
            return Err(abort(&app, &trail, "upstream_reset"));
        }
        Err(_) => return Err(abort(&app, &trail, "upstream_reset")),
    };

    // 11. The response streams back. The allow line is written when the body ends.
    let status = upstream.status();
    let out_headers = forward::response_headers(upstream.headers());
    let audit = StreamAudit {
        app: Arc::clone(&app),
        trail,
        status: status.as_u16(),
        reset: false,
        end: End::Allow,
    };
    let idle = Duration::from_secs(pt.upstream_idle_secs);
    let stream = audited(upstream.bytes_stream(), audit, deadline, idle);
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = out_headers;
    Ok(response)
}
