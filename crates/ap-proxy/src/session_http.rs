//! Session plane: JSON over HTTP/1.1 on the Unix socket (design Q1-B, session-plane table).
//!
//! Every call except `hello` carries `Authorization: Bearer <authority-token>`. The calling
//! identity is found from the token: each identity's hash file in the token directory is compared
//! in constant time. The registry checks the token again on every call.
//!
//! Each call writes exactly one audit line, including calls refused before the handler's own
//! logic (missing or wrong bearer, bad body, bad generation). The line carries the session id,
//! generation, a 12-character prefix of the surrogate's sha256 and the result. For renew and
//! resync, which name several sessions in one body, the line carries `sessions` (the count of
//! sessions in the request) in place of a session id. The token and the surrogate never appear in
//! it.

use std::sync::{Arc, MutexGuard};
use std::time::Duration;

use ap_broker::clock::{Clock, SystemClock};
use ap_broker::proof::{verify, NONCE_TTL_SECS};
use ap_broker::registry::{sha256_hex, HelloErr, Registry, SessErr};
use ap_broker::session::{read_token_hash, token_file};
use ap_core::session_wire::{
    is_nonce, Entry, HelloChallenge, HelloReq, HelloResp, RegisterResp, RenewReq, ResyncReq,
    SessionRef, BODY_CAP,
};
use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tokio::net::UnixListener;

use crate::pipeline::App;

#[cfg(test)]
mod tests;

/// Routes of the session plane.
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/v1/hello", post(hello))
        .route("/v1/hello/challenge", get(hello_challenge))
        .route("/v1/sessions", post(register).put(resync))
        .route("/v1/renew", post(renew))
        .route("/v1/sessions/{session}/{generation}", delete(revoke))
        .with_state(app)
}

/// Serve `router` on a Unix listener. Each connection runs HTTP/1.1 on its own task.
pub async fn serve_unix(listener: UnixListener, router: Router) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let service = TowerToHyperService::new(router.clone());
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

pub(crate) fn json_reply<T: Serialize>(status: u16, value: &T) -> Response {
    let body = serde_json::to_vec(value).unwrap_or_default();
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

pub(crate) fn error_reply(status: u16, code: &str) -> Response {
    json_reply(status, &json!({ "error": code }))
}

/// The one `Authorization: Bearer` value, or `None`.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok()?.strip_prefix("Bearer ")
}

/// The identity whose stored token hash matches `token`, if any.
fn identify(app: &App, token: &str) -> Option<String> {
    let presented = sha256_hex(token);
    let mut found = None;
    for name in &app.identity_names {
        if let Ok(stored) = read_token_hash(&token_file(&app.token_dir, name)) {
            let same: bool = presented.as_bytes().ct_eq(stored.trim().as_bytes()).into();
            if same && found.is_none() {
                found = Some(name.clone());
            }
        }
    }
    found
}

/// A refusal decided before the handler's own logic: HTTP status and error code.
#[derive(Debug, Clone, Copy)]
struct Refusal {
    status: u16,
    code: &'static str,
}

fn refusal(status: u16, code: &'static str) -> Refusal {
    Refusal { status, code }
}

/// The calling identity and its token, or a 401 refusal.
fn authenticate(app: &App, headers: &HeaderMap) -> Result<(String, String), Refusal> {
    let token = bearer_token(headers).ok_or_else(|| refusal(401, "unauthorized"))?;
    let identity = identify(app, token).ok_or_else(|| refusal(401, "unauthorized"))?;
    Ok((identity, token.to_string()))
}

async fn read_json<T: DeserializeOwned>(body: Body) -> Result<T, Refusal> {
    let bytes = to_bytes(body, BODY_CAP)
        .await
        .map_err(|_| refusal(413, "body_too_large"))?;
    serde_json::from_slice(&bytes).map_err(|_| refusal(400, "invalid_body"))
}

/// Run `f` with the registry and the current time. `None` when the registry lock is poisoned.
pub(crate) fn with_registry<T>(
    app: &App,
    f: impl FnOnce(&mut Registry<SystemClock>, u64) -> T,
) -> Option<T> {
    let mut reg: MutexGuard<'_, Registry<SystemClock>> = app.registry.lock().ok()?;
    let now = reg.now();
    Some(f(&mut reg, now))
}

/// Status, error code and body for a failed registry call.
fn sess_error(e: &SessErr) -> (u16, Value) {
    match e {
        SessErr::Unauthorized => (401, json!({ "error": "unauthorized" })),
        SessErr::Invalid(w) => (400, json!({ "error": "invalid_field", "field": w.field })),
        SessErr::CredentialNotGranted => (403, json!({ "error": "credential_not_granted" })),
        SessErr::Conflict => (409, json!({ "error": "conflict" })),
        SessErr::TooMany => (429, json!({ "error": "too_many_sessions" })),
        SessErr::AbsoluteExpired => (403, json!({ "error": "session_expired" })),
        SessErr::Unavailable => (503, json!({ "error": "broker_unavailable" })),
    }
}

fn sess_reply(e: &SessErr) -> (u16, Response) {
    let (status, body) = sess_error(e);
    (status, json_reply(status, &body))
}

/// One session-plane audit line.
struct Event<'a> {
    op: &'static str,
    identity: &'a str,
    session: Option<&'a str>,
    generation: Option<u64>,
    /// Count of sessions named in a renew or resync body.
    sessions: Option<usize>,
    surrogate_sha256: Option<&'a str>,
    status: u16,
    result: &'a str,
}

impl<'a> Event<'a> {
    /// An event for `op` with no session fields. The caller sets `status` and `result`.
    fn bare(op: &'static str, identity: &'a str) -> Self {
        Event {
            op,
            identity,
            session: None,
            generation: None,
            sessions: None,
            surrogate_sha256: None,
            status: 0,
            result: "",
        }
    }
}

fn audit(app: &App, ev: Event<'_>) {
    let prefix = ev
        .surrogate_sha256
        .map(|s| s.chars().take(12).collect::<String>());
    let line = json!({
        "event": "session",
        "op": ev.op,
        "identity": ev.identity,
        "session": ev.session,
        "generation": ev.generation,
        "sessions": ev.sessions,
        "surrogate_sha256_prefix": prefix,
        "status": ev.status,
        "result": ev.result,
    });
    app.audit.write_line(&line.to_string());
}

/// Audit a refusal made before the handler's logic, and build its response. The refusal supplies
/// the status and result; the event supplies the rest.
fn refused(app: &App, mut ev: Event<'_>, r: Refusal) -> Response {
    ev.status = r.status;
    ev.result = r.code;
    audit(app, ev);
    error_reply(r.status, r.code)
}

/// `GET /v1/hello/challenge`: one nonce for one hello. Writes one audit line with no nonce value.
async fn hello_challenge(State(app): State<Arc<App>>) -> Response {
    let now = SystemClock.now();
    let nonce = match app.nonces.lock() {
        Ok(mut table) => table.issue(now),
        Err(_) => {
            audit(
                &app,
                Event {
                    status: 503,
                    result: "unavailable",
                    ..Event::bare("hello_challenge", "")
                },
            );
            return error_reply(503, "unavailable");
        }
    };
    audit(
        &app,
        Event {
            status: 200,
            result: "ok",
            ..Event::bare("hello_challenge", "")
        },
    );
    json_reply(
        200,
        &HelloChallenge {
            nonce,
            ttl_secs: NONCE_TTL_SECS,
        },
    )
}

/// `POST /v1/hello`. The checks run in the order of `docs/design/runtime-split.md`, "Verification
/// order". The first failure refuses and nothing after it runs.
async fn hello(State(app): State<Arc<App>>, body: Body) -> Response {
    let req: HelloReq = match read_json(body).await {
        Ok(r) => r,
        Err(r) => return refused(&app, Event::bare("hello", ""), r),
    };
    let identity = req.identity.clone();
    let ev = || Event::bare("hello", &identity);
    if req.nonce.as_deref().is_some_and(|n| !is_nonce(n)) {
        return refused(&app, ev(), refusal(400, "invalid_body"));
    }
    if !app.identity_names.contains(&identity) {
        return refused(&app, ev(), refusal(400, "identity_unknown"));
    }
    let Some(key) = app.runtime_keys.get(&identity) else {
        return refused(&app, ev(), refusal(403, "runtime_key_missing"));
    };
    let Some(proof) = req.proof.as_deref() else {
        return refused(&app, ev(), refusal(401, "proof_missing"));
    };
    let Some(nonce) = req.nonce.as_deref() else {
        return refused(&app, ev(), refusal(401, "nonce_invalid"));
    };
    // `consume` removes the nonce whether or not it is valid, so a nonce works once.
    let now = SystemClock.now();
    let spent = match app.nonces.lock() {
        Ok(mut table) => table.consume(nonce, now),
        Err(_) => return refused(&app, ev(), refusal(503, "unavailable")),
    };
    if !spent {
        return refused(&app, ev(), refusal(401, "nonce_invalid"));
    }
    if verify(key, &identity, nonce, proof).is_err() {
        return refused(&app, ev(), refusal(401, "proof_invalid"));
    }

    let outcome = with_registry(&app, |reg, now| reg.hello(&identity, now));
    let (status, reply, result) = match outcome {
        None => (
            503,
            error_reply(503, "unavailable"),
            "unavailable".to_string(),
        ),
        Some(Ok(token)) => {
            let resp = HelloResp {
                authority_token: token,
                lease_secs: app.authority_lease_secs,
            };
            (201, json_reply(201, &resp), "ok".to_string())
        }
        Some(Err(HelloErr::AuthorityActive { retry_after })) => (
            409,
            json_reply(
                409,
                &json!({ "error": "authority_active", "retry_after": retry_after }),
            ),
            "authority_active".to_string(),
        ),
        Some(Err(HelloErr::Unavailable)) => (
            503,
            error_reply(503, "unavailable"),
            "unavailable".to_string(),
        ),
    };
    audit(
        &app,
        Event {
            status,
            result: &result,
            ..ev()
        },
    );
    reply
}

async fn register(State(app): State<Arc<App>>, headers: HeaderMap, body: Body) -> Response {
    let (identity, token) = match authenticate(&app, &headers) {
        Ok(v) => v,
        Err(r) => return refused(&app, Event::bare("register", ""), r),
    };
    let entry: Entry = match read_json(body).await {
        Ok(e) => e,
        Err(r) => return refused(&app, Event::bare("register", &identity), r),
    };
    let session = entry.session.clone();
    let generation = entry.generation;
    let surrogate = entry.surrogate_sha256.clone();
    let outcome = with_registry(&app, |reg, now| reg.register(&identity, &token, entry, now));
    let (status, reply, result) = match outcome {
        None => (
            503,
            error_reply(503, "unavailable"),
            "unavailable".to_string(),
        ),
        Some(Ok(lease_secs)) => (
            201,
            json_reply(201, &RegisterResp { lease_secs }),
            "ok".to_string(),
        ),
        Some(Err(e)) => {
            let (status, reply) = sess_reply(&e);
            let result = sess_error(&e).1["error"]
                .as_str()
                .unwrap_or("error")
                .to_string();
            (status, reply, result)
        }
    };
    audit(
        &app,
        Event {
            session: Some(&session),
            generation: Some(generation),
            surrogate_sha256: Some(&surrogate),
            status,
            result: &result,
            ..Event::bare("register", &identity)
        },
    );
    reply
}

async fn renew(State(app): State<Arc<App>>, headers: HeaderMap, body: Body) -> Response {
    let (identity, token) = match authenticate(&app, &headers) {
        Ok(v) => v,
        Err(r) => return refused(&app, Event::bare("renew", ""), r),
    };
    let req: RenewReq = match read_json(body).await {
        Ok(r) => r,
        Err(r) => return refused(&app, Event::bare("renew", &identity), r),
    };
    let refs: Vec<SessionRef> = req.sessions;
    let count = refs.len();
    let outcome = with_registry(&app, |reg, now| reg.renew(&identity, &token, &refs, now));
    let (status, reply, result) = match outcome {
        None => (
            503,
            error_reply(503, "unavailable"),
            "unavailable".to_string(),
        ),
        Some(Ok(resp)) => (200, json_reply(200, &resp), "ok".to_string()),
        Some(Err(e)) => {
            let (status, reply) = sess_reply(&e);
            (status, reply, "error".to_string())
        }
    };
    audit(
        &app,
        Event {
            sessions: Some(count),
            status,
            result: &result,
            ..Event::bare("renew", &identity)
        },
    );
    reply
}

async fn resync(State(app): State<Arc<App>>, headers: HeaderMap, body: Body) -> Response {
    let (identity, token) = match authenticate(&app, &headers) {
        Ok(v) => v,
        Err(r) => return refused(&app, Event::bare("resync", ""), r),
    };
    let req: ResyncReq = match read_json(body).await {
        Ok(r) => r,
        Err(r) => return refused(&app, Event::bare("resync", &identity), r),
    };
    let list = req.sessions;
    let count = list.len();
    let outcome = with_registry(&app, |reg, now| reg.resync(&identity, &token, list, now));
    let (status, reply, result) = match outcome {
        None => (
            503,
            error_reply(503, "unavailable"),
            "unavailable".to_string(),
        ),
        Some(Ok(resp)) => (200, json_reply(200, &resp), "ok".to_string()),
        Some(Err(e)) => {
            let (status, reply) = sess_reply(&e);
            (status, reply, "error".to_string())
        }
    };
    audit(
        &app,
        Event {
            sessions: Some(count),
            status,
            result: &result,
            ..Event::bare("resync", &identity)
        },
    );
    reply
}

async fn revoke(
    State(app): State<Arc<App>>,
    Path((session, generation)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let (identity, token) = match authenticate(&app, &headers) {
        Ok(v) => v,
        Err(r) => {
            return refused(
                &app,
                Event {
                    session: Some(&session),
                    ..Event::bare("revoke", "")
                },
                r,
            )
        }
    };
    let Ok(generation) = generation.parse::<u64>() else {
        return refused(
            &app,
            Event {
                session: Some(&session),
                ..Event::bare("revoke", &identity)
            },
            refusal(400, "invalid_field"),
        );
    };
    let session_ref = session.clone();
    let outcome = with_registry(&app, |reg, now| {
        reg.revoke(&identity, &token, &session_ref, generation, now)
    });
    let (status, reply, result) = match outcome {
        None => (
            503,
            error_reply(503, "unavailable"),
            "unavailable".to_string(),
        ),
        Some(Ok(())) => {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = StatusCode::NO_CONTENT;
            (204, r, "ok".to_string())
        }
        Some(Err(e)) => {
            let (status, reply) = sess_reply(&e);
            (status, reply, "error".to_string())
        }
    };
    audit(
        &app,
        Event {
            session: Some(&session),
            generation: Some(generation),
            status,
            result: &result,
            ..Event::bare("revoke", &identity)
        },
    );
    reply
}
