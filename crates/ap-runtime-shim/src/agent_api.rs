//! The agent-runtime API: the only operations the agent may call, served on the agent socket
//! (`/run/auth-proxy-agent/runtime.sock`). Every path and method not listed here is refused before
//! anything reaches the proxy. See `docs/design/runtime-split.md`, "Agent-runtime socket operations".
//!
//! Operations: `POST /v1/session` (register), `DELETE /v1/session/{session}/{generation}` (revoke),
//! `GET /v1/status`. The agent cannot name an identity, so every session is the runtime's own.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

use ap_client::authority::{Authority, AuthorityError};
use ap_core::session_wire::{validate_session, BODY_CAP};
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, StatusCode};
use axum::response::Response;
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};

/// The runtime's state: its identity, its authority, and the sessions it registered. Only a
/// session the runtime registered is ever sent to the proxy for revoke.
pub struct Shim {
    identity: String,
    authority: Authority,
    registered: Mutex<BTreeSet<(String, u64)>>,
}

impl Shim {
    pub fn new(identity: String, authority: Authority) -> Arc<Shim> {
        Arc::new(Shim {
            identity,
            authority,
            registered: Mutex::new(BTreeSet::new()),
        })
    }

    fn sessions(&self) -> MutexGuard<'_, BTreeSet<(String, u64)>> {
        // A poisoned set still holds the last complete state, so keep serving from it.
        self.registered.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// `POST /v1/session` body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    session: String,
    generation: u64,
    credentials: Vec<String>,
}

/// The agent-facing router. It has one fallback, which dispatches on method and path, so every
/// other request gets the same JSON refusal.
pub fn router(shim: Arc<Shim>) -> Router {
    Router::new().fallback(dispatch).with_state(shim)
}

async fn dispatch(State(shim): State<Arc<Shim>>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let parts: Vec<&str> = path.split('/').collect();
    match parts.as_slice() {
        ["", "v1", "session"] => {
            if method == Method::POST {
                register(&shim, req).await
            } else {
                error(405, "method_not_allowed")
            }
        }
        ["", "v1", "session", session, generation] => {
            if method == Method::DELETE {
                revoke(&shim, session, generation).await
            } else {
                error(405, "method_not_allowed")
            }
        }
        ["", "v1", "status"] => {
            if method == Method::GET {
                status(&shim)
            } else {
                error(405, "method_not_allowed")
            }
        }
        _ => error(404, "unknown_operation"),
    }
}

async fn register(shim: &Shim, req: Request) -> Response {
    let bytes = match to_bytes(req.into_body(), BODY_CAP).await {
        Ok(b) => b,
        Err(_) => return error(413, "body_too_large"),
    };
    let body: RegisterBody = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(_) => return error(400, "invalid_body"),
    };
    let RegisterBody {
        session,
        generation,
        credentials,
    } = body;
    match shim
        .authority
        .register(&session, generation, credentials)
        .await
    {
        Ok(surrogate) => {
            shim.sessions().insert((session, generation));
            reply(201, &json!({ "surrogate": surrogate.expose() }))
        }
        Err(e) => authority_error(e),
    }
}

async fn revoke(shim: &Shim, session: &str, generation: &str) -> Response {
    if validate_session(session).is_err() {
        return invalid_field("session");
    }
    let Ok(generation) = generation.parse::<u64>() else {
        return invalid_field("generation");
    };
    let key = (session.to_string(), generation);
    // A key the runtime did not register is not the agent's to end. Answer 204 without a proxy call.
    if !shim.sessions().contains(&key) {
        return empty(204);
    }
    match shim.authority.end(session, generation).await {
        Ok(()) => {
            shim.sessions().remove(&key);
            empty(204)
        }
        Err(e) => authority_error(e),
    }
}

fn status(shim: &Shim) -> Response {
    let sessions: Vec<Value> = shim
        .sessions()
        .iter()
        .map(|(s, g)| json!({ "session": s, "generation": g }))
        .collect();
    reply(
        200,
        &json!({ "identity": shim.identity, "authority": "live", "sessions": sessions }),
    )
}

/// Map a failed authority call to the agent's reply. The proxy's status and code pass through.
fn authority_error(e: AuthorityError) -> Response {
    match e {
        AuthorityError::Invalid(w) => invalid_field(w.field),
        AuthorityError::RevokePending => error(409, "revoke_pending"),
        AuthorityError::Refused { status, code } => {
            let code = if code.is_empty() {
                "broker_unavailable".to_string()
            } else {
                code
            };
            reply(status, &json!({ "error": code }))
        }
        AuthorityError::Transport(_) | AuthorityError::Decode(_) => {
            error(503, "broker_unavailable")
        }
    }
}

fn invalid_field(field: &str) -> Response {
    reply(400, &json!({ "error": "invalid_field", "field": field }))
}

fn error(status: u16, code: &str) -> Response {
    reply(status, &json!({ "error": code }))
}

fn reply(status: u16, body: &Value) -> Response {
    let mut r = Response::new(Body::from(body.to_string()));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    r
}

fn empty(status: u16) -> Response {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r
}
