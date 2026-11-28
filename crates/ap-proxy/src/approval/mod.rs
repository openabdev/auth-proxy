//! The approval plane (design 3.6): a separate listener, a separate router and a separate
//! credential. The public router mounts none of these routes, and nothing here accepts a caller
//! key.
//!
//! API, client-agnostic:
//!
//! - `GET /pending` lists the pending entries.
//! - `GET /pending/<id>` shows one entry (HTML, or JSON with `Accept: application/json`).
//! - `POST /pending/<id>/approve` and `.../deny` carry the page's CSRF token in a form or JSON
//!   `csrf` field and answer `{"result": "..."}`.
//!
//! Every response, errors included, goes through [`harden`]. A failed authentication waits a
//! fixed 250 ms before the 401.

pub mod auth;
pub mod csrf;
pub mod page;
pub mod telegram;

use std::sync::Arc;
use std::time::Duration;

use ap_core::config::Approval;
use axum::body::Body;
use futures_util::StreamExt;
use http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use serde_json::{json, Value};

use crate::hold::{ApproveResult, DenyResult, State, Table};

/// Most bytes a POST body may carry.
pub const BODY_LIMIT: usize = 1024;
/// How long a POST body may take to arrive.
const BODY_READ: Duration = Duration::from_secs(10);
/// Wait before a 401, so a password guess costs time.
pub const FAIL_DELAY: Duration = Duration::from_millis(250);

/// The state of the approval listener.
pub struct ApprovalApp {
    table: Arc<Table>,
    /// The policy in force now, read at each approve (`None`: no valid policy, which refuses).
    policy: PolicySource,
    creds: auth::Credentials,
    csrf: csrf::Csrf,
    realm: String,
    fail_delay: Duration,
    /// Serve `GET /view/<token>` without Basic auth. Set only when the Telegram buttons are on.
    view_links: bool,
}

impl std::fmt::Debug for ApprovalApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalApp").finish_non_exhaustive()
    }
}

/// Where the approval plane reads the policy that an approve is checked against.
pub type PolicySource = Arc<dyn Fn() -> Option<Arc<ap_core::policy::Snapshot>> + Send + Sync>;

impl ApprovalApp {
    pub fn new(table: Arc<Table>, cfg: &Approval, policy: PolicySource) -> Arc<ApprovalApp> {
        Self::build(table, cfg, FAIL_DELAY, policy, false)
    }

    /// Like [`ApprovalApp::new`], and with `view_links` also serves the no-login one-time view
    /// route (`/view/<token>`). The route is tailnet-only with the rest of this listener.
    pub fn new_with_view_links(
        table: Arc<Table>,
        cfg: &Approval,
        policy: PolicySource,
        view_links: bool,
    ) -> Arc<ApprovalApp> {
        Self::build(table, cfg, FAIL_DELAY, policy, view_links)
    }

    fn build(
        table: Arc<Table>,
        cfg: &Approval,
        fail_delay: Duration,
        policy: PolicySource,
        view_links: bool,
    ) -> Arc<ApprovalApp> {
        Arc::new(ApprovalApp {
            table,
            policy,
            creds: auth::Credentials::new(cfg),
            csrf: csrf::Csrf::new(),
            realm: cfg.realm.clone(),
            fail_delay,
            view_links,
        })
    }

    /// The channel labels of the policy in force now, read at each page render so a reload
    /// shows at once. No valid policy means no labels (the id alone is shown).
    fn labels(&self) -> page::Labels {
        (self.policy)()
            .map(|s| s.channel_labels().clone())
            .unwrap_or_default()
    }

    fn new_token(&self, id: &str) -> String {
        let table = &self.table;
        self.csrf.issue(id, table.limits().hold, |e| {
            table.state(e) == Some(State::Pending)
        })
    }
}

/// Serve one request. Never fails: every outcome is a response.
pub async fn handle(app: Arc<ApprovalApp>, req: Request<Body>) -> Response<Body> {
    harden(route(&app, req).await)
}

/// Add the six response headers of design 3.6 to `resp`, whatever its status.
pub fn harden(mut resp: Response<Body>) -> Response<Body> {
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(page::csp()).expect("the policy is printable ASCII"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

fn wants_json(headers: &HeaderMap) -> bool {
    let accepts = headers
        .get_all(header::ACCEPT)
        .iter()
        .any(|v| has_json(v.as_bytes()));
    accepts || is_json_body(headers)
}

fn is_json_body(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
}

fn has_json(v: &[u8]) -> bool {
    String::from_utf8_lossy(v)
        .to_ascii_lowercase()
        .contains("application/json")
}

fn respond(status: StatusCode, content_type: &'static str, body: String) -> Response<Body> {
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    r
}

fn json_response(status: StatusCode, v: &Value) -> Response<Body> {
    respond(status, "application/json", v.to_string())
}

fn html_response(status: StatusCode, html: String) -> Response<Body> {
    respond(status, "text/html; charset=utf-8", html)
}

/// A refusal or result in the client's format: `{"result": ...}` or a small page.
fn result(
    status: StatusCode,
    json_wanted: bool,
    result: &str,
    newest: Option<&str>,
) -> Response<Body> {
    if json_wanted {
        let mut v = json!({ "result": result });
        if let Some(n) = newest {
            v["newest"] = json!(n);
        }
        json_response(status, &v)
    } else {
        html_response(status, page::message(result, result, newest))
    }
}

fn unauthorized(app: &ApprovalApp, json_wanted: bool) -> Response<Body> {
    let mut r = result(StatusCode::UNAUTHORIZED, json_wanted, "unauthorized", None);
    // The realm was validated at load: printable ASCII without a quote or a backslash.
    let value = format!("Basic realm=\"{}\", charset=\"UTF-8\"", app.realm);
    if let Ok(v) = HeaderValue::from_str(&value) {
        r.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    r
}

fn not_allowed(allow: &'static str, json_wanted: bool) -> Response<Body> {
    let mut r = result(
        StatusCode::METHOD_NOT_ALLOWED,
        json_wanted,
        "method_not_allowed",
        None,
    );
    r.headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allow));
    r
}

/// An entry id as the table issues it: 32 lowercase hex characters.
fn valid_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

async fn route(app: &ApprovalApp, req: Request<Body>) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let json_wanted = wants_json(&parts.headers);
    // The one-time view link needs no login. Its token is the only credential, and only a
    // `Pending` hold has one, so the answer is the same 404 for an unknown or ended token.
    if app.view_links && parts.method == Method::GET {
        if let Some(token) = parts.uri.path().strip_prefix("/view/") {
            if !token.contains('/') {
                return view_by_token(app, token);
            }
        }
    }
    let Some(approver) = app.creds.authenticate(&parts.headers) else {
        tokio::time::sleep(app.fail_delay).await;
        return unauthorized(app, json_wanted);
    };
    let segments: Vec<&str> = parts.uri.path().split('/').collect();
    match segments.as_slice() {
        ["", "pending"] => match parts.method {
            Method::GET => list(app, json_wanted),
            _ => not_allowed("GET", json_wanted),
        },
        ["", "pending", id] if valid_id(id) => match parts.method {
            Method::GET => show(app, id, json_wanted),
            _ => not_allowed("GET", json_wanted),
        },
        ["", "pending", id, action @ ("approve" | "deny")] if valid_id(id) => {
            if parts.method != Method::POST {
                return not_allowed("POST", json_wanted);
            }
            decide(
                app,
                &approver,
                id,
                *action == "approve",
                &parts.headers,
                body,
            )
            .await
        }
        _ => result(StatusCode::NOT_FOUND, json_wanted, "not_found", None),
    }
}

fn list(app: &ApprovalApp, json_wanted: bool) -> Response<Body> {
    let items = app.table.list();
    if json_wanted {
        let pending: Vec<Value> = items.iter().map(page::summary_json).collect();
        json_response(StatusCode::OK, &json!({ "pending": pending }))
    } else {
        html_response(StatusCode::OK, page::list(&items))
    }
}

fn show(app: &ApprovalApp, id: &str, json_wanted: bool) -> Response<Body> {
    let Some(view) = app.table.view(id) else {
        return result(StatusCode::NOT_FOUND, json_wanted, "not_found", None);
    };
    let token = (view.state == State::Pending).then(|| app.new_token(id));
    if json_wanted {
        json_response(StatusCode::OK, &page::entry_json(&view, token.as_deref()))
    } else {
        html_response(
            StatusCode::OK,
            page::entry(&view, token.as_deref(), &app.labels()),
        )
    }
}

/// The read-only page for a `Pending` hold, or the generic 404.
fn view_by_token(app: &ApprovalApp, token: &str) -> Response<Body> {
    match app.table.view_by_token(token) {
        Some(view) => html_response(StatusCode::OK, page::view_only(&view, &app.labels())),
        None => result(StatusCode::NOT_FOUND, false, "not_found", None),
    }
}

/// Read a POST body of at most [`BODY_LIMIT`] bytes.
async fn read_body(headers: &HeaderMap, body: Body) -> Result<Vec<u8>, StatusCode> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > BODY_LIMIT as u64) {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let mut stream = body.into_data_stream();
    let read = async {
        let mut buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
            if buf.len() + chunk.len() > BODY_LIMIT {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    };
    tokio::time::timeout(BODY_READ, read)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
}

/// The `csrf` field of a form or JSON body. `Err` is a malformed body; `Ok(None)` is a missing
/// field.
fn csrf_field(headers: &HeaderMap, body: &[u8]) -> Result<Option<String>, ()> {
    if is_json_body(headers) {
        let v: Value = serde_json::from_slice(body).map_err(|_| ())?;
        let obj = v.as_object().ok_or(())?;
        return Ok(obj.get("csrf").and_then(Value::as_str).map(str::to_string));
    }
    let text = std::str::from_utf8(body).map_err(|_| ())?;
    Ok(text
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == "csrf")
        .map(|(_, v)| v.to_string()))
}

/// Approve `id` against the policy in force at the moment of the transition: `policy` is read
/// inside the table's critical section, by the same callback that decides, so no snapshot taken
/// earlier can be used. A grant removed after that read is caught by the start claim.
pub(crate) async fn approve_checked(
    table: &Table,
    policy: &PolicySource,
    id: &str,
    approver: &str,
) -> ApproveResult {
    table
        .approve_if(id, approver, |identity, req| {
            policy().is_some_and(|s| crate::passthrough::still_held(&s, identity, req))
        })
        .await
}

async fn decide(
    app: &ApprovalApp,
    approver: &str,
    id: &str,
    approve: bool,
    headers: &HeaderMap,
    body: Body,
) -> Response<Body> {
    let json_wanted = wants_json(headers);
    let bytes = match read_body(headers, body).await {
        Ok(b) => b,
        Err(status) => {
            let name = if status == StatusCode::PAYLOAD_TOO_LARGE {
                "payload_too_large"
            } else {
                "bad_request"
            };
            return result(status, json_wanted, name, None);
        }
    };
    let Ok(token) = csrf_field(headers, &bytes) else {
        return result(StatusCode::BAD_REQUEST, json_wanted, "bad_request", None);
    };
    let token_ok = token.is_some_and(|t| app.csrf.consume(&t, id));
    if !token_ok {
        return result(StatusCode::FORBIDDEN, json_wanted, "csrf_refused", None);
    }
    let (status, name, newest) = if approve {
        approve_outcome(approve_checked(&app.table, &app.policy, id, approver).await)
    } else {
        deny_outcome(app.table.deny(id, approver))
    };
    result(status, json_wanted, name, newest.as_deref())
}

/// `200` only for success. A request that was decided already or can no longer run is a
/// conflict (409) or gone (410); an approve whose outcome is unknown is 504, since the request
/// may have reached Discord.
fn approve_outcome(r: ApproveResult) -> (StatusCode, &'static str, Option<String>) {
    let name = r.as_str();
    match r {
        ApproveResult::Success => (StatusCode::OK, name, None),
        ApproveResult::Superseded { newest } => (StatusCode::CONFLICT, name, Some(newest)),
        ApproveResult::AlreadyDecided | ApproveResult::ApprovedButAbandoned => {
            (StatusCode::CONFLICT, name, None)
        }
        ApproveResult::Expired
        | ApproveResult::Dropped
        | ApproveResult::PolicyChanged
        | ApproveResult::Gone => (StatusCode::GONE, name, None),
        ApproveResult::ApprovedUnconfirmed => (StatusCode::GATEWAY_TIMEOUT, name, None),
        ApproveResult::AuditUnavailable | ApproveResult::ConnectFailed => {
            (StatusCode::SERVICE_UNAVAILABLE, name, None)
        }
        ApproveResult::NotFound => (StatusCode::NOT_FOUND, name, None),
    }
}

fn deny_outcome(r: DenyResult) -> (StatusCode, &'static str, Option<String>) {
    let name = r.as_str();
    match r {
        DenyResult::Denied => (StatusCode::OK, name, None),
        DenyResult::Superseded { newest } => (StatusCode::CONFLICT, name, Some(newest)),
        DenyResult::AlreadyDecided => (StatusCode::CONFLICT, name, None),
        DenyResult::Expired | DenyResult::Dropped | DenyResult::Gone => {
            (StatusCode::GONE, name, None)
        }
        DenyResult::NotFound => (StatusCode::NOT_FOUND, name, None),
    }
}

#[cfg(test)]
mod telegram_tests;
#[cfg(test)]
mod tests;
