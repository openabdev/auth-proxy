//! The session plane over the Unix socket: five calls, HTTP/1.1 and JSON, the
//! statuses of the design doc table. The socket is the only way in, so there
//! is no Host or path-prefix handling here.
//!
//! Every call is audited with the session id, generation, an 8-hex hash prefix
//! and the result. The surrogate never reaches this process (only its hash),
//! and the authority token is never logged or echoed except in the one
//! `hello` answer.

use crate::agent::fixed_json;
use crate::app::App;
use crate::audit::{hash8, PlaneEvent};
use ap_broker::{PlaneError, RegisterReq, SessionRef};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use futures_util::FutureExt;
use http::{header, HeaderMap, Method};
use serde::{Deserialize, Serialize};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

const MAX_BODY: usize = 1024 * 1024;

pub async fn handler(State(app): State<Arc<App>>, req: Request) -> Response {
    match AssertUnwindSafe(handle(app, req)).catch_unwind().await {
        Ok(r) => r,
        Err(_) => fixed_json(
            500,
            r#"{"error":"internal_error","message":"auth-proxy: internal error"}"#,
        ),
    }
}

fn json<T: Serialize>(status: u16, v: &T) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(v).unwrap_or_default()))
        .unwrap()
}

fn error(status: u16, code: &str, message: &str) -> Response {
    json(
        status,
        &serde_json::json!({"error": code, "message": message}),
    )
}

fn plane_error(e: &PlaneError) -> Response {
    error(e.status(), e.code(), &e.to_string())
}

fn no_content() -> Response {
    Response::builder().status(204).body(Body::empty()).unwrap()
}

/// `Authorization: Bearer <token>`, exactly one header.
fn bearer(h: &HeaderMap) -> Option<String> {
    let mut it = h.get_all(header::AUTHORIZATION).iter();
    let v = it.next()?;
    if it.next().is_some() {
        return None;
    }
    let s = v.to_str().ok()?;
    let (scheme, tok) = s.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !tok.is_empty()).then(|| tok.to_string())
}

enum Call {
    Hello,
    Register,
    Renew,
    Revoke(String, u64),
    Resync,
}

fn session_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

enum Routed {
    Found(Call),
    BadPath(&'static str),
    WrongMethod,
    Unknown,
}

fn route(method: &Method, path: &str) -> Routed {
    use Routed::*;
    match path {
        "/v1/hello" => match *method {
            Method::POST => Found(Call::Hello),
            _ => WrongMethod,
        },
        "/v1/renew" => match *method {
            Method::POST => Found(Call::Renew),
            _ => WrongMethod,
        },
        "/v1/sessions" => match *method {
            Method::POST => Found(Call::Register),
            Method::PUT => Found(Call::Resync),
            _ => WrongMethod,
        },
        _ => match path.strip_prefix("/v1/sessions/") {
            Some(rest) => {
                if *method != Method::DELETE {
                    return WrongMethod;
                }
                let mut it = rest.split('/');
                match (it.next(), it.next(), it.next()) {
                    (Some(s), Some(g), None) if session_ok(s) => match g.parse::<u64>() {
                        Ok(g) => Found(Call::Revoke(s.to_string(), g)),
                        Err(_) => BadPath("generation must be an unsigned integer"),
                    },
                    (Some(_), Some(_), None) => {
                        BadPath("session must be 1-128 characters of [A-Za-z0-9._:-]")
                    }
                    _ => Unknown,
                }
            }
            None => Unknown,
        },
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewBody {
    sessions: Vec<SessionRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResyncBody {
    sessions: Vec<RegisterReq>,
}

fn too_big() -> Response {
    error(413, "body_too_large", "request body over 1 MiB")
}

/// `Err(())` means over the 1 MiB cap (or unreadable): the caller answers 413.
async fn read_body(headers: &HeaderMap, body: Body) -> Result<Vec<u8>, ()> {
    let declared: Option<usize> = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    if declared.is_some_and(|n| n > MAX_BODY) {
        crate::agent::drain(body, 4 * MAX_BODY as u64).await;
        return Err(());
    }
    axum::body::to_bytes(body, MAX_BODY)
        .await
        .map(|b| b.to_vec())
        .map_err(|_| ())
}

fn bad_json() -> PlaneError {
    PlaneError::Invalid("request body is not the expected JSON".into())
}

async fn handle(app: Arc<App>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let call = match route(&parts.method, parts.uri.path()) {
        Routed::Found(c) => c,
        Routed::BadPath(m) => return error(400, "invalid_request", m),
        Routed::WrongMethod => return error(405, "method_not_allowed", "method not allowed"),
        Routed::Unknown => return error(404, "not_found", "unknown session-plane call"),
    };
    let token = bearer(&parts.headers);
    let reply = |ev: PlaneEvent<'_>, r: Response| {
        app.audit.plane(&PlaneEvent {
            status: r.status().as_u16(),
            ..ev
        });
        r
    };
    let fail = |ev: PlaneEvent<'_>, e: &PlaneError| {
        reply(
            PlaneEvent {
                result: e.code(),
                ..ev
            },
            plane_error(e),
        )
    };

    if let Call::Hello = call {
        let ev = PlaneEvent {
            call: "hello",
            result: "ok",
            ..Default::default()
        };
        // The body is `{}`; it is read (and bounded) but not interpreted.
        if read_body(&parts.headers, body).await.is_err() {
            return reply(
                PlaneEvent {
                    result: "body_too_large",
                    ..ev
                },
                too_big(),
            );
        }
        return match app.plane.hello() {
            Ok(h) => reply(ev, json(201, &h)),
            Err(e) => fail(ev, &e),
        };
    }

    // Every other call carries the authority token.
    let label = match &call {
        Call::Register => "register",
        Call::Renew => "renew",
        Call::Revoke(..) => "revoke",
        Call::Resync => "resync",
        Call::Hello => unreachable!(),
    };
    let ev0 = PlaneEvent {
        call: label,
        result: "ok",
        ..Default::default()
    };
    let Some(token) = token else {
        return fail(ev0, &PlaneError::Unauthorized);
    };
    let bytes = match read_body(&parts.headers, body).await {
        Ok(b) => b,
        Err(()) => {
            return reply(
                PlaneEvent {
                    result: "body_too_large",
                    ..ev0
                },
                too_big(),
            )
        }
    };

    match call {
        Call::Hello => unreachable!(),
        Call::Revoke(session, generation) => {
            let ev = PlaneEvent {
                session: Some(&session),
                generation: Some(generation),
                ..ev0
            };
            match app.plane.revoke(&token, &session, generation) {
                Ok(()) => reply(ev, no_content()),
                Err(e) => fail(ev, &e),
            }
        }
        Call::Renew => {
            let Ok(b) = serde_json::from_slice::<RenewBody>(&bytes) else {
                return fail(ev0, &bad_json());
            };
            let ev = PlaneEvent {
                count: Some(b.sessions.len()),
                ..ev0
            };
            match app.plane.renew(&token, &b.sessions) {
                Ok(ok) => reply(ev, json(200, &ok)),
                Err(e) => fail(ev, &e),
            }
        }
        Call::Register => {
            let Ok(req) = serde_json::from_slice::<RegisterReq>(&bytes) else {
                return fail(ev0, &bad_json());
            };
            let h8 = hash8(&req.surrogate_sha256);
            let ev = PlaneEvent {
                session: Some(&req.session),
                generation: Some(req.generation),
                hash8: h8.as_deref(),
                ..ev0
            };
            let policy = match app.policy.current() {
                Ok(p) => p,
                Err(_) => {
                    return reply(
                        PlaneEvent {
                            result: "policy_unavailable",
                            ..ev
                        },
                        policy_unavailable(),
                    )
                }
            };
            match app.plane.register(&token, &policy, &req) {
                Ok(ok) => reply(ev, json(201, &ok)),
                Err(e) => fail(ev, &e),
            }
        }
        Call::Resync => {
            let Ok(b) = serde_json::from_slice::<ResyncBody>(&bytes) else {
                return fail(ev0, &bad_json());
            };
            let ev = PlaneEvent {
                count: Some(b.sessions.len()),
                ..ev0
            };
            let policy = match app.policy.current() {
                Ok(p) => p,
                Err(_) => {
                    return reply(
                        PlaneEvent {
                            result: "policy_unavailable",
                            ..ev
                        },
                        policy_unavailable(),
                    )
                }
            };
            match app.plane.resync(&token, &policy, &b.sessions) {
                Ok(ok) => reply(ev, json(200, &ok)),
                Err(e) => fail(ev, &e),
            }
        }
    }
}

fn policy_unavailable() -> Response {
    error(503, "policy_unavailable", "policy unavailable; refusing")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn routing_table() {
        let k = |m: &Method, p: &str| match route(m, p) {
            Routed::Found(Call::Hello) => "hello".to_string(),
            Routed::Found(Call::Register) => "register".into(),
            Routed::Found(Call::Renew) => "renew".into(),
            Routed::Found(Call::Resync) => "resync".into(),
            Routed::Found(Call::Revoke(s, g)) => format!("revoke {s} {g}"),
            Routed::BadPath(_) => "bad".into(),
            Routed::WrongMethod => "405".into(),
            Routed::Unknown => "404".into(),
        };
        assert_eq!(k(&Method::POST, "/v1/hello"), "hello");
        assert_eq!(k(&Method::GET, "/v1/hello"), "405");
        assert_eq!(k(&Method::POST, "/v1/sessions"), "register");
        assert_eq!(k(&Method::PUT, "/v1/sessions"), "resync");
        assert_eq!(k(&Method::DELETE, "/v1/sessions"), "405");
        assert_eq!(k(&Method::POST, "/v1/renew"), "renew");
        assert_eq!(
            k(&Method::DELETE, "/v1/sessions/a.b:c-d/7"),
            "revoke a.b:c-d 7"
        );
        assert_eq!(k(&Method::DELETE, "/v1/sessions/a/x"), "bad");
        assert_eq!(k(&Method::DELETE, "/v1/sessions/a%2f/1"), "bad");
        assert_eq!(k(&Method::DELETE, "/v1/sessions/a"), "404");
        assert_eq!(k(&Method::DELETE, "/v1/sessions/a/1/2"), "404");
        assert_eq!(k(&Method::POST, "/v1/sessions/a/1"), "405");
        assert_eq!(k(&Method::POST, "/v2/hello"), "404");
        assert_eq!(k(&Method::POST, "/"), "404");
    }

    #[test]
    fn bearer_parsing() {
        let mut h = HeaderMap::new();
        assert_eq!(bearer(&h), None);
        h.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(bearer(&h).as_deref(), Some("abc"));
        h.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(bearer(&h), None, "two headers");
        let mut h = HeaderMap::new();
        h.append(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer(&h), None);
        let mut h = HeaderMap::new();
        h.append(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert_eq!(bearer(&h), None);
    }
}
