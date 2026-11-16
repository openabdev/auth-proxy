//! The admin plane: a Unix socket in a directory only the proxy container
//! mounts. Two calls, neither of which returns a credential or a token:
//! `POST /admin/revoke-all` and `GET /admin/status`.

use crate::agent::fixed_json;
use crate::app::App;
use crate::audit::PlaneEvent;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use http::{header, Method};
use std::sync::Arc;

fn json(status: u16, v: serde_json::Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(v.to_string()))
        .unwrap()
}

pub async fn handler(State(app): State<Arc<App>>, req: Request) -> Response {
    let (m, p) = (req.method().clone(), req.uri().path().to_string());
    match (m, p.as_str()) {
        (Method::POST, "/admin/revoke-all") => {
            let n = app.plane.revoke_all();
            app.audit.plane(&PlaneEvent {
                call: "revoke-all",
                count: Some(n),
                status: 200,
                result: "ok",
                ..Default::default()
            });
            json(200, serde_json::json!({ "revoked": n }))
        }
        (Method::GET, "/admin/status") => {
            let (policy, identity) = match app.policy.current() {
                Ok(p) => ("ok", Some(p.identity().to_string())),
                Err(_) => ("unavailable", None),
            };
            app.audit.plane(&PlaneEvent {
                call: "status",
                status: 200,
                result: "ok",
                ..Default::default()
            });
            json(
                200,
                serde_json::json!({
                    "authority_live": app.plane.authority_live(),
                    "sessions": app.plane.session_count(),
                    "policy": policy,
                    "identity": identity,
                }),
            )
        }
        (_, "/admin/revoke-all") | (_, "/admin/status") => fixed_json(
            405,
            r#"{"error":"method_not_allowed","message":"method not allowed"}"#,
        ),
        _ => fixed_json(
            404,
            r#"{"error":"not_found","message":"unknown admin call"}"#,
        ),
    }
}
