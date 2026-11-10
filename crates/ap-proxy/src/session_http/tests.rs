//! Session-plane and admin tests, driven through the routers with `tower::ServiceExt::oneshot`.

use std::sync::Arc;

use ap_broker::registry::{sha256_hex, Deny};
use axum::body::to_bytes;
use axum::Router;
use serde_json::{json, Value};
use tower::ServiceExt;

use super::*;
use crate::test_support::{start_upstream, surrogate_token, Fixture, IDENTITY, ROUTE};

async fn call(
    router: Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Value,
) -> (u16, Value) {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let req = builder.body(Body::from(body.to_string())).expect("request");
    let resp = router.oneshot(req).await.expect("router");
    let status = resp.status().as_u16();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

#[tokio::test]
async fn session_plane_registers_renews_and_refuses_a_wrong_token() {
    let up = start_upstream().await;
    let f = Fixture::new("sess", &up);
    let app = Arc::clone(&f.app);

    let (status, hello) = call(
        router(Arc::clone(&app)),
        "POST",
        "/v1/hello",
        None,
        json!({ "identity": IDENTITY }),
    )
    .await;
    assert_eq!(status, 201);
    let token = hello["authority_token"]
        .as_str()
        .expect("token")
        .to_string();

    let surrogate = surrogate_token();
    let entry = json!({
        "session": "sess-1",
        "generation": 1,
        "surrogate_sha256": sha256_hex(&surrogate),
        "credentials": ["kiro"],
    });
    let (status, _) = call(
        router(Arc::clone(&app)),
        "POST",
        "/v1/sessions",
        Some(&token),
        entry.clone(),
    )
    .await;
    assert_eq!(status, 201);

    let (status, _) = call(
        router(Arc::clone(&app)),
        "POST",
        "/v1/sessions",
        Some("apt_wrong"),
        entry,
    )
    .await;
    assert_eq!(status, 401);

    let (status, renew) = call(
        router(Arc::clone(&app)),
        "POST",
        "/v1/renew",
        Some(&token),
        json!({ "sessions": [{ "session": "sess-1", "generation": 1 }] }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(renew["unknown"], json!([]));

    // The audit lines name the session and the result, and hold neither secret.
    let text = f.audit_text();
    assert!(text.contains("\"op\":\"register\""), "{text}");
    assert!(!text.contains(&token), "authority token in audit");
    assert!(!text.contains(&surrogate), "surrogate in audit");
}

#[tokio::test]
async fn unauthenticated_call_writes_one_audit_line_and_no_token() {
    let up = start_upstream().await;
    let f = Fixture::new("unauth", &up);
    let (status, _) = call(
        router(Arc::clone(&f.app)),
        "POST",
        "/v1/sessions",
        Some("apt_wrong_0001"),
        json!({
            "session": "sess-1",
            "generation": 1,
            "surrogate_sha256": sha256_hex("aps_unused"),
            "credentials": ["kiro"],
        }),
    )
    .await;
    assert_eq!(status, 401);

    let text = f.audit_text();
    let lines: Vec<&str> = text.lines().filter(|l| l.contains("\"op\":")).collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(lines[0].contains("\"op\":\"register\""), "{text}");
    assert!(lines[0].contains("\"status\":401"), "{text}");
    assert!(lines[0].contains("\"result\":\"unauthorized\""), "{text}");
    assert!(!text.contains("apt_wrong_0001"), "presented token in audit");
}

#[tokio::test]
async fn admin_lists_sessions_and_revoke_all_revokes_them() {
    let up = start_upstream().await;
    let f = Fixture::new("admin", &up);
    let app = Arc::clone(&f.app);
    let surrogate = crate::test_support::register_session(&app, IDENTITY, "sess-9", 3);

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/admin/v1/sessions")
        .body(Body::empty())
        .expect("request");
    let resp = crate::admin_http::router(Arc::clone(&app))
        .oneshot(req)
        .await
        .expect("router");
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let listing: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        listing["sessions"],
        json!([{ "identity": IDENTITY, "session": "sess-9", "generation": 3 }])
    );
    assert!(!String::from_utf8_lossy(&bytes).contains(&sha256_hex(&surrogate)));

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/admin/v1/revoke-all")
        .body(Body::empty())
        .expect("request");
    let resp = crate::admin_http::router(Arc::clone(&app))
        .oneshot(req)
        .await
        .expect("router");
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let revoked: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(revoked["revoked"], json!(1));

    let reg = app.registry.lock().expect("registry");
    let now = reg.now();
    let denied = reg.authorize(&sha256_hex(&surrogate), IDENTITY, ROUTE, now);
    assert_eq!(denied, Err(Deny::Revoked));
}
