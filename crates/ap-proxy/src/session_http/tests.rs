//! Session-plane and admin tests, driven through the routers with `tower::ServiceExt::oneshot`.

use std::sync::Arc;

use ap_broker::registry::{sha256_hex, Deny};
use ap_core::session_wire::hello_message;
use axum::body::to_bytes;
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use tower::ServiceExt;

use super::*;
use crate::pipeline::App;
use crate::test_support::{sign_hello, start_upstream, surrogate_token, Fixture, IDENTITY, ROUTE};

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

/// A hello body for `IDENTITY` that passes every check: a fresh nonce, signed with the test seed.
async fn signed_hello(app: &Arc<App>) -> Value {
    let (status, ch) = call(
        router(Arc::clone(app)),
        "GET",
        "/v1/hello/challenge",
        None,
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let nonce = ch["nonce"].as_str().expect("nonce").to_string();
    json!({ "identity": IDENTITY, "nonce": nonce, "proof": sign_hello(IDENTITY, &nonce) })
}

/// Post one hello body and return the status and the decoded reply.
async fn hello_with(app: &Arc<App>, body: Value) -> (u16, Value) {
    call(router(Arc::clone(app)), "POST", "/v1/hello", None, body).await
}

/// A proof over the hello message, signed with a seed other than the configured one.
fn proof_from_other_seed(identity: &str, nonce: &str) -> String {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    STANDARD.encode(key.sign(&hello_message(identity, nonce)).to_bytes())
}

#[tokio::test]
async fn session_plane_registers_renews_and_refuses_a_wrong_token() {
    let up = start_upstream().await;
    let f = Fixture::new("sess", &up);
    let app = Arc::clone(&f.app);

    let (status, hello) = hello_with(&app, signed_hello(&app).await).await;
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
async fn resync_response_omits_expired_when_nothing_expired() {
    let up = start_upstream().await;
    let f = Fixture::new("resync-wire", &up);
    let app = Arc::clone(&f.app);

    let (status, hello) = hello_with(&app, signed_hello(&app).await).await;
    assert_eq!(status, 201);
    let token = hello["authority_token"]
        .as_str()
        .expect("token")
        .to_string();

    let entry = json!({
        "session": "sess-resync",
        "generation": 1,
        "surrogate_sha256": sha256_hex(&surrogate_token()),
        "credentials": ["kiro"],
    });
    let (status, resp) = call(
        router(Arc::clone(&app)),
        "PUT",
        "/v1/sessions",
        Some(&token),
        json!({ "sessions": [entry] }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(resp["registered"], json!(1));
    // Nothing expired, so the reply keeps the shape an older client parses.
    assert!(resp.get("expired").is_none(), "{resp}");
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

#[tokio::test]
async fn hello_challenge_issues_a_fresh_nonce_and_audits_without_it() {
    let up = start_upstream().await;
    let f = Fixture::new("challenge", &up);
    let app = Arc::clone(&f.app);

    let (status, a) = call(
        router(Arc::clone(&app)),
        "GET",
        "/v1/hello/challenge",
        None,
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, b) = call(
        router(Arc::clone(&app)),
        "GET",
        "/v1/hello/challenge",
        None,
        json!({}),
    )
    .await;
    assert_eq!(status, 200);

    let first = a["nonce"].as_str().expect("nonce").to_string();
    let second = b["nonce"].as_str().expect("nonce").to_string();
    assert!(ap_core::canon::is_lower_hex_64(&first));
    assert_ne!(first, second);
    assert_eq!(a["ttl_secs"], json!(30));

    let text = f.audit_text();
    assert!(text.contains("\"op\":\"hello_challenge\""), "{text}");
    assert!(!text.contains(&first), "nonce in audit");
}

#[tokio::test]
async fn hello_with_only_an_identity_is_refused_as_proof_missing() {
    // The lease-lapse attacker: UID 1000 has no seed and sends the identity alone.
    let up = start_upstream().await;
    let f = Fixture::new("noproof", &up);
    let app = Arc::clone(&f.app);

    let (status, body) = hello_with(&app, json!({ "identity": IDENTITY })).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"], "proof_missing");

    // The refusal took no authority: a proper hello still gets one.
    let (status, _) = hello_with(&app, signed_hello(&app).await).await;
    assert_eq!(status, 201);
}

#[tokio::test]
async fn hello_with_a_proof_from_another_key_is_refused() {
    let up = start_upstream().await;
    let f = Fixture::new("wrongproof", &up);
    let app = Arc::clone(&f.app);
    let nonce = "a".repeat(64);
    let proof = proof_from_other_seed(IDENTITY, &nonce);

    let (status, body) = hello_with(
        &app,
        json!({ "identity": IDENTITY, "nonce": nonce, "proof": proof }),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(
        body["error"], "nonce_invalid",
        "a nonce the proxy never issued"
    );

    let (_, ch) = call(
        router(Arc::clone(&app)),
        "GET",
        "/v1/hello/challenge",
        None,
        json!({}),
    )
    .await;
    let issued = ch["nonce"].as_str().expect("nonce").to_string();
    let forged = proof_from_other_seed(IDENTITY, &issued);
    let (status, body) = hello_with(
        &app,
        json!({ "identity": IDENTITY, "nonce": issued, "proof": forged }),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["error"], "proof_invalid");
    assert!(!f.audit_text().contains(&forged), "proof in audit");
}

#[tokio::test]
async fn a_nonce_works_once() {
    let up = start_upstream().await;
    let f = Fixture::new("replay", &up);
    let app = Arc::clone(&f.app);
    let body = signed_hello(&app).await;

    let (status, _) = hello_with(&app, body.clone()).await;
    assert_eq!(status, 201);
    let (status, reply) = hello_with(&app, body).await;
    assert_eq!(status, 401);
    assert_eq!(reply["error"], "nonce_invalid");
}

#[tokio::test]
async fn a_refused_hello_does_not_spend_its_nonce() {
    let up = start_upstream().await;
    let f = Fixture::new("keepnonce", &up);
    let app = Arc::clone(&f.app);
    let body = signed_hello(&app).await;
    let nonce = body["nonce"].as_str().expect("nonce").to_string();

    let (status, reply) = hello_with(&app, json!({ "identity": IDENTITY, "nonce": nonce })).await;
    assert_eq!(status, 401);
    assert_eq!(reply["error"], "proof_missing");

    let (status, _) = hello_with(&app, body).await;
    assert_eq!(status, 201, "the same nonce still works with a proof");
}

#[tokio::test]
async fn a_proof_without_a_nonce_is_refused_as_nonce_invalid() {
    let up = start_upstream().await;
    let f = Fixture::new("nononce", &up);
    let app = Arc::clone(&f.app);
    let (status, reply) = hello_with(&app, json!({ "identity": IDENTITY, "proof": "AAAA" })).await;
    assert_eq!(status, 401);
    assert_eq!(reply["error"], "nonce_invalid");
}

#[tokio::test]
async fn a_nonce_that_is_not_64_lowercase_hex_is_an_invalid_body() {
    let up = start_upstream().await;
    let f = Fixture::new("badnonce", &up);
    let app = Arc::clone(&f.app);
    let (status, reply) = hello_with(
        &app,
        json!({ "identity": IDENTITY, "nonce": "XYZ", "proof": "AAAA" }),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(reply["error"], "invalid_body");
}

#[tokio::test]
async fn hello_for_an_identity_without_a_runtime_key_is_refused() {
    let up = start_upstream().await;
    let f = Fixture::without_runtime_key("nokey", &up);
    let app = Arc::clone(&f.app);
    let (status, reply) = hello_with(&app, json!({ "identity": IDENTITY })).await;
    assert_eq!(status, 403);
    assert_eq!(reply["error"], "runtime_key_missing");
}

#[tokio::test]
async fn hello_for_an_unknown_identity_is_refused_before_the_proof() {
    let up = start_upstream().await;
    let f = Fixture::new("unknownid", &up);
    let app = Arc::clone(&f.app);
    let (status, reply) = hello_with(&app, json!({ "identity": "nobody" })).await;
    assert_eq!(status, 400);
    assert_eq!(reply["error"], "identity_unknown");
}
