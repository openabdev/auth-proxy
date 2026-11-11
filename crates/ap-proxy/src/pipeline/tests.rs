//! Pipeline tests: refusal order, the forwarded request, the body cap, policy reload and the
//! audit contents. Each test runs `handle` against a fixture upstream with a throwaway CA.

use std::sync::atomic::Ordering;

use axum::body::to_bytes;
use http::{HeaderMap, Method};

use super::*;
use crate::test_support::{
    agent_request, register_session, start_upstream, surrogate_token, Fixture, Upstream, CAP,
    CREDENTIAL, IDENTITY, LISTEN, ROUTE,
};

async fn run_request(app: &Arc<App>, req: Request) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = handle(Arc::clone(app), req).await;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("response body");
    (status, headers, body.to_vec())
}

#[tokio::test]
async fn absolute_form_is_refused_before_the_caller_check() {
    let up = start_upstream().await;
    let f = Fixture::new("abs", &up);
    // The caller key is wrong on purpose. Absolute form must be refused first.
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "http://{LISTEN}/ap/apk_{}/{ROUTE}/",
            "0".repeat(64)
        ))
        .header("host", LISTEN)
        .body(Body::empty())
        .expect("request");
    let (status, _, _) = run_request(&f.app, req).await;
    assert_eq!(status, 400);
    let text = f.audit_text();
    assert!(text.contains("\"code\":\"absolute_form\""), "{text}");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn connect_and_websocket_upgrade_are_refused_without_upstream() {
    let up = start_upstream().await;
    let f = Fixture::new("refuse", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);

    let connect = Request::builder()
        .method(Method::CONNECT)
        .uri("127.0.0.1:443")
        .body(Body::empty())
        .expect("connect");
    let (status, _, _) = run_request(&f.app, connect).await;
    assert_eq!(status, 405);

    let upgrade = Request::builder()
        .method("GET")
        .uri(format!("/ap/{}/{ROUTE}/", f.caller))
        .header("host", LISTEN)
        .header("authorization", format!("Bearer {surrogate}"))
        .header("upgrade", "websocket")
        .body(Body::empty())
        .expect("upgrade");
    let (status, _, _) = run_request(&f.app, upgrade).await;
    assert_eq!(status, 501);

    let text = f.audit_text();
    assert!(text.contains("\"code\":\"connect_refused\""), "{text}");
    assert!(
        text.contains("\"code\":\"websocket_unsupported\""),
        "{text}"
    );
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn forwarded_request_carries_one_credential_and_no_client_auth() {
    let up = start_upstream().await;
    let f = Fixture::new("fwd", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);

    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/ap/{}/{ROUTE}/echo", f.caller))
        .header("host", LISTEN)
        .header("authorization", format!("Bearer {surrogate}"))
        .header("tokentype", "API_KEY");
    for name in ap_core::headers::AUTH_HEADERS {
        if *name != "authorization" {
            builder = builder.header(*name, "client-leak-0001");
        }
    }
    let req = builder.body(Body::from("hi")).expect("request");
    let (status, _, body) = run_request(&f.app, req).await;
    assert_eq!(status, 200);

    let seen: Vec<(String, String)> = serde_json::from_slice(&body).expect("echo json");
    let auth: Vec<&str> = seen
        .iter()
        .filter(|(k, _)| k == "authorization")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(auth, vec![format!("Bearer {CREDENTIAL}").as_str()]);
    for (name, value) in &seen {
        assert!(!value.contains("client-leak-0001"), "leaked via {name}");
        assert!(
            !value.contains(&surrogate),
            "surrogate sent upstream via {name}"
        );
    }
    assert!(seen.iter().any(|(k, v)| k == "tokentype" && v == "API_KEY"));

    // The allow line is written when the response body ends, which the collect above forced.
    let text = f.audit_text();
    assert!(text.contains("\"decision\":\"allow\""), "{text}");
    assert!(!text.contains(CREDENTIAL));
    assert!(!text.contains(&surrogate));
    assert!(!text.contains(&f.caller));
}

#[tokio::test]
async fn upstream_redirect_is_returned_to_the_agent_unchanged() {
    let up = start_upstream().await;
    let f = Fixture::new("redir", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);
    let req = agent_request("POST", "/redirect", &f.caller, &surrogate);
    let (status, headers, _) = run_request(&f.app, req).await;
    assert_eq!(status, 302);
    assert_eq!(
        headers.get("location").and_then(|v| v.to_str().ok()),
        Some("https://elsewhere.test.example/next")
    );
}

#[tokio::test]
async fn declared_body_over_the_cap_is_413_and_never_connects_upstream() {
    let up = start_upstream().await;
    let f = Fixture::new("cap", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/ap/{}/{ROUTE}/", f.caller))
        .header("host", LISTEN)
        .header("authorization", format!("Bearer {surrogate}"))
        .header("content-length", (CAP + 1).to_string())
        .body(Body::empty())
        .expect("request");
    let (status, _, _) = run_request(&f.app, req).await;
    assert_eq!(status, 413);
    assert!(f.audit_text().contains("\"code\":\"body_too_large\""));
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn undeclared_body_over_the_cap_is_413_with_an_audit_line() {
    // No Content-Length, so the proxy cannot refuse before connecting. The upstream connection
    // opens, the body stream fails at the cap, and the agent gets 413 with the audit line.
    let up = start_upstream().await;
    let f = Fixture::new("streamcap", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);
    let body = vec![b'x'; (CAP + 1) as usize];
    let req = Request::builder()
        .method("POST")
        .uri(format!("/ap/{}/{ROUTE}/", f.caller))
        .header("host", LISTEN)
        .header("authorization", format!("Bearer {surrogate}"))
        .body(Body::from(body))
        .expect("request");
    let (status, _, _) = run_request(&f.app, req).await;
    assert_eq!(status, 413);
    let text = f.audit_text();
    assert!(text.contains("\"code\":\"body_too_large\""), "{text}");
    assert!(!text.contains(&surrogate), "surrogate in audit");
}

#[tokio::test]
async fn corrupted_policy_file_drops_the_snapshot_until_it_is_valid_again() {
    let up = start_upstream().await;
    let f = Fixture::new("policy", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);
    assert!(f.app.policy().is_some());

    std::fs::write(&f.policy_path, "version = [oops").expect("corrupt policy");
    let req = agent_request("POST", "/", &f.caller, &surrogate);
    let (status, _, body) = run_request(&f.app, req).await;
    assert_eq!(status, 503);
    assert!(String::from_utf8_lossy(&body).contains("policy_unavailable"));
    assert!(f.app.policy().is_none());
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);

    std::fs::write(
        &f.policy_path,
        crate::test_support::policy_text(&sha256_hex(&f.caller), up.addr.port()),
    )
    .expect("restore policy");
    assert!(f.app.policy().is_some());
}

#[tokio::test]
async fn refused_request_audit_holds_no_caller_key_surrogate_or_credential() {
    let up: Upstream = start_upstream().await;
    let f = Fixture::new("noleak", &up);
    let _registered = register_session(&f.app, IDENTITY, "sess-1", 1);
    let unknown = surrogate_token();
    let req = agent_request("POST", "/", &f.caller, &unknown);
    let (status, _, _) = run_request(&f.app, req).await;
    assert_eq!(status, 403);

    let text = f.audit_text();
    assert!(text.contains("\"code\":\"surrogate_unknown\""), "{text}");
    assert!(!text.contains(&f.caller), "caller key in audit");
    assert!(!text.contains(&unknown), "surrogate in audit");
    assert!(!text.contains(CREDENTIAL), "credential in audit");
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
}
