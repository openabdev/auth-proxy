//! A resync reply that lists a session under `expired` must remove that session from the client's
//! live set. The next renew must not name it, and the client must not resync it again.
//! The stand-in session server reports `unknown` once for s1, then answers the resync with s1 in
//! `expired`. It records the body of every renew and resync it receives.

use ap_client::authority::Authority;
use ap_proxy::session_http::serve_unix;
use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::response::Response;
use axum::Router;
use std::sync::{Arc, Mutex};
use tokio::net::UnixListener;

fn reply(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .expect("response")
}

#[derive(Default)]
struct Log {
    renew_bodies: Vec<String>,
    resync_bodies: Vec<String>,
    renews: usize,
}

async fn answer(log: &Mutex<Log>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let body = to_bytes(req.into_body(), 1 << 20)
        .await
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let mut log = log.lock().expect("log lock");
    if method == Method::POST && path == "/v1/hello" {
        return reply(
            StatusCode::CREATED,
            r#"{"authority_token":"stand-in-token","lease_secs":300}"#,
        );
    }
    if method == Method::POST && path == "/v1/sessions" {
        return reply(StatusCode::CREATED, r#"{"lease_secs":300}"#);
    }
    if method == Method::POST && path == "/v1/renew" {
        log.renew_bodies.push(body);
        log.renews += 1;
        return if log.renews == 1 {
            reply(
                StatusCode::OK,
                r#"{"lease_secs":300,"unknown":[{"session":"s1","generation":1}]}"#,
            )
        } else {
            reply(StatusCode::OK, r#"{"lease_secs":300,"unknown":[]}"#)
        };
    }
    if method == Method::PUT && path == "/v1/sessions" {
        log.resync_bodies.push(body);
        return reply(
            StatusCode::OK,
            r#"{"registered":1,"dropped":0,"expired":[{"session":"s1","generation":1}]}"#,
        );
    }
    reply(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#)
}

#[tokio::test]
async fn expired_in_resync_reply_drops_the_session_from_renew_and_resync() {
    let socket = std::path::PathBuf::from(format!("/tmp/apc-ex-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let log: Arc<Mutex<Log>> = Arc::new(Mutex::new(Log::default()));
    let fake = Router::new().fallback({
        let log = Arc::clone(&log);
        move |req: Request| {
            let log = Arc::clone(&log);
            async move { answer(&log, req).await }
        }
    });
    let listener = UnixListener::bind(&socket).expect("bind stand-in socket");
    let server = tokio::spawn(serve_unix(listener, fake));

    let auth = Authority::start("pty-a", socket.clone())
        .await
        .expect("hello");
    auth.register("s1", 1, vec!["kiro".into()])
        .await
        .expect("register s1");
    auth.register("s2", 1, vec!["kiro".into()])
        .await
        .expect("register s2");

    // First renew: the proxy reports s1 unknown, so the client resyncs. The reply lists s1 as
    // expired, and the client must drop it.
    auth.renew().await.expect("renew with resync");
    // Second renew: s1 must not be named any more.
    auth.renew().await.expect("second renew");

    let log = log.lock().expect("log lock");
    assert_eq!(log.resync_bodies.len(), 1, "one resync after unknown");
    assert!(
        log.resync_bodies[0].contains("\"s1\""),
        "the first resync still carries s1, the proxy has not said it expired yet"
    );
    let second = &log.renew_bodies[1];
    assert!(
        !second.contains("\"s1\""),
        "renew after an expired reply must not name s1: {second}"
    );
    assert!(second.contains("\"s2\""), "s2 stays live: {second}");
    drop(log);

    server.abort();
    let _ = std::fs::remove_file(&socket);
}
