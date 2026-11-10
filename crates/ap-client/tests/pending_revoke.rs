//! A registration must not be sent while an earlier end of the same session is still pending.
//! The stand-in session server answers hello and accepts registrations, but refuses every DELETE
//! with 500, so the end stays pending. It records each request it receives.

use ap_client::authority::{Authority, AuthorityError};
use ap_proxy::session_http::serve_unix;
use axum::body::Body;
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

/// Answer one request and append "METHOD path" to `log`.
fn answer(log: &Mutex<Vec<String>>, req: &Request) -> Response {
    log.lock()
        .expect("log lock")
        .push(format!("{} {}", req.method(), req.uri().path()));
    if req.method() == Method::POST && req.uri().path() == "/v1/hello" {
        return reply(
            StatusCode::OK,
            r#"{"authority_token":"stand-in-token","lease_secs":300}"#,
        );
    }
    if req.method() == Method::DELETE {
        return reply(StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"down"}"#);
    }
    reply(StatusCode::OK, "{}")
}

#[tokio::test]
async fn register_is_refused_while_an_earlier_revoke_is_pending() {
    let socket = std::path::PathBuf::from(format!("/tmp/apc-pr-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let fake = Router::new().fallback({
        let log = Arc::clone(&seen);
        move |req: Request| {
            let log = Arc::clone(&log);
            async move { answer(&log, &req) }
        }
    });
    let listener = UnixListener::bind(&socket).expect("bind stand-in socket");
    let server = tokio::spawn(serve_unix(listener, fake));

    let auth = Authority::start("pty-a", socket.clone())
        .await
        .expect("hello");
    auth.register("s1", 1, vec!["kiro".into()])
        .await
        .expect("first registration");
    assert!(
        auth.end("s1", 1).await.is_err(),
        "end is refused, so the revoke stays pending"
    );
    seen.lock().expect("log lock").clear();

    match auth.register("s1", 1, vec!["kiro".into()]).await {
        Err(AuthorityError::RevokePending) => {}
        Err(other) => panic!("expected RevokePending, got {other:?}"),
        Ok(_) => panic!("registration must not succeed while the revoke is pending"),
    }

    // The only request sent is the retried DELETE. No registration reached the server.
    let sent = seen.lock().expect("log lock").clone();
    assert_eq!(sent, vec!["DELETE /v1/sessions/s1/1".to_string()]);

    server.abort();
    let _ = std::fs::remove_file(&socket);
}
