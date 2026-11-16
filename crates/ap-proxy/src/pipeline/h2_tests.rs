//! HTTP/2 upstream tests: the relay over h2, and the `upstream_reset` audit line with the bytes
//! already forwarded. The upstream is a real h2-only TLS server (ALPN offers only `h2`) under a
//! throwaway CA.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::to_bytes;
use bytes::Bytes;
use futures_util::StreamExt;
use h2::{server, Reason};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::test_support::{
    agent_request, register_session, tls_server_config, Fixture, Upstream, CREDENTIAL, IDENTITY,
};

fn head() -> http::Response<()> {
    http::Response::builder()
        .status(200)
        .header("content-type", "text/plain")
        .body(())
        .expect("head")
}

async fn serve(
    req: http::Request<h2::RecvStream>,
    mut respond: server::SendResponse<Bytes>,
    protocol_seen: Arc<std::sync::Mutex<Vec<String>>>,
) {
    protocol_seen
        .lock()
        .expect("seen")
        .push(format!("{:?}", req.version()));
    match req.uri().path() {
        "/ok" => {
            let mut tx = respond.send_response(head(), false).expect("head");
            tx.send_data(Bytes::from("one-"), false).expect("data");
            tx.send_data(Bytes::from("two"), true).expect("data");
        }
        // Headers and 8 body bytes, then RST_STREAM.
        "/reset-mid" => {
            let mut tx = respond.send_response(head(), false).expect("head");
            tx.send_data(Bytes::from("partial-"), false).expect("data");
            tokio::time::sleep(Duration::from_millis(150)).await;
            tx.send_reset(Reason::INTERNAL_ERROR);
        }
        // RST_STREAM before any response header.
        "/reset-early" => respond.send_reset(Reason::INTERNAL_ERROR),
        _ => respond.send_reset(Reason::REFUSED_STREAM),
    }
}

/// An h2-only TLS upstream. The second value lists the HTTP version of each request it served.
async fn start_h2_upstream() -> (Upstream, Arc<std::sync::Mutex<Vec<String>>>) {
    let (server_cfg, ca_der) = tls_server_config(b"h2");
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let (counter, seen2) = (Arc::clone(&hits), Arc::clone(&seen));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let (acceptor, seen) = (acceptor.clone(), Arc::clone(&seen2));
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut conn) = server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((req, respond))) = conn.accept().await {
                    tokio::spawn(serve(req, respond, Arc::clone(&seen)));
                }
            });
        }
    });
    (Upstream::from_parts(addr, hits, ca_der), seen)
}

fn audit_values(f: &Fixture) -> Vec<serde_json::Value> {
    f.audit_text()
        .lines()
        .map(|l| serde_json::from_str(l).expect("audit line is json"))
        .collect()
}

#[tokio::test]
async fn a_request_is_relayed_to_an_http2_upstream() {
    let (up, seen) = start_h2_upstream().await;
    let f = Fixture::new("h2ok", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);

    let resp = handle(
        Arc::clone(&f.app),
        agent_request("GET", "/ok", &f.caller, &surrogate),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    assert_eq!(&body[..], b"one-two");
    assert_eq!(*seen.lock().expect("seen"), vec!["HTTP/2.0".to_string()]);

    let lines = audit_values(&f);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["decision"], "allow");
    assert!(lines[0].get("bytes_sent").is_none(), "{}", lines[0]);
}

#[tokio::test]
async fn a_mid_stream_reset_is_not_a_success_and_audits_the_bytes_forwarded() {
    let (up, _seen) = start_h2_upstream().await;
    let f = Fixture::new("h2mid", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);

    let resp = handle(
        Arc::clone(&f.app),
        agent_request("GET", "/reset-mid", &f.caller, &surrogate),
    )
    .await;
    // The head was already sent, so the status is the upstream's.
    assert_eq!(resp.status(), 200);
    let mut stream = resp.into_body().into_data_stream();
    let mut got = Vec::new();
    let mut failed = false;
    while let Some(item) = stream.next().await {
        match item {
            Ok(b) => got.extend_from_slice(&b),
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    drop(stream);
    assert!(failed, "the body ended cleanly after an upstream reset");
    assert_eq!(got, b"partial-");

    let lines = audit_values(&f);
    let resets: Vec<_> = lines
        .iter()
        .filter(|v| v["code"] == "upstream_reset")
        .collect();
    assert_eq!(resets.len(), 1, "{lines:?}");
    assert_eq!(lines.len(), 1, "no other audit line: {lines:?}");
    let r = resets[0];
    assert_eq!(r["bytes_sent"], "partial-".len() as u64, "{r}");
    assert_eq!(r["status"], 200);
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["path"], "/reset-mid");
    let text = f.audit_text();
    assert!(!text.contains("/ap/") && !text.contains("apk_") && !text.contains("aps_"));
    assert!(!text.contains(&f.caller) && !text.contains(&surrogate));
    assert!(!text.contains(CREDENTIAL));
}

#[tokio::test]
async fn a_reset_before_any_response_byte_is_502_with_no_bytes() {
    let (up, _seen) = start_h2_upstream().await;
    let f = Fixture::new("h2early", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);

    let resp = handle(
        Arc::clone(&f.app),
        agent_request("GET", "/reset-early", &f.caller, &surrogate),
    )
    .await;
    assert_eq!(resp.status(), 502);
    let _ = to_bytes(resp.into_body(), 1 << 20).await;

    let lines = audit_values(&f);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["code"], "upstream_unavailable");
    assert_eq!(lines[0]["status"], 502);
    assert!(lines[0].get("bytes_sent").is_none(), "{}", lines[0]);
    assert!(!f.audit_text().contains("upstream_reset"));
}
