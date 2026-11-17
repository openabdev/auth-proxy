//! HTTP/2 upstream tests: the relay over h2, and the `upstream_reset` audit line with the bytes
//! already forwarded. The upstream is a real h2-only TLS server (ALPN offers only `h2`) under a
//! throwaway CA.

use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::to_bytes;
use bytes::Bytes;
use futures_util::StreamExt;
use h2::{server, Reason};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::test_support::{
    agent_request, register_session, tls_server_config, Fixture, Upstream, CREDENTIAL, IDENTITY,
};

/// The reset routes wait on this gate, which the test fills in before the request. The test
/// releases it once it has observed what the reset must not overtake.
type Gate = Arc<std::sync::Mutex<Option<oneshot::Receiver<()>>>>;

async fn wait_gate(gate: &Gate) {
    let rx = gate.lock().expect("gate").take();
    if let Some(rx) = rx {
        let _ = rx.await;
    }
}

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
    gate: Gate,
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
        // Headers and 8 body bytes in two DATA frames, then RST_STREAM once the test has seen them.
        "/reset-mid" => {
            let mut tx = respond.send_response(head(), false).expect("head");
            tx.send_data(Bytes::from("par"), false).expect("data");
            tx.send_data(Bytes::from("tial-"), false).expect("data");
            wait_gate(&gate).await;
            tx.send_reset(Reason::INTERNAL_ERROR);
        }
        // Headers only, then RST_STREAM once the test has seen the head.
        "/reset-zero" => {
            let mut tx = respond.send_response(head(), false).expect("head");
            wait_gate(&gate).await;
            tx.send_reset(Reason::INTERNAL_ERROR);
        }
        // RST_STREAM before any response header.
        "/reset-early" => respond.send_reset(Reason::INTERNAL_ERROR),
        _ => respond.send_reset(Reason::REFUSED_STREAM),
    }
}

/// An h2-only TLS upstream. The second value lists the HTTP version of each request it served.
async fn start_h2_upstream() -> (Upstream, Arc<std::sync::Mutex<Vec<String>>>, Gate) {
    let (server_cfg, ca_der) = tls_server_config(b"h2");
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let gate: Gate = Arc::default();
    let (counter, seen2, gate2) = (Arc::clone(&hits), Arc::clone(&seen), Arc::clone(&gate));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let (acceptor, seen, gate) = (acceptor.clone(), Arc::clone(&seen2), Arc::clone(&gate2));
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut conn) = server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((req, respond))) = conn.accept().await {
                    tokio::spawn(serve(req, respond, Arc::clone(&seen), Arc::clone(&gate)));
                }
            });
        }
    });
    (Upstream::from_parts(addr, hits, ca_der), seen, gate)
}

fn audit_values(f: &Fixture) -> Vec<serde_json::Value> {
    f.audit_text()
        .lines()
        .map(|l| serde_json::from_str(l).expect("audit line is json"))
        .collect()
}

#[tokio::test]
async fn a_request_is_relayed_to_an_http2_upstream() {
    let (up, seen, _gate) = start_h2_upstream().await;
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
    let (up, _seen, gate) = start_h2_upstream().await;
    let (release, rx) = oneshot::channel();
    *gate.lock().expect("gate") = Some(rx);
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
    // Observe every body byte before the server may reset, so the reset cannot overtake them.
    let mut got = Vec::new();
    while got.len() < "partial-".len() {
        let b = stream
            .next()
            .await
            .expect("body ended before the data")
            .expect("data chunk before the reset");
        got.extend_from_slice(&b);
    }
    assert_eq!(got, b"partial-");
    release.send(()).expect("release the reset");
    let failed = matches!(stream.next().await, Some(Err(_)));
    drop(stream);
    assert!(failed, "the body ended cleanly after an upstream reset");

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
    let (up, _seen, _gate) = start_h2_upstream().await;
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

#[tokio::test]
async fn a_reset_after_the_head_with_no_body_audits_zero_bytes() {
    let (up, _seen, gate) = start_h2_upstream().await;
    let (release, rx) = oneshot::channel();
    *gate.lock().expect("gate") = Some(rx);
    let f = Fixture::new("h2zero", &up);
    let surrogate = register_session(&f.app, IDENTITY, "sess-1", 1);

    let resp = handle(
        Arc::clone(&f.app),
        agent_request("GET", "/reset-zero", &f.caller, &surrogate),
    )
    .await;
    // The head reached the proxy, so the reset can no longer replace it.
    assert_eq!(resp.status(), 200);
    release.send(()).expect("release the reset");
    let mut stream = resp.into_body().into_data_stream();
    assert!(
        matches!(stream.next().await, Some(Err(_))),
        "the first body item must be the reset"
    );
    drop(stream);

    let lines = audit_values(&f);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["code"], "upstream_reset");
    assert_eq!(lines[0]["status"], 200);
    assert_eq!(lines[0]["bytes_sent"], 0, "{}", lines[0]);
}
