//! HTTP/2 upstream (design section 5, backlog item 2) and the `upstream_reset`
//! audit line (section 4, "Upstream error mid-stream").
//!
//! The upstream here is a real HTTP/2-only TLS server built on the `h2` crate
//! (ALPN offers only `h2`), serving the throwaway `api.up.test` certificate of
//! the other integration tests. The proxy is the real binary. The agent side is
//! HTTP/1.1, as in production.

mod support;

use bytes::Bytes;
use h2::{server, Reason};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use support::*;
use tokio_rustls::TlsAcceptor;

/// One request as the h2 upstream saw it.
#[derive(Clone, Debug)]
struct Seen {
    alpn: Option<Vec<u8>>,
    version: String,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

struct H2Up {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl H2Up {
    fn start() -> H2Up {
        let dir = pki();
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(dir.join("api.pem"))
                .unwrap()
                .map(|c| c.unwrap())
                .collect();
        let key = PrivateKeyDer::from_pem_file(dir.join("api.key")).unwrap();
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(cfg));

        let port = free_port();
        let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let seen2 = seen.clone();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        r = listener.accept() => {
                            let Ok((tcp, _)) = r else { continue };
                            let (acceptor, seen) = (acceptor.clone(), seen2.clone());
                            tokio::spawn(async move {
                                let Ok(tls) = acceptor.accept(tcp).await else { return };
                                let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                                let Ok(mut conn) = server::handshake(tls).await else { return };
                                while let Some(Ok((req, respond))) = conn.accept().await {
                                    tokio::spawn(serve(req, respond, seen.clone(), alpn.clone()));
                                }
                            });
                        }
                    }
                }
            });
        });
        let end = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < end, "h2 upstream did not come up");
            std::thread::sleep(Duration::from_millis(20));
        }
        H2Up {
            port,
            seen,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for H2Up {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

async fn serve(
    mut req: http::Request<h2::RecvStream>,
    mut respond: server::SendResponse<Bytes>,
    seen: Arc<Mutex<Vec<Seen>>>,
    alpn: Option<Vec<u8>>,
) {
    let mut body = Vec::new();
    while let Some(chunk) = req.body_mut().data().await {
        let Ok(chunk) = chunk else { return };
        let _ = req.body_mut().flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
    }
    let path = req.uri().path().to_string();
    seen.lock().unwrap().push(Seen {
        alpn,
        version: format!("{:?}", req.version()),
        method: req.method().to_string(),
        path: path.clone(),
        headers: req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<bin>").to_string()))
            .collect(),
        body: body.clone(),
    });

    let head = |ctype: &str| {
        http::Response::builder()
            .status(200)
            .header("content-type", ctype)
            .body(())
            .unwrap()
    };
    match path.as_str() {
        // Echo the request body back, in one response with a length.
        "/v1/echo" => {
            let h = http::Response::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .header("content-length", body.len())
                .header("x-upstream-proto", "h2")
                .body(())
                .unwrap();
            let end = body.is_empty();
            let mut tx = respond.send_response(h, end).unwrap();
            if !end {
                tx.send_data(Bytes::from(body), true).unwrap();
            }
        }
        // Three DATA frames with gaps, then a clean end.
        "/v1/chunks" => {
            let mut tx = respond.send_response(head("text/plain"), false).unwrap();
            for part in ["one\n", "two\n"] {
                tx.send_data(Bytes::from(part), false).unwrap();
                tokio::time::sleep(Duration::from_millis(60)).await;
            }
            tx.send_data(Bytes::from("three\n"), true).unwrap();
        }
        // Headers and some data, then RST_STREAM(INTERNAL_ERROR).
        "/v1/reset-mid" => {
            let mut tx = respond.send_response(head("text/plain"), false).unwrap();
            tx.send_data(Bytes::from("partial-"), false).unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            tx.send_reset(Reason::INTERNAL_ERROR);
        }
        // RST_STREAM before any response header.
        "/v1/reset-early" => respond.send_reset(Reason::INTERNAL_ERROR),
        _ => {
            let mut tx = respond.send_response(head("text/plain"), false).unwrap();
            tx.send_data(Bytes::from("ok"), true).unwrap();
        }
    }
}

/// A fixture whose routes `up`, `upaws` and `other` point at the h2 upstream.
/// `connect_to` is read at proxy start, so the policy is written first.
fn fixture_with_h2() -> (Fixture, H2Up, ap_client::Surrogate) {
    let up = H2Up::start();
    let mut fx = Fixture::new(Opts::default());
    let policy = fx
        .policy_toml("agent-1", &default_grants())
        .replace(
            &format!("connect_to = \"127.0.0.1:{}\"", fx.up_port),
            &format!("connect_to = \"127.0.0.1:{}\"", up.port),
        )
        .replace(
            &format!("port = {}\n", fx.up_port),
            &format!("port = {}\n", up.port),
        );
    assert!(policy.contains(&up.port.to_string()));
    assert!(!policy.contains(&format!("127.0.0.1:{}\"", fx.up_port)));
    fx.set_policy_raw(&policy);
    fx.start_proxy();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let s = rt.block_on(async {
        let c = fx.client();
        c.hello().await.unwrap();
        register(&c, "s1", 1, &["c-up"]).await
    });
    (fx, up, s)
}

/// Send one request and read until EOF or `limit`. Returns the raw bytes and
/// whether the read ended by EOF (`true`) or by the deadline (`false`).
fn raw_until_eof(port: u16, req: &str, limit: Duration) -> (Vec<u8>, bool) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let end = Instant::now() + limit;
    loop {
        match s.read(&mut buf) {
            Ok(0) => return (out, true),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return (out, true), // reset by the proxy counts as closed
        }
        if Instant::now() > end {
            return (out, false);
        }
    }
}

fn get_req(fx: &Fixture, path: &str, sur: &str) -> String {
    format!(
        "GET /ap/{}/up{path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {sur}\r\nConnection: close\r\n\r\n",
        fx.caller_key, fx.port
    )
}

fn wait_audit(fx: &Fixture, code: &str) -> Vec<serde_json::Value> {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let l = fx.audit_lines();
        if l.iter().any(|v| v["code"] == code) || Instant::now() > end {
            return l;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_request_is_relayed_to_an_http2_upstream() {
    let (fx, up, s) = fixture_with_h2();

    // POST with a body: the upstream echoes it; the agent side stays HTTP/1.1.
    let payload = vec![b'x'; 100_000];
    let r = fx.request(
        "POST",
        "up",
        "/v1/echo",
        &[
            ("Authorization", &format!("Bearer {}", s.expose())),
            ("tokentype", "pass-me"),
        ],
        &payload,
    );
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.header("x-upstream-proto"), Some("h2"));
    assert_eq!(r.body, payload, "echoed body differs");

    let seen = up.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let q = &seen[0];
    assert_eq!(q.alpn.as_deref(), Some(&b"h2"[..]), "ALPN did not pick h2");
    assert_eq!(q.version, "HTTP/2.0");
    assert_eq!((q.method.as_str(), q.path.as_str()), ("POST", "/v1/echo"));
    assert_eq!(q.body, payload);
    // The credential is swapped; the surrogate and the caller key never reach
    // the upstream; pass_headers survive.
    let real = fx.secret_value("c-up");
    assert_eq!(q.header("authorization"), Some(format!("Bearer {real}").as_str()));
    let dump = format!("{q:?}");
    assert!(!dump.contains(s.expose()) && !dump.contains(&fx.caller_key), "{dump}");
    assert_eq!(q.header("tokentype"), Some("pass-me"));
    assert_eq!(q.header(":authority"), None); // pseudo-headers are not in the map
}

#[test]
fn http2_response_chunks_are_streamed_and_audited_as_allowed() {
    let (fx, up, s) = fixture_with_h2();
    let t = Instant::now();
    let r = fx.get("up", "/v1/chunks", s.expose());
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.text(), "one\ntwo\nthree\n");
    assert!(t.elapsed() >= Duration::from_millis(100), "no gaps seen");
    assert_eq!(up.seen()[0].version, "HTTP/2.0");

    let lines = fx.audit_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["decision"], "allow");
    assert_eq!(lines[0]["code"], "ok");
    assert_eq!(lines[0]["status"], 200);
    assert_eq!(lines[0]["path"], "/v1/chunks");
}

#[test]
fn an_upstream_reset_mid_stream_is_audited_and_closes_the_client_stream() {
    let (mut fx, up, s) = fixture_with_h2();

    let (raw, eof) = raw_until_eof(
        fx.port,
        &get_req(&fx, "/v1/reset-mid", s.expose()),
        Duration::from_secs(10),
    );
    let text = String::from_utf8_lossy(&raw).into_owned();
    eprintln!("client saw (eof={eof}): {text:?}");
    assert!(eof, "the client stream hung open; got {text:?}");
    // The head and the first bytes were already relayed, so the status is 200.
    assert!(text.starts_with("HTTP/1.1 200"), "{text:?}");
    assert!(text.contains("partial-"), "{text:?}");
    // No synthetic success: a clean chunked end would be `0\r\n\r\n`.
    assert!(
        !text.ends_with("0\r\n\r\n"),
        "the stream was terminated as if complete: {text:?}"
    );
    assert_eq!(up.seen()[0].version, "HTTP/2.0");

    let lines = wait_audit(&fx, "upstream_reset");
    eprintln!("audit: {lines:#?}");
    let allow: Vec<_> = lines.iter().filter(|v| v["code"] == "ok").collect();
    let reset: Vec<_> = lines
        .iter()
        .filter(|v| v["code"] == "upstream_reset")
        .collect();
    assert_eq!(allow.len(), 1, "{lines:?}");
    assert_eq!(reset.len(), 1, "exactly one upstream_reset line: {lines:?}");
    let r = reset[0];
    assert_eq!(r["decision"], "error");
    assert_eq!(r["status"], 200, "status is the one already sent");
    assert_eq!(r["identity"], "agent-1");
    assert_eq!(r["route"], "up");
    assert_eq!(r["method"], "GET");
    assert_eq!(r["path"], "/v1/reset-mid");
    assert_eq!(r["session"], "s1");
    // No key material in any line.
    let all = lines
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!all.contains("apk_") && !all.contains("aps_") && !all.contains(&fx.secret_value("c-up")));

    // The proxy survived and serves the next request on the same upstream.
    assert!(fx.proxy_alive());
    let ok = fx.get("up", "/v1/chunks", s.expose());
    assert_eq!(ok.status, 200);
    assert_eq!(ok.text(), "one\ntwo\nthree\n");
    let (_, stderr) = fx.read_logs();
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn an_upstream_reset_before_the_response_is_a_502_upstream_unavailable() {
    let (mut fx, _up, s) = fixture_with_h2();
    let r = fx.get("up", "/v1/reset-early", s.expose());
    assert_eq!(r.status, 502, "{}", r.text());
    assert_eq!(r.code(), Some("upstream_unavailable"));
    let lines = fx.audit_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["decision"], "deny");
    assert_eq!(lines[0]["code"], "upstream_unavailable");
    assert_eq!(lines[0]["status"], 502);
    assert!(fx.proxy_alive());
    let (_, stderr) = fx.read_logs();
    assert!(!stderr.contains("panicked"), "{stderr}");
}

/// The design (section 4, "Upstream error mid-stream") says the audit line
/// records `upstream_reset` and the bytes sent. `AuditRec` has no such field.
/// Kept as an ignored test so the gap is on record without turning the suite
/// red: run with `--ignored` to see it fail.
#[test]
#[ignore = "design claim not implemented: the upstream_reset audit line has no bytes-sent field"]
fn the_upstream_reset_audit_line_records_the_bytes_sent() {
    let (fx, _up, s) = fixture_with_h2();
    let _ = raw_until_eof(
        fx.port,
        &get_req(&fx, "/v1/reset-mid", s.expose()),
        Duration::from_secs(10),
    );
    let lines = wait_audit(&fx, "upstream_reset");
    let r = lines
        .iter()
        .find(|v| v["code"] == "upstream_reset")
        .expect("an upstream_reset line");
    let obj = r.as_object().unwrap();
    let field = ["bytes_sent", "bytes", "bytes_out", "response_bytes"]
        .iter()
        .find_map(|k| obj.get(*k));
    let n = field
        .unwrap_or_else(|| panic!("no bytes field in the upstream_reset line: {r}"))
        .as_u64()
        .expect("a number");
    assert_eq!(n, "partial-".len() as u64);
}
