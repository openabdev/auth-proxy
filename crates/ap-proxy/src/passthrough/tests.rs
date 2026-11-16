use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use bytes::Bytes;
use http::Request;
use http_body_util::BodyExt;

use super::*;
use crate::test_support::{
    buffer_sink, caller_key, client_for, start_upstream, Scratch, Upstream, HOST,
};
use ap_broker::registry::sha256_hex;

const AUTH: &str = "gate.example.test";
const SENTINEL: &str = "SENTINEL-DISCORD-TOKEN-0001";
const PATH_TOKEN: &str = "SENTINEL-PATH-TOKEN-0002";

struct Pt {
    app: Arc<PtApp>,
    key: String,
    audit: Arc<Mutex<Vec<u8>>>,
    up: Upstream,
    _s: Scratch,
}

impl Pt {
    async fn new(tag: &str) -> Pt {
        Self::with(tag, "").await
    }

    async fn with(tag: &str, pt_extra: &str) -> Pt {
        let up = start_upstream().await;
        let s = Scratch::new(tag);
        let key = caller_key();
        let text = format!(
            r#"version = 1

[listen]
proxy = "127.0.0.1:8443"

[limits]
max_body_bytes = 1024

[passthrough]
public_authority = "{AUTH}"
body_read_secs = 1
{pt_extra}

[[identity]]
name = "muse-pilot"
caller_key_sha256 = "{sha}"

[[route]]
name = "discord"
host = "{HOST}"
port = {port}
mode = "passthrough"

[[grant]]
identity = "muse-pilot"
route = "discord"
methods = ["GET"]
paths = ["/api/", "/xap", "/me"]

[[grant]]
identity = "muse-pilot"
route = "discord"
methods = ["POST"]
paths = ["/up/"]

[probe]
enabled = true
"#,
            sha = sha256_hex(&key),
            port = up.addr.port()
        );
        let path = s.path().join("policy.toml");
        std::fs::write(&path, &text).unwrap();
        let cfg = ap_core::config::load(&text).expect("valid");
        let (sink, audit) = buffer_sink();
        let app = PtApp::new(path, cfg, sink, client_for(&up));
        Pt {
            app,
            key,
            audit,
            up,
            _s: s,
        }
    }

    fn req(&self, method: &str, path: &str) -> http::request::Builder {
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", AUTH)
            .header("x-ap-caller-key", self.key.as_str())
            .header("authorization", format!("Bot {SENTINEL}"))
    }

    fn audit_text(&self) -> String {
        String::from_utf8_lossy(&self.audit.lock().unwrap()).into_owned()
    }

    fn hits(&self) -> usize {
        self.up.hits.load(Ordering::SeqCst)
    }

    async fn send(&self, r: Request<Body>) -> Result<(http::response::Parts, Bytes), ()> {
        match handle(Arc::clone(&self.app), r).await {
            Ok(resp) => {
                let (p, b) = resp.into_parts();
                let bytes = b.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
                Ok((p, bytes))
            }
            Err(_) => Err(()),
        }
    }
}

fn decision(p: &http::response::Parts) -> String {
    p.headers
        .get("x-ap-decision")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default()
}

fn code(b: &Bytes) -> String {
    let v: serde_json::Value = serde_json::from_slice(b).unwrap();
    v["code"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn get_passes_and_upstream_x_ap_headers_are_kept() {
    let t = Pt::new("get").await;
    let (p, b) = t
        .send(t.req("GET", "/discord/xap").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(p.status, 200);
    assert_eq!(decision(&p), "denied");
    assert_eq!(p.headers.get("x-ap-other").unwrap(), "kept");
    assert_eq!(p.headers.get("x-plain").unwrap(), "yes");
    assert_eq!(&b[..], b"upstream-body");
}

#[tokio::test]
async fn forwarded_headers_drop_the_caller_key_and_keep_authorization() {
    let t = Pt::new("fwd").await;
    let r = t
        .req("GET", "/discord/api/echo2?x=1")
        .header("x-ap-other", "1")
        .header("forwarded", "for=1")
        .header("tailscale-user-login", "someone")
        .header("cookie", "a=b")
        .body(Body::empty())
        .unwrap();
    let (p, b) = t.send(r).await.unwrap();
    assert_eq!(p.status, 200);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let names: Vec<String> = v["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h[0].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"authorization".to_string()));
    for gone in [
        "x-ap-caller-key",
        "x-ap-other",
        "forwarded",
        "tailscale-user-login",
        "cookie",
    ] {
        assert!(
            !names.contains(&gone.to_string()),
            "{gone} reached upstream"
        );
    }
    let auth = v["headers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h[0] == "authorization")
        .unwrap();
    assert_eq!(auth[1], format!("Bot {SENTINEL}"));
    assert!(v["path"].as_str().unwrap().ends_with("/api/echo2?x=1"));
    assert!(!t.audit_text().contains(&t.key));
}

#[tokio::test]
async fn write_is_423_no_grant_and_nothing_goes_upstream() {
    let t = Pt::new("post").await;
    let r = t
        .req("POST", "/discord/api/v10/channels/1/messages")
        .header("content-length", "2")
        .body(Body::from("{}"))
        .unwrap();
    let (p, b) = t.send(r).await.unwrap();
    assert_eq!(p.status, 423);
    assert_eq!(decision(&p), "denied");
    assert_eq!(code(&b), "no_grant");
    assert_eq!(t.hits(), 0);
}

#[tokio::test]
async fn refusal_table() {
    let t = Pt::new("refuse").await;
    let mk = |f: &dyn Fn(http::request::Builder) -> http::request::Builder| {
        f(Request::builder()
            .method("GET")
            .uri("/discord/api/x")
            .header("host", AUTH))
        .body(Body::empty())
        .unwrap()
    };
    let key = t.key.clone();
    let cases: Vec<(&str, Request<Body>, u16, &str, &str)> = vec![
        (
            "missing key",
            mk(&|b| b),
            401,
            "rejected",
            "caller_rejected",
        ),
        (
            "malformed key",
            mk(&|b| b.header("x-ap-caller-key", "apk_short")),
            401,
            "rejected",
            "caller_rejected",
        ),
        (
            "unknown key",
            mk(&|b| b.header("x-ap-caller-key", caller_key())),
            401,
            "rejected",
            "caller_rejected",
        ),
        (
            "duplicate key",
            mk(&|b| {
                b.header("x-ap-caller-key", key.as_str())
                    .header("x-ap-caller-key", key.as_str())
            }),
            401,
            "rejected",
            "caller_rejected",
        ),
        (
            "unknown route",
            Request::builder()
                .uri("/nope/api/x")
                .header("host", AUTH)
                .header("x-ap-caller-key", key.as_str())
                .body(Body::empty())
                .unwrap(),
            423,
            "denied",
            "route_unknown",
        ),
        (
            "duplicate authorization",
            mk(&|b| {
                b.header("x-ap-caller-key", key.as_str())
                    .header("authorization", "a")
                    .header("authorization", "b")
            }),
            400,
            "denied",
            "authorization_duplicate",
        ),
        (
            "connect",
            Request::builder()
                .method("CONNECT")
                .uri("/discord/api/x")
                .header("host", AUTH)
                .body(Body::empty())
                .unwrap(),
            405,
            "denied",
            "connect_refused",
        ),
        (
            "upgrade",
            mk(&|b| b.header("upgrade", "websocket")),
            501,
            "denied",
            "websocket_unsupported",
        ),
        (
            "wrong host",
            Request::builder()
                .uri("/discord/api/x")
                .header("host", "evil.test")
                .header("x-ap-caller-key", key.as_str())
                .body(Body::empty())
                .unwrap(),
            400,
            "denied",
            "host_rejected",
        ),
        (
            "framing",
            mk(&|b| {
                b.header("x-ap-caller-key", key.as_str())
                    .header("content-length", "2")
                    .header("transfer-encoding", "chunked")
            }),
            400,
            "denied",
            "framing_refused",
        ),
    ];
    for (name, req, status, dec, c) in cases {
        let (p, b) = t.send(req).await.unwrap();
        assert_eq!(p.status.as_u16(), status, "{name}");
        assert_eq!(decision(&p), dec, "{name}");
        assert_eq!(code(&b), c, "{name}");
    }
    assert_eq!(t.hits(), 0);
}

#[tokio::test]
async fn path_variants_are_refused_with_no_upstream_hit() {
    let t = Pt::new("paths").await;
    for p in [
        "/discord/api/../x",
        "/discord/api/%2e%2e/x",
        "/discord/api/%2e/x",
        "/discord/api%2fx",
        "/discord//api/x",
        "/discord/api/%252e%252e/x",
    ] {
        let (parts, b) = t
            .send(t.req("GET", p).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(parts.status, 400, "{p}");
        assert_eq!(code(&b), "path_ambiguous", "{p}");
        assert_eq!(decision(&parts), "denied");
    }
    assert_eq!(t.hits(), 0);
}

#[tokio::test]
async fn no_sentinel_in_audit_for_any_outcome() {
    let t = Pt::new("sentinel").await;
    let hook = format!("/discord/api/v10/webhooks/1/{PATH_TOKEN}/github");
    let inter = format!("/discord/api/v10/interactions/1/{PATH_TOKEN}/callback");
    let _ = t
        .send(t.req("GET", &hook).body(Body::empty()).unwrap())
        .await;
    let _ = t
        .send(t.req("POST", &inter).body(Body::empty()).unwrap())
        .await;
    let _ = t
        .send(
            t.req("GET", "/discord/api/echo2")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let big = t
        .req("POST", "/discord/up/echo2")
        .header("content-length", "5000")
        .body(Body::empty())
        .unwrap();
    let _ = t.send(big).await;
    let bad = Request::builder()
        .uri("/discord/api/x")
        .header("host", AUTH)
        .header("x-ap-caller-key", "apk_bad")
        .header("authorization", format!("Bot {SENTINEL}"))
        .body(Body::empty())
        .unwrap();
    let _ = t.send(bad).await;
    let text = t.audit_text();
    assert!(!text.is_empty());
    for s in [SENTINEL, PATH_TOKEN, t.key.as_str()] {
        assert!(!text.contains(s), "{s} leaked: {text}");
    }
    assert!(text.contains("<redacted>"));
    assert!(text.contains("\"evidence\""));
    let tr = Trail::new("GET");
    assert!(!format!("{tr:?}").contains(SENTINEL));
}

#[tokio::test]
async fn body_over_declared_cap_is_413() {
    let t = Pt::new("cap").await;
    let r = t
        .req("POST", "/discord/up/echo2")
        .header("content-length", "5000")
        .body(Body::empty())
        .unwrap();
    let (p, b) = t.send(r).await.unwrap();
    assert_eq!(p.status, 413);
    assert_eq!(code(&b), "body_too_large");
    assert_eq!(t.hits(), 0);
}

fn chan_body() -> (
    tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    Body,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    let s = futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx));
    (tx, Body::from_stream(s))
}

#[tokio::test]
async fn stall_after_a_prefix_aborts_with_body_failed_after_send() {
    let t = Pt::new("stall1").await;
    let (tx, body) = chan_body();
    tx.send(Ok(Bytes::from_static(b"abc"))).await.unwrap();
    let r = t
        .req("POST", "/discord/up/echo2")
        .header("transfer-encoding", "chunked")
        .body(body)
        .unwrap();
    assert!(t.send(r).await.is_err());
    let text = t.audit_text();
    assert!(text.contains("body_failed_after_send"), "{text}");
    assert_eq!(text.matches("\"decision\"").count(), 1);
    drop(tx);
}

#[tokio::test]
async fn stall_before_the_first_byte_is_503() {
    let t = Pt::new("stall0").await;
    let (tx, body) = chan_body();
    let r = t
        .req("POST", "/discord/up/echo2")
        .header("transfer-encoding", "chunked")
        .body(body)
        .unwrap();
    let (p, b) = t.send(r).await.unwrap();
    assert_eq!(p.status, 503);
    assert_eq!(decision(&p), "unavailable");
    assert_eq!(code(&b), "body_read_timeout");
    drop(tx);
}

#[tokio::test]
async fn undeclared_over_cap_after_a_prefix_aborts() {
    let t = Pt::new("over1").await;
    let (tx, body) = chan_body();
    tx.send(Ok(Bytes::from(vec![1u8; 600]))).await.unwrap();
    tx.send(Ok(Bytes::from(vec![1u8; 600]))).await.unwrap();
    let r = t
        .req("POST", "/discord/up/echo2")
        .header("transfer-encoding", "chunked")
        .body(body)
        .unwrap();
    assert!(t.send(r).await.is_err());
    assert!(t.audit_text().contains("body_failed_after_send"));
    drop(tx);
}

#[tokio::test]
async fn undeclared_over_cap_before_any_byte_is_413() {
    let t = Pt::new("over0").await;
    let (tx, body) = chan_body();
    tx.send(Ok(Bytes::from(vec![1u8; 2000]))).await.unwrap();
    let r = t
        .req("POST", "/discord/up/echo2")
        .header("transfer-encoding", "chunked")
        .body(body)
        .unwrap();
    let (p, b) = t.send(r).await.unwrap();
    assert_eq!(p.status, 413);
    assert_eq!(code(&b), "body_too_large");
    drop(tx);
}

#[tokio::test]
async fn chunked_body_reaches_upstream_chunked_without_content_length() {
    let t = Pt::new("chunked").await;
    let (tx, body) = chan_body();
    tx.send(Ok(Bytes::from_static(b"hello "))).await.unwrap();
    tx.send(Ok(Bytes::from_static(b"world"))).await.unwrap();
    drop(tx);
    let r = t
        .req("POST", "/discord/up/echo2")
        .header("transfer-encoding", "chunked")
        .body(body)
        .unwrap();
    let (p, b) = t.send(r).await.unwrap();
    assert_eq!(p.status, 200);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["body_len"], 11);
    let names: Vec<&str> = v["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h[0].as_str().unwrap())
        .collect();
    assert!(names.contains(&"transfer-encoding"));
    assert!(!names.contains(&"content-length"));
}

#[tokio::test]
async fn unreachable_upstream_is_503_connect_failed() {
    let t = Pt::new("down").await;
    // Point the route at a closed port by rewriting the policy file.
    let text = std::fs::read_to_string(t._s.path().join("policy.toml")).unwrap();
    let dead = text.replace(&format!("port = {}", t.up.addr.port()), "port = 9");
    std::fs::write(t._s.path().join("policy.toml"), dead).unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (p, b) = t
        .send(t.req("GET", "/discord/api/x").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(p.status, 503);
    assert_eq!(code(&b), "connect_failed");
    assert_eq!(decision(&p), "unavailable");
}

#[cfg(feature = "stage1-probe")]
mod probe_tests {
    use super::*;

    async fn probe(t: &Pt, key: bool, path: &str) -> (http::response::Parts, Bytes) {
        let mut b = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", AUTH)
            .header("content-length", "2");
        if key {
            b = b.header("x-ap-caller-key", t.key.as_str());
        }
        t.send(b.body(Body::from("{}")).unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn probe_needs_a_caller_key() {
        let t = Pt::new("probe-key").await;
        let (p, _) = probe(&t, false, "/__ap_probe/200/1").await;
        assert_eq!(p.status, 401);
        assert_eq!(decision(&p), "rejected");
    }

    #[tokio::test]
    async fn probe_answers_each_status_with_its_decision() {
        let t = Pt::new("probe-status").await;
        for (status, dec) in [
            (200, ""),
            (410, "expired"),
            (423, "denied"),
            (503, "unavailable"),
        ] {
            let (p, _) = probe(&t, true, &format!("/__ap_probe/{status}/1")).await;
            assert_eq!(p.status.as_u16(), status);
            assert_eq!(decision(&p), dec);
            assert!(p.headers.get("retry-after").is_none());
        }
        assert!(t.audit_text().contains("\"event\":\"completed\""));
        assert_eq!(t.hits(), 0);
    }

    #[tokio::test]
    async fn probe_rejects_bad_parameters() {
        let t = Pt::new("probe-bad").await;
        for path in [
            "/__ap_probe/201/1",
            "/__ap_probe/200/7",
            "/__ap_probe/200",
            "/__ap_probe/x/1",
        ] {
            let (p, b) = probe(&t, true, path).await;
            assert_eq!(p.status, 400, "{path}");
            assert_eq!(code(&b), "probe_params");
        }
    }

    #[tokio::test]
    async fn dropping_the_handler_records_client_gone() {
        let t = Pt::new("probe-gone").await;
        let r = Request::builder()
            .method("POST")
            .uri("/__ap_probe/200/10")
            .header("host", AUTH)
            .header("x-ap-caller-key", t.key.as_str())
            .header("content-length", "2")
            .body(Body::from("{}"))
            .unwrap();
        let fut = handle(Arc::clone(&t.app), r);
        let _ = tokio::time::timeout(Duration::from_millis(200), fut).await;
        assert!(t.audit_text().contains("\"event\":\"client_gone\""));
    }
}
