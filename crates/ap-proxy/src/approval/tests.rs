//! The approval plane over real sockets (design stage 2 acceptance 7, 11, 20 and 22): headers on
//! every status, Basic realm, CSRF, escaping, no credential value in a page, concurrent approves,
//! and the two credential domains staying apart.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ap_broker::registry::sha256_hex;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::*;
use crate::listener::approval::{serve_approval, ApprovalLimits};
use crate::passthrough::{self, PtApp};
use crate::test_support::{buffer_sink, caller_key, client_for, start_upstream, Scratch, HOST};

const AUTH: &str = "gate.example.test";
const PW: &str = "approver-password-0001-xxxxxxxxxxxxxxxxxxxx";
const SENTINEL: &str = "SENTINEL-DISCORD-TOKEN-0001";
const PATH_TOKEN: &str = "SENTINEL-PATH-TOKEN-0002";
const HEADERS: [(&str, &str); 6] = [
    (
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'; form-action 'self'",
    ),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("cache-control", "no-store"),
    ("pragma", "no-cache"),
    ("x-content-type-options", "nosniff"),
];

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.body))
    }

    fn result(&self) -> String {
        self.json()["result"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    /// All six design 3.6 headers, with exactly the specified values.
    fn assert_hardened(&self, what: &str) {
        for (n, v) in HEADERS {
            let all: Vec<&str> = self
                .headers
                .iter()
                .filter(|(h, _)| h == n)
                .map(|(_, v)| v.as_str())
                .collect();
            assert_eq!(all, vec![v], "{what}: header {n} in {:?}", self.headers);
        }
    }
}

async fn send(addr: SocketAddr, raw: &str) -> Resp {
    let mut c = TcpStream::connect(addr).await.expect("connect");
    c.write_all(raw.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut buf))
        .await
        .expect("response in time")
        .ok();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {text:?}"));
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Resp {
        status,
        headers,
        body: body.to_string(),
    }
}

fn basic(user: &str, pw: &str) -> String {
    format!(
        "Authorization: Basic {}\r\n",
        STANDARD.encode(format!("{user}:{pw}"))
    )
}

fn request(method: &str, path: &str, extra: &str, body: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: approve.example.test\r\nConnection: close\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

const JSON_ACCEPT: &str = "Accept: application/json\r\n";

struct Env {
    app: Arc<PtApp>,
    addr: SocketAddr,
    key: String,
    audit: Arc<Mutex<Vec<u8>>>,
    up: crate::test_support::Upstream,
    _s: Scratch,
}

impl Env {
    async fn new(tag: &str) -> Env {
        Self::with(tag, Duration::from_millis(1), ApprovalLimits::default()).await
    }

    async fn with(tag: &str, delay: Duration, limits: ApprovalLimits) -> Env {
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
cooldown_secs = 0

[approval]
listen = "127.0.0.1:8444"
user = "owner"
password_sha256 = "{pw}"
public_base_url = "https://approve.example.test"

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
paths = ["/api/"]

[[grant]]
identity = "muse-pilot"
route = "discord"
methods = ["POST"]
decision = "hold"
path_patterns = ["/hold/*", "/webhooks/*/*"]
"#,
            pw = sha256_hex(PW),
            sha = sha256_hex(&key),
            port = up.addr.port(),
        );
        let policy = s.path().join("policy.toml");
        std::fs::write(&policy, &text).unwrap();
        let cfg = ap_core::config::load(&text).expect("valid policy");
        let approval = cfg.approval.clone().expect("approval block");
        let (sink, audit) = buffer_sink();
        let app = PtApp::new(policy, cfg, &text, sink, client_for(&up));
        let state =
            ApprovalApp::build(Arc::clone(&app.hold), &approval, delay, app.policy_source());
        let l = crate::listener::bind_loopback("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve_approval(l, state, limits));
        Env {
            app,
            addr,
            key,
            audit,
            up,
            _s: s,
        }
    }

    fn hold_request(&self, path: &str, body: &'static [u8]) -> http::Request<Body> {
        http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", AUTH)
            .header("x-ap-caller-key", &self.key)
            .header("authorization", format!("Bot {SENTINEL}"))
            .header("content-type", "application/json")
            .header("x-note", "hello-note")
            .header("content-length", body.len())
            .body(Body::from(Bytes::from_static(body)))
            .unwrap()
    }

    /// Hold a request in a task. Returns the task and the new entry's id.
    async fn hold(
        &self,
        path: &str,
        body: &'static [u8],
    ) -> (
        tokio::task::JoinHandle<Option<(http::response::Parts, Bytes)>>,
        String,
    ) {
        let before: Vec<String> = self.app.hold.list().into_iter().map(|v| v.id).collect();
        let app = Arc::clone(&self.app);
        let req = self.hold_request(path, body);
        let h = tokio::spawn(async move {
            match passthrough::handle(app, req).await {
                Ok(resp) => {
                    let (p, b) = resp.into_parts();
                    Some((
                        p,
                        b.collect().await.map(|c| c.to_bytes()).unwrap_or_default(),
                    ))
                }
                Err(_) => None,
            }
        });
        for _ in 0..250 {
            if let Some(v) = self
                .app
                .hold
                .list()
                .iter()
                .find(|v| !before.contains(&v.id))
            {
                return (h, v.id.clone());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("hold never appeared");
    }

    async fn get(&self, path: &str, accept: &str) -> Resp {
        send(
            self.addr,
            &request("GET", path, &format!("{}{accept}", basic("owner", PW)), ""),
        )
        .await
    }

    async fn token(&self, id: &str) -> String {
        let r = self.get(&format!("/pending/{id}"), JSON_ACCEPT).await;
        assert_eq!(r.status, 200, "{}", r.body);
        r.json()["csrf"].as_str().expect("csrf token").to_string()
    }

    async fn post_json(&self, id: &str, action: &str, token: &str) -> Resp {
        let body = format!(r#"{{"csrf":"{token}"}}"#);
        send(
            self.addr,
            &request(
                "POST",
                &format!("/pending/{id}/{action}"),
                &format!("{}Content-Type: application/json\r\n", basic("owner", PW)),
                &body,
            ),
        )
        .await
    }

    async fn approve(&self, id: &str) -> Resp {
        let t = self.token(id).await;
        self.post_json(id, "approve", &t).await
    }

    fn audit_lines(&self) -> Vec<serde_json::Value> {
        String::from_utf8_lossy(&self.audit.lock().unwrap())
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn audit_text(&self) -> String {
        String::from_utf8_lossy(&self.audit.lock().unwrap()).into_owned()
    }

    fn upstream_hits(&self) -> usize {
        self.up.hits.load(Ordering::SeqCst)
    }

    fn public_get(&self, path: &str, extra: &[(&str, &str)]) -> http::Request<Body> {
        let mut b = http::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", AUTH);
        for (n, v) in extra {
            b = b.header(*n, *v);
        }
        b.body(Body::empty()).unwrap()
    }
}

async fn refusal(app: &Arc<PtApp>, req: http::Request<Body>) -> (u16, String, String) {
    let resp = passthrough::handle(Arc::clone(app), req)
        .await
        .expect("answer");
    let (p, b) = resp.into_parts();
    let body = b.collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (
        p.status.as_u16(),
        v["ap_decision"].as_str().unwrap_or_default().to_string(),
        v["code"].as_str().unwrap_or_default().to_string(),
    )
}

// ---------------------------------------------------------------- headers and authentication

#[tokio::test]
async fn every_status_carries_the_six_headers() {
    let env = Env::new("hdr").await;
    let creds = basic("owner", PW);
    let big = "x".repeat(2000);
    let cases: Vec<(u16, String)> = vec![
        (200, request("GET", "/pending", &creds, "")),
        (401, request("GET", "/pending", "", "")),
        (404, request("GET", "/nope", &creds, "")),
        (405, request("DELETE", "/pending", &creds, "")),
        (
            405,
            request(
                "GET",
                &format!("/pending/{}/approve", "a".repeat(32)),
                &creds,
                "",
            ),
        ),
        (
            413,
            request(
                "POST",
                &format!("/pending/{}/approve", "a".repeat(32)),
                &creds,
                &big,
            ),
        ),
        (
            400,
            request(
                "POST",
                &format!("/pending/{}/deny", "a".repeat(32)),
                &format!("{creds}Content-Type: application/json\r\n"),
                "{not json",
            ),
        ),
        (
            403,
            request(
                "POST",
                &format!("/pending/{}/deny", "a".repeat(32)),
                &creds,
                "csrf=nope",
            ),
        ),
    ];
    for (want, raw) in cases {
        let r = send(env.addr, &raw).await;
        assert_eq!(r.status, want, "{raw:?} -> {}", r.body);
        r.assert_hardened(&format!("status {want}"));
    }
}

#[tokio::test]
async fn hardened_headers_hold_for_json_and_html_clients() {
    let env = Env::new("hdr2").await;
    for accept in ["", JSON_ACCEPT] {
        let r = send(env.addr, &request("GET", "/pending", accept, "")).await;
        assert_eq!(r.status, 401);
        r.assert_hardened("401");
    }
}

#[tokio::test]
async fn missing_or_wrong_credentials_get_401_with_a_basic_realm() {
    let env = Env::new("auth").await;
    let wrong = [
        String::new(),
        basic("owner", "wrong"),
        basic("intruder", PW),
        "Authorization: Bearer abc\r\n".to_string(),
        format!("{}{}", basic("owner", PW), basic("owner", PW)),
    ];
    for extra in wrong {
        let r = send(env.addr, &request("GET", "/pending", &extra, "")).await;
        assert_eq!(r.status, 401, "{extra:?}");
        assert_eq!(
            r.header("www-authenticate"),
            Some("Basic realm=\"auth-proxy approval\", charset=\"UTF-8\"")
        );
    }
    assert_eq!(env.get("/pending", "").await.status, 200);
}

#[tokio::test]
async fn an_auth_failure_waits_a_fixed_250_ms() {
    let env = Env::with("delay", FAIL_DELAY, ApprovalLimits::default()).await;
    let t = Instant::now();
    let r = send(
        env.addr,
        &request("GET", "/pending", &basic("owner", "wrong"), ""),
    )
    .await;
    assert_eq!(r.status, 401);
    assert!(
        t.elapsed() >= Duration::from_millis(240),
        "{:?}",
        t.elapsed()
    );
    let t = Instant::now();
    assert_eq!(env.get("/pending", "").await.status, 200);
    assert!(
        t.elapsed() < Duration::from_millis(240),
        "success must not wait"
    );
}

// ---------------------------------------------------------------- page and API

#[tokio::test]
async fn the_page_escapes_a_script_body_and_shows_no_credential() {
    let env = Env::new("page").await;
    let (_h, id) = env
        .hold(
            &format!("/discord/webhooks/123/{PATH_TOKEN}?wait=true"),
            br#"{"content":"<script>alert(1)</script>"}"#,
        )
        .await;
    let page = env.get(&format!("/pending/{id}"), "").await;
    assert_eq!(page.status, 200);
    page.assert_hardened("page");
    assert!(page
        .header("content-type")
        .unwrap()
        .starts_with("text/html"));
    let html = &page.body;
    assert!(!html.contains("<script>"), "{html}");
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    // What the approver is told.
    for want in [
        "POST",
        "discord",
        "/webhooks/123/&lt;redacted&gt;",
        "wait=true",
        "application/json",
        "unknown",
    ] {
        assert!(html.contains(want), "page lacks {want}: {html}");
    }
    assert!(html.contains("<th>authorization</th><td>present (value not shown)</td>"));
    assert!(html.contains("<th>x-note</th><td>hello-note</td>"));
    assert!(!html.contains("x-ap-caller-key"), "stripped header listed");
    // No credential value, no path token, anywhere in the page or in the JSON view.
    let json = env.get(&format!("/pending/{id}"), JSON_ACCEPT).await;
    for text in [
        html.as_str(),
        json.body.as_str(),
        &env.get("/pending", "").await.body,
    ] {
        for secret in [SENTINEL, PATH_TOKEN, env.key.as_str(), PW] {
            assert!(!text.contains(secret), "{secret} leaked");
        }
    }
    let v = json.json();
    assert_eq!(v["state"], "pending");
    assert_eq!(v["connection"], "unknown");
    assert_eq!(v["path"], "/webhooks/123/<redacted>");
    assert_eq!(v["body_len"], 39);
    assert!(v["digest"].as_str().unwrap().len() == 64);
}

#[tokio::test]
async fn a_body_that_is_not_utf8_gets_a_banner() {
    let env = Env::new("lossy").await;
    let (_h, id) = env.hold("/discord/hold/a", b"{\"x\":\"\xff\xfe\"}").await;
    let html = env.get(&format!("/pending/{id}"), "").await.body;
    assert!(html.contains("not valid UTF-8"), "{html}");
    let json = env.get(&format!("/pending/{id}"), JSON_ACCEPT).await.json();
    assert_eq!(json["body_lossy"], true);
}

#[tokio::test]
async fn the_list_shows_pending_entries_without_content() {
    let env = Env::new("list").await;
    let empty = env.get("/pending", JSON_ACCEPT).await.json();
    assert_eq!(empty["pending"].as_array().unwrap().len(), 0);
    let (_h, id) = env
        .hold("/discord/hold/a", br#"{"secret-looking":"body-text"}"#)
        .await;
    let r = env.get("/pending", JSON_ACCEPT).await;
    let v = r.json();
    assert_eq!(v["pending"][0]["id"], id.as_str());
    assert_eq!(v["pending"][0]["method"], "POST");
    assert!(!r.body.contains("body-text"));
    let html = env.get("/pending", "").await.body;
    assert!(html.contains(&format!("href=\"/pending/{id}\"")));
}

// ---------------------------------------------------------------- CSRF

#[tokio::test]
async fn a_post_without_the_csrf_token_is_refused_and_changes_nothing() {
    let env = Env::new("csrf-missing").await;
    let (_h, id) = env.hold("/discord/hold/a", b"{}").await;
    let creds = basic("owner", PW);
    for (extra, body) in [
        ("", "".to_string()),
        ("", "other=1".to_string()),
        ("", "csrf=".to_string()),
        ("Content-Type: application/json\r\n", "{}".to_string()),
        ("", "csrf=not-a-token".to_string()),
    ] {
        let r = send(
            env.addr,
            &request(
                "POST",
                &format!("/pending/{id}/approve"),
                &format!("{creds}{JSON_ACCEPT}{extra}"),
                &body,
            ),
        )
        .await;
        assert_eq!(
            (r.status, r.result().as_str()),
            (403, "csrf_refused"),
            "{body:?}"
        );
    }
    assert_eq!(env.app.hold.state(&id), Some(crate::hold::State::Pending));
    assert_eq!(env.upstream_hits(), 0);
}

#[tokio::test]
async fn a_csrf_token_is_single_use() {
    let env = Env::new("csrf-reuse").await;
    let (_h, a) = env.hold("/discord/hold/a", b"{\"n\":1}").await;
    let (_h2, b) = env.hold("/discord/hold/b", b"{\"n\":2}").await;
    let token = env.token(&a).await;
    // A token for entry A does nothing on entry B, and is spent by the attempt.
    let r = env.post_json(&b, "approve", &token).await;
    assert_eq!((r.status, r.result().as_str()), (403, "csrf_refused"));
    let r = env.post_json(&a, "approve", &token).await;
    assert_eq!(r.status, 403, "the wrong-entry attempt spent the token");
    // A fresh token works once; the same one again is refused.
    let t2 = env.token(&b).await;
    let ok = env.post_json(&b, "deny", &t2).await;
    assert_eq!((ok.status, ok.result().as_str()), (200, "denied"));
    let again = env.post_json(&b, "deny", &t2).await;
    assert_eq!(again.status, 403);
    assert_eq!(env.app.hold.state(&a), Some(crate::hold::State::Pending));
}

#[tokio::test]
async fn the_html_form_flow_works_with_a_form_post() {
    let env = Env::new("form").await;
    let (h, id) = env.hold("/discord/hold/a", b"{}").await;
    let html = env.get(&format!("/pending/{id}"), "").await.body;
    assert!(html.contains(&format!("action=\"/pending/{id}/approve\"")));
    let token = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("token in the form")
        .to_string();
    let r = send(
        env.addr,
        &request(
            "POST",
            &format!("/pending/{id}/approve"),
            &format!(
                "{}Content-Type: application/x-www-form-urlencoded\r\n",
                basic("owner", PW)
            ),
            &format!("csrf={token}"),
        ),
    )
    .await;
    assert_eq!(r.status, 200);
    r.assert_hardened("form result");
    assert!(r.header("content-type").unwrap().starts_with("text/html"));
    assert!(r.body.contains("success"));
    let (p, _) = h.await.unwrap().expect("caller answered");
    assert_eq!(p.status, 200);
    assert_eq!(env.upstream_hits(), 1);
}

// ---------------------------------------------------------------- approve and deny

#[tokio::test]
async fn approve_over_http_sends_exactly_one_upstream_request() {
    let env = Env::new("approve").await;
    let (h, id) = env.hold("/discord/hold/a", br#"{"content":"hi"}"#).await;
    assert_eq!(env.upstream_hits(), 0, "nothing before approval");
    let r = env.approve(&id).await;
    r.assert_hardened("approve");
    assert_eq!((r.status, r.result().as_str()), (200, "success"));
    let (p, body) = h.await.unwrap().expect("caller answered");
    assert_eq!(p.status, 200);
    assert!(String::from_utf8_lossy(&body).contains("x-note"));
    assert_eq!(env.upstream_hits(), 1);
    // The approver's name is in the audit transition.
    let lines = env.audit_lines();
    let approved = lines
        .iter()
        .find(|v| v["transition"] == "approved")
        .expect("approved line");
    assert_eq!(approved["approver"], "owner");
    assert!(!env.audit_text().contains(PW));
}

#[tokio::test]
async fn deny_over_http_answers_the_caller_423_and_sends_nothing() {
    let env = Env::new("deny").await;
    let (h, id) = env.hold("/discord/hold/a", b"{}").await;
    let t = env.token(&id).await;
    let r = env.post_json(&id, "deny", &t).await;
    assert_eq!((r.status, r.result().as_str()), (200, "denied"));
    let (p, body) = h.await.unwrap().expect("caller answered");
    assert_eq!(p.status, 423);
    assert!(String::from_utf8_lossy(&body).contains("human_denied"));
    assert_eq!(env.upstream_hits(), 0);
    let lines = env.audit_lines();
    let denied = lines
        .iter()
        .find(|v| v["transition"] == "denied")
        .expect("denied line");
    assert_eq!(denied["approver"], "owner");
}

#[tokio::test]
async fn two_concurrent_http_approves_make_one_success_and_one_upstream_request() {
    let env = Env::new("concurrent").await;
    let (h, id) = env.hold("/discord/hold/a", b"{}").await;
    let (t1, t2) = (env.token(&id).await, env.token(&id).await);
    let (a, b) = tokio::join!(
        env.post_json(&id, "approve", &t1),
        env.post_json(&id, "approve", &t2)
    );
    let mut got = [(a.status, a.result()), (b.status, b.result())];
    got.sort();
    assert_eq!(
        got,
        [
            (200, "success".to_string()),
            (409, "already_decided".to_string())
        ]
    );
    let (p, _) = h.await.unwrap().expect("caller answered");
    assert_eq!(p.status, 200);
    assert_eq!(env.upstream_hits(), 1);
}

#[tokio::test]
async fn approve_after_each_state_answers_that_state_and_sends_nothing() {
    let env = Env::new("states").await;

    // Denied, then approve.
    let (_h, id) = env.hold("/discord/hold/denied", b"{}").await;
    let t = env.token(&id).await;
    let t_late = env.token(&id).await;
    assert_eq!(env.post_json(&id, "deny", &t).await.status, 200);
    let r = env.post_json(&id, "approve", &t_late).await;
    assert_eq!((r.status, r.result().as_str()), (409, "already_decided"));

    // Expired.
    let (_h, id) = env.hold("/discord/hold/expired", b"{}").await;
    let t = env.token(&id).await;
    assert!(env.app.hold.expire(&id));
    let r = env.post_json(&id, "approve", &t).await;
    assert_eq!((r.status, r.result().as_str()), (410, "expired"));

    // Abandoned: the caller goes away.
    let (h, id) = env.hold("/discord/hold/abandoned", b"{}").await;
    let t = env.token(&id).await;
    h.abort();
    for _ in 0..100 {
        if env.app.hold.state(&id) != Some(crate::hold::State::Pending) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let r = env.post_json(&id, "approve", &t).await;
    assert_eq!((r.status, r.result().as_str()), (410, "gone"));

    // Dropped by a reload.
    let (_h, id) = env.hold("/discord/hold/dropped", b"{}").await;
    let t = env.token(&id).await;
    assert_eq!(env.app.hold.drop_all(), 1);
    let r = env.post_json(&id, "approve", &t).await;
    assert_eq!((r.status, r.result().as_str()), (410, "dropped"));

    // Superseded by an identical retry; the answer names the newest entry.
    let (_h1, old) = env.hold("/discord/hold/same", b"{\"same\":1}").await;
    let t = env.token(&old).await;
    let (_h2, newest) = env.hold("/discord/hold/same", b"{\"same\":1}").await;
    assert_ne!(old, newest);
    let r = env.post_json(&old, "approve", &t).await;
    assert_eq!(r.status, 409);
    assert_eq!(
        r.json(),
        serde_json::json!({"result": "superseded", "newest": newest})
    );
    let page = env.get(&format!("/pending/{old}"), "").await.body;
    assert!(page.contains("Superseded."));
    assert!(page.contains(&format!("href=\"/pending/{newest}\"")));
    assert!(page.contains("disabled") && !page.contains("<form method"));
    let json = env
        .get(&format!("/pending/{old}"), JSON_ACCEPT)
        .await
        .json();
    assert_eq!(
        (json["state"].as_str(), json["newest"].as_str()),
        (Some("superseded"), Some(newest.as_str()))
    );
    assert!(json.get("csrf").is_none(), "no token for a decided entry");

    // Unknown id.
    let unknown = "0".repeat(32);
    assert_eq!(
        env.get(&format!("/pending/{unknown}"), JSON_ACCEPT)
            .await
            .status,
        404
    );

    assert_eq!(env.upstream_hits(), 0, "none of these sent anything");
}

// ---------------------------------------------------------------- two credential domains

#[tokio::test]
async fn the_public_router_has_no_approval_route_even_with_a_valid_key() {
    let env = Env::new("public").await;
    let (_h, id) = env.hold("/discord/hold/a", b"{}").await;
    let key = ("x-ap-caller-key", env.key.as_str());
    let before = env.upstream_hits();
    for path in [
        "/pending".to_string(),
        format!("/pending/{id}"),
        format!("/pending/{id}/approve"),
        format!("/discord/pending/{id}/approve"),
    ] {
        for req in [
            env.public_get(&path, &[key]),
            http::Request::builder()
                .method("POST")
                .uri(&path)
                .header("host", AUTH)
                .header("x-ap-caller-key", &env.key)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        ] {
            let (status, decision, code) = refusal(&env.app, req).await;
            assert_eq!(status, 423, "{path}");
            assert_eq!(decision, "denied");
            assert!(
                code == "route_unknown" || code == "no_grant",
                "{path}: {code}"
            );
        }
    }
    assert_eq!(env.app.hold.state(&id), Some(crate::hold::State::Pending));
    assert_eq!(env.upstream_hits(), before, "zero upstream requests");
}

#[tokio::test]
async fn the_approver_credential_is_refused_on_the_public_listener() {
    let env = Env::new("cross-public").await;
    let basic_value = format!("Basic {}", STANDARD.encode(format!("owner:{PW}")));
    let (_h, id) = env.hold("/discord/hold/a", b"{}").await;
    for req in [
        // Basic approver credentials, no caller key.
        env.public_get("/pending", &[("authorization", basic_value.as_str())]),
        // The approver password used as a caller key, in the header and in the path prefix.
        env.public_get("/pending", &[("x-ap-caller-key", PW)]),
        env.public_get(&format!("/ap/{PW}/discord/api/x"), &[]),
        env.public_get(&format!("/ap/{}/pending/{id}/approve", sha256_hex(PW)), &[]),
    ] {
        let (status, decision, code) = refusal(&env.app, req).await;
        assert_eq!(
            (status, decision.as_str(), code.as_str()),
            (401, "rejected", "caller_rejected")
        );
    }
    assert_eq!(env.app.hold.state(&id), Some(crate::hold::State::Pending));
    assert_eq!(env.upstream_hits(), 0);
}

#[tokio::test]
async fn a_caller_key_is_refused_on_the_approval_listener() {
    let env = Env::new("cross-approval").await;
    let (_h, id) = env.hold("/discord/hold/a", b"{}").await;
    let key = &env.key;
    let key_as_password = basic("owner", key);
    let key_as_user = basic(key, PW);
    let attempts = [
        request(
            "GET",
            "/pending",
            &format!("x-ap-caller-key: {key}\r\n"),
            "",
        ),
        request("GET", &format!("/ap/{key}/pending"), "", ""),
        request("GET", "/pending", &key_as_password, ""),
        request("GET", "/pending", &key_as_user, ""),
        request(
            "GET",
            "/pending",
            &format!("Authorization: Bearer {key}\r\n"),
            "",
        ),
        request(
            "GET",
            "/pending",
            &format!("Authorization: Bot {key}\r\n"),
            "",
        ),
    ];
    for raw in attempts {
        let r = send(env.addr, &raw).await;
        assert_eq!(r.status, 401, "{raw:?}");
        r.assert_hardened("cross");
        assert!(
            !r.body.contains(id.as_str()),
            "a refusal must not list entries"
        );
    }
    // A POST with only the caller key does not reach the table.
    let r = send(
        env.addr,
        &request(
            "POST",
            &format!("/pending/{id}/approve"),
            &format!("x-ap-caller-key: {key}\r\n"),
            "csrf=x",
        ),
    )
    .await;
    assert_eq!(r.status, 401);
    assert_eq!(env.app.hold.state(&id), Some(crate::hold::State::Pending));
    assert_eq!(env.upstream_hits(), 0);
}

// ---------------------------------------------------------------- listener limits

#[tokio::test]
async fn the_post_body_limit_holds_for_a_chunked_body_too() {
    let env = Env::new("chunked").await;
    let chunk = "y".repeat(600);
    let raw = format!(
        "POST /pending/{}/approve HTTP/1.1\r\nHost: a\r\nConnection: close\r\n{}Transfer-Encoding: chunked\r\n\r\n258\r\n{chunk}\r\n258\r\n{chunk}\r\n0\r\n\r\n",
        "a".repeat(32),
        basic("owner", PW)
    );
    let r = send(env.addr, &raw).await;
    assert_eq!(r.status, 413);
    r.assert_hardened("chunked 413");
}

#[tokio::test]
async fn the_connection_cap_closes_the_extra_connection() {
    let env = Env::with(
        "cap",
        Duration::from_millis(1),
        ApprovalLimits {
            max_connections: 2,
            header_read: Duration::from_secs(5),
        },
    )
    .await;
    let mut a = TcpStream::connect(env.addr).await.unwrap();
    let mut b = TcpStream::connect(env.addr).await.unwrap();
    let get = request("GET", "/pending", &basic("owner", PW), "")
        .replace("Connection: close", "Connection: keep-alive");
    for c in [&mut a, &mut b] {
        c.write_all(get.as_bytes()).await.unwrap();
        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    }
    let mut c = TcpStream::connect(env.addr).await.unwrap();
    let _ = c.write_all(get.as_bytes()).await;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
        .await
        .expect("closed in time")
        .unwrap_or(0);
    assert_eq!(n, 0, "the third connection must be closed");
}

#[tokio::test]
async fn a_slow_header_block_is_closed() {
    let env = Env::with(
        "slow",
        Duration::from_millis(1),
        ApprovalLimits {
            max_connections: 4,
            header_read: Duration::from_millis(300),
        },
    )
    .await;
    let mut c = TcpStream::connect(env.addr).await.unwrap();
    c.write_all(b"GET /pend").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
        .await
        .expect("closed in time")
        .unwrap_or(0);
    assert_eq!(n, 0);
    assert_eq!(env.get("/pending", "").await.status, 200);
}

#[tokio::test]
async fn approving_after_the_hold_grant_is_removed_is_refused_and_sends_nothing() {
    let env = Env::new("apr-grant-gone").await;
    let (h, id) = env.hold("/discord/hold/1", br#"{"a":1}"#).await;
    // The owner removes the hold grant. The one-second reload tick has not run yet.
    let policy = env._s.path().join("policy.toml");
    let text = std::fs::read_to_string(&policy).unwrap();
    let cut = text
        .find("[[grant]]\nidentity = \"muse-pilot\"\nroute = \"discord\"\nmethods = [\"POST\"]")
        .unwrap();
    std::fs::write(&policy, &text[..cut]).unwrap();
    let r = env.approve(&id).await;
    assert_eq!(r.status, 410, "{}", r.body);
    assert_eq!(r.json()["result"], "policy_changed");
    let (p, body) = h.await.unwrap().expect("answer");
    assert_eq!(p.status.as_u16(), 503);
    assert!(String::from_utf8_lossy(&body).contains("dropped_on_reload"));
    assert_eq!(env.upstream_hits(), 0);
    assert!(env.audit_text().contains("dropped_on_reload"));
}
