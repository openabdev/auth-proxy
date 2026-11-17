//! Cross-cutting checks for stage 2 (design acceptance 12 and 27), run through the real pipeline.
//!
//! * The sentinel leak suite drives every way a hold can end (approve, deny, expire, abandon,
//!   supersede, reload drop, notification failure, audit failure) with sentinel credentials and
//!   asserts that none of them shows up in the audit stream, any response a caller or the approver
//!   gets, or any notification payload.
//! * The refusal table generates every row of design section 3.5 and checks status,
//!   `X-AP-Decision`, `code` and the two-key body.
//!
//! Panic output and the process journal belong to the real binary; the black-box row PT-29 in
//! `tests/matrix/passthrough.py` covers them.

use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use super::*;
use crate::approval::ApprovalApp;

const PW: &str = "approver-password-0001-xxxxxxxxxxxxxxxxxxxx";
const WRONG_PW: &str = "SENTINEL-WRONG-PASSWORD-0005";
const BODY_MARK: &str = "SENTINEL-BODY-0004";
const QUERY_MARK: &str = "SENTINEL-CHANNEL-0003";

fn approval_tail() -> String {
    format!(
        r#"
[approval]
listen = "127.0.0.1:8444"
user = "owner"
password_sha256 = "{}"
public_base_url = "https://approve.example.test"
"#,
        sha256_hex(PW)
    )
}

// ---------------------------------------------------------------- the leak suite

/// Everything a scenario produced, with what must not appear in it.
struct Leak {
    /// (surface, text, request content may appear). The approval page shows the held content to the
    /// approver on purpose, so only credentials are forbidden there.
    surfaces: Vec<(String, String, bool)>,
    secrets: Vec<String>,
    /// Approval tokens: the approver's own pages carry them, nothing else may.
    csrf: Vec<String>,
}

impl Leak {
    fn new() -> Leak {
        Leak {
            surfaces: Vec::new(),
            secrets: vec![
                SENTINEL.to_string(),
                PATH_TOKEN.to_string(),
                PW.to_string(),
                WRONG_PW.to_string(),
                STANDARD.encode(format!("owner:{PW}")),
            ],
            csrf: Vec::new(),
        }
    }

    fn add(&mut self, name: &str, text: String, content_ok: bool) {
        self.surfaces.push((name.to_string(), text, content_ok));
    }

    fn response(&mut self, name: &str, p: &http::response::Parts, b: &Bytes) {
        let text = format!("{:?} {}", p.headers, String::from_utf8_lossy(b));
        self.add(name, text, false);
    }

    /// Record the audit stream and the notification payloads of one fixture.
    fn fixture(&mut self, name: &str, t: &Ht, n: Option<&MockNotifier>) {
        self.secrets.push(t.key.clone());
        self.secrets.push(t.other_key.clone());
        self.add(&format!("{name}: audit"), t.text(), false);
        if let Some(n) = n {
            self.add(
                &format!("{name}: notify"),
                format!("{:?}", n.calls()),
                false,
            );
        }
    }

    fn check(&self) {
        assert!(
            self.surfaces.len() >= 30,
            "the suite recorded {} surfaces",
            self.surfaces.len()
        );
        for (name, text, content_ok) in &self.surfaces {
            for s in &self.secrets {
                assert!(!text.contains(s.as_str()), "{s} leaked into {name}: {text}");
            }
            assert!(
                !text.contains("/ap/"),
                "a path-form prefix leaked into {name}"
            );
            if !content_ok {
                for s in &self.csrf {
                    assert!(
                        !text.contains(s.as_str()),
                        "a CSRF token leaked into {name}"
                    );
                }
                for s in [BODY_MARK, QUERY_MARK] {
                    assert!(!text.contains(s), "request content {s} leaked into {name}");
                }
            }
        }
    }
}

struct Plane {
    app: Arc<ApprovalApp>,
}

impl Plane {
    fn new(t: &Ht) -> Plane {
        let text = std::fs::read_to_string(&t.policy).unwrap();
        let cfg = ap_core::config::load(&text).expect("policy");
        let approval = cfg.approval.expect("approval block");
        Plane {
            app: ApprovalApp::new(Arc::clone(&t.app.hold), &approval),
        }
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        pw: &str,
        json: bool,
        body: Option<String>,
    ) -> (http::response::Parts, String) {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "approve.example.test")
            .header(
                "authorization",
                format!("Basic {}", STANDARD.encode(format!("owner:{pw}"))),
            );
        if json {
            b = b.header("accept", "application/json");
        }
        let req = if let Some(body) = body {
            b.header("content-type", "application/json")
                .header("content-length", body.len())
                .body(Body::from(body))
        } else {
            b.body(Body::empty())
        }
        .unwrap();
        let resp = crate::approval::handle(Arc::clone(&self.app), req).await;
        let (p, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        (p, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// View an entry every way the plane offers, record it all, and (when `action` is set) decide.
    async fn review(&self, l: &mut Leak, name: &str, id: &str, action: Option<&str>) {
        for (what, path, json) in [
            ("list html", "/pending".to_string(), false),
            ("list json", "/pending".to_string(), true),
            ("page html", format!("/pending/{id}"), false),
        ] {
            let (p, b) = self.call("GET", &path, PW, json, None).await;
            assert_eq!(p.status, 200, "{name} {what}: {b}");
            l.add(
                &format!("{name}: {what}"),
                format!("{:?} {b}", p.headers),
                true,
            );
        }
        let (p, b) = self
            .call("GET", &format!("/pending/{id}"), PW, true, None)
            .await;
        assert_eq!(p.status, 200, "{name}: {b}");
        l.add(
            &format!("{name}: page json"),
            format!("{:?} {b}", p.headers),
            true,
        );
        // A decided entry offers no token.
        let csrf = serde_json::from_str::<serde_json::Value>(&b).unwrap()["csrf"]
            .as_str()
            .map(String::from);
        assert_eq!(csrf.is_some(), action.is_some(), "{name}: token offer");
        l.csrf.extend(csrf.clone());
        // A wrong password gets the same refusal whatever it says.
        let (p, b) = self.call("GET", "/pending", WRONG_PW, true, None).await;
        assert_eq!(p.status, 401);
        l.add(
            &format!("{name}: 401"),
            format!("{:?} {b}", p.headers),
            false,
        );
        if let (Some(action), Some(csrf)) = (action, csrf) {
            let body = format!(r#"{{"csrf":"{csrf}"}}"#);
            let (p, b) = self
                .call(
                    "POST",
                    &format!("/pending/{id}/{action}"),
                    PW,
                    true,
                    Some(body),
                )
                .await;
            assert!(
                [200, 503].contains(&p.status.as_u16()),
                "{name} {action}: {b}"
            );
            l.add(
                &format!("{name}: {action}"),
                format!("{:?} {b}", p.headers),
                true,
            );
            // A repeat with the spent token and an unknown id.
            let body = format!(r#"{{"csrf":"{csrf}"}}"#);
            let (p, b) = self
                .call(
                    "POST",
                    &format!("/pending/{id}/{action}"),
                    PW,
                    true,
                    Some(body),
                )
                .await;
            l.add(
                &format!("{name}: repeat"),
                format!("{:?} {b}", p.headers),
                true,
            );
            let (p, b) = self
                .call(
                    "GET",
                    &format!("/pending/{}", "0".repeat(32)),
                    PW,
                    true,
                    None,
                )
                .await;
            l.add(
                &format!("{name}: unknown id"),
                format!("{:?} {b}", p.headers),
                true,
            );
        }
    }
}

/// A hold request with sentinel credentials, content and a path token, in header or path form.
fn leak_req(t: &Ht, path_form: bool, body_extra: &str) -> Request<Body> {
    let path = format!("/discord/webhooks/1/{PATH_TOKEN}?channel={QUERY_MARK}&{body_extra}");
    let body = format!(r#"{{"content":"{BODY_MARK}","n":"{body_extra}"}}"#);
    let b = if path_form {
        Request::builder()
            .method("POST")
            .uri(format!("/ap/{}{path}", t.key))
            .header("host", AUTH)
            .header("authorization", format!("Bot {SENTINEL}"))
    } else {
        t.builder(&t.key, "POST", &path)
    };
    b.header("content-type", "application/json")
        .header("content-length", body.len())
        .body(Body::from(body))
        .unwrap()
}

async fn finish(
    l: &mut Leak,
    name: &str,
    h: tokio::task::JoinHandle<Result<(http::response::Parts, Bytes), ()>>,
) -> Option<u16> {
    match h.await.unwrap() {
        Ok((p, b)) => {
            l.response(&format!("{name}: caller"), &p, &b);
            Some(p.status.as_u16())
        }
        Err(()) => None,
    }
}

#[tokio::test]
async fn no_sentinel_reaches_any_surface_on_any_hold_path() {
    let mock = Mock::start().await;
    let mut l = Leak::new();

    // Approve, header form and path form, then deny in the other form.
    {
        let n = MockNotifier::new(false);
        let o = Opts {
            notifier: Some(Arc::clone(&n)),
            tail: approval_tail(),
            ..Opts::default()
        };
        let t = Ht::with("leak-approve", &mock.up, o).await;
        let plane = Plane::new(&t);
        for (i, (form, action)) in [(false, "approve"), (true, "deny")].into_iter().enumerate() {
            let h = t.spawn(leak_req(&t, form, &format!("a{i}")));
            let id = t.held(i + 1).await;
            plane
                .review(&mut l, &format!("{action} form={form}"), &id, Some(action))
                .await;
            let s = finish(&mut l, action, h).await;
            assert_eq!(s, Some(if action == "approve" { 200 } else { 423 }));
        }
        assert_eq!(
            mock.recorded().len(),
            1,
            "only the approved request went upstream"
        );
        l.fixture("approve/deny", &t, Some(&n));
    }

    // Expire.
    {
        let n = MockNotifier::new(false);
        let mut o = Opts {
            notifier: Some(Arc::clone(&n)),
            tail: approval_tail(),
            ..Opts::default()
        };
        o.limits.hold = Duration::from_millis(300);
        let t = Ht::with("leak-expire", &mock.up, o).await;
        let h = t.spawn(leak_req(&t, false, "e"));
        let id = t.held(1).await;
        assert_eq!(finish(&mut l, "expire", h).await, Some(410));
        Plane::new(&t)
            .review(&mut l, "expired entry", &id, None)
            .await;
        l.fixture("expire", &t, Some(&n));
    }

    // Abandon (the caller goes away), then supersede.
    {
        let t = Ht::with(
            "leak-abandon",
            &mock.up,
            Opts {
                tail: approval_tail(),
                ..Opts::default()
            },
        )
        .await;
        let plane = Plane::new(&t);
        let h = t.spawn(leak_req(&t, false, "ab"));
        let id = t.held(1).await;
        h.abort();
        until("abandon", || {
            t.app.hold.state(&id) == Some(State::Abandoned)
        })
        .await;
        plane.review(&mut l, "abandoned entry", &id, None).await;

        let first = t.spawn(leak_req(&t, false, "sup"));
        let old = t.held(2).await;
        let second = t.spawn(leak_req(&t, true, "sup"));
        let newest = t.held(3).await;
        assert_ne!(old, newest);
        assert_eq!(finish(&mut l, "superseded", first).await, Some(503));
        plane.review(&mut l, "superseded entry", &old, None).await;
        plane
            .review(&mut l, "newest entry", &newest, Some("deny"))
            .await;
        assert_eq!(finish(&mut l, "supersede newest", second).await, Some(423));
        l.fixture("abandon/supersede", &t, None);
    }

    // Reload drop, then a policy that is gone.
    {
        let t = Ht::with(
            "leak-reload",
            &mock.up,
            Opts {
                tail: approval_tail(),
                ..Opts::default()
            },
        )
        .await;
        let h = t.spawn(leak_req(&t, false, "r"));
        t.held(1).await;
        std::fs::remove_file(&t.policy).unwrap();
        assert_eq!(t.app.reload_tick(), 1);
        assert_eq!(finish(&mut l, "reload", h).await, Some(503));
        let (p, b) = t.send(leak_req(&t, false, "r2")).await.unwrap();
        assert_eq!(p.status, 503);
        l.response("policy unavailable", &p, &b);
        l.fixture("reload", &t, None);
    }

    // Notification failure.
    {
        let n = MockNotifier::new(true);
        let o = Opts {
            notifier: Some(Arc::clone(&n)),
            tail: approval_tail(),
            ..Opts::default()
        };
        let t = Ht::with("leak-notify", &mock.up, o).await;
        let plane = Plane::new(&t);
        let h = t.spawn(leak_req(&t, false, "n"));
        let id = t.held(1).await;
        until("notify_failed", || t.count("notify_failed") == 1).await;
        plane
            .review(&mut l, "notify-failed entry", &id, Some("deny"))
            .await;
        assert_eq!(finish(&mut l, "notify-fail", h).await, Some(423));
        l.fixture("notify-fail", &t, Some(&n));
    }

    // Audit failure before the hold, and between approve and send.
    {
        let sw = Switch::default();
        let o = Opts {
            sink: Some(sw.clone()),
            tail: approval_tail(),
            ..Opts::default()
        };
        let t = Ht::with("leak-audit", &mock.up, o).await;
        let plane = Plane::new(&t);
        sw.fail_all.store(true, Ordering::SeqCst);
        let (p, b) = t.send(leak_req(&t, false, "af")).await.unwrap();
        assert_eq!(code(&b), "audit_unavailable");
        l.response("audit failure before hold", &p, &b);
        sw.fail_all.store(false, Ordering::SeqCst);
        let h = t.spawn(leak_req(&t, false, "af2"));
        let id = t.held(1).await;
        *sw.fail_on.lock().unwrap() = Some("\"forward_started\"".into());
        plane
            .review(&mut l, "audit failure on approve", &id, Some("approve"))
            .await;
        assert_eq!(finish(&mut l, "audit failure between", h).await, Some(503));
        l.fixture("audit-fail", &t, None);
    }

    l.check();
    // A refused forward_started write still lets the connection open, but no request arrives.
    assert_eq!(mock.recorded().len(), 1);
}

#[tokio::test]
async fn a_caller_key_in_every_position_stays_out_of_the_stream() {
    let mock = Mock::start().await;
    let t = Ht::new("leak-key", &mock.up).await;
    let mut l = Leak::new();
    // Both forms at once, a duplicate header, and a path-form key with a bad route.
    let both = t
        .builder(&t.key, "POST", &format!("/ap/{}/discord/hold/ok", t.key))
        .body(Body::empty())
        .unwrap();
    let dup = t
        .builder(&t.key, "GET", "/discord/api/x")
        .header("x-ap-caller-key", t.other_key.as_str())
        .body(Body::empty())
        .unwrap();
    let bad_route = Request::builder()
        .uri(format!("/ap/{}/nope/x", t.key))
        .header("host", AUTH)
        .body(Body::empty())
        .unwrap();
    for (name, req) in [("both", both), ("duplicate", dup), ("bad route", bad_route)] {
        let (p, b) = t.send(req).await.unwrap();
        assert!(p.status.as_u16() >= 400, "{name}");
        l.response(name, &p, &b);
    }
    l.fixture("key", &t, None);
    // Only the content of each surface matters here, not the suite-size guard of `check`.
    for (name, text, _) in &l.surfaces {
        for s in &l.secrets {
            assert!(!text.contains(s.as_str()), "{s} leaked into {name}");
        }
    }
    assert_eq!(mock.hits(), 0);
}

// ---------------------------------------------------------------- the refusal table

struct Rows {
    seen: BTreeSet<String>,
}

impl Rows {
    fn row(
        &mut self,
        name: &str,
        p: &http::response::Parts,
        b: &Bytes,
        status: u16,
        decision_header: &str,
        code_str: &str,
    ) {
        assert_eq!(p.status.as_u16(), status, "{name}: status");
        assert_eq!(decision(p), decision_header, "{name}: X-AP-Decision");
        assert!(
            p.headers.get("retry-after").is_none(),
            "{name}: Retry-After"
        );
        let v: serde_json::Value =
            serde_json::from_slice(b).unwrap_or_else(|_| panic!("{name}: body is not JSON: {b:?}"));
        let obj = v
            .as_object()
            .unwrap_or_else(|| panic!("{name}: not an object"));
        assert_eq!(obj.len(), 2, "{name}: body keys {obj:?}");
        assert_eq!(obj["ap_decision"], decision_header, "{name}: body decision");
        assert_eq!(obj["code"], code_str, "{name}: code");
        let text = String::from_utf8_lossy(b);
        assert!(
            !text.contains(SENTINEL) && !text.contains("apk_"),
            "{name}: body echoes request data"
        );
        self.seen.insert(code_str.to_string());
    }

    async fn send(
        &mut self,
        name: &str,
        t: &Ht,
        req: Request<Body>,
        status: u16,
        d: &str,
        c: &str,
    ) {
        let (p, b) = t
            .send(req)
            .await
            .unwrap_or_else(|()| panic!("{name}: closed"));
        self.row(name, &p, &b, status, d, c);
    }

    async fn joined(
        &mut self,
        name: &str,
        h: tokio::task::JoinHandle<Result<(http::response::Parts, Bytes), ()>>,
        status: u16,
        d: &str,
        c: &str,
    ) {
        let (p, b) = h
            .await
            .unwrap()
            .unwrap_or_else(|()| panic!("{name}: closed"));
        self.row(name, &p, &b, status, d, c);
    }
}

#[tokio::test]
async fn every_row_of_the_outcome_contract_is_generated_through_the_pipeline() {
    let mock = Mock::start().await;
    let mut r = Rows {
        seen: BTreeSet::new(),
    };

    // Rows that need no special fixture.
    let t = Ht::new("rows-plain", &mock.up).await;
    let stranger = caller_key();
    let get = |m: &str, p: &str| t.builder(&t.key, m, p);
    r.send(
        "unknown key",
        &t,
        t.builder(&stranger, "GET", "/discord/api/x")
            .body(Body::empty())
            .unwrap(),
        401,
        "rejected",
        "caller_rejected",
    )
    .await;
    r.send(
        "both sources",
        &t,
        Request::builder()
            .uri(format!("/ap/{}/discord/api/x", t.key))
            .header("host", AUTH)
            .header("x-ap-caller-key", t.key.as_str())
            .body(Body::empty())
            .unwrap(),
        400,
        "denied",
        "caller_key_ambiguous",
    )
    .await;
    r.send(
        "path ambiguity",
        &t,
        get("GET", "/discord/api/../x").body(Body::empty()).unwrap(),
        400,
        "denied",
        "path_ambiguous",
    )
    .await;
    r.send(
        "host",
        &t,
        Request::builder()
            .uri("/discord/api/x")
            .header("host", "evil.test")
            .header("x-ap-caller-key", t.key.as_str())
            .body(Body::empty())
            .unwrap(),
        400,
        "denied",
        "host_rejected",
    )
    .await;
    r.send(
        "framing",
        &t,
        get("GET", "/discord/api/x")
            .header("content-length", "2")
            .header("transfer-encoding", "chunked")
            .body(Body::empty())
            .unwrap(),
        400,
        "denied",
        "framing_refused",
    )
    .await;
    r.send(
        "two authorization headers",
        &t,
        get("GET", "/discord/api/x")
            .header("authorization", "second")
            .body(Body::empty())
            .unwrap(),
        400,
        "denied",
        "authorization_duplicate",
    )
    .await;
    r.send(
        "connect",
        &t,
        Request::builder()
            .method("CONNECT")
            .uri("/discord/api/x")
            .header("host", AUTH)
            .body(Body::empty())
            .unwrap(),
        405,
        "denied",
        "connect_refused",
    )
    .await;
    r.send(
        "upgrade",
        &t,
        get("GET", "/discord/api/x")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap(),
        501,
        "denied",
        "websocket_unsupported",
    )
    .await;
    r.send(
        "no grant",
        &t,
        get("DELETE", "/discord/api/x").body(Body::empty()).unwrap(),
        423,
        "denied",
        "no_grant",
    )
    .await;
    r.send(
        "no grant on a hold route for another method",
        &t,
        get("PATCH", "/discord/hold/ok")
            .body(Body::empty())
            .unwrap(),
        423,
        "denied",
        "no_grant",
    )
    .await;
    r.send(
        "unknown route",
        &t,
        get("GET", "/nope/api/x").body(Body::empty()).unwrap(),
        423,
        "denied",
        "route_unknown",
    )
    .await;
    let held = |f: &dyn Fn(http::request::Builder) -> http::request::Builder, body: String| {
        f(Request::builder()
            .method("POST")
            .uri("/discord/hold/ok")
            .header("host", AUTH)
            .header("x-ap-caller-key", t.key.as_str())
            .header("content-length", body.len()))
        .body(Body::from(body))
        .unwrap()
    };
    let json = |b: http::request::Builder| {
        b.header("content-type", "application/json")
            .header("authorization", "Bot t")
    };
    r.send(
        "held body over the cap",
        &t,
        held(&json, "x".repeat(3000)),
        413,
        "denied",
        "body_too_large",
    )
    .await;
    r.send(
        "content encoding",
        &t,
        held(&|b| json(b).header("content-encoding", "gzip"), "{}".into()),
        400,
        "denied",
        "content_encoding",
    )
    .await;
    r.send(
        "no authorization on a held route",
        &t,
        held(
            &|b| b.header("content-type", "application/json"),
            "{}".into(),
        ),
        400,
        "denied",
        "credential_missing",
    )
    .await;
    r.send(
        "content type",
        &t,
        held(
            &|b| {
                b.header("content-type", "multipart/form-data; boundary=x")
                    .header("authorization", "Bot t")
            },
            "--x--".into(),
        ),
        400,
        "denied",
        "content_type",
    )
    .await;
    {
        // A held body that stalls before it is complete.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(4);
        let body = Body::from_stream(futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx)));
        let req = t
            .builder(&t.key, "POST", "/discord/hold/ok")
            .header("content-type", "application/json")
            .header("transfer-encoding", "chunked")
            .body(body)
            .unwrap();
        r.send(
            "held body stalls",
            &t,
            req,
            503,
            "unavailable",
            "body_read_timeout",
        )
        .await;
        drop(tx);
    }
    // Denied by a person, then superseded.
    {
        let h = t.spawn(t.post("/discord/hold/ok", r#"{"d":1}"#));
        let id = t.held(1).await;
        t.app.hold.deny(&id, "alice");
        r.joined("denied", h, 423, "denied", "human_denied").await;
        let first = t.spawn(t.post("/discord/hold/ok", r#"{"s":1}"#));
        t.held(2).await;
        let second = t.spawn(t.post("/discord/hold/ok", r#"{"s":1}"#));
        let newest = t.held(3).await;
        r.joined("superseded", first, 503, "unavailable", "superseded")
            .await;
        t.app.hold.deny(&newest, "alice");
        second.await.unwrap().unwrap();
    }
    // Approved, then the upstream resets after the request was sent: the caller sees a closed
    // connection and no decision (the last row of section 3.5).
    {
        let h = t.spawn(t.post("/discord/hold/reset-after-read", "{}"));
        let id = t.held(4).await;
        assert_eq!(
            t.app.hold.approve(&id, "alice").await,
            ApproveResult::Success
        );
        assert!(
            h.await.unwrap().is_err(),
            "the connection closes with no response"
        );
    }
    assert_eq!(
        mock.hits(),
        1,
        "only the approved request reached the upstream"
    );

    // Caps, the unavailable rows and reload.
    {
        let mut o = Opts::default();
        o.limits.max_per_identity = 1;
        let t = Ht::with("rows-idcap", &mock.up, o).await;
        let a = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
        t.held(1).await;
        r.send(
            "identity cap",
            &t,
            t.post("/discord/hold/ok", r#"{"n":2}"#),
            503,
            "unavailable",
            "identity_cap",
        )
        .await;
        t.app.hold.drain_pending();
        a.await.unwrap().unwrap();
    }
    {
        let mut o = Opts::default();
        o.limits.max_total = 2;
        let t = Ht::with("rows-full", &mock.up, o).await;
        let a = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
        let b = t.spawn(t.post("/discord/hold/ok", r#"{"n":2}"#));
        t.held(2).await;
        r.send(
            "table full",
            &t,
            t.post_other("/discord/hold/ok", r#"{"n":4}"#),
            503,
            "unavailable",
            "table_full",
        )
        .await;
        std::fs::remove_file(&t.policy).unwrap();
        r.send(
            "policy gone",
            &t,
            t.post("/discord/hold/ok", r#"{"n":5}"#),
            503,
            "unavailable",
            "policy_unavailable",
        )
        .await;
        assert_eq!(t.app.reload_tick(), 2);
        r.joined(
            "dropped on reload",
            a,
            503,
            "unavailable",
            "dropped_on_reload",
        )
        .await;
        b.await.unwrap().unwrap();
    }
    {
        let t = Ht::with("rows-shutdown", &mock.up, Opts::default()).await;
        let a = t.spawn(t.post("/discord/hold/ok", "{}"));
        t.held(1).await;
        assert_eq!(t.app.hold.drain_pending(), 1);
        r.joined("shutdown", a, 503, "unavailable", "shutdown")
            .await;
    }
    // Cooldown after a denial and expiry.
    {
        let mut o = Opts::default();
        o.limits.cooldown = Duration::from_secs(30);
        o.limits.hold = Duration::from_millis(300);
        let t = Ht::with("rows-expire", &mock.up, o).await;
        r.send(
            "expired",
            &t,
            t.post("/discord/hold/ok", "{}"),
            410,
            "expired",
            "expired",
        )
        .await;
        r.send(
            "cooldown",
            &t,
            t.post("/discord/hold/ok", "{}"),
            503,
            "unavailable",
            "cooldown",
        )
        .await;
    }
    // The audit log is down.
    {
        let sw = Switch::default();
        let o = Opts {
            sink: Some(sw.clone()),
            ..Opts::default()
        };
        let t = Ht::with("rows-audit", &mock.up, o).await;
        sw.fail_all.store(true, Ordering::SeqCst);
        r.send(
            "audit down",
            &t,
            t.post("/discord/hold/ok", "{}"),
            503,
            "unavailable",
            "audit_unavailable",
        )
        .await;
    }
    // The upstream refuses the connection after approval.
    {
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let o = Opts {
            port: Some(dead),
            ..Opts::default()
        };
        let t = Ht::with("rows-connect", &mock.up, o).await;
        let h = t.spawn(t.post("/discord/hold/ok", "{}"));
        let id = t.held(1).await;
        assert_eq!(
            t.app.hold.approve(&id, "alice").await,
            ApproveResult::ConnectFailed
        );
        r.joined("connect failed", h, 503, "unavailable", "connect_failed")
            .await;
    }

    // Every code listed in design section 3.5 was produced and checked.
    let want: BTreeSet<String> = [
        "human_denied",
        "no_grant",
        "route_unknown",
        "caller_rejected",
        "caller_key_ambiguous",
        "path_ambiguous",
        "host_rejected",
        "framing_refused",
        "authorization_duplicate",
        "credential_missing",
        "content_encoding",
        "content_type",
        "connect_refused",
        "websocket_unsupported",
        "body_too_large",
        "expired",
        "policy_unavailable",
        "table_full",
        "identity_cap",
        "cooldown",
        "superseded",
        "shutdown",
        "dropped_on_reload",
        "body_read_timeout",
        "connect_failed",
        "audit_unavailable",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(r.seen, want);
}
