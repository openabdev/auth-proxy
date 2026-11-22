//! The Muse async poll mode end to end (`docs/design/muse-async-poll.md`), on the hold-path
//! fixture. Every secret here is a synthetic sentinel.

use super::*;
use serde_json::Value;

const ASYNC: &str = "hold_mode = \"async\"";

fn async_opts(extra: &str) -> Opts {
    Opts {
        route_extra: ASYNC.to_string(),
        extra: extra.to_string(),
        ..Opts::default()
    }
}

async fn async_ht(tag: &str, up: &Upstream) -> Ht {
    Ht::with(tag, up, async_opts("")).await
}

/// What a 202 carried.
struct Admitted {
    id: String,
    token: String,
}

impl Ht {
    async fn submit(&self, path: &str, body: &str) -> Admitted {
        let (p, b) = self.send(self.post(path, body)).await.unwrap();
        assert_eq!(p.status, 202, "{}", String::from_utf8_lossy(&b));
        assert!(p.headers.get("x-ap-decision").is_none());
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["status"], "pending");
        let text = String::from_utf8_lossy(&b).into_owned();
        for secret in [SENTINEL, self.key.as_str(), body] {
            assert!(!text.contains(secret), "the 202 echoed {secret}");
        }
        let id = v["request_id"].as_str().unwrap().to_string();
        assert_eq!(self.held(1).await, id);
        Admitted {
            id,
            token: v["poll_token"].as_str().unwrap().to_string(),
        }
    }

    async fn poll(&self, token: &str, query: &str) -> (u16, Value) {
        let uri = if query.is_empty() {
            format!("/poll/{token}")
        } else {
            format!("/poll/{token}?{query}")
        };
        // No Authorization and no caller key: the token is the only credential.
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", AUTH)
            .body(Body::empty())
            .unwrap();
        let (p, b) = self.send(req).await.unwrap();
        (p.status.as_u16(), serde_json::from_slice(&b).unwrap())
    }

    async fn poll_until(&self, token: &str, status: &str) -> Value {
        for _ in 0..250 {
            let (code, v) = self.poll(token, "").await;
            assert_eq!(code, 200);
            if v["status"] == status {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("poll never reached {status}");
    }

    /// Nothing the audit stream holds may name a poll token or its hash.
    fn assert_token_not_audited(&self, token: &str) {
        let t = self.text();
        assert!(
            !t.contains(token),
            "the poll token reached the audit stream"
        );
        assert!(
            !t.contains(&sha256_hex(token)),
            "the token hash reached the audit stream"
        );
        self.assert_clean();
    }
}

#[tokio::test]
async fn approved_request_is_sent_and_the_poll_reports_discord_status_and_body() {
    let mock = Mock::start().await;
    let t = async_ht("async-ok", &mock.up).await;
    let a = t.submit("/discord/hold/ok", r#"{"content":"hi"}"#).await;
    assert_eq!(a.token.len(), 32);
    // Pending, and nothing has gone upstream.
    let (code, v) = t.poll(&a.token, "").await;
    assert_eq!((code, v["status"].as_str()), (200, Some("pending")));
    assert_eq!(v["request_id"], a.id);
    assert_eq!(mock.hits(), 0);
    assert_eq!(
        t.app.hold.approve(&a.id, "alice").await,
        ApproveResult::Success
    );
    let v = t.poll_until(&a.token, "approved_and_sent").await;
    assert_eq!(v["discord_status"], 200);
    assert_eq!(v["body"], "ok");
    assert_eq!(v["truncated"], false);
    assert_eq!(v["request_id"], a.id);
    assert_eq!(mock.recorded().len(), 1);
    assert_eq!(
        t.transitions(),
        ["held", "approved", "forward_started", "completed"]
    );
    t.assert_token_not_audited(&a.token);
}

#[tokio::test]
async fn a_long_wait_returns_as_soon_as_the_request_is_sent() {
    let mock = Mock::start().await;
    let t = async_ht("async-wait", &mock.up).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    let id = a.id.clone();
    let table = Arc::clone(&t.app.hold);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        table.approve(&id, "alice").await;
    });
    let t0 = Instant::now();
    let (code, v) = t.poll(&a.token, "wait=20").await;
    assert_eq!(
        (code, v["status"].as_str()),
        (200, Some("approved_and_sent"))
    );
    assert!(t0.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn a_large_discord_body_is_cut_at_64_kib() {
    let mock = Mock::start().await;
    let t = async_ht("async-big", &mock.up).await;
    let a = t.submit("/discord/hold/big", "{}").await;
    t.app.hold.approve(&a.id, "alice").await;
    let v = t.poll_until(&a.token, "approved_and_sent").await;
    assert_eq!(v["truncated"], true);
    assert_eq!(v["body"].as_str().unwrap().len(), 64 * 1024);
}

#[tokio::test]
async fn a_non_200_discord_status_is_still_approved_and_sent() {
    let mock = Mock::start().await;
    let t = async_ht("async-418", &mock.up).await;
    let a = t.submit("/discord/hold/teapot", "{}").await;
    t.app.hold.approve(&a.id, "alice").await;
    let v = t.poll_until(&a.token, "approved_and_sent").await;
    assert_eq!(v["discord_status"], 418);
    assert_eq!(v["body"], "short and stout");
}

#[tokio::test]
async fn denied_request_polls_as_denied_and_sends_nothing() {
    let mock = Mock::start().await;
    let t = async_ht("async-deny", &mock.up).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    t.app.hold.deny(&a.id, "alice");
    let v = t.poll_until(&a.token, "denied").await;
    assert_eq!(v.as_object().unwrap().len(), 2);
    assert_eq!(mock.hits(), 0);
    assert_eq!(t.transitions(), ["held", "denied"]);
    t.assert_token_not_audited(&a.token);
}

#[tokio::test]
async fn unapproved_entry_expires_after_async_hold_secs() {
    let mock = Mock::start().await;
    let mut o = async_opts("");
    o.route_extra.push_str("\nasync_hold_secs = 5");
    let t = Ht::with("async-expire", &mock.up, o).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    let (_, v) = t.poll(&a.token, "").await;
    assert_eq!(v["status"], "pending");
    let (code, v) = t.poll(&a.token, "wait=10").await;
    assert_eq!((code, v["status"].as_str()), (200, Some("expired")));
    assert_eq!(t.transitions(), ["held", "expired"]);
    assert_eq!(mock.hits(), 0);
    // A late approve finds nothing to approve.
    assert_eq!(
        t.app.hold.approve(&a.id, "alice").await,
        ApproveResult::Expired
    );
}

#[tokio::test]
async fn policy_reload_drops_a_pending_entry() {
    let mock = Mock::start().await;
    let t = async_ht("async-drop", &mock.up).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    assert_eq!(t.app.hold.drop_all(), 1);
    let v = t.poll_until(&a.token, "dropped").await;
    assert_eq!(v.as_object().unwrap().len(), 2);
    assert_eq!(t.count("dropped_on_reload"), 1);
}

#[tokio::test]
async fn start_claim_failure_before_any_byte_is_dropped_with_the_existing_audit_code() {
    let mock = Mock::start().await;
    let o = Opts {
        tail: pilot_tail("2026-12-20"),
        ..async_opts("")
    };
    let mut t = Ht::with("async-claim", &mock.up, o).await;
    let clock = ManualClock::new(PILOT_LAST_DAY);
    PtApp::set_clock(&mut t.app, Arc::new(clock.clone()));
    let (p, b) = t
        .send(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)))
        .await
        .unwrap();
    assert_eq!(p.status, 202);
    let token = serde_json::from_slice::<Value>(&b).unwrap()["poll_token"]
        .as_str()
        .unwrap()
        .to_string();
    let id = t.held(1).await;
    // The pilot window closes between admission and the approve: the claim refuses.
    clock.set(PILOT_REFUSED);
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::PolicyChanged
    );
    let (code, v) = t.poll(&token, "").await;
    assert_eq!((code, v["status"].as_str()), (200, Some("dropped")));
    assert_eq!(t.count("dropped_on_reload"), 1);
    assert_eq!(t.count("forward_started"), 0);
    assert!(mock.recorded().is_empty());
    t.assert_token_not_audited(&token);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approved_just_before_shutdown_is_refused_at_the_claim_and_polls_as_dropped() {
    let mock = Mock::start().await;
    let t = async_ht("async-shutdown", &mock.up).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    let gate = Gate::new();
    t.app.pause.set_after_approve(Arc::clone(&gate));
    let table = Arc::clone(&t.app.hold);
    let id = a.id.clone();
    let approve = tokio::spawn(async move { table.approve(&id, "alice").await });
    tokio::time::timeout(Duration::from_secs(5), gate.arrived())
        .await
        .unwrap();
    t.app.hold.drain_pending();
    gate.release();
    assert_eq!(approve.await.unwrap(), ApproveResult::ApprovedButAbandoned);
    t.poll_until(&a.token, "dropped").await;
    assert_eq!(t.count("forward_started"), 0);
    assert!(mock.recorded().is_empty());
}

#[tokio::test]
async fn connect_failure_is_send_failed_and_writes_no_forward_started() {
    let mock = Mock::start().await;
    // Nothing listens on this port.
    let free = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let o = Opts {
        port: Some(free),
        ..async_opts("")
    };
    let t = Ht::with("async-connect", &mock.up, o).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    t.app.hold.approve(&a.id, "alice").await;
    let v = t.poll_until(&a.token, "send_failed").await;
    assert_eq!(v.as_object().unwrap().len(), 2);
    assert_eq!(t.count("connect_failed"), 1);
    assert_eq!(t.count("forward_started"), 0);
}

#[tokio::test]
async fn a_failed_forward_started_write_is_send_failed() {
    let raw = Raw::start().await;
    let sw = Switch::default();
    let o = Opts {
        sink: Some(sw.clone()),
        ..async_opts("")
    };
    let t = Ht::with("async-fs-audit", &raw.up, o).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    *sw.fail_on.lock().unwrap() = Some("\"forward_started\"".into());
    t.app.hold.approve(&a.id, "alice").await;
    t.poll_until(&a.token, "send_failed").await;
    assert_eq!(t.count("audit_unavailable"), 1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(raw.bytes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reset_after_the_request_was_sent_is_send_unknown_never_dropped() {
    let mock = Mock::start().await;
    let t = async_ht("async-reset", &mock.up).await;
    let a = t.submit("/discord/hold/reset-after-read", "{}").await;
    t.app.hold.approve(&a.id, "alice").await;
    let v = t.poll_until(&a.token, "send_unknown").await;
    assert_eq!(v["error_class"], "reset");
    assert_eq!(mock.recorded().len(), 1);
    assert_eq!(t.count("forward_started"), 1);
    assert_eq!(t.count("completed"), 0);
    t.assert_token_not_audited(&a.token);
}

#[tokio::test]
async fn no_answer_within_the_request_deadline_is_send_unknown_timeout() {
    let mock = Mock::start().await;
    let t = Ht::with(
        "async-timeout",
        &mock.up,
        async_opts("request_deadline_secs = 1"),
    )
    .await;
    let a = t.submit("/discord/hold/stall", "{}").await;
    t.app.hold.approve(&a.id, "alice").await;
    let (code, v) = t.poll(&a.token, "wait=10").await;
    assert_eq!(code, 200);
    assert_eq!(v["status"], "send_unknown");
    assert_eq!(v["error_class"], "timeout");
}

#[tokio::test]
async fn a_stalled_response_body_is_send_unknown_timeout() {
    let mock = Mock::start().await;
    let t = Ht::with(
        "async-stall-body",
        &mock.up,
        async_opts("upstream_idle_secs = 1"),
    )
    .await;
    let a = t.submit("/discord/hold/stall-body", "{}").await;
    t.app.hold.approve(&a.id, "alice").await;
    let (_, v) = t.poll(&a.token, "wait=10").await;
    assert_eq!(v["status"], "send_unknown");
    assert_eq!(v["error_class"], "timeout");
}

#[tokio::test]
async fn unknown_token_and_ended_window_give_the_same_404_and_headers_do_not_matter() {
    let mock = Mock::start().await;
    let mut t = async_ht("async-404", &mock.up).await;
    let clock = ManualClock::new(5_000);
    PtApp::set_clock(&mut t.app, Arc::new(clock.clone()));
    let a = t.submit("/discord/hold/ok", "{}").await;
    t.app.hold.deny(&a.id, "alice");
    t.poll_until(&a.token, "denied").await;
    clock.advance(59);
    assert_eq!(t.poll(&a.token, "").await.0, 200);
    clock.advance(1);
    let ended = t.poll(&a.token, "").await;
    let unknown = t.poll("00000000000000000000000000000000", "").await;
    assert_eq!(ended.0, 404);
    assert_eq!(ended, unknown);
    // Whatever headers a caller sends, the unknown token gets the same answer.
    let req = Request::builder()
        .method("GET")
        .uri("/poll/00000000000000000000000000000000")
        .header("host", AUTH)
        .header("x-ap-caller-key", t.key.as_str())
        .header("authorization", format!("Bot {SENTINEL}"))
        .body(Body::empty())
        .unwrap();
    let (p, b) = t.send(req).await.unwrap();
    assert_eq!(p.status, 404);
    assert_eq!(serde_json::from_slice::<Value>(&b).unwrap(), unknown.1);
    // A method other than GET is the same 404.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/poll/{}", a.token))
        .header("host", AUTH)
        .body(Body::empty())
        .unwrap();
    assert_eq!(t.send(req).await.unwrap().0.status, 404);
}

#[tokio::test]
async fn wait_parameter_is_validated_through_the_listener_path() {
    let mock = Mock::start().await;
    let t = async_ht("async-wait-param", &mock.up).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    for q in ["wait=abc", "wait=-1", "wait=1.5"] {
        let known = t.poll(&a.token, q).await;
        let unknown = t.poll("ffffffffffffffffffffffffffffffff", q).await;
        assert_eq!(known.0, 400, "{q}");
        assert_eq!(known, unknown, "{q} must not reveal the token");
    }
    // Missing and over-cap are accepted. A missing wait does not wait.
    let t0 = Instant::now();
    assert_eq!(t.poll(&a.token, "").await.1["status"], "pending");
    assert!(t0.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn restart_loses_pending_entries_and_their_polls_are_404() {
    let mock = Mock::start().await;
    let t = async_ht("async-restart-a", &mock.up).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    assert_eq!(t.poll(&a.token, "").await.0, 200);
    // A new process: a new app over the same policy has an empty table and store.
    let t2 = async_ht("async-restart-b", &mock.up).await;
    assert_eq!(t2.poll(&a.token, "").await.0, 404);
    assert_eq!(t2.app.hold.pending_len(), 0);
}

#[tokio::test]
async fn the_poll_token_cannot_approve_deny_or_change_state() {
    let mock = Mock::start().await;
    let t = async_ht("async-readonly", &mock.up).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    // The token and the request id in every shape a caller might try.
    for uri in [
        format!("/poll/{}/approve", a.token),
        format!("/poll/{}?approve=1&decision=approved", a.token),
        format!("/approve/{}", a.token),
        format!("/pending/{}/approve", a.token),
    ] {
        for method in ["GET", "POST", "PUT", "DELETE"] {
            let req = Request::builder()
                .method(method)
                .uri(&uri)
                .header("host", AUTH)
                .body(Body::empty())
                .unwrap();
            let _ = t.send(req).await;
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(t.app.hold.state(&a.id), Some(State::Pending));
    assert_eq!(mock.hits(), 0);
    assert_eq!(t.transitions(), ["held"]);
}

#[tokio::test]
async fn a_failed_held_write_refuses_before_any_entry_or_notification() {
    let mock = Mock::start().await;
    let sw = Switch::default();
    let n = MockNotifier::new(false);
    let o = Opts {
        sink: Some(sw.clone()),
        notifier: Some(Arc::clone(&n)),
        ..async_opts("")
    };
    let t = Ht::with("async-held-fail", &mock.up, o).await;
    *sw.fail_on.lock().unwrap() = Some("\"held\"".into());
    let (p, b) = t.send(t.post("/discord/hold/ok", "{}")).await.unwrap();
    assert_eq!(p.status, 503);
    assert_eq!(code(&b), "audit_unavailable");
    assert_eq!(t.app.hold.pending_len(), 0);
    assert_eq!(t.app.polls.pending_len(), 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        n.calls().is_empty(),
        "a notification went out without an entry"
    );
    assert_eq!(mock.hits(), 0);
    // No token was issued.
    assert!(!String::from_utf8_lossy(&b).contains("poll_token"));
}

#[tokio::test]
async fn admission_refusals_keep_their_codes_after_the_held_record_and_issue_no_token() {
    let mock = Mock::start().await;
    let mut o = async_opts("");
    o.limits.max_per_identity = 1;
    let t = Ht::with("async-caps", &mock.up, o).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    // Async mode does not dedupe: an identical second request is refused by the cap, not merged.
    let (p, b) = t.send(t.post("/discord/hold/ok", "{}")).await.unwrap();
    assert_eq!(
        (p.status.as_u16(), code(&b).as_str()),
        (503, "identity_cap")
    );
    assert!(!String::from_utf8_lossy(&b).contains("poll_token"));
    assert_eq!(
        t.count("held"),
        2,
        "the held record comes before the checks"
    );
    // The refused request's id has a terminal record with the refusal's code and 503.
    let refused_id = t.held(2).await;
    assert_ne!(refused_id, a.id);
    let term: Vec<_> = t
        .lines()
        .into_iter()
        .filter(|v| v["request_id"] == refused_id.as_str() && v["transition"] != "held")
        .collect();
    assert_eq!(term.len(), 1, "{term:?}");
    assert_eq!(term[0]["code"], "identity_cap");
    assert_eq!(term[0]["status"], 503);
    assert_eq!(t.app.hold.state(&a.id), Some(State::Pending));
    assert_eq!(t.app.hold.pending_len(), 1);
}

#[tokio::test]
async fn identical_requests_are_independent_entries_with_their_own_tokens() {
    let mock = Mock::start().await;
    let n = MockNotifier::new(false);
    let o = Opts {
        notifier: Some(Arc::clone(&n)),
        ..async_opts("")
    };
    let t = Ht::with("async-indep", &mock.up, o).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    let (p, b) = t.send(t.post("/discord/hold/ok", "{}")).await.unwrap();
    assert_eq!(p.status, 202);
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_ne!(v["poll_token"], a.token);
    assert_ne!(v["request_id"], a.id);
    assert_eq!(t.app.hold.pending_len(), 2);
    assert_eq!(t.count("superseded"), 0);
    calls_reach(&n, 2).await;
    assert_eq!(t.poll(&a.token, "").await.1["status"], "pending");
}

#[tokio::test]
async fn the_blocking_mode_is_the_default_and_has_no_poll_route() {
    let mock = Mock::start().await;
    let t = Ht::new("async-default-off", &mock.up).await;
    // Same request as before: held on the caller's connection, answered when decided.
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!((p.status.as_u16(), &b[..]), (200, &b"ok"[..]));
    // `/poll/...` is just an unauthenticated request in blocking mode.
    let req = Request::builder()
        .method("GET")
        .uri("/poll/abcdef")
        .header("host", AUTH)
        .body(Body::empty())
        .unwrap();
    let (p, _) = t.send(req).await.unwrap();
    assert_eq!(p.status, 401);
}

#[tokio::test]
async fn rapid_polls_just_return_the_current_status() {
    let mock = Mock::start().await;
    let t = async_ht("async-rapid", &mock.up).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    for _ in 0..40 {
        let (code, v) = t.poll(&a.token, "").await;
        assert_eq!((code, v["status"].as_str()), (200, Some("pending")));
    }
    assert_eq!(t.app.hold.state(&a.id), Some(State::Pending));
}

/// A second held route on the same policy: another port, so its own `[[route]]`.
fn second_route(port: u16) -> String {
    format!(
        "\n[[route]]\nname = \"other\"\nhost = \"{HOST}\"\nport = {port}\nmode = \"passthrough\"\n\n[[grant]]\nidentity = \"muse-pilot\"\nroute = \"other\"\nmethods = [\"POST\"]\ndecision = \"hold\"\npath_patterns = [\"/hold/*\"]\n"
    )
}

#[tokio::test]
async fn a_second_held_route_stays_blocking_while_the_muse_route_is_async() {
    let mock = Mock::start().await;
    let mut o = async_opts("");
    o.tail = second_route(mock.up.addr.port().wrapping_add(1).max(1024));
    let t = Ht::with("async-two-routes", &mock.up, o).await;
    // The async route answers 202 at once.
    let a = t.submit("/discord/hold/ok", "{}").await;
    // The other route holds the caller's connection until it is decided, with an X-AP-Decision answer.
    let first = t.spawn(t.post("/other/hold/ok", "{}"));
    let id1 = t.held(2).await;
    assert_ne!(id1, a.id);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!first.is_finished());
    t.app.hold.deny(&id1, "alice");
    let (p1, _) = first.await.unwrap().unwrap();
    assert_eq!(p1.status.as_u16(), 423);
    // And the async entry is untouched.
    assert_eq!(t.poll(&a.token, "").await.1["status"], "pending");
}

#[tokio::test]
async fn shutdown_waits_for_a_started_forward_and_a_cut_after_start_is_send_unknown() {
    let mock = Mock::start().await;
    let t = async_ht("async-shutdown", &mock.up).await;
    let a = t.submit("/discord/hold/stall", "{}").await;
    t.app.hold.approve(&a.id, "alice").await;
    for _ in 0..250 {
        if t.count("forward_started") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(t.count("forward_started"), 1);
    // Shutdown closes the table; the started forward is not told to stop and the wait covers it.
    t.app.hold.drain_pending();
    let waited = tokio::time::timeout(Duration::from_millis(400), t.app.async_tasks.idle()).await;
    assert!(
        waited.is_err(),
        "the wait did not cover the started forward"
    );
    assert_eq!(t.poll(&a.token, "").await.1["status"], "pending");
    // The wait ran out: the cut ends it as send_unknown, with the existing code, not dropped.
    t.app.async_tasks.cut();
    tokio::time::timeout(Duration::from_secs(2), t.app.async_tasks.idle())
        .await
        .expect("tasks ended");
    let v = t.poll(&a.token, "").await.1;
    assert_eq!(v["status"], "send_unknown");
    assert_eq!(v["error_class"], "reset");
    let end: Vec<_> = t
        .lines()
        .into_iter()
        .filter(|v| v["request_id"] == a.id.as_str() && v["transition"] == "completed")
        .collect();
    assert_eq!(end.len(), 1);
    assert_eq!(end[0]["code"], "upstream_reset");
    assert_eq!(t.count("abandoned_after_approve"), 0);
}

#[tokio::test]
async fn a_cut_before_forward_started_is_dropped() {
    let mock = Mock::start().await;
    let t = async_ht("async-cut-early", &mock.up).await;
    let a = t.submit("/discord/hold/ok", "{}").await;
    t.app.async_tasks.cut();
    tokio::time::timeout(Duration::from_secs(2), t.app.async_tasks.idle())
        .await
        .expect("tasks ended");
    assert_eq!(t.poll(&a.token, "").await.1["status"], "dropped");
    assert_eq!(mock.hits(), 0);
}
