//! Tests for the netfilter gate: the state machine with fake checkers, the refusal, readiness,
//! and the file-polling loop.

use std::sync::Mutex;

use super::*;
use crate::test_support::{buffer_sink, Scratch};

const MAX: Duration = Duration::from_secs(20);

fn ok(tick: &str) -> String {
    format!("tick={tick} state=ok reason=ok\n")
}

fn fail(tick: &str, reason: &str) -> String {
    format!("tick={tick} state=fail reason={reason}\n")
}

fn fresh(text: &str) -> Option<Reading<'_>> {
    Some(Reading {
        text,
        age: Duration::ZERO,
    })
}

#[test]
fn status_lines_parse_and_odd_ones_do_not() {
    assert_eq!(
        parse_status("tick=17-3 state=ok reason=ok\n"),
        Some(Parsed {
            tick: "17-3".into(),
            ok: true,
            reason: "ok".into()
        })
    );
    let p = parse_status("reason=egress_open state=fail tick=9").expect("order is free");
    assert!(!p.ok);
    assert_eq!(p.reason, "egress_open");
    for bad in [
        "",
        "tick=1 state=ok",
        "tick=1 state=maybe reason=ok",
        "tick=1 state=ok reason=ok extra=1",
        "tick=1 tick=2 state=ok reason=ok",
        "tick=1 state=ok reason=has space",
        "tick=1 state=ok reason=a/b",
        "tick=1 state=ok reason=",
        "garbage",
    ] {
        assert_eq!(parse_status(bad), None, "{bad:?}");
    }
    let long = format!("tick={} state=ok reason=ok", "x".repeat(65));
    assert_eq!(parse_status(&long), None);
}

#[test]
fn starts_closed_and_opens_only_when_both_checkers_are_healthy() {
    let t0 = Instant::now();
    let mut g = Guard::new(MAX, t0);
    assert_eq!(g.state(), &GuardState::Unverified("starting".into()));
    // Neither file exists yet.
    assert_eq!(
        g.observe(t0, [None, None]),
        Some(GuardState::Unverified("rules:missing".into()))
    );
    // One checker is healthy, the other is not there: still closed.
    let a = ok("a1");
    assert_eq!(
        g.observe(t0, [fresh(&a), None]),
        Some(GuardState::Unverified("probe:missing".into()))
    );
    let b = ok("b1");
    assert_eq!(
        g.observe(t0, [fresh(&a), fresh(&b)]),
        Some(GuardState::Ready)
    );
    // A repeat reading changes nothing.
    assert_eq!(g.observe(t0, [fresh(&a), fresh(&b)]), None);
}

#[test]
fn a_failing_probe_closes_the_gate_and_recovery_reopens_it() {
    let t0 = Instant::now();
    let mut g = Guard::new(MAX, t0);
    let (r1, p1) = (ok("r1"), ok("p1"));
    assert_eq!(
        g.observe(t0, [fresh(&r1), fresh(&p1)]),
        Some(GuardState::Ready)
    );

    let t1 = t0 + Duration::from_secs(10);
    let (r2, p2) = (ok("r2"), fail("p2", "egress_open"));
    assert_eq!(
        g.observe(t1, [fresh(&r2), fresh(&p2)]),
        Some(GuardState::Failed("probe:egress_open".into()))
    );
    let t2 = t0 + Duration::from_secs(20);
    let (r3, p3) = (fail("r3", "rules_changed"), ok("p3"));
    assert_eq!(
        g.observe(t2, [fresh(&r3), fresh(&p3)]),
        Some(GuardState::Failed("rules:rules_changed".into()))
    );
    let t3 = t0 + Duration::from_secs(30);
    let (r4, p4) = (ok("r4"), ok("p4"));
    assert_eq!(
        g.observe(t3, [fresh(&r4), fresh(&p4)]),
        Some(GuardState::Ready)
    );
}

#[test]
fn a_checker_that_stops_ticking_closes_the_gate_after_max_age() {
    let t0 = Instant::now();
    let mut g = Guard::new(MAX, t0);
    let (r, p) = (ok("r1"), ok("p1"));
    assert_eq!(
        g.observe(t0, [fresh(&r), fresh(&p)]),
        Some(GuardState::Ready)
    );
    // The probe keeps ticking, the rules checker is dead and repeats its last "ok".
    let mut now = t0;
    for i in 2..=10u64 {
        now += Duration::from_secs(2);
        let p = ok(&format!("p{i}"));
        assert_eq!(
            g.observe(now, [fresh(&r), fresh(&p)]),
            None,
            "still within max age at +{i}"
        );
    }
    // 20 s of silence (the limit) is still allowed; past it the gate closes.
    now = t0 + MAX + Duration::from_secs(1);
    let p = ok("p99");
    assert_eq!(
        g.observe(now, [fresh(&r), fresh(&p)]),
        Some(GuardState::Failed("rules:stale".into()))
    );
    // The checker comes back with a new tick.
    let r = ok("r2");
    assert_eq!(
        g.observe(now, [fresh(&r), fresh(&p)]),
        Some(GuardState::Ready)
    );
}

#[test]
fn a_status_file_that_disappears_or_breaks_closes_the_gate() {
    let t0 = Instant::now();
    let mut g = Guard::new(MAX, t0);
    let (r, p) = (ok("r1"), ok("p1"));
    g.observe(t0, [fresh(&r), fresh(&p)]);
    assert_eq!(
        g.observe(t0, [fresh(&r), None]),
        Some(GuardState::Failed("probe:missing".into()))
    );
    assert_eq!(
        g.observe(t0, [fresh(&r), fresh(&p)]),
        Some(GuardState::Ready)
    );
    assert_eq!(
        g.observe(t0, [fresh("not a status line"), fresh(&p)]),
        Some(GuardState::Failed("rules:malformed".into()))
    );
}

#[test]
fn a_file_left_by_a_dead_checker_is_not_fresh_when_the_proxy_starts() {
    let t0 = Instant::now();
    let mut g = Guard::new(MAX, t0);
    let (r, p) = (ok("old-r"), ok("old-p"));
    // Both files hold "ok" but were last written long before this proxy started.
    let aged = |text| {
        Some(Reading {
            text,
            age: Duration::from_secs(600),
        })
    };
    assert_eq!(
        g.observe(t0, [aged(&r), aged(&p)]),
        Some(GuardState::Unverified("rules:stale".into()))
    );
    // A checker that is alive writes a new tick.
    let (r2, p2) = (ok("new-r"), ok("new-p"));
    assert_eq!(
        g.observe(t0, [fresh(&r2), fresh(&p2)]),
        Some(GuardState::Ready)
    );
}

#[test]
fn before_the_first_healthy_reading_a_problem_is_unverified_not_failed() {
    let t0 = Instant::now();
    let mut g = Guard::new(MAX, t0);
    let (r, p) = (fail("r", "rules_missing"), ok("p"));
    let state = g.observe(t0, [fresh(&r), fresh(&p)]).expect("changed");
    assert_eq!(state, GuardState::Unverified("rules:rules_missing".into()));
}

#[test]
fn refusal_is_a_terminal_503_with_fixed_strings_and_an_audit_line() {
    let (audit, buf) = buffer_sink();
    let gate = Gate::new();
    let r = refusal(&gate, &audit).expect("closed at start");
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.headers()["x-ap-decision"], "unavailable");
    assert_eq!(r.headers()["connection"], "close");
    assert_eq!(r.headers()["content-type"], "application/json");
    let line = String::from_utf8(buf.lock().expect("lock").clone()).expect("utf8");
    let v: serde_json::Value = serde_json::from_str(line.trim_end()).expect("json");
    assert_eq!(v["event"], "netfilter");
    assert_eq!(v["decision"], "deny");
    assert_eq!(v["code"], "netfilter_unverified");
    assert_eq!(v["status"], 503);
    assert_eq!(
        v.as_object().expect("object").len(),
        4,
        "no other field: {line}"
    );
    gate.set(GuardState::Ready);
    assert!(refusal(&gate, &audit).is_none());
    gate.set(GuardState::Failed("probe:dns_open".into()));
    assert!(refusal(&gate, &audit).is_some());
}

#[tokio::test]
async fn refusal_body_matches_the_gate_decision_convention() {
    let (audit, _) = buffer_sink();
    let r = refusal(&Gate::new(), &audit).expect("closed");
    let bytes = axum::body::to_bytes(r.into_body(), 1024)
        .await
        .expect("body");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(v["ap_decision"], "unavailable");
    assert_eq!(v["code"], "netfilter_unverified");
}

async fn ready_status(gate: Option<Arc<Gate>>) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let req = http::Request::builder()
        .uri("/admin/v1/ready")
        .body(Body::empty())
        .expect("request");
    let resp = ready_router(gate).oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).expect("json"))
}

#[tokio::test]
async fn readiness_follows_the_gate_and_is_open_when_there_is_no_gate() {
    let (st, v) = ready_status(None).await;
    assert_eq!((st, v["ready"].as_bool()), (StatusCode::OK, Some(true)));

    let gate = Gate::new();
    let (st, v) = ready_status(Some(Arc::clone(&gate))).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        (v["ready"].as_bool(), v["state"].as_str()),
        (Some(false), Some("unverified"))
    );

    gate.set(GuardState::Ready);
    assert_eq!(
        ready_status(Some(Arc::clone(&gate))).await.0,
        StatusCode::OK
    );

    gate.set(GuardState::Failed("rules:stale".into()));
    let (st, v) = ready_status(Some(gate)).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["reason"], "rules:stale");
}

#[tokio::test]
async fn check_ready_exit_status_follows_the_admin_endpoint() {
    let scratch = Scratch::new("ready");
    let sock = scratch.path().join("admin.sock");
    let gate = Gate::new();
    let listener = crate::listener::bind_unix_socket(&sock, 0o600).expect("bind");
    tokio::spawn(crate::session_http::serve_unix(
        listener,
        ready_router(Some(Arc::clone(&gate))),
    ));
    let args = vec![
        "--check-ready".to_string(),
        "--admin-socket".to_string(),
        sock.display().to_string(),
    ];
    let run = |args: Vec<String>| async move {
        tokio::task::spawn_blocking(move || check_ready_main(&args))
            .await
            .expect("join")
    };
    assert_eq!(run(args.clone()).await, 1, "closed gate is not ready");
    gate.set(GuardState::Ready);
    assert_eq!(run(args.clone()).await, 0);
    gate.set(GuardState::Failed("probe:dns_open".into()));
    assert_eq!(run(args).await, 1);
    let missing = vec![
        "--check-ready".to_string(),
        "--admin-socket".to_string(),
        scratch.path().join("absent.sock").display().to_string(),
    ];
    assert_eq!(run(missing).await, 1, "no socket is not ready");
}

/// A fake checker that writes the status file the way the real ones do.
fn write(path: &Path, text: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).expect("write");
    std::fs::rename(&tmp, path).expect("rename");
}

async fn wait_for(gate: &Gate, want: impl Fn(&GuardState) -> bool) -> GuardState {
    for _ in 0..200 {
        let s = gate.state();
        if want(&s) {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "gate never reached the wanted state; now {:?}",
        gate.state()
    );
}

#[tokio::test]
async fn the_poll_loop_opens_closes_and_reopens_with_the_files() {
    let scratch = Scratch::new("monitor");
    let rules = scratch.path().join("rules");
    let probe = scratch.path().join("probe");
    // Interval 0 gives a max age of the 5 s slack, so the test needs no long wait.
    let opts = NetfilterOpts {
        rules_status: rules.clone(),
        probe_status: probe.clone(),
        interval: Duration::ZERO,
    };
    let gate = Gate::new();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = Arc::clone(&seen);
    let task = tokio::spawn(monitor(
        opts,
        Duration::from_millis(20),
        Arc::clone(&gate),
        move |s| {
            log.lock()
                .expect("lock")
                .push(format!("{}:{}", s.name(), s.reason()))
        },
    ));

    // No files: closed.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_ne!(gate.state(), GuardState::Ready);

    write(&rules, &ok("r1"));
    write(&probe, &ok("p1"));
    wait_for(&gate, |s| *s == GuardState::Ready).await;

    // The functional probe starts failing: closed within a poll.
    write(&probe, &fail("p2", "egress_open"));
    let s = wait_for(&gate, |s| matches!(s, GuardState::Failed(_))).await;
    assert_eq!(s, GuardState::Failed("probe:egress_open".into()));

    // The rules checker is killed (its file goes away).
    write(&probe, &ok("p3"));
    wait_for(&gate, |s| *s == GuardState::Ready).await;
    std::fs::remove_file(&rules).expect("remove");
    let s = wait_for(&gate, |s| matches!(s, GuardState::Failed(_))).await;
    assert_eq!(s, GuardState::Failed("rules:missing".into()));

    // And it comes back.
    write(&rules, &ok("r2"));
    wait_for(&gate, |s| *s == GuardState::Ready).await;
    task.abort();

    let log = seen.lock().expect("lock").clone();
    assert_eq!(log.first().map(String::as_str), Some("unverified:starting"));
    assert!(
        log.contains(&"failed:probe:egress_open".to_string()),
        "{log:?}"
    );
    assert!(log.contains(&"failed:rules:missing".to_string()), "{log:?}");
}
