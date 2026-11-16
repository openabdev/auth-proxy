//! Q1-B behavior of the session plane, against the real binary: leases,
//! synchronous revocation, resync after a proxy restart, the statuses of the
//! design doc's table, the socket modes, and what the process listens on.

mod support;

use ap_client::{
    Authority, AuthorityConfig, Backoff, Client, ClientError, Registration, RenewOutcome,
    SessionRef, Surrogate,
};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::*;

fn sref(session: &str, generation: u64) -> SessionRef {
    SessionRef {
        session: session.into(),
        generation,
    }
}

fn reg(session: &str, generation: u64, s: &Surrogate) -> Registration {
    Registration::new(session, generation, s, &["c-up"])
}

fn api_status(e: ClientError) -> (u16, String) {
    match e {
        ClientError::Api { status, code, .. } => (status, code),
        other => panic!("expected an API error, got {other}"),
    }
}

async fn status_json(fx: &Fixture) -> serde_json::Value {
    let r = fx
        .admin()
        .raw("GET", "/admin/status", None, None)
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    serde_json::from_slice(&r.body).unwrap()
}

async fn post(a: &Client, body: &str) -> (u16, serde_json::Value) {
    let tok = a.token();
    let r = a
        .raw(
            "POST",
            "/v1/sessions",
            tok.as_deref(),
            Some(body.as_bytes()),
        )
        .await
        .unwrap();
    (
        r.status,
        serde_json::from_slice(&r.body).unwrap_or_default(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_is_synchronous_and_idempotent() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let a = fx.client();
    assert_eq!(a.hello().await.unwrap(), 90);
    let s = register(&a, "s1", 1, &["c-up"]).await;
    let r = fx.get("up", "/v1/echo", s.expose());
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(fx.upstream_count(), 1);

    a.revoke("s1", 1).await.unwrap();
    let r = fx.get("up", "/v1/echo", s.expose());
    assert_eq!((r.status, r.code()), (403, Some("surrogate_revoked")));
    assert_eq!(
        fx.upstream_count(),
        1,
        "nothing reached the upstream after revoke"
    );
    // 204 also when the session is unknown, and on a repeat.
    a.revoke("s1", 1).await.unwrap();
    a.revoke("never-registered", 7).await.unwrap();

    // The same session and generation can be registered again with a new surrogate.
    let s2 = register(&a, "s1", 1, &["c-up"]).await;
    assert_eq!(fx.get("up", "/v1/echo", s2.expose()).status, 200);
    assert_eq!(
        fx.get("up", "/v1/echo", s.expose()).code(),
        Some("surrogate_revoked")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn renewal_is_capped_at_the_absolute_ttl() {
    let mut fx = Fixture::new(Opts {
        absolute_ttl_secs: Some(3),
        session_lease_secs: Some(2),
        ..Default::default()
    });
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let t0 = Instant::now();
    let s = register(&a, "s1", 1, &["c-up"]).await;

    // Renewing keeps it alive past the 2 s lease...
    while t0.elapsed() < Duration::from_millis(2500) {
        let r = a.renew(&[sref("s1", 1)]).await.unwrap();
        assert!(r.unknown.is_empty());
        assert_eq!(r.lease_secs, 2);
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);

    // ... but never past the 3 s absolute TTL.
    tokio::time::sleep(Duration::from_millis(3300).saturating_sub(t0.elapsed())).await;
    let r = a.renew(&[sref("s1", 1)]).await.unwrap();
    assert_eq!(
        r.unknown,
        vec![sref("s1", 1)],
        "renew must not revive a session past its TTL"
    );
    let r = fx.get("up", "/v1/echo", s.expose());
    assert_eq!((r.status, r.code()), (403, Some("surrogate_expired")));
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_restart_then_resync_keeps_the_same_surrogate_and_dropped_stay_dropped() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let cfg = AuthorityConfig {
        renew_every: Duration::from_millis(200),
        backoff: Backoff {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(200),
            deadline: Some(Duration::from_secs(10)),
        },
    };
    let auth = Authority::connect(fx.session_sock(), cfg).await.unwrap();
    let keep = auth.register("keep", 1, &["c-up"]).await.unwrap();
    let dropped = auth.register("dropped", 1, &["c-up"]).await.unwrap();
    auth.revoke("dropped", 1).await.unwrap();
    assert_eq!(fx.get("up", "/v1/echo", keep.expose()).status, 200);
    assert_eq!(fx.get("up", "/v1/echo", dropped.expose()).status, 403);
    assert_eq!(auth.live_sessions(), vec![sref("keep", 1)]);

    // A crashed proxy leaves its socket files behind; the new one replaces them.
    fx.kill_proxy();
    fx.start_proxy();
    let before = fx.upstream_count();
    // In the gap every surrogate is unknown, the CLI's included.
    let r = fx.get("up", "/v1/echo", keep.expose());
    assert_eq!((r.status, r.code()), (403, Some("surrogate_unknown")));

    // The authority's next renew sees the session listed as unknown and resends the full list.
    assert_eq!(auth.renew_once().await.unwrap(), RenewOutcome::Resynced);
    let r = fx.get("up", "/v1/echo", keep.expose());
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(fx.upstream_count(), before + 1);
    // The revoked session was not in the list, so it stays dropped.
    let r = fx.get("up", "/v1/echo", dropped.expose());
    assert_eq!((r.status, r.code()), (403, Some("surrogate_unknown")));
    assert_eq!(status_json(&fx).await["sessions"], 1);

    // With the renew loop running, a second restart heals itself within a few intervals.
    let auth = Arc::new(auth);
    let task = tokio::spawn(auth.clone().run_renew_loop());
    fx.kill_proxy();
    fx.start_proxy();
    let end = Instant::now() + Duration::from_secs(8);
    loop {
        if fx.get("up", "/v1/echo", keep.expose()).status == 200 {
            break;
        }
        assert!(
            Instant::now() < end,
            "the renew loop did not resync after a restart"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    task.abort();
    assert_eq!(fx.get("up", "/v1/echo", dropped.expose()).status, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lapsed_authority_that_comes_back_wins_hello_again_and_resyncs() {
    let mut fx = Fixture::new(Opts {
        authority_lease_secs: Some(3),
        ..Default::default()
    });
    fx.start_proxy();
    let cfg = AuthorityConfig {
        renew_every: Duration::from_secs(30),
        backoff: Backoff {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(200),
            deadline: Some(Duration::from_secs(10)),
        },
    };
    let auth = Authority::connect(fx.session_sock(), cfg).await.unwrap();
    let s = auth.register("s1", 1, &["c-up"]).await.unwrap();
    // The authority was stalled past its lease (nobody else took the lock).
    tokio::time::sleep(Duration::from_millis(3400)).await;
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 403);
    assert_eq!(auth.renew_once().await.unwrap(), RenewOutcome::Reacquired);
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn max_sessions_is_429_and_a_repeat_registration_is_idempotent() {
    let mut fx = Fixture::new(Opts {
        max_sessions: Some(2),
        ..Default::default()
    });
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let (s1, s2, s3) = (
        Surrogate::generate().unwrap(),
        Surrogate::generate().unwrap(),
        Surrogate::generate().unwrap(),
    );
    a.register(&reg("a", 1, &s1)).await.unwrap();
    a.register(&reg("b", 1, &s2)).await.unwrap();
    let e = a.register(&reg("c", 1, &s3)).await.unwrap_err();
    assert_eq!(api_status(e), (429, "too_many_sessions".into()));
    // The same registration again is a renewal, not a new session.
    a.register(&reg("a", 1, &s1)).await.unwrap();
    assert_eq!(status_json(&fx).await["sessions"], 2);
    // A slot frees up on revoke.
    a.revoke("a", 1).await.unwrap();
    a.register(&reg("c", 1, &s3)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn same_session_with_another_hash_is_409() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let (s1, s2) = (
        Surrogate::generate().unwrap(),
        Surrogate::generate().unwrap(),
    );
    a.register(&reg("s", 1, &s1)).await.unwrap();
    a.register(&reg("s", 1, &s1)).await.unwrap();
    let e = a.register(&reg("s", 1, &s2)).await.unwrap_err();
    assert_eq!(api_status(e), (409, "session_conflict".into()));
    // Another generation is another session.
    a.register(&reg("s", 2, &s2)).await.unwrap();
    // A hash cannot be bound twice.
    let e = a.register(&reg("t", 1, &s1)).await.unwrap_err();
    assert_eq!(api_status(e).0, 409);
    // The refused registrations changed nothing: s1 still works, s2 is the generation-2 one.
    assert_eq!(fx.get("up", "/v1/echo", s1.expose()).status, 200);
    assert_eq!(fx.get("up", "/v1/echo", s2.expose()).status, 200);
    assert_eq!(status_json(&fx).await["sessions"], 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_registrations_are_400_and_change_nothing() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let h = "ab".repeat(32);
    let body = |session: &str, gen: &str, hash: &str, creds: &str| {
        format!(
            r#"{{"session":"{session}","generation":{gen},"surrogate_sha256":"{hash}","credentials":{creds}}}"#
        )
    };
    let too_many: Vec<String> = (0..17).map(|i| format!("\"c{i}\"")).collect();
    let cases: Vec<(&str, String, u16)> = vec![
        (
            "space in session",
            body("bad session", "1", &h, r#"["c-up"]"#),
            400,
        ),
        ("empty session", body("", "1", &h, r#"["c-up"]"#), 400),
        (
            "129-char session",
            body(&"s".repeat(129), "1", &h, r#"["c-up"]"#),
            400,
        ),
        ("slash in session", body("a/b", "1", &h, r#"["c-up"]"#), 400),
        (
            "negative generation",
            body("s", "-1", &h, r#"["c-up"]"#),
            400,
        ),
        (
            "fractional generation",
            body("s", "1.5", &h, r#"["c-up"]"#),
            400,
        ),
        (
            "uppercase hash",
            body("s", "1", &h.to_uppercase(), r#"["c-up"]"#),
            400,
        ),
        ("63-char hash", body("s", "1", &h[..63], r#"["c-up"]"#), 400),
        ("no credentials", body("s", "1", &h, "[]"), 400),
        (
            "17 credentials",
            body("s", "1", &h, &format!("[{}]", too_many.join(","))),
            400,
        ),
        (
            "duplicate credential",
            body("s", "1", &h, r#"["c-up","c-up"]"#),
            400,
        ),
        (
            "unknown field",
            format!(
                r#"{{"session":"s","generation":1,"surrogate_sha256":"{h}","credentials":["c-up"],"x":1}}"#
            ),
            400,
        ),
        (
            "missing field",
            r#"{"session":"s","generation":1,"credentials":["c-up"]}"#.to_string(),
            400,
        ),
        ("not JSON", "not json".into(), 400),
        (
            "credential not defined",
            body("s", "1", &h, r#"["nope"]"#),
            403,
        ),
    ];
    for (label, b, want) in cases {
        let (st, j) = post(&a, &b).await;
        assert_eq!(st, want, "{label}: {j}");
        assert!(j["error"].is_string(), "{label}: {j}");
    }
    assert_eq!(
        status_json(&fx).await["sessions"],
        0,
        "a refused registration registered something"
    );

    // A resync list is validated whole: one bad entry applies nothing, and the
    // answer names the entry.
    let s_keep = Surrogate::generate().unwrap();
    a.register(&reg("keep", 1, &s_keep)).await.unwrap();
    let good_new = reg("new", 1, &Surrogate::generate().unwrap());
    let bad = Registration {
        credentials: vec!["nope".into()],
        ..reg("bad", 1, &Surrogate::generate().unwrap())
    };
    let keep_reg = reg("keep", 1, &s_keep);
    let e = a.resync(&[good_new.clone(), bad]).await.unwrap_err();
    let ClientError::Api {
        status, message, ..
    } = &e
    else {
        panic!("{e}")
    };
    assert_eq!(*status, 403);
    assert!(message.contains("entry 1"), "{message}");
    assert_eq!(
        status_json(&fx).await["sessions"],
        1,
        "a partly bad resync applied something"
    );
    assert_eq!(fx.get("up", "/v1/echo", s_keep.expose()).status, 200);
    // Duplicate entries are rejected too.
    let e = a
        .resync(&[keep_reg.clone(), keep_reg.clone()])
        .await
        .unwrap_err();
    assert_eq!(e.status(), Some(400), "{e}");
    // A good list replaces the registry: `keep` stays, `new` is added.
    let ok = a.resync(&[keep_reg, good_new]).await.unwrap();
    assert_eq!((ok.registered, ok.dropped), (2, 0));
    // And an empty list drops everything.
    let ok = a.resync(&[]).await.unwrap();
    assert_eq!((ok.registered, ok.dropped), (0, 2));
    assert_eq!(fx.get("up", "/v1/echo", s_keep.expose()).status, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn bodies_over_1_mib_are_413_and_register_nothing() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let tok = a.token();
    let big = vec![b' '; 1024 * 1024 + 1];
    for (m, p) in [
        ("POST", "/v1/sessions"),
        ("PUT", "/v1/sessions"),
        ("POST", "/v1/renew"),
    ] {
        let r = a.raw(m, p, tok.as_deref(), Some(&big)).await.unwrap();
        assert_eq!(r.status, 413, "{m} {p}");
    }
    assert_eq!(status_json(&fx).await["sessions"], 0);
    // The authority is still usable on a new connection.
    register(&a, "s", 1, &["c-up"]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_socket_status_and_revoke_all() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let s1 = register(&a, "s1", 1, &["c-up"]).await;
    let s2 = register(&a, "s2", 1, &["c-up"]).await;
    let j = status_json(&fx).await;
    assert_eq!(j["sessions"], 2);
    assert_eq!(j["authority_live"], true);
    assert_eq!(j["policy"], "ok");
    assert_eq!(j["identity"], "agent-1");

    let r = fx
        .admin()
        .raw("POST", "/admin/revoke-all", None, None)
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&r.body).unwrap()["revoked"],
        2
    );
    for s in [&s1, &s2] {
        assert_eq!(
            fx.get("up", "/v1/echo", s.expose()).code(),
            Some("surrogate_revoked")
        );
    }
    assert_eq!(status_json(&fx).await["sessions"], 0);
    // No admin call returns a credential or a token.
    let text = String::from_utf8_lossy(
        &fx.admin()
            .raw("GET", "/admin/status", None, None)
            .await
            .unwrap()
            .body,
    )
    .into_owned();
    assert!(!text.contains("apt_") && !text.contains(&fx.secret_value("c-up")));
    assert_eq!(
        fx.admin()
            .raw("GET", "/admin/revoke-all", None, None)
            .await
            .unwrap()
            .status,
        405
    );
    assert_eq!(
        fx.admin()
            .raw("GET", "/admin/credentials", None, None)
            .await
            .unwrap()
            .status,
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_session_socket_has_exactly_the_five_calls_and_nothing_else() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let tok = a.token();
    let t = tok.as_deref();
    // F1: there is no resolve endpoint, and the admin calls are not on this socket.
    for (m, p, want) in [
        ("POST", "/v1/resolve", 404),
        ("GET", "/v1/resolve", 404),
        ("GET", "/admin/status", 404),
        ("POST", "/admin/revoke-all", 404),
        ("GET", "/v1/sessions", 405),
        ("DELETE", "/v1/sessions", 405),
        ("GET", "/v1/hello", 405),
        ("DELETE", "/v1/sessions/a/not-a-number", 400),
        ("DELETE", "/v1/sessions/a", 404),
        ("GET", "/", 404),
    ] {
        let r = a.raw(m, p, t, None).await.unwrap();
        assert_eq!(r.status, want, "{m} {p}");
    }
    // And the admin socket does not serve the session plane.
    let r = fx
        .admin()
        .raw("POST", "/v1/hello", None, Some(b"{}"))
        .await
        .unwrap();
    assert_eq!(r.status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn socket_modes_and_a_second_proxy_on_a_live_socket() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let mode = |p: std::path::PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(fx.session_sock()), 0o660);
    assert_eq!(mode(fx.admin_sock()), 0o600);

    // A second proxy over the same sockets: exit code 2, and the first is untouched.
    let out = fx.proxy_command().output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("live"), "{err}");
    assert!(fx.proxy_alive());
    fx.client().hello().await.unwrap();
}

/// "Proxy binds no TCP port other than the one loopback listener."
#[tokio::test(flavor = "multi_thread")]
async fn exactly_one_tcp_listener_on_loopback() {
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    register(&a, "s", 1, &["c-up"]).await;
    let pid = fx.proxy_pid().to_string();
    let out = std::process::Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid, "-iTCP", "-sTCP:LISTEN", "-Fn"])
        .output();
    let Ok(out) = out else {
        eprintln!("lsof is not installed: listener check skipped");
        return;
    };
    let names: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.strip_prefix('n'))
        .map(String::from)
        .collect();
    assert_eq!(
        names,
        vec![format!("127.0.0.1:{}", fx.port)],
        "TCP listeners of the proxy"
    );
}

#[test]
fn startup_refuses_a_non_loopback_listener() {
    let fx = Fixture::new(Opts::default());
    for listen in [
        "0.0.0.0:18999",
        "192.168.1.5:18999",
        "[::]:18999",
        "127.0.0.1:0",
    ] {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_auth-proxy"));
        cmd.args(["--policy", &fx.policy_path().to_string_lossy()])
            .args(["--secrets-dir", &fx.secrets_dir().to_string_lossy()])
            .args(["--listen", listen])
            .args(["--session-socket", &fx.session_sock().to_string_lossy()])
            .args(["--admin-socket", &fx.admin_sock().to_string_lossy()])
            .args(["--state-dir", &fx.state_dir().to_string_lossy()]);
        let out = cmd.output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{listen}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("loopback"), "{listen}: {err}");
        assert!(
            !fx.session_sock().exists(),
            "no socket may be bound before the listener check"
        );
    }
}
