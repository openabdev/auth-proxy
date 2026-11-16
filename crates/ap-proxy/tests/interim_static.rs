//! INTERIM Q1-A path: one surrogate fixed at proxy start, valid for the life of
//! the process, with no per-session revocation (owner-accepted, see
//! `docs/interim-static-session.md`). The Q1-B session plane keeps working next
//! to it and is untouched by it.

mod support;

use ap_client::Surrogate;
use std::process::Stdio;
use std::time::Duration;
use support::*;

fn interim(s: &Surrogate) -> Opts {
    Opts {
        interim_static_sha256: Some(s.sha256_hex()),
        ..Default::default()
    }
}

#[test]
fn the_static_surrogate_works_with_the_real_credential_and_audits_as_interim() {
    let s = Surrogate::generate().unwrap();
    let mut fx = Fixture::new(interim(&s));
    fx.start_proxy();

    let r = fx.get("up", "/v1/echo", s.expose());
    assert_eq!(r.status, 200, "{}", r.text());
    // The upstream got the real credential, not the surrogate.
    let log = fx.upstream_log();
    assert_eq!(log.len(), 1);
    let seen = log[0].to_string();
    assert!(seen.contains(&fx.secret_value("c-up")), "{seen}");
    assert!(!seen.contains(s.expose()), "{seen}");

    let lines = fx.audit_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["decision"], "allow");
    assert_eq!(lines[0]["identity"], "agent-1");
    assert_eq!(lines[0]["session"], "interim-static");
    assert_eq!(lines[0]["generation"], 0);

    // Both credentials of the policy are bound: the second route works too.
    assert_eq!(fx.get("other", "/v1/echo", s.expose()).status, 200);
}

#[test]
fn the_startup_line_labels_the_interim_path_and_nothing_leaks() {
    let s = Surrogate::generate().unwrap();
    let mut fx = Fixture::new(interim(&s));
    fx.start_proxy();
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);
    let (out, err) = fx.read_logs();
    assert!(err.contains("INTERIM static session"), "{err}");
    assert!(err.contains("NO per-session revocation"), "{err}");
    for (name, log) in [("stdout", &out), ("stderr", &err)] {
        assert!(!log.contains(s.expose()), "{name} has the surrogate");
        assert!(!log.contains(&fx.caller_key), "{name} has the caller key");
        assert!(!log.contains("/ap/"), "{name} has the /ap/ prefix");
        assert!(!log.contains(&fx.secret_value("c-up")), "{name}");
    }
}

#[test]
fn without_the_flag_there_is_no_static_session() {
    let s = Surrogate::generate().unwrap();
    let mut fx = Fixture::new(Opts::default());
    fx.start_proxy();
    let r = fx.get("up", "/v1/echo", s.expose());
    assert_eq!((r.status, r.code()), (403, Some("surrogate_unknown")));
    let (_, err) = fx.read_logs();
    assert!(!err.contains("INTERIM"), "{err}");
}

#[test]
fn the_caller_key_the_grants_and_the_surrogate_check_still_apply() {
    let s = Surrogate::generate().unwrap();
    let mut fx = Fixture::new(interim(&s));
    fx.start_proxy();

    // Another surrogate is unknown.
    let other = Surrogate::generate().unwrap();
    let r = fx.get("up", "/v1/echo", other.expose());
    assert_eq!((r.status, r.code()), (403, Some("surrogate_unknown")));

    // Wrong caller key: refused before the surrogate is looked at.
    let wrong = format!("apk_{}", "0".repeat(64));
    let r = fx.request_with_key(
        &wrong,
        "GET",
        "up",
        "/v1/echo",
        &[("Authorization", &format!("Bearer {}", s.expose()))],
        b"",
    );
    assert_eq!((r.status, r.code()), (403, Some("caller_rejected")));

    // A path outside the grant (`/v1/` only) is denied by policy.
    let r = fx.get("up", "/other/echo", s.expose());
    assert_eq!((r.status, r.code()), (403, Some("policy_denied")));
    assert_eq!(fx.upstream_count(), 0, "no refusal reached the upstream");
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_on_the_session_plane_or_admin_socket_ends_the_static_session() {
    let s = Surrogate::generate().unwrap();
    let mut fx = Fixture::new(interim(&s));
    fx.start_proxy();
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);

    // revoke-all on the admin socket drops Q1-B sessions, not the static one.
    let r = fx
        .admin()
        .raw("POST", "/admin/revoke-all", None, None)
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);

    // An authority that takes the lock and resyncs an empty list drops every
    // Q1-B session; the static one is not in that registry.
    let a = fx.client();
    a.hello().await.unwrap();
    a.resync(&[]).await.unwrap();
    a.revoke("interim-static", 0).await.unwrap();
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);

    // It also has no entry in the admin status session count.
    let st = fx
        .admin()
        .raw("GET", "/admin/status", None, None)
        .await
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&st.body).unwrap();
    assert_eq!(j["sessions"], 0);
}

#[test]
fn the_static_session_has_no_lease_or_absolute_ttl() {
    let s = Surrogate::generate().unwrap();
    let mut fx = Fixture::new(Opts {
        session_lease_secs: Some(1),
        absolute_ttl_secs: Some(1),
        authority_lease_secs: Some(3),
        ..interim(&s)
    });
    fx.start_proxy();
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);
    std::thread::sleep(Duration::from_millis(3500));
    assert_eq!(
        fx.get("up", "/v1/echo", s.expose()).status,
        200,
        "still valid after the lease and TTL a Q1-B session would have hit"
    );
}

#[test]
fn a_proxy_restart_needs_no_resync_and_has_no_gap() {
    let s = Surrogate::generate().unwrap();
    let mut fx = Fixture::new(interim(&s));
    fx.start_proxy();
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);
    fx.kill_proxy();
    fx.start_proxy();
    // First request after the restart, no authority and no resync in between.
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn q1b_sessions_still_work_beside_the_static_one() {
    let s = Surrogate::generate().unwrap();
    let mut fx = Fixture::new(interim(&s));
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let q = register(&a, "s1", 1, &["c-up"]).await;
    assert_eq!(fx.get("up", "/v1/echo", q.expose()).status, 200);
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);

    // Q1-B revocation is still synchronous and per session; the static one stays.
    a.revoke("s1", 1).await.unwrap();
    let r = fx.get("up", "/v1/echo", q.expose());
    assert_eq!((r.status, r.code()), (403, Some("surrogate_revoked")));
    assert_eq!(fx.get("up", "/v1/echo", s.expose()).status, 200);
    let audit = fx.audit_lines();
    let sessions: Vec<_> = audit.iter().map(|v| v["session"].clone()).collect();
    assert!(sessions.contains(&"s1".into()) && sessions.contains(&"interim-static".into()));
}

#[test]
fn a_malformed_hash_is_a_startup_failure() {
    let fx = Fixture::new(Opts::default());
    for bad in ["abc", &"AB".repeat(32), &"zz".repeat(32)] {
        let out = fx
            .proxy_command()
            .args(["--interim-static-surrogate-sha256", bad])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("interim-static-surrogate-sha256"), "{err}");
    }
}
