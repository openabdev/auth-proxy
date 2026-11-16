//! Owner condition (a): the `hello` race after an authority container restart.
//!
//! In a real pod the authority is the runtime container's PID 1: when it dies,
//! every process in the container (every agent-UID shell, any orphan) dies with
//! it, and the next `hello` can only come from the restarted PID 1, which sends
//! it before any session exists. The proxy's part of that is the 90 s lock:
//! while the dead authority's lease is live, nobody can take it; when it lapses,
//! the sessions of the dead authority are revoked and the first `hello` wins.
//!
//! These tests run the real binary with the authority lease shortened to 3 s
//! (the minimum; the defaults 90/30 s are pinned by a constants test in
//! ap-broker). "Authority dies" is simulated by the client going silent.
//!
//! The real-pod version (kill the runtime container with the proxy up, confirm
//! no orphan survives, fresh PID 1 wins after 90 s) is in the pre-release
//! checklist: it needs a cluster.

mod support;

use ap_client::{Backoff, Client, ClientError, Registration, SessionRef, Surrogate};
use std::time::{Duration, Instant};
use support::*;

const LEASE: u64 = 3;

fn opts() -> Opts {
    Opts {
        authority_lease_secs: Some(LEASE),
        ..Default::default()
    }
}

fn backoff() -> Backoff {
    Backoff {
        initial: Duration::from_millis(100),
        max: Duration::from_millis(200),
        deadline: Some(Duration::from_secs(10)),
    }
}

fn sref(session: &str, generation: u64) -> SessionRef {
    SessionRef {
        session: session.into(),
        generation,
    }
}

fn assert_surrogate_gone(fx: &Fixture, s: &Surrogate) {
    let before = fx.upstream_count();
    let r = fx.get("up", "/v1/echo", s.expose());
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(
        matches!(
            r.code(),
            Some("surrogate_revoked" | "surrogate_unknown" | "surrogate_expired")
        ),
        "{:?}",
        r.code()
    );
    assert_eq!(
        fx.upstream_count(),
        before,
        "a refused request reached the upstream"
    );
}

/// Two clients race for the lock with retry and backoff. Exactly one wins; the
/// loser keeps getting 409. Returns (winner client, loser client, instant won).
async fn race(a: Client, b: Client) -> (Client, Client, Instant) {
    let (ca, cb) = (a.clone(), b.clone());
    let mut ha = tokio::spawn(async move { ca.hello_retry(backoff()).await });
    let mut hb = tokio::spawn(async move { cb.hello_retry(backoff()).await });
    let which = tokio::select! {
        r = &mut ha => { r.unwrap().expect("client a won"); 0 }
        r = &mut hb => { r.unwrap().expect("client b won"); 1 }
    };
    let (winner, loser, mut loser_task) = if which == 0 { (a, b, hb) } else { (b, a, ha) };
    let won_at = Instant::now();
    // The loser is still retrying: it cannot also win.
    let still = tokio::time::timeout(Duration::from_millis(800), &mut loser_task).await;
    match still {
        Err(_) => loser_task.abort(),
        Ok(r) => assert!(
            r.unwrap().is_err(),
            "both clients won the authority lock (two tokens)"
        ),
    }
    assert!(loser.token().is_none(), "the loser must not hold a token");
    (winner, loser, won_at)
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_race_after_authority_restart() {
    let mut fx = Fixture::new(opts());
    fx.start_proxy();

    // Authority A, the runtime's PID 1: hello, one session, one renew.
    let a = fx.client();
    assert_eq!(a.hello().await.unwrap(), LEASE);
    let a_token = a.token().unwrap();
    let s1 = register(&a, "sess-1", 1, &["c-up"]).await;
    assert_eq!(fx.get("up", "/v1/echo", s1.expose()).status, 200);
    a.renew(&[sref("sess-1", 1)]).await.unwrap();
    let last_renew = Instant::now();
    // ... and A dies: from here on it sends nothing.

    // An orphan (agent-UID process that survived; no token) tries to take the
    // lock, and to act on the plane: all refused while A's lease is live.
    let orphan = fx.client();
    let e = orphan.hello().await.unwrap_err();
    assert!(e.is_authority_active(), "orphan hello: {e}");
    assert_eq!(e.status(), Some(409));
    let reg = Registration::new("evil", 1, &Surrogate::generate().unwrap(), &["c-up"]);
    orphan.set_token(Some(format!("apt_{}", "0".repeat(64))));
    assert!(orphan.register(&reg).await.unwrap_err().is_unauthorized());
    assert!(orphan.renew(&[]).await.unwrap_err().is_unauthorized());
    assert!(orphan
        .revoke("sess-1", 1)
        .await
        .unwrap_err()
        .is_unauthorized());
    assert!(orphan.resync(&[]).await.unwrap_err().is_unauthorized());
    orphan.set_token(None);
    let raw = orphan
        .raw("POST", "/v1/sessions", None, Some(b"{}"))
        .await
        .unwrap();
    assert_eq!(raw.status, 401, "no token at all");
    // A's own session keeps working until the lease lapses.
    assert_eq!(fx.get("up", "/v1/echo", s1.expose()).status, 200);
    assert_eq!(fx.upstream_count(), 2);

    // The fresh runtime (PID 1 of the restarted container) and a second
    // would-be authority race with retry and backoff.
    let fresh = fx.client();
    let rival = fx.client();
    let (winner, loser, won_at) = race(fresh, rival).await;
    let waited = won_at.duration_since(last_renew);
    assert!(
        waited >= Duration::from_millis(2900),
        "the lock was taken {waited:?} after the last renew; it must hold for the {LEASE} s lease"
    );
    assert!(waited < Duration::from_secs(6), "took {waited:?}");

    // The lock is taken again: a further hello is refused, A's token is dead.
    assert!(loser.hello().await.unwrap_err().is_authority_active());
    assert!(a
        .renew(&[sref("sess-1", 1)])
        .await
        .unwrap_err()
        .is_unauthorized());
    assert!(a.register(&reg).await.unwrap_err().is_unauthorized());
    assert!(a.revoke("sess-1", 1).await.unwrap_err().is_unauthorized());
    assert_ne!(winner.token().unwrap(), a_token);

    // A's session died with A, with nothing sent upstream.
    assert_surrogate_gone(&fx, &s1);

    // The new authority works.
    let s2 = register(&winner, "sess-2", 1, &["c-up"]).await;
    assert_eq!(fx.get("up", "/v1/echo", s2.expose()).status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_race_with_a_proxy_restart_in_the_middle() {
    let mut fx = Fixture::new(opts());
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    let a_token = a.token().unwrap();
    let reg_surrogate = Surrogate::generate().unwrap();
    let reg = Registration::new("sess-1", 1, &reg_surrogate, &["c-up"]);
    a.register(&reg).await.unwrap();
    assert_eq!(fx.get("up", "/v1/echo", reg_surrogate.expose()).status, 200);

    // The proxy is killed and restarted; only the authority token's hash was
    // persisted (proxy-private state dir).
    fx.kill_proxy();
    fx.start_proxy();
    let state = std::fs::read_to_string(fx.state_dir().join("authority.json")).unwrap();
    assert!(state.contains("token_sha256") && !state.contains(&a_token));

    // The lock is live for one authority lease from the restart: an orphan's
    // hello is refused although the proxy has no sessions at all.
    let orphan = fx.client();
    assert!(orphan.hello().await.unwrap_err().is_authority_active());
    // The proxy forgot the sessions: requests in the gap are refused.
    assert_eq!(
        fx.get("up", "/v1/echo", reg_surrogate.expose()).code(),
        Some("surrogate_unknown")
    );

    // A's token is still good: its renew lists the session as unknown, and the
    // full-list resync brings the same surrogate back.
    let r = a.renew(&[sref("sess-1", 1)]).await.unwrap();
    let last_renew = Instant::now();
    assert_eq!(r.unknown, vec![sref("sess-1", 1)]);
    assert_eq!(
        a.resync(std::slice::from_ref(&reg))
            .await
            .unwrap()
            .registered,
        1
    );
    assert_eq!(fx.get("up", "/v1/echo", reg_surrogate.expose()).status, 200);

    // A dies after the restart. The lock still holds for the lease, then the
    // fresh runtime wins and A's session is revoked.
    let e = orphan.hello().await.unwrap_err();
    assert!(e.is_authority_active(), "{e}");
    let fresh = fx.client();
    fresh.hello_retry(backoff()).await.unwrap();
    let waited = Instant::now().duration_since(last_renew);
    assert!(
        waited >= Duration::from_millis(2900),
        "lock lapsed after {waited:?}"
    );
    assert!(a.renew(&[]).await.unwrap_err().is_unauthorized());
    assert_surrogate_gone(&fx, &reg_surrogate);
    assert!(
        fresh.register(&reg).await.is_ok(),
        "new authority can register"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_after_a_proxy_restart_lapses_one_lease_after_the_restart() {
    let mut fx = Fixture::new(opts());
    fx.start_proxy();
    let a = fx.client();
    a.hello().await.unwrap();
    fx.kill_proxy();
    fx.start_proxy();
    let restarted = Instant::now();

    // A is silent: the persisted lock holds for one lease from the restart,
    // not from the (unknown) last renew.
    let orphan = fx.client();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(orphan.hello().await.unwrap_err().is_authority_active());
    let fresh = fx.client();
    fresh.hello_retry(backoff()).await.unwrap();
    let waited = Instant::now().duration_since(restarted);
    assert!(
        waited >= Duration::from_millis(2300) && waited < Duration::from_secs(7),
        "lock lapsed {waited:?} after the restart"
    );
    // A's old token is dead; the persisted hash was replaced by the new one.
    assert!(a.renew(&[]).await.unwrap_err().is_unauthorized());
    assert!(fresh.renew(&[]).await.is_ok());
    let again = fx.client();
    let e: ClientError = again.hello().await.unwrap_err();
    assert!(e.is_authority_active());
}
