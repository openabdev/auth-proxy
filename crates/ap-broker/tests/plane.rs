//! Session registry and authority lock, driven by a fake clock.

mod support;

use ap_broker::{
    PlaneConfig, PlaneError, RegisterReq, RegistryConfig, AUTHORITY_RENEW_SECS,
    DEFAULT_ABSOLUTE_TTL_SECS, DEFAULT_AUTHORITY_LEASE_SECS, DEFAULT_SESSION_LEASE_SECS,
};
use ap_core::Code;
use std::time::Duration;
use support::*;

#[test]
fn pinned_defaults() {
    assert_eq!(DEFAULT_AUTHORITY_LEASE_SECS, 90);
    assert_eq!(AUTHORITY_RENEW_SECS, 30);
    assert_eq!(DEFAULT_SESSION_LEASE_SECS, 15 * 60);
    assert_eq!(DEFAULT_ABSOLUTE_TTL_SECS, 12 * 60 * 60);
    let c = PlaneConfig::default();
    assert_eq!(c.authority_lease_secs, 90);
    assert_eq!(c.registry.lease, Duration::from_secs(900));
    assert_eq!(c.registry.absolute_ttl, Duration::from_secs(43_200));
    let (_, p) = plane();
    let h = p.hello().unwrap();
    assert_eq!(h.lease_secs, 90);
    assert_eq!(
        p.register(&h.authority_token, &policy(), &req("s", 1, 1, &["kiro"]))
            .unwrap()
            .lease_secs,
        900
    );
}

#[test]
fn authority_lease_below_minimum_is_refused() {
    for secs in [0, 1, 2] {
        let cfg = PlaneConfig {
            authority_lease_secs: secs,
            ..Default::default()
        };
        assert!(ap_broker::SessionPlane::new(
            cfg,
            std::sync::Arc::new(ap_broker::FakeClock::new())
        )
        .is_err());
    }
    let cfg = PlaneConfig {
        authority_lease_secs: 3,
        ..Default::default()
    };
    assert!(
        ap_broker::SessionPlane::new(cfg, std::sync::Arc::new(ap_broker::FakeClock::new())).is_ok()
    );
}

// ---------------------------------------------------------------- leases

#[test]
fn session_lease_is_15_minutes_from_registration() {
    let (clock, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    p.register(&tok, &policy(), &req("s1", 1, 1, &["kiro"]))
        .unwrap();
    advance_renewing_authority(&clock, &p, &tok, 899);
    assert!(p.lookup(&hash(1)).is_ok(), "alive at 899 s");
    advance_renewing_authority(&clock, &p, &tok, 1);
    assert_eq!(
        p.lookup(&hash(1)),
        Err(Code::SurrogateExpired),
        "lapsed at 900 s"
    );
    assert_eq!(p.session_count(), 0);
}

#[test]
fn renew_restarts_the_15_minute_lease() {
    let (clock, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    p.register(&tok, &policy(), &req("s1", 1, 1, &["kiro"]))
        .unwrap();
    advance_renewing_authority(&clock, &p, &tok, 600);
    let r = p.renew(&tok, &[sref("s1", 1)]).unwrap();
    assert_eq!(r.lease_secs, 900);
    assert!(r.unknown.is_empty());
    advance_renewing_authority(&clock, &p, &tok, 899);
    assert!(
        p.lookup(&hash(1)).is_ok(),
        "600 + 899 s: renewed lease still holds"
    );
    advance_renewing_authority(&clock, &p, &tok, 1);
    assert_eq!(p.lookup(&hash(1)), Err(Code::SurrogateExpired));
}

#[test]
fn use_does_not_extend_a_lease() {
    let (clock, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    p.register(&tok, &policy(), &req("s1", 1, 1, &["kiro"]))
        .unwrap();
    for _ in 0..29 {
        advance_renewing_authority(&clock, &p, &tok, 30);
        let _ = p.lookup(&hash(1));
    }
    // 870 s of lookups so far; a lookup never renews
    advance_renewing_authority(&clock, &p, &tok, 30);
    assert_eq!(p.lookup(&hash(1)), Err(Code::SurrogateExpired));
}

#[test]
fn renew_cannot_extend_past_the_absolute_ttl() {
    let (clock, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    p.register(&tok, &policy(), &req("s1", 1, 1, &["kiro"]))
        .unwrap();
    let sessions = [sref("s1", 1)];
    // renew every 30 s for 12 h minus 30 s
    let mut t = 0;
    while t < DEFAULT_ABSOLUTE_TTL_SECS - 30 {
        clock.advance_secs(30);
        t += 30;
        let r = p.renew(&tok, &sessions).unwrap();
        assert!(r.unknown.is_empty(), "t={t}");
    }
    assert!(p.lookup(&hash(1)).is_ok());
    // this renew would reach 43170 + 900 s without the cap
    clock.advance_secs(29);
    let r = p.renew(&tok, &sessions).unwrap();
    assert!(r.unknown.is_empty());
    assert!(
        p.lookup(&hash(1)).is_ok(),
        "alive one second before the TTL"
    );
    clock.advance_secs(1);
    assert_eq!(
        p.lookup(&hash(1)),
        Err(Code::SurrogateExpired),
        "dead at exactly 12 h"
    );
    let r = p.renew(&tok, &sessions).unwrap();
    assert_eq!(r.unknown, vec![sref("s1", 1)], "renew reports it unknown");
}

#[test]
fn configurable_ttl_and_lease() {
    let cfg = PlaneConfig {
        registry: RegistryConfig {
            lease: Duration::from_secs(60),
            absolute_ttl: Duration::from_secs(100),
            max_sessions: 8,
        },
        authority_lease_secs: 90,
        authority_state: None,
    };
    let (clock, p) = plane_with(cfg);
    let tok = p.hello().unwrap().authority_token;
    assert_eq!(
        p.register(&tok, &policy(), &req("s", 1, 1, &["kiro"]))
            .unwrap()
            .lease_secs,
        60
    );
    clock.advance_secs(50);
    p.renew(&tok, &[sref("s", 1)]).unwrap(); // lease would end at 110, TTL caps at 100
    clock.advance_secs(49);
    assert!(p.lookup(&hash(1)).is_ok());
    clock.advance_secs(1);
    assert_eq!(p.lookup(&hash(1)), Err(Code::SurrogateExpired));
}

// ---------------------------------------------------------------- registration

#[test]
fn register_validation_rejects_and_changes_nothing() {
    let (_, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    let pol = policy();
    let good = req("s1", 1, 1, &["kiro"]);
    let bad_hash = |h: &str| RegisterReq {
        surrogate_sha256: h.into(),
        ..good.clone()
    };
    let upper = hex::encode(hash(1)).to_uppercase();
    let cases: Vec<(&str, RegisterReq, u16, &str)> = vec![
        (
            "empty session",
            RegisterReq {
                session: "".into(),
                ..good.clone()
            },
            400,
            "invalid_request",
        ),
        (
            "session too long",
            RegisterReq {
                session: "a".repeat(129),
                ..good.clone()
            },
            400,
            "invalid_request",
        ),
        (
            "session bad char",
            RegisterReq {
                session: "a b".into(),
                ..good.clone()
            },
            400,
            "invalid_request",
        ),
        (
            "session slash",
            RegisterReq {
                session: "a/b".into(),
                ..good.clone()
            },
            400,
            "invalid_request",
        ),
        (
            "hash short",
            bad_hash(&"a".repeat(63)),
            400,
            "invalid_request",
        ),
        (
            "hash long",
            bad_hash(&"a".repeat(65)),
            400,
            "invalid_request",
        ),
        ("hash upper", bad_hash(&upper), 400, "invalid_request"),
        (
            "hash non-hex",
            bad_hash(&"g".repeat(64)),
            400,
            "invalid_request",
        ),
        (
            "no credentials",
            RegisterReq {
                credentials: vec![],
                ..good.clone()
            },
            400,
            "invalid_request",
        ),
        (
            "17 credentials",
            RegisterReq {
                credentials: (0..17).map(|i| format!("c{i}")).collect(),
                ..good.clone()
            },
            400,
            "invalid_request",
        ),
        (
            "duplicate credential",
            RegisterReq {
                credentials: vec!["kiro".into(), "kiro".into()],
                ..good.clone()
            },
            400,
            "invalid_request",
        ),
        (
            "credential not granted",
            RegisterReq {
                credentials: vec!["ghost".into()],
                ..good.clone()
            },
            403,
            "credential_not_granted",
        ),
        (
            "one granted one not",
            RegisterReq {
                credentials: vec!["kiro".into(), "ghost".into()],
                ..good.clone()
            },
            403,
            "credential_not_granted",
        ),
    ];
    for (label, r, status, code) in cases {
        let e = p.register(&tok, &pol, &r).expect_err(label);
        assert_eq!((e.status(), e.code()), (status, code), "{label}: {e}");
    }
    assert_eq!(p.session_count(), 0);
    // boundaries that are valid
    p.register(
        &tok,
        &pol,
        &RegisterReq {
            session: "A.b_c:d-e".repeat(10),
            generation: u64::MAX,
            ..good.clone()
        },
    )
    .unwrap();
    let both: Vec<String> = ["kiro", "anthropic"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    p.register(
        &tok,
        &pol,
        &RegisterReq {
            session: "two".into(),
            generation: 0,
            credentials: both,
            ..req("x", 0, 2, &[])
        },
    )
    .unwrap();
}

#[test]
fn register_conflicts_and_idempotence() {
    let (_, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    let pol = policy();
    p.register(&tok, &pol, &req("s1", 1, 1, &["kiro"])).unwrap();
    // identical retry is fine
    assert!(p.register(&tok, &pol, &req("s1", 1, 1, &["kiro"])).is_ok());
    // same session+generation, other hash
    let e = p
        .register(&tok, &pol, &req("s1", 1, 2, &["kiro"]))
        .unwrap_err();
    assert_eq!((e.status(), e.code()), (409, "session_conflict"));
    // same session+generation, other credentials
    let e = p
        .register(&tok, &pol, &req("s1", 1, 1, &["anthropic"]))
        .unwrap_err();
    assert_eq!(e.status(), 409);
    // same hash under another session
    let e = p
        .register(&tok, &pol, &req("s2", 1, 1, &["kiro"]))
        .unwrap_err();
    assert_eq!(e.status(), 409);
    // new generation of the same session with its own hash coexists
    p.register(&tok, &pol, &req("s1", 2, 3, &["kiro"])).unwrap();
    assert_eq!(p.session_count(), 2);
}

#[test]
fn max_sessions_gives_429_and_frees_on_revoke() {
    let cfg = PlaneConfig {
        registry: RegistryConfig {
            max_sessions: 2,
            ..Default::default()
        },
        ..Default::default()
    };
    let (_, p) = plane_with(cfg);
    let tok = p.hello().unwrap().authority_token;
    let pol = policy();
    p.register(&tok, &pol, &req("a", 1, 1, &["kiro"])).unwrap();
    p.register(&tok, &pol, &req("b", 1, 2, &["kiro"])).unwrap();
    let e = p
        .register(&tok, &pol, &req("c", 1, 3, &["kiro"]))
        .unwrap_err();
    assert_eq!((e.status(), e.code()), (429, "too_many_sessions"));
    // an idempotent retry of an existing one is not over the limit
    p.register(&tok, &pol, &req("b", 1, 2, &["kiro"])).unwrap();
    p.revoke(&tok, "a", 1).unwrap();
    p.register(&tok, &pol, &req("c", 1, 3, &["kiro"])).unwrap();
}

#[test]
fn revoke_is_synchronous_and_idempotent() {
    let (_, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    p.register(&tok, &policy(), &req("s1", 1, 1, &["kiro"]))
        .unwrap();
    assert!(p.lookup(&hash(1)).is_ok());
    p.revoke(&tok, "s1", 1).unwrap();
    assert_eq!(p.lookup(&hash(1)), Err(Code::SurrogateRevoked));
    p.revoke(&tok, "s1", 1).unwrap();
    p.revoke(&tok, "never-existed", 9).unwrap();
    assert_eq!(p.lookup(&hash(77)), Err(Code::SurrogateUnknown));
    // re-registering the same hash clears the revoked memory
    p.register(&tok, &policy(), &req("s1", 2, 1, &["kiro"]))
        .unwrap();
    assert!(p.lookup(&hash(1)).is_ok());
}

#[test]
fn every_call_needs_the_token() {
    let (_, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    let pol = policy();
    for bad in [
        "",
        "apt_",
        "garbage",
        &format!("{tok}x"),
        &tok[..tok.len() - 1],
    ] {
        assert_eq!(
            p.register(bad, &pol, &req("s", 1, 1, &["kiro"])),
            Err(PlaneError::Unauthorized)
        );
        assert_eq!(p.renew(bad, &[]), Err(PlaneError::Unauthorized));
        assert_eq!(p.revoke(bad, "s", 1), Err(PlaneError::Unauthorized));
        assert_eq!(p.resync(bad, &pol, &[]), Err(PlaneError::Unauthorized));
    }
    assert_eq!(p.session_count(), 0);
}

// ---------------------------------------------------------------- resync

#[test]
fn resync_validates_the_whole_list_before_applying() {
    let (_, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    let pol = policy();
    p.register(&tok, &pol, &req("old", 1, 9, &["kiro"]))
        .unwrap();
    let list = vec![
        req("new1", 1, 1, &["kiro"]),
        req("new2", 1, 2, &["ghost"]), // not granted
    ];
    let e = p.resync(&tok, &pol, &list).unwrap_err();
    assert_eq!(e.status(), 403);
    assert!(
        e.to_string().contains("entry 1"),
        "says which entry failed: {e}"
    );
    assert_eq!(p.session_count(), 1, "nothing applied");
    assert!(p.lookup(&hash(9)).is_ok(), "old session untouched");
    assert_eq!(
        p.lookup(&hash(1)),
        Err(Code::SurrogateUnknown),
        "good entry not registered"
    );

    for (label, list, status) in [
        (
            "duplicate key",
            vec![req("a", 1, 1, &["kiro"]), req("a", 1, 2, &["kiro"])],
            400,
        ),
        (
            "duplicate hash",
            vec![req("a", 1, 1, &["kiro"]), req("b", 1, 1, &["kiro"])],
            409,
        ),
        (
            "bad hash",
            vec![RegisterReq {
                surrogate_sha256: "zz".into(),
                ..req("a", 1, 1, &["kiro"])
            }],
            400,
        ),
        (
            "rebinds existing key",
            vec![req("old", 1, 5, &["kiro"])],
            409,
        ),
    ] {
        let e = p.resync(&tok, &pol, &list).expect_err(label);
        assert_eq!(e.status(), status, "{label}: {e}");
        assert!(p.lookup(&hash(9)).is_ok(), "{label}: nothing applied");
    }
}

#[test]
fn resync_registers_drops_and_reports() {
    let (_, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    let pol = policy();
    p.register(&tok, &pol, &req("keep", 1, 1, &["kiro"]))
        .unwrap();
    p.register(&tok, &pol, &req("drop", 1, 2, &["kiro"]))
        .unwrap();
    let r = p
        .resync(
            &tok,
            &pol,
            &[
                req("keep", 1, 1, &["kiro"]),
                req("fresh", 1, 3, &["anthropic"]),
            ],
        )
        .unwrap();
    assert_eq!((r.registered, r.dropped), (2, 1));
    assert!(p.lookup(&hash(1)).is_ok());
    assert!(p.lookup(&hash(3)).is_ok());
    assert_eq!(
        p.lookup(&hash(2)),
        Err(Code::SurrogateRevoked),
        "dropped sessions stay dropped"
    );
    let r = p.resync(&tok, &pol, &[]).unwrap();
    assert_eq!((r.registered, r.dropped), (0, 2));
    assert_eq!(p.session_count(), 0);
}

#[test]
fn resync_keeps_the_original_absolute_ttl() {
    let (clock, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    let pol = policy();
    p.register(&tok, &pol, &req("s", 1, 1, &["kiro"])).unwrap();
    advance_renewing(&clock, &p, &tok, 43_000, &[sref("s", 1)]);
    p.resync(&tok, &pol, &[req("s", 1, 1, &["kiro"])]).unwrap();
    advance_renewing_authority(&clock, &p, &tok, 199);
    assert!(p.lookup(&hash(1)).is_ok());
    advance_renewing_authority(&clock, &p, &tok, 1);
    assert_eq!(
        p.lookup(&hash(1)),
        Err(Code::SurrogateExpired),
        "resync does not restart the 12 h"
    );
}

#[test]
fn proxy_restart_then_resync_restores_the_same_surrogates() {
    let dir = tmpdir("restart");
    let state = dir.join("authority.json");
    let cfg = || PlaneConfig {
        authority_state: Some(state.clone()),
        ..Default::default()
    };
    let pol = policy();
    let (clock1, p1) = plane_with(cfg());
    let tok = p1.hello().unwrap().authority_token;
    p1.register(&tok, &pol, &req("a", 1, 1, &["kiro"])).unwrap();
    p1.register(&tok, &pol, &req("b", 1, 2, &["anthropic"]))
        .unwrap();
    clock1.advance_secs(20);
    drop(p1); // proxy restarts: registry is memory only

    let (_clock2, p2) = plane_with(cfg());
    assert_eq!(
        p2.lookup(&hash(1)),
        Err(Code::SurrogateUnknown),
        "gap: refused"
    );
    // the authority's next renew lists everything as unknown
    let r = p2.renew(&tok, &[sref("a", 1), sref("b", 1)]).unwrap();
    assert_eq!(r.unknown.len(), 2);
    // it re-sends the live sessions it still has (only "a")
    let r = p2.resync(&tok, &pol, &[req("a", 1, 1, &["kiro"])]).unwrap();
    assert_eq!((r.registered, r.dropped), (1, 0));
    assert!(p2.lookup(&hash(1)).is_ok(), "same surrogate works again");
    assert_eq!(
        p2.lookup(&hash(2)),
        Err(Code::SurrogateUnknown),
        "dropped session stays dropped"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------- hello lock

#[test]
fn hello_409_while_live_then_lapse_revokes_everything_and_next_hello_wins() {
    let (clock, p) = plane();
    let pol = policy();
    let a = p.hello().unwrap();
    assert_eq!(a.lease_secs, 90);
    assert!(a.authority_token.starts_with("apt_") && a.authority_token.len() == 68);
    p.register(&a.authority_token, &pol, &req("s1", 1, 1, &["kiro"]))
        .unwrap();

    // renewed every 30 s: the lock stays held for as long as it is renewed
    for _ in 0..10 {
        clock.advance_secs(30);
        p.renew(&a.authority_token, &[sref("s1", 1)]).unwrap();
        assert_eq!(p.hello(), Err(PlaneError::AuthorityActive));
    }
    // the authority dies: 89 s of silence
    clock.advance_secs(89);
    assert_eq!(
        p.hello(),
        Err(PlaneError::AuthorityActive),
        "lock holds until the lease ends"
    );
    assert!(p.lookup(&hash(1)).is_ok(), "sessions still work until then");
    assert!(p.authority_live());
    // 90 s
    clock.advance_secs(1);
    assert!(!p.authority_live());
    assert_eq!(
        p.lookup(&hash(1)),
        Err(Code::SurrogateRevoked),
        "lapse revokes the authority's sessions"
    );
    assert_eq!(p.session_count(), 0);
    // the old token is dead
    assert_eq!(
        p.renew(&a.authority_token, &[]),
        Err(PlaneError::Unauthorized)
    );
    assert_eq!(
        p.register(&a.authority_token, &pol, &req("s2", 1, 2, &["kiro"])),
        Err(PlaneError::Unauthorized)
    );
    // exactly one hello wins
    let b = p.hello().unwrap();
    assert_ne!(a.authority_token, b.authority_token);
    assert_eq!(
        p.hello(),
        Err(PlaneError::AuthorityActive),
        "a concurrent second hello gets 409"
    );
    // stale token after a new hello is 401, the new one works
    assert_eq!(
        p.renew(&a.authority_token, &[]),
        Err(PlaneError::Unauthorized)
    );
    p.register(&b.authority_token, &pol, &req("s3", 1, 3, &["kiro"]))
        .unwrap();
}

#[test]
fn restarted_runtime_retries_with_backoff_and_wins_only_after_the_lease() {
    let (clock, p) = plane();
    let a = p.hello().unwrap();
    p.renew(&a.authority_token, &[]).unwrap();
    // container dies at t=0 (last renew). The fresh PID 1 retries every 10 s.
    let mut won_at = None;
    for attempt in 1..=12u64 {
        clock.advance_secs(10);
        match p.hello() {
            Ok(_) => {
                won_at = Some(attempt * 10);
                break;
            }
            Err(e) => assert_eq!(e, PlaneError::AuthorityActive, "t={}", attempt * 10),
        }
    }
    assert_eq!(
        won_at,
        Some(90),
        "first attempt at or after the 90 s lease wins"
    );
}

#[test]
fn hello_wins_exactly_once_under_concurrency() {
    use std::sync::Arc;
    let (clock, p) = plane();
    let p = Arc::new(p);
    let a = p.hello().unwrap();
    clock.advance_secs(90);
    let _ = a;
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let p = p.clone();
            std::thread::spawn(move || p.hello().is_ok())
        })
        .collect();
    let wins = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|w| *w)
        .count();
    assert_eq!(wins, 1);
}

#[test]
fn authority_lock_survives_a_proxy_restart_for_one_lease() {
    let dir = tmpdir("lock");
    let state = dir.join("authority.json");
    let cfg = || PlaneConfig {
        authority_state: Some(state.clone()),
        ..Default::default()
    };
    let pol = policy();
    let (_c1, p1) = plane_with(cfg());
    let a = p1.hello().unwrap();
    drop(p1);

    // the file holds the hash and nothing secret
    let text = std::fs::read_to_string(&state).unwrap();
    assert!(!text.contains(&a.authority_token), "token never written");
    assert!(!text.contains("apt_"));
    assert!(text.contains("token_sha256"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // restart: the lock is live for one full lease from now, the token still works
    let (c2, p2) = plane_with(cfg());
    assert!(p2.authority_live());
    assert_eq!(p2.hello(), Err(PlaneError::AuthorityActive));
    p2.register(&a.authority_token, &pol, &req("s", 1, 1, &["kiro"]))
        .unwrap();
    c2.advance_secs(89);
    assert_eq!(p2.hello(), Err(PlaneError::AuthorityActive));
    // a renew after the restart extends it by a full lease again
    p2.renew(&a.authority_token, &[sref("s", 1)]).unwrap();
    c2.advance_secs(89);
    assert_eq!(p2.hello(), Err(PlaneError::AuthorityActive));
    // silence for the rest of a lease frees it
    c2.advance_secs(1);
    assert!(!p2.authority_live());
    assert_eq!(p2.lookup(&hash(1)), Err(Code::SurrogateRevoked));
    let b = p2.hello().unwrap();
    assert_eq!(
        p2.renew(&a.authority_token, &[]),
        Err(PlaneError::Unauthorized)
    );
    assert!(p2.renew(&b.authority_token, &[]).is_ok());

    // a restart after a lapse finds no lock: the state file was cleared on
    // the lapse, then rewritten for b; drop b's lease and restart again
    drop(p2);
    let (c3, p3) = plane_with(cfg());
    c3.advance_secs(90);
    assert!(!p3.authority_live());
    p3.hello().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lapse_clears_the_state_file() {
    let dir = tmpdir("clear");
    let state = dir.join("authority.json");
    let (clock, p) = plane_with(PlaneConfig {
        authority_state: Some(state.clone()),
        ..Default::default()
    });
    p.hello().unwrap();
    assert!(state.exists());
    clock.advance_secs(90);
    assert!(!p.authority_live());
    assert!(!state.exists(), "no stale hash left behind after a lapse");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unwritable_state_means_no_lock_is_taken() {
    let dir = tmpdir("nowrite");
    let (_, p) = plane_with(PlaneConfig {
        authority_state: Some(dir.join("missing-dir").join("authority.json")),
        ..Default::default()
    });
    for _ in 0..2 {
        let e = p.hello().unwrap_err();
        assert_eq!(e.status(), 500, "{e}");
    }
    assert!(!p.authority_live());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_state_file_starts_with_no_lock() {
    let dir = tmpdir("corrupt");
    let state = dir.join("authority.json");
    for junk in [
        "",
        "not json",
        "{\"version\":2,\"token_sha256\":\"00\"}",
        "{\"version\":1,\"token_sha256\":\"zz\"}",
    ] {
        std::fs::write(&state, junk).unwrap();
        let (_, p) = plane_with(PlaneConfig {
            authority_state: Some(state.clone()),
            ..Default::default()
        });
        assert!(!p.authority_live(), "{junk:?}");
        p.hello().unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn authority_lease_is_configurable_for_tests_only_down_to_3_s() {
    let (clock, p) = plane_with(PlaneConfig {
        authority_lease_secs: 3,
        ..Default::default()
    });
    let a = p.hello().unwrap();
    assert_eq!(a.lease_secs, 3);
    clock.advance_secs(2);
    assert_eq!(p.hello(), Err(PlaneError::AuthorityActive));
    clock.advance_secs(1);
    assert!(p.hello().is_ok());
}

#[test]
fn revoke_all_drops_every_session_and_keeps_the_authority() {
    let (_, p) = plane();
    let tok = p.hello().unwrap().authority_token;
    p.register(&tok, &policy(), &req("a", 1, 1, &["kiro"]))
        .unwrap();
    p.register(&tok, &policy(), &req("b", 1, 2, &["kiro"]))
        .unwrap();
    assert_eq!(p.revoke_all(), 2);
    assert_eq!(p.session_count(), 0);
    assert_eq!(p.lookup(&hash(1)), Err(Code::SurrogateRevoked));
    assert!(p.authority_live(), "revoke_all must not free the lock");
    assert_eq!(p.revoke_all(), 0);
    // The live authority can register again.
    p.register(&tok, &policy(), &req("a", 1, 1, &["kiro"]))
        .unwrap();
}
