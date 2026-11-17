//! Deterministic tests for the hold table. Time is paused, so the 2 s confirm window and the
//! cooldown run on the virtual clock.

use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::oneshot::error::TryRecvError;

use super::*;

const SECRET_AUTH: &str = "Bot SENTINEL-AUTH-VALUE";
const SECRET_BODY: &str = "SENTINEL-BODY-TEXT";
const SECRET_KEY: &str = "SENTINEL-API-KEY";

fn limits(total: usize, per: usize, cooldown_secs: u64) -> Limits {
    Limits {
        hold: Duration::from_secs(120),
        max_total: total,
        max_per_identity: per,
        cooldown: Duration::from_secs(cooldown_secs),
    }
}

fn table(total: usize, per: usize, cooldown_secs: u64) -> Arc<Table> {
    Arc::new(Table::new(limits(total, per, cooldown_secs)))
}

fn req(auth: &str, body: &str) -> Arc<HeldRequest> {
    Arc::new(HeldRequest {
        method: "POST".into(),
        route: "discord".into(),
        path: "/channels/1/messages".into(),
        query: Some("wait=true".into()),
        headers: vec![
            ("authorization".into(), auth.as_bytes().to_vec()),
            ("content-type".into(), b"application/json".to_vec()),
            ("x-api-key".into(), SECRET_KEY.as_bytes().to_vec()),
        ],
        body: Bytes::copy_from_slice(body.as_bytes()),
    })
}

fn ok(_: &str, _: &str) -> io::Result<()> {
    Ok(())
}

fn admit(t: &Table, identity: &str, r: Arc<HeldRequest>) -> Admission {
    t.admit(identity, r, ok)
}

fn held(t: &Table, identity: &str, r: Arc<HeldRequest>) -> Held {
    match admit(t, identity, r) {
        Admission::Held(h) => h,
        Admission::Refused(c) => panic!("refused: {}", c.code_str()),
    }
}

fn refused(a: Admission) -> Code {
    match a {
        Admission::Refused(c) => c,
        Admission::Held(h) => panic!("held {}", h.id),
    }
}

/// How a simulated handler answers an approve.
#[derive(Clone, Copy)]
enum Mode {
    Send(Confirm),
    DropIt,
    /// Keep the confirm sender alive and never answer.
    Hold,
}

/// Run a handler for `h` that answers an approve as `mode`. The task returns the decision label.
fn handler(h: Held, mode: Mode) -> tokio::task::JoinHandle<&'static str> {
    tokio::spawn(async move {
        match h.decision.await {
            Ok(Decision::Approved { confirm, .. }) => {
                match mode {
                    Mode::Send(c) => confirm.send(c),
                    Mode::DropIt => drop(confirm),
                    Mode::Hold => std::future::pending::<()>().await,
                }
                "approved"
            }
            Ok(Decision::Denied { .. }) => "denied",
            Ok(Decision::Superseded { .. }) => "superseded",
            Ok(Decision::Dropped) => "dropped",
            Ok(Decision::Shutdown) => "shutdown",
            Err(_) => "no_decision",
        }
    })
}

// ---- state machine -------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn approve_success_then_already_decided() {
    let t = table(8, 4, 60);
    let h = held(&t, "muse", req(SECRET_AUTH, "a"));
    let id = h.id.clone();
    let task = handler(h, Mode::Send(Confirm::Started));
    assert_eq!(t.approve(&id, "alice").await, ApproveResult::Success);
    assert_eq!(task.await.unwrap(), "approved");
    assert_eq!(t.state(&id), Some(State::Approved));
    assert_eq!(t.approve(&id, "alice").await, ApproveResult::AlreadyDecided);
    assert_eq!(t.deny(&id, "alice"), DenyResult::AlreadyDecided);
    assert!(!t.expire(&id));
    assert!(!t.abandon(&id));
    assert_eq!(t.pending_len(), 0);
}

#[tokio::test(start_paused = true)]
async fn approve_result_rows() {
    // Approved, handler answers Abandoned before milestone 2.
    let t = table(8, 4, 0);
    let h = held(&t, "muse", req(SECRET_AUTH, "1"));
    let id = h.id.clone();
    let _task = handler(h, Mode::Send(Confirm::Abandoned));
    assert_eq!(
        t.approve(&id, "a").await,
        ApproveResult::ApprovedButAbandoned
    );

    // Approved, handler drops the confirm sender.
    let h = held(&t, "muse", req(SECRET_AUTH, "2"));
    let id = h.id.clone();
    let _task = handler(h, Mode::DropIt);
    assert_eq!(
        t.approve(&id, "a").await,
        ApproveResult::ApprovedButAbandoned
    );

    // Approved, handler future already gone (decision receiver dropped).
    let h = held(&t, "muse", req(SECRET_AUTH, "3"));
    let id = h.id.clone();
    drop(h.decision);
    assert_eq!(
        t.approve(&id, "a").await,
        ApproveResult::ApprovedButAbandoned
    );
    assert!(!t.abandon(&id), "the approve already won");
    assert_eq!(t.state(&id), Some(State::Approved));

    // Approved, no confirmation within 2 s.
    let h = held(&t, "muse", req(SECRET_AUTH, "4"));
    let id = h.id.clone();
    let _task = handler(h, Mode::Hold);
    let before = tokio::time::Instant::now();
    assert_eq!(
        t.approve(&id, "a").await,
        ApproveResult::ApprovedUnconfirmed
    );
    assert_eq!(before.elapsed(), CONFIRM_TIMEOUT);

    // Approved, audit write failed / connect failed.
    let h = held(&t, "muse", req(SECRET_AUTH, "5"));
    let id = h.id.clone();
    let _task = handler(h, Mode::Send(Confirm::AuditUnavailable));
    assert_eq!(t.approve(&id, "a").await, ApproveResult::AuditUnavailable);
    let h = held(&t, "muse", req(SECRET_AUTH, "6"));
    let id = h.id.clone();
    let _task = handler(h, Mode::Send(Confirm::ConnectFailed));
    assert_eq!(t.approve(&id, "a").await, ApproveResult::ConnectFailed);
}

#[tokio::test(start_paused = true)]
async fn approve_rows_for_decided_states() {
    let t = table(8, 4, 0);

    let h = held(&t, "muse", req(SECRET_AUTH, "denied"));
    let id = h.id.clone();
    assert_eq!(t.deny(&id, "bob"), DenyResult::Denied);
    assert_eq!(t.approve(&id, "a").await, ApproveResult::AlreadyDecided);
    assert_eq!(t.deny(&id, "bob"), DenyResult::AlreadyDecided);

    let h = held(&t, "muse", req(SECRET_AUTH, "expired"));
    let id = h.id.clone();
    assert!(t.expire(&id));
    assert_eq!(t.approve(&id, "a").await, ApproveResult::Expired);
    assert_eq!(t.deny(&id, "a"), DenyResult::Expired);
    assert!(!t.expire(&id), "a second expire does nothing");

    let h = held(&t, "muse", req(SECRET_AUTH, "abandoned"));
    let id = h.id.clone();
    assert!(t.abandon(&id));
    assert_eq!(t.approve(&id, "a").await, ApproveResult::Gone);
    assert_eq!(t.deny(&id, "a"), DenyResult::Gone);

    let h = held(&t, "other", req(SECRET_AUTH, "dropped"));
    let id = h.id.clone();
    assert_eq!(t.drop_identities_missing(&HashSet::new()), 1);
    assert_eq!(t.approve(&id, "a").await, ApproveResult::Dropped);
    assert_eq!(t.deny(&id, "a"), DenyResult::Dropped);

    assert_eq!(t.approve("no-such-id", "a").await, ApproveResult::NotFound);
    assert_eq!(t.deny("no-such-id", "a"), DenyResult::NotFound);
    drop(h.decision);
}

#[tokio::test(start_paused = true)]
async fn approve_on_superseded_names_the_newest_entry() {
    let t = table(8, 4, 60);
    let first = held(&t, "muse", req(SECRET_AUTH, "same"));
    let first_id = first.id.clone();
    let second = held(&t, "muse", req(SECRET_AUTH, "same"));
    assert_eq!(second.superseded.as_deref(), Some(first_id.as_str()));
    assert_eq!(
        t.approve(&first_id, "a").await,
        ApproveResult::Superseded {
            newest: second.id.clone()
        }
    );
    assert_eq!(
        t.deny(&first_id, "a"),
        DenyResult::Superseded {
            newest: second.id.clone()
        }
    );
    assert_eq!(t.state(&first_id), Some(State::Superseded));
    assert_eq!(t.state(&second.id), Some(State::Pending));
}

#[tokio::test(start_paused = true)]
async fn each_transition_order_has_one_winner() {
    #[derive(Clone, Copy)]
    enum Act {
        Approve,
        Deny,
        Expire,
    }
    use Act::*;
    let orders = [
        [Approve, Deny, Expire],
        [Approve, Expire, Deny],
        [Deny, Approve, Expire],
        [Deny, Expire, Approve],
        [Expire, Approve, Deny],
        [Expire, Deny, Approve],
    ];
    for order in orders {
        let t = table(8, 4, 0);
        let h = held(&t, "muse", req(SECRET_AUTH, "race"));
        let id = h.id.clone();
        let _handler = handler(h, Mode::Send(Confirm::Started));
        let mut tasks = Vec::new();
        for act in order {
            let t = t.clone();
            let id = id.clone();
            tasks.push(tokio::spawn(async move {
                match act {
                    Approve => t.approve(&id, "a").await == ApproveResult::Success,
                    Deny => t.deny(&id, "a") == DenyResult::Denied,
                    Expire => t.expire(&id),
                }
            }));
        }
        let mut wins = 0;
        for task in tasks {
            if task.await.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one of approve, deny and expire wins");
        assert_eq!(t.pending_len(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn two_concurrent_approves_one_success_one_already_decided() {
    let t = table(8, 4, 60);
    let h = held(&t, "muse", req(SECRET_AUTH, "x"));
    let id = h.id.clone();
    let _handler = handler(h, Mode::Send(Confirm::Started));
    let a = {
        let (t, id) = (t.clone(), id.clone());
        tokio::spawn(async move { t.approve(&id, "a").await })
    };
    let b = {
        let (t, id) = (t.clone(), id.clone());
        tokio::spawn(async move { t.approve(&id, "b").await })
    };
    let mut got = vec![a.await.unwrap(), b.await.unwrap()];
    got.sort_by_key(|r| r.as_str());
    assert_eq!(
        got,
        vec![ApproveResult::AlreadyDecided, ApproveResult::Success]
    );
}

#[tokio::test(start_paused = true)]
async fn expire_and_abandon_send_no_decision_but_free_the_slot() {
    let t = table(8, 1, 0);
    let mut h = held(&t, "muse", req(SECRET_AUTH, "e"));
    assert!(t.expire(&h.id));
    assert!(matches!(h.decision.try_recv(), Err(TryRecvError::Closed)));
    let mut h2 = held(&t, "muse", req(SECRET_AUTH, "f"));
    assert!(t.abandon(&h2.id));
    assert!(matches!(h2.decision.try_recv(), Err(TryRecvError::Closed)));
    assert_eq!(t.pending_len(), 0);
}

// ---- admission -----------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn ten_rapid_retries_leave_one_entry() {
    let t = table(8, 4, 60);
    let mut all: Vec<Held> = Vec::new();
    for _ in 0..10 {
        all.push(held(&t, "muse", req(SECRET_AUTH, "same")));
    }
    assert_eq!(t.pending_len(), 1);
    assert!(all[0].superseded.is_none(), "only the first one notifies");
    for i in 1..10 {
        assert_eq!(all[i].superseded.as_deref(), Some(all[i - 1].id.as_str()));
    }
    let ids: Vec<String> = all.iter().map(|h| h.id.clone()).collect();
    for (i, h) in all.iter_mut().enumerate().take(9) {
        match h.decision.try_recv() {
            Ok(Decision::Superseded { newest }) => assert_eq!(newest, ids[i + 1], "entry {i}"),
            other => panic!("entry {i}: {other:?}"),
        }
    }
    assert!(matches!(
        all[9].decision.try_recv(),
        Err(TryRecvError::Empty)
    ));
    // Every older id resolves to the newest entry, not just to its direct replacement.
    for old in &ids[..9] {
        assert_eq!(
            t.approve(old, "a").await,
            ApproveResult::Superseded {
                newest: ids[9].clone()
            }
        );
    }
}

#[tokio::test(start_paused = true)]
async fn changed_authorization_is_a_distinct_entry() {
    let t = table(8, 4, 60);
    let a = held(&t, "muse", req("Bot ONE", "same"));
    let b = held(&t, "muse", req("Bot TWO", "same"));
    assert!(b.superseded.is_none());
    assert_ne!(a.id, b.id);
    assert_eq!(t.pending_len(), 2);
    assert_eq!(t.state(&a.id), Some(State::Pending));
    // The audit digest is credential-blind, so it is the same for both.
    assert_eq!(a.digest, b.digest);
}

#[tokio::test(start_paused = true)]
async fn same_body_for_another_identity_is_not_a_duplicate() {
    let t = table(8, 4, 60);
    let a = held(&t, "muse", req(SECRET_AUTH, "same"));
    let b = held(&t, "other", req(SECRET_AUTH, "same"));
    assert!(b.superseded.is_none());
    assert_eq!(t.state(&a.id), Some(State::Pending));
    assert_eq!(t.pending_len(), 2);
}

#[tokio::test(start_paused = true)]
async fn caps_per_identity_then_total() {
    let t = table(3, 2, 60);
    let _a = held(&t, "muse", req(SECRET_AUTH, "1"));
    let _b = held(&t, "muse", req(SECRET_AUTH, "2"));
    assert_eq!(
        refused(admit(&t, "muse", req(SECRET_AUTH, "3"))),
        Code::IdentityCap
    );
    let _c = held(&t, "other", req(SECRET_AUTH, "4"));
    assert_eq!(
        refused(admit(&t, "other", req(SECRET_AUTH, "5"))),
        Code::TableFull
    );
    // An identity at both caps reports the per-identity cap first.
    let t = table(2, 2, 60);
    let _a = held(&t, "muse", req(SECRET_AUTH, "1"));
    let _b = held(&t, "muse", req(SECRET_AUTH, "2"));
    assert_eq!(
        refused(admit(&t, "muse", req(SECRET_AUTH, "3"))),
        Code::IdentityCap
    );
    assert_eq!(t.pending_len(), 2);
}

#[tokio::test(start_paused = true)]
async fn identical_retry_at_a_cap_supersedes() {
    let t = table(2, 2, 60);
    let a = held(&t, "muse", req(SECRET_AUTH, "1"));
    let _b = held(&t, "muse", req(SECRET_AUTH, "2"));
    // Per-identity and total caps are both full; the identical retry is not counted.
    let again = held(&t, "muse", req(SECRET_AUTH, "1"));
    assert_eq!(again.superseded.as_deref(), Some(a.id.as_str()));
    assert_eq!(t.pending_len(), 2);
    assert_eq!(t.state(&a.id), Some(State::Superseded));
}

#[tokio::test(start_paused = true)]
async fn deny_and_expire_free_the_slot_at_once() {
    let t = table(8, 1, 0);
    let a = held(&t, "muse", req(SECRET_AUTH, "1"));
    assert_eq!(
        refused(admit(&t, "muse", req(SECRET_AUTH, "2"))),
        Code::IdentityCap
    );
    assert_eq!(t.deny(&a.id, "bob"), DenyResult::Denied);
    let b = held(&t, "muse", req(SECRET_AUTH, "2"));
    assert!(t.expire(&b.id));
    let _c = held(&t, "muse", req(SECRET_AUTH, "3"));
}

#[tokio::test(start_paused = true)]
async fn approved_entry_no_longer_counts_against_the_caps() {
    let t = table(8, 1, 0);
    let a = held(&t, "muse", req(SECRET_AUTH, "1"));
    let id = a.id.clone();
    let _handler = handler(a, Mode::Send(Confirm::Started));
    assert_eq!(t.approve(&id, "a").await, ApproveResult::Success);
    let _b = held(&t, "muse", req(SECRET_AUTH, "2"));
}

// ---- cooldown ------------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn deny_starts_a_cooldown_that_ends() {
    let t = table(8, 4, 60);
    let a = held(&t, "muse", req(SECRET_AUTH, "1"));
    assert_eq!(t.deny(&a.id, "bob"), DenyResult::Denied);
    assert_eq!(t.pending_len(), 0, "the slot is free at once");
    assert_eq!(
        refused(admit(&t, "muse", req(SECRET_AUTH, "1"))),
        Code::Cooldown
    );
    assert_eq!(
        refused(admit(&t, "muse", req(SECRET_AUTH, "other body"))),
        Code::Cooldown
    );
    let _elsewhere = held(&t, "other", req(SECRET_AUTH, "1"));
    tokio::time::advance(Duration::from_secs(59)).await;
    assert_eq!(
        refused(admit(&t, "muse", req(SECRET_AUTH, "1"))),
        Code::Cooldown
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    let _again = held(&t, "muse", req(SECRET_AUTH, "1"));
}

#[tokio::test(start_paused = true)]
async fn expiry_starts_a_cooldown() {
    let t = table(8, 4, 60);
    let a = held(&t, "muse", req(SECRET_AUTH, "1"));
    assert!(t.expire(&a.id));
    assert_eq!(
        refused(admit(&t, "muse", req(SECRET_AUTH, "2"))),
        Code::Cooldown
    );
}

#[tokio::test(start_paused = true)]
async fn cooldown_zero_disables_it() {
    let t = table(8, 4, 0);
    let a = held(&t, "muse", req(SECRET_AUTH, "1"));
    assert_eq!(t.deny(&a.id, "bob"), DenyResult::Denied);
    let _b = held(&t, "muse", req(SECRET_AUTH, "1"));
}

#[tokio::test(start_paused = true)]
async fn only_deny_and_expiry_start_a_cooldown() {
    let t = table(8, 4, 60);

    let a = held(&t, "muse", req(SECRET_AUTH, "abandon"));
    assert!(t.abandon(&a.id));
    let b = held(&t, "muse", req(SECRET_AUTH, "approve"));
    let b_id = b.id.clone();
    let _h = handler(b, Mode::Send(Confirm::Started));
    assert_eq!(t.approve(&b_id, "a").await, ApproveResult::Success);
    let _c = held(&t, "muse", req(SECRET_AUTH, "supersede"));
    let _d = held(&t, "muse", req(SECRET_AUTH, "supersede"));
    assert_eq!(t.drop_all(), 1);
    let _e = held(&t, "muse", req(SECRET_AUTH, "after reload drop"));

    // A failed audit write is not the identity's doing.
    let t2 = table(8, 4, 60);
    let failing = t2.admit("muse", req(SECRET_AUTH, "x"), |_, _| {
        Err(io::Error::other("disk"))
    });
    assert_eq!(refused(failing), Code::AuditUnavailable);
    let _ok = held(&t2, "muse", req(SECRET_AUTH, "x"));
}

#[tokio::test(start_paused = true)]
async fn cooldown_beats_duplicate_and_leaves_pending_entries() {
    let t = table(8, 4, 60);
    let a = held(&t, "muse", req(SECRET_AUTH, "keeps waiting"));
    let b = held(&t, "muse", req(SECRET_AUTH, "gets denied"));
    assert_eq!(t.deny(&b.id, "bob"), DenyResult::Denied);

    // An identical retry of the still-pending `a` hits the cooldown first; it does not supersede.
    assert_eq!(
        refused(admit(&t, "muse", req(SECRET_AUTH, "keeps waiting"))),
        Code::Cooldown
    );
    assert_eq!(t.state(&a.id), Some(State::Pending));
    let a_id = a.id.clone();
    let _h = handler(a, Mode::Send(Confirm::Started));
    assert_eq!(t.approve(&a_id, "alice").await, ApproveResult::Success);
}

// ---- audit-before-insert -------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn failed_persist_changes_nothing() {
    let t = table(8, 4, 60);
    let mut old = held(&t, "muse", req(SECRET_AUTH, "same"));
    let r = t.admit("muse", req(SECRET_AUTH, "same"), |_, _| {
        Err(io::Error::other("sink down"))
    });
    assert_eq!(refused(r), Code::AuditUnavailable);
    assert_eq!(t.pending_len(), 1);
    assert_eq!(t.state(&old.id), Some(State::Pending), "no supersede");
    assert!(matches!(old.decision.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test(start_paused = true)]
async fn persist_sees_the_id_and_digest_of_the_new_entry() {
    let t = table(8, 4, 60);
    let mut seen = None;
    let r = t.admit("muse", req(SECRET_AUTH, "x"), |id, digest| {
        seen = Some((id.to_string(), digest.to_string()));
        Ok(())
    });
    let Admission::Held(h) = r else {
        panic!("not held")
    };
    assert_eq!(seen, Some((h.id.clone(), h.digest.clone())));
    assert_eq!(h.id.len(), 32);
    assert_eq!(h.digest.len(), 64);
    assert!(!h.digest.contains("SENTINEL"));
}

#[tokio::test(start_paused = true)]
async fn persist_is_not_called_for_a_refusal() {
    let t = table(1, 1, 60);
    let _a = held(&t, "muse", req(SECRET_AUTH, "1"));
    let mut called = false;
    let r = t.admit("muse", req(SECRET_AUTH, "2"), |_, _| {
        called = true;
        Ok(())
    });
    assert_eq!(refused(r), Code::IdentityCap);
    assert!(!called, "no held record for a refused request");
}

// ---- reload and shutdown ------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn reload_drops_only_the_identities_that_are_gone() {
    let t = table(8, 4, 60);
    let a = held(&t, "gone", req(SECRET_AUTH, "1"));
    let a2 = held(&t, "gone", req(SECRET_AUTH, "2"));
    let b = held(&t, "stays", req(SECRET_AUTH, "1"));
    let present: HashSet<String> = ["stays".to_string()].into_iter().collect();
    assert_eq!(t.drop_identities_missing(&present), 2);
    assert_eq!(t.state(&a.id), Some(State::Dropped));
    assert_eq!(t.state(&a2.id), Some(State::Dropped));
    assert_eq!(t.state(&b.id), Some(State::Pending));
    assert_eq!(t.pending_len(), 1);
    assert_eq!(handler(a, Mode::DropIt).await.unwrap(), "dropped");
    // No cooldown: the identity did nothing wrong.
    let _again = held(&t, "gone", req(SECRET_AUTH, "1"));
    // Nothing more to drop for an unchanged set.
    assert_eq!(t.drop_identities_missing(&present), 1);
}

#[tokio::test(start_paused = true)]
async fn drain_answers_shutdown_and_closes_admission() {
    let t = table(8, 4, 60);
    let a = held(&t, "muse", req(SECRET_AUTH, "1"));
    let b = held(&t, "other", req(SECRET_AUTH, "1"));
    assert_eq!(t.drain_pending(), 2);
    assert_eq!(handler(a, Mode::DropIt).await.unwrap(), "shutdown");
    assert_eq!(handler(b, Mode::DropIt).await.unwrap(), "shutdown");
    assert_eq!(t.pending_len(), 0);
    assert_eq!(
        refused(admit(&t, "muse", req(SECRET_AUTH, "2"))),
        Code::Shutdown
    );
}

#[tokio::test(start_paused = true)]
async fn tombstones_are_bounded() {
    let t = table(8, 4, 0);
    let first = held(&t, "muse", req(SECRET_AUTH, "first"));
    assert_eq!(t.deny(&first.id, "a"), DenyResult::Denied);
    for i in 0..1100 {
        let h = held(&t, "muse", req(SECRET_AUTH, &format!("n{i}")));
        assert!(t.abandon(&h.id));
    }
    assert_eq!(
        t.state(&first.id),
        None,
        "the oldest tombstone was forgotten"
    );
    assert_eq!(t.approve(&first.id, "a").await, ApproveResult::NotFound);
}

// ---- view and Debug ------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn view_omits_credential_values_and_redacts_the_path() {
    let t = table(8, 4, 60);
    let mut r = (*req(SECRET_AUTH, SECRET_BODY)).clone();
    r.path = "/webhooks/123/WEBHOOK-TOKEN/messages".into();
    r.headers.push(("x-custom".into(), b"visible".to_vec()));
    r.headers
        .push(("cookie".into(), b"session=COOKIE-VALUE".to_vec()));
    let h = held(&t, "muse", Arc::new(r));
    let v = t.view(&h.id).unwrap();
    assert_eq!(v.state, State::Pending);
    let c = v.content.as_ref().unwrap();
    assert_eq!(c.path, "/webhooks/123/<redacted>/messages");
    assert_eq!(c.query.as_deref(), Some("wait=true"));
    assert_eq!(c.content_type.as_deref(), Some("application/json"));
    assert_eq!(c.body_len, SECRET_BODY.len());
    assert_eq!(c.body_text, SECRET_BODY);
    assert!(!c.body_lossy);
    assert_eq!(c.digest, h.digest);
    for hd in &c.headers {
        match hd.name.as_str() {
            "authorization" | "x-api-key" | "cookie" => assert!(hd.value.is_none(), "{}", hd.name),
            "content-type" | "x-custom" => assert!(hd.value.is_some(), "{}", hd.name),
            other => panic!("unexpected header {other}"),
        }
    }
    assert!(!c.headers.iter().any(|h| h
        .value
        .as_deref()
        .is_some_and(|v| v.contains("SENTINEL") || v.contains("COOKIE-VALUE"))));
}

#[tokio::test(start_paused = true)]
async fn view_marks_a_body_that_is_not_utf8() {
    let t = table(8, 4, 60);
    let mut r = (*req(SECRET_AUTH, "")).clone();
    r.body = Bytes::from_static(&[0x7b, 0xff, 0xfe, 0x7d]);
    let h = held(&t, "muse", Arc::new(r));
    let c = t.view(&h.id).unwrap().content.unwrap();
    assert!(c.body_lossy);
    assert_eq!(c.body_len, 4);
}

#[tokio::test(start_paused = true)]
async fn view_of_a_decided_entry_has_no_content() {
    let t = table(8, 4, 60);
    let a = held(&t, "muse", req(SECRET_AUTH, "same"));
    let b = held(&t, "muse", req(SECRET_AUTH, "same"));
    let v = t.view(&a.id).unwrap();
    assert_eq!(v.state, State::Superseded);
    assert_eq!(v.superseded_by.as_deref(), Some(b.id.as_str()));
    assert!(v.content.is_none());
    assert!(t.view("unknown").is_none());
}

#[tokio::test(start_paused = true)]
async fn no_secret_or_fingerprint_in_any_debug_output() {
    let t = table(8, 4, 60);
    let r = req(SECRET_AUTH, SECRET_BODY);
    let fp = t.fingerprinter.fingerprint(&r).hex_for_test();
    let h = held(&t, "muse", r.clone());
    let view = t.view(&h.id).unwrap();
    let mut shown = String::new();
    shown.push_str(&format!(
        "{r:?}\n{t:?}\n{h:?}\n{view:?}\n{:?}\n",
        view.content
    ));
    shown.push_str(&format!("{:?}\n", view.content.as_ref().unwrap().headers));
    {
        let g = t.lock();
        for e in g.pending.values() {
            shown.push_str(&format!("{e:?}\n{:?}\n", e.fingerprint));
        }
    }
    shown.push_str(&format!("{:?}\n", t.fingerprinter));
    let id = h.id.clone();
    let task = handler(h, Mode::Send(Confirm::Started));
    // The decision types hold the approver name and a sender, never the request.
    assert_eq!(t.approve(&id, "alice").await, ApproveResult::Success);
    task.await.unwrap();
    shown.push_str(&format!("{:?}\n", Admission::Refused(Code::Cooldown)));
    for secret in [
        SECRET_AUTH,
        "SENTINEL",
        SECRET_BODY,
        SECRET_KEY,
        fp.as_str(),
    ] {
        assert!(!shown.contains(secret), "Debug leaked {secret}");
    }
    assert!(shown.contains("Fingerprint(..)"));
}

#[tokio::test(start_paused = true)]
async fn list_returns_pending_entries_in_admission_order_and_no_decided_ones() {
    let t = table(8, 8, 0);
    let a = held(&t, "x", req("Bot a", "1"));
    let b = held(&t, "x", req("Bot b", "2"));
    let c = held(&t, "y", req("Bot c", "3"));
    let ids = |t: &Table| t.list().into_iter().map(|v| v.id).collect::<Vec<_>>();
    assert_eq!(ids(&t), vec![a.id.clone(), b.id.clone(), c.id.clone()]);
    assert!(t.list().iter().all(|v| v.content.is_some()));
    assert_eq!(t.deny(&b.id, "alice"), DenyResult::Denied);
    assert_eq!(ids(&t), vec![a.id, c.id]);
}
