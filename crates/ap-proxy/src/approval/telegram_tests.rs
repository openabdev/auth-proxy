//! The hold-side secrets of the Telegram buttons: the nonce and the one-time view token. They are
//! checked here at the table; the end-to-end press and view cases are in `approval/tests.rs`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use super::telegram::APPROVER;
use crate::hold::{
    digest, Admission, CallbackAction, CallbackRefusal, CallbackTransition, Held, HeldRequest,
    Limits, State, Table, Upstream,
};
use crate::notify::poll::callback_data;

fn table() -> Table {
    Table::new(Limits {
        hold: Duration::from_secs(90),
        max_total: 8,
        max_per_identity: 8,
        cooldown: Duration::ZERO,
    })
}

fn request(body: &'static [u8]) -> Arc<HeldRequest> {
    Arc::new(HeldRequest {
        method: "POST".into(),
        route: "discord".into(),
        upstream: Upstream {
            scheme: "https".into(),
            host: "discord.example.test".into(),
            port: 443,
            keep_auth: Vec::new(),
        },
        generation: 1,
        path: "/hold/1".into(),
        query: None,
        headers: vec![("authorization".into(), b"Bot SYNTHETIC-AUTH-0011".to_vec())],
        body: Bytes::from_static(body),
        token_admitted: false,
    })
}

fn admit(t: &Table, body: &'static [u8]) -> Held {
    match t.admit("muse-pilot", request(body), |_, _| Ok(())) {
        Admission::Held(h) => h,
        Admission::Refused(c) => panic!("refused: {c:?}"),
    }
}

#[test]
fn nonce_and_view_token_have_the_documented_shape() {
    let t = table();
    let h = admit(&t, b"{\"a\":1}");
    assert_eq!(h.nonce.len(), 24);
    assert_eq!(h.view_token.len(), 32);
    assert!(h.nonce.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(h.view_token.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(h.nonce, h.view_token);
    assert_eq!(
        callback_data(CallbackAction::Approve, &h.id, &h.nonce).len(),
        crate::notify::poll::CALLBACK_DATA_LEN
    );
}

#[test]
fn view_token_is_live_only_while_pending() {
    let t = table();
    let mut ended_by = Vec::new();
    for (i, body) in [
        b"{\"n\":0}" as &'static [u8],
        b"{\"n\":1}",
        b"{\"n\":2}",
        b"{\"n\":3}",
        b"{\"n\":4}",
    ]
    .into_iter()
    .enumerate()
    {
        let h = admit(&t, body);
        assert!(t.view_by_token(&h.view_token).is_some(), "live {i}");
        match i {
            0 => {
                assert!(matches!(
                    t.transition_by_callback(
                        &h.id,
                        &h.nonce,
                        CallbackAction::Approve,
                        APPROVER,
                        |_, _| true
                    ),
                    CallbackTransition::ApproveStarted(_)
                ));
            }
            1 => {
                t.deny(&h.id, APPROVER);
            }
            2 => {
                assert!(t.expire(&h.id));
            }
            3 => {
                assert_eq!(t.drop_all(), 1);
            }
            _ => {
                assert!(t.abandon(&h.id));
            }
        }
        assert!(t.view_by_token(&h.view_token).is_none(), "ended {i}");
        ended_by.push(h.view_token.clone());
        drop(h);
    }
    assert_eq!(t.state(&"0".repeat(32)), None);
    for token in ended_by {
        assert!(t.view_by_token(&token).is_none());
    }
}

#[test]
fn a_callback_with_the_wrong_nonce_changes_nothing() {
    let t = table();
    let h = admit(&t, b"{\"a\":1}");
    let wrong = digest::random_hex(12);
    assert!(matches!(
        t.transition_by_callback(&h.id, &wrong, CallbackAction::Deny, APPROVER, |_, _| true),
        CallbackTransition::Refused(CallbackRefusal::NonceMismatch)
    ));
    assert_eq!(t.state(&h.id), Some(State::Pending));
    assert!(t.view_by_token(&h.view_token).is_some());
}

#[test]
fn a_policy_that_no_longer_holds_drops_the_entry_on_approve() {
    let t = table();
    let mut h = admit(&t, b"{\"a\":1}");
    assert!(matches!(
        t.transition_by_callback(
            &h.id,
            &h.nonce,
            CallbackAction::Approve,
            APPROVER,
            |_, _| false
        ),
        CallbackTransition::Refused(CallbackRefusal::PolicyChanged)
    ));
    assert_eq!(t.state(&h.id), Some(State::Dropped));
    assert!(matches!(
        h.decision.try_recv(),
        Ok(crate::hold::Decision::Dropped)
    ));
}

#[test]
fn held_and_secrets_never_print() {
    let t = table();
    let h = admit(&t, b"{\"a\":1}");
    let shown = format!("{h:?} {t:?}");
    assert!(!shown.contains(&h.nonce));
    assert!(!shown.contains(&h.view_token));
    assert!(!shown.contains("SYNTHETIC-AUTH-0011"));
}
