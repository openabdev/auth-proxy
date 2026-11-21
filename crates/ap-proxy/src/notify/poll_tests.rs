//! Callback intake: the owner check, the callback data shape, and `getUpdates` offsets against a
//! loopback server. Every value is synthetic; no test reaches the real Bot API.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::poll::*;
use super::TELEGRAM_API;
use crate::hold::CallbackAction;

const OWNER: i64 = 4242;
const TOKEN: &str = "123456:SYNTHETIC_TOKEN_0008";
const REQ_ID: &str = "0123456789abcdef0123456789abcdef";
const NONCE: &str = "00112233445566778899aabb";

fn update(update_id: i64, from: i64, data: &str) -> Value {
    json!({
        "update_id": update_id,
        "callback_query": {
            "id": format!("cbq-{update_id}"),
            "from": { "id": from },
            "data": data,
        }
    })
}

#[test]
fn owner_callback_with_the_fixed_shape_is_parsed() {
    let data = callback_data(CallbackAction::Approve, REQ_ID, NONCE);
    assert_eq!(data.len(), CALLBACK_DATA_LEN);
    let got = parse_update(&update(1, OWNER, &data), OWNER);
    assert_eq!(
        got,
        Some(Update::Callback(Callback {
            callback_id: "cbq-1".into(),
            action: CallbackAction::Approve,
            request_id: REQ_ID.into(),
            nonce: NONCE.into(),
        }))
    );
    let deny = callback_data(CallbackAction::Deny, REQ_ID, NONCE);
    assert!(matches!(
        parse_update(&update(2, OWNER, &deny), OWNER),
        Some(Update::Callback(Callback {
            action: CallbackAction::Deny,
            ..
        }))
    ));
}

#[test]
fn non_owner_callback_is_returned_as_unauthorised_not_parsed() {
    let data = callback_data(CallbackAction::Approve, REQ_ID, NONCE);
    assert_eq!(
        parse_update(&update(3, OWNER + 1, &data), OWNER),
        Some(Update::Refused {
            callback_id: "cbq-3".into(),
            reply: NOT_AUTHORISED,
        })
    );
}

#[test]
fn callback_data_of_the_wrong_length_or_alphabet_is_rejected() {
    let good = callback_data(CallbackAction::Approve, REQ_ID, NONCE);
    let bad = [
        format!("x{}", &good[1..]),
        good.to_uppercase(),
        format!("{good}0"),
        good[..good.len() - 1].to_string(),
        format!("a{REQ_ID}{}", "G".repeat(24)),
        format!("a{}", "é".repeat(28)),
        String::new(),
    ];
    for data in bad {
        assert_eq!(
            parse_update(&update(4, OWNER, &data), OWNER),
            Some(Update::Refused {
                callback_id: "cbq-4".into(),
                reply: NOT_RECOGNISED,
            }),
            "accepted {data:?}"
        );
    }
}

#[test]
fn messages_that_are_not_callbacks_are_ignored() {
    let msg = json!({ "update_id": 5, "message": { "text": "hi", "from": { "id": OWNER } } });
    assert_eq!(parse_update(&msg, OWNER), None);
}

/// A loopback `getUpdates` server. `replies` are answered in order; once they run out the server
/// holds the connection open, as a long poll with nothing new does. Returns the base URL and the
/// request bodies seen.
async fn server(replies: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let s = Arc::clone(&seen);
    let replies = Arc::new(Mutex::new(replies.into_iter()));
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let (s, replies) = (Arc::clone(&s), Arc::clone(&replies));
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                let body = loop {
                    let n = c.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let want = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if body.len() >= want {
                            break body.to_string();
                        }
                    }
                };
                s.lock().unwrap().push(body);
                let next = replies.lock().unwrap().next();
                match next {
                    Some(r) => {
                        let _ = c.write_all(r.as_bytes()).await;
                        let _ = c.shutdown().await;
                    }
                    None => tokio::time::sleep(Duration::from_secs(60)).await,
                }
            });
        }
    });
    (base, seen)
}

fn ok_json(v: &Value) -> String {
    let body = v.to_string();
    format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn getupdates_advances_offset_past_each_update_and_hands_them_on() {
    let data = callback_data(CallbackAction::Approve, REQ_ID, NONCE);
    let first = json!({ "ok": true, "result": [
        update(10, OWNER, &data),
        update(11, OWNER + 1, &data),
    ]});
    let (base, seen) = server(vec![ok_json(&first)]).await;
    let poller =
        Arc::new(TelegramPoller::with_api(&base, TOKEN, OWNER, Duration::from_secs(5)).unwrap());
    let got: Arc<Mutex<Vec<Update>>> = Arc::default();
    let g = Arc::clone(&got);
    let task = tokio::spawn(run(Arc::clone(&poller), move |u| g.lock().unwrap().push(u)));
    for _ in 0..200 {
        let polls = seen.lock().unwrap().len();
        if got.lock().unwrap().len() == 2 && polls >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    task.abort();
    let bodies = seen.lock().unwrap().clone();
    assert!(bodies.len() >= 2, "{bodies:?}");
    let first_req: Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(first_req["offset"], 0);
    assert_eq!(first_req["allowed_updates"], json!(["callback_query"]));
    let second_req: Value = serde_json::from_str(&bodies[1]).unwrap();
    assert_eq!(
        second_req["offset"], 12,
        "offset moves past the last update"
    );
    let got = got.lock().unwrap().clone();
    assert!(matches!(got[0], Update::Callback(_)));
    assert!(matches!(
        got[1],
        Update::Refused {
            reply: NOT_AUTHORISED,
            ..
        }
    ));
}

#[tokio::test]
async fn a_conflict_is_reported_without_the_token() {
    let (base, _seen) = server(vec![
        "HTTP/1.1 409 Conflict\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".to_string(),
    ])
    .await;
    let poller = TelegramPoller::with_api(&base, TOKEN, OWNER, Duration::from_secs(5)).unwrap();
    let err = poller.get_updates(0).await.unwrap_err();
    assert_eq!(err, PollError::Conflict);
    assert!(!format!("{err:?} {poller:?}").contains(TOKEN));
}

#[test]
fn bad_tokens_and_owner_ids_are_refused() {
    assert!(TelegramPoller::with_api(TELEGRAM_API, "", OWNER, Duration::from_secs(5)).is_err());
    assert!(TelegramPoller::with_api(TELEGRAM_API, "1/2", OWNER, Duration::from_secs(5)).is_err());
    assert!(TelegramPoller::with_api(TELEGRAM_API, TOKEN, 0, Duration::from_secs(5)).is_err());
}
