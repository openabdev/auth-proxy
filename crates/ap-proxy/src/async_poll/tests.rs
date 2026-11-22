//! The poll store and the poll answer, without a hold table.

use super::*;
use ap_broker::clock::{Clock, ManualClock};

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(1_000))
}

async fn get(
    store: &PollStore,
    clock: &Arc<ManualClock>,
    token: &str,
    query: Option<&str>,
) -> (StatusCode, Value) {
    let c: &(dyn Clock + Send + Sync) = clock.as_ref();
    let r = poll(store, c, token, query).await;
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn every_final_status_reads_back_with_its_fields() {
    let store = PollStore::default();
    let c = clock();
    let cases = [
        (
            Final::Approved {
                discord_status: 200,
                body: b"{\"id\":\"1\"}".to_vec(),
                truncated: false,
            },
            "approved_and_sent",
        ),
        (Final::Denied, "denied"),
        (Final::Expired, "expired"),
        (Final::Dropped, "dropped"),
        (Final::SendFailed, "send_failed"),
        (Final::SendUnknown("reset"), "send_unknown"),
    ];
    for (i, (out, name)) in cases.into_iter().enumerate() {
        let id = format!("req-{i}");
        let token = store.insert(&id, c.now());
        assert_eq!(get(&store, &c, &token, None).await.1["status"], "pending");
        store.finish(&id, out, c.now());
        let (st, v) = get(&store, &c, &token, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["status"], name);
        assert_eq!(v["request_id"], id);
        match name {
            "approved_and_sent" => {
                assert_eq!(v["discord_status"], 200);
                assert_eq!(v["body"], "{\"id\":\"1\"}");
                assert_eq!(v["truncated"], false);
            }
            "send_unknown" => assert_eq!(v["error_class"], "reset"),
            _ => assert_eq!(v.as_object().unwrap().len(), 2, "{v}"),
        }
    }
}

#[tokio::test]
async fn first_final_status_wins() {
    let store = PollStore::default();
    let c = clock();
    let token = store.insert("r", c.now());
    store.finish("r", Final::Expired, c.now());
    store.finish("r", Final::Denied, c.now());
    assert_eq!(get(&store, &c, &token, None).await.1["status"], "expired");
}

#[tokio::test]
async fn final_is_readable_for_sixty_seconds_then_uniform_404() {
    let store = PollStore::default();
    let c = clock();
    let token = store.insert("r", c.now());
    store.finish("r", Final::Denied, c.now());
    c.advance(FINAL_WINDOW_SECS - 1);
    assert_eq!(get(&store, &c, &token, None).await.0, StatusCode::OK);
    c.advance(1);
    let gone = get(&store, &c, &token, None).await;
    let unknown = get(&store, &c, "0123456789abcdef0123456789abcdef", None).await;
    assert_eq!(gone.0, StatusCode::NOT_FOUND);
    assert_eq!(gone, unknown, "an ended window looks like an unknown token");
    assert_eq!(store.pending_len(), 0);
}

#[tokio::test]
async fn pending_does_not_expire_by_the_window() {
    let store = PollStore::default();
    let c = clock();
    let token = store.insert("r", c.now());
    c.advance(10_000);
    assert_eq!(get(&store, &c, &token, None).await.1["status"], "pending");
}

#[tokio::test]
async fn wait_parameter_handling() {
    let store = PollStore::default();
    let c = clock();
    let token = store.insert("r", c.now());
    for q in [
        "wait=abc",
        "wait=-1",
        "wait=",
        "wait=1.5",
        "wait=+2",
        "wait=1&wait=2",
    ] {
        let (st, v) = get(&store, &c, &token, Some(q)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{q}");
        assert_eq!(v["error"], "bad_wait");
        // The same answer for a token that does not exist.
        assert_eq!(get(&store, &c, "nope", Some(q)).await, (st, v), "{q}");
    }
    assert_eq!(parse_wait(None), Some(0));
    assert_eq!(parse_wait(Some("x=1")), Some(0));
    assert_eq!(parse_wait(Some("wait=7")), Some(7));
    assert_eq!(parse_wait(Some("wait=26")), Some(25));
    assert_eq!(parse_wait(Some("wait=99999999999999999999999")), Some(25));
    assert_eq!(parse_wait(Some("a=1&wait=3")), Some(3));
}

#[tokio::test(start_paused = true)]
async fn wait_returns_pending_after_the_wait_and_the_final_status_when_it_arrives() {
    let store = Arc::new(PollStore::default());
    let c = clock();
    let token = store.insert("r", c.now());
    let t0 = tokio::time::Instant::now();
    let (_, v) = get(&store, &c, &token, Some("wait=3")).await;
    assert_eq!(v["status"], "pending");
    assert_eq!(t0.elapsed(), Duration::from_secs(3));
    // A wait above the cap is cut at 25 s.
    let t0 = tokio::time::Instant::now();
    let (_, v) = get(&store, &c, &token, Some("wait=60")).await;
    assert_eq!(v["status"], "pending");
    assert_eq!(t0.elapsed(), Duration::from_secs(MAX_WAIT_SECS));
    // A final status wakes the waiter early.
    let s2 = Arc::clone(&store);
    let c2 = Arc::clone(&c);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        s2.finish("r", Final::Denied, c2.now());
    });
    let t0 = tokio::time::Instant::now();
    let (_, v) = get(&store, &c, &token, Some("wait=20")).await;
    assert_eq!(v["status"], "denied");
    assert_eq!(t0.elapsed(), Duration::from_secs(2));
}

#[tokio::test]
async fn rapid_polls_just_return_the_current_status() {
    let store = PollStore::default();
    let c = clock();
    let token = store.insert("r", c.now());
    for _ in 0..50 {
        let (code, v) = get(&store, &c, &token, None).await;
        assert_eq!(
            (code, v["status"].as_str()),
            (StatusCode::OK, Some("pending"))
        );
    }
}

#[tokio::test]
async fn the_guard_ends_an_unfinished_entry_as_dropped() {
    let store = Arc::new(PollStore::default());
    let c = clock();
    let token = store.insert("r", c.now());
    drop(FinishGuard::new(
        Arc::clone(&store),
        c.clone(),
        "r",
        Box::new(|| Final::Dropped),
    ));
    assert_eq!(get(&store, &c, &token, None).await.1["status"], "dropped");
}

#[test]
fn the_token_is_128_bits_and_only_its_hash_is_stored() {
    let store = PollStore::default();
    let a = store.insert("a", 0);
    let b = store.insert("b", 0);
    assert_eq!(a.len(), 32);
    assert_ne!(a, b);
    let g = store.lock();
    assert!(g
        .iter()
        .all(|s| s.key != a && s.key == sha256_hex(&a) || s.key == sha256_hex(&b)));
}
