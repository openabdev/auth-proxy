//! The poll side of the Muse async hold mode (`docs/design/muse-async-poll.md`).
//!
//! An admitted request gets a random poll token. The store keeps only the sha256 of the token, the
//! request id and the state. `GET /poll/<token>?wait=N` reads the state and never changes it: the
//! token cannot approve, deny or cancel anything. A final status stays readable for
//! [`FINAL_WINDOW_SECS`] from the transition, on the app clock; afterwards, and for any token the
//! store does not know, the answer is one uniform 404. Nothing here is persistent, so a restart
//! forgets every entry.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ap_broker::registry::sha256_hex;
use axum::body::Body;
use http::{header, HeaderValue, Response, StatusCode};
use serde_json::{json, Value};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::hold::digest::{ct_eq, random_hex};

/// How long a final status stays readable, from the final transition.
pub const FINAL_WINDOW_SECS: u64 = 60;
/// Longest `wait` a poll may ask for.
pub const MAX_WAIT_SECS: u64 = 25;
/// Largest Discord response body kept for a poll.
pub const BODY_MAX: usize = 64 * 1024;
/// Polls one token may make in one clock second before it is answered 429.
const POLLS_PER_SEC: u32 = 10;

/// How a held request ended, as the poll reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Final {
    Approved {
        discord_status: u16,
        body: Vec<u8>,
        truncated: bool,
    },
    Denied,
    Expired,
    Dropped,
    SendFailed,
    /// Past the first request byte with no confirmed Discord response. `error_class` is `reset`,
    /// `timeout` or `write_failed`.
    SendUnknown(&'static str),
}

#[derive(Clone)]
enum State {
    Pending,
    Final { at: u64, out: Final },
}

struct Slot {
    /// sha256 hex of the poll token.
    key: String,
    request_id: String,
    state: State,
    notify: Arc<Notify>,
    /// Rate-limit window: the clock second and the polls seen in it.
    second: u64,
    polls: u32,
}

/// What a read found.
enum Read {
    NotFound,
    Limited,
    Pending { id: String, notify: Arc<Notify> },
    Final { id: String, out: Final },
}

/// The in-memory poll table.
#[derive(Default)]
pub struct PollStore {
    slots: Mutex<Vec<Slot>>,
}

impl PollStore {
    fn lock(&self) -> MutexGuard<'_, Vec<Slot>> {
        match self.slots.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// A fresh token for a new pending entry. 128 random bits as hex; only its hash is stored.
    pub fn insert(&self, request_id: &str, now: u64) -> String {
        let token = random_hex(16);
        let mut g = self.lock();
        g.retain(|s| !expired(s, now));
        g.push(Slot {
            key: sha256_hex(&token),
            request_id: request_id.to_string(),
            state: State::Pending,
            notify: Arc::new(Notify::new()),
            second: now,
            polls: 0,
        });
        token
    }

    /// Record the final status of the entry for `request_id`. The first one wins.
    pub fn finish(&self, request_id: &str, out: Final, now: u64) {
        let mut g = self.lock();
        if let Some(s) = g.iter_mut().find(|s| s.request_id == request_id) {
            if matches!(s.state, State::Pending) {
                s.state = State::Final { at: now, out };
                s.notify.notify_waiters();
            }
        }
    }

    /// Whether any entry for `request_id` is still pending.
    #[cfg(test)]
    pub fn pending_len(&self) -> usize {
        self.lock()
            .iter()
            .filter(|s| matches!(s.state, State::Pending))
            .count()
    }

    fn read(&self, token: &str, now: u64, count: bool) -> Read {
        let key = sha256_hex(token);
        let mut g = self.lock();
        g.retain(|s| !expired(s, now));
        // Every slot is compared, so the time taken does not show which one matched.
        let mut hit = None;
        for (i, s) in g.iter().enumerate() {
            if ct_eq(&s.key, &key) {
                hit = Some(i);
            }
        }
        let Some(i) = hit else {
            return Read::NotFound;
        };
        let s = &mut g[i];
        if count {
            if s.second != now {
                s.second = now;
                s.polls = 0;
            }
            if s.polls >= POLLS_PER_SEC {
                return Read::Limited;
            }
            s.polls += 1;
        }
        match &s.state {
            State::Pending => Read::Pending {
                id: s.request_id.clone(),
                notify: Arc::clone(&s.notify),
            },
            State::Final { out, .. } => Read::Final {
                id: s.request_id.clone(),
                out: out.clone(),
            },
        }
    }
}

fn expired(s: &Slot, now: u64) -> bool {
    matches!(&s.state, State::Final { at, .. } if now >= at.saturating_add(FINAL_WINDOW_SECS))
}

/// Ends the entry as `dropped` if the task that should finish it goes away without doing so.
pub struct FinishGuard {
    store: Arc<PollStore>,
    clock: Arc<dyn ap_broker::clock::Clock + Send + Sync>,
    request_id: String,
}

impl FinishGuard {
    pub fn new(
        store: Arc<PollStore>,
        clock: Arc<dyn ap_broker::clock::Clock + Send + Sync>,
        request_id: &str,
    ) -> FinishGuard {
        FinishGuard {
            store,
            clock,
            request_id: request_id.to_string(),
        }
    }

    pub fn finish(&self, out: Final) {
        self.store.finish(&self.request_id, out, self.clock.now());
    }
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        // A no-op when `finish` already ran: the first final status wins.
        self.finish(Final::Dropped);
    }
}

fn json_response(status: StatusCode, v: &Value) -> Response<Body> {
    let mut r = Response::new(Body::from(v.to_string()));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// The one answer for an unknown token, an ended window and any method but GET.
pub fn not_found() -> Response<Body> {
    json_response(StatusCode::NOT_FOUND, &json!({"error": "not_found"}))
}

/// The 202 a POST gets in async mode. No body or `Authorization` of the request is in it.
pub fn accepted(request_id: &str, token: &str) -> Response<Body> {
    json_response(
        StatusCode::ACCEPTED,
        &json!({"status": "pending", "request_id": request_id, "poll_token": token}),
    )
}

/// `wait` from the query: missing is 0, an integer above the cap is the cap, anything else (not
/// all digits, empty, repeated) is `None`.
fn parse_wait(query: Option<&str>) -> Option<u64> {
    let mut found = None;
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k != "wait" {
            continue;
        }
        if found.is_some() || v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // More than nine digits is certainly above the cap.
        found = Some(if v.len() > 9 {
            MAX_WAIT_SECS
        } else {
            v.parse::<u64>().ok()?.min(MAX_WAIT_SECS)
        });
    }
    Some(found.unwrap_or(0))
}

fn final_json(id: &str, out: &Final) -> Value {
    match out {
        Final::Approved {
            discord_status,
            body,
            truncated,
        } => json!({
            "status": "approved_and_sent",
            "request_id": id,
            "discord_status": discord_status,
            "body": String::from_utf8_lossy(body),
            "truncated": truncated,
        }),
        Final::Denied => json!({"status": "denied", "request_id": id}),
        Final::Expired => json!({"status": "expired", "request_id": id}),
        Final::Dropped => json!({"status": "dropped", "request_id": id}),
        Final::SendFailed => json!({"status": "send_failed", "request_id": id}),
        Final::SendUnknown(class) => {
            json!({"status": "send_unknown", "request_id": id, "error_class": class})
        }
    }
}

/// Answer `GET /poll/<token>?wait=N`. The caller has already checked the method and the prefix.
pub async fn poll(
    store: &PollStore,
    clock: &(dyn ap_broker::clock::Clock + Send + Sync),
    token: &str,
    query: Option<&str>,
) -> Response<Body> {
    // The wait is checked first, so a bad one says nothing about the token.
    let Some(wait) = parse_wait(query) else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"error": "bad_wait"}));
    };
    let deadline = Instant::now() + Duration::from_secs(wait);
    let mut count = true;
    loop {
        let (id, notify) = match store.read(token, clock.now(), count) {
            Read::NotFound => return not_found(),
            Read::Limited => {
                let mut r = json_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    &json!({"error": "rate_limited"}),
                );
                r.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                return r;
            }
            Read::Final { id, out } => {
                return json_response(StatusCode::OK, &final_json(&id, &out))
            }
            Read::Pending { id, notify } => (id, notify),
        };
        count = false;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return json_response(
                StatusCode::OK,
                &json!({"status": "pending", "request_id": id}),
            );
        }
        // Register for the wake-up, then look again, so a final status set in between is seen.
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !matches!(store.read(token, clock.now(), false), Read::Pending { .. }) {
            continue;
        }
        let _ = tokio::time::timeout(left, notified).await;
    }
}

#[cfg(test)]
mod tests;
