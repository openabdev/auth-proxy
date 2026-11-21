//! Telegram callback intake for the approve and deny buttons (stage 2 buttons).
//!
//! The gate reads button presses by long polling `getUpdates`, so no public webhook exists. An
//! update counts only when it is a callback query from the configured owner id, and its
//! `callback_data` has the fixed shape: a verb (`a` or `d`), the 32-hex request id and the 24-hex
//! nonce, 57 bytes in all. The nonce is checked against the live hold by the caller.
//!
//! Errors carry no URL, token or chat id, following [`NotifyError`]'s rule.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use serde_json::{json, Value};

use super::{valid_token, NotifyError, TELEGRAM_API};
use crate::hold::CallbackAction;

/// Telegram caps `callback_data` at 64 bytes: one verb, 32 hex of request id, 24 hex of nonce.
pub const CALLBACK_DATA_LEN: usize = 57;

/// Seconds Telegram holds an empty `getUpdates` open.
const POLL_SECS: u64 = 25;
/// Connect and whole request. Longer than the poll, so a normal empty poll never times out.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Wait after a failed `getUpdates` before the next one.
const BACKOFF: Duration = Duration::from_secs(5);

/// A button press from the owner, already shape-checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    pub callback_id: String,
    pub action: CallbackAction,
    pub request_id: String,
    pub nonce: String,
}

/// A callback query the gate must answer. `Refused` carries the short reply shown to the
/// presser and changes nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    Callback(Callback),
    Refused {
        callback_id: String,
        reply: &'static str,
    },
}

/// Reply to a callback from anyone but the owner. It reveals nothing about any hold.
pub const NOT_AUTHORISED: &str = "Not authorised";
/// Reply to an owner callback whose data does not have the fixed shape.
pub const NOT_RECOGNISED: &str = "Not recognised";

fn lower_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Split `callback_data` into its verb, request id and nonce. Only the exact 57-byte shape counts.
fn parse_data(data: &str) -> Option<(CallbackAction, String, String)> {
    if data.len() != CALLBACK_DATA_LEN || !data.is_ascii() {
        return None;
    }
    let action = match &data[..1] {
        "a" => CallbackAction::Approve,
        "d" => CallbackAction::Deny,
        _ => return None,
    };
    let (id, nonce) = (&data[1..33], &data[33..]);
    if !lower_hex(id) || !lower_hex(nonce) {
        return None;
    }
    Some((action, id.to_string(), nonce.to_string()))
}

/// Classify one raw update. `None` for anything that is not a callback query.
pub fn parse_update(update: &Value, owner: i64) -> Option<Update> {
    let q = update.get("callback_query")?;
    let callback_id = q.get("id")?.as_str()?.to_string();
    let from = q.get("from")?.get("id")?.as_i64();
    if from != Some(owner) {
        return Some(Update::Refused {
            callback_id,
            reply: NOT_AUTHORISED,
        });
    }
    let data = q.get("data").and_then(Value::as_str).unwrap_or("");
    Some(match parse_data(data) {
        Some((action, request_id, nonce)) => Update::Callback(Callback {
            callback_id,
            action,
            request_id,
            nonce,
        }),
        None => Update::Refused {
            callback_id,
            reply: NOT_RECOGNISED,
        },
    })
}

/// The callback data for one button: verb, request id and nonce.
pub fn callback_data(action: CallbackAction, request_id: &str, nonce: &str) -> String {
    let verb = match action {
        CallbackAction::Approve => 'a',
        CallbackAction::Deny => 'd',
    };
    format!("{verb}{request_id}{nonce}")
}

fn json_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

/// A failed `getUpdates`. `Conflict` is HTTP 409, which Telegram sends while a webhook is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollError {
    Conflict,
    Failed,
}

/// Long-polls `getUpdates` and answers callback queries, for one owner id.
pub struct TelegramPoller {
    client: reqwest::Client,
    updates_url: String,
    answer_url: String,
    owner: i64,
}

impl fmt::Debug for TelegramPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TelegramPoller(..)")
    }
}

impl TelegramPoller {
    /// Build for the production Bot API.
    pub fn new(token: &str, owner: i64) -> Result<Self, NotifyError> {
        Self::with_api(TELEGRAM_API, token, owner, REQUEST_TIMEOUT)
    }

    pub(crate) fn with_api(
        api: &str,
        token: &str,
        owner: i64,
        timeout: Duration,
    ) -> Result<Self, NotifyError> {
        if !valid_token(token) || owner <= 0 {
            return Err(NotifyError);
        }
        // As the notifier: no proxies, no redirects, and the token-bearing URLs stay on the API host.
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| NotifyError)?;
        let root = api.trim_end_matches('/');
        Ok(TelegramPoller {
            client,
            updates_url: format!("{root}/bot{token}/getUpdates"),
            answer_url: format!("{root}/bot{token}/answerCallbackQuery"),
            owner,
        })
    }

    /// The owner id that `parse_update` checks against.
    pub fn owner(&self) -> i64 {
        self.owner
    }

    /// One long poll from `offset`, for callback queries only.
    pub async fn get_updates(&self, offset: i64) -> Result<Vec<Value>, PollError> {
        let body = json!({
            "offset": offset,
            "timeout": POLL_SECS,
            "allowed_updates": ["callback_query"],
        });
        // The error is dropped: its text contains the URL, and so the token.
        let resp = self
            .client
            .post(&self.updates_url)
            .header(CONTENT_TYPE, "application/json")
            .body(json_bytes(&body))
            .send()
            .await
            .map_err(|_| PollError::Failed)?;
        let status = resp.status();
        if status == reqwest::StatusCode::CONFLICT {
            return Err(PollError::Conflict);
        }
        if !status.is_success() {
            return Err(PollError::Failed);
        }
        let bytes = resp.bytes().await.map_err(|_| PollError::Failed)?;
        let v: Value = serde_json::from_slice(&bytes).map_err(|_| PollError::Failed)?;
        v.get("result")
            .and_then(Value::as_array)
            .cloned()
            .ok_or(PollError::Failed)
    }

    /// Answer one callback query so the button stops spinning. A failure is logged without detail.
    pub async fn answer(&self, callback_id: &str, text: &str) {
        let body = json!({ "callback_query_id": callback_id, "text": text });
        let sent = self
            .client
            .post(&self.answer_url)
            .header(CONTENT_TYPE, "application/json")
            .body(json_bytes(&body))
            .send()
            .await;
        if !matches!(sent, Ok(ref r) if r.status().is_success()) {
            eprintln!("auth-proxy: telegram answerCallbackQuery failed");
        }
    }
}

/// Poll forever. Every parsed update goes to `on_update`, which must not block. A failed poll
/// waits [`BACKOFF`] and tries again. The offset moves past each update seen, so none repeats.
pub async fn run(poller: Arc<TelegramPoller>, mut on_update: impl FnMut(Update)) {
    let mut offset: i64 = 0;
    loop {
        match poller.get_updates(offset).await {
            Ok(updates) => {
                for u in updates {
                    if let Some(id) = u.get("update_id").and_then(Value::as_i64) {
                        offset = offset.max(id.saturating_add(1));
                    }
                    if let Some(parsed) = parse_update(&u, poller.owner()) {
                        on_update(parsed);
                    }
                }
            }
            Err(PollError::Conflict) => {
                eprintln!("auth-proxy: telegram getUpdates conflict: a webhook may be set");
                tokio::time::sleep(BACKOFF).await;
            }
            Err(PollError::Failed) => {
                eprintln!("auth-proxy: telegram getUpdates failed");
                tokio::time::sleep(BACKOFF).await;
            }
        }
    }
}
