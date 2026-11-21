//! Notification hook for new hold entries (design 3.4 step 5, 3.6.1).
//!
//! The gate stores an optional [`Notifier`] and calls it for a new distinct entry, never for a
//! supersede. The Telegram implementation sends one `sendMessage` per call. Its text is the fixed
//! sentence, the request id and the approval link, and nothing else. The Bot API takes the token in
//! the URL path, so the token file is read under the rules for every secret file here, and no error
//! or Debug output of this module contains the URL, the token or the chat id.

use std::fmt;
use std::future::Future;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use reqwest::header::CONTENT_TYPE;

/// The fixed sentence that opens every notification.
pub const TEXT: &str = "A gated request is waiting for approval.";

/// The Bot API root. Production always uses this; tests point the notifier at a loopback mock.
pub const TELEGRAM_API: &str = "https://api.telegram.org";

/// Per attempt: connect and whole request each get this long.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// A notification could not be delivered. It carries no detail, so no URL, token or chat id can
/// reach a log through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyError;

impl fmt::Display for NotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("notification failed")
    }
}

impl std::error::Error for NotifyError {}

/// The two inline buttons of a notification. Each value is the `callback_data` the button sends
/// back: a verb character, the request id and the hold's nonce (57 bytes, under Telegram's 64).
#[derive(Clone, PartialEq, Eq)]
pub struct Buttons {
    pub approve: String,
    pub deny: String,
}

impl fmt::Debug for Buttons {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Buttons(..)")
    }
}

/// Sends one notification about a new held request.
pub trait Notifier: Send + Sync {
    /// One delivery, with at most one bounded retry inside the implementation. `text` is [`TEXT`];
    /// `approval_url` is the link the owner opens; `buttons` adds the inline keyboard.
    fn notify(
        &self,
        request_id: &str,
        text: &str,
        approval_url: &str,
        buttons: Option<&Buttons>,
    ) -> Pin<Box<dyn Future<Output = Result<(), NotifyError>> + Send + '_>>;
}

/// Longest secret file read. A token is far shorter.
const SECRET_MAX_BYTES: u64 = 4096;

/// A secret file was refused. The message names the kind of fault, never the path or contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    Unreadable,
    NotRegularFile,
    /// Readable by group or other.
    TooPermissive,
    Empty,
    TooLong,
    /// Not valid UTF-8, or holds a character that cannot be part of a token.
    Invalid,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SecretError::Unreadable => "secret file cannot be read",
            SecretError::NotRegularFile => "secret file is not a regular file",
            SecretError::TooPermissive => "secret file must not be accessible to group or other",
            SecretError::Empty => "secret file is empty",
            SecretError::TooLong => "secret file is too long",
            SecretError::Invalid => "secret file holds an invalid value",
        })
    }
}

impl std::error::Error for SecretError {}

/// Read a secret from `path`. The file must be a regular file with no group or other permission
/// bits (checked on the opened file, so a swap between check and read cannot help). Trailing
/// whitespace and newlines are trimmed.
pub fn read_secret_file(path: &Path) -> Result<String, SecretError> {
    let file = std::fs::File::open(path).map_err(|_| SecretError::Unreadable)?;
    let meta = file.metadata().map_err(|_| SecretError::Unreadable)?;
    if !meta.is_file() {
        return Err(SecretError::NotRegularFile);
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(SecretError::TooPermissive);
    }
    let mut bytes = Vec::new();
    file.take(SECRET_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SecretError::Unreadable)?;
    if bytes.len() as u64 > SECRET_MAX_BYTES {
        return Err(SecretError::TooLong);
    }
    let text = String::from_utf8(bytes).map_err(|_| SecretError::Invalid)?;
    let text = text.trim();
    if text.is_empty() {
        return Err(SecretError::Empty);
    }
    if !text.chars().all(|c| c.is_ascii_graphic()) {
        return Err(SecretError::Invalid);
    }
    Ok(text.to_string())
}

/// Whether `token` has the shape of a Bot API token. It goes into a URL path, so a `/`, `?` or
/// `#` in it could change the route.
pub(crate) fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'_' || b == b'-')
}

/// Why one attempt failed. `Transport` covers every error from `send()` (connect, timeout, reset,
/// or a lost reply) and gets one retry. The retry can duplicate a message the first attempt
/// delivered; that risk is accepted. `Rejected` is a reply that is not 2xx and is never retried.
enum Attempt {
    Transport,
    Rejected,
}

/// Sends one `sendMessage` per notification to the Telegram Bot API. It has its own HTTP client:
/// `no_proxy`, rustls, a five second timeout per attempt, and no redirects.
pub struct TelegramNotifier {
    client: reqwest::Client,
    /// `{api}/bot{token}/sendMessage`. The token is in the path, so this is never printed.
    url: String,
    chat_id: String,
}

impl fmt::Debug for TelegramNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TelegramNotifier(..)")
    }
}

impl TelegramNotifier {
    /// Build for the production Bot API.
    pub fn new(token: &str, chat_id: &str) -> Result<Self, NotifyError> {
        Self::with_api(TELEGRAM_API, token, chat_id, SEND_TIMEOUT)
    }

    /// Build against `api` (scheme, host and port, no path) with a given per-attempt timeout.
    /// The token must be a Bot API token (`digits:letters`): it goes into the URL path, so a `/`,
    /// `?` or `#` in it could change the route.
    pub(crate) fn with_api(
        api: &str,
        token: &str,
        chat_id: &str,
        timeout: Duration,
    ) -> Result<Self, NotifyError> {
        if !valid_token(token) || chat_id.is_empty() {
            return Err(NotifyError);
        }
        // `no_proxy` also turns off system proxy detection: the token-bearing URL goes to the
        // configured API host and nowhere else. Redirects are never followed.
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(timeout)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| NotifyError)?;
        Ok(TelegramNotifier {
            client,
            url: format!("{}/bot{token}/sendMessage", api.trim_end_matches('/')),
            chat_id: chat_id.to_string(),
        })
    }

    async fn send_once(&self, body: &[u8]) -> Result<(), Attempt> {
        // The error is dropped: its text contains the URL, and so the token.
        let resp = self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| Attempt::Transport)?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Attempt::Rejected)
        }
    }
}

impl Notifier for TelegramNotifier {
    fn notify(
        &self,
        request_id: &str,
        text: &str,
        approval_url: &str,
        buttons: Option<&Buttons>,
    ) -> Pin<Box<dyn Future<Output = Result<(), NotifyError>> + Send + '_>> {
        let mut body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": format!("{text}\nRequest: {request_id}\n{approval_url}"),
            "link_preview_options": { "is_disabled": true },
        });
        if let Some(b) = buttons {
            body["reply_markup"] = serde_json::json!({
                "inline_keyboard": [[
                    { "text": "Approve", "callback_data": b.approve },
                    { "text": "Deny", "callback_data": b.deny },
                ]],
            });
        }
        let body = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(_) => return Box::pin(async { Err(NotifyError) }),
        };
        Box::pin(async move {
            match self.send_once(&body).await {
                Ok(()) => Ok(()),
                Err(Attempt::Transport) => self.send_once(&body).await.map_err(|_| NotifyError),
                Err(Attempt::Rejected) => Err(NotifyError),
            }
        })
    }
}

/// Records every call and can be told to fail.
#[cfg(test)]
pub(crate) struct MockNotifier {
    pub calls: std::sync::Mutex<Vec<(String, String, String)>>,
    /// Whether each call carried buttons, in call order.
    pub with_buttons: std::sync::Mutex<Vec<bool>>,
    pub fail: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl MockNotifier {
    pub fn new(fail: bool) -> std::sync::Arc<MockNotifier> {
        std::sync::Arc::new(MockNotifier {
            calls: std::sync::Mutex::default(),
            with_buttons: std::sync::Mutex::default(),
            fail: std::sync::atomic::AtomicBool::new(fail),
        })
    }

    pub fn calls(&self) -> Vec<(String, String, String)> {
        self.calls.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl Notifier for MockNotifier {
    fn notify(
        &self,
        request_id: &str,
        text: &str,
        approval_url: &str,
        buttons: Option<&Buttons>,
    ) -> Pin<Box<dyn Future<Output = Result<(), NotifyError>> + Send + '_>> {
        self.calls.lock().unwrap().push((
            request_id.to_string(),
            text.to_string(),
            approval_url.to_string(),
        ));
        self.with_buttons.lock().unwrap().push(buttons.is_some());
        let fail = self.fail.load(std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            if fail {
                Err(NotifyError)
            } else {
                Ok(())
            }
        })
    }
}

pub mod poll;

#[cfg(test)]
mod poll_tests;
#[cfg(test)]
mod tests;
