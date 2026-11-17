//! Notification hook for new hold entries (design 3.4 step 5).
//!
//! The gate stores an optional [`Notifier`] and calls it for a new distinct entry, never for a
//! supersede, once and without retry. The text is fixed and carries nothing from the request. The
//! ntfy implementation reads its topic and token from files that only the owner may read, and no
//! error or Debug output of this module contains either.

use std::fmt;
use std::future::Future;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use reqwest::header::{HeaderValue, AUTHORIZATION};

/// The only text a notification may carry.
pub const TEXT: &str = "A gated request is waiting for approval.";

/// A notification could not be delivered. It carries no detail, so no URL, topic or token can
/// reach a log through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyError;

impl fmt::Display for NotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("notification failed")
    }
}

impl std::error::Error for NotifyError {}

/// Sends one notification about a new held request.
pub trait Notifier: Send + Sync {
    /// One attempt, no retry. `text` is [`TEXT`]; `approval_url` points at the entry's page.
    fn notify(
        &self,
        request_id: &str,
        text: &str,
        approval_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), NotifyError>> + Send + '_>>;
}

/// Longest secret file read. A topic or token is far shorter.
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
    /// Not valid UTF-8, or holds a character that cannot be part of a topic or header value.
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

/// Sends one POST per notification to an ntfy server. It has its own HTTP client: five second
/// timeout, no redirects, never the upstream client.
pub struct NtfyNotifier {
    client: reqwest::Client,
    /// `{base_url}/{topic}`. This is the topic, so it is never printed.
    url: String,
    bearer: Option<HeaderValue>,
}

impl fmt::Debug for NtfyNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NtfyNotifier(..)")
    }
}

impl NtfyNotifier {
    /// Build from the server base URL and the secrets read by [`read_secret_file`]. A topic holds
    /// only letters, digits, `-` and `_`.
    pub fn new(base_url: &str, topic: &str, token: Option<&str>) -> Result<Self, NotifyError> {
        Self::with_timeout(base_url, topic, token, Duration::from_secs(5))
    }

    pub(crate) fn with_timeout(
        base_url: &str,
        topic: &str,
        token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, NotifyError> {
        let valid_topic = !topic.is_empty()
            && topic
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !valid_topic {
            return Err(NotifyError);
        }
        let bearer = match token {
            Some(t) => {
                let mut v =
                    HeaderValue::from_str(&format!("Bearer {t}")).map_err(|_| NotifyError)?;
                v.set_sensitive(true);
                Some(v)
            }
            None => None,
        };
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| NotifyError)?;
        Ok(NtfyNotifier {
            client,
            url: format!("{}/{topic}", base_url.trim_end_matches('/')),
            bearer,
        })
    }
}

impl Notifier for NtfyNotifier {
    fn notify(
        &self,
        _request_id: &str,
        text: &str,
        approval_url: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), NotifyError>> + Send + '_>> {
        let text = text.to_string();
        let click = HeaderValue::from_str(approval_url).map_err(|_| NotifyError);
        Box::pin(async move {
            let mut req = self
                .client
                .post(&self.url)
                .header("Click", click?)
                .body(text);
            if let Some(b) = &self.bearer {
                req = req.header(AUTHORIZATION, b.clone());
            }
            let resp = req.send().await.map_err(|_| NotifyError)?;
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(NotifyError)
            }
        })
    }
}

/// Records every call and can be told to fail.
#[cfg(test)]
pub(crate) struct MockNotifier {
    pub calls: std::sync::Mutex<Vec<(String, String, String)>>,
    pub fail: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl MockNotifier {
    pub fn new(fail: bool) -> std::sync::Arc<MockNotifier> {
        std::sync::Arc::new(MockNotifier {
            calls: std::sync::Mutex::default(),
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
    ) -> Pin<Box<dyn Future<Output = Result<(), NotifyError>> + Send + '_>> {
        self.calls.lock().unwrap().push((
            request_id.to_string(),
            text.to_string(),
            approval_url.to_string(),
        ));
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

#[cfg(test)]
mod tests;
