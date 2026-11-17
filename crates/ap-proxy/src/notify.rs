//! Notification hook for new hold entries (design 3.4 step 5).
//!
//! This module holds the interface only. The gate stores an optional [`Notifier`] and calls it
//! for a new distinct entry, never for a supersede. The text is fixed and carries nothing from the
//! request.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

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
