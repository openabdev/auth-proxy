//! Session-plane errors. Messages name fields and ids, never a token or a
//! surrogate.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaneError {
    /// Missing, wrong or lapsed authority token (401).
    Unauthorized,
    /// `hello` while the current authority's lease is live (409).
    AuthorityActive,
    /// A field failed validation (400). Nothing was changed.
    Invalid(String),
    /// A credential id is not defined for this identity (403).
    CredentialNotGranted(String),
    /// Same session and generation registered with another binding, or the
    /// surrogate hash is already bound elsewhere (409).
    Conflict(String),
    /// Over `max_sessions` (429).
    TooManySessions,
    /// The proxy could not persist its state (500).
    Internal(String),
}

impl PlaneError {
    pub fn status(&self) -> u16 {
        match self {
            PlaneError::Invalid(_) => 400,
            PlaneError::Unauthorized => 401,
            PlaneError::CredentialNotGranted(_) => 403,
            PlaneError::AuthorityActive | PlaneError::Conflict(_) => 409,
            PlaneError::TooManySessions => 429,
            PlaneError::Internal(_) => 500,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            PlaneError::Unauthorized => "unauthorized",
            PlaneError::AuthorityActive => "authority_active",
            PlaneError::Invalid(_) => "invalid_request",
            PlaneError::CredentialNotGranted(_) => "credential_not_granted",
            PlaneError::Conflict(_) => "session_conflict",
            PlaneError::TooManySessions => "too_many_sessions",
            PlaneError::Internal(_) => "internal_error",
        }
    }

    /// Prefix the message with the failing list entry (resync).
    pub fn at_entry(self, index: usize) -> PlaneError {
        let p = |m: String| format!("entry {index}: {m}");
        match self {
            PlaneError::Invalid(m) => PlaneError::Invalid(p(m)),
            PlaneError::CredentialNotGranted(m) => PlaneError::CredentialNotGranted(p(m)),
            PlaneError::Conflict(m) => PlaneError::Conflict(p(m)),
            other => other,
        }
    }
}

impl fmt::Display for PlaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlaneError::Unauthorized => f.write_str("authority token missing, wrong or lapsed"),
            PlaneError::AuthorityActive => f.write_str("another authority's lease is live"),
            PlaneError::Invalid(m) | PlaneError::Conflict(m) | PlaneError::Internal(m) => {
                f.write_str(m)
            }
            PlaneError::CredentialNotGranted(m) => f.write_str(m),
            PlaneError::TooManySessions => f.write_str("too many sessions"),
        }
    }
}

impl std::error::Error for PlaneError {}
