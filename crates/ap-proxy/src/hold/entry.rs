//! Hold entry types: the immutable request, the state machine's states, and the messages the
//! table sends to the waiting handler (design 3.4 steps 6 and 8).
//!
//! `HeldRequest`, `Entry` and `View` hold headers, a body or a fingerprint, so each has a
//! hand-written `Debug` that prints sizes and names only.

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::oneshot;

use super::digest::Fingerprint;

/// The complete outbound semantic request of a held entry. Immutable once admitted: the entry id
/// names exactly these bytes.
#[derive(Clone)]
pub struct HeldRequest {
    pub method: String,
    pub route: String,
    /// Route-relative raw path, as matched by policy and forwarded.
    pub path: String,
    /// Raw query without the `?`.
    pub query: Option<String>,
    /// The forwarded header set after the strip algorithm, repeated headers in order. Names are
    /// lowercase.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Bytes,
}

impl HeldRequest {
    /// Whether a forwarded header carries a credential (`Authorization` or any `AUTH_HEADERS`
    /// member).
    pub fn is_credential(name: &str) -> bool {
        ap_core::headers::AUTH_HEADERS
            .iter()
            .any(|c| c.eq_ignore_ascii_case(name))
    }

    /// Whether the request carries an `Authorization` header.
    pub fn auth_present(&self) -> bool {
        self.headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("authorization"))
    }
}

impl fmt::Debug for HeldRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeldRequest")
            .field("method", &self.method)
            .field("route", &self.route)
            .field("headers", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Where an entry is in its life. `Pending` moves to exactly one of the others, once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Approved,
    Denied,
    Expired,
    /// The caller went away before any decision.
    Abandoned,
    /// A newer identical request from the same identity replaced it.
    Superseded,
    /// Removed by a policy reload or by shutdown.
    Dropped,
}

/// What the waiting handler learns. Sent at most once, by the transition that wins.
#[derive(Debug)]
pub enum Decision {
    /// A human approved. The handler must answer `confirm` (design 3.4 step 8).
    Approved {
        approver: String,
        confirm: ConfirmTx,
    },
    Denied {
        approver: String,
    },
    /// Replaced by `newest`.
    Superseded {
        newest: String,
    },
    /// Identity removed by a reload, or the policy file went away.
    Dropped,
    /// The gate is shutting down.
    Shutdown,
}

/// The handler's answer to an approve call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    /// Milestone 2: the first request byte was handed to the upstream connection.
    Started,
    /// The caller is gone before milestone 2; nothing was sent.
    Abandoned,
    /// The `forward_started` audit write failed; nothing was sent.
    AuditUnavailable,
    /// The upstream connection could not be established; nothing was sent.
    ConnectFailed,
}

/// The handler's end of the approve confirmation. Dropping it without sending reads as
/// `approved_but_abandoned`.
#[derive(Debug)]
pub struct ConfirmTx(pub(super) oneshot::Sender<Confirm>);

impl ConfirmTx {
    pub fn send(self, c: Confirm) {
        let _ = self.0.send(c);
    }
}

/// The result of an approve call (design 3.4, approve table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproveResult {
    /// Pending, and the forward reached milestone 2.
    Success,
    /// The entry was replaced; carries the newest entry id.
    Superseded {
        newest: String,
    },
    /// Approved or denied already.
    AlreadyDecided,
    Expired,
    Dropped,
    /// The caller disconnected before any decision.
    Gone,
    /// Approved, but the handler was gone before milestone 2. Nothing was sent.
    ApprovedButAbandoned,
    /// Approved, and no confirmation arrived within 2 s.
    ApprovedUnconfirmed,
    /// Approved, but the `forward_started` audit write failed. Nothing was sent.
    AuditUnavailable,
    /// Approved, but the upstream connection failed. Nothing was sent.
    ConnectFailed,
    /// No such entry (never existed, or forgotten after it was decided).
    NotFound,
}

impl ApproveResult {
    /// Stable identifier for the approval API.
    pub fn as_str(&self) -> &'static str {
        match self {
            ApproveResult::Success => "success",
            ApproveResult::Superseded { .. } => "superseded",
            ApproveResult::AlreadyDecided => "already_decided",
            ApproveResult::Expired => "expired",
            ApproveResult::Dropped => "dropped",
            ApproveResult::Gone => "gone",
            ApproveResult::ApprovedButAbandoned => "approved_but_abandoned",
            ApproveResult::ApprovedUnconfirmed => "approved_unconfirmed",
            ApproveResult::AuditUnavailable => "audit_unavailable",
            ApproveResult::ConnectFailed => "connect_failed",
            ApproveResult::NotFound => "not_found",
        }
    }
}

/// The result of a deny call. A deny on a decided entry changes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyResult {
    Denied,
    Superseded { newest: String },
    AlreadyDecided,
    Expired,
    Dropped,
    Gone,
    NotFound,
}

impl DenyResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            DenyResult::Denied => "denied",
            DenyResult::Superseded { .. } => "superseded",
            DenyResult::AlreadyDecided => "already_decided",
            DenyResult::Expired => "expired",
            DenyResult::Dropped => "dropped",
            DenyResult::Gone => "gone",
            DenyResult::NotFound => "not_found",
        }
    }
}

/// A `Pending` entry.
pub(super) struct Entry {
    /// Admission order, for listing.
    pub seq: u64,
    pub identity: String,
    pub fingerprint: Fingerprint,
    pub digest: String,
    pub req: Arc<HeldRequest>,
    pub tx: Option<oneshot::Sender<Decision>>,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("identity", &self.identity)
            .field("req", &self.req)
            .finish_non_exhaustive()
    }
}

/// What the table remembers about an entry after it left `Pending`: the state only, no request.
#[derive(Debug, Clone)]
pub(super) struct Done {
    pub state: State,
    pub identity: String,
    pub superseded_by: Option<String>,
}

/// One header as the approver sees it. `value` is `None` for a credential header, which the page
/// shows as present.
#[derive(Clone, PartialEq, Eq)]
pub struct ViewHeader {
    pub name: String,
    pub value: Option<String>,
}

/// The request content of a `Pending` entry, as the approval page shows it.
#[derive(Clone)]
pub struct ViewContent {
    pub method: String,
    pub route: String,
    /// Path with `webhooks`/`interactions` token segments redacted.
    pub path: String,
    pub query: Option<String>,
    pub content_type: Option<String>,
    pub body_len: usize,
    /// The body as lossy UTF-8 text. The page must escape it.
    pub body_text: String,
    /// The body was not valid UTF-8 and `body_text` replaced some bytes.
    pub body_lossy: bool,
    pub digest: String,
    pub headers: Vec<ViewHeader>,
}

/// What the approval API may show about an entry. Credential header values are never in it.
#[derive(Clone)]
pub struct View {
    pub id: String,
    pub state: State,
    pub identity: String,
    /// The newest entry id, when `state` is `Superseded`.
    pub superseded_by: Option<String>,
    /// Present while the entry is `Pending`.
    pub content: Option<ViewContent>,
}

impl fmt::Debug for View {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("View")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("identity", &self.identity)
            .field("content", &self.content.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ViewContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewContent")
            .field("method", &self.method)
            .field("route", &self.route)
            .field("body_len", &self.body_len)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ViewHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewHeader")
            .field("name", &self.name)
            .field("value_shown", &self.value.is_some())
            .finish()
    }
}
