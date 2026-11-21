//! The hold table (design 3.4 steps 4 to 8, the approve table, cooldown, and 3.7 caps).
//!
//! Library only: nothing here reads a socket or writes an audit line by itself. A handler admits
//! a request, waits on the returned [`Decision`] channel, and writes the audit record for the
//! transition it learns about. One mutex guards every entry, the per-identity cooldown and the
//! supersede lookup, so the first transition out of `Pending` wins and no later one can happen.
//!
//! Only `Pending` entries count against the caps. A decided entry is reduced to a tombstone
//! (state, identity, newest id) so a late approve still gets the right answer, and the tombstones
//! are bounded.
//!
//! Nothing in this module prints a header, a body or a fingerprint, and every type that holds one
//! has a hand-written `Debug`.

pub mod digest;
pub mod entry;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ap_core::canon::redact_path;
use ap_core::config::Passthrough;
use ap_core::error::Code;
use tokio::sync::oneshot;
use tokio::time::Instant;

pub use entry::{
    ApproveResult, CallbackAction, CallbackRefusal, CallbackTransition, Confirm, ConfirmTx,
    Decision, DenyResult, HeldRequest, State, Upstream, View, ViewContent, ViewHeader,
};
use entry::{Done, Entry};

/// How long an approve call waits for the handler's confirmation (design 3.4 step 8).
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(2);

/// Decided entries remembered so a late approve, deny or page view gets a precise answer.
const DONE_MAX: usize = 1024;

/// The bounds of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How long a handler waits for a decision before it calls [`Table::expire`].
    pub hold: Duration,
    pub max_total: usize,
    pub max_per_identity: usize,
    /// Refusal window after a human deny or an expiry. Zero disables it.
    pub cooldown: Duration,
}

impl Limits {
    pub fn from_config(pt: &Passthrough) -> Limits {
        Limits {
            hold: Duration::from_secs(pt.hold_secs),
            max_total: pt.max_held_total,
            max_per_identity: pt.max_held_per_identity,
            cooldown: Duration::from_secs(pt.cooldown_secs),
        }
    }
}

/// What [`Table::admit`] decided.
#[derive(Debug)]
pub enum Admission {
    /// The request is held. `superseded` names the older entry it replaced, if any; a notifier
    /// fires only when it is `None`.
    Held(Held),
    /// Refused; nothing was inserted and no older entry changed.
    Refused(Code),
}

/// The handler's side of a new entry.
pub struct Held {
    pub id: String,
    /// Credential-blind digest, as written to the `held` audit record.
    pub digest: String,
    /// Resolves when a transition other than expiry or abandonment wins.
    pub decision: oneshot::Receiver<Decision>,
    pub superseded: Option<String>,
    /// Secret that a Telegram callback must echo (24 hex). Never printed.
    pub nonce: String,
    /// Bearer of the one-time view link (32 hex). Never printed.
    pub view_token: String,
}

impl fmt::Debug for Held {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Held")
            .field("id", &self.id)
            .field("digest", &self.digest)
            .field("superseded", &self.superseded)
            .finish_non_exhaustive()
    }
}

struct Inner {
    pending: HashMap<String, Entry>,
    done: HashMap<String, Done>,
    done_order: VecDeque<String>,
    /// Identity to the instant its cooldown ends.
    cooldown: HashMap<String, Instant>,
    /// Set by `drain_pending`: no new entry is admitted.
    closed: bool,
    /// Next admission sequence number.
    next_seq: u64,
}

impl Inner {
    /// Move `id` out of `Pending` into a tombstone with `state`. Returns the entry.
    fn finish(&mut self, id: &str, state: State, superseded_by: Option<String>) -> Option<Entry> {
        let entry = self.pending.remove(id)?;
        self.done.insert(
            id.to_string(),
            Done {
                state,
                identity: entry.identity.clone(),
                superseded_by,
            },
        );
        self.done_order.push_back(id.to_string());
        while self.done_order.len() > DONE_MAX {
            if let Some(old) = self.done_order.pop_front() {
                self.done.remove(&old);
            }
        }
        Some(entry)
    }
}

/// Entries, cooldowns and the equality key, behind one mutex.
pub struct Table {
    limits: Limits,
    fingerprinter: digest::Fingerprinter,
    inner: Mutex<Inner>,
}

impl fmt::Debug for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Table")
            .field("limits", &self.limits)
            .field("pending", &self.pending_len())
            .finish_non_exhaustive()
    }
}

impl Table {
    pub fn new(limits: Limits) -> Table {
        Table {
            limits,
            fingerprinter: digest::Fingerprinter::new(),
            inner: Mutex::new(Inner {
                pending: HashMap::new(),
                done: HashMap::new(),
                done_order: VecDeque::new(),
                cooldown: HashMap::new(),
                closed: false,
                next_seq: 0,
            }),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Number of `Pending` entries.
    pub fn pending_len(&self) -> usize {
        self.lock().pending.len()
    }

    /// The state of `id`, if the table still knows it.
    pub fn state(&self, id: &str) -> Option<State> {
        let g = self.lock();
        if g.pending.contains_key(id) {
            Some(State::Pending)
        } else {
            g.done.get(id).map(|d| d.state)
        }
    }

    fn start_cooldown(&self, g: &mut Inner, identity: &str) {
        if !self.limits.cooldown.is_zero() {
            g.cooldown
                .insert(identity.to_string(), Instant::now() + self.limits.cooldown);
        }
    }

    /// Admit a new hold, in the order of design 3.4 step 5: cooldown, then dedupe, then the caps.
    ///
    /// `persist` writes the fallible `held` audit record. It runs under the table lock, after
    /// every check passed and before anything changes, so a failure refuses with
    /// `audit_unavailable` and leaves the table as it was: no entry, no supersede, no cooldown.
    /// It receives the new id and the audit digest and must not call back into the table.
    pub fn admit<F>(&self, identity: &str, req: Arc<HeldRequest>, persist: F) -> Admission
    where
        F: FnOnce(&str, &str) -> io::Result<()>,
    {
        let fingerprint = self.fingerprinter.fingerprint(&req);
        let digest = digest::audit_digest(&req);
        let now = Instant::now();
        let mut g = self.lock();
        if g.closed {
            return Admission::Refused(Code::Shutdown);
        }
        g.cooldown.retain(|_, until| *until > now);
        if g.cooldown.contains_key(identity) {
            return Admission::Refused(Code::Cooldown);
        }
        let duplicate = g
            .pending
            .iter()
            .find(|(_, e)| e.identity == identity && e.fingerprint == fingerprint)
            .map(|(id, _)| id.clone());
        if duplicate.is_none() {
            let own = g
                .pending
                .values()
                .filter(|e| e.identity == identity)
                .count();
            if own >= self.limits.max_per_identity {
                return Admission::Refused(Code::IdentityCap);
            }
            if g.pending.len() >= self.limits.max_total {
                return Admission::Refused(Code::TableFull);
            }
        }
        let id = digest::random_hex(16);
        let nonce = digest::random_hex(12);
        let view_token = digest::random_hex(16);
        if persist(&id, &digest).is_err() {
            return Admission::Refused(Code::AuditUnavailable);
        }
        if let Some(old_id) = &duplicate {
            if let Some(mut old) = g.finish(old_id, State::Superseded, Some(id.clone())) {
                if let Some(tx) = old.tx.take() {
                    let _ = tx.send(Decision::Superseded { newest: id.clone() });
                }
            }
            // Older tombstones that pointed at the replaced entry now point at the newest one.
            for d in g.done.values_mut() {
                if d.superseded_by.as_deref() == Some(old_id.as_str()) {
                    d.superseded_by = Some(id.clone());
                }
            }
        }
        let (tx, rx) = oneshot::channel();
        let seq = g.next_seq;
        g.next_seq += 1;
        g.pending.insert(
            id.clone(),
            Entry {
                seq,
                held_at: now,
                identity: identity.to_string(),
                fingerprint,
                digest: digest.clone(),
                req,
                tx: Some(tx),
                nonce: nonce.clone(),
                view_token: view_token.clone(),
            },
        );
        Admission::Held(Held {
            id,
            digest,
            decision: rx,
            superseded: duplicate,
            nonce,
            view_token,
        })
    }

    /// Approve `id` for `approver` and wait for the handler's confirmation, with no policy
    /// re-check. The approval listener uses [`Table::approve_if`].
    ///
    /// The first transition out of `Pending` wins, so two concurrent approves give one result
    /// from the handler and `AlreadyDecided` for the other.
    pub async fn approve(&self, id: &str, approver: &str) -> ApproveResult {
        self.approve_if(id, approver, |_, _| true).await
    }

    /// Like [`Table::approve`], but `still_held(identity, request)` is asked first, under the
    /// table lock. The callback must read the policy itself, when it is called: a snapshot
    /// taken before the call is a view the table lock does not protect. When it answers `false` the entry is dropped (the caller gets
    /// `dropped_on_reload`, nothing is sent upstream) and the result is `PolicyChanged`, so an
    /// approval can never run a permission the policy no longer gives.
    pub async fn approve_if(
        &self,
        id: &str,
        approver: &str,
        still_held: impl FnOnce(&str, &HeldRequest) -> bool,
    ) -> ApproveResult {
        let confirmed = {
            let mut g = self.lock();
            let keep = g.pending.get(id).map(|e| still_held(&e.identity, &e.req));
            if keep == Some(false) {
                if let Some(mut entry) = g.finish(id, State::Dropped, None) {
                    if let Some(tx) = entry.tx.take() {
                        let _ = tx.send(Decision::Dropped);
                    }
                }
                return ApproveResult::PolicyChanged;
            }
            match g.finish(id, State::Approved, None) {
                Some(mut entry) => {
                    let (ctx, crx) = oneshot::channel();
                    let decision = Decision::Approved {
                        approver: approver.to_string(),
                        confirm: ConfirmTx(ctx),
                    };
                    match entry.tx.take().map(|tx| tx.send(decision)) {
                        Some(Ok(())) => crx,
                        // The handler is already gone, so nothing can be sent.
                        _ => return ApproveResult::ApprovedButAbandoned,
                    }
                }
                None => return Self::approve_when_decided(&g, id),
            }
        };
        Self::await_confirm(confirmed).await
    }

    /// Wait up to [`CONFIRM_TIMEOUT`] for the handler's answer to an approve that already won.
    pub async fn await_confirm(confirmed: oneshot::Receiver<Confirm>) -> ApproveResult {
        match tokio::time::timeout(CONFIRM_TIMEOUT, confirmed).await {
            Ok(Ok(Confirm::Started)) => ApproveResult::Success,
            Ok(Ok(Confirm::Abandoned)) | Ok(Err(_)) => ApproveResult::ApprovedButAbandoned,
            Ok(Ok(Confirm::AuditUnavailable)) => ApproveResult::AuditUnavailable,
            Ok(Ok(Confirm::ConnectFailed)) => ApproveResult::ConnectFailed,
            Ok(Ok(Confirm::PolicyChanged)) => ApproveResult::PolicyChanged,
            Err(_) => ApproveResult::ApprovedUnconfirmed,
        }
    }

    fn approve_when_decided(g: &Inner, id: &str) -> ApproveResult {
        match g.done.get(id) {
            None => ApproveResult::NotFound,
            Some(d) => match d.state {
                State::Approved | State::Denied | State::Pending => ApproveResult::AlreadyDecided,
                State::Expired => ApproveResult::Expired,
                State::Dropped => ApproveResult::Dropped,
                State::Abandoned => ApproveResult::Gone,
                State::Superseded => ApproveResult::Superseded {
                    newest: d.superseded_by.clone().unwrap_or_default(),
                },
            },
        }
    }

    /// Deny `id`. A human deny starts the identity's cooldown and frees the slot at once.
    pub fn deny(&self, id: &str, approver: &str) -> DenyResult {
        let mut g = self.lock();
        match g.finish(id, State::Denied, None) {
            Some(mut entry) => {
                self.start_cooldown(&mut g, &entry.identity);
                if let Some(tx) = entry.tx.take() {
                    let _ = tx.send(Decision::Denied {
                        approver: approver.to_string(),
                    });
                }
                DenyResult::Denied
            }
            None => match g.done.get(id) {
                None => DenyResult::NotFound,
                Some(d) => match d.state {
                    State::Approved | State::Denied | State::Pending => DenyResult::AlreadyDecided,
                    State::Expired => DenyResult::Expired,
                    State::Dropped => DenyResult::Dropped,
                    State::Abandoned => DenyResult::Gone,
                    State::Superseded => DenyResult::Superseded {
                        newest: d.superseded_by.clone().unwrap_or_default(),
                    },
                },
            },
        }
    }

    /// `hold_secs` elapsed. Called by the handler whose timer fired. Returns `true` when the
    /// entry moved to `Expired`, which also starts the cooldown; `false` means another
    /// transition won first and the decision is already in the handler's channel.
    pub fn expire(&self, id: &str) -> bool {
        let mut g = self.lock();
        match g.finish(id, State::Expired, None) {
            Some(entry) => {
                self.start_cooldown(&mut g, &entry.identity);
                true
            }
            None => false,
        }
    }

    /// The caller went away. Called from the handler's drop guard. Returns `true` when the entry
    /// moved to `Abandoned`; `false` when a decision already won (the handler then sees it as
    /// `abandoned_after_approve`, or has nothing to do). No cooldown.
    pub fn abandon(&self, id: &str) -> bool {
        self.lock().finish(id, State::Abandoned, None).is_some()
    }

    fn drop_where<P, D>(&self, mut pred: P, decision: D) -> usize
    where
        P: FnMut(&str, &HeldRequest) -> bool,
        D: Fn() -> Decision,
    {
        let mut g = self.lock();
        let ids: Vec<String> = g
            .pending
            .iter()
            .filter(|(_, e)| pred(&e.identity, &e.req))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &ids {
            if let Some(mut e) = g.finish(id, State::Dropped, None) {
                if let Some(tx) = e.tx.take() {
                    let _ = tx.send(decision());
                }
            }
        }
        ids.len()
    }

    /// A policy reload kept only the identities in `present`: drop the `Pending` entries of the
    /// others. Entries of identities that remain are untouched. Returns the number dropped.
    pub fn drop_identities_missing(&self, present: &HashSet<String>) -> usize {
        self.drop_where(
            |identity, _| !present.contains(identity),
            || Decision::Dropped,
        )
    }

    /// A policy reload: drop every `Pending` entry for which `still_held(identity, request)` is
    /// false, that is, whose identity, route, method or path no longer yields a hold. Returns
    /// the number dropped.
    pub fn drop_unless(&self, mut still_held: impl FnMut(&str, &HeldRequest) -> bool) -> usize {
        self.drop_where(|i, r| !still_held(i, r), || Decision::Dropped)
    }

    /// The policy file went away: drop every `Pending` entry.
    pub fn drop_all(&self) -> usize {
        self.drop_where(|_, _| true, || Decision::Dropped)
    }

    /// Shutdown: answer every `Pending` entry `Shutdown` and refuse new admissions. An approved
    /// entry that has not yet claimed its start (`claim_start`) is refused at the claim; one that
    /// has claimed runs on in its handler.
    pub fn drain_pending(&self) -> usize {
        self.lock().closed = true;
        self.drop_where(|_, _| true, || Decision::Shutdown)
    }

    /// An approved request asks to start its forward (design 3.7). The closed check and `f`, the
    /// `forward_started` write, run under the table lock that `drain_pending` takes to close the
    /// table, so shutdown either comes before the claim (`Ok(false)`, nothing is written) or
    /// after the whole claim (`Ok(true)`), never between the check and the write. `f` must not
    /// call back into the table.
    pub fn claim_start<E>(&self, f: impl FnOnce() -> Result<(), E>) -> Result<bool, E> {
        let g = self.lock();
        if g.closed {
            return Ok(false);
        }
        f()?;
        drop(g);
        Ok(true)
    }

    /// A Telegram callback for `id`. Under one lock: the entry must be `Pending`, `nonce` must
    /// match its nonce, and for an approve the policy must still hold it (`still_held`, read
    /// inside the lock as in [`Table::approve_if`]). Any refusal changes nothing, except that a
    /// failed policy check drops the entry, exactly as the approval page's approve does. A deny
    /// starts the identity's cooldown, as [`Table::deny`] does.
    pub fn transition_by_callback(
        &self,
        id: &str,
        nonce: &str,
        action: CallbackAction,
        approver: &str,
        still_held: impl FnOnce(&str, &HeldRequest) -> bool,
    ) -> CallbackTransition {
        let mut g = self.lock();
        let keep = match g.pending.get(id) {
            None => return CallbackTransition::Refused(CallbackRefusal::NoLiveEntry),
            Some(e) => {
                if !digest::ct_eq(&e.nonce, nonce) {
                    return CallbackTransition::Refused(CallbackRefusal::NonceMismatch);
                }
                match action {
                    CallbackAction::Deny => true,
                    CallbackAction::Approve => still_held(&e.identity, &e.req),
                }
            }
        };
        if !keep {
            if let Some(mut entry) = g.finish(id, State::Dropped, None) {
                if let Some(tx) = entry.tx.take() {
                    let _ = tx.send(Decision::Dropped);
                }
            }
            return CallbackTransition::Refused(CallbackRefusal::PolicyChanged);
        }
        match action {
            CallbackAction::Deny => {
                let Some(mut entry) = g.finish(id, State::Denied, None) else {
                    return CallbackTransition::Refused(CallbackRefusal::NoLiveEntry);
                };
                self.start_cooldown(&mut g, &entry.identity);
                if let Some(tx) = entry.tx.take() {
                    let _ = tx.send(Decision::Denied {
                        approver: approver.to_string(),
                    });
                }
                CallbackTransition::Denied
            }
            CallbackAction::Approve => {
                let Some(mut entry) = g.finish(id, State::Approved, None) else {
                    return CallbackTransition::Refused(CallbackRefusal::NoLiveEntry);
                };
                let (ctx, crx) = oneshot::channel();
                let decision = Decision::Approved {
                    approver: approver.to_string(),
                    confirm: ConfirmTx(ctx),
                };
                match entry.tx.take().map(|tx| tx.send(decision)) {
                    Some(Ok(())) => CallbackTransition::ApproveStarted(crx),
                    // The handler is already gone, so nothing can be sent.
                    _ => CallbackTransition::Refused(CallbackRefusal::NoLiveEntry),
                }
            }
        }
    }

    /// The view of the `Pending` entry whose one-time view token is `token`. Every token is
    /// compared in constant time and the scan does not stop at a match. An entry that left
    /// `Pending` no longer holds its token, so an ended hold answers `None`.
    pub fn view_by_token(&self, token: &str) -> Option<View> {
        let g = self.lock();
        let mut hit: Option<String> = None;
        for (id, e) in &g.pending {
            if digest::ct_eq(&e.view_token, token) {
                hit = Some(id.clone());
            }
        }
        let id = hit?;
        view_in(&g, &id, self.limits.hold).filter(|v| v.state == State::Pending)
    }

    /// Test-only: the nonce and view token of a `Pending` entry.
    #[cfg(test)]
    pub(crate) fn test_secrets(&self, id: &str) -> Option<(String, String)> {
        let g = self.lock();
        g.pending
            .get(id)
            .map(|e| (e.nonce.clone(), e.view_token.clone()))
    }

    /// The `Pending` entries in admission order, as the approval API may show them.
    pub fn list(&self) -> Vec<View> {
        let mut ids: Vec<(u64, String)> = {
            let g = self.lock();
            g.pending
                .iter()
                .map(|(id, e)| (e.seq, id.clone()))
                .collect()
        };
        ids.sort();
        ids.iter().filter_map(|(_, id)| self.view(id)).collect()
    }

    /// What the approval API may show about `id`. Credential header values are left out, and
    /// request content is present only while the entry is `Pending`.
    pub fn view(&self, id: &str) -> Option<View> {
        view_in(&self.lock(), id, self.limits.hold)
    }
}

fn view_in(g: &Inner, id: &str, hold: Duration) -> Option<View> {
    if let Some(e) = g.pending.get(id) {
        let req = &e.req;
        let held = Instant::now().saturating_duration_since(e.held_at);
        let remaining = hold.saturating_sub(held);
        let content_type = req
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned());
        let body_text = String::from_utf8_lossy(&req.body);
        let body_lossy = std::str::from_utf8(&req.body).is_err();
        let headers = req
            .headers
            .iter()
            .map(|(n, v)| ViewHeader {
                name: n.clone(),
                value: if HeldRequest::is_credential(n) {
                    None
                } else {
                    Some(String::from_utf8_lossy(v).into_owned())
                },
            })
            .collect();
        return Some(View {
            id: id.to_string(),
            state: State::Pending,
            identity: e.identity.clone(),
            superseded_by: None,
            content: Some(ViewContent {
                method: req.method.clone(),
                route: req.route.clone(),
                upstream: req.upstream.authority(),
                path: redact_path(&req.path),
                query: req.query.clone(),
                content_type,
                body_len: req.body.len(),
                body_text: body_text.into_owned(),
                body_lossy,
                digest: e.digest.clone(),
                headers,
                held_secs: held.as_secs(),
                remaining_secs: remaining.as_secs(),
            }),
        });
    }
    g.done.get(id).map(|d| View {
        id: id.to_string(),
        state: d.state,
        identity: d.identity.clone(),
        superseded_by: d.superseded_by.clone(),
        content: None,
    })
}

#[cfg(test)]
mod tests;
