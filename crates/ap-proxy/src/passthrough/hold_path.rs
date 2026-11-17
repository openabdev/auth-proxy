//! The hold path (design 3.4): a request whose grant says `hold` is checked, buffered, parked in
//! the hold table, and forwarded only after a human approves it.
//!
//! Order of refusals, all before the table is touched: content type, content encoding, missing
//! `Authorization`, declared length over the cap, then the buffered read. Then admission and the
//! fallible `held` audit write. A drop guard moves the entry to `Abandoned` when the caller goes
//! away, which hyper reports by dropping the handler future.
//!
//! The approved forward runs in this task, on a client that opens one HTTP/1.1 connection per
//! request. Two milestones decide when the approve call may return (design 3.4 step 8):
//!
//! 1. the first poll of the request body stream, which the client makes only after the connection
//!    exists and before it flushes the request head: the `forward_started` record is written
//!    there, and a failed write aborts the body so nothing is sent;
//! 2. the moment the first body chunk is handed over, which resolves the approve confirmation.
//!
//! A connect failure never polls the body, so it yields `connect_failed` with no `forward_started`.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use ap_core::audit::HoldRec;
use ap_core::config::{Passthrough, Route};
use bytes::Bytes;
use futures_util::Stream;
use http::{header, HeaderMap, HeaderValue};
use tokio::sync::{oneshot, Notify};

use super::{
    audited, refusal_response, refuse, refuse_unread, ConnAbort, Drain, End, PtApp, Trail,
};
use super::{Code, Duration, Instant, Response, StreamAudit};
use crate::forward::{self, BufferError};
use crate::hold::{Admission, Confirm, ConfirmTx, Decision, HeldRequest};
use ap_core::outcome::render_passthrough;
use axum::body::Body;

/// Everything the hold path needs from the pipeline once the grant said `hold`.
pub(super) struct Request<'a> {
    pub app: Arc<PtApp>,
    pub trail: Trail,
    pub parts: http::request::Parts,
    pub body: Body,
    pub pt: &'a Passthrough,
    pub route: &'a Route,
    pub rel: &'a str,
    pub identity: &'a str,
    pub drain: Drain,
}

/// What the audit records of one held request share. No header value, no body, no query.
#[derive(Clone)]
struct Ctx {
    identity: String,
    route: Option<String>,
    method: String,
    /// Route-relative path with token segments already redacted.
    path: String,
    auth_present: bool,
    started: Instant,
}

impl Ctx {
    fn rec(
        &self,
        id: &str,
        digest: &str,
        transition: &'static str,
        approver: Option<&str>,
        code: Option<&str>,
        status: Option<u16>,
    ) -> HoldRec {
        HoldRec {
            request_id: id.to_string(),
            identity: self.identity.clone(),
            route: self.route.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            digest: Some(digest.to_string()),
            transition,
            approver: approver.map(str::to_string),
            code: code.map(str::to_string),
            status,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            auth_present: self.auth_present,
        }
    }
}

/// Longest a notification attempt may run, whatever the notifier does.
const NOTIFY_CAP: Duration = Duration::from_secs(5);

/// Fire-and-forget notification for a new entry: one attempt, no retry. The link carries only the
/// entry id; the text is the fixed sentence. Nothing here waits for the result.
fn announce(app: &Arc<PtApp>, ctx: &Ctx, id: &str, digest: &str) {
    let (Some(notifier), Some(base)) = (app.notifier.clone(), app.approval_base.clone()) else {
        return;
    };
    let app = Arc::clone(app);
    let (ctx, id, digest) = (ctx.clone(), id.to_string(), digest.to_string());
    tokio::spawn(async move {
        let url = format!("{base}/pending/{id}");
        let sent =
            tokio::time::timeout(NOTIFY_CAP, notifier.notify(&id, crate::notify::TEXT, &url)).await;
        if !matches!(sent, Ok(Ok(()))) {
            app.audit.write_hold(&ctx.rec(
                &id,
                &digest,
                "notify_failed",
                None,
                Some("notify_failed"),
                None,
            ));
        }
    });
}

/// What the response stream needs to write the `completed` line.
pub(super) struct HeldEnd {
    ctx: Ctx,
    id: String,
    digest: String,
}

impl HeldEnd {
    pub(super) fn completed(&self, status: u16) -> HoldRec {
        self.ctx.rec(
            &self.id,
            &self.digest,
            "completed",
            None,
            None,
            Some(status),
        )
    }
}

/// When milestone 1 happened.
struct Started {
    at: Mutex<Option<Instant>>,
    notify: Notify,
}

impl Started {
    fn new() -> Started {
        Started {
            at: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    fn set(&self) {
        if let Ok(mut at) = self.at.lock() {
            *at = Some(Instant::now());
        }
        self.notify.notify_one();
    }

    fn get(&self) -> Option<Instant> {
        self.at.lock().ok().and_then(|g| *g)
    }

    /// Resolves `limit` after milestone 1. An approved request's deadline counts from there.
    async fn deadline(&self, limit: Duration) {
        loop {
            let n = self.notify.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if let Some(at) = self.get() {
                tokio::time::sleep_until(tokio::time::Instant::from_std(at + limit)).await;
                return;
            }
            n.await;
        }
    }
}

type SharedConfirm = Arc<Mutex<Option<ConfirmTx>>>;

fn take_confirm(c: &SharedConfirm) -> Option<ConfirmTx> {
    c.lock().ok().and_then(|mut g| g.take())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for a decision.
    Pending,
    /// A human approved; the forward has not reached milestone 1 yet.
    Approved,
    /// Nothing left for the guard to record.
    Done,
}

/// Owns the entry's side of the handler. Dropping it while the handler is still waiting means the
/// caller went away.
struct Guard {
    app: Arc<PtApp>,
    ctx: Ctx,
    id: String,
    digest: String,
    phase: Phase,
    rx: Option<oneshot::Receiver<Decision>>,
    started: Arc<Started>,
}

impl Guard {
    fn write(
        &self,
        transition: &'static str,
        approver: Option<&str>,
        code: Option<&str>,
        status: Option<u16>,
    ) {
        self.app.audit.write_hold(&self.ctx.rec(
            &self.id,
            &self.digest,
            transition,
            approver,
            code,
            status,
        ));
    }

    /// The transition record a decision stands for.
    fn record(&self, d: &Decision) {
        match d {
            Decision::Approved { approver, .. } => {
                self.write("approved", Some(approver), None, None);
            }
            Decision::Denied { approver } => {
                self.write("denied", Some(approver), Some("human_denied"), Some(423));
            }
            Decision::Superseded { .. } => {
                self.write("superseded", None, Some("superseded"), Some(503));
            }
            Decision::Dropped => {
                self.write(
                    "dropped_on_reload",
                    None,
                    Some("dropped_on_reload"),
                    Some(503),
                );
            }
            // Shutdown has no transition of its own; the handler writes a refusal line.
            Decision::Shutdown => {}
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        match self.phase {
            Phase::Done => {}
            Phase::Pending => {
                if self.app.hold.abandon(&self.id) {
                    self.write("abandoned", None, None, None);
                } else if let Some(rx) = self.rx.as_mut() {
                    // A decision won before the caller left and was never read.
                    if let Ok(d) = rx.try_recv() {
                        self.record(&d);
                        if matches!(d, Decision::Approved { .. }) {
                            self.write("abandoned_after_approve", None, None, None);
                        }
                    }
                }
            }
            Phase::Approved => {
                if self.started.get().is_none() {
                    self.write("abandoned_after_approve", None, None, None);
                }
            }
        }
    }
}

/// The approved request's body, as a stream the HTTP client polls. See the module doc for the two
/// milestones.
struct HeldBody {
    app: Arc<PtApp>,
    ctx: Ctx,
    id: String,
    digest: String,
    first: bool,
    body: Option<Bytes>,
    confirm: SharedConfirm,
    started: Arc<Started>,
    audit_failed: Arc<AtomicBool>,
    failed: bool,
}

impl Stream for HeldBody {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.failed {
            return Poll::Ready(None);
        }
        if this.first {
            this.first = false;
            // Milestone 1: the connection exists and no request byte has been flushed. The record
            // must reach the sink first; if it cannot, the body fails and nothing is sent.
            let rec = this
                .ctx
                .rec(&this.id, &this.digest, "forward_started", None, None, None);
            if this.app.audit.try_write_hold(&rec).is_err() {
                this.failed = true;
                this.audit_failed.store(true, Ordering::SeqCst);
                if let Some(c) = take_confirm(&this.confirm) {
                    c.send(Confirm::AuditUnavailable);
                }
                return Poll::Ready(Some(Err(io::Error::other("audit write failed"))));
            }
            this.started.set();
            #[cfg(any(test, feature = "matrix-upstream"))]
            this.app.pause.between_milestones();
        }
        // Milestone 2: the first chunk is handed over (or, for an empty body, the end).
        if let Some(c) = take_confirm(&this.confirm) {
            c.send(Confirm::Started);
        }
        match this.body.take() {
            Some(b) if !b.is_empty() => Poll::Ready(Some(Ok(b))),
            _ => Poll::Ready(None),
        }
    }
}

fn json_content_type(h: &HeaderMap) -> bool {
    let mut it = h.get_all(header::CONTENT_TYPE).iter();
    let (Some(v), None) = (it.next(), it.next()) else {
        return false;
    };
    let Ok(s) = v.to_str() else {
        return false;
    };
    s.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/json")
}

fn identity_encoding(h: &HeaderMap) -> bool {
    h.get_all(header::CONTENT_ENCODING).iter().all(|v| {
        v.to_str().is_ok_and(|s| {
            s.split(',').all(|t| {
                let t = t.trim();
                t.is_empty() || t.eq_ignore_ascii_case("identity")
            })
        })
    })
}

/// The final answer for a refusal that already has its transition record: evidence line, status,
/// `X-AP-Decision` and body.
fn finish(app: &PtApp, trail: &Trail, code: Code) -> Response<Body> {
    let (status, _, _) = render_passthrough(code);
    trail.write_evidence(&app.audit, status);
    refusal_response(code)
}

/// The caller's connection is closed with no answer, after the first request byte may have left.
fn abort(app: &PtApp, trail: &Trail) -> ConnAbort {
    trail.write_evidence(&app.audit, 0);
    ConnAbort
}

pub(super) async fn run(r: Request<'_>) -> Result<Response<Body>, ConnAbort> {
    let Request {
        app,
        trail,
        parts,
        body,
        pt,
        route,
        rel,
        identity,
        drain,
    } = r;

    // 1-3. Refusals before the body is read.
    if !json_content_type(&parts.headers) {
        return Ok(refuse_unread(&app, &trail, Code::ContentType, body, &drain).await);
    }
    if !identity_encoding(&parts.headers) {
        return Ok(refuse_unread(&app, &trail, Code::ContentEncoding, body, &drain).await);
    }
    if !parts.headers.contains_key(header::AUTHORIZATION) {
        return Ok(refuse_unread(&app, &trail, Code::CredentialMissing, body, &drain).await);
    }
    let cap = pt.held_body_max_bytes;
    if forward::declared_length(&parts.headers).is_some_and(|n| n > cap) {
        return Ok(refuse_unread(&app, &trail, Code::BodyTooLarge, body, &drain).await);
    }

    // 4. Read the body into memory.
    let bytes = match forward::buffer_body(body, cap, Duration::from_secs(pt.body_read_secs)).await
    {
        Ok(b) => b,
        Err(BufferError::Overflow) => return Ok(refuse(&app, &trail, Code::BodyTooLarge)),
        Err(BufferError::Stalled | BufferError::Read) => {
            return Ok(refuse(&app, &trail, Code::BodyReadTimeout))
        }
    };

    // 5. The complete outbound request, as it will be sent. The entry names exactly these bytes.
    let mut headers = forward::passthrough_headers(&parts.headers, route, pt);
    // The body is buffered, so its length is known. An empty body gets no `Content-Length`: hyper
    // never polls the body of a zero-length request, so milestone 1 would not happen, and the
    // request goes out chunked instead (its stream is polled before the head is flushed).
    if bytes.is_empty() {
        headers.remove(header::CONTENT_LENGTH);
    } else {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    }
    let query = parts.uri.query().map(str::to_string);
    let req = Arc::new(HeldRequest {
        method: parts.method.as_str().to_string(),
        route: route.name.clone(),
        path: rel.to_string(),
        query: query.clone(),
        headers: headers
            .iter()
            .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
            .collect(),
        body: bytes.clone(),
    });
    let ctx = Ctx {
        identity: identity.to_string(),
        route: trail.route.clone(),
        method: parts.method.as_str().to_string(),
        path: trail.path.clone(),
        auth_present: req.auth_present(),
        started: trail.started,
    };

    // 6. Admission. The `held` record is written under the table lock, before anything changes.
    let admission = app.hold.admit(identity, Arc::clone(&req), |id, digest| {
        app.audit
            .try_write_hold(&ctx.rec(id, digest, "held", None, None, None))
    });
    let held = match admission {
        Admission::Refused(code) => return Ok(refuse(&app, &trail, code)),
        Admission::Held(h) => h,
    };
    // A new entry is announced once; a supersede is not. The entry's state does not depend on
    // the outcome, so a failure only leaves a `notify_failed` line.
    if held.superseded.is_none() {
        announce(&app, &ctx, &held.id, &held.digest);
    }
    let mut guard = Guard {
        app: Arc::clone(&app),
        ctx: ctx.clone(),
        id: held.id,
        digest: held.digest,
        phase: Phase::Pending,
        rx: Some(held.decision),
        started: Arc::new(Started::new()),
    };

    // 7. Wait for a decision, the timer or the caller leaving (which drops this future).
    enum Event {
        Decision(Result<Decision, oneshot::error::RecvError>),
        Timer,
    }
    let hold = app.hold.limits().hold;
    let event = {
        let Some(rx) = guard.rx.as_mut() else {
            return Ok(refuse(&app, &trail, Code::Shutdown));
        };
        tokio::select! {
            d = rx => Event::Decision(d),
            () = tokio::time::sleep(hold) => Event::Timer,
        }
    };
    let decision = match event {
        Event::Decision(d) => d,
        Event::Timer => {
            if app.hold.expire(&guard.id) {
                guard.phase = Phase::Done;
                guard.write("expired", None, Some("expired"), Some(410));
                return Ok(finish(&app, &trail, Code::Expired));
            }
            // Another transition won first; its decision is already in the channel.
            match guard.rx.as_mut() {
                Some(rx) => rx.await,
                None => return Ok(refuse(&app, &trail, Code::Shutdown)),
            }
        }
    };
    guard.rx = None;
    let decision = match decision {
        Ok(d) => d,
        Err(_) => {
            guard.phase = Phase::Done;
            return Ok(refuse(&app, &trail, Code::Shutdown));
        }
    };
    guard.record(&decision);
    match decision {
        Decision::Approved { confirm, .. } => {
            guard.phase = Phase::Approved;
            forward_approved(Forward {
                app,
                trail,
                guard,
                confirm,
                headers,
                bytes,
                method: parts.method,
                url: forward::upstream_url(
                    route,
                    &match &query {
                        Some(q) => format!("{rel}?{q}"),
                        None => rel.to_string(),
                    },
                ),
                pt,
            })
            .await
        }
        Decision::Denied { .. } => {
            guard.phase = Phase::Done;
            Ok(finish(&app, &trail, Code::HumanDenied))
        }
        Decision::Superseded { .. } => {
            guard.phase = Phase::Done;
            Ok(finish(&app, &trail, Code::Superseded))
        }
        Decision::Dropped => {
            guard.phase = Phase::Done;
            Ok(finish(&app, &trail, Code::DroppedOnReload))
        }
        Decision::Shutdown => {
            guard.phase = Phase::Done;
            Ok(refuse(&app, &trail, Code::Shutdown))
        }
    }
}

struct Forward<'a> {
    app: Arc<PtApp>,
    trail: Trail,
    guard: Guard,
    confirm: ConfirmTx,
    headers: HeaderMap,
    bytes: Bytes,
    method: http::Method,
    url: String,
    pt: &'a Passthrough,
}

enum Sent {
    Done(reqwest::Result<reqwest::Response>),
    Timeout,
}

async fn forward_approved(f: Forward<'_>) -> Result<Response<Body>, ConnAbort> {
    let Forward {
        app,
        trail,
        mut guard,
        confirm,
        headers,
        bytes,
        method,
        url,
        pt,
    } = f;
    let confirm: SharedConfirm = Arc::new(Mutex::new(Some(confirm)));

    #[cfg(any(test, feature = "matrix-upstream"))]
    app.pause.after_approve().await;

    let audit_failed = Arc::new(AtomicBool::new(false));
    let stream = HeldBody {
        app: Arc::clone(&app),
        ctx: guard.ctx.clone(),
        id: guard.id.clone(),
        digest: guard.digest.clone(),
        first: true,
        body: Some(bytes),
        confirm: Arc::clone(&confirm),
        started: Arc::clone(&guard.started),
        audit_failed: Arc::clone(&audit_failed),
        failed: false,
    };
    let send = app
        .held_client
        .request(method, url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(stream))
        .send();
    tokio::pin!(send);
    let started = Arc::clone(&guard.started);
    let limit = Duration::from_secs(pt.request_deadline_secs);
    let sent = tokio::select! {
        r = &mut send => Sent::Done(r),
        () = started.deadline(limit) => Sent::Timeout,
    };

    let upstream = match sent {
        Sent::Done(Ok(r)) => r,
        Sent::Done(Err(_)) => {
            guard.phase = Phase::Done;
            if audit_failed.load(Ordering::SeqCst) {
                guard.write(
                    "audit_unavailable",
                    None,
                    Some("audit_unavailable"),
                    Some(503),
                );
                return Ok(finish(&app, &trail, Code::AuditUnavailable));
            }
            if started.get().is_none() {
                // The body was never polled: no connection, nothing sent.
                if let Some(c) = take_confirm(&confirm) {
                    c.send(Confirm::ConnectFailed);
                }
                guard.write("connect_failed", None, Some("connect_failed"), Some(503));
                return Ok(finish(&app, &trail, Code::ConnectFailed));
            }
            // After `forward_started`: no synthetic answer, and no `completed`.
            return Err(abort(&app, &trail));
        }
        Sent::Timeout => {
            guard.phase = Phase::Done;
            return Err(abort(&app, &trail));
        }
    };

    // The request is on its way; the guard has nothing left to record.
    guard.phase = Phase::Done;
    let status = upstream.status();
    let out_headers = forward::response_headers(upstream.headers());
    let deadline = started.get().unwrap_or_else(Instant::now) + limit;
    let end = HeldEnd {
        ctx: guard.ctx.clone(),
        id: guard.id.clone(),
        digest: guard.digest.clone(),
    };
    let audit = StreamAudit {
        app: Arc::clone(&app),
        trail,
        status: status.as_u16(),
        reset: false,
        end: End::Held(end),
    };
    let idle = Duration::from_secs(pt.upstream_idle_secs);
    let stream = audited(upstream.bytes_stream(), audit, deadline, idle);
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = out_headers;
    Ok(response)
}
