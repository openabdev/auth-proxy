//! The async hold mode (`docs/design/muse-async-poll.md`): the same hold, approval and forward as
//! the blocking path, but the caller gets `202` with a poll token at once and a detached task
//! carries the entry to its end. The task's outcome is stored for `GET /poll/<token>`.
//!
//! What is reused unchanged: the hold table, the start claim in [`HeldBody`], the audit records
//! and the Telegram notification. What is new: the admission order (the `held` record first), the
//! absence of dedupe and supersede, and the mapping from each ending to a poll status.

use super::*;
use crate::async_poll::{self, Final, FinishGuard, BODY_MAX};
use futures_util::StreamExt;

pub(super) struct Request<'a> {
    pub app: Arc<PtApp>,
    pub trail: Trail,
    pub ctx: Ctx,
    pub req: Arc<HeldRequest>,
    pub headers: HeaderMap,
    pub bytes: Bytes,
    pub method: http::Method,
    pub url: String,
    pub hold: Duration,
    pub deadline: Duration,
    pub idle: Duration,
    pub identity: &'a str,
}

struct Drive {
    app: Arc<PtApp>,
    trail: Trail,
    req: Arc<HeldRequest>,
    guard: Guard,
    fin: FinishGuard,
    headers: HeaderMap,
    bytes: Bytes,
    method: http::Method,
    url: String,
    hold: Duration,
    deadline: Duration,
    idle: Duration,
}

/// Admit the request and answer `202`, or refuse as the blocking path does.
pub(super) async fn run(r: Request<'_>) -> Response<Body> {
    let Request {
        app,
        trail,
        ctx,
        req,
        headers,
        bytes,
        method,
        url,
        hold,
        deadline,
        idle,
        identity,
    } = r;

    // The `held` record is written first, under the table lock. A failed write refuses before any
    // entry exists; a refusal by the checks that follow leaves the record and gets its own.
    let admission = app.hold.admit_async(
        identity,
        Arc::clone(&req),
        |id, digest| {
            let mut rec = ctx.rec(id, digest, "held", None, None, None);
            rec.upstream = Some(req.upstream.authority());
            rec.policy_generation = Some(req.generation);
            app.audit.try_write_hold(&rec)
        },
        // A refusal after the `held` record gets its own terminal record for the same id.
        |id, digest, code| {
            let rec = ctx.rec(
                id,
                digest,
                "abandoned",
                None,
                Some(code.code_str()),
                Some(503),
            );
            app.audit.write_hold(&rec);
        },
    );
    let held = match admission {
        Admission::Refused(code) => return refuse(&app, &trail, code),
        Admission::Held(h) => h,
    };
    let token = app.polls.insert(&held.id, app.clock.now());
    announce(&app, &ctx, &held);
    let started = Arc::new(Started::new());
    // If the task is cut (shutdown past the wait), a forward that already passed
    // `forward_started` is `send_unknown`, never `dropped`; before it, `dropped`.
    let on_cut = {
        let (app, ctx, started) = (Arc::clone(&app), ctx.clone(), Arc::clone(&started));
        let (id, digest) = (held.id.clone(), held.digest.clone());
        Box::new(move || {
            if started.get().is_some() {
                app.audit.write_hold(&ctx.rec(
                    &id,
                    &digest,
                    "completed",
                    None,
                    Some("upstream_reset"),
                    None,
                ));
                Final::SendUnknown("reset")
            } else {
                Final::Dropped
            }
        })
    };
    let fin = FinishGuard::new(
        Arc::clone(&app.polls),
        Arc::clone(&app.clock),
        &held.id,
        on_cut,
    );
    let guard = Guard {
        app: Arc::clone(&app),
        ctx,
        id: held.id,
        digest: held.digest,
        phase: Phase::Pending,
        rx: Some(held.decision),
        started,
    };
    trail.write_evidence(&app.audit, 202);
    let response = async_poll::accepted(&guard.id, &token);
    let tasks = Arc::clone(&app.async_tasks);
    tasks.spawn(drive(Drive {
        app,
        trail,
        req,
        guard,
        fin,
        headers,
        bytes,
        method,
        url,
        hold,
        deadline,
        idle,
    }));
    response
}

/// Wait for a decision or the timer, then forward if approved, and store the ending.
async fn drive(d: Drive) {
    let Drive {
        app,
        trail,
        req,
        mut guard,
        fin,
        headers,
        bytes,
        method,
        url,
        hold,
        deadline,
        idle,
    } = d;
    enum Event {
        Decision(Result<Decision, oneshot::error::RecvError>),
        Timer,
    }
    let event = {
        let Some(rx) = guard.rx.as_mut() else {
            return;
        };
        tokio::select! {
            d = rx => Event::Decision(d),
            () = tokio::time::sleep(hold) => Event::Timer,
        }
    };
    // Approve versus expiry is decided inside the table, on its one mutex: the first wins.
    let decision = match event {
        Event::Decision(d) => d,
        Event::Timer => {
            if app.hold.expire(&guard.id) {
                guard.phase = Phase::Done;
                guard.write("expired", None, Some("expired"), Some(410));
                fin.finish(Final::Expired);
                return;
            }
            match guard.rx.as_mut() {
                Some(rx) => rx.await,
                None => return,
            }
        }
    };
    guard.rx = None;
    let shutdown = |guard: &mut Guard| {
        guard.phase = Phase::Done;
        let code = Code::Shutdown;
        let (status, _, _) = render_passthrough(code);
        app.audit
            .write_rec(&trail.rec("deny", Some(code.code_str()), status));
    };
    let decision = match decision {
        Ok(d) => d,
        Err(_) => {
            shutdown(&mut guard);
            fin.finish(Final::Dropped);
            return;
        }
    };
    guard.record(&decision);
    match decision {
        Decision::Approved { confirm, .. } => {
            guard.phase = Phase::Approved;
            let out = forward(
                &app,
                req,
                &mut guard,
                confirm,
                headers,
                bytes,
                method,
                url,
                (deadline, idle),
            )
            .await;
            fin.finish(out);
        }
        Decision::Denied { .. } => {
            guard.phase = Phase::Done;
            fin.finish(Final::Denied);
        }
        // No dedupe in async mode, so a supersede cannot happen; treat it as dropped anyway.
        Decision::Superseded { .. } | Decision::Dropped => {
            guard.phase = Phase::Done;
            fin.finish(Final::Dropped);
        }
        Decision::Shutdown => {
            shutdown(&mut guard);
            fin.finish(Final::Dropped);
        }
    }
}

/// The approved forward. Same milestones and audit records as `forward_approved`; the ending is a
/// poll status instead of a response. Anything past the first request byte that is not a fully
/// read Discord response is `send_unknown`, never `dropped`.
#[allow(clippy::too_many_arguments)]
async fn forward(
    app: &Arc<PtApp>,
    req: Arc<HeldRequest>,
    guard: &mut Guard,
    confirm: ConfirmTx,
    headers: HeaderMap,
    bytes: Bytes,
    method: http::Method,
    url: String,
    (deadline, idle): (Duration, Duration),
) -> Final {
    let confirm: SharedConfirm = Arc::new(Mutex::new(Some(confirm)));

    #[cfg(any(test, feature = "matrix-upstream"))]
    app.pause.after_approve().await;

    let audit_failed = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(AtomicBool::new(false));
    let policy_changed = Arc::new(AtomicBool::new(false));
    let stream = HeldBody {
        app: Arc::clone(app),
        req,
        ctx: guard.ctx.clone(),
        id: guard.id.clone(),
        digest: guard.digest.clone(),
        first: true,
        body: Some(bytes),
        confirm: Arc::clone(&confirm),
        started: Arc::clone(&guard.started),
        audit_failed: Arc::clone(&audit_failed),
        shutdown: Arc::clone(&shutdown),
        policy_changed: Arc::clone(&policy_changed),
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
    let sent = tokio::select! {
        r = &mut send => Sent::Done(r),
        () = started.deadline(deadline) => Sent::Timeout,
    };
    let upstream = match sent {
        Sent::Done(Ok(r)) => r,
        Sent::Done(Err(e)) => {
            guard.phase = Phase::Done;
            if audit_failed.load(Ordering::SeqCst) {
                guard.write(
                    "audit_unavailable",
                    None,
                    Some("audit_unavailable"),
                    Some(503),
                );
                return Final::SendFailed;
            }
            if policy_changed.load(Ordering::SeqCst) {
                guard.write(
                    "dropped_on_reload",
                    None,
                    Some("dropped_on_reload"),
                    Some(503),
                );
                return Final::Dropped;
            }
            if shutdown.load(Ordering::SeqCst) {
                guard.write("abandoned_after_approve", None, Some("shutdown"), Some(503));
                return Final::Dropped;
            }
            if started.get().is_none() {
                if let Some(c) = take_confirm(&confirm) {
                    c.send(Confirm::ConnectFailed);
                }
                guard.write("connect_failed", None, Some("connect_failed"), Some(503));
                return Final::SendFailed;
            }
            return Final::SendUnknown(if e.is_timeout() {
                "timeout"
            } else {
                error_class(&e)
            });
        }
        Sent::Timeout => {
            guard.phase = Phase::Done;
            return Final::SendUnknown("timeout");
        }
    };

    // The request is on its way; the guard has nothing left to record.
    guard.phase = Phase::Done;
    let status = upstream.status().as_u16();
    let limit = started.get().unwrap_or_else(Instant::now) + deadline;
    let mut stream = upstream.bytes_stream();
    let mut body: Vec<u8> = Vec::new();
    let mut truncated = false;
    loop {
        let wait = limit.saturating_duration_since(Instant::now()).min(idle);
        match tokio::time::timeout(wait, stream.next()).await {
            Ok(Some(Ok(chunk))) => {
                body.extend_from_slice(&chunk);
                if body.len() > BODY_MAX {
                    body.truncate(BODY_MAX);
                    truncated = true;
                    break;
                }
            }
            Ok(Some(Err(_))) => return Final::SendUnknown("reset"),
            Ok(None) => break,
            Err(_) => return Final::SendUnknown("timeout"),
        }
    }
    guard.write("completed", None, None, Some(status));
    Final::Approved {
        discord_status: status,
        body,
        truncated,
    }
}

/// `write_failed` when a write on the connection failed, otherwise `reset`.
fn error_class(e: &(dyn std::error::Error + 'static)) -> &'static str {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(io) = err.downcast_ref::<io::Error>() {
            match io.kind() {
                io::ErrorKind::TimedOut => return "timeout",
                io::ErrorKind::BrokenPipe | io::ErrorKind::WriteZero => return "write_failed",
                _ => {}
            }
        }
        cur = err.source();
    }
    "reset"
}

#[cfg(test)]
mod class_tests {
    use super::*;

    #[test]
    fn error_class_reads_the_io_kind_in_the_chain() {
        let pipe = io::Error::new(io::ErrorKind::BrokenPipe, "x");
        assert_eq!(error_class(&pipe), "write_failed");
        let timed = io::Error::new(io::ErrorKind::TimedOut, "x");
        assert_eq!(error_class(&timed), "timeout");
        let other = io::Error::other("x");
        assert_eq!(error_class(&other), "reset");
    }
}
