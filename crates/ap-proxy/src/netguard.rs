//! Fail-closed gate on the per-UID netfilter rules (sidecar profile only).
//!
//! The proxy container has no network capability, so it cannot read or test the rules itself.
//! Two checker containers in the pod do that and each writes a one-line status file:
//!
//! - `netcheck` (root, `NET_ADMIN`) compares the live `OUTPUT` chain with the snapshot `netinit`
//!   took when it installed the rules (rule presence).
//! - `ap-netprobe` (the agent UID, no capability) tries a loopback connect, a direct connect and
//!   a DNS query. Each must be refused (functional probe).
//!
//! The status line is `tick=<token> state=ok|fail reason=<code>`. The proxy mounts both files
//! read-only and polls them. It serves only while both say `ok` and both ticks keep changing. A
//! missing, unreadable, malformed, failing or stale file closes the gate, so the death of a checker
//! counts as a failure. The gate reopens by itself once both files are healthy again.
//!
//! While the gate is closed the agent listener answers every request with a terminal 503 and the
//! admin readiness endpoint reports not ready. The session and admin sockets stay up, so a
//! revoke-all still works during an incident.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::body::Body;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use http::{header, HeaderValue, StatusCode};
use serde_json::json;

use crate::audit_sink::AuditSink;
use crate::pipeline::App;

/// Default period of the checkers, and so of the self-check.
pub const DEFAULT_INTERVAL_SECS: u64 = 30;
/// Extra time on top of two intervals before a silent checker counts as dead. It covers the
/// probe timeouts, which can stretch one checker cycle past its interval.
pub const STALE_SLACK: Duration = Duration::from_secs(5);
/// How often the proxy reads the status files.
pub const POLL: Duration = Duration::from_secs(1);
/// A status file is one short line. Anything larger is malformed.
const MAX_STATUS_BYTES: u64 = 512;
/// The gate counts as stale when the monitor has not published for this long. It closes the gate
/// if the monitor task dies or stalls, so an open gate always rests on a recent reading.
const GATE_STALE: Duration = Duration::from_secs(5);
/// One read of a status file must finish within this. A read that does not counts as missing.
const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Default owner of the rules status file: `netcheck` runs as root.
pub const DEFAULT_RULES_UID: u32 = 0;
/// Default owner of the probe status file: `netprobe` runs as the agent UID.
pub const DEFAULT_PROBE_UID: u32 = 1000;

/// Where the checkers write and how often they run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetfilterOpts {
    pub rules_status: PathBuf,
    pub probe_status: PathBuf,
    pub interval: Duration,
    /// The only owner the rules status file may have.
    pub rules_uid: u32,
    /// The only owner the probe status file may have.
    pub probe_uid: u32,
}

impl NetfilterOpts {
    /// The longest a status file may go without a new tick before it counts as stale.
    pub fn max_age(&self) -> Duration {
        self.interval * 2 + STALE_SLACK
    }
}

/// The gate state. `Unverified` holds until the first healthy reading after start; `Failed`
/// holds after a healthy reading was lost. Both refuse requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardState {
    Unverified(String),
    Ready,
    Failed(String),
}

impl GuardState {
    pub fn name(&self) -> &'static str {
        match self {
            GuardState::Unverified(_) => "unverified",
            GuardState::Ready => "ready",
            GuardState::Failed(_) => "failed",
        }
    }

    pub fn reason(&self) -> &str {
        match self {
            GuardState::Ready => "ok",
            GuardState::Unverified(r) | GuardState::Failed(r) => r,
        }
    }
}

/// One status file as read: its text and the age of the file.
#[derive(Debug, Clone, Copy)]
pub struct Reading<'a> {
    pub text: &'a str,
    /// Age of the file by its mtime. `None` when it is unknown (no mtime, or one in the future),
    /// which counts as stale until a new tick arrives.
    pub age: Option<Duration>,
}

/// A parsed status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub tick: String,
    pub ok: bool,
    pub reason: String,
}

fn token_ok(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Parse `tick=<t> state=ok|fail reason=<code>`. Every value is a short token of letters, digits,
/// `_`, `-` and `.`, so a reason can be logged as is. Anything else is `None`.
pub fn parse_status(text: &str) -> Option<Parsed> {
    let mut tick = None;
    let mut state = None;
    let mut reason = None;
    let mut parts = text.split_whitespace();
    for part in parts.by_ref() {
        let (k, v) = part.split_once('=')?;
        if !token_ok(v) {
            return None;
        }
        let slot = match k {
            "tick" => &mut tick,
            "state" => &mut state,
            "reason" => &mut reason,
            _ => return None,
        };
        if slot.replace(v.to_string()).is_some() {
            return None;
        }
    }
    let ok = match state?.as_str() {
        "ok" => true,
        "fail" => false,
        _ => return None,
    };
    Some(Parsed {
        tick: tick?,
        ok,
        reason: reason?,
    })
}

struct Source {
    name: &'static str,
    last_tick: Option<String>,
    last_change: Instant,
    /// The first reading could not be aged, so the source is stale until a new tick arrives.
    unaged: bool,
}

/// The state machine. It holds no clock and does no I/O: the caller passes the time and the two
/// readings (rules, then probe), so tests drive it with fake checkers.
pub struct Guard {
    max_age: Duration,
    sources: [Source; 2],
    ever_ready: bool,
    state: GuardState,
}

impl Guard {
    pub fn new(max_age: Duration, now: Instant) -> Self {
        let src = |name| Source {
            name,
            last_tick: None,
            last_change: now,
            unaged: false,
        };
        Guard {
            max_age,
            sources: [src("rules"), src("probe")],
            ever_ready: false,
            state: GuardState::Unverified("starting".to_string()),
        }
    }

    pub fn state(&self) -> &GuardState {
        &self.state
    }

    /// Feed one poll. Returns the new state when it changed.
    pub fn observe(
        &mut self,
        now: Instant,
        readings: [Option<Reading<'_>>; 2],
    ) -> Option<GuardState> {
        let mut problem: Option<String> = None;
        for (src, reading) in self.sources.iter_mut().zip(readings) {
            let found = Self::check(src, reading, now, self.max_age);
            if problem.is_none() {
                problem = found;
            }
        }
        let next = match problem {
            None => {
                self.ever_ready = true;
                GuardState::Ready
            }
            Some(p) if self.ever_ready => GuardState::Failed(p),
            Some(p) => GuardState::Unverified(p),
        };
        if next == self.state {
            None
        } else {
            self.state = next.clone();
            Some(next)
        }
    }

    /// The problem with one source, or `None` when it is healthy.
    fn check(
        src: &mut Source,
        reading: Option<Reading<'_>>,
        now: Instant,
        max_age: Duration,
    ) -> Option<String> {
        let name = src.name;
        let Some(reading) = reading else {
            return Some(format!("{name}:missing"));
        };
        let Some(parsed) = parse_status(reading.text) else {
            return Some(format!("{name}:malformed"));
        };
        if src.last_tick.as_deref() != Some(parsed.tick.as_str()) {
            // First sight counts the file's own age, so a file left behind by a dead checker
            // does not look fresh when the proxy restarts. A later new tick is fresh by itself.
            let first = src.last_tick.is_none();
            src.unaged = false;
            src.last_change = now;
            if first {
                // An unknown age, or one the monotonic clock cannot go back by, is not trusted.
                match reading.age.and_then(|a| now.checked_sub(a)) {
                    Some(t) => src.last_change = t,
                    None => src.unaged = true,
                }
            }
            src.last_tick = Some(parsed.tick.clone());
        }
        if !parsed.ok {
            return Some(format!("{name}:{}", parsed.reason));
        }
        if src.unaged || now.saturating_duration_since(src.last_change) > max_age {
            return Some(format!("{name}:stale"));
        }
        None
    }
}

/// The shared gate state, read by the agent listener and the readiness endpoint.
pub struct Gate {
    state: Mutex<(GuardState, Instant)>,
}

impl Gate {
    pub fn new() -> Arc<Gate> {
        Arc::new(Gate {
            state: Mutex::new((
                GuardState::Unverified("starting".to_string()),
                Instant::now(),
            )),
        })
    }

    pub fn state(&self) -> GuardState {
        self.state_at(Instant::now())
    }

    fn state_at(&self, now: Instant) -> GuardState {
        match self.state.lock() {
            // An open gate needs a recent publication from the monitor. If the monitor task has
            // died or stalled, the gate closes by itself.
            Ok(s)
                if s.0 == GuardState::Ready && now.saturating_duration_since(s.1) > GATE_STALE =>
            {
                GuardState::Failed("gate:stale".to_string())
            }
            Ok(s) => s.0.clone(),
            // A poisoned lock closes the gate.
            Err(_) => GuardState::Failed("gate:poisoned".to_string()),
        }
    }

    /// Publish the monitor's current state. The monitor calls it on every poll.
    fn set(&self, next: GuardState) {
        let mut s = match self.state.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };
        *s = (next, Instant::now());
    }
}

/// Read one status file: its text and its age. `None` when it cannot be trusted or read.
///
/// The file is opened with `O_NONBLOCK` and `O_NOFOLLOW`, so a FIFO cannot block the open and a
/// symlink is refused. The opened descriptor is then checked: it must be a regular file owned by
/// `owner_uid`, not writable by group or world, and no larger than one status line. Anything else
/// (FIFO, socket, directory, device, symlink, wrong owner, oversized) reads as `None`, and the gate
/// treats that as a failing check. The read never blocks: a regular file does not block on read.
pub fn read_status(path: &Path, owner_uid: u32) -> Option<(String, Option<Duration>)> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.file_type().is_file()
        || meta.uid() != owner_uid
        || meta.mode() & 0o022 != 0
        || meta.len() > MAX_STATUS_BYTES
    {
        return None;
    }
    let age = meta
        .modified()
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok());
    let mut text = String::new();
    file.take(MAX_STATUS_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > MAX_STATUS_BYTES {
        return None;
    }
    Some((text, age))
}

/// `read_status` on a blocking thread with a deadline, so a stuck filesystem can never stall the
/// monitor or a worker. A read that misses the deadline counts as missing.
async fn read_status_bounded(path: PathBuf, uid: u32) -> Option<(String, Option<Duration>)> {
    let task = tokio::task::spawn_blocking(move || read_status(&path, uid));
    match tokio::time::timeout(READ_TIMEOUT, task).await {
        Ok(Ok(r)) => r,
        _ => None,
    }
}

fn audit_state(audit: &AuditSink, state: &GuardState) {
    let line = json!({
        "event": "netfilter",
        "state": state.name(),
        "reason": state.reason(),
    })
    .to_string();
    audit.write_line(&line);
    // A failed write to stderr must not panic: the monitor has to keep running.
    let _ = writeln!(
        std::io::stderr(),
        "auth-proxy: netfilter self-check {}: {}",
        state.name(),
        state.reason()
    );
}

/// Start the poll task. It reads both files every `POLL`, feeds the state machine and publishes
/// the state. The task ends with the process.
pub fn spawn_monitor(opts: NetfilterOpts, gate: Arc<Gate>, app: Arc<App>) {
    tokio::spawn(monitor(opts, POLL, gate, move |s| {
        audit_state(&app.audit, s)
    }));
}

fn view(r: &Option<(String, Option<Duration>)>) -> Option<Reading<'_>> {
    r.as_ref().map(|(text, age)| Reading { text, age: *age })
}

/// The poll loop. `on_change` is called with every new state, and with the first one at start.
pub(crate) async fn monitor<F>(opts: NetfilterOpts, poll: Duration, gate: Arc<Gate>, on_change: F)
where
    F: Fn(&GuardState),
{
    let mut guard = Guard::new(opts.max_age(), Instant::now());
    on_change(guard.state());
    loop {
        let rules = read_status_bounded(opts.rules_status.clone(), opts.rules_uid).await;
        let probe = read_status_bounded(opts.probe_status.clone(), opts.probe_uid).await;
        let changed = guard.observe(Instant::now(), [view(&rules), view(&probe)]);
        gate.set(guard.state().clone());
        if let Some(next) = changed {
            on_change(&next);
        }
        tokio::time::sleep(poll).await;
    }
}

/// The terminal refusal while the gate is closed: 503 with `X-AP-Decision: unavailable` and the
/// gate's JSON body. The body and the audit line hold fixed strings only.
pub fn refusal(gate: &Gate, audit: &AuditSink) -> Option<Response> {
    if gate.state() == GuardState::Ready {
        return None;
    }
    let line = json!({
        "event": "netfilter",
        "decision": "deny",
        "code": "netfilter_unverified",
        "status": 503,
    })
    .to_string();
    audit.write_line(&line);
    let mut r = Response::new(Body::from(
        "{\"ap_decision\":\"unavailable\",\"code\":\"netfilter_unverified\"}",
    ));
    *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(
        ap_core::outcome::DECISION_HEADER,
        HeaderValue::from_static("unavailable"),
    );
    h.insert(header::CONNECTION, HeaderValue::from_static("close"));
    Some(r)
}

/// `GET /admin/v1/ready` on the admin socket. 200 when the gate is open (or no gate is
/// configured), 503 with the state and reason code otherwise.
pub fn ready_router(gate: Option<Arc<Gate>>) -> Router {
    Router::new().route(
        "/admin/v1/ready",
        get(move || {
            let gate = gate.clone();
            async move {
                let state = gate.as_ref().map_or(GuardState::Ready, |g| g.state());
                let ready = state == GuardState::Ready;
                let body =
                    json!({ "ready": ready, "state": state.name(), "reason": state.reason() });
                let mut r = Response::new(Body::from(body.to_string()));
                *r.status_mut() = if ready {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                r
            }
        }),
    )
}

/// `auth-proxy --check-ready [--admin-socket <path>]`: the Kubernetes exec readiness probe. The
/// distroless image has no shell or curl, so the binary asks its own admin socket. Exit 0 when
/// ready, 1 when not ready or unreachable.
pub fn check_ready_main(args: &[String]) -> i32 {
    let mut socket = PathBuf::from("/run/auth-proxy-private/admin.sock");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--check-ready" => {}
            "--admin-socket" => match it.next() {
                Some(p) => socket = PathBuf::from(p),
                None => return 2,
            },
            _ => return 2,
        }
    }
    i32::from(!ask_ready(&socket))
}

fn ask_ready(socket: &Path) -> bool {
    let Ok(mut s) = UnixStream::connect(socket) else {
        return false;
    };
    let t = Some(Duration::from_secs(2));
    if s.set_read_timeout(t).is_err() || s.set_write_timeout(t).is_err() {
        return false;
    }
    let req = "GET /admin/v1/ready HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n";
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0u8; 12];
    s.read_exact(&mut head).is_ok() && &head == b"HTTP/1.1 200"
}

#[cfg(test)]
mod tests;
