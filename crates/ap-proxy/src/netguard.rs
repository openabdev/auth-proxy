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

/// Where the checkers write and how often they run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetfilterOpts {
    pub rules_status: PathBuf,
    pub probe_status: PathBuf,
    pub interval: Duration,
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
    pub age: Duration,
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
            src.last_change = if first {
                now.checked_sub(reading.age).unwrap_or(now)
            } else {
                now
            };
            src.last_tick = Some(parsed.tick.clone());
        }
        if !parsed.ok {
            return Some(format!("{name}:{}", parsed.reason));
        }
        if now.saturating_duration_since(src.last_change) > max_age {
            return Some(format!("{name}:stale"));
        }
        None
    }
}

/// The shared gate state, read by the agent listener and the readiness endpoint.
pub struct Gate {
    state: Mutex<GuardState>,
}

impl Gate {
    pub fn new() -> Arc<Gate> {
        Arc::new(Gate {
            state: Mutex::new(GuardState::Unverified("starting".to_string())),
        })
    }

    pub fn state(&self) -> GuardState {
        match self.state.lock() {
            Ok(s) => s.clone(),
            // A poisoned lock closes the gate.
            Err(_) => GuardState::Failed("gate:poisoned".to_string()),
        }
    }

    fn set(&self, next: GuardState) {
        let mut s = match self.state.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };
        *s = next;
    }
}

/// Read one status file: its text and its age. `None` when it cannot be read or is too large.
pub fn read_status(path: &Path) -> Option<(String, Duration)> {
    let file = fs::File::open(path).ok()?;
    let age = file
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or(Duration::ZERO);
    let mut text = String::new();
    file.take(MAX_STATUS_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > MAX_STATUS_BYTES {
        return None;
    }
    Some((text, age))
}

fn audit_state(audit: &AuditSink, state: &GuardState) {
    let line = json!({
        "event": "netfilter",
        "state": state.name(),
        "reason": state.reason(),
    })
    .to_string();
    audit.write_line(&line);
    eprintln!(
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

fn view(r: &Option<(String, Duration)>) -> Option<Reading<'_>> {
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
        let rules = read_status(&opts.rules_status);
        let probe = read_status(&opts.probe_status);
        if let Some(next) = guard.observe(Instant::now(), [view(&rules), view(&probe)]) {
            gate.set(next.clone());
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
