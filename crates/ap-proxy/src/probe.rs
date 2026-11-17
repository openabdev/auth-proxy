//! Stage 1 hold-tolerance probe (design acceptance 10). Compiled only with the `stage1-probe`
//! feature and mounted only when `[probe] enabled`.
//!
//! `POST /__ap_probe/<status>/<secs>` answers with `status` after `secs` seconds and the matching
//! `X-AP-Decision`. It runs after the caller-key check, so it is never an unauthenticated slow
//! endpoint. A drop guard records whether the handler future was dropped before it answered,
//! which is how a client disconnect reaching the proxy is measured.

use std::time::{Duration, Instant};

use ap_core::config::Passthrough;
use ap_core::error::Code;
use ap_core::outcome::DECISION_HEADER;
use axum::body::Body;
use futures_util::StreamExt;
use http::{header, HeaderValue, Method, Response, StatusCode};

use crate::passthrough::{refuse, PtApp, Trail};

/// Path prefix of the probe route.
pub(crate) const PREFIX: &str = "/__ap_probe/";

const STATUSES: &[u16] = &[200, 410, 423, 503];
#[cfg(not(test))]
const SECS: &[u64] = &[10, 30, 60, 120, 300];
#[cfg(test)]
const SECS: &[u64] = &[0, 1, 2, 10, 30, 60, 120, 300];
const MAX_BODY: usize = 1024 * 1024;

fn parse(path: &str) -> Option<(u16, u64)> {
    let rest = path.strip_prefix(PREFIX)?;
    let (s, n) = rest.split_once('/')?;
    let status: u16 = s.parse().ok()?;
    let secs: u64 = n.parse().ok()?;
    (STATUSES.contains(&status) && SECS.contains(&secs)).then_some((status, secs))
}

struct Guard<'a> {
    app: &'a PtApp,
    status: u16,
    secs: u64,
    started: Instant,
    done: bool,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let event = if self.done {
            "completed"
        } else {
            "client_gone"
        };
        let line = serde_json::json!({"probe": {
            "event": event,
            "status": self.status,
            "secs": self.secs,
            "elapsed_ms": u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }})
        .to_string();
        self.app.audit.write_line(&line);
    }
}

pub(crate) async fn handle(
    app: &PtApp,
    trail: &Trail,
    method: &Method,
    path: &str,
    body: Body,
    pt: &Passthrough,
) -> Response<Body> {
    let Some((status, secs)) = parse(path).filter(|_| method == Method::POST) else {
        return refuse(app, trail, Code::ProbeParams);
    };
    let mut guard = Guard {
        app,
        status,
        secs,
        started: Instant::now(),
        done: false,
    };
    // Read the body (a write is what will be held), bounded in size, per-chunk time and total time.
    let mut stream = body.into_data_stream();
    let mut seen = 0usize;
    // Total bound on the body read, so a trickling caller cannot hold the slot indefinitely.
    let deadline = Instant::now() + Duration::from_secs(pt.request_deadline_secs);
    loop {
        let wait = Duration::from_secs(pt.body_read_secs)
            .min(deadline.saturating_duration_since(Instant::now()));
        match tokio::time::timeout(wait, stream.next()).await {
            Err(_) => {
                guard.done = true;
                return refuse(app, trail, Code::BodyReadTimeout);
            }
            Ok(None) => break,
            Ok(Some(Err(_))) => {
                guard.done = true;
                return refuse(app, trail, Code::BodyReadTimeout);
            }
            Ok(Some(Ok(c))) => {
                seen += c.len();
                if seen > MAX_BODY {
                    guard.done = true;
                    return refuse(app, trail, Code::BodyTooLarge);
                }
            }
        }
    }
    tokio::time::sleep(Duration::from_secs(secs)).await;
    guard.done = true;
    let decision = match status {
        410 => Some("expired"),
        423 => Some("denied"),
        503 => Some("unavailable"),
        _ => None,
    };
    let body = match decision {
        Some(d) => format!("{{\"ap_decision\":\"{d}\",\"code\":\"probe\"}}"),
        None => "{\"probe\":\"ok\"}".to_string(),
    };
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(d) = decision {
        r.headers_mut()
            .insert(DECISION_HEADER, HeaderValue::from_static(d));
    }
    r
}
