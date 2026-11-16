//! The agent listener: design doc section 4, step by step.
//!
//! LOGGING RULE (owner condition b). The request URI carries the caller key
//! (`/ap/<caller-key>/<route>/...`) and never reaches a log:
//!
//! - no tracing or access-log layer is installed anywhere in this process;
//! - `ApPath::verify` is the single place the prefix is taken apart, and it
//!   hands back a `VerifiedPath` that holds only the route and the rest, so
//!   everything after caller verification (audit, upstream URL, errors) cannot
//!   see the key;
//! - a request refused before the key is verified is audited with path `-`;
//! - upstream errors are never formatted: `reqwest` error text embeds the URL,
//!   so only fixed codes are logged;
//! - the panic hook (main.rs) prints a fixed string, and `handler` turns a
//!   panic into a fixed 500.

use crate::app::App;
use ap_broker::Broker;
use ap_core::surrogate::hash_surrogate;
use ap_core::{
    canon::path_ambiguous, deny_parts, strip_request_headers, ApPath, AuditInput, AuditRec, Code,
    ErrorShape, RoutePath, HOP_HEADERS,
};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use futures_util::{FutureExt, StreamExt};
use http::{header, HeaderMap, HeaderName, HeaderValue, Method};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// How much of an oversized body is read and discarded before the 413.
const DRAIN_LIMIT: u64 = 64 * 1024 * 1024;

pub async fn handler(State(app): State<Arc<App>>, req: Request) -> Response {
    match AssertUnwindSafe(handle(app, req)).catch_unwind().await {
        Ok(r) => r,
        Err(_) => fixed_json(
            500,
            r#"{"type":"error","error":{"type":"internal_error","message":"auth-proxy: internal error"}}"#,
        ),
    }
}

pub fn fixed_json(status: u16, body: &'static str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// What the audit line learns as the request moves through the pipeline.
#[derive(Default, Clone)]
struct Ctx {
    identity: Option<String>,
    session: Option<String>,
    generation: Option<u64>,
    route: Option<String>,
    aws_target: Option<String>,
}

impl Ctx {
    fn input<'a>(&'a self, method: &'a str, t0: Instant) -> AuditInput<'a> {
        AuditInput {
            identity: self.identity.as_deref(),
            session: self.session.as_deref(),
            generation: self.generation,
            route: self.route.as_deref(),
            method,
            aws_target: self.aws_target.as_deref(),
            duration_ms: t0.elapsed().as_millis() as u64,
        }
    }
}

fn deny_response(shape: ErrorShape, code: Code) -> Response {
    let (status, headers, body) = deny_parts(shape, code);
    let mut r = Response::builder().status(status);
    for (k, v) in headers {
        r = r.header(k, v);
    }
    r.body(Body::from(body)).unwrap()
}

/// Audit the refusal, then build it in the route's error dialect.
fn refuse(
    app: &App,
    ctx: &Ctx,
    method: &str,
    t0: Instant,
    path: &RoutePath,
    shape: ErrorShape,
    code: Code,
) -> Response {
    app.audit
        .request(&AuditRec::refused(&ctx.input(method, t0), path, code));
    match code {
        Code::PolicyUnavailable => {
            let why = app.policy.last_error().unwrap_or_default();
            app.warn_limited("policy_unavailable", &format!("policy unavailable: {why}"));
        }
        Code::BrokerUnavailable => {
            app.warn_limited("broker_unavailable", "credential store unavailable");
        }
        _ => {}
    }
    deny_response(shape, code)
}

/// The dialect of the route named in a path whose caller key is not verified.
/// Only used to choose how to word a refusal; the name is never logged.
fn guess_shape(app: &App, path: &str) -> ErrorShape {
    let Some(ap) = ApPath::split(path) else {
        return ErrorShape::Json;
    };
    match app.policy.current() {
        Ok(p) => p
            .route(ap.unverified_route())
            .map(|r| r.error_shape)
            .unwrap_or_default(),
        Err(_) => ErrorShape::Json,
    }
}

fn is_websocket_upgrade(h: &HeaderMap) -> bool {
    h.get_all(header::UPGRADE).iter().any(|v| {
        v.to_str()
            .is_ok_and(|s| s.to_ascii_lowercase().contains("websocket"))
    })
}

/// Exactly one surrogate in the route's header, in the route's scheme.
fn presented_surrogate<'a>(
    headers: &'a HeaderMap,
    route: &ap_core::config::RouteCfg,
) -> Result<&'a str, Code> {
    let vals: Vec<&HeaderValue> = headers
        .get_all(route.surrogate_header.as_str())
        .iter()
        .collect();
    match vals.as_slice() {
        [] => Err(Code::SurrogateMissing),
        [one] => {
            let raw = one.to_str().map_err(|_| Code::SurrogateMalformed)?;
            if raw.contains(',') {
                return Err(Code::SurrogateAmbiguous);
            }
            if route.surrogate_scheme.is_empty() {
                return Ok(raw);
            }
            let p = route.surrogate_scheme.len() + 1;
            let b = raw.as_bytes();
            if b.len() > p
                && b[..route.surrogate_scheme.len()]
                    .eq_ignore_ascii_case(route.surrogate_scheme.as_bytes())
                && b[route.surrogate_scheme.len()] == b' '
            {
                Ok(&raw[p..])
            } else {
                Err(Code::SurrogateMalformed)
            }
        }
        _ => Err(Code::SurrogateAmbiguous),
    }
}

/// Read and discard what the client is still sending, bounded in bytes and
/// time, so the refusal is delivered instead of being lost to a connection
/// reset. A client that sends more than the limit gets the reset.
pub async fn drain(body: Body, limit: u64) {
    let mut s = body.into_data_stream();
    let mut n = 0u64;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(Ok(b)) = s.next().await {
            n += b.len() as u64;
            if n > limit {
                break;
            }
        }
    })
    .await;
}

/// Counts request-body bytes and fails the stream once the cap is crossed.
fn capped(
    body: Body,
    max: u64,
    over: Arc<AtomicBool>,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send + 'static {
    let seen = AtomicU64::new(0);
    body.into_data_stream().map(move |r| match r {
        Ok(b) => {
            let total = seen.fetch_add(b.len() as u64, Ordering::Relaxed) + b.len() as u64;
            if total > max {
                over.store(true, Ordering::Relaxed);
                Err(std::io::Error::other("request body over the cap"))
            } else {
                Ok(b)
            }
        }
        Err(_) => Err(std::io::Error::other("request body read failed")),
    })
}

async fn handle(app: Arc<App>, req: Request) -> Response {
    let t0 = Instant::now();
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_owned();
    let none = RoutePath::none();
    let mut ctx = Ctx::default();

    // 1. CONNECT and WebSocket upgrades.
    if parts.method == Method::CONNECT {
        return refuse(
            &app,
            &ctx,
            &method,
            t0,
            &none,
            ErrorShape::Json,
            Code::ConnectRefused,
        );
    }
    if is_websocket_upgrade(&parts.headers) {
        let shape = guess_shape(&app, parts.uri.path());
        return refuse(
            &app,
            &ctx,
            &method,
            t0,
            &none,
            shape,
            Code::WebsocketUnsupported,
        );
    }

    // 2. Canonicalize: origin-form, exactly one Host equal to a listener
    //    authority, no ambiguous path.
    if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
        let shape = guess_shape(&app, parts.uri.path());
        return refuse(&app, &ctx, &method, t0, &none, shape, Code::AbsoluteForm);
    }
    let hosts: Vec<&HeaderValue> = parts.headers.get_all(header::HOST).iter().collect();
    let host_ok = hosts.len() == 1
        && hosts[0]
            .to_str()
            .is_ok_and(|h| app.authorities.iter().any(|a| a == h));
    if !host_ok {
        let shape = guess_shape(&app, parts.uri.path());
        return refuse(&app, &ctx, &method, t0, &none, shape, Code::HostRejected);
    }
    let path = parts.uri.path();
    if path_ambiguous(path) {
        let shape = guess_shape(&app, path);
        return refuse(&app, &ctx, &method, t0, &none, shape, Code::PathAmbiguous);
    }

    // 3. /ap/<caller-key>/<route>/...: the caller key is checked against the
    //    policy's hash, in constant time, and dropped.
    let Some(ap) = ApPath::split(path) else {
        return refuse(
            &app,
            &ctx,
            &method,
            t0,
            &none,
            ErrorShape::Json,
            Code::RouteUnknown,
        );
    };
    let policy = match app.policy.current() {
        Ok(p) => p,
        Err(code) => {
            return refuse(&app, &ctx, &method, t0, &none, ErrorShape::Json, code);
        }
    };
    let shape_unverified = policy
        .route(ap.unverified_route())
        .map(|r| r.error_shape)
        .unwrap_or_default();
    let Some(vp) = ap.verify(|k| policy.caller_matches(k)) else {
        return refuse(
            &app,
            &ctx,
            &method,
            t0,
            &none,
            shape_unverified,
            Code::CallerRejected,
        );
    };
    ctx.identity = Some(policy.identity().to_string());
    let rp = vp.route_relative();
    let Some(route) = policy.route(vp.route()) else {
        return refuse(
            &app,
            &ctx,
            &method,
            t0,
            &rp,
            ErrorShape::Json,
            Code::RouteUnknown,
        );
    };
    ctx.route = Some(route.name.clone());
    let shape = route.error_shape;
    let deny = |ctx: &Ctx, code: Code| refuse(&app, ctx, &method, t0, &rp, shape, code);

    // 4. Exactly one surrogate, well formed.
    let hash = match presented_surrogate(&parts.headers, route).and_then(hash_surrogate) {
        Ok(h) => h,
        Err(code) => return deny(&ctx, code),
    };

    // 5. Registry lookup by sha256(surrogate).
    let binding = match app.broker.admit(&hash, &route.name, &policy) {
        Ok(b) => b,
        Err(code) => return deny(&ctx, code),
    };
    ctx.session = Some(binding.session.clone());
    ctx.generation = Some(binding.generation);

    // 6. Policy: method, path and AWS target against the grants.
    let targets: Vec<&[u8]> = parts
        .headers
        .get_all("x-amz-target")
        .iter()
        .map(|v| v.as_bytes())
        .collect();
    if let [one] = targets.as_slice() {
        ctx.aws_target = std::str::from_utf8(one).ok().map(str::to_string);
    }
    let credential_id = match policy.authorize(
        &binding.credentials,
        &route.name,
        &method,
        &vp.rest_path(),
        &targets,
    ) {
        Ok(id) => id.to_string(),
        Err(code) => return deny(&ctx, code),
    };

    // 7. The credential value, read from the store now.
    let secret = match app.broker.secret(&credential_id, &policy) {
        Ok(s) => s,
        Err(code) => return deny(&ctx, code),
    };
    let mut value = Vec::with_capacity(route.credential_scheme.len() + 1 + secret.expose().len());
    if !route.credential_scheme.is_empty() {
        value.extend_from_slice(route.credential_scheme.as_bytes());
        value.push(b' ');
    }
    value.extend_from_slice(secret.expose());
    let mut credential_value = match HeaderValue::from_bytes(&value) {
        Ok(v) => v,
        Err(_) => return deny(&ctx, Code::BrokerUnavailable),
    };
    credential_value.set_sensitive(true);
    drop(secret);

    // Body cap: a declared length over the cap is refused before anything goes out.
    let declared: Option<u64> = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    if declared.is_some_and(|n| n > app.max_body) {
        drain(body, DRAIN_LIMIT).await;
        return deny(&ctx, Code::BodyTooLarge);
    }
    let has_body =
        declared.is_some_and(|n| n > 0) || parts.headers.contains_key(header::TRANSFER_ENCODING);

    // 8. Strip every auth and hop-by-hop header, keep the rest (so
    //    `pass_headers` survive), set exactly one credential header.
    let mut h = parts.headers.clone();
    strip_request_headers(&mut h);
    let cred_name = HeaderName::from_bytes(route.credential_header.as_bytes()).unwrap();
    h.insert(cred_name, credential_value);
    if let Some(n) = declared {
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(n));
    }
    let query = parts
        .uri
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let url = format!("https://{}{}{}", route.authority(), vp.rest_path(), query);

    let over = Arc::new(AtomicBool::new(false));
    let mut rb = app.client.request(parts.method.clone(), url).headers(h);
    if has_body {
        rb = rb.body(reqwest::Body::wrap_stream(capped(
            body,
            app.max_body,
            over.clone(),
        )));
    }
    let up = match rb.send().await {
        Ok(r) => r,
        Err(_) => {
            // The error text embeds the URL: only the fixed code is used.
            let code = if over.load(Ordering::Relaxed) {
                Code::BodyTooLarge
            } else {
                Code::UpstreamUnavailable
            };
            return deny(&ctx, code);
        }
    };

    let status = up.status();
    app.audit.request(&AuditRec::allowed(
        &ctx.input(&method, t0),
        &rp,
        status.as_u16(),
    ));
    let mut r = Response::builder().status(status);
    for (k, v) in up.headers() {
        if !HOP_HEADERS.contains(&k.as_str()) || k == header::CONTENT_LENGTH {
            r = r.header(k, v);
        }
    }
    // Streamed chunk by chunk (SSE, AWS eventstream): nothing is buffered. An
    // upstream failure mid-stream closes the client stream without a synthetic
    // success, and adds one audit line.
    let (app2, ctx2, rp2, method2) = (app.clone(), ctx.clone(), rp.clone(), method.clone());
    let code = status.as_u16();
    let mut logged = false;
    let stream = up.bytes_stream().map(move |chunk| {
        if chunk.is_err() && !logged {
            logged = true;
            app2.audit.request(&AuditRec::failed(
                &ctx2.input(&method2, t0),
                &rp2,
                "upstream_reset",
                code,
            ));
        }
        chunk
    });
    r.body(Body::from_stream(stream)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_core::testing::sample_toml;
    use ap_core::Policy;

    fn route(name: &str) -> ap_core::config::RouteCfg {
        let p = Policy::parse(sample_toml().as_bytes()).unwrap();
        p.route(name).unwrap().clone()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn surrogate_extraction() {
        let bearer = route("kiro-krs");
        let key = route("anthropic");
        let s = format!("aps_{}", "ab".repeat(32));
        let h = headers(&[("authorization", &format!("Bearer {s}"))]);
        assert_eq!(presented_surrogate(&h, &bearer), Ok(s.as_str()));
        let h = headers(&[("authorization", &format!("bearer {s}"))]);
        assert_eq!(presented_surrogate(&h, &bearer), Ok(s.as_str()));
        assert_eq!(
            presented_surrogate(&headers(&[]), &bearer),
            Err(Code::SurrogateMissing)
        );
        let h = headers(&[("authorization", &s)]);
        assert_eq!(
            presented_surrogate(&h, &bearer),
            Err(Code::SurrogateMalformed)
        );
        let h = headers(&[("authorization", "Bearer")]);
        assert_eq!(
            presented_surrogate(&h, &bearer),
            Err(Code::SurrogateMalformed)
        );
        let h = headers(&[
            ("authorization", &format!("Bearer {s}")),
            ("authorization", &format!("Bearer {s}")),
        ]);
        assert_eq!(
            presented_surrogate(&h, &bearer),
            Err(Code::SurrogateAmbiguous)
        );
        let h = headers(&[("authorization", &format!("Bearer {s}, Bearer {s}"))]);
        assert_eq!(
            presented_surrogate(&h, &bearer),
            Err(Code::SurrogateAmbiguous)
        );
        // schemeless route
        let h = headers(&[("x-api-key", &s)]);
        assert_eq!(presented_surrogate(&h, &key), Ok(s.as_str()));
        let h = headers(&[("x-api-key", &format!("Bearer {s}"))]);
        assert_eq!(
            presented_surrogate(&h, &key).and_then(hash_surrogate),
            Err(Code::SurrogateMalformed)
        );
    }

    #[test]
    fn websocket_detection() {
        assert!(is_websocket_upgrade(&headers(&[("upgrade", "WebSocket")])));
        assert!(is_websocket_upgrade(&headers(&[(
            "upgrade",
            "h2c, websocket"
        )])));
        assert!(!is_websocket_upgrade(&headers(&[("upgrade", "h2c")])));
        assert!(!is_websocket_upgrade(&headers(&[])));
    }

    #[tokio::test]
    async fn cap_fails_the_stream_and_sets_the_flag() {
        let over = Arc::new(AtomicBool::new(false));
        let s = capped(Body::from(vec![0u8; 100]), 99, over.clone());
        let items: Vec<_> = s.collect().await;
        assert!(items.iter().any(|r| r.is_err()));
        assert!(over.load(Ordering::Relaxed));

        let over = Arc::new(AtomicBool::new(false));
        let s = capped(Body::from(vec![0u8; 100]), 100, over.clone());
        let items: Vec<_> = s.collect().await;
        assert!(items.iter().all(|r| r.is_ok()));
        assert!(!over.load(Ordering::Relaxed));
    }
}
