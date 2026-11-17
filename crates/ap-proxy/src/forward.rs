//! Upstream forwarder: the rustls client, the outbound header rewrite, the capped request body
//! and the response header filter.
//!
//! The client follows no redirects, so a 3xx goes back to the agent unchanged. It sets
//! `TCP_NODELAY`. The route host is the only target, and TLS SNI comes from that host.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ap_broker::store::SecretBytes;
use ap_core::config::{Passthrough, Route};
use ap_core::headers::{strip_request_headers, AUTH_HEADERS, HOP_HEADERS};
use axum::body::Body;
use bytes::Bytes;
use futures_util::StreamExt;
use http::header::{AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use reqwest::redirect::Policy;
use reqwest::{Client, ClientBuilder};

/// Builder with the production client settings. Tests extend it with extra roots or a
/// `resolve` override. Nothing else changes between production and tests.
pub fn client_builder() -> ClientBuilder {
    Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .redirect(Policy::none())
        .tcp_nodelay(true)
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(60))
}

/// The production client, with the system trust roots. A `matrix-upstream` test build also applies
/// the test overrides in `matrix_hooks`.
pub fn client() -> Result<Client, String> {
    #[cfg(feature = "matrix-upstream")]
    let builder = crate::matrix_hooks::apply(client_builder())?;
    #[cfg(not(feature = "matrix-upstream"))]
    let builder = client_builder();
    builder.build().map_err(|e| e.to_string())
}

/// Builder for the client that sends approved (held) requests. It speaks HTTP/1.1 only and keeps
/// no idle connections, so every approved request opens its own connection and the first poll of
/// its body stream happens before any request byte is flushed (design 3.4 step 8).
pub fn held_client_builder() -> ClientBuilder {
    client_builder().http1_only().pool_max_idle_per_host(0)
}

/// The client for approved requests, with the same test overrides as [`client`].
pub fn held_client() -> Result<Client, String> {
    #[cfg(feature = "matrix-upstream")]
    let builder = crate::matrix_hooks::apply(held_client_builder())?;
    #[cfg(not(feature = "matrix-upstream"))]
    let builder = held_client_builder();
    builder.build().map_err(|e| e.to_string())
}

/// The upstream URL for a route. `path_and_query` is the route-relative path with its query.
pub fn upstream_url(route: &Route, path_and_query: &str) -> String {
    format!("https://{}:{}{}", route.host, route.port, path_and_query)
}

/// The outbound headers could not be built: the credential is empty or not a valid header value,
/// or the route's credential header name is invalid. Nothing is sent in this case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderBuildError;

/// Build the outbound request headers.
///
/// Every client auth header, hop-by-hop header and `Host` is removed. `pass_headers` survive.
/// The agent's `Content-Length`, if any, is put back, so the upstream request keeps the declared
/// framing. Then exactly one credential header is set, as `Bearer <secret>`. Trailing whitespace
/// in the secret file (a final newline, for example) is removed. An empty or unusable value is
/// an error, so nothing is sent without a credential.
pub fn outbound_headers(
    inbound: &HeaderMap,
    route: &Route,
    secret: &SecretBytes,
) -> Result<HeaderMap, HeaderBuildError> {
    let mut h = inbound.clone();
    strip_request_headers(&mut h, &route.pass_headers);
    h.remove(HOST);
    if let Some(len) = inbound.get(CONTENT_LENGTH) {
        h.insert(CONTENT_LENGTH, len.clone());
    }
    let name =
        HeaderName::from_bytes(route.credential_header.as_bytes()).map_err(|_| HeaderBuildError)?;
    h.insert(name, credential_value(secret.expose())?);
    Ok(h)
}

fn credential_value(secret: &[u8]) -> Result<HeaderValue, HeaderBuildError> {
    let end = secret
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |i| i + 1);
    let token = &secret[..end];
    if token.is_empty() {
        return Err(HeaderBuildError);
    }
    let mut value = Vec::with_capacity(token.len() + 7);
    value.extend_from_slice(b"Bearer ");
    value.extend_from_slice(token);
    let mut hv = HeaderValue::from_bytes(&value).map_err(|_| HeaderBuildError)?;
    hv.set_sensitive(true);
    Ok(hv)
}

/// The `Content-Length` the agent declared, if it sent one and it parses.
pub fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
}

/// Wrap the agent's request body as an upstream body. Bytes are counted as they stream. Above
/// `max` the stream fails and `overflow` is set, so the caller can answer 413 instead of 502.
pub fn capped_body(body: Body, max: u64, overflow: Arc<AtomicBool>) -> reqwest::Body {
    let mut seen: u64 = 0;
    let stream = body
        .into_data_stream()
        .map(move |chunk| -> Result<Bytes, io::Error> {
            let chunk = chunk.map_err(io::Error::other)?;
            seen = seen.saturating_add(chunk.len() as u64);
            if seen > max {
                overflow.store(true, Ordering::SeqCst);
                return Err(io::Error::other(
                    "request body exceeds the configured limit",
                ));
            }
            Ok(chunk)
        });
    reqwest::Body::wrap_stream(stream)
}

/// Whether `name` matches a front-header pattern: exact, or a prefix when the pattern ends in `*`.
fn matches_pattern(name: &str, pattern: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == pattern,
    }
}

/// Build the outbound headers for a passthrough route (design 3.1, ordered algorithm).
///
/// Removed: the caller-key header, every `x-ap-*` header, hop-by-hop headers, every header named
/// by `Connection`, `Expect`, `Host`, the configured front headers, and every `AUTH_HEADERS`
/// member except `authorization` and the route's `keep_auth_headers`. Everything else is kept,
/// repeated values included. A declared `Content-Length` is put back, so the upstream request
/// keeps the declared framing. `Authorization` is marked sensitive and otherwise unchanged.
pub fn passthrough_headers(inbound: &HeaderMap, route: &Route, pt: &Passthrough) -> HeaderMap {
    let nominated: Vec<String> = inbound
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    let mut out = HeaderMap::new();
    for (name, value) in inbound {
        let n = name.as_str();
        let drop = n == pt.caller_key_header
            || n.starts_with("x-ap-")
            || n == "expect"
            || HOP_HEADERS.contains(&n)
            || nominated.iter().any(|c| c == n)
            || pt.front_strip_headers.iter().any(|p| matches_pattern(n, p))
            || (AUTH_HEADERS.contains(&n)
                && n != AUTHORIZATION.as_str()
                && !route.keep_auth_headers.iter().any(|k| k == n));
        if drop {
            continue;
        }
        let mut v = value.clone();
        if n == AUTHORIZATION.as_str() {
            v.set_sensitive(true);
        }
        out.append(name.clone(), v);
    }
    if let Some(len) = inbound.get(CONTENT_LENGTH) {
        out.insert(CONTENT_LENGTH, len.clone());
    }
    out
}

/// Shared flags a [`guarded_body`] sets while the upstream client reads it.
#[derive(Clone, Default)]
pub struct BodyFlags {
    /// At least one body chunk was handed to the upstream request.
    pub sent_any: Arc<AtomicBool>,
    /// The body went over the cap.
    pub overflow: Arc<AtomicBool>,
    /// The client stalled longer than the per-chunk limit.
    pub stalled: Arc<AtomicBool>,
}

/// Wrap the inbound request body for an allowed passthrough request.
///
/// Bytes are counted against `max`, each chunk must arrive within `stall`, and the flags record
/// what happened. Chunks are forwarded as they come, with no buffering.
pub fn guarded_body(body: Body, max: u64, stall: Duration, flags: BodyFlags) -> reqwest::Body {
    let stream = futures_util::stream::unfold(
        (Box::pin(body.into_data_stream()), 0u64, flags, false),
        move |(mut s, seen, flags, failed)| async move {
            if failed {
                return None;
            }
            let next = match tokio::time::timeout(stall, s.next()).await {
                Ok(n) => n,
                Err(_) => {
                    flags.stalled.store(true, Ordering::SeqCst);
                    let e = io::Error::new(io::ErrorKind::TimedOut, "request body stalled");
                    return Some((Err(e), (s, seen, flags, true)));
                }
            };
            match next {
                None => None,
                Some(Err(e)) => Some((Err(io::Error::other(e)), (s, seen, flags, true))),
                Some(Ok(chunk)) => {
                    let seen = seen.saturating_add(chunk.len() as u64);
                    if seen > max {
                        flags.overflow.store(true, Ordering::SeqCst);
                        let e = io::Error::other("request body exceeds the configured limit");
                        return Some((Err(e), (s, seen, flags, true)));
                    }
                    if !chunk.is_empty() {
                        flags.sent_any.store(true, Ordering::SeqCst);
                    }
                    Some((Ok::<Bytes, io::Error>(chunk), (s, seen, flags, false)))
                }
            }
        },
    );
    reqwest::Body::wrap_stream(stream)
}

/// Why [`buffer_body`] gave up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferError {
    /// More than `max` bytes arrived.
    Overflow,
    /// A chunk took longer than the stall limit.
    Stalled,
    /// The caller's connection failed while the body was being read.
    Read,
}

/// Read a whole request body into memory. Bytes are counted against `max`, and each chunk must
/// arrive within `stall`. Used for held requests, which are kept in memory until a human decides.
pub async fn buffer_body(body: Body, max: u64, stall: Duration) -> Result<Bytes, BufferError> {
    let mut stream = Box::pin(body.into_data_stream());
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match tokio::time::timeout(stall, stream.next()).await {
            Err(_) => return Err(BufferError::Stalled),
            Ok(None) => return Ok(Bytes::from(buf)),
            Ok(Some(Err(_))) => return Err(BufferError::Read),
            Ok(Some(Ok(chunk))) => {
                if (buf.len() as u64).saturating_add(chunk.len() as u64) > max {
                    return Err(BufferError::Overflow);
                }
                buf.extend_from_slice(&chunk);
            }
        }
    }
}

/// Read and discard up to `max` bytes of `body`, for at most `total`, so a client still writing a
/// large body can read the refusal instead of seeing a reset (design 3.4 step 1). Errors and the
/// time limit end the drain quietly.
pub async fn drain_body(body: Body, max: u64, total: Duration) {
    let drain = async {
        let mut stream = Box::pin(body.into_data_stream());
        let mut seen: u64 = 0;
        while let Some(Ok(chunk)) = stream.next().await {
            seen = seen.saturating_add(chunk.len() as u64);
            if seen >= max {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(total, drain).await;
}

/// Response-only hop-by-hop fields, in addition to `HOP_HEADERS`.
const RESPONSE_HOP_HEADERS: &[&str] = &["proxy-authenticate"];

/// Copy the upstream response headers for the agent. Hop-by-hop headers and every field named by an
/// upstream `Connection` header are dropped. `Content-Length` is kept, because the body is streamed
/// without re-framing.
pub fn response_headers(upstream: &HeaderMap) -> HeaderMap {
    let nominated: Vec<String> = upstream
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    let mut out = HeaderMap::new();
    for (name, value) in upstream {
        let n = name.as_str();
        if nominated.iter().any(|t| t == n) || RESPONSE_HOP_HEADERS.contains(&n) {
            continue;
        }
        if n == CONTENT_LENGTH.as_str() || !HOP_HEADERS.contains(&n) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// Send one upstream request.
pub async fn send(
    client: &Client,
    method: Method,
    url: &str,
    headers: HeaderMap,
    body: reqwest::Body,
) -> reqwest::Result<reqwest::Response> {
    client
        .request(method, url)
        .headers(headers)
        .body(body)
        .send()
        .await
}

#[cfg(test)]
mod passthrough_tests {
    use super::*;
    use ap_core::config::{load, Config};
    use http::HeaderValue;

    fn cfg(extra_route: &str) -> Config {
        load(&format!(
            r#"version = 1
[listen]
proxy = "127.0.0.1:8443"
[passthrough]
public_authority = "gate.example.test"
[[identity]]
name = "m"
caller_key_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
[[route]]
name = "discord"
host = "discord.com"
mode = "passthrough"
{extra_route}
[[grant]]
identity = "m"
route = "discord"
methods = ["GET"]
paths = ["/"]
"#
        ))
        .expect("valid")
    }

    fn build(c: &Config, pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        passthrough_headers(&h, &c.routes[0], c.passthrough.as_ref().unwrap())
    }

    #[test]
    fn keeps_authorization_and_ordinary_headers_and_repeats() {
        let c = cfg("");
        let out = build(
            &c,
            &[
                ("authorization", "Bot abc"),
                ("content-type", "application/json"),
                ("x-custom", "1"),
                ("x-custom", "2"),
                ("user-agent", "DiscordBot"),
            ],
        );
        assert_eq!(out.get("authorization").unwrap(), "Bot abc");
        assert!(out.get("authorization").unwrap().is_sensitive());
        assert_eq!(out.get("content-type").unwrap(), "application/json");
        assert_eq!(out.get_all("x-custom").iter().count(), 2);
        assert_eq!(out.get("user-agent").unwrap(), "DiscordBot");
    }

    #[test]
    fn strips_caller_key_front_hop_and_credential_headers() {
        let c = cfg("");
        let out = build(
            &c,
            &[
                ("authorization", "Bot abc"),
                ("x-ap-caller-key", "apk_x"),
                ("x-ap-foo", "1"),
                ("forwarded", "for=1"),
                ("x-forwarded-for", "1"),
                ("x-real-ip", "1"),
                ("via", "1"),
                ("cf-ray", "1"),
                ("tailscale-user-login", "someone"),
                ("cookie", "a=b"),
                ("proxy-authorization", "x"),
                ("x-api-key", "k"),
                ("expect", "100-continue"),
                ("host", "gate.example.test"),
                ("connection", "x-private, keep-alive"),
                ("x-private", "1"),
                ("keep-alive", "5"),
                ("te", "trailers"),
                ("upgrade", "websocket"),
            ],
        );
        let names: Vec<&str> = out.keys().map(|k| k.as_str()).collect();
        assert_eq!(names, vec!["authorization"], "left: {names:?}");
    }

    #[test]
    fn keep_auth_headers_keeps_a_named_member_only() {
        let c = cfg("keep_auth_headers = [\"x-api-key\"]");
        let out = build(&c, &[("x-api-key", "k"), ("cookie", "a=b")]);
        assert_eq!(out.get("x-api-key").unwrap(), "k");
        assert!(out.get("cookie").is_none());
    }

    #[test]
    fn response_drops_hop_headers_and_connection_nominations() {
        let mut up = HeaderMap::new();
        for (k, v) in [
            ("connection", "X-Hop, keep-alive"),
            ("connection", " x-other "),
            ("x-hop", "value"),
            ("x-other", "value"),
            ("x-kept", "ok"),
            ("proxy-authenticate", "Basic"),
            ("content-length", "5"),
        ] {
            up.append(
                HeaderName::from_static(k),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        let out = response_headers(&up);
        let mut names: Vec<&str> = out.keys().map(|k| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["content-length", "x-kept"]);
    }

    #[test]
    fn declared_content_length_is_put_back() {
        let c = cfg("");
        let out = build(&c, &[("content-length", "12")]);
        assert_eq!(out.get("content-length").unwrap(), "12");
        let out = build(&c, &[("transfer-encoding", "chunked")]);
        assert!(out.get("content-length").is_none());
        assert!(out.get("transfer-encoding").is_none());
    }

    async fn drain(b: reqwest::Body) -> Vec<Result<Bytes, String>> {
        let mut out = Vec::new();
        let mut s = http_body_util::BodyDataStream::new(b);
        while let Some(c) = s.next().await {
            out.push(c.map_err(|e| e.to_string()));
        }
        out
    }

    fn flags() -> BodyFlags {
        BodyFlags::default()
    }

    #[tokio::test]
    async fn stall_after_a_prefix_sets_sent_any_and_stalled() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(2);
        tx.send(Ok(Bytes::from_static(b"abc"))).await.unwrap();
        let f = flags();
        let body = guarded_body(
            Body::from_stream(tokio_stream_from(rx)),
            100,
            Duration::from_millis(50),
            f.clone(),
        );
        let got = drain(body).await;
        assert!(got[0].is_ok());
        assert!(got[1].is_err());
        assert!(f.sent_any.load(Ordering::SeqCst));
        assert!(f.stalled.load(Ordering::SeqCst));
        drop(tx);
    }

    #[tokio::test]
    async fn stall_before_any_chunk_leaves_sent_any_false() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(2);
        let f = flags();
        let body = guarded_body(
            Body::from_stream(tokio_stream_from(rx)),
            100,
            Duration::from_millis(50),
            f.clone(),
        );
        let got = drain(body).await;
        assert!(got[0].is_err());
        assert!(!f.sent_any.load(Ordering::SeqCst));
        assert!(f.stalled.load(Ordering::SeqCst));
        drop(tx);
    }

    #[tokio::test]
    async fn over_cap_sets_overflow() {
        let f = flags();
        let body = guarded_body(
            Body::from(vec![0u8; 10]),
            5,
            Duration::from_secs(5),
            f.clone(),
        );
        let got = drain(body).await;
        assert!(got[0].is_err());
        assert!(f.overflow.load(Ordering::SeqCst));
        assert!(!f.sent_any.load(Ordering::SeqCst));
    }

    fn tokio_stream_from(
        mut rx: tokio::sync::mpsc::Receiver<Result<Bytes, io::Error>>,
    ) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> {
        futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
    }
}
