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
use ap_core::config::Route;
use ap_core::headers::{strip_request_headers, HOP_HEADERS};
use axum::body::Body;
use bytes::Bytes;
use futures_util::StreamExt;
use http::header::{CONTENT_LENGTH, HOST};
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

/// The production client, with the system trust roots.
pub fn client() -> reqwest::Result<Client> {
    client_builder().build()
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

/// Copy the upstream response headers for the agent. Hop-by-hop headers are dropped.
/// `Content-Length` is kept, because the body is streamed without re-framing.
pub fn response_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in upstream {
        let n = name.as_str();
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
