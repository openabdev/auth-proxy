//! auth-proxy session-plane client (Q1-B), Unix socket only.
//!
//! For the process that spawns agent sessions: the openab-pty runtime, or any
//! other session authority on Kubernetes. It talks HTTP/1.1 and JSON to the
//! proxy's session socket and never sees a credential: it generates a
//! surrogate, keeps it only to put it in the child's environment, and sends
//! the proxy `sha256(surrogate)`.
//!
//! Two layers:
//!
//! - [`Client`]: one function per session-plane call, plus [`Client::raw`].
//! - [`Authority`]: owns the authority token and the live-session list, renews
//!   every 30 s, and resyncs when the proxy forgot its sessions.
//!
//! The HTTP exchange is hand-written (one request per connection,
//! `Connection: close`), so the dependency set stays at tokio, serde, sha2,
//! hex and getrandom. The HTTPS session plane and `ap-relay` belong to the
//! deferred ECS rollout and are not here.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// How often an authority renews itself and its sessions.
pub const RENEW_EVERY: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

// ---------------------------------------------------------------- errors

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// Connect, read or write failed (or timed out). Carries the error kind only.
    Io(String),
    /// The answer was not the HTTP/JSON the session plane speaks, or an
    /// argument could not be sent safely.
    Protocol(String),
    /// The proxy answered with an error status.
    Api {
        status: u16,
        code: String,
        message: String,
    },
}

impl ClientError {
    pub fn status(&self) -> Option<u16> {
        match self {
            ClientError::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The error code of an API error (`authority_active`, `unauthorized`, ...).
    pub fn code(&self) -> Option<&str> {
        match self {
            ClientError::Api { code, .. } => Some(code),
            _ => None,
        }
    }

    /// 401: the token is wrong or the authority lease lapsed.
    pub fn is_unauthorized(&self) -> bool {
        self.status() == Some(401)
    }

    /// 409 `authority_active`: another authority's lease is live.
    pub fn is_authority_active(&self) -> bool {
        self.code() == Some("authority_active")
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Io(k) => write!(f, "session plane i/o error: {k}"),
            ClientError::Protocol(m) => write!(f, "session plane protocol error: {m}"),
            ClientError::Api {
                status,
                code,
                message,
            } => write!(f, "session plane answered {status} {code}: {message}"),
        }
    }
}

impl std::error::Error for ClientError {}

// ---------------------------------------------------------------- surrogate

/// A freshly generated surrogate: `aps_` + 64 lowercase hex. Put it in the
/// child's environment and drop it. `Debug` is redacted.
pub struct Surrogate(String);

impl Surrogate {
    pub fn generate() -> Result<Surrogate, ClientError> {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw)
            .map_err(|_| ClientError::Protocol("no randomness available".into()))?;
        Ok(Surrogate(format!("aps_{}", hex::encode(raw))))
    }

    /// The value for the child's environment variable.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// What the proxy stores: sha256 of the whole string, `aps_` included.
    pub fn sha256_hex(&self) -> String {
        hex::encode(Sha256::digest(self.0.as_bytes()))
    }
}

impl fmt::Debug for Surrogate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Surrogate(<redacted>)")
    }
}

// ---------------------------------------------------------------- wire types

/// One live session, as named in `renew` and `revoke`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionRef {
    pub session: String,
    pub generation: u64,
}

/// `POST /v1/sessions` body, and one entry of a `PUT /v1/sessions` list.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub session: String,
    pub generation: u64,
    pub surrogate_sha256: String,
    pub credentials: Vec<String>,
}

impl Registration {
    pub fn new(
        session: &str,
        generation: u64,
        surrogate: &Surrogate,
        credentials: &[&str],
    ) -> Registration {
        Registration {
            session: session.into(),
            generation,
            surrogate_sha256: surrogate.sha256_hex(),
            credentials: credentials.iter().map(|c| c.to_string()).collect(),
        }
    }

    pub fn session_ref(&self) -> SessionRef {
        SessionRef {
            session: self.session.clone(),
            generation: self.generation,
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LeaseReply {
    pub lease_secs: u64,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RenewReply {
    pub lease_secs: u64,
    #[serde(default)]
    pub unknown: Vec<SessionRef>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ResyncReply {
    pub registered: usize,
    pub dropped: usize,
}

/// An HTTP answer, before status handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

// ---------------------------------------------------------------- backoff

#[derive(Clone, Copy, Debug)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
    /// Give up after this long. `None` retries forever.
    pub deadline: Option<Duration>,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(15),
            deadline: None,
        }
    }
}

impl Backoff {
    fn next(&self, cur: Duration) -> Duration {
        (cur * 2).min(self.max)
    }
}

// ---------------------------------------------------------------- client

/// One function per session-plane call. Cheap to clone; clones share the token.
#[derive(Clone)]
pub struct Client {
    socket: PathBuf,
    token: Arc<Mutex<Option<String>>>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("socket", &self.socket)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl Client {
    pub fn new(socket: impl Into<PathBuf>) -> Client {
        Client {
            socket: socket.into(),
            token: Arc::new(Mutex::new(None)),
        }
    }

    /// The authority token from the last successful `hello` (or `set_token`).
    pub fn token(&self) -> Option<String> {
        self.token.lock().unwrap().clone()
    }

    pub fn set_token(&self, token: Option<String>) {
        *self.token.lock().unwrap() = token;
    }

    /// A client for the same socket with its own token slot.
    pub fn fresh(&self) -> Client {
        Client::new(self.socket.clone())
    }

    /// `POST /v1/hello`. Stores the token. Returns the authority lease length.
    pub async fn hello(&self) -> Result<u64, ClientError> {
        #[derive(Deserialize)]
        struct Hello {
            authority_token: String,
            lease_secs: u64,
        }
        let r = self.call("POST", "/v1/hello", false, Some(b"{}")).await?;
        let h: Hello = parse_json(&r)?;
        self.set_token(Some(h.authority_token));
        Ok(h.lease_secs)
    }

    /// `hello`, retried with backoff while another authority's lease is live
    /// (409) or the socket is not there yet. Any other answer ends the loop.
    pub async fn hello_retry(&self, backoff: Backoff) -> Result<u64, ClientError> {
        let start = Instant::now();
        let mut delay = backoff.initial;
        loop {
            match self.hello().await {
                Ok(l) => return Ok(l),
                Err(e) if e.is_authority_active() || matches!(e, ClientError::Io(_)) => {
                    if backoff
                        .deadline
                        .is_some_and(|d| start.elapsed() + delay > d)
                    {
                        return Err(e);
                    }
                    tokio::time::sleep(delay).await;
                    delay = backoff.next(delay);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// `POST /v1/sessions`. Returns the session lease length.
    pub async fn register(&self, reg: &Registration) -> Result<u64, ClientError> {
        let body = to_json(reg)?;
        let r = self.call("POST", "/v1/sessions", true, Some(&body)).await?;
        Ok(parse_json::<LeaseReply>(&r)?.lease_secs)
    }

    /// `POST /v1/renew`: renews the authority and the listed sessions.
    pub async fn renew(&self, sessions: &[SessionRef]) -> Result<RenewReply, ClientError> {
        let body = to_json(&serde_json::json!({ "sessions": sessions }))?;
        let r = self.call("POST", "/v1/renew", true, Some(&body)).await?;
        parse_json(&r)
    }

    /// `DELETE /v1/sessions/{session}/{generation}`. Also succeeds when the
    /// proxy does not know the session.
    pub async fn revoke(&self, session: &str, generation: u64) -> Result<(), ClientError> {
        if !path_safe(session) {
            return Err(ClientError::Protocol(
                "session must be [A-Za-z0-9._:-]{1,128}".into(),
            ));
        }
        let path = format!("/v1/sessions/{session}/{generation}");
        self.call("DELETE", &path, true, None).await.map(|_| ())
    }

    /// `PUT /v1/sessions`: the list is the whole truth; sessions not in it are
    /// revoked.
    pub async fn resync(&self, regs: &[Registration]) -> Result<ResyncReply, ClientError> {
        let body = to_json(&serde_json::json!({ "sessions": regs }))?;
        let r = self.call("PUT", "/v1/sessions", true, Some(&body)).await?;
        parse_json(&r)
    }

    /// Success statuses only; an error status becomes `ClientError::Api`.
    async fn call(
        &self,
        method: &str,
        path: &str,
        auth: bool,
        body: Option<&[u8]>,
    ) -> Result<RawResponse, ClientError> {
        let token = if auth {
            Some(self.token().ok_or_else(|| {
                ClientError::Protocol("no authority token: call hello first".into())
            })?)
        } else {
            None
        };
        let r = self.raw(method, path, token.as_deref(), body).await?;
        if (200..300).contains(&r.status) {
            Ok(r)
        } else {
            Err(api_error(&r))
        }
    }

    /// One request, any status. For callers that need the exact answer, and
    /// for tests that send malformed bodies on purpose.
    pub async fn raw(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<RawResponse, ClientError> {
        let head_ok = |s: &str| !s.bytes().any(|b| b <= 0x20 || b == 0x7f);
        if !head_ok(method) || !head_ok(path) || bearer.is_some_and(|t| !head_ok(t)) {
            return Err(ClientError::Protocol(
                "method, path and token must not contain whitespace or control characters".into(),
            ));
        }
        let mut head =
            format!("{method} {path} HTTP/1.1\r\nHost: auth-proxy\r\nConnection: close\r\n");
        if let Some(t) = bearer {
            head.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        if let Some(b) = body {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        head.push_str("\r\n");
        let socket = self.socket.clone();
        let exchange = async move {
            let mut s = UnixStream::connect(&socket)
                .await
                .map_err(|e| ClientError::Io(format!("{:?}", e.kind())))?;
            let mut sent = s.write_all(head.as_bytes()).await;
            if sent.is_ok() {
                if let Some(b) = body {
                    sent = s.write_all(b).await;
                }
            }
            // A proxy that refuses a request early (413) may close before it
            // has read the whole body: the answer is still on the socket.
            if let Err(e) = sent {
                if !matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) {
                    return Err(ClientError::Io(format!("{:?}", e.kind())));
                }
            }
            let mut out = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = match s.read(&mut buf).await {
                    Ok(n) => n,
                    // The proxy may reset after a refusal it sent already.
                    Err(e)
                        if !out.is_empty() && e.kind() == std::io::ErrorKind::ConnectionReset =>
                    {
                        0
                    }
                    Err(e) => return Err(ClientError::Io(format!("{:?}", e.kind()))),
                };
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
                if out.len() > MAX_RESPONSE_BYTES {
                    return Err(ClientError::Protocol("response too large".into()));
                }
            }
            parse_response(&out)
        };
        match tokio::time::timeout(IO_TIMEOUT, exchange).await {
            Ok(r) => r,
            Err(_) => Err(ClientError::Io("TimedOut".into())),
        }
    }
}

fn path_safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn to_json<T: Serialize>(v: &T) -> Result<Vec<u8>, ClientError> {
    serde_json::to_vec(v).map_err(|_| ClientError::Protocol("cannot encode request".into()))
}

fn parse_json<T: for<'de> Deserialize<'de>>(r: &RawResponse) -> Result<T, ClientError> {
    serde_json::from_slice(&r.body)
        .map_err(|_| ClientError::Protocol("answer is not the expected JSON".into()))
}

fn api_error(r: &RawResponse) -> ClientError {
    #[derive(Deserialize, Default)]
    struct E {
        #[serde(default)]
        error: String,
        #[serde(default)]
        message: String,
    }
    let e: E = serde_json::from_slice(&r.body).unwrap_or_default();
    ClientError::Api {
        status: r.status,
        code: e.error,
        message: e.message,
    }
}

/// Parse a complete HTTP/1.1 answer (read to EOF).
pub fn parse_response(raw: &[u8]) -> Result<RawResponse, ClientError> {
    let bad = |m: &str| ClientError::Protocol(m.into());
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad("no end of headers"))?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| bad("headers not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| bad("empty answer"))?;
    let mut parts = status_line.splitn(3, ' ');
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(bad("not an HTTP/1.x answer"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad("bad status line"))?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            if k == "content-length" {
                content_length = Some(v.parse().map_err(|_| bad("bad content-length"))?);
            } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    let rest = &raw[split + 4..];
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(n) = content_length {
        if rest.len() < n {
            return Err(bad("body shorter than content-length"));
        }
        rest[..n].to_vec()
    } else {
        rest.to_vec()
    };
    Ok(RawResponse { status, body })
}

fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, ClientError> {
    let bad = || ClientError::Protocol("bad chunked body".into());
    let mut out = Vec::new();
    loop {
        let eol = rest.windows(2).position(|w| w == b"\r\n").ok_or_else(bad)?;
        let size_txt = std::str::from_utf8(&rest[..eol]).map_err(|_| bad())?;
        let size_txt = size_txt.split(';').next().unwrap_or("").trim();
        let n = usize::from_str_radix(size_txt, 16).map_err(|_| bad())?;
        rest = &rest[eol + 2..];
        if n == 0 {
            return Ok(out);
        }
        if rest.len() < n + 2 {
            return Err(bad());
        }
        out.extend_from_slice(&rest[..n]);
        rest = &rest[n + 2..];
    }
}

// ---------------------------------------------------------------- authority

#[derive(Clone, Copy, Debug)]
pub struct AuthorityConfig {
    pub renew_every: Duration,
    pub backoff: Backoff,
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        AuthorityConfig {
            renew_every: RENEW_EVERY,
            backoff: Backoff::default(),
        }
    }
}

/// What one renew pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewOutcome {
    /// Every live session was known to the proxy.
    Renewed,
    /// The proxy had forgotten sessions (it restarted): the full list was re-sent.
    Resynced,
    /// The authority lease had lapsed: a new `hello` won, then the full list was re-sent.
    Reacquired,
}

/// The session authority's side of Q1-B. Holds the authority token and the
/// registrations of the live sessions (hashes and credential ids, never the
/// surrogates, which only the spawned children hold).
pub struct Authority {
    client: Client,
    cfg: AuthorityConfig,
    live: Mutex<HashMap<SessionRef, Registration>>,
}

impl Authority {
    /// Send `hello` before binding listeners or spawning anything, retrying
    /// with backoff while a previous authority's 90 s lock is live.
    pub async fn connect(
        socket: impl Into<PathBuf>,
        cfg: AuthorityConfig,
    ) -> Result<Authority, ClientError> {
        let client = Client::new(socket);
        client.hello_retry(cfg.backoff).await?;
        Ok(Authority {
            client,
            cfg,
            live: Mutex::new(HashMap::new()),
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Generate a surrogate, register its hash, and return the surrogate for
    /// the child's environment. The session is only tracked when the proxy
    /// accepted it.
    pub async fn register(
        &self,
        session: &str,
        generation: u64,
        credentials: &[&str],
    ) -> Result<Surrogate, ClientError> {
        let s = Surrogate::generate()?;
        let reg = Registration::new(session, generation, &s, credentials);
        self.client.register(&reg).await?;
        self.live.lock().unwrap().insert(reg.session_ref(), reg);
        Ok(s)
    }

    /// End a session. It stops being tracked first, so a resync can never
    /// bring it back; an error from the proxy is still returned.
    pub async fn revoke(&self, session: &str, generation: u64) -> Result<(), ClientError> {
        self.live.lock().unwrap().remove(&SessionRef {
            session: session.into(),
            generation,
        });
        self.client.revoke(session, generation).await
    }

    pub fn live_sessions(&self) -> Vec<SessionRef> {
        let mut v: Vec<_> = self.live.lock().unwrap().keys().cloned().collect();
        v.sort_by(|a, b| (&a.session, a.generation).cmp(&(&b.session, b.generation)));
        v
    }

    async fn resync(&self) -> Result<ResyncReply, ClientError> {
        let regs: Vec<Registration> = self.live.lock().unwrap().values().cloned().collect();
        self.client.resync(&regs).await
    }

    /// One renew pass: renew everything; if the proxy lists sessions as
    /// unknown, resend the full list; if the token was refused, win `hello`
    /// again and resend the full list.
    pub async fn renew_once(&self) -> Result<RenewOutcome, ClientError> {
        let refs = self.live_sessions();
        match self.client.renew(&refs).await {
            Ok(r) if r.unknown.is_empty() => Ok(RenewOutcome::Renewed),
            Ok(_) => {
                self.resync().await?;
                Ok(RenewOutcome::Resynced)
            }
            Err(e) if e.is_unauthorized() => {
                self.client.hello_retry(self.cfg.backoff).await?;
                self.resync().await?;
                Ok(RenewOutcome::Reacquired)
            }
            Err(e) => Err(e),
        }
    }

    /// Renew every `renew_every` for as long as the task lives. After an error
    /// it retries with backoff. It never tears sessions down: the proxy's
    /// leases are what end them. Abort the task to stop renewing.
    pub async fn run_renew_loop(self: Arc<Self>) {
        let mut retry = None::<Duration>;
        loop {
            tokio::time::sleep(retry.unwrap_or(self.cfg.renew_every)).await;
            retry = match self.renew_once().await {
                Ok(_) => None,
                Err(_) => Some(match retry {
                    None => self.cfg.backoff.initial,
                    Some(d) => self.cfg.backoff.next(d),
                }),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surrogate_has_the_proxy_format_and_hash() {
        let s = Surrogate::generate().unwrap();
        assert!(ap_core::surrogate::is_surrogate(s.expose()), "{s:?}");
        assert_eq!(
            s.sha256_hex(),
            hex::encode(ap_core::surrogate::hash_surrogate(s.expose()).unwrap())
        );
        assert_ne!(s.expose(), Surrogate::generate().unwrap().expose());
        assert_eq!(format!("{s:?}"), "Surrogate(<redacted>)");
    }

    #[test]
    fn registration_carries_only_the_hash() {
        let s = Surrogate::generate().unwrap();
        let reg = Registration::new("sess-1", 2, &s, &["kiro", "anthropic"]);
        let json = serde_json::to_string(&reg).unwrap();
        assert!(!json.contains(s.expose()));
        assert!(json.contains(&s.sha256_hex()));
        assert_eq!(reg.session_ref().generation, 2);
    }

    #[test]
    fn parses_content_length_chunked_and_eof_bodies() {
        let r =
            parse_response(b"HTTP/1.1 201 Created\r\ncontent-length: 2\r\n\r\n{}extra").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (201, &b"{}"[..]));
        let r = parse_response(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.body, b"abcde");
        let r = parse_response(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!((r.status, r.body.len()), (204, 0));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\nab").is_err());
        assert!(parse_response(b"garbage").is_err());
        assert!(parse_response(b"SMTP 200 x\r\n\r\n").is_err());
    }

    #[test]
    fn api_errors_carry_code_and_status() {
        let e = api_error(&RawResponse {
            status: 409,
            body: br#"{"error":"authority_active","message":"another authority's lease is live"}"#
                .to_vec(),
        });
        assert!(e.is_authority_active());
        assert_eq!(e.status(), Some(409));
        let e = api_error(&RawResponse {
            status: 401,
            body: b"not json".to_vec(),
        });
        assert!(e.is_unauthorized());
    }

    #[tokio::test]
    async fn refuses_header_injection_and_missing_token() {
        let c = Client::new("/nonexistent/s.sock");
        let e = c.raw("POST", "/v1/hello", Some("a\r\nX: y"), None).await;
        assert!(matches!(e, Err(ClientError::Protocol(_))));
        let e = c.raw("POST", "/v1/hello HTTP/1.1", None, None).await;
        assert!(matches!(e, Err(ClientError::Protocol(_))));
        let e = c.renew(&[]).await.unwrap_err();
        assert!(matches!(e, ClientError::Protocol(_)), "{e}");
        let e = c.revoke("bad session", 1).await.unwrap_err();
        assert!(matches!(e, ClientError::Protocol(_)), "{e}");
        // No socket: an I/O error, which hello_retry treats as "not up yet".
        let e = c.hello().await.unwrap_err();
        assert!(matches!(e, ClientError::Io(_)), "{e}");
    }

    #[tokio::test]
    async fn hello_retry_honors_its_deadline() {
        let c = Client::new("/nonexistent/s.sock");
        let t0 = Instant::now();
        let e = c
            .hello_retry(Backoff {
                initial: Duration::from_millis(20),
                max: Duration::from_millis(40),
                deadline: Some(Duration::from_millis(150)),
            })
            .await
            .unwrap_err();
        assert!(matches!(e, ClientError::Io(_)));
        assert!(t0.elapsed() < Duration::from_secs(2));
    }
}
