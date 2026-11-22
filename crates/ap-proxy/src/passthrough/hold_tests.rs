//! The hold path end to end (design stage 2 acceptance 1 to 6, 8, 13 to 18, 20, 23 to 25 and 29),
//! against a mock TLS upstream that records what it receives.

use std::convert::Infallible;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use bytes::Bytes;
use futures_util::StreamExt;
use http::Request;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use super::pause::Gate;
use super::*;
use crate::approval::PolicySource;
use crate::hold::{ApproveResult, DenyResult, Limits, State};
use crate::notify::{MockNotifier, TEXT};
use crate::test_support::{
    buffer_sink, caller_key, client_for, tls_server_config, Scratch, Upstream, HOST,
};
use ap_broker::clock::ManualClock;
use ap_broker::registry::sha256_hex;

const NOTIFY_BASE: &str = "https://approve.example.test/";
const VIEW_BASE: &str = "https://view.example.test";
const AUTH: &str = "gate.example.test";
const SENTINEL: &str = "SENTINEL-DISCORD-TOKEN-0001";
const PATH_TOKEN: &str = "SENTINEL-PATH-TOKEN-0002";

// The cross-cutting leak suite and refusal table reuse this module's fixture.
#[path = "../leak_tests.rs"]
mod leak_tests;

// The Muse async poll mode.
#[path = "async_tests.rs"]
mod async_tests;

// ---------------------------------------------------------------- mock upstreams

#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    uri: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Bytes,
}

type MockBody = UnsyncBoxBody<Bytes, io::Error>;

fn full(b: &'static str) -> MockBody {
    Full::new(Bytes::from_static(b.as_bytes()))
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

/// A TLS upstream that records every request it fully receives. The last path segment picks the
/// behaviour: `teapot` answers 418 with `X-AP-*` headers, `reset-after-read` and
/// `reset-before-read` drop the connection, `stall` never answers, `stall-body` sends a head and
/// one chunk and then goes quiet, `trickle` sends a chunk every 300 ms forever.
struct Mock {
    up: Upstream,
    reqs: Arc<Mutex<Vec<Recorded>>>,
}

impl Mock {
    async fn start() -> Mock {
        let (server, ca_der) = tls_server_config(b"http/1.1");
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().expect("mock addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let reqs: Arc<Mutex<Vec<Recorded>>> = Arc::default();
        let (h, r) = (Arc::clone(&hits), Arc::clone(&reqs));
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                h.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let reqs = Arc::clone(&r);
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let svc = service_fn(move |req| serve(req, Arc::clone(&reqs)));
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), svc)
                            .await;
                    }
                });
            }
        });
        Mock {
            up: Upstream::from_parts(addr, hits, ca_der),
            reqs,
        }
    }

    fn recorded(&self) -> Vec<Recorded> {
        self.reqs.lock().unwrap().clone()
    }

    fn hits(&self) -> usize {
        self.up.hits.load(Ordering::SeqCst)
    }
}

async fn serve(
    req: hyper::Request<Incoming>,
    reqs: Arc<Mutex<Vec<Recorded>>>,
) -> Result<hyper::Response<MockBody>, io::Error> {
    let (parts, body) = req.into_parts();
    let tail = parts
        .uri
        .path()
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_string();
    if tail == "reset-before-read" {
        return Err(io::Error::other("reset"));
    }
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    reqs.lock().unwrap().push(Recorded {
        method: parts.method.to_string(),
        uri: parts.uri.to_string(),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
            .collect(),
        body,
    });
    match tail.as_str() {
        "teapot" => Ok(hyper::Response::builder()
            .status(418)
            .header("x-ap-decision", "denied")
            .header("x-ap-other", "kept")
            .header("x-plain", "yes")
            .body(full("short and stout"))
            .expect("teapot")),
        "reset-after-read" => Err(io::Error::other("reset")),
        "big" => Ok(hyper::Response::new(
            Full::new(Bytes::from(vec![b'x'; 70_000]))
                .map_err(|never: Infallible| match never {})
                .boxed_unsync(),
        )),
        "stall" => std::future::pending().await,
        "stall-body" => {
            let s = futures_util::stream::once(async {
                Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"a")))
            })
            .chain(futures_util::stream::pending());
            Ok(hyper::Response::new(StreamBody::new(s).boxed_unsync()))
        }
        "trickle" => {
            let s = futures_util::stream::unfold((), |()| async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                Some((
                    Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"t"))),
                    (),
                ))
            });
            Ok(hyper::Response::new(StreamBody::new(s).boxed_unsync()))
        }
        _ => Ok(hyper::Response::new(full("ok"))),
    }
}

/// A TLS upstream that completes handshakes and counts the request bytes it receives, answering
/// nothing.
struct Raw {
    up: Upstream,
    accepted: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
}

impl Raw {
    async fn start() -> Raw {
        let (server, ca_der) = tls_server_config(b"http/1.1");
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind raw");
        let addr = listener.local_addr().expect("raw addr");
        let accepted = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicUsize::new(0));
        let (a, b) = (Arc::clone(&accepted), Arc::clone(&bytes));
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, a, b) = (acceptor.clone(), Arc::clone(&a), Arc::clone(&b));
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    a.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = tls.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        b.fetch_add(n, Ordering::SeqCst);
                    }
                });
            }
        });
        Raw {
            up: Upstream::from_parts(addr, Arc::new(AtomicUsize::new(0)), ca_der),
            accepted,
            bytes,
        }
    }
}

// ---------------------------------------------------------------- audit sink that can fail

#[derive(Clone, Default)]
struct Switch {
    buf: Arc<Mutex<Vec<u8>>>,
    fail_all: Arc<AtomicBool>,
    fail_on: Arc<Mutex<Option<String>>>,
}

impl Write for Switch {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.fail_all.load(Ordering::SeqCst) {
            return Err(io::Error::other("sink down"));
        }
        if let Some(pat) = self.fail_on.lock().unwrap().as_deref() {
            if String::from_utf8_lossy(data).contains(pat) {
                return Err(io::Error::other("sink rejects this line"));
            }
        }
        self.buf.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------- fixture

struct Opts {
    limits: Limits,
    /// Extra keys inside `[passthrough]`.
    extra: String,
    /// Extra keys inside the `discord` `[[route]]`.
    route_extra: String,
    held_body_max: u64,
    /// Text appended after the grants.
    tail: String,
    port: Option<u16>,
    sink: Option<Switch>,
    notifier: Option<Arc<MockNotifier>>,
    /// Telegram buttons mode: the view link and the buttons.
    buttons: bool,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            limits: Limits {
                hold: Duration::from_secs(30),
                max_total: 8,
                max_per_identity: 4,
                cooldown: Duration::ZERO,
            },
            extra: String::new(),
            route_extra: String::new(),
            held_body_max: 2048,
            tail: String::new(),
            port: None,
            sink: None,
            notifier: None,
            buttons: false,
        }
    }
}

struct Ht {
    app: Arc<PtApp>,
    key: String,
    other_key: String,
    audit: Arc<Mutex<Vec<u8>>>,
    policy: std::path::PathBuf,
    _s: Scratch,
}

impl Ht {
    async fn new(tag: &str, up: &Upstream) -> Ht {
        Self::with(tag, up, Opts::default()).await
    }

    async fn with(tag: &str, up: &Upstream, o: Opts) -> Ht {
        let s = Scratch::new(tag);
        let key = caller_key();
        let other_key = caller_key();
        let port = o.port.unwrap_or(up.addr.port());
        let text = format!(
            r#"version = 1

[listen]
proxy = "127.0.0.1:8443"

[limits]
max_body_bytes = 1024

[passthrough]
public_authority = "{AUTH}"
body_read_secs = 1
held_body_max_bytes = {max}
{extra}

[[identity]]
name = "muse-pilot"
caller_key_sha256 = "{sha}"

[[identity]]
name = "muse-other"
caller_key_sha256 = "{sha2}"

[[route]]
name = "discord"
host = "{HOST}"
port = {port}
mode = "passthrough"
{route_extra}

[[grant]]
identity = "muse-pilot"
route = "discord"
methods = ["GET"]
paths = ["/api/", "/me"]

[[grant]]
identity = "muse-pilot"
route = "discord"
methods = ["POST", "PUT"]
decision = "hold"
path_patterns = ["/hold/*", "/hold/*/messages", "/webhooks/*/*"]

[[grant]]
identity = "muse-other"
route = "discord"
methods = ["POST"]
decision = "hold"
path_patterns = ["/hold/*"]
{tail}
"#,
            max = o.held_body_max,
            extra = o.extra,
            route_extra = o.route_extra,
            tail = o.tail,
            sha = sha256_hex(&key),
            sha2 = sha256_hex(&other_key),
        );
        let policy = s.path().join("policy.toml");
        std::fs::write(&policy, &text).unwrap();
        let cfg = ap_core::config::load(&text).expect("valid policy");
        let (sink, audit) = match o.sink {
            Some(sw) => (AuditSink::new(Box::new(sw.clone())), sw.buf),
            None => buffer_sink(),
        };
        let client = client_for(up);
        let mut app = PtApp::build(
            policy.clone(),
            cfg,
            &text,
            sink,
            client.clone(),
            client,
            o.limits,
        );
        if let Some(n) = &o.notifier {
            let view = o.buttons.then_some(VIEW_BASE);
            PtApp::set_notifier(&mut app, n.clone(), NOTIFY_BASE, view);
        }
        Ht {
            app,
            key,
            other_key,
            audit,
            policy,
            _s: s,
        }
    }

    fn builder(&self, key: &str, method: &str, path: &str) -> http::request::Builder {
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", AUTH)
            .header("x-ap-caller-key", key)
            .header("authorization", format!("Bot {SENTINEL}"))
    }

    fn post(&self, path: &str, body: &str) -> Request<Body> {
        self.builder(&self.key, "POST", path)
            .header("content-type", "application/json")
            .header("content-length", body.len())
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn post_other(&self, path: &str, body: &str) -> Request<Body> {
        self.builder(&self.other_key, "POST", path)
            .header("content-type", "application/json")
            .header("content-length", body.len())
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn spawn(
        &self,
        req: Request<Body>,
    ) -> tokio::task::JoinHandle<Result<(http::response::Parts, Bytes), ()>> {
        let app = Arc::clone(&self.app);
        tokio::spawn(async move { collect(handle(app, req).await).await })
    }

    async fn send(&self, req: Request<Body>) -> Result<(http::response::Parts, Bytes), ()> {
        collect(handle(Arc::clone(&self.app), req).await).await
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.audit.lock().unwrap()).into_owned()
    }

    fn lines(&self) -> Vec<serde_json::Value> {
        self.text()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn transitions(&self) -> Vec<String> {
        self.lines()
            .iter()
            .filter_map(|v| v["transition"].as_str().map(str::to_string))
            .collect()
    }

    fn count(&self, transition: &str) -> usize {
        self.transitions()
            .iter()
            .filter(|t| *t == transition)
            .count()
    }

    fn held_ids(&self) -> Vec<String> {
        self.lines()
            .iter()
            .filter(|v| v["transition"] == "held")
            .filter_map(|v| v["request_id"].as_str().map(str::to_string))
            .collect()
    }

    /// The id of the `n`th (1-based) `held` record, once it exists.
    async fn held(&self, n: usize) -> String {
        for _ in 0..250 {
            let ids = self.held_ids();
            if ids.len() >= n {
                return ids[n - 1].clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("hold {n} never appeared: {}", self.text());
    }

    /// Hold `req`, approve it, and return what the caller saw.
    async fn approved(&self, req: Request<Body>) -> (http::response::Parts, Bytes) {
        let n = self.held_ids().len() + 1;
        let h = self.spawn(req);
        let id = self.held(n).await;
        assert_eq!(
            self.app.hold.approve(&id, "alice").await,
            ApproveResult::Success
        );
        h.await.unwrap().unwrap()
    }

    async fn serve(&self) -> SocketAddr {
        let l = crate::listener::bind_loopback("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(crate::listener::public::serve_public(
            l,
            Arc::clone(&self.app),
            crate::listener::public::PublicLimits {
                max_connections: 16,
                header_read: Duration::from_secs(5),
            },
        ));
        addr
    }

    fn assert_clean(&self) {
        let t = self.text();
        for s in [
            SENTINEL,
            PATH_TOKEN,
            self.key.as_str(),
            self.other_key.as_str(),
        ] {
            assert!(!t.contains(s), "{s} leaked into the audit stream: {t}");
        }
    }
}

async fn collect(
    r: Result<Response<Body>, ConnAbort>,
) -> Result<(http::response::Parts, Bytes), ()> {
    match r {
        Ok(resp) => {
            let (p, b) = resp.into_parts();
            let bytes = b.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
            Ok((p, bytes))
        }
        Err(_) => Err(()),
    }
}

fn decision(p: &http::response::Parts) -> String {
    p.headers
        .get("x-ap-decision")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default()
}

fn code(b: &Bytes) -> String {
    let v: serde_json::Value = serde_json::from_slice(b).unwrap();
    v["code"].as_str().unwrap().to_string()
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..250 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

fn header_values<'a>(r: &'a Recorded, name: &str) -> Vec<&'a [u8]> {
    r.headers
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
        .collect()
}

// ---------------------------------------------------------------- spike: disconnect and milestone

#[tokio::test]
async fn hyper_drops_the_handler_future_when_the_peer_closes() {
    let mock = Mock::start().await;
    let t = Ht::new("spike-drop", &mock.up).await;
    let addr = t.serve().await;
    let mut c = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /discord/hold/ok HTTP/1.1\r\nHost: {AUTH}\r\nx-ap-caller-key: {}\r\nauthorization: Bot {SENTINEL}\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{{}}",
        t.key
    );
    c.write_all(req.as_bytes()).await.unwrap();
    let id = t.held(1).await;
    assert_eq!(t.app.hold.state(&id), Some(State::Pending));
    drop(c);
    until("the entry to be abandoned", || {
        t.app.hold.state(&id) == Some(State::Abandoned)
    })
    .await;
    assert_eq!(t.app.hold.pending_len(), 0);
    assert_eq!(t.app.hold.approve(&id, "alice").await, ApproveResult::Gone);
    assert_eq!(t.count("abandoned"), 1);
    assert_eq!(t.count("abandoned_after_approve"), 0);
    assert_eq!(mock.hits(), 0);
    t.assert_clean();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_request_byte_leaves_before_forward_started_and_approve_waits_for_the_first_chunk() {
    let raw = Raw::start().await;
    let t = Ht::new("milestones", &raw.up).await;
    let gate = Gate::new();
    t.app.pause.set_between_milestones(Arc::clone(&gate));
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    let table = Arc::clone(&t.app.hold);
    let approve = tokio::spawn(async move { table.approve(&id, "alice").await });
    tokio::time::timeout(Duration::from_secs(5), gate.arrived())
        .await
        .expect("handler reached the gap between the milestones");
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Connected, and forward_started is on the record, but not one request byte has arrived.
    assert_eq!(raw.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(raw.bytes.load(Ordering::SeqCst), 0, "a byte left early");
    assert_eq!(t.count("forward_started"), 1);
    assert!(
        !approve.is_finished(),
        "approve returned before the first byte"
    );
    gate.release();
    let result = tokio::time::timeout(Duration::from_secs(5), approve)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, ApproveResult::Success);
    until("request bytes", || raw.bytes.load(Ordering::SeqCst) > 0).await;
    h.abort();
}

// ---------------------------------------------------------------- 1, 2, 3, 13

#[tokio::test]
async fn nothing_goes_upstream_before_approval_and_exactly_one_request_after() {
    let mock = Mock::start().await;
    let t = Ht::new("before-after", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"content":"hi"}"#));
    let id = t.held(1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(mock.hits(), 0);
    assert!(mock.recorded().is_empty());
    assert_eq!(t.app.hold.state(&id), Some(State::Pending));
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(p.status, 200);
    assert_eq!(&b[..], b"ok");
    assert_eq!(mock.recorded().len(), 1);
    assert_eq!(
        t.transitions(),
        ["held", "approved", "forward_started", "completed"]
    );
    t.assert_clean();
}

#[tokio::test]
async fn approved_request_arrives_unchanged_and_the_response_is_verbatim() {
    let mock = Mock::start().await;
    let t = Ht::new("verbatim", &mock.up).await;
    let body = r#"{"content":"hello \u00e9","n":[1,2,3]}"#;
    let req = t
        .builder(&t.key, "POST", "/discord/hold/teapot?a=1&b=%2Fz")
        .header("content-type", "application/json; charset=utf-8")
        .header("accept", "application/json")
        .header("content-length", body.len())
        .header("x-dup", "one")
        .header("x-dup", "two")
        .header("x-keep", "kept")
        .header("expect", "100-continue")
        .header("forwarded", "for=1")
        .header("x-forwarded-for", "1.2.3.4")
        .header("via", "1.1 front")
        .header("cf-ray", "abc")
        .header("tailscale-user-login", "someone")
        .header("cookie", "a=b")
        .header("proxy-authorization", "Basic x")
        .header("x-api-key", "k")
        .header("connection", "x-secret-hop")
        .header("x-secret-hop", "1")
        .body(Body::from(body))
        .unwrap();
    let (p, b) = t.approved(req).await;
    // The upstream response, status, headers and body, including X-AP-* names.
    assert_eq!(p.status, 418);
    assert_eq!(p.headers.get("x-ap-decision").unwrap(), "denied");
    assert_eq!(p.headers.get("x-ap-other").unwrap(), "kept");
    assert_eq!(p.headers.get("x-plain").unwrap(), "yes");
    assert_eq!(&b[..], b"short and stout");
    // The request: one, with the same method, target, body and headers except the stripped ones.
    let recs = mock.recorded();
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.method, "POST");
    assert!(
        r.uri.ends_with("/hold/teapot?a=1&b=%2Fz"),
        "target changed: {}",
        r.uri
    );
    assert_eq!(&r.body[..], body.as_bytes());
    assert_eq!(
        header_values(r, "authorization"),
        [format!("Bot {SENTINEL}").as_bytes()]
    );
    assert_eq!(header_values(r, "x-dup"), [&b"one"[..], &b"two"[..]]);
    assert_eq!(header_values(r, "x-keep"), [&b"kept"[..]]);
    assert_eq!(
        header_values(r, "content-type"),
        [&b"application/json; charset=utf-8"[..]]
    );
    assert_eq!(
        header_values(r, "content-length"),
        [body.len().to_string().as_bytes()]
    );
    for gone in [
        "x-ap-caller-key",
        "expect",
        "forwarded",
        "x-forwarded-for",
        "via",
        "cf-ray",
        "tailscale-user-login",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "x-secret-hop",
    ] {
        assert!(header_values(r, gone).is_empty(), "{gone} reached upstream");
    }
    t.assert_clean();
}

#[tokio::test]
async fn caller_key_is_stripped_in_both_forms() {
    let mock = Mock::start().await;
    let t = Ht::new("keystrip", &mock.up).await;
    let by_header = t.post("/discord/hold/a", r#"{"k":"header"}"#);
    let (p, _) = t.approved(by_header).await;
    assert_eq!(p.status, 200);
    let by_path = Request::builder()
        .method("POST")
        .uri(format!("/ap/{}/discord/hold/b", t.key))
        .header("host", AUTH)
        .header("authorization", format!("Bot {SENTINEL}"))
        .header("content-type", "application/json")
        .header("content-length", "2")
        .body(Body::from("{}"))
        .unwrap();
    let (p, _) = t.approved(by_path).await;
    assert_eq!(p.status, 200);
    let recs = mock.recorded();
    assert_eq!(recs.len(), 2);
    for r in &recs {
        assert!(header_values(r, "x-ap-caller-key").is_empty());
        assert!(
            !r.uri.contains("/ap/") && !r.uri.contains(&t.key),
            "{}",
            r.uri
        );
        for (_, v) in &r.headers {
            assert!(!String::from_utf8_lossy(v).contains(&t.key));
        }
    }
    assert!(recs[1].uri.ends_with("/hold/b"));
    t.assert_clean();
}

#[tokio::test]
async fn an_empty_body_is_still_forwarded_and_confirmed() {
    let mock = Mock::start().await;
    let t = Ht::new("empty", &mock.up).await;
    let (p, _) = t.approved(t.post("/discord/hold/ok", "")).await;
    assert_eq!(p.status, 200);
    let recs = mock.recorded();
    assert_eq!(recs.len(), 1);
    assert!(recs[0].body.is_empty());
    // Chunked, because hyper never polls the body of a zero-length request, which would skip
    // milestone 1.
    assert_eq!(
        header_values(&recs[0], "transfer-encoding"),
        [&b"chunked"[..]]
    );
    assert!(header_values(&recs[0], "content-length").is_empty());
    assert_eq!(
        t.transitions(),
        ["held", "approved", "forward_started", "completed"]
    );
}

// ---------------------------------------------------------------- 4, 5, 23

#[tokio::test]
async fn deny_sends_nothing_and_a_cooldown_follows() {
    let mock = Mock::start().await;
    let mut o = Opts::default();
    o.limits.cooldown = Duration::from_secs(30);
    let t = Ht::with("deny", &mock.up, o).await;
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    assert_eq!(t.app.hold.deny(&id, "alice"), DenyResult::Denied);
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(p.status, 423);
    assert_eq!(decision(&p), "denied");
    assert_eq!(code(&b), "human_denied");
    assert_eq!(mock.hits(), 0);
    assert_eq!(t.transitions(), ["held", "denied"]);
    let denied = t
        .lines()
        .into_iter()
        .find(|v| v["transition"] == "denied")
        .unwrap();
    assert_eq!(denied["approver"], "alice");
    // The slot is free, and the identity is in cooldown.
    assert_eq!(t.app.hold.pending_len(), 0);
    let (p, b) = t.send(t.post("/discord/hold/ok", "{}")).await.unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&b)),
        (503, "unavailable".into(), "cooldown".into())
    );
    // Approving the denied entry changes nothing.
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::AlreadyDecided
    );
    assert_eq!(mock.hits(), 0);
}

#[tokio::test]
async fn a_zero_cooldown_lets_the_next_request_be_held_at_once() {
    let mock = Mock::start().await;
    let t = Ht::new("nocool", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    t.app.hold.deny(&id, "alice");
    h.await.unwrap().unwrap();
    let h2 = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id2 = t.held(2).await;
    assert_eq!(t.app.hold.state(&id2), Some(State::Pending));
    t.app.hold.deny(&id2, "alice");
    h2.await.unwrap().unwrap();
}

#[tokio::test]
async fn expiry_answers_410_without_retry_after_and_sends_nothing() {
    let mock = Mock::start().await;
    let mut o = Opts::default();
    o.limits.hold = Duration::from_millis(400);
    o.limits.cooldown = Duration::from_secs(30);
    let t = Ht::with("expire", &mock.up, o).await;
    let start = Instant::now();
    let (p, b) = t.send(t.post("/discord/hold/ok", "{}")).await.unwrap();
    assert!(start.elapsed() >= Duration::from_millis(350));
    assert_eq!(p.status, 410);
    assert_eq!(decision(&p), "expired");
    assert_eq!(code(&b), "expired");
    assert!(p.headers.get("retry-after").is_none());
    assert_eq!(mock.hits(), 0);
    assert_eq!(t.transitions(), ["held", "expired"]);
    let id = t.held(1).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Expired
    );
    // An expiry starts the cooldown.
    let (p, b) = t.send(t.post("/discord/hold/ok", "{}")).await.unwrap();
    assert_eq!((p.status.as_u16(), code(&b)), (503, "cooldown".into()));
}

// ---------------------------------------------------------------- 6, 14, 20

#[tokio::test]
async fn caps_and_unavailable_rows_send_nothing() {
    let mock = Mock::start().await;
    let mut o = Opts::default();
    o.limits.max_per_identity = 1;
    o.limits.max_total = 2;
    let t = Ht::with("caps", &mock.up, o).await;
    let a1 = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    t.held(1).await;
    // A second distinct request from the same identity: per-identity cap.
    let (p, b) = t
        .send(t.post("/discord/hold/ok", r#"{"n":2}"#))
        .await
        .unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&b)),
        (503, "unavailable".into(), "identity_cap".into())
    );
    // Another identity is accepted.
    let b1 = t.spawn(t.post_other("/discord/hold/ok", r#"{"n":3}"#));
    t.held(2).await;
    assert_eq!(t.app.hold.pending_len(), 2);
    // Policy file removed: 503 policy_unavailable.
    std::fs::remove_file(&t.policy).unwrap();
    let (p, b) = t
        .send(t.post("/discord/hold/ok", r#"{"n":4}"#))
        .await
        .unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&b)),
        (503, "unavailable".into(), "policy_unavailable".into())
    );
    // Shutdown answers every Pending entry 503 shutdown.
    assert_eq!(t.app.hold.drain_pending(), 2);
    for h in [a1, b1] {
        let (p, b) = h.await.unwrap().unwrap();
        assert_eq!(
            (p.status.as_u16(), decision(&p), code(&b)),
            (503, "unavailable".into(), "shutdown".into())
        );
    }
    assert_eq!(mock.hits(), 0);
    t.assert_clean();
}

#[tokio::test]
async fn a_full_table_refuses_and_a_reload_drop_answers_503() {
    let mock = Mock::start().await;
    let mut o = Opts::default();
    o.limits.max_total = 2;
    let t = Ht::with("full", &mock.up, o).await;
    let a = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let b = t.spawn(t.post("/discord/hold/ok", r#"{"n":2}"#));
    t.held(2).await;
    let (p, body) = t
        .send(t.post_other("/discord/hold/ok", r#"{"n":3}"#))
        .await
        .unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&body)),
        (503, "unavailable".into(), "table_full".into())
    );
    assert_eq!(t.app.hold.drop_all(), 2);
    for h in [a, b] {
        let (p, body) = h.await.unwrap().unwrap();
        assert_eq!(
            (p.status.as_u16(), decision(&p), code(&body)),
            (503, "unavailable".into(), "dropped_on_reload".into())
        );
    }
    assert_eq!(t.count("dropped_on_reload"), 2);
    assert_eq!(mock.hits(), 0);
}

#[tokio::test]
async fn the_reload_tick_drops_every_hold_when_the_policy_file_is_gone() {
    let mock = Mock::start().await;
    let t = Ht::new("tick", &mock.up).await;
    let a = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let b = t.spawn(t.post_other("/discord/hold/ok", r#"{"n":2}"#));
    t.held(2).await;
    // A valid policy that still lists both identities drops nothing.
    assert_eq!(t.app.reload_tick(), 0);
    assert_eq!(t.app.hold.pending_len(), 2);
    std::fs::remove_file(&t.policy).unwrap();
    assert_eq!(t.app.reload_tick(), 2);
    for h in [a, b] {
        let (p, body) = h.await.unwrap().unwrap();
        assert_eq!(
            (p.status.as_u16(), decision(&p), code(&body)),
            (503, "unavailable".into(), "dropped_on_reload".into())
        );
    }
    assert_eq!(t.count("dropped_on_reload"), 2);
    assert_eq!(mock.hits(), 0);
}

// ---------------------------------------------------------------- reload re-evaluates holds

impl Ht {
    /// Rewrite the policy file with `f`, which must change it.
    fn rewrite(&self, f: impl FnOnce(String) -> String) {
        let old = std::fs::read_to_string(&self.policy).unwrap();
        let new = f(old.clone());
        assert_ne!(old, new, "the rewrite changed nothing");
        // The file stamp is the mtime and the length; keep two rewrites apart on coarse clocks.
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&self.policy, new).unwrap();
    }

    /// Rewrite the policy file with `f`, which must keep its length, then put back the mtime it
    /// had. The file stamp (mtime and length) is then the same as before the rewrite.
    fn rewrite_same_stamp(&self, f: impl FnOnce(String) -> String) {
        let before = std::fs::metadata(&self.policy).unwrap();
        let mtime = before.modified().unwrap();
        let old = std::fs::read_to_string(&self.policy).unwrap();
        let new = f(old.clone());
        assert_ne!(old, new, "the rewrite changed nothing");
        assert_eq!(old.len(), new.len(), "the rewrite must keep the length");
        std::fs::write(&self.policy, new).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&self.policy)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(mtime))
            .unwrap();
        let after = std::fs::metadata(&self.policy).unwrap();
        assert_eq!(
            (after.len(), after.modified().unwrap()),
            (before.len(), mtime),
            "the stamp must match the one before the rewrite"
        );
    }

    /// Approve the way the approval listener does: checked against the policy in force now.
    async fn approve_checked(&self, id: &str) -> ApproveResult {
        self.approve_with(id, self.app.policy_source()).await
    }

    /// Approve through the listener's own function, reading the policy from `source`.
    async fn approve_with(&self, id: &str, source: PolicySource) -> ApproveResult {
        crate::approval::approve_checked(&self.app.hold, &source, id, "alice").await
    }

    /// The policy source with `gate` placed before or after its read of the policy. The listener
    /// calls it inside the table's critical section, so the gate holds the table lock.
    fn gated_source(&self, gate: Arc<Gate>, after_read: bool) -> PolicySource {
        let inner = self.app.policy_source();
        Arc::new(move || {
            if !after_read {
                gate.pass_blocking();
            }
            let snap = inner();
            if after_read {
                gate.pass_blocking();
            }
            snap
        })
    }

    /// The mock upstream port the policy names for the route.
    fn port(&self) -> String {
        let text = std::fs::read_to_string(&self.policy).unwrap();
        let head = format!("host = \"{HOST}\"\nport = ");
        let at = text.find(&head).expect("route block") + head.len();
        text[at..].lines().next().unwrap().to_string()
    }

    /// A policy rewrite that names `host` and `port` for the route `discord` instead. The old
    /// port stays behind as a comment, so the file length always changes.
    fn retarget(&self, host: &str, port: &str) -> impl FnOnce(String) -> String {
        let (from_host, host, port) = (HOST.to_string(), host.to_string(), port.to_string());
        move |s: String| {
            let head = format!("host = \"{from_host}\"\nport = ");
            let at = s.find(&head).expect("route block") + head.len();
            let end = at + s[at..].find('\n').expect("port line");
            format!(
                "{}host = \"{host}\"\nport = {port}\n# was {}{}",
                &s[..at - head.len()],
                &s[at..end],
                &s[end..]
            )
        }
    }

    /// The caller of a dropped hold saw 503 `dropped_on_reload`, and nothing went upstream.
    async fn assert_dropped(
        &self,
        h: tokio::task::JoinHandle<Result<(http::response::Parts, Bytes), ()>>,
        mock: &Mock,
    ) {
        let (p, body) = h.await.unwrap().unwrap();
        assert_eq!(
            (p.status.as_u16(), decision(&p), code(&body)),
            (503, "unavailable".into(), "dropped_on_reload".into())
        );
        assert_eq!(self.app.hold.pending_len(), 0);
        assert_eq!(self.count("dropped_on_reload"), 1);
        assert_eq!(mock.hits(), 0);
    }
}

/// `text` with the pilot hold grant's `/hold/*` patterns renamed to `/deny/*`. The length is the
/// same, so the file stamp only changes if the store reads the mtime and length alone.
fn hold_to_deny(text: String) -> String {
    text.replacen(
        "path_patterns = [\"/hold/*\", \"/hold/*/messages\"",
        "path_patterns = [\"/deny/*\", \"/deny/*/messages\"",
        1,
    )
}

/// `text` without the grant block that starts with `head` (up to the next `[[grant]]` or the end).
fn without_grant(text: &str, head: &str) -> String {
    let start = text.find(head).expect("grant block");
    let end = text[start + 2..]
        .find("[[grant]]")
        .map_or(text.len(), |n| start + 2 + n);
    format!("{}{}", &text[..start], &text[end..])
}

/// A same-length policy swap that keeps the file's mtime is still a change: approval sees the
/// new policy, drops the hold and forwards nothing.
#[tokio::test]
async fn a_same_length_same_mtime_swap_that_removes_the_hold_grant_drops_it_at_approve() {
    let mock = Mock::start().await;
    let t = Ht::new("rl-same-stamp", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    t.rewrite_same_stamp(hold_to_deny);
    assert_eq!(t.approve_checked(&id).await, ApproveResult::PolicyChanged);
    t.assert_dropped(h, &mock).await;
    assert!(mock.recorded().is_empty(), "a request went upstream");
    assert_eq!(t.count("forward_started"), 0);
}

const PILOT_HOLD: &str =
    "[[grant]]\nidentity = \"muse-pilot\"\nroute = \"discord\"\nmethods = [\"POST\", \"PUT\"]";

#[tokio::test]
async fn removing_the_hold_grant_on_reload_drops_its_pending_hold() {
    let mock = Mock::start().await;
    let t = Ht::new("rl-grant", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    assert_eq!(t.app.reload_tick(), 0);
    t.rewrite(|s| without_grant(&s, PILOT_HOLD));
    assert_eq!(t.app.reload_tick(), 1);
    t.assert_dropped(h, &mock).await;
    assert_eq!(t.app.hold.state(&id), Some(State::Dropped));
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Dropped
    );
}

#[tokio::test]
async fn removing_the_route_on_reload_drops_its_pending_hold() {
    let mock = Mock::start().await;
    let t = Ht::new("rl-route", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    t.held(1).await;
    // A valid policy whose route has another name: the held route no longer exists.
    t.rewrite(|s| s.replace("\"discord\"", "\"discord9\""));
    assert_eq!(t.app.reload_tick(), 1);
    t.assert_dropped(h, &mock).await;
}

#[tokio::test]
async fn removing_the_identity_on_reload_drops_its_pending_hold() {
    let mock = Mock::start().await;
    let t = Ht::new("rl-ident", &mock.up).await;
    let h = t.spawn(t.post_other("/discord/hold/ok", r#"{"n":1}"#));
    t.held(1).await;
    t.rewrite(|s| {
        let s = without_grant(&s, "[[grant]]\nidentity = \"muse-other\"");
        let a = s.find("[[identity]]\nname = \"muse-other\"").unwrap();
        let b = s.find("[[route]]").unwrap();
        format!("{}{}", &s[..a], &s[b..])
    });
    assert_eq!(t.app.reload_tick(), 1);
    t.assert_dropped(h, &mock).await;
}

#[tokio::test]
async fn narrowing_the_hold_pattern_on_reload_drops_the_hold_it_no_longer_covers() {
    let mock = Mock::start().await;
    let t = Ht::new("rl-narrow", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    t.held(1).await;
    // `/hold/ok` matched `/hold/*`; the narrowed grant holds `/hold/*/messages` only, and no
    // allow grant covers `/hold/ok`, so it is denied now.
    t.rewrite(|s| s.replace("\"/hold/*\", \"/hold/*/messages\"", "\"/hold/*/messages\""));
    assert_eq!(t.app.reload_tick(), 1);
    t.assert_dropped(h, &mock).await;
}

#[tokio::test]
async fn a_method_removed_from_the_hold_grant_drops_the_hold() {
    let mock = Mock::start().await;
    let t = Ht::new("rl-method", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    t.held(1).await;
    t.rewrite(|s| s.replace("methods = [\"POST\", \"PUT\"]", "methods = [\"PUT\"]"));
    assert_eq!(t.app.reload_tick(), 1);
    t.assert_dropped(h, &mock).await;
}

#[tokio::test]
async fn a_hold_that_the_new_policy_still_holds_survives_and_can_be_approved() {
    let mock = Mock::start().await;
    let t = Ht::new("rl-keep", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    t.rewrite(|s| s.replace("\"/webhooks/*/*\"]", "\"/webhooks/*/*\", \"/extra/*\"]"));
    assert_eq!(t.app.reload_tick(), 0);
    assert_eq!(t.app.hold.pending_len(), 1);
    assert_eq!(t.approve_checked(&id).await, ApproveResult::Success);
    let (p, _) = h.await.unwrap().unwrap();
    assert_eq!(p.status.as_u16(), 200);
    assert_eq!(mock.hits(), 1);
}

#[tokio::test]
async fn an_invalid_policy_replacing_the_file_fails_closed_for_holds_and_approvals() {
    let mock = Mock::start().await;
    let t = Ht::new("rl-invalid", &mock.up).await;
    let a = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    t.rewrite(|_| "version = 1\nthis is = not a valid policy\n".into());
    // An approve that arrives before the tick is refused too: no valid policy, no approval.
    assert_eq!(t.approve_checked(&id).await, ApproveResult::PolicyChanged);
    t.assert_dropped(a, &mock).await;
    let b = t.spawn(t.post("/discord/hold/ok", r#"{"n":2}"#));
    let (p, _) = b.await.unwrap().unwrap();
    assert_eq!(p.status.as_u16(), 503);
    assert_eq!(mock.hits(), 0);
}

#[tokio::test]
async fn an_approve_racing_a_reload_does_not_forward() {
    let mock = Mock::start().await;
    let t = Ht::new("rl-race", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    // The file changed, the reload tick has not run: the approve itself re-reads the policy.
    t.rewrite(|s| without_grant(&s, PILOT_HOLD));
    assert_eq!(t.app.hold.pending_len(), 1);
    assert_eq!(t.approve_checked(&id).await, ApproveResult::PolicyChanged);
    t.assert_dropped(h, &mock).await;
    // A later tick has nothing left to drop and nothing is sent.
    assert_eq!(t.app.reload_tick(), 0);
    assert_eq!(mock.hits(), 0);
}

// ------------------------------------------- approve and reload interleavings (same family)

/// Where a reload lands relative to an approve.
#[derive(Clone, Copy, Debug)]
enum Point {
    /// Before the approve call starts.
    BeforeApprove,
    /// Inside the table's critical section, before the policy is read.
    InLockBeforeRead,
    /// Inside the table's critical section, after the policy was read and before the verdict.
    InLockAfterRead,
    /// After the approve took the entry out of the table, before the first upstream byte.
    ApprovedBeforeSend,
    /// Inside the start claim, before the `forward_started` write.
    InClaim,
}

const POINTS: [Point; 5] = [
    Point::BeforeApprove,
    Point::InLockBeforeRead,
    Point::InLockAfterRead,
    Point::ApprovedBeforeSend,
    Point::InClaim,
];

/// Run one approve with the policy change `change` injected at `point`, and a reload tick racing
/// it. Returns the fixture, the mock, the approve result, the caller's status and code, and the
/// number of holds the racing tick dropped.
async fn interleave(
    tag: &str,
    point: Point,
    change: impl FnOnce(&Ht),
) -> (Ht, Mock, ApproveResult, (u16, String), usize) {
    let mock = Mock::start().await;
    let t = Ht::new(tag, &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    let gate = Gate::new();
    let source = match point {
        Point::InLockBeforeRead => t.gated_source(Arc::clone(&gate), false),
        Point::InLockAfterRead => t.gated_source(Arc::clone(&gate), true),
        _ => t.app.policy_source(),
    };
    match point {
        Point::ApprovedBeforeSend => t.app.pause.set_after_approve(Arc::clone(&gate)),
        Point::InClaim => t.app.pause.set_in_claim(Arc::clone(&gate)),
        _ => {}
    }
    let mut change = Some(change);
    if matches!(point, Point::BeforeApprove) {
        (change.take().expect("once"))(&t);
    }
    let table = Arc::clone(&t.app.hold);
    let approve = tokio::spawn(async move {
        crate::approval::approve_checked(&table, &source, &id, "alice").await
    });
    let mut tick = 0;
    if !matches!(point, Point::BeforeApprove) {
        tokio::time::timeout(Duration::from_secs(5), gate.arrived())
            .await
            .expect("the handler reached the injection point");
        (change.take().expect("once"))(&t);
        // A reload tick racing the approve. Inside the table lock it cannot run at all.
        let app = Arc::clone(&t.app);
        let racing = tokio::task::spawn_blocking(move || app.reload_tick());
        // Blocking sleep: a worker may be parked inside a gate and own the timer driver.
        std::thread::sleep(Duration::from_millis(200));
        let inside_lock = matches!(
            point,
            Point::InLockBeforeRead | Point::InLockAfterRead | Point::InClaim
        );
        let ran_early = racing.is_finished();
        gate.release();
        // Asserted after the release, so a failure cannot leave a thread parked in the gate.
        assert!(
            !(inside_lock && ran_early),
            "{point:?}: a reload ran inside the approve's critical section"
        );
        tick = racing.await.unwrap();
    }
    let result = tokio::time::timeout(Duration::from_secs(10), approve)
        .await
        .expect("approve returned")
        .unwrap();
    let (p, body) = h.await.unwrap().unwrap();
    let body_code = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["code"].as_str().map(str::to_string))
        .unwrap_or_default();
    (t, mock, result, (p.status.as_u16(), body_code), tick)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_grant_never_forwards_whenever_the_reload_lands() {
    for point in POINTS {
        let tag = format!("il-revoke-{point:?}");
        let (t, mock, result, (status, body), tick) = interleave(&tag, point, |t| {
            t.rewrite(|s| without_grant(&s, PILOT_HOLD))
        })
        .await;
        assert_eq!(result, ApproveResult::PolicyChanged, "{point:?}");
        assert_eq!(
            (status, body.as_str()),
            (503, "dropped_on_reload"),
            "{point:?}"
        );
        assert!(
            mock.recorded().is_empty(),
            "{point:?}: a request went upstream"
        );
        assert_eq!(t.count("forward_started"), 0, "{point:?}");
        assert_eq!(t.count("dropped_on_reload"), 1, "{point:?}");
        assert_eq!(t.app.hold.pending_len(), 0, "{point:?}");
        // The tick has nothing left to drop in every case that raced it.
        assert_eq!(tick, 0, "{point:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hold_that_stays_held_is_approved_under_the_policy_current_at_send_time() {
    for point in POINTS {
        let tag = format!("il-keep-{point:?}");
        let (t, mock, result, (status, _), tick) = interleave(&tag, point, |t| {
            t.rewrite(|s| s.replace("\"/webhooks/*/*\"]", "\"/webhooks/*/*\", \"/extra/*\"]"));
        })
        .await;
        assert_eq!(result, ApproveResult::Success, "{point:?}");
        assert_eq!(status, 200, "{point:?}");
        assert_eq!(mock.recorded().len(), 1, "{point:?}");
        assert_eq!(t.count("forward_started"), 1, "{point:?}");
        assert_eq!(t.count("dropped_on_reload"), 0, "{point:?}");
        assert_eq!(tick, 0, "{point:?}");
    }
}

/// The reported schedule: the approve has read the policy, the grant is removed, and the approve
/// carries on with the snapshot it already holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_approve_that_read_the_policy_before_the_grant_was_removed_does_not_forward() {
    let (t, mock, result, (status, body), tick) =
        interleave("il-sol", Point::InLockAfterRead, |t| {
            t.rewrite(|s| without_grant(&s, PILOT_HOLD));
        })
        .await;
    assert_eq!(result, ApproveResult::PolicyChanged);
    assert_eq!((status, body.as_str()), (503, "dropped_on_reload"));
    assert!(mock.recorded().is_empty());
    assert_eq!(
        t.count("approved"),
        1,
        "the approve itself saw the old policy"
    );
    assert_eq!(t.count("forward_started"), 0);
    assert_eq!(tick, 0);
}

// ------------------------------------------------ the upstream authority of a held request

#[tokio::test]
async fn a_held_request_records_its_upstream_in_the_held_record_and_the_view() {
    let mock = Mock::start().await;
    let t = Ht::new("auth-record", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    let authority = format!("https://{HOST}:{}", mock.up.addr.port());
    let held: Vec<_> = t
        .lines()
        .into_iter()
        .filter(|v| v["transition"] == "held")
        .collect();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0]["upstream"], authority.as_str());
    assert_eq!(held[0]["policy_generation"], 1);
    let view = t.app.hold.view(&id).and_then(|v| v.content).unwrap();
    assert_eq!(view.upstream, authority);
    t.app.hold.drop_all();
    let _ = h.await;
}

/// Hold one request, apply `change`, and check what a reload tick and an approve do. `at_tick`
/// runs the tick first (the entry is dropped there); otherwise the approve meets the change.
async fn authority_case(tag: &str, at_tick: bool, change: impl FnOnce(&Ht)) {
    let mock = Mock::start().await;
    let t = Ht::new(tag, &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    assert_eq!(
        t.app.reload_tick(),
        0,
        "{tag}: unchanged policy keeps the hold"
    );
    change(&t);
    if at_tick {
        assert_eq!(t.app.reload_tick(), 1, "{tag}");
    } else {
        assert_eq!(
            t.approve_checked(&id).await,
            ApproveResult::PolicyChanged,
            "{tag}"
        );
    }
    t.assert_dropped(h, &mock).await;
}

#[tokio::test]
async fn a_route_host_change_drops_the_hold_at_reload_and_at_approve() {
    for at_tick in [true, false] {
        let tag = format!("auth-host-{at_tick}");
        authority_case(&tag, at_tick, |t| {
            let port = t.port();
            t.rewrite(t.retarget("other.example.test", &port));
        })
        .await;
    }
}

#[tokio::test]
async fn a_route_port_change_drops_the_hold_at_reload_and_at_approve() {
    for at_tick in [true, false] {
        let tag = format!("auth-port-{at_tick}");
        authority_case(&tag, at_tick, |t| t.rewrite(t.retarget(HOST, "9"))).await;
    }
}

#[tokio::test]
async fn a_route_rename_drops_the_hold_at_reload_and_at_approve() {
    for at_tick in [true, false] {
        let tag = format!("auth-rename-{at_tick}");
        authority_case(&tag, at_tick, |t| {
            t.rewrite(|s| s.replace("\"discord\"", "\"discord9\""));
        })
        .await;
    }
}

#[tokio::test]
async fn a_change_to_the_routes_kept_auth_headers_drops_the_hold() {
    for at_tick in [true, false] {
        let tag = format!("auth-keep-{at_tick}");
        authority_case(&tag, at_tick, |t| {
            t.rewrite(|s| {
                s.replace(
                    "mode = \"passthrough\"\n",
                    "mode = \"passthrough\"\nkeep_auth_headers = [\"x-api-key\"]\n",
                )
            });
        })
        .await;
    }
}

#[tokio::test]
async fn an_unchanged_authority_keeps_the_hold_and_it_goes_to_that_upstream() {
    let mock = Mock::start().await;
    let t = Ht::new("auth-same", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    // Everything else about the route and the grants changes; the authority does not.
    t.rewrite(|s| s.replace("\"/webhooks/*/*\"]", "\"/webhooks/*/*\", \"/extra/*\"]"));
    assert_eq!(t.app.reload_tick(), 0);
    assert_eq!(t.approve_checked(&id).await, ApproveResult::Success);
    let (p, _) = h.await.unwrap().unwrap();
    assert_eq!(p.status.as_u16(), 200);
    assert_eq!(mock.hits(), 1);
}

#[tokio::test]
async fn a_policy_swap_that_changes_the_host_and_back_is_judged_when_it_is_seen() {
    // Seen while changed: dropped, and it stays dropped when the policy goes back.
    let mock = Mock::start().await;
    let t = Ht::new("auth-swap-seen", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    let port = t.port();
    t.rewrite(t.retarget("other.example.test", &port));
    assert_eq!(t.app.reload_tick(), 1);
    t.rewrite(|s| s.replace("other.example.test", HOST));
    assert_eq!(t.app.reload_tick(), 0);
    assert_eq!(t.approve_checked(&id).await, ApproveResult::Dropped);
    t.assert_dropped(h, &mock).await;

    // Never seen while changed: the authority the owner reviewed is the one in force, so the
    // approve goes to it.
    let t = Ht::new("auth-swap-unseen", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", r#"{"n":1}"#));
    let id = t.held(1).await;
    let original = std::fs::read_to_string(&t.policy).unwrap();
    t.rewrite(t.retarget("other.example.test", &port));
    t.rewrite(|_| original);
    assert_eq!(t.approve_checked(&id).await, ApproveResult::Success);
    let (p, _) = h.await.unwrap().unwrap();
    assert_eq!(p.status.as_u16(), 200);
    assert_eq!(mock.hits(), 1);
}

#[tokio::test]
async fn an_identical_retry_supersedes_and_one_approval_makes_one_request() {
    let mock = Mock::start().await;
    let t = Ht::new("supersede", &mock.up).await;
    let first = t.spawn(t.post("/discord/hold/ok", r#"{"same":true}"#));
    let id1 = t.held(1).await;
    // Ten rapid identical retries leave one entry.
    let mut retries = Vec::new();
    for n in 2..=11 {
        retries.push(t.spawn(t.post("/discord/hold/ok", r#"{"same":true}"#)));
        t.held(n).await;
    }
    assert_eq!(t.app.hold.pending_len(), 1);
    let (p, b) = first.await.unwrap().unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&b)),
        (503, "unavailable".into(), "superseded".into())
    );
    let newest = t.held(11).await;
    assert!(matches!(
        t.app.hold.approve(&id1, "alice").await,
        ApproveResult::Superseded { newest: n } if n == newest
    ));
    // A changed Authorization is a different request with its own entry.
    let other = t.spawn(
        Request::builder()
            .method("POST")
            .uri("/discord/hold/ok")
            .header("host", AUTH)
            .header("x-ap-caller-key", t.key.as_str())
            .header("authorization", "Bot something-else")
            .header("content-type", "application/json")
            .header("content-length", 13)
            .body(Body::from(r#"{"same":true}"#))
            .unwrap(),
    );
    t.held(12).await;
    assert_eq!(t.app.hold.pending_len(), 2);
    assert_eq!(
        t.app.hold.approve(&newest, "alice").await,
        ApproveResult::Success
    );
    let last = retries.pop().unwrap();
    assert_eq!(last.await.unwrap().unwrap().0.status, 200);
    for r in retries {
        let (p, _) = r.await.unwrap().unwrap();
        assert_eq!(p.status, 503);
    }
    assert_eq!(mock.recorded().len(), 1);
    assert_eq!(t.count("superseded"), 10);
    t.app.hold.deny(&t.held(12).await, "alice");
    other.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_changed_ordinary_header_is_a_distinct_entry_with_its_own_notification() {
    let mock = Mock::start().await;
    let n = MockNotifier::new(false);
    let o = Opts {
        notifier: Some(Arc::clone(&n)),
        ..Opts::default()
    };
    let t = Ht::with("distinct-header", &mock.up, o).await;
    let mk = |note: &str| {
        t.builder(&t.key, "POST", "/discord/hold/ok")
            .header("content-type", "application/json")
            .header("content-length", 2)
            .header("x-note", note)
            .body(Body::from("{}"))
            .unwrap()
    };
    let a = t.spawn(mk("one"));
    let id_a = t.held(1).await;
    let b = t.spawn(mk("two"));
    let id_b = t.held(2).await;
    calls_reach(&n, 2).await;
    assert_ne!(id_a, id_b);
    assert_eq!(t.app.hold.pending_len(), 2, "no supersede");
    assert_eq!(t.count("superseded"), 0);
    // Independent decisions: deny one, approve the other.
    t.app.hold.deny(&id_a, "alice");
    let (pa, _) = a.await.unwrap().unwrap();
    assert_eq!(pa.status, 423);
    assert_eq!(t.app.hold.state(&id_b), Some(State::Pending));
    assert_eq!(
        t.app.hold.approve(&id_b, "alice").await,
        ApproveResult::Success
    );
    let (pb, _) = b.await.unwrap().unwrap();
    assert_eq!(pb.status, 200);
    assert_eq!(mock.recorded().len(), 1);
    assert_eq!(n.calls().len(), 2);
}

// ---------------------------------------------------------------- 8

#[tokio::test]
async fn disconnect_before_approve_frees_the_slot_and_approve_says_gone() {
    let mock = Mock::start().await;
    let t = Ht::new("gone", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    h.abort();
    until("abandoned", || {
        t.app.hold.state(&id) == Some(State::Abandoned)
    })
    .await;
    assert_eq!(t.app.hold.pending_len(), 0);
    assert_eq!(t.app.hold.approve(&id, "alice").await, ApproveResult::Gone);
    assert_eq!(t.count("abandoned"), 1);
    assert_eq!(t.count("abandoned_after_approve"), 0);
    assert_eq!(mock.hits(), 0);
}

#[tokio::test]
async fn disconnect_after_approve_before_the_send_sends_nothing() {
    let mock = Mock::start().await;
    let t = Ht::new("abandoned-after", &mock.up).await;
    let gate = Gate::new();
    t.app.pause.set_after_approve(Arc::clone(&gate));
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    let table = Arc::clone(&t.app.hold);
    let approve = tokio::spawn(async move { table.approve(&id, "alice").await });
    gate.arrived().await;
    h.abort();
    assert_eq!(approve.await.unwrap(), ApproveResult::ApprovedButAbandoned);
    until("abandoned_after_approve", || {
        t.count("abandoned_after_approve") == 1
    })
    .await;
    assert_eq!(t.count("forward_started"), 0);
    assert_eq!(t.count("abandoned"), 0);
    assert_eq!(mock.hits(), 0);
}

#[tokio::test]
async fn shutdown_between_approve_and_the_send_sends_nothing() {
    let mock = Mock::start().await;
    let t = Ht::new("shutdown-after-approve", &mock.up).await;
    let gate = Gate::new();
    t.app.pause.set_after_approve(Arc::clone(&gate));
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    let table = Arc::clone(&t.app.hold);
    let approve = tokio::spawn(async move { table.approve(&id, "alice").await });
    gate.arrived().await;
    // Approved, not yet past forward_started: the drain finds no Pending entry, and the start
    // claim then refuses.
    assert_eq!(t.app.hold.drain_pending(), 0);
    gate.release();
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&b)),
        (503, "unavailable".into(), "shutdown".into())
    );
    assert_eq!(approve.await.unwrap(), ApproveResult::ApprovedButAbandoned);
    assert_eq!(t.count("forward_started"), 0);
    assert_eq!(t.count("abandoned_after_approve"), 1);
    // The connection opens before the start claim; no request reaches the upstream.
    assert!(mock.recorded().is_empty());
    t.assert_clean();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_racing_the_start_claim_cannot_split_claim_and_forward_started() {
    let mock = Mock::start().await;
    let t = Ht::new("shutdown-in-claim", &mock.up).await;
    let gate = Gate::new();
    t.app.pause.set_in_claim(Arc::clone(&gate));
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    let table = Arc::clone(&t.app.hold);
    let approve = tokio::spawn(async move { table.approve(&id, "alice").await });
    tokio::time::timeout(Duration::from_secs(5), gate.arrived())
        .await
        .expect("handler is inside the claim, after the closure check");
    // The drain starts while the claim is open; it must wait for the claim and its
    // `forward_started` write rather than run between them.
    let table = Arc::clone(&t.app.hold);
    let drain = std::thread::spawn(move || table.drain_pending());
    // A plain thread sleep: the claim holds the table lock and may pin runtime workers.
    std::thread::sleep(Duration::from_millis(300));
    assert!(!drain.is_finished(), "the drain ran inside the claim");
    gate.release();
    let (p, _) = h.await.unwrap().unwrap();
    assert_eq!(p.status, 200);
    assert_eq!(approve.await.unwrap(), ApproveResult::Success);
    assert_eq!(drain.join().unwrap(), 0);
    // The claim won as a whole: forward_started is written before the table closed, and the
    // request completed.
    assert_eq!(t.count("forward_started"), 1);
    assert_eq!(mock.recorded().len(), 1);
    // After the drain the table is closed: a later claim sends nothing.
    assert!(!t.app.hold.claim_start(|| Ok::<(), ()>(())).unwrap_or(true));
    t.assert_clean();
}

// ---------------------------------------------------------------- 15

#[tokio::test]
async fn body_rules_refuse_before_anything_is_held_or_sent() {
    let mock = Mock::start().await;
    let t = Ht::new("rules", &mock.up).await;
    let big = "x".repeat(3000);
    let mk = |f: &dyn Fn(http::request::Builder) -> http::request::Builder, body: String| {
        f(Request::builder()
            .method("POST")
            .uri("/discord/hold/ok")
            .header("host", AUTH)
            .header("x-ap-caller-key", t.key.as_str())
            .header("content-length", body.len()))
        .body(Body::from(body))
        .unwrap()
    };
    let json = |b: http::request::Builder| {
        b.header("content-type", "application/json")
            .header("authorization", "Bot t")
    };
    let cases: Vec<(&str, Request<Body>, u16, &str)> = vec![
        ("over cap", mk(&json, big.clone()), 413, "body_too_large"),
        (
            "compressed",
            mk(&|b| json(b).header("content-encoding", "gzip"), "{}".into()),
            400,
            "content_encoding",
        ),
        (
            "empty encoding element",
            mk(&|b| json(b).header("content-encoding", ","), "{}".into()),
            400,
            "content_encoding",
        ),
        (
            "repeated identity",
            mk(
                &|b| json(b).header("content-encoding", "identity,,identity"),
                "{}".into(),
            ),
            400,
            "content_encoding",
        ),
        (
            "duplicate encoding header",
            mk(
                &|b| {
                    json(b)
                        .header("content-encoding", "identity")
                        .header("content-encoding", "identity")
                },
                "{}".into(),
            ),
            400,
            "content_encoding",
        ),
        (
            "no authorization",
            mk(
                &|b| b.header("content-type", "application/json"),
                "{}".into(),
            ),
            400,
            "credential_missing",
        ),
        (
            "multipart in cap",
            mk(
                &|b| {
                    b.header("content-type", "multipart/form-data; boundary=x")
                        .header("authorization", "Bot t")
                },
                "--x--".into(),
            ),
            400,
            "content_type",
        ),
        (
            "multipart over cap",
            mk(
                &|b| {
                    b.header("content-type", "multipart/form-data; boundary=x")
                        .header("authorization", "Bot t")
                },
                big.clone(),
            ),
            400,
            "content_type",
        ),
        (
            "no content type",
            mk(&|b| b.header("authorization", "Bot t"), "{}".into()),
            400,
            "content_type",
        ),
        (
            "text/plain",
            mk(
                &|b| {
                    b.header("content-type", "text/plain")
                        .header("authorization", "Bot t")
                },
                "{}".into(),
            ),
            400,
            "content_type",
        ),
    ];
    for (name, req, status, c) in cases {
        let (p, b) = t.send(req).await.unwrap();
        assert_eq!(p.status.as_u16(), status, "{name}");
        assert_eq!(decision(&p), "denied", "{name}");
        assert_eq!(code(&b), c, "{name}");
    }
    // An undeclared (chunked) body over the cap.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(4);
    tx.send(Ok(Bytes::from(vec![b'x'; 3000]))).await.unwrap();
    drop(tx);
    let chunked = Body::from_stream(futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx)));
    let req = t
        .builder(&t.key, "POST", "/discord/hold/ok")
        .header("content-type", "application/json")
        .header("transfer-encoding", "chunked")
        .body(chunked)
        .unwrap();
    let (p, b) = t.send(req).await.unwrap();
    assert_eq!(
        (p.status.as_u16(), code(&b)),
        (413, "body_too_large".into())
    );
    assert_eq!(mock.hits(), 0);
    assert_eq!(t.app.hold.pending_len(), 0);
    assert!(t.held_ids().is_empty());
}

#[tokio::test]
async fn a_stalled_held_body_is_503_and_not_held() {
    let mock = Mock::start().await;
    let t = Ht::new("stall-body", &mock.up).await;
    let (_tx, mut rx) = tokio::sync::mpsc::channel::<Result<Bytes, io::Error>>(4);
    let stalled = Body::from_stream(futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx)));
    let req = t
        .builder(&t.key, "POST", "/discord/hold/ok")
        .header("content-type", "application/json")
        .header("transfer-encoding", "chunked")
        .body(stalled)
        .unwrap();
    let (p, b) = t.send(req).await.unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&b)),
        (503, "unavailable".into(), "body_read_timeout".into())
    );
    assert!(t.held_ids().is_empty());
}

// ---------------------------------------------------------------- 17

async fn failed_connect(t: &Ht, mock_hits: &dyn Fn() -> usize) {
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::ConnectFailed
    );
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&b)),
        (503, "unavailable".into(), "connect_failed".into())
    );
    assert_eq!(t.transitions(), ["held", "approved", "connect_failed"]);
    assert_eq!(mock_hits(), 0);
}

#[tokio::test]
async fn a_refused_connection_is_connect_failed_with_no_forward_started() {
    let mock = Mock::start().await;
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let o = Opts {
        port: Some(dead),
        ..Opts::default()
    };
    let t = Ht::with("refused", &mock.up, o).await;
    failed_connect(&t, &|| mock.hits()).await;
}

#[tokio::test]
async fn a_failed_tls_handshake_is_connect_failed_with_no_forward_started() {
    // Accepts the TCP connection and closes it, so the handshake fails.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let a = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            a.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    });
    let mock = Mock::start().await;
    let o = Opts {
        port: Some(port),
        ..Opts::default()
    };
    let t = Ht::with("tls-fail", &mock.up, o).await;
    failed_connect(&t, &|| 0).await;
    assert!(accepted.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn a_reset_after_forward_started_closes_the_caller_with_no_completed() {
    let mock = Mock::start().await;
    let t = Ht::new("reset", &mock.up).await;
    for (n, path) in [
        "/discord/hold/reset-after-read",
        "/discord/hold/reset-before-read",
    ]
    .into_iter()
    .enumerate()
    {
        let h = t.spawn(t.post(path, "{}"));
        let id = t.held(n + 1).await;
        assert_eq!(
            t.app.hold.approve(&id, "alice").await,
            ApproveResult::Success
        );
        assert!(
            h.await.unwrap().is_err(),
            "{path}: connection must close without an answer"
        );
    }
    assert_eq!(t.count("forward_started"), 2);
    assert_eq!(t.count("completed"), 0);
}

// ---------------------------------------------------------------- 25

#[tokio::test]
async fn approved_requests_are_closed_at_the_idle_and_total_deadlines() {
    let mock = Mock::start().await;
    let o = Opts {
        extra: "request_deadline_secs = 2\nupstream_idle_secs = 1".into(),
        ..Opts::default()
    };
    let t = Ht::with("deadlines", &mock.up, o).await;

    // No byte for upstream_idle_secs after the head: the body ends in an error.
    let start = Instant::now();
    let n = t.held_ids().len() + 1;
    let h = t.spawn(t.post("/discord/hold/stall-body", "{}"));
    let id = t.held(n).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(p.status, 200);
    assert_eq!(&b[..], b"", "body is cut when it errors");
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_millis(1900),
        "{took:?}"
    );

    // A trickle never idles, so the total deadline closes it.
    let start = Instant::now();
    let n = t.held_ids().len() + 1;
    let h = t.spawn(t.post("/discord/hold/trickle", "{}"));
    let id = t.held(n).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    h.await.unwrap().unwrap();
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(1800) && took < Duration::from_millis(3200),
        "{took:?}"
    );

    // No answer at all: the total deadline, counted from forward_started, closes the caller.
    let start = Instant::now();
    let n = t.held_ids().len() + 1;
    let h = t.spawn(t.post("/discord/hold/stall", "{}"));
    let id = t.held(n).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    assert!(h.await.unwrap().is_err());
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(1800) && took < Duration::from_millis(3200),
        "{took:?}"
    );
    // Reset and timeouts after forward_started write no `completed`.
    assert_eq!(t.count("forward_started"), 3);
    assert_eq!(t.count("completed"), 0);
}

#[tokio::test]
async fn allowed_requests_are_closed_at_the_idle_and_total_deadlines() {
    let mock = Mock::start().await;
    let o = Opts {
        extra: "request_deadline_secs = 2\nupstream_idle_secs = 1".into(),
        ..Opts::default()
    };
    let t = Ht::with("allow-deadlines", &mock.up, o).await;
    let get = |path: &str| t.builder(&t.key, "GET", path).body(Body::empty()).unwrap();

    // No byte for upstream_idle_secs after the head: the body ends in an error.
    let start = Instant::now();
    let (p, b) = t.send(get("/discord/api/stall-body")).await.unwrap();
    assert_eq!(p.status, 200);
    assert_eq!(&b[..], b"", "body is cut when it errors");
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_millis(1900),
        "{took:?}"
    );

    // A trickle never idles, so the total deadline closes it.
    let start = Instant::now();
    t.send(get("/discord/api/trickle")).await.unwrap();
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(1800) && took < Duration::from_millis(3200),
        "{took:?}"
    );

    // No response head at all: the total deadline closes the caller.
    let start = Instant::now();
    assert!(t.send(get("/discord/api/stall")).await.is_err());
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(1800) && took < Duration::from_millis(3200),
        "{took:?}"
    );

    // Each of the three ends is one `allow` line with `upstream_reset`.
    let resets = t
        .lines()
        .iter()
        .filter(|v| v["decision"] == "allow" && v["code"] == "upstream_reset")
        .count();
    assert_eq!(resets, 3, "{}", t.text());
    t.assert_clean();
}

// ---------------------------------------------------------------- 29

#[tokio::test]
async fn a_failing_sink_before_the_hold_refuses_the_write_and_lets_reads_pass() {
    let mock = Mock::start().await;
    let sw = Switch::default();
    let o = Opts {
        sink: Some(sw.clone()),
        ..Opts::default()
    };
    let t = Ht::with("sink-before", &mock.up, o).await;
    sw.fail_all.store(true, Ordering::SeqCst);
    let (p, b) = t.send(t.post("/discord/hold/ok", "{}")).await.unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&b)),
        (503, "unavailable".into(), "audit_unavailable".into())
    );
    assert_eq!(t.app.hold.pending_len(), 0);
    assert_eq!(mock.hits(), 0);
    // An allowed read still passes with the sink down.
    let (p, _) = t
        .send(
            t.builder(&t.key, "GET", "/discord/api/x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(p.status, 200);
    // And a refusal for the failure did not start a cooldown.
    sw.fail_all.store(false, Ordering::SeqCst);
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    t.held(1).await;
    t.app.hold.drain_pending();
    h.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_failing_sink_between_approve_and_send_sends_nothing() {
    let raw = Raw::start().await;
    let sw = Switch::default();
    let mut o = Opts {
        sink: Some(sw.clone()),
        ..Opts::default()
    };
    o.limits.cooldown = Duration::from_secs(30);
    let t = Ht::with("sink-between", &raw.up, o).await;
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    *sw.fail_on.lock().unwrap() = Some("\"forward_started\"".into());
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::AuditUnavailable
    );
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&b)),
        (503, "unavailable".into(), "audit_unavailable".into())
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        raw.bytes.load(Ordering::SeqCst),
        0,
        "request bytes reached the upstream"
    );
    assert_eq!(t.count("forward_started"), 0);
    // A sink failure is not the identity's doing: no cooldown.
    *sw.fail_on.lock().unwrap() = None;
    let h2 = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id2 = t.held(2).await;
    assert_eq!(t.app.hold.state(&id2), Some(State::Pending));
    t.app.hold.deny(&id2, "alice");
    h2.await.unwrap().unwrap();
}

// ---------------------------------------------------------------- 18, 19 (direct), 24

async fn raw_exchange(addr: SocketAddr, head: String, body_len: usize) -> String {
    let c = TcpStream::connect(addr).await.unwrap();
    let (mut r, mut w) = c.into_split();
    let writer = tokio::spawn(async move {
        w.write_all(head.as_bytes()).await.unwrap();
        let chunk = vec![b'a'; 16 * 1024];
        let mut left = body_len;
        while left > 0 {
            let n = left.min(chunk.len());
            if w.write_all(&chunk[..n]).await.is_err() {
                break;
            }
            left -= n;
        }
        w
    });
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(5), r.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                out.extend_from_slice(&buf[..n]);
                if out.windows(4).any(|w| w == b"\r\n\r\n")
                    && String::from_utf8_lossy(&out).contains("\"code\"")
                {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
    let _ = writer.await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn a_denied_one_mebibyte_post_gets_a_readable_423() {
    let mock = Mock::start().await;
    let o = Opts {
        held_body_max: 1024 * 1024,
        ..Opts::default()
    };
    let t = Ht::with("big-denied", &mock.up, o).await;
    let addr = t.serve().await;
    let len = 1024 * 1024;
    // No grant for this path, and a hold route refused on content type.
    for (path, ctype, want_status, want_code) in [
        ("/discord/nogrant/x", "application/json", "423", "no_grant"),
        ("/discord/hold/ok", "text/plain", "400", "content_type"),
    ] {
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {AUTH}\r\nx-ap-caller-key: {}\r\nauthorization: Bot t\r\ncontent-type: {ctype}\r\ncontent-length: {len}\r\n\r\n",
            t.key
        );
        let out = raw_exchange(addr, head, len).await;
        assert!(
            out.starts_with(&format!("HTTP/1.1 {want_status}")),
            "{path}: {out:?}"
        );
        assert!(out.contains(want_code), "{path}: {out:?}");
    }
    assert_eq!(mock.hits(), 0);
}

#[tokio::test]
async fn expect_continue_refusals_skip_the_drain() {
    let mock = Mock::start().await;
    // The drain would wait `body_read_secs` (1 s in this fixture) for a body that never comes.
    let t = Ht::new("expect", &mock.up).await;
    let addr = t.serve().await;
    let head = format!(
        "POST /discord/nogrant/x HTTP/1.1\r\nHost: {AUTH}\r\nx-ap-caller-key: {}\r\nauthorization: Bot t\r\ncontent-type: application/json\r\ncontent-length: 1048576\r\nexpect: 100-continue\r\n\r\n",
        t.key
    );
    let start = Instant::now();
    // No body follows the head: the client waits for `100 Continue`, which never comes.
    let out = raw_exchange(addr, head, 0).await;
    assert!(out.starts_with("HTTP/1.1 423"), "{out:?}");
    assert!(
        start.elapsed() < Duration::from_millis(800),
        "{:?}",
        start.elapsed()
    );
}

#[cfg(not(feature = "stage1-probe"))]
#[tokio::test]
async fn the_probe_route_does_not_exist_without_the_feature() {
    let mock = Mock::start().await;
    let o = Opts {
        tail: "\n[probe]\nenabled = true\n".into(),
        ..Opts::default()
    };
    let t = Ht::with("no-probe", &mock.up, o).await;
    let (p, b) = t
        .send(
            t.builder(&t.key, "GET", "/__ap_probe/sleep/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        (p.status.as_u16(), decision(&p), code(&b)),
        (423, "denied".into(), "route_unknown".into())
    );
    assert_eq!(mock.hits(), 0);
}

#[tokio::test]
async fn webhook_path_tokens_are_redacted_in_every_hold_record() {
    let mock = Mock::start().await;
    let t = Ht::new("tokens", &mock.up).await;
    let path = format!("/discord/webhooks/1/{PATH_TOKEN}");
    let (p, _) = t.approved(t.post(&path, "{}")).await;
    assert_eq!(p.status, 200);
    assert!(
        mock.recorded()[0].uri.contains(PATH_TOKEN),
        "the upstream still gets the token"
    );
    assert!(t.text().contains("<redacted>"));
    t.assert_clean();
}

// ---------------------------------------------------------------- notification

/// Wait until the notifier has been called `n` times.
async fn calls_reach(n: &MockNotifier, count: usize) {
    for _ in 0..250 {
        if n.calls().len() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("notifier saw {} calls, wanted {count}", n.calls().len());
}

#[tokio::test]
async fn notify_once_per_distinct_entry_with_only_id_text_and_link() {
    let mock = Mock::start().await;
    let n = MockNotifier::new(false);
    let o = Opts {
        notifier: Some(Arc::clone(&n)),
        ..Opts::default()
    };
    let t = Ht::with("notify-one", &mock.up, o).await;
    let path = format!("/discord/hold/ok?channel=SENTINEL-CHANNEL-0003&{PATH_TOKEN}=1");
    let body = r#"{"content":"SENTINEL-BODY-0004"}"#;
    let first = t.spawn(t.post(&path, body));
    let id1 = t.held(1).await;
    calls_reach(&n, 1).await;
    // Identical retries supersede the first entry and announce nothing.
    let mut retries = Vec::new();
    for k in 2..=4 {
        retries.push(t.spawn(t.post(&path, body)));
        t.held(k).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(n.calls().len(), 1, "a supersede does not notify again");
    // A different request is a new distinct entry and notifies once.
    let other = t.spawn(t.post("/discord/hold/other", r#"{"x":1}"#));
    let id_other = t.held(5).await;
    calls_reach(&n, 2).await;
    let calls = n.calls();
    assert_eq!(
        calls[0],
        (
            id1.clone(),
            TEXT.to_string(),
            format!("https://approve.example.test/pending/{id1}")
        )
    );
    assert_eq!(calls[1].0, id_other);
    assert_eq!(calls[1].1, TEXT);
    assert_eq!(
        calls[1].2,
        format!("https://approve.example.test/pending/{id_other}")
    );
    for (id, text, url) in &calls {
        let all = format!("{id}{text}{url}");
        for needle in [
            "SENTINEL",
            PATH_TOKEN,
            "Bot",
            "channel",
            "content",
            "muse-pilot",
            &t.key,
        ] {
            assert!(!all.contains(needle), "payload leaks {needle}");
        }
    }
    assert_eq!(t.count("notify_failed"), 0);
    t.app.hold.deny(&id_other, "alice");
    other.await.unwrap().unwrap();
    let newest = t.held(4).await;
    t.app.hold.deny(&newest, "alice");
    first.await.unwrap().unwrap();
    for r in retries {
        r.await.unwrap().unwrap();
    }
    assert_eq!(mock.hits(), 0);
    t.assert_clean();
}

#[tokio::test]
async fn notify_failure_leaves_the_entry_to_expire_and_sends_nothing() {
    let mock = Mock::start().await;
    let n = MockNotifier::new(true);
    let mut o = Opts {
        notifier: Some(Arc::clone(&n)),
        ..Opts::default()
    };
    o.limits.hold = Duration::from_millis(900);
    let t = Ht::with("notify-fail", &mock.up, o).await;
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    calls_reach(&n, 1).await;
    for _ in 0..100 {
        if t.count("notify_failed") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(t.count("notify_failed"), 1);
    assert_eq!(
        t.app.hold.pending_len(),
        1,
        "the failure does not change the entry"
    );
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!((p.status.as_u16(), code(&b)), (410, "expired".into()));
    assert_eq!(mock.hits(), 0);
    assert_eq!(t.transitions(), ["held", "notify_failed", "expired"]);
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Expired
    );
    let line = t
        .lines()
        .into_iter()
        .find(|v| v["transition"] == "notify_failed")
        .unwrap();
    assert_eq!(line["code"], "notify_failed");
    t.assert_clean();
}

#[tokio::test]
async fn notify_absent_means_the_hold_just_waits() {
    let mock = Mock::start().await;
    let t = Ht::new("notify-none", &mock.up).await;
    let h = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(t.count("notify_failed"), 0);
    t.app.hold.deny(&id, "alice");
    h.await.unwrap().unwrap();
}

/// Every canonicalization attack form the fuzz work refuses on the plain path is refused on a
/// hold grant too, before the request can be held: nothing is admitted to the table, nothing is
/// written as `held`, no notification goes out and the upstream sees nothing.
#[tokio::test]
async fn canonicalization_attack_forms_are_refused_before_a_hold_exists() {
    let mock = Mock::start().await;
    let n = MockNotifier::new(false);
    let o = Opts {
        notifier: Some(Arc::clone(&n)),
        ..Opts::default()
    };
    let t = Ht::with("canon-hold", &mock.up, o).await;
    // (label, request path). Every path would match a hold pattern if the canonical-form check
    // let it through, so a bypass is held (the request waits) and not merely `no_grant`.
    let paths: &[(&str, &str)] = &[
        ("layered %252f", "/discord/hold/%252f"),
        ("layered %255c", "/discord/hold/%255c"),
        ("layered %25252e", "/discord/hold/%252525252e/messages"),
        (
            "layered dot-dot",
            "/discord/hold/%25%32%45%25%32%45/messages",
        ),
        ("layered %2500", "/discord/hold/%2500"),
        ("..%3b", "/discord/hold/..%3b/messages"),
        (".%3B mixed case", "/discord/hold/.%3B/messages"),
        ("..%253b layered", "/discord/hold/..%253b/messages"),
        ("mixed-case %2E%2e", "/discord/hold/%2E%2e/messages"),
        ("mixed-case %2F", "/discord/hold/1%2Fmessages"),
        ("mixed-case %5C", "/discord/hold/%5Cx"),
        ("semicolon dot-dot", "/discord/hold/..;/messages"),
        ("overlong utf8", "/discord/hold/%c0%ae/messages"),
        ("%u escape", "/discord/hold/%u002e"),
        (
            "escaped unreserved, lower hex",
            "/discord/hold/1/%6dessages",
        ),
        (
            "escaped unreserved, upper hex",
            "/discord/hold/1/%4Dessages",
        ),
        (
            "escaped unreserved in a wildcard segment",
            "/discord/hold/%4D",
        ),
        ("escaped hyphen", "/discord/hold/a%2Db/messages"),
        ("escaped tilde", "/discord/hold/%7E/messages"),
        ("layered escaped unreserved", "/discord/hold/1/%256Dessages"),
    ];
    // (label, request path, Host override, expected code)
    let mut forms: Vec<(String, String, Option<&str>, &str)> = Vec::new();
    for (label, p) in paths {
        forms.push((
            format!("header form: {label}"),
            (*p).to_string(),
            None,
            "path_ambiguous",
        ));
        forms.push((
            format!("path form: {label}"),
            format!("/ap/{}{}", t.key, p),
            None,
            "path_ambiguous",
        ));
    }
    for host in [
        "0x7f.0.0.1",
        "127.0.0.0x1",
        "gate.example.0xff",
        "2130706433",
    ] {
        forms.push((
            format!("hex-tail IP host {host}"),
            "/discord/hold/ok".to_string(),
            Some(host),
            "host_rejected",
        ));
    }
    for (label, path, host, want) in &forms {
        // Path-form requests carry no key header, so the refusal can only come from the path.
        let mut b = Request::builder()
            .method("POST")
            .uri(path.as_str())
            .header("host", AUTH)
            .header("authorization", format!("Bot {SENTINEL}"))
            .header("content-type", "application/json")
            .header("content-length", 2);
        if !path.starts_with("/ap/") {
            b = b.header("x-ap-caller-key", t.key.as_str());
        }
        let mut req = b.body(Body::from("{}")).unwrap();
        if let Some(h) = host {
            // The attack Host must be the only one.
            let hv = req.headers_mut();
            hv.remove("host");
            hv.insert("host", http::HeaderValue::from_str(h).unwrap());
        }
        let res = tokio::time::timeout(Duration::from_secs(3), t.send(req)).await;
        let (parts, body) = match res {
            Ok(Ok(r)) => r,
            // A refusal that closes the connection without a response is also not a hold.
            Ok(Err(())) => continue,
            Err(_) => panic!("{label}: the request waited, it was held or hung"),
        };
        assert_eq!(parts.status, 400, "{label}: status {}", parts.status);
        assert_eq!(code(&body), *want, "{label}");
        assert_ne!(decision(&parts), "held", "{label}");
        assert_eq!(t.app.hold.pending_len(), 0, "{label}: hold table not empty");
    }
    assert_eq!(t.app.hold.pending_len(), 0);
    assert_eq!(t.count("held"), 0, "a hold was recorded: {}", t.text());
    assert_eq!(t.count("forward_started"), 0);
    assert!(n.calls().is_empty(), "a notification was sent");
    assert_eq!(mock.recorded().len(), 0, "the upstream saw a request");
    // The same route still holds a clean request, so the refusals above came from the
    // canonical-form check and not from a broken fixture.
    let ok = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    calls_reach(&n, 1).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    let (parts, _) = ok.await.unwrap().unwrap();
    assert_eq!(parts.status, 200);
    let up = mock.recorded();
    assert_eq!(up.len(), 1);
    assert_eq!(
        up[0].uri, "/hold/ok",
        "forwarded path equals the matched path"
    );
}

/// The authenticated caller key repeated inside the route path or the query is refused before the
/// Trail has a path, before a hold exists and before the upstream is called, on the hold route and
/// on the allow route, in the header form and the path form, in every spelling. The key reaches
/// no audit line, no notification, no response body and no upstream request.
#[tokio::test]
async fn caller_key_repeated_in_the_path_or_query_is_refused_before_anything_is_built() {
    let mock = Mock::start().await;
    let n = MockNotifier::new(false);
    let o = Opts {
        notifier: Some(Arc::clone(&n)),
        ..Opts::default()
    };
    let t = Ht::with("key-echo", &mock.up, o).await;
    let k = t.key.clone();
    let digits = k.strip_prefix("apk_").unwrap().to_string();
    let enc = |s: &str| -> String { s.bytes().map(|b| format!("%{b:02x}")).collect() };
    // (label, method, route-relative path with query)
    let rels: Vec<(String, &str, String)> = vec![
        ("hold, exact".into(), "POST", format!("/discord/hold/{k}")),
        (
            "hold, upper case".into(),
            "POST",
            format!("/discord/hold/{}", k.to_uppercase()),
        ),
        (
            "hold, digits only".into(),
            "POST",
            format!("/discord/hold/{digits}"),
        ),
        (
            "hold, last segment of a deeper pattern".into(),
            "POST",
            format!("/discord/hold/1/{k}"),
        ),
        (
            "hold, percent-encoded".into(),
            "POST",
            format!("/discord/hold/{}", enc(&k)),
        ),
        (
            "hold, encoded prefix only".into(),
            "POST",
            format!("/discord/hold/%61pk_{digits}"),
        ),
        (
            "hold, doubly encoded".into(),
            "POST",
            format!("/discord/hold/{}", enc(&enc(&k))),
        ),
        (
            "hold, in the query".into(),
            "POST",
            format!("/discord/hold/ok?a={k}"),
        ),
        (
            "hold, encoded in the query".into(),
            "POST",
            format!("/discord/hold/ok?a={}", enc(&k)),
        ),
        (
            "hold, mixed case encoded in the query".into(),
            "POST",
            format!("/discord/hold/ok?a=%61PK%5f{}", digits.to_uppercase()),
        ),
        (
            "hold, doubly encoded in the query".into(),
            "POST",
            format!("/discord/hold/ok?a={}", enc(&enc(&k))),
        ),
        ("allow, exact".into(), "GET", format!("/discord/api/{k}")),
        (
            "allow, encoded".into(),
            "GET",
            format!("/discord/api/{}", enc(&k)),
        ),
        (
            "allow, in the query".into(),
            "GET",
            format!("/discord/api/x?token={k}"),
        ),
        (
            "allow, encoded in the query".into(),
            "GET",
            format!("/discord/api/x?token={}", enc(&digits)),
        ),
    ];
    for (label, method, rel) in &rels {
        for path_form in [false, true] {
            let (uri, header_key) = if path_form {
                (format!("/ap/{k}{rel}"), false)
            } else {
                (rel.clone(), true)
            };
            let mut b = Request::builder()
                .method(*method)
                .uri(uri.as_str())
                .header("host", AUTH)
                .header("authorization", format!("Bot {SENTINEL}"));
            if header_key {
                b = b.header("x-ap-caller-key", k.as_str());
            }
            let req = if *method == "POST" {
                b.header("content-type", "application/json")
                    .header("content-length", 2)
                    .body(Body::from("{}"))
                    .unwrap()
            } else {
                b.body(Body::empty()).unwrap()
            };
            let form = if path_form {
                "path form"
            } else {
                "header form"
            };
            let res = tokio::time::timeout(Duration::from_secs(3), t.send(req)).await;
            let (parts, body) = match res {
                Ok(Ok(r)) => r,
                Ok(Err(())) => continue,
                Err(_) => panic!("{form}: {label}: the request waited, it was held or hung"),
            };
            assert_eq!(parts.status, 400, "{form}: {label}");
            let c = code(&body);
            // An encoded copy inside the path is refused earlier, as an ambiguous path.
            assert!(
                c == "caller_key_ambiguous" || c == "path_ambiguous",
                "{form}: {label}: code {c}"
            );
            let text = String::from_utf8_lossy(&body).to_lowercase();
            assert!(!text.contains(&digits), "{form}: {label}: key in the body");
            assert_eq!(t.app.hold.pending_len(), 0, "{form}: {label}");
        }
    }
    // The plain forms (not encoded) must be named by the key-echo code specifically.
    for rel in [format!("/discord/hold/{k}"), format!("/discord/api/{k}")] {
        let method = if rel.contains("hold") { "POST" } else { "GET" };
        let req = t
            .builder(&t.key, method, &rel)
            .header("content-length", 0)
            .body(Body::empty())
            .unwrap();
        let (parts, body) = t.send(req).await.unwrap();
        assert_eq!(parts.status, 400);
        assert_eq!(code(&body), "caller_key_ambiguous", "{rel}");
    }
    assert_eq!(t.count("held"), 0, "a hold was recorded: {}", t.text());
    assert_eq!(t.count("forward_started"), 0);
    assert!(n.calls().is_empty(), "a notification was sent");
    assert_eq!(mock.recorded().len(), 0, "the upstream saw a request");
    t.assert_clean();
    let lower = t.text().to_lowercase();
    assert!(!lower.contains(&digits), "key digits in the audit: {lower}");
    assert!(!lower.contains(&enc(&digits)), "encoded key in the audit");
    // The same caller still holds and forwards a clean request.
    let ok = t.spawn(t.post("/discord/hold/ok", "{}"));
    let id = t.held(1).await;
    calls_reach(&n, 1).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    let (parts, _) = ok.await.unwrap().unwrap();
    assert_eq!(parts.status, 200);
    assert_eq!(mock.recorded()[0].uri, "/hold/ok");
}

// ---------------------------------------------------------------- option B (design 4.5)

const PILOT_NAME: &str = "muse-pilot-b";
const PILOT_TOKEN: &str = "SENTINEL-PILOT-TOKEN-0003";
const PILOT_AUTH: &str = "Bot SENTINEL-PILOT-TOKEN-0003";
const PILOT_ROTATED_AUTH: &str = "Bot SENTINEL-PILOT-TOKEN-0004";
const PILOT_KEYED_CALLER: &str = "SENTINEL-PILOT-KEYED-CALLER-0005";
const PILOT_WRITE: &str = "/discord/hold/ok/messages";
/// 2026-12-20T00:00:00Z, the first second of the last valid day.
const PILOT_LAST_DAY: u64 = 1_797_724_800;
/// 2026-12-21T00:00:00Z, the first refused second.
const PILOT_REFUSED: u64 = 1_797_811_200;

/// The pilot token, bound to `discord`, and its hold grant, appended to the fixture policy.
fn pilot_tail(expires: &str) -> String {
    format!(
        "\n[[token_identity]]\nname = \"{PILOT_NAME}\"\nroute = \"discord\"\n\
         token_sha256 = \"{}\"\nexpires = \"{expires}\"\n\n\
         [[grant]]\nidentity = \"{PILOT_NAME}\"\nroute = \"discord\"\nmethods = [\"POST\"]\n\
         decision = \"hold\"\npath_patterns = [\"/hold/*/messages\"]\n",
        sha256_hex(PILOT_AUTH)
    )
}

/// The fixture with the pilot token. The clock reads `now` and the returned handle moves it.
async fn pilot_ht(tag: &str, up: &Upstream, expires: &str, now: u64) -> (Ht, ManualClock) {
    let o = Opts {
        tail: pilot_tail(expires),
        ..Opts::default()
    };
    let mut t = Ht::with(tag, up, o).await;
    let clock = ManualClock::new(now);
    PtApp::set_clock(&mut t.app, Arc::new(clock.clone()));
    (t, clock)
}

/// A request with no caller key header and no `/ap/` prefix. `auth` is the Authorization value.
fn keyless(method: &str, path: &str, auth: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("host", AUTH);
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    let body = if method == "POST" {
        r#"{"content":"hi"}"#
    } else {
        ""
    };
    b.header("content-type", "application/json")
        .header("content-length", body.len())
        .body(Body::from(body))
        .unwrap()
}

fn assert_caller_rejected(p: &http::response::Parts, b: &Bytes) {
    assert_eq!(p.status, 401, "{}", String::from_utf8_lossy(b));
    assert_eq!(decision(p), "rejected");
    assert_eq!(code(b), "caller_rejected");
}

#[tokio::test]
async fn pilot_write_without_caller_key_is_held_and_sent_only_after_approval() {
    let mock = Mock::start().await;
    let (t, _clock) = pilot_ht("pilot-held", &mock.up, "2026-12-20", PILOT_LAST_DAY).await;
    let h = t.spawn(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)));
    let id = t.held(1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(mock.hits(), 0, "nothing is sent before the approval");
    assert_eq!(t.app.hold.state(&id), Some(State::Pending));
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(p.status, 200);
    assert_eq!(&b[..], b"ok");
    let recs = mock.recorded();
    assert_eq!(recs.len(), 1);
    assert!(header_values(&recs[0], "x-ap-caller-key").is_empty());
    assert_eq!(
        header_values(&recs[0], "authorization"),
        [PILOT_AUTH.as_bytes()]
    );
    let held = t
        .lines()
        .into_iter()
        .find(|v| v["transition"] == "held")
        .unwrap();
    assert_eq!(held["identity"], PILOT_NAME);
    assert_eq!(
        t.transitions(),
        ["held", "approved", "forward_started", "completed"]
    );
    t.assert_clean();
}

#[tokio::test]
async fn pilot_wrong_or_missing_token_is_refused_before_any_hold() {
    let mock = Mock::start().await;
    let (t, _clock) = pilot_ht("pilot-wrong", &mock.up, "2026-12-20", PILOT_LAST_DAY).await;
    // Another token, the bare token without its `Bot ` prefix, and no Authorization at all.
    for auth in [
        Some("Bot SENTINEL-PILOT-TOKEN-9999"),
        Some(PILOT_TOKEN),
        None,
    ] {
        let (p, b) = t.send(keyless("POST", PILOT_WRITE, auth)).await.unwrap();
        assert_caller_rejected(&p, &b);
    }
    assert_eq!(t.count("held"), 0);
    assert_eq!(mock.hits(), 0, "the upstream saw a request");
    t.assert_clean();
}

#[tokio::test]
async fn pilot_refuses_from_the_day_after_expiry_and_sends_nothing() {
    let mock = Mock::start().await;
    let (t, clock) = pilot_ht("pilot-expiry", &mock.up, "2026-12-20", PILOT_REFUSED - 1).await;
    // The last second of the last valid day: the write is held and approved as usual.
    let h = t.spawn(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)));
    let id = t.held(1).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    assert_eq!(h.await.unwrap().unwrap().0.status, 200);
    assert_eq!(mock.hits(), 1);
    // One second later the same request is refused: no hold, nothing forwarded.
    clock.set(PILOT_REFUSED);
    let (p, b) = t
        .send(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)))
        .await
        .unwrap();
    assert_caller_rejected(&p, &b);
    assert_eq!(t.count("held"), 1, "a hold was recorded after expiry");
    assert_eq!(mock.hits(), 1, "the upstream saw a request after expiry");
}

#[tokio::test]
async fn pilot_expiry_is_read_from_the_policy_file() {
    let mock = Mock::start().await;
    // The same day that the 2026-12-20 policy refuses is still inside this policy's window.
    let (t, _clock) = pilot_ht("pilot-config-expiry", &mock.up, "2027-01-31", PILOT_REFUSED).await;
    let h = t.spawn(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)));
    let id = t.held(1).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    assert_eq!(h.await.unwrap().unwrap().0.status, 200);
}

#[tokio::test]
async fn non_pilot_requests_still_need_the_caller_key() {
    let mock = Mock::start().await;
    let (t, _clock) = pilot_ht("pilot-keyed", &mock.up, "2026-12-20", PILOT_LAST_DAY).await;
    // Positive control: a keyed read on the same route is still forwarded.
    let keyed = t
        .builder(&t.key, "GET", "/discord/api/x")
        .body(Body::empty())
        .unwrap();
    let (p, _) = t.send(keyed).await.unwrap();
    assert_eq!(p.status, 200);
    // Keyless requests that the pilot does not cover: a read, a write to another path, a PUT to
    // the held path, and a held write with no token. Each is refused as a missing caller key.
    let refused = [
        ("GET", "/discord/api/x", Some(PILOT_AUTH)),
        ("POST", "/discord/hold/ok", Some(PILOT_AUTH)),
        ("PUT", PILOT_WRITE, Some(PILOT_AUTH)),
        ("POST", PILOT_WRITE, None),
    ];
    for (method, path, auth) in refused {
        let (p, b) = t.send(keyless(method, path, auth)).await.unwrap();
        assert_caller_rejected(&p, &b);
    }
    assert_eq!(mock.hits(), 1, "only the keyed read may reach the upstream");
    assert_eq!(t.count("held"), 0);
}

#[tokio::test]
async fn the_pilot_token_and_its_hash_reach_no_audit_record_or_error_body() {
    let mock = Mock::start().await;
    let (t, clock) = pilot_ht("pilot-leak", &mock.up, "2026-12-20", PILOT_LAST_DAY).await;
    let hash = sha256_hex(PILOT_AUTH);
    let mut bodies = Vec::new();
    let h = t.spawn(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)));
    let id = t.held(1).await;
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::Success
    );
    h.await.unwrap().unwrap();
    for auth in [
        Some("Bot SENTINEL-PILOT-TOKEN-9999"),
        Some(PILOT_TOKEN),
        None,
    ] {
        let (_, b) = t.send(keyless("POST", PILOT_WRITE, auth)).await.unwrap();
        bodies.push(b);
    }
    clock.set(PILOT_REFUSED);
    let (_, b) = t
        .send(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)))
        .await
        .unwrap();
    bodies.push(b);
    let audit = t.text();
    for needle in [PILOT_AUTH, PILOT_TOKEN, hash.as_str(), &hash[..16]] {
        assert!(!audit.contains(needle), "{needle} reached the audit stream");
        for b in &bodies {
            let body = String::from_utf8_lossy(b);
            assert!(!body.contains(needle), "{needle} reached an error body");
        }
    }
}

#[tokio::test]
async fn pilot_admitted_before_the_cutoff_is_not_forwarded_after_it() {
    let mock = Mock::start().await;
    let (t, clock) = pilot_ht("pilot-cross", &mock.up, "2026-12-20", PILOT_REFUSED - 1).await;
    // Admitted one second before the cutoff, so it is held as usual.
    let h = t.spawn(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)));
    let id = t.held(1).await;
    // The cutoff passes while the request waits, and the approval lands after it.
    clock.set(PILOT_REFUSED);
    assert_eq!(
        t.app.hold.approve(&id, "alice").await,
        ApproveResult::PolicyChanged
    );
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(p.status, 503, "{}", String::from_utf8_lossy(&b));
    assert_eq!(code(&b), "dropped_on_reload");
    assert_eq!(t.count("forward_started"), 0);
    assert_eq!(t.count("dropped_on_reload"), 1);
    // The connection may have opened before the claim refused; no request reached the upstream.
    assert!(
        mock.recorded().is_empty(),
        "the upstream saw a request after the cutoff"
    );
}

#[tokio::test]
async fn pilot_hold_admitted_before_a_token_rotation_is_not_forwarded_after_it() {
    let mock = Mock::start().await;
    let (t, _clock) = pilot_ht("pilot-rotate", &mock.up, "2026-12-20", PILOT_LAST_DAY).await;
    // Admitted with the old token, which the policy binds by `token_sha256`.
    let h = t.spawn(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)));
    let id = t.held(1).await;
    // The operator rotates the hash only: the name, the route and the grant stay as they were.
    t.rewrite(|s| s.replacen(&sha256_hex(PILOT_AUTH), &sha256_hex(PILOT_ROTATED_AUTH), 1));
    assert_eq!(
        t.approve_checked(&id).await,
        ApproveResult::PolicyChanged,
        "the held Authorization no longer matches the token in force"
    );
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(p.status, 503, "{}", String::from_utf8_lossy(&b));
    assert_eq!(code(&b), "dropped_on_reload");
    assert_eq!(t.count("forward_started"), 0);
    assert_eq!(t.count("dropped_on_reload"), 1);
    // `hits` counts accepted connections, which can open before the claim refuses. A request
    // is what reaches the upstream, so the recorded requests are the check.
    assert!(
        mock.recorded().is_empty(),
        "the upstream received a request after the rotation"
    );
}

#[tokio::test]
async fn pilot_callback_approve_is_not_forwarded_when_the_token_rotates_before_the_claim() {
    let mock = Mock::start().await;
    let (t, _clock) = pilot_ht("pilot-cb-rotate", &mock.up, "2026-12-20", PILOT_LAST_DAY).await;
    let h = t.spawn(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)));
    let id = t.held(1).await;
    let (nonce, _) = t.app.hold.test_secrets(&id).expect("pending");
    let gate = Gate::new();
    t.app.pause.set_after_approve(Arc::clone(&gate));
    // The callback approve transition runs under the token identity in force, so it starts.
    let started = t.app.hold.transition_by_callback(
        &id,
        &nonce,
        crate::hold::CallbackAction::Approve,
        "telegram-owner",
        |identity: &str, req: &crate::hold::HeldRequest| t.app.still_holds(identity, req),
    );
    let crate::hold::CallbackTransition::ApproveStarted(rx) = started else {
        panic!("the callback approve did not start");
    };
    let confirm = tokio::spawn(crate::hold::Table::await_confirm(rx));
    tokio::time::timeout(Duration::from_secs(5), gate.arrived())
        .await
        .expect("the handler reached the point before the start claim");
    // The operator rotates the token hash before the claim reads the policy.
    t.rewrite(|s| s.replacen(&sha256_hex(PILOT_AUTH), &sha256_hex(PILOT_ROTATED_AUTH), 1));
    t.app.reload_tick();
    gate.release();
    assert_eq!(confirm.await.unwrap(), ApproveResult::PolicyChanged);
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(p.status, 503, "{}", String::from_utf8_lossy(&b));
    assert_eq!(code(&b), "dropped_on_reload");
    assert_eq!(t.count("forward_started"), 0);
    assert!(
        mock.recorded().is_empty(),
        "the upstream received a request after the rotation"
    );
}

#[tokio::test]
async fn pilot_hold_admitted_with_a_token_is_not_forwarded_once_a_keyed_identity_takes_its_name() {
    let mock = Mock::start().await;
    let (t, _clock) = pilot_ht("pilot-mode", &mock.up, "2026-12-20", PILOT_LAST_DAY).await;
    // Admitted with the token, so the held entry is a token-admitted hold.
    let h = t.spawn(keyless("POST", PILOT_WRITE, Some(PILOT_AUTH)));
    let id = t.held(1).await;
    // The token identity is replaced by a keyed identity of the same name. The route and the
    // hold grant stay as they were.
    t.rewrite(|s| {
        s.replacen(
            &format!(
                "[[token_identity]]\nname = \"{PILOT_NAME}\"\nroute = \"discord\"\n\
                 token_sha256 = \"{}\"\nexpires = \"2026-12-20\"",
                sha256_hex(PILOT_AUTH)
            ),
            &format!(
                "[[identity]]\nname = \"{PILOT_NAME}\"\ncaller_key_sha256 = \"{}\"",
                sha256_hex(PILOT_KEYED_CALLER)
            ),
            1,
        )
    });
    assert_eq!(
        t.approve_checked(&id).await,
        ApproveResult::PolicyChanged,
        "a token-admitted hold must not survive its token identity being replaced"
    );
    let (p, b) = h.await.unwrap().unwrap();
    assert_eq!(p.status, 503, "{}", String::from_utf8_lossy(&b));
    assert_eq!(code(&b), "dropped_on_reload");
    assert_eq!(t.count("forward_started"), 0);
    assert_eq!(t.count("dropped_on_reload"), 1);
    assert!(
        mock.recorded().is_empty(),
        "the upstream received a request after the token identity was replaced"
    );
}

/// `s` with every byte percent-encoded.
fn pct_all(s: &str) -> String {
    s.bytes().map(|b| format!("%{b:02X}")).collect()
}

#[tokio::test]
async fn pilot_token_echoed_in_the_path_or_query_is_refused_before_any_hold() {
    let mock = Mock::start().await;
    let (t, _clock) = pilot_ht("pilot-echo", &mock.up, "2026-12-20", PILOT_LAST_DAY).await;
    let encoded = pct_all(PILOT_TOKEN);
    // Each spelling with the code it is refused with. An unreserved percent-escape in the path is
    // refused as ambiguous before the pilot is considered; the query is not subject to that rule.
    let cases = [
        (
            format!("/discord/hold/{PILOT_TOKEN}/messages"),
            "caller_key_ambiguous",
        ),
        (
            format!("/discord/hold/{encoded}/messages"),
            "path_ambiguous",
        ),
        (
            format!("/discord/hold/ok/messages?t={PILOT_TOKEN}"),
            "caller_key_ambiguous",
        ),
        (
            format!("/discord/hold/ok/messages?t={encoded}"),
            "caller_key_ambiguous",
        ),
        (
            format!("/discord/hold/ok/messages?t={}", pct_all(&encoded)),
            "caller_key_ambiguous",
        ),
    ];
    for (path, expected) in &cases {
        let (p, b) = t
            .send(keyless("POST", path, Some(PILOT_AUTH)))
            .await
            .unwrap();
        assert_eq!(p.status, 400, "{path}: {}", String::from_utf8_lossy(&b));
        assert_eq!(code(&b), *expected, "{path}");
    }
    assert_eq!(t.count("held"), 0, "a hold was built from a token echo");
    assert!(t.held_ids().is_empty(), "the approval page would list one");
    assert!(mock.recorded().is_empty(), "the upstream saw a token echo");
    let audit = t.text();
    for needle in [PILOT_TOKEN, encoded.as_str()] {
        assert!(!audit.contains(needle), "{needle} reached the audit stream");
    }
}

#[tokio::test]
async fn buttons_mode_renotifies_the_newest_entry_on_supersede() {
    let mock = Mock::start().await;
    let n = MockNotifier::new(false);
    let o = Opts {
        notifier: Some(Arc::clone(&n)),
        buttons: true,
        ..Opts::default()
    };
    let t = Ht::with("notify-buttons-supersede", &mock.up, o).await;
    let path = format!("/discord/hold/ok?channel=SENTINEL-CHANNEL-0003&{PATH_TOKEN}=1");
    let body = r#"{"content":"SENTINEL-BODY-0004"}"#;
    let _first = t.spawn(t.post(&path, body));
    let _id1 = t.held(1).await;
    calls_reach(&n, 1).await;
    // The first message's buttons are dead once superseded, so the newest entry is announced.
    let _second = t.spawn(t.post(&path, body));
    let id2 = t.held(2).await;
    calls_reach(&n, 2).await;
    let calls = n.calls();
    assert_eq!(calls[1].0, id2, "the newest entry is announced");
    assert_eq!(*n.with_buttons.lock().unwrap(), vec![true, true]);
}

#[tokio::test]
async fn buttons_mode_link_is_the_view_token_not_the_request_id() {
    let mock = Mock::start().await;
    let n = MockNotifier::new(false);
    let o = Opts {
        notifier: Some(Arc::clone(&n)),
        buttons: true,
        ..Opts::default()
    };
    let t = Ht::with("notify-buttons-link", &mock.up, o).await;
    let _first = t.spawn(t.post("/discord/hold/ok", r#"{"x":1}"#));
    let id = t.held(1).await;
    calls_reach(&n, 1).await;
    let link = n.calls()[0].2.clone();
    let token = link
        .strip_prefix(&format!("{VIEW_BASE}/view/"))
        .expect("view link");
    assert_eq!(token.len(), 32);
    assert_ne!(token, id);
    assert!(!link.contains(&id), "the link must not name the request id");
}
