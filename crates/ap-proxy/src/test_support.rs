//! Test fixtures: a TLS upstream under a throwaway CA, a proxy `App` over a temp policy file, and
//! random caller keys and surrogates. Test-only, never compiled into the binary.
//!
//! Credentials here are the literal `test-credential-0001`, which the spec names for tests. Caller
//! keys and surrogates are random per run. No fixture reaches a real service.

use std::convert::Infallible;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ap_broker::broker::Broker;
use ap_broker::registry::sha256_hex;
use ap_broker::store::FileStore;
use ap_core::session_wire::Entry;
use axum::body::Body;
use axum::extract::Request;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::audit_sink::AuditSink;
use crate::forward;
use crate::pipeline::App;

/// The route host. It is never resolved in DNS: the test client maps it to the fixture upstream.
pub const HOST: &str = "runtime.kiro.test.example";
/// The agent listener authority. Requests must send this Host.
pub const LISTEN: &str = "127.0.0.1:8443";
/// The credential value the fixture's secret file holds (with a trailing newline).
pub const CREDENTIAL: &str = "test-credential-0001";
/// Body cap for fixtures, in bytes.
pub const CAP: u64 = 1024;
pub const IDENTITY: &str = "pty-team-a";
pub const ROUTE: &str = "upstream";

/// `n` random bytes as lowercase hex.
pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    getrandom::getrandom(&mut bytes).expect("os randomness");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn caller_key() -> String {
    format!("apk_{}", random_hex(32))
}

pub fn surrogate_token() -> String {
    format!("aps_{}", random_hex(32))
}

/// A TLS upstream on loopback, with the CA that signed its certificate.
pub struct Upstream {
    pub addr: SocketAddr,
    /// TCP connections accepted so far. A refused request must leave this unchanged.
    pub hits: Arc<AtomicUsize>,
    ca_der: Vec<u8>,
}

/// Start the upstream. `/redirect` answers 302. Every other path echoes the request headers as
/// a JSON array of `[name, value]` pairs.
pub async fn start_upstream() -> Upstream {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let ca = ca_params.self_signed(&ca_key).expect("ca cert");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf_params = rcgen::CertificateParams::new(vec![HOST.to_string()]).expect("leaf params");
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("leaf cert");
    let chain: Vec<CertificateDer<'static>> = vec![leaf.der().clone(), ca.der().clone()];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server config");
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service_fn(echo))
                        .await;
                }
            });
        }
    });
    Upstream {
        addr,
        hits,
        ca_der: ca.der().to_vec(),
    }
}

async fn echo(req: hyper::Request<Incoming>) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    if req.uri().path() == "/redirect" {
        let resp = hyper::Response::builder()
            .status(302)
            .header("location", "https://elsewhere.test.example/next")
            .body(Full::new(Bytes::new()))
            .expect("redirect response");
        return Ok(resp);
    }
    let seen: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = serde_json::to_vec(&seen).unwrap_or_default();
    Ok(hyper::Response::new(Full::new(Bytes::from(body))))
}

/// The client the proxy uses in tests: production settings, with the fixture CA and the route
/// host mapped to the fixture address.
pub fn client_for(up: &Upstream) -> reqwest::Client {
    let root = reqwest::Certificate::from_der(&up.ca_der).expect("ca der");
    forward::client_builder()
        .add_root_certificate(root)
        .resolve(HOST, up.addr)
        .build()
        .expect("test client")
}

/// An audit sink whose lines can be read back.
pub fn buffer_sink() -> (AuditSink, Arc<Mutex<Vec<u8>>>) {
    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let buf = Arc::new(Mutex::new(Vec::new()));
    (AuditSink::new(Box::new(Shared(Arc::clone(&buf)))), buf)
}

/// The policy text. One identity, one credential, one route, one grant for POST and GET on `/`.
pub fn policy_text(caller_sha: &str, port: u16) -> String {
    format!(
        r#"version = 1

[listen]
proxy = "{LISTEN}"

[limits]
max_body_bytes = {CAP}

[[identity]]
name = "{IDENTITY}"
caller_key_sha256 = "{caller_sha}"

[[route]]
name = "{ROUTE}"
host = "{HOST}"
port = {port}
pass_headers = ["tokentype"]

[[credential]]
id = "kiro"
source = "k8s:auth-proxy-kiro:api_key"
routes = ["{ROUTE}"]

[[grant]]
identity = "{IDENTITY}"
credential = "kiro"
route = "{ROUTE}"
methods = ["POST", "GET"]
paths = ["/"]
"#
    )
}

/// A scratch directory under the system temp dir, removed when dropped.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("apx-{tag}-{}", random_hex(6)));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A proxy over a fresh policy file, secret store and token directory.
pub struct Fixture {
    pub app: Arc<App>,
    pub caller: String,
    pub audit: Arc<Mutex<Vec<u8>>>,
    pub policy_path: PathBuf,
    /// Removes the scratch directory when the fixture drops.
    pub _scratch: Scratch,
}

impl Fixture {
    pub fn new(tag: &str, up: &Upstream) -> Fixture {
        let scratch = Scratch::new(tag);
        let root = scratch.path().to_path_buf();
        let caller = caller_key();
        let policy_path = root.join("policy.toml");
        std::fs::write(
            &policy_path,
            policy_text(&sha256_hex(&caller), up.addr.port()),
        )
        .expect("write policy");

        let secret_dir = root.join("secrets").join("auth-proxy-kiro");
        std::fs::create_dir_all(&secret_dir).expect("secret dir");
        std::fs::write(secret_dir.join("api_key"), format!("{CREDENTIAL}\n")).expect("secret");
        std::fs::create_dir_all(root.join("tokens")).expect("token dir");

        let cfg = ap_core::config::load(&std::fs::read_to_string(&policy_path).expect("read"))
            .expect("fixture config is valid");
        let broker: Arc<dyn Broker> = Arc::new(FileStore::new(root.join("secrets")));
        let (sink, audit) = buffer_sink();
        let app = App::new(
            policy_path.clone(),
            cfg,
            root.join("tokens"),
            broker,
            sink,
            client_for(up),
        );
        Fixture {
            app,
            caller,
            audit,
            policy_path,
            _scratch: scratch,
        }
    }

    /// Everything written to the audit sink so far, as text.
    pub fn audit_text(&self) -> String {
        let bytes = self.audit.lock().expect("audit buffer").clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// Start an authority for `identity`, register one session, and return its surrogate.
pub fn register_session(app: &App, identity: &str, session: &str, generation: u64) -> String {
    let mut reg = app.registry.lock().expect("registry");
    let now = reg.now();
    let token = reg.hello(identity, now).expect("hello");
    let surrogate = surrogate_token();
    let entry = Entry {
        session: session.to_string(),
        generation,
        surrogate_sha256: sha256_hex(&surrogate),
        credentials: vec!["kiro".to_string()],
    };
    reg.register(identity, &token, entry, now)
        .expect("register");
    surrogate
}

/// An agent request to `/ap/<caller>/<route>/<path>` with the surrogate in the Bearer header.
pub fn agent_request(method: &str, path: &str, caller: &str, surrogate: &str) -> Request {
    Request::builder()
        .method(method)
        .uri(format!("/ap/{caller}/{ROUTE}{path}"))
        .header("host", LISTEN)
        .header("authorization", format!("Bearer {surrogate}"))
        .body(Body::empty())
        .expect("agent request")
}
