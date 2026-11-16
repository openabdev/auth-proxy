//! The agent-runtime API, driven against the real session plane of `ap-proxy`. The shim takes its
//! authority over a Unix socket with a signed hello, so every register and revoke that reaches the
//! proxy is a real call. Requests go through the router with `tower::ServiceExt::oneshot`.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ap_broker::expiry::file_in;
use ap_broker::registry::sha256_hex;
use ap_broker::store::FileStore;
use ap_client::authority::Authority;
use ap_client::proof::RuntimeKey;
use ap_proxy::audit_sink::AuditSink;
use ap_proxy::pipeline::App;
use ap_proxy::{forward, listener, session_http};
use ap_runtime_shim::agent_api::{self, Shim};
use axum::body::Body;
use axum::http::Request;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const IDENTITY: &str = "pty-a";
const SEED: [u8; 32] = [7u8; 32];

/// A scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).expect("os randomness");
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("aps-{tag}-{hex}"));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A writer whose bytes the test can read back.
#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("buffer lock")).into_owned()
    }
}

fn config_text(runtime_pubkey: &str) -> String {
    format!(
        r#"version = 1

[listen]
proxy = "127.0.0.1:8443"

[[identity]]
name = "{IDENTITY}"
runtime_pubkey = "{runtime_pubkey}"
caller_key_sha256 = "{caller}"

[[route]]
name = "kiro-krs"
host = "runtime.us-east-1.kiro.dev"

[[credential]]
id = "kiro"
source = "k8s:auth-proxy-kiro:api_key"
routes = ["kiro-krs"]

[[grant]]
identity = "{IDENTITY}"
credential = "kiro"
route = "kiro-krs"
methods = ["POST"]
paths = ["/"]
"#,
        caller = sha256_hex("apk_test-caller-key")
    )
}

/// A running shim whose authority is live on a real proxy session plane.
struct Harness {
    shim: Arc<Shim>,
    audit: Buf,
    _scratch: Scratch,
}

async fn harness(tag: &str) -> Harness {
    let scratch = Scratch::new(tag);
    let root = scratch.0.clone();
    let pubkey = RuntimeKey::from_seed_b64(&STANDARD.encode(SEED))
        .expect("seed")
        .public_key_b64();

    let cfg_path = root.join("auth-proxy.toml");
    let text = config_text(&pubkey);
    std::fs::write(&cfg_path, &text).expect("write config");
    let cfg = ap_core::config::load(&text).expect("config");
    std::fs::create_dir_all(root.join("tokens")).expect("tokens");
    std::fs::write(
        file_in(&root.join("tokens")),
        "auth-proxy session expiry v1\n",
    )
    .expect("expiry store");

    let audit = Buf::default();
    let app = App::new(
        cfg_path,
        cfg,
        root.join("tokens"),
        file_in(&root.join("tokens")),
        Arc::new(FileStore::new(root.join("secrets"))),
        AuditSink::new(Box::new(audit.clone())),
        forward::client().expect("client"),
    )
    .expect("app");
    let socket = listener::bind_session_socket(&root.join("session.sock")).expect("bind");
    tokio::spawn(session_http::serve_unix(
        socket,
        session_http::router(Arc::clone(&app)),
    ));

    let key = Arc::new(RuntimeKey::from_seed_b64(&STANDARD.encode(SEED)).expect("seed"));
    let authority = Authority::start(IDENTITY, root.join("session.sock"), key)
        .await
        .expect("hello");
    Harness {
        shim: Shim::new(IDENTITY.to_string(), authority),
        audit,
        _scratch: scratch,
    }
}

/// Send one request to the agent API and return the status and the decoded JSON body (or `Null`).
async fn send(shim: &Arc<Shim>, method: &str, uri: &str, body: Option<Vec<u8>>) -> (u16, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(match body {
            Some(b) => Body::from(b),
            None => Body::empty(),
        })
        .expect("request");
    let resp = agent_api::router(Arc::clone(shim))
        .oneshot(req)
        .await
        .expect("router");
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn register_body(session: &str, generation: u64, credentials: &[&str]) -> Vec<u8> {
    json!({ "session": session, "generation": generation, "credentials": credentials })
        .to_string()
        .into_bytes()
}

#[tokio::test]
async fn register_returns_a_surrogate_and_the_proxy_records_its_digest() {
    let h = harness("register").await;
    let (status, body) = send(
        &h.shim,
        "POST",
        "/v1/session",
        Some(register_body("s1", 1, &["kiro"])),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let surrogate = body["surrogate"].as_str().expect("surrogate").to_string();
    assert!(surrogate.starts_with("aps_"));
    assert_eq!(surrogate.len(), 68);

    // The proxy holds only the digest. Its audit line carries the first 12 characters of it.
    let digest = sha256_hex(&surrogate);
    let audit = h.audit.text();
    assert!(
        audit.contains(&format!(
            "\"surrogate_sha256_prefix\":\"{}\"",
            &digest[..12]
        )),
        "{audit}"
    );
    assert!(!audit.contains(&surrogate), "surrogate in the proxy audit");

    let (_, status_body) = send(&h.shim, "GET", "/v1/status", None).await;
    assert_eq!(
        status_body["sessions"],
        json!([{ "session": "s1", "generation": 1 }])
    );
}

#[tokio::test]
async fn revoke_of_a_key_the_runtime_never_registered_is_204_with_no_proxy_call() {
    let h = harness("untracked").await;
    let before = h.audit.text().lines().count();
    let (status, _) = send(&h.shim, "DELETE", "/v1/session/never/9", None).await;
    assert_eq!(status, 204);
    assert_eq!(
        h.audit.text().lines().count(),
        before,
        "the proxy was called"
    );
}

#[tokio::test]
async fn revoke_ends_a_registered_session_at_the_proxy() {
    let h = harness("revoke").await;
    let (status, _) = send(
        &h.shim,
        "POST",
        "/v1/session",
        Some(register_body("s2", 4, &["kiro"])),
    )
    .await;
    assert_eq!(status, 201);

    let (status, _) = send(&h.shim, "DELETE", "/v1/session/s2/4", None).await;
    assert_eq!(status, 204);
    let (_, status_body) = send(&h.shim, "GET", "/v1/status", None).await;
    assert_eq!(status_body["sessions"], json!([]));
    assert!(h.audit.text().contains("\"op\":\"revoke\""));
}

#[tokio::test]
async fn hello_and_challenge_are_not_operations_on_the_agent_socket() {
    let h = harness("nohello").await;
    for (method, uri) in [
        ("POST", "/v1/hello"),
        ("GET", "/v1/hello/challenge"),
        ("POST", "/v1/hello/challenge"),
        ("POST", "/v1/renew"),
        ("GET", "/v1/sessions"),
        ("GET", "/"),
    ] {
        let body = (method == "POST").then(|| br#"{"identity":"pty-a"}"#.to_vec());
        let (status, reply) = send(&h.shim, method, uri, body).await;
        assert_eq!(status, 404, "{method} {uri}");
        assert_eq!(reply["error"], "unknown_operation", "{method} {uri}");
    }
}

#[tokio::test]
async fn a_listed_path_with_the_wrong_method_is_405() {
    let h = harness("method").await;
    let (status, reply) = send(&h.shim, "GET", "/v1/session", None).await;
    assert_eq!(status, 405);
    assert_eq!(reply["error"], "method_not_allowed");
    let (status, _) = send(&h.shim, "POST", "/v1/status", None).await;
    assert_eq!(status, 405);
}

#[tokio::test]
async fn an_oversized_body_is_413() {
    let h = harness("big").await;
    let big = vec![b'a'; ap_core::session_wire::BODY_CAP + 1];
    let (status, reply) = send(&h.shim, "POST", "/v1/session", Some(big)).await;
    assert_eq!(status, 413);
    assert_eq!(reply["error"], "body_too_large");
}

#[tokio::test]
async fn an_ungranted_credential_passes_through_from_the_proxy() {
    let h = harness("grant").await;
    let (status, reply) = send(
        &h.shim,
        "POST",
        "/v1/session",
        Some(register_body("s3", 1, &["not-granted"])),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(reply["error"], "credential_not_granted");
}

#[tokio::test]
async fn a_bad_session_name_names_the_field() {
    let h = harness("badsess").await;
    let (status, reply) = send(
        &h.shim,
        "POST",
        "/v1/session",
        Some(register_body("bad/name", 1, &["kiro"])),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(reply["error"], "invalid_field");
    assert_eq!(reply["field"], "session");
}

#[tokio::test]
async fn a_body_with_an_unknown_field_is_invalid_body() {
    let h = harness("extra").await;
    let body = json!({
        "session": "s4",
        "generation": 1,
        "credentials": ["kiro"],
        "identity": "someone-else",
    })
    .to_string()
    .into_bytes();
    let (status, reply) = send(&h.shim, "POST", "/v1/session", Some(body)).await;
    assert_eq!(status, 400);
    assert_eq!(reply["error"], "invalid_body");
}

#[tokio::test]
async fn a_non_numeric_generation_on_revoke_names_the_field() {
    let h = harness("badgen").await;
    let (status, reply) = send(&h.shim, "DELETE", "/v1/session/s1/x", None).await;
    assert_eq!(status, 400);
    assert_eq!(reply["field"], "generation");
}
