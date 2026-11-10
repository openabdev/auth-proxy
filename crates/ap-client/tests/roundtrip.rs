//! Round trip against the real session server in ap-proxy. Covers hello, register, renew, end,
//! a proxy restart that forgets the registry, renew with unknown sessions, resync, a failed end
//! that is retried, and an admin revoke-all.

use ap_broker::store::FileStore;
use ap_client::authority::Authority;
use ap_client::caller::{caller_sha256, new_caller_key};
use ap_client::uds;
use ap_proxy::admin_http;
use ap_proxy::audit_sink::AuditSink;
use ap_proxy::pipeline::{self, App};
use ap_proxy::session_http::serve_unix;
use ap_proxy::{forward, listener, session_http};
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

fn config_text(caller_sha: &str) -> String {
    format!(
        r#"version = 1

[listen]
proxy = "127.0.0.1:8443"

[[identity]]
name = "pty-a"
caller_key_sha256 = "{caller_sha}"

[[route]]
name = "kiro-krs"
host = "runtime.us-east-1.kiro.dev"

[[credential]]
id = "kiro"
source = "k8s:auth-proxy-kiro:api_key"
routes = ["kiro-krs"]

[[grant]]
identity = "pty-a"
credential = "kiro"
route = "kiro-krs"
methods = ["POST"]
paths = ["/"]
"#
    )
}

/// A running session server. `app` is the state the agent listener would share.
struct Server {
    app: Arc<App>,
    task: JoinHandle<()>,
}

impl Server {
    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Start the session plane on `root/session.sock`. The token hashes live in `root/tokens`, so a
/// second start over the same `root` is a restart that keeps the authority tokens and drops the
/// registry.
async fn start_server(root: &Path, caller_sha: &str) -> Server {
    let cfg_path = root.join("auth-proxy.toml");
    let text = config_text(caller_sha);
    std::fs::write(&cfg_path, &text).expect("write config");
    let cfg = ap_core::config::load(&text).expect("valid config");
    let app = App::new(
        cfg_path,
        cfg,
        root.join("tokens"),
        Arc::new(FileStore::new(root.join("secrets"))),
        AuditSink::new(Box::new(std::io::sink())),
        forward::client().expect("upstream client"),
    );
    let socket = listener::bind_session_socket(&root.join("session.sock")).expect("bind socket");
    let task = tokio::spawn(serve_unix(socket, session_http::router(Arc::clone(&app))));
    Server { app, task }
}

/// Serve the admin router on `root/admin.sock`, the socket the revoke-all operator uses.
fn start_admin(root: &Path, app: Arc<App>) -> JoinHandle<()> {
    let listener = UnixListener::bind(root.join("admin.sock")).expect("bind admin socket");
    tokio::spawn(serve_unix(listener, admin_http::router(app)))
}

/// Run one request carrying `surrogate` through the authorize step. Returns the status and the
/// body. A refused surrogate names its code (`surrogate_*`) in the body.
async fn agent_response(app: &Arc<App>, caller: &str, surrogate: &str) -> (u16, String) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/ap/{caller}/kiro-krs/"))
        .header("host", "127.0.0.1:8443")
        .header("authorization", format!("Bearer {surrogate}"))
        .body(Body::from("{}"))
        .expect("request");
    let resp = pipeline::handle(Arc::clone(app), req).await;
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// True when authorize refused the surrogate. A request that passed authorize is refused, if at
/// all, by a later step, and its body carries no `surrogate_*` code.
async fn surrogate_refused(app: &Arc<App>, caller: &str, surrogate: &str) -> bool {
    let (status, body) = agent_response(app, caller, surrogate).await;
    let refused = body.contains("surrogate_");
    assert!(
        !refused || status == 403,
        "surrogate refusal is a 403: {status} {body}"
    );
    refused
}

fn scratch_dir() -> PathBuf {
    // Short path: a Unix socket path is limited to about 100 bytes. The counter makes the name
    // unique even when the clock's resolution gives two tests the same timestamp; without it
    // parallel tests shared one directory and failed to bind the same socket path.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from("/tmp").join(format!("apc-{}-{nanos}-{n}", std::process::id()));
    std::fs::create_dir_all(dir.join("tokens")).expect("tokens dir");
    std::fs::create_dir_all(dir.join("secrets")).expect("secrets dir");
    dir
}

#[tokio::test]
async fn restart_restores_live_sessions_and_keeps_ended_ones_refused() {
    let root = scratch_dir();
    let caller = new_caller_key();
    let caller_sha = caller_sha256(&caller);
    let server = start_server(&root, &caller_sha).await;
    let socket = root.join("session.sock");

    let auth = Authority::start("pty-a", socket.clone())
        .await
        .expect("hello");
    let s1 = auth
        .register("s1", 1, vec!["kiro".into()])
        .await
        .expect("register s1");
    let s2 = auth
        .register("s2", 1, vec!["kiro".into()])
        .await
        .expect("register s2");
    auth.renew().await.expect("renew with both live");
    auth.end("s2", 1).await.expect("end s2");

    assert!(
        !surrogate_refused(&server.app, &caller, s1.expose()).await,
        "live session passes authorize"
    );
    assert!(
        surrogate_refused(&server.app, &caller, s2.expose()).await,
        "ended session is refused"
    );

    server.stop().await;
    let restarted = start_server(&root, &caller_sha).await;
    assert!(
        surrogate_refused(&restarted.app, &caller, s1.expose()).await,
        "a restarted proxy forgets the registry"
    );

    // Renew reports s1 as unknown, the client resyncs its live list, and s1 is back.
    auth.renew().await.expect("renew after restart");
    assert!(
        !surrogate_refused(&restarted.app, &caller, s1.expose()).await,
        "resync restores the live session"
    );
    assert!(
        surrogate_refused(&restarted.app, &caller, s2.expose()).await,
        "the ended session is not restored"
    );

    restarted.stop().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn failed_end_is_retried_and_not_resynced_after_restart() {
    let root = scratch_dir();
    let caller = new_caller_key();
    let caller_sha = caller_sha256(&caller);
    let server = start_server(&root, &caller_sha).await;
    let socket = root.join("session.sock");

    let auth = Authority::start("pty-a", socket.clone())
        .await
        .expect("hello");
    let s1 = auth
        .register("s1", 1, vec!["kiro".into()])
        .await
        .expect("register s1");
    assert!(!surrogate_refused(&server.app, &caller, s1.expose()).await);

    // The proxy is down, so the DELETE fails and end reports the error.
    server.stop().await;
    assert!(
        auth.end("s1", 1).await.is_err(),
        "end while the proxy is down fails"
    );

    // The proxy restarts with an empty registry. The next renew must not send s1 back, and the
    // pending DELETE is answered 404, which clears it.
    let restarted = start_server(&root, &caller_sha).await;
    auth.renew().await.expect("renew after restart");
    assert!(
        surrogate_refused(&restarted.app, &caller, s1.expose()).await,
        "the ended session stays refused after renew"
    );
    auth.renew().await.expect("a later renew stays clean");
    assert!(
        surrogate_refused(&restarted.app, &caller, s1.expose()).await,
        "the ended session is not resynced in a later round"
    );

    restarted.stop().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn revoke_all_recovers_without_restart() {
    let root = scratch_dir();
    let caller = new_caller_key();
    let caller_sha = caller_sha256(&caller);
    let server = start_server(&root, &caller_sha).await;
    let admin = start_admin(&root, Arc::clone(&server.app));
    let socket = root.join("session.sock");

    let auth = Authority::start("pty-a", socket.clone())
        .await
        .expect("hello");
    let s1 = auth
        .register("s1", 1, vec!["kiro".into()])
        .await
        .expect("register s1");
    let s2 = auth
        .register("s2", 1, vec!["kiro".into()])
        .await
        .expect("register s2");
    auth.renew().await.expect("renew with both live");

    let revoked = uds::post_json(
        &root.join("admin.sock"),
        "/admin/v1/revoke-all",
        None,
        &serde_json::json!({}),
    )
    .await
    .expect("revoke-all");
    assert_eq!(revoked.status, 200);
    assert!(surrogate_refused(&server.app, &caller, s1.expose()).await);
    assert!(surrogate_refused(&server.app, &caller, s2.expose()).await);

    // Renew reports both as unknown. Their resync is rejected with 409, and the client drops
    // them and resyncs the rest. Every later round must succeed.
    auth.renew().await.expect("renew after revoke-all");
    auth.renew().await.expect("second renew after revoke-all");
    assert!(surrogate_refused(&server.app, &caller, s1.expose()).await);

    admin.abort();
    server.stop().await;
    let _ = std::fs::remove_dir_all(&root);
}
