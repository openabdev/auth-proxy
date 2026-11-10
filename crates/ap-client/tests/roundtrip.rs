//! Round trip against the real session server in ap-proxy. Covers hello, register, renew, end,
//! a proxy restart that forgets the registry, renew with unknown sessions, and resync.

use ap_broker::store::FileStore;
use ap_client::authority::Authority;
use ap_client::caller::{caller_sha256, new_caller_key};
use ap_proxy::audit_sink::AuditSink;
use ap_proxy::pipeline::{self, App};
use ap_proxy::{forward, listener, session_http};
use axum::body::Body;
use axum::http::Request;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
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
    let task = tokio::spawn(session_http::serve_unix(
        socket,
        session_http::router(Arc::clone(&app)),
    ));
    Server { app, task }
}

/// Status the agent listener would return for a request carrying `surrogate`. A registered
/// surrogate passes authorize, so the status is not 403. An unknown one is refused with 403.
async fn agent_status(app: &Arc<App>, caller: &str, surrogate: &str) -> u16 {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/ap/{caller}/kiro-krs/"))
        .header("host", "127.0.0.1:8443")
        .header("authorization", format!("Bearer {surrogate}"))
        .body(Body::from("{}"))
        .expect("request");
    pipeline::handle(Arc::clone(app), req)
        .await
        .status()
        .as_u16()
}

fn scratch_dir() -> PathBuf {
    // Short path: a Unix socket path is limited to about 100 bytes.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = PathBuf::from("/tmp").join(format!("apc-{}-{nanos}", std::process::id()));
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

    assert_ne!(
        agent_status(&server.app, &caller, s1.expose()).await,
        403,
        "live session passes authorize"
    );
    assert_eq!(
        agent_status(&server.app, &caller, s2.expose()).await,
        403,
        "ended session is refused"
    );

    server.stop().await;
    let restarted = start_server(&root, &caller_sha).await;
    assert_eq!(
        agent_status(&restarted.app, &caller, s1.expose()).await,
        403,
        "a restarted proxy forgets the registry"
    );

    // Renew reports s1 as unknown, the client resyncs its live list, and s1 is back.
    auth.renew().await.expect("renew after restart");
    assert_ne!(
        agent_status(&restarted.app, &caller, s1.expose()).await,
        403,
        "resync restores the live session"
    );
    assert_eq!(
        agent_status(&restarted.app, &caller, s2.expose()).await,
        403,
        "the ended session is not restored"
    );

    restarted.stop().await;
    let _ = std::fs::remove_dir_all(&root);
}
