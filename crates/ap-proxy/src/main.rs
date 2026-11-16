//! `auth-proxy`: the Phase 1 credential-swapping reverse proxy (Kubernetes).
//!
//! One process: the agent listener (the only TCP listener, loopback only), the
//! session-plane Unix socket, the admin Unix socket, the in-process broker and
//! the S1 file store. A startup problem is exit code 2 with the reason on
//! stderr, so a bad config is CrashLoopBackOff and never a half-working proxy.

mod admin;
mod agent;
mod app;
mod args;
mod audit;
mod plane_http;
mod sock;

use ap_broker::{FileStore, LocalBroker, PlaneConfig, RegistryConfig, SessionPlane, SystemClock};
use ap_core::PolicyStore;
use app::App;
use args::{Args, Parsed};
use axum::serve::ListenerExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    // A panic message can embed the value that caused it. Print a fixed line.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("auth-proxy: internal error (panic); details withheld");
    }));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(real_main());
    std::process::exit(code);
}

async fn real_main() -> i32 {
    let args = match args::parse(std::env::args().skip(1), &|k| std::env::var(k).ok()) {
        Ok(Parsed::Run(a)) => *a,
        Ok(Parsed::Help) => {
            print!("{}", args::USAGE);
            return 0;
        }
        Err(e) => {
            eprintln!("auth-proxy: {e}");
            return 2;
        }
    };
    match run(args).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("auth-proxy: {e}");
            2
        }
    }
}

fn router<H, T>(h: H, app: Arc<App>) -> axum::Router
where
    H: axum::handler::Handler<T, Arc<App>>,
    T: 'static,
{
    axum::Router::new().fallback(h).with_state(app)
}

fn default_authorities(listen: SocketAddr) -> Vec<String> {
    let host = if listen.is_ipv4() {
        "127.0.0.1"
    } else {
        "[::1]"
    };
    vec![
        format!("{host}:{}", listen.port()),
        format!("localhost:{}", listen.port()),
    ]
}

fn build_client(args: &Args, policy: &ap_core::Policy) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        // Never follow redirects: the client gets the 3xx and the credential
        // stays with this process.
        .redirect(reqwest::redirect::Policy::none())
        .tcp_nodelay(true)
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(60));
    if let Some(ca) = &args.ca_file {
        let pem = std::fs::read(ca).map_err(|e| format!("read --ca-file: {}", e.kind()))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|_| "--ca-file is not a PEM certificate".to_string())?;
        b = b.tls_built_in_root_certs(false).add_root_certificate(cert);
    }
    // Test-only resolver override from the policy (like curl --resolve), present
    // only in `test-resolve` builds (always `None` in a shipped build, whose
    // policy parser rejects the key). The destination identity (SNI, Host,
    // certificate name) stays the route host. It is read at startup; a reload
    // that adds one has no effect.
    for r in &policy.config().routes {
        if let Some(a) = r.resolve_override() {
            b = b.resolve(&r.host, a);
        }
    }
    b.build()
        .map_err(|_| "cannot build the upstream client".to_string())
}

async fn run(args: Args) -> Result<(), String> {
    // Policy: the whole file is validated, or the proxy does not start.
    let store = PolicyStore::open(&args.policy).map_err(|e| format!("policy rejected: {e}"))?;
    let snap = store.current().map_err(|_| {
        format!(
            "policy rejected: {}",
            store.last_error().unwrap_or_else(|| "unavailable".into())
        )
    })?;

    // Exactly one TCP listener, on loopback.
    let policy_listener = snap.config().listener.as_ref();
    let listen = match (args.listen, policy_listener.map(|l| l.listen)) {
        (Some(a), Some(b)) if a != b => {
            return Err("--listen differs from the policy's [listener].listen".into())
        }
        (Some(a), _) | (None, Some(a)) => a,
        (None, None) => {
            return Err("no listener: pass --listen or set [listener] in the policy".into())
        }
    };
    if !listen.ip().is_loopback() || listen.port() == 0 {
        return Err("the agent listener must be a loopback address with a non-zero port".into());
    }
    let authorities = match policy_listener {
        Some(l) => l.effective_authorities(),
        None => default_authorities(listen),
    };

    for c in &snap.config().credentials {
        if !FileStore::supports(&c.source) {
            return Err(format!(
                "credential {}: this source kind is not supported in Phase 1 (use k8s: or file:)",
                c.id
            ));
        }
    }

    // State and the in-process broker.
    std::fs::create_dir_all(&args.state_dir)
        .map_err(|e| format!("create --state-dir: {}", e.kind()))?;
    let plane = Arc::new(SessionPlane::new(
        PlaneConfig {
            registry: RegistryConfig {
                lease: Duration::from_secs(args.session_lease_secs),
                absolute_ttl: Duration::from_secs(args.absolute_ttl_secs),
                max_sessions: args.max_sessions,
            },
            authority_lease_secs: args.authority_lease_secs,
            authority_state: Some(args.state_dir.join("authority.json")),
        },
        Arc::new(SystemClock::new()),
    )?);
    let broker = LocalBroker::new(plane, Arc::new(FileStore::new(&args.secrets_dir)));
    let client = build_client(&args, &snap)?;
    drop(snap);
    let app = Arc::new(App::new(
        store,
        broker,
        client,
        authorities,
        args.max_body_bytes,
    ));

    // The Unix sockets first, the TCP listener last: once the port answers,
    // everything is up.
    let session_l = sock::bind_unix(&args.session_socket, args.session_socket_mode)
        .await
        .map_err(|e| format!("session socket: {e}"))?;
    if let Some(dir) = args.admin_socket.parent() {
        if !dir.exists() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("create admin socket dir: {}", e.kind()))?;
        }
    }
    let admin_l = sock::bind_unix(&args.admin_socket, 0o600)
        .await
        .map_err(|e| format!("admin socket: {e}"))?;
    let tcp = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind listener: {}", e.kind()))?
        // axum does not set TCP_NODELAY on accepted sockets; without it a
        // streamed response meets the client's delayed ACK (+40 ms p99 measured).
        .tap_io(|t| {
            let _ = t.set_nodelay(true);
        });

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn({
        let r = router(agent::handler, app.clone());
        async move { axum::serve(tcp, r).await.map_err(|e| e.kind()) }
    });
    tasks.spawn({
        let r = router(plane_http::handler, app.clone());
        async move { axum::serve(session_l, r).await.map_err(|e| e.kind()) }
    });
    tasks.spawn({
        let r = router(admin::handler, app.clone());
        async move { axum::serve(admin_l, r).await.map_err(|e| e.kind()) }
    });

    // Lease sweeper. Lookups also check expiry inline, so a lapsed lease is
    // refused even before this runs; the sweeper frees memory and fires the
    // authority-lapse revoke-all promptly.
    let sweeper = app.plane.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(1));
        loop {
            t.tick().await;
            sweeper.session_count();
        }
    });

    eprintln!("auth-proxy: ready, agent listener on {listen}");

    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).map_err(|e| format!("signal: {}", e.kind()))?;
    let mut int = signal(SignalKind::interrupt()).map_err(|e| format!("signal: {}", e.kind()))?;
    let outcome = tokio::select! {
        _ = term.recv() => Ok(()),
        _ = int.recv() => Ok(()),
        r = tasks.join_next() => {
            let kind = match r {
                Some(Ok(Err(k))) => format!("{k:?}"),
                Some(Err(_)) => "task failed".to_string(),
                _ => "stopped".to_string(),
            };
            Err(format!("a server stopped unexpectedly: {kind}"))
        }
    };
    for p in [&args.session_socket, &args.admin_socket] {
        let _ = std::fs::remove_file(p);
    }
    outcome
}
