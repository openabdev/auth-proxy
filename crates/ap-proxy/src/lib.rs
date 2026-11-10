//! Credential proxy: library half.
//!
//! `run` starts the process: it loads and validates the config, binds the agent listener and the
//! two Unix sockets, and serves until one of them stops. Startup failures return exit code 2.

pub mod admin_http;
pub mod audit_sink;
pub mod forward;
pub mod listener;
pub mod pipeline;
pub mod session_http;

use std::future::IntoFuture;
use std::path::PathBuf;
use std::sync::Arc;

use ap_broker::broker::Broker;
use ap_broker::store::FileStore;
use axum::extract::Request;
use axum::response::Response;
use axum::serve::ListenerExt;
use axum::Router;

use audit_sink::AuditSink;
use pipeline::App;

/// Command-line usage, printed with every argument error.
pub const USAGE: &str = "usage: auth-proxy --config <path> [--session-socket <path>] \
[--admin-socket <path>] [--secret-root <dir>] [--token-dir <dir>]";

/// Where the process reads its config, binds its sockets, and finds its secrets and tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub config: PathBuf,
    pub session_socket: PathBuf,
    pub admin_socket: PathBuf,
    pub secret_root: PathBuf,
    pub token_dir: PathBuf,
}

/// Parse the arguments after the program name. `--config` is required. The other paths default
/// to the pod layout in the design.
pub fn parse_args<I>(args: I) -> Result<Options, String>
where
    I: IntoIterator<Item = String>,
{
    let mut config = None;
    let mut session_socket = PathBuf::from("/run/auth-proxy/session.sock");
    let mut admin_socket = PathBuf::from("/run/auth-proxy-private/admin.sock");
    let mut secret_root = PathBuf::from("/var/run/auth-proxy/secrets");
    let mut token_dir = PathBuf::from("/run/auth-proxy-private/tokens");
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--config" => config = Some(PathBuf::from(value)),
            "--session-socket" => session_socket = PathBuf::from(value),
            "--admin-socket" => admin_socket = PathBuf::from(value),
            "--secret-root" => secret_root = PathBuf::from(value),
            "--token-dir" => token_dir = PathBuf::from(value),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let config = config.ok_or_else(|| format!("--config is required\n{USAGE}"))?;
    Ok(Options {
        config,
        session_socket,
        admin_socket,
        secret_root,
        token_dir,
    })
}

/// Start the proxy and serve until a listener stops. Returns the process exit code: 2 for an
/// invalid config or a socket that cannot be bound, 1 for a listener that stops while serving.
pub async fn run(opts: Options) -> i32 {
    let text = match std::fs::read_to_string(&opts.config) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("auth-proxy: cannot read config: {e}");
            return 2;
        }
    };
    let cfg = match ap_core::config::load(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("auth-proxy: {e}");
            return 2;
        }
    };
    let listen = cfg.listen.proxy;
    let broker: Arc<dyn Broker> = Arc::new(FileStore::new(&opts.secret_root));
    let client = match forward::client() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("auth-proxy: cannot build the upstream client: {e}");
            return 1;
        }
    };
    let app = App::new(
        opts.config.clone(),
        cfg,
        opts.token_dir.clone(),
        broker,
        AuditSink::stdout(),
        client,
    );

    let agent_listener = match listener::bind_loopback(listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("auth-proxy: cannot bind the agent listener: {e}");
            return 2;
        }
    };
    let session_listener = match listener::bind_session_socket(&opts.session_socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("auth-proxy: cannot bind the session socket: {e}");
            return 2;
        }
    };
    let admin_listener = match listener::bind_unix_socket(&opts.admin_socket, 0o600) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("auth-proxy: cannot bind the admin socket: {e}");
            return 2;
        }
    };

    let agent_app = Arc::clone(&app);
    let agent_router = Router::new().fallback(move |req: Request| {
        let app = Arc::clone(&agent_app);
        async move { agent_response(app, req).await }
    });
    // axum does not set TCP_NODELAY on accepted sockets. Without it a streamed response
    // (head, then body) waits on the client's delayed ACK.
    let agent = axum::serve(
        agent_listener.tap_io(|t| {
            let _ = t.set_nodelay(true);
        }),
        agent_router,
    )
    .into_future();
    let session =
        session_http::serve_unix(session_listener, session_http::router(Arc::clone(&app)));
    let admin = session_http::serve_unix(admin_listener, admin_http::router(Arc::clone(&app)));

    eprintln!("auth-proxy: listening");
    tokio::select! {
        r = agent => {
            eprintln!("auth-proxy: agent listener stopped: {r:?}");
            1
        }
        () = session => 1,
        () = admin => 1,
    }
}

async fn agent_response(app: Arc<App>, req: Request) -> Response {
    pipeline::handle(app, req).await
}
