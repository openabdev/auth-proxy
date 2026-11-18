//! Credential proxy: library half.
//!
//! `run` starts the process: it loads and validates the config, binds the agent listener and the
//! two Unix sockets, and serves until one of them stops. Startup failures return exit code 2.

pub mod admin_http;
pub mod approval;
pub mod audit_sink;
pub mod evidence;
pub mod forward;
pub mod hold;
pub mod listener;
#[cfg(feature = "matrix-upstream")]
pub mod matrix_hooks;
pub mod netguard;
pub mod notify;
pub mod passthrough;
pub mod pipeline;
mod policy_store;
#[cfg(feature = "stage1-probe")]
mod probe;
pub mod session_http;

use std::future::IntoFuture;
use std::path::PathBuf;
use std::sync::Arc;

use ap_broker::broker::Broker;
use ap_broker::expiry::file_in;
use ap_broker::store::FileStore;
use axum::extract::Request;
use axum::response::Response;
use axum::serve::ListenerExt;
use axum::Router;
use tokio::signal::unix::{signal, SignalKind};

use audit_sink::AuditSink;
use netguard::NetfilterOpts;
use pipeline::App;

#[cfg(test)]
mod canon_diff_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

/// Command-line usage, printed with every argument error.
pub const USAGE: &str = "usage: auth-proxy --config <path> [--session-socket <path>] \
[--admin-socket <path>] [--secret-root <dir>] [--token-dir <dir>] [--expiry-store <file>] \
[--netfilter-rules-status <file> --netfilter-probe-status <file> [--netfilter-interval-secs <n>] \
[--netfilter-rules-uid <uid>] [--netfilter-probe-uid <uid>]]\n\
       auth-proxy --check-ready [--admin-socket <path>]";

/// Where the process reads its config, binds its sockets, and finds its secrets and tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub config: PathBuf,
    pub session_socket: PathBuf,
    pub admin_socket: PathBuf,
    pub secret_root: PathBuf,
    pub token_dir: PathBuf,
    /// Session expiry store file. `None` means `<token_dir>/session-expiry.v1`, the default
    /// location. The pod puts it on its own durable volume.
    pub expiry_store: Option<PathBuf>,
    /// The per-UID netfilter self-check (sidecar profile only). `None` leaves the proxy as it
    /// was: no gate, and the readiness endpoint always reports ready.
    pub netfilter: Option<NetfilterOpts>,
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
    let mut expiry_store = None;
    let mut rules_status = None;
    let mut probe_status = None;
    let mut interval = None;
    let mut rules_uid = netguard::DEFAULT_RULES_UID;
    let mut probe_uid = netguard::DEFAULT_PROBE_UID;
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
            "--expiry-store" => expiry_store = Some(PathBuf::from(value)),
            "--netfilter-rules-status" => rules_status = Some(PathBuf::from(value)),
            "--netfilter-probe-status" => probe_status = Some(PathBuf::from(value)),
            "--netfilter-interval-secs" => match value.parse::<u64>() {
                Ok(n) if (1..=3600).contains(&n) => interval = Some(n),
                _ => {
                    return Err(format!(
                        "--netfilter-interval-secs must be 1 to 3600\n{USAGE}"
                    ))
                }
            },
            "--netfilter-rules-uid" => {
                rules_uid = value
                    .parse::<u32>()
                    .map_err(|_| format!("--netfilter-rules-uid must be a number\n{USAGE}"))?
            }
            "--netfilter-probe-uid" => {
                probe_uid = value
                    .parse::<u32>()
                    .map_err(|_| format!("--netfilter-probe-uid must be a number\n{USAGE}"))?
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let config = config.ok_or_else(|| format!("--config is required\n{USAGE}"))?;
    let netfilter = match (rules_status, probe_status) {
        (Some(rules_status), Some(probe_status)) => Some(NetfilterOpts {
            rules_status,
            probe_status,
            interval: std::time::Duration::from_secs(
                interval.unwrap_or(netguard::DEFAULT_INTERVAL_SECS),
            ),
            rules_uid,
            probe_uid,
        }),
        (None, None) if interval.is_none() => None,
        _ => {
            return Err(format!(
                "the netfilter self-check needs both --netfilter-rules-status and \
--netfilter-probe-status\n{USAGE}"
            ))
        }
    };
    Ok(Options {
        config,
        session_socket,
        admin_socket,
        secret_root,
        token_dir,
        expiry_store,
        netfilter,
    })
}

/// Start the proxy and serve until a listener stops. Returns the process exit code: 2 for an
/// invalid config or a socket that cannot be bound, 1 for a listener that stops while serving. A
/// passthrough process that stops on SIGTERM or SIGINT after draining returns 0.
pub async fn run(opts: Options) -> i32 {
    #[cfg(feature = "matrix-upstream")]
    eprintln!("{}", matrix_hooks::WARNING);
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
    if cfg.is_passthrough_only() {
        return run_passthrough(&opts, cfg, &text).await;
    }
    let listen = cfg.listen.proxy;
    // The store is never created here. A missing file means it was lost or never provisioned,
    // and the proxy must not start over it.
    let expiry_store = opts
        .expiry_store
        .clone()
        .unwrap_or_else(|| file_in(&opts.token_dir));
    match expiry_store.try_exists() {
        Ok(true) => {}
        _ => {
            eprintln!(
                "auth-proxy: session expiry store is missing: {}",
                expiry_store.display()
            );
            return 2;
        }
    }
    let broker: Arc<dyn Broker> = Arc::new(FileStore::new(&opts.secret_root));
    let client = match forward::client() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("auth-proxy: cannot build the upstream client: {e}");
            return 1;
        }
    };
    let app = match App::new(
        opts.config.clone(),
        cfg,
        &text,
        opts.token_dir.clone(),
        expiry_store,
        broker,
        AuditSink::stdout(),
        client,
    ) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("auth-proxy: {e}");
            return 2;
        }
    };

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

    // The gate starts closed. The agent listener answers 503 until both checkers report healthy.
    let gate = opts.netfilter.clone().map(|nf| {
        let gate = netguard::Gate::new();
        netguard::spawn_monitor(nf, Arc::clone(&gate), Arc::clone(&app));
        gate
    });
    let agent_app = Arc::clone(&app);
    let agent_gate = gate.clone();
    let agent_router = Router::new().fallback(move |req: Request| {
        let app = Arc::clone(&agent_app);
        let gate = agent_gate.clone();
        async move {
            if let Some(refused) = gate
                .as_deref()
                .and_then(|g| netguard::refusal(g, &app.audit))
            {
                return refused;
            }
            agent_response(app, req).await
        }
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
    let admin_router = admin_http::router(Arc::clone(&app)).merge(netguard::ready_router(gate));
    let admin = session_http::serve_unix(admin_listener, admin_router);

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

/// A passthrough-only deployment (the Muse gate). It needs no expiry store, broker, session
/// socket or admin socket, so none is read or bound, and the sidecar flags are ignored.
async fn run_passthrough(opts: &Options, cfg: ap_core::config::Config, text: &str) -> i32 {
    if opts.netfilter.is_some() {
        eprintln!(
            "auth-proxy: the netfilter self-check applies to the sidecar profile; \
a passthrough-only config has no per-UID rules"
        );
        return 2;
    }
    if cfg.probe.enabled && !cfg!(feature = "stage1-probe") {
        eprintln!("auth-proxy: [probe] is enabled but this build lacks the stage1-probe feature");
        return 2;
    }
    let Some(pt) = cfg.passthrough.clone() else {
        eprintln!("auth-proxy: passthrough settings are missing");
        return 2;
    };
    let client = match forward::client() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("auth-proxy: cannot build the upstream client: {e}");
            return 1;
        }
    };
    let held_client = match forward::held_client() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("auth-proxy: cannot build the upstream client: {e}");
            return 1;
        }
    };
    let listen = cfg.listen.proxy;
    let listener = match listener::bind_loopback(listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("auth-proxy: cannot bind the public listener: {e}");
            return 2;
        }
    };
    // The approval listener is a second socket (design 3.6). Without an `[approval]` block there
    // is none, and holds simply expire.
    let approval_listener = match &cfg.approval {
        Some(a) => match listener::bind_loopback(a.listen).await {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("auth-proxy: cannot bind the approval listener: {e}");
                return 2;
            }
        },
        None => None,
    };
    let approval_cfg = cfg.approval.clone();
    let notify_cfg = cfg.notify.clone();
    // A panic line carries the source location only, never the payload, which could hold a
    // header value.
    std::panic::set_hook(Box::new(|info| match info.location() {
        Some(l) => eprintln!("auth-proxy: panic at {}:{}", l.file(), l.line()),
        None => eprintln!("auth-proxy: panic"),
    }));
    let mut app = passthrough::PtApp::with_held_client(
        opts.config.clone(),
        cfg,
        text,
        AuditSink::stdout(),
        client,
        held_client,
    );
    if let Some(n) = notify_cfg {
        let Some(a) = &approval_cfg else {
            eprintln!("auth-proxy: [notify] needs an [approval] block to link to");
            return 2;
        };
        let topic = match notify::read_secret_file(std::path::Path::new(&n.topic_file)) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("auth-proxy: notify topic file: {e}");
                return 2;
            }
        };
        let token = match n.token_file.as_deref().map(std::path::Path::new) {
            Some(p) => match notify::read_secret_file(p) {
                Ok(t) => Some(t),
                Err(e) => {
                    eprintln!("auth-proxy: notify token file: {e}");
                    return 2;
                }
            },
            None => None,
        };
        match notify::NtfyNotifier::new(&n.base_url, &topic, token.as_deref()) {
            Ok(nt) => passthrough::PtApp::set_notifier(&mut app, Arc::new(nt), &a.public_base_url),
            Err(e) => {
                eprintln!("auth-proxy: cannot build the notifier: {e}");
                return 2;
            }
        }
    }
    let limits = listener::public::PublicLimits {
        max_connections: pt.max_connections,
        header_read: std::time::Duration::from_secs(pt.header_read_secs),
    };
    let (mut sigterm, mut sigint) = match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        _ => {
            eprintln!("auth-proxy: cannot install the signal handlers");
            return 1;
        }
    };
    let approval = async {
        match (approval_listener, approval_cfg) {
            (Some(l), Some(cfg)) => {
                let state =
                    approval::ApprovalApp::new(Arc::clone(&app.hold), &cfg, app.policy_source());
                listener::approval::serve_approval(l, state, Default::default()).await;
            }
            _ => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(approval);
    let permits = Arc::new(tokio::sync::Semaphore::new(pt.max_connections));
    let (shutdown, down) = tokio::sync::watch::channel(false);
    let public = listener::public::serve_public_until(
        listener,
        Arc::clone(&app),
        limits,
        Arc::clone(&permits),
        down,
    );
    tokio::pin!(public);
    // Held requests notice a reload within a second (design 3.9).
    let mut reload = tokio::time::interval(std::time::Duration::from_secs(1));
    reload.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    eprintln!("auth-proxy: listening");
    loop {
        tokio::select! {
            () = &mut public => {
                eprintln!("auth-proxy: public listener stopped");
                return 1;
            }
            () = &mut approval => {
                eprintln!("auth-proxy: approval listener stopped");
                return 1;
            }
            _ = reload.tick() => {
                app.reload_tick();
            }
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
        }
    }
    // Shutdown (design 3.7): stop accepting, answer every pending hold 503 `shutdown`, and let
    // requests already approved run to their end or to `request_deadline_secs`. A second signal
    // ends the wait.
    eprintln!("auth-proxy: shutting down");
    // The approval future is not polled again, so it accepts nothing more; an approval already
    // accepted meets the closed table at `claim_start`.
    let _ = shutdown.send(true);
    app.hold.drain_pending();
    let wait = std::time::Duration::from_secs(pt.request_deadline_secs)
        .saturating_add(std::time::Duration::from_secs(2));
    let ended = permits.acquire_many(pt.max_connections as u32);
    tokio::select! {
        _ = ended => {}
        () = tokio::time::sleep(wait) => {
            eprintln!("auth-proxy: shutdown wait reached the request deadline");
        }
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    0
}
