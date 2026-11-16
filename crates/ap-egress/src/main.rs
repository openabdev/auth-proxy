//! ap-egress binary. `ap-egress --policy PATH [--listen 127.0.0.1:3128]`
//! (env twins AP_POLICY, AP_EGRESS_LISTEN). Exit 2 on bad arguments or policy.

use ap_core::PolicyStore;
use ap_egress::{serve, Egress, Options, SystemResolver};
use std::net::SocketAddr;
use std::sync::Arc;

const USAGE: &str = "\
ap-egress: CONNECT-only egress allowlist proxy

  --policy PATH   policy file (same TOML as auth-proxy; only [egress] is used)   AP_POLICY (required)
  --listen ADDR   loopback listen address [127.0.0.1:3128]                       AP_EGRESS_LISTEN
  --help

Exit codes: 0 clean stop, 2 invalid arguments or policy.
";

fn parse() -> Result<Option<(String, SocketAddr)>, String> {
    let mut policy = std::env::var("AP_POLICY").ok();
    let mut listen = std::env::var("AP_EGRESS_LISTEN").unwrap_or_else(|_| "127.0.0.1:3128".into());
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--help" | "-h" => return Ok(None),
            "--policy" => policy = Some(it.next().ok_or("--policy needs a value")?),
            "--listen" => listen = it.next().ok_or("--listen needs a value")?,
            _ => return Err(format!("unknown argument {a:?}")),
        }
    }
    let policy = policy.ok_or("--policy (or AP_POLICY) is required")?;
    let addr: SocketAddr = listen.parse().map_err(|_| "--listen: not an address")?;
    if !addr.ip().is_loopback() {
        return Err("--listen must be a loopback address".into());
    }
    Ok(Some((policy, addr)))
}

#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("ap-egress: internal error (panic)")));
    let (policy, addr) = match parse() {
        Ok(Some(v)) => v,
        Ok(None) => {
            print!("{USAGE}");
            return;
        }
        Err(e) => {
            eprintln!("ap-egress: {e}");
            std::process::exit(2);
        }
    };
    let store = match PolicyStore::open(&policy) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ap-egress: policy: {e}");
            std::process::exit(2);
        }
    };
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ap-egress: bind {addr}: {}", e.kind());
            std::process::exit(2);
        }
    };
    eprintln!("ap-egress: listening on {addr}");
    let eg = Arc::new(Egress {
        store,
        resolver: Box::new(SystemResolver),
        opts: Options::default(),
    });
    tokio::select! {
        r = serve(listener, eg) => {
            eprintln!("ap-egress: accept failed: {:?}", r.err().map(|e| e.kind()));
            std::process::exit(2);
        }
        _ = tokio::signal::ctrl_c() => {}
    }
}
