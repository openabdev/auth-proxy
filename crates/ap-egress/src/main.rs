//! Allowlisting CONNECT proxy binary.
//!
//! Usage: `ap-egress --config <path> --listen <loopback-addr>`. Exits 2 on a bad argument, an
//! invalid config, a non-loopback listen address or a bind failure.

use ap_egress::connect::{serve_conn, TcpConnector};
use ap_egress::resolve::SystemResolver;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

const USAGE: &str = "usage: ap-egress --config <path> --listen <loopback-addr>";

struct Args {
    config: String,
    listen: SocketAddr,
}

fn parse_args() -> Result<Args, String> {
    let mut config = None;
    let mut listen = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--config" => config = Some(value),
            "--listen" => {
                listen = Some(
                    value
                        .parse::<SocketAddr>()
                        .map_err(|e| format!("--listen: {e}"))?,
                )
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    Ok(Args {
        config: config.ok_or_else(|| format!("--config is required\n{USAGE}"))?,
        listen: listen.ok_or_else(|| format!("--listen is required\n{USAGE}"))?,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("ap-egress: {msg}");
            return ExitCode::from(2);
        }
    };
    let text = match std::fs::read_to_string(&args.config) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("ap-egress: cannot read config: {e}");
            return ExitCode::from(2);
        }
    };
    let cfg = match ap_core::config::load(&text) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("ap-egress: {e}");
            return ExitCode::from(2);
        }
    };
    if !args.listen.ip().is_loopback() {
        eprintln!("ap-egress: --listen must be a loopback address");
        return ExitCode::from(2);
    }
    let listener = match TcpListener::bind(args.listen).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("ap-egress: cannot bind {}: {e}", args.listen);
            return ExitCode::from(2);
        }
    };
    eprintln!("ap-egress: listening");

    let allow = Arc::new(cfg.egress.allow);
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let allow = Arc::clone(&allow);
                tokio::spawn(async move {
                    let _ = serve_conn(stream, &allow, &SystemResolver, &TcpConnector).await;
                });
            }
            Err(e) => {
                eprintln!("ap-egress: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
