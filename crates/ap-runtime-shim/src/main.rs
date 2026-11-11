//! Entry point. Read the seed, take the authority with a signed hello, then bind the agent socket
//! and serve. The socket does not exist until hello succeeds.
//!
//! Exit codes: 2 for bad arguments or an unreadable seed. 1 when hello or the socket fails. The
//! container restart policy retries on 1.

use std::process::ExitCode;
use std::sync::Arc;

use ap_client::authority::Authority;
use ap_client::proof::RuntimeKey;
use ap_runtime_shim::agent_api::{self, Shim};
use ap_runtime_shim::args::{parse_args, USAGE};
use ap_runtime_shim::bind_agent_socket;

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ap-runtime-shim: {e}");
            return ExitCode::from(2);
        }
    };
    let seed_text = match std::fs::read_to_string(&args.seed_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ap-runtime-shim: cannot read the seed file: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    // The error is not printed: it carries no seed bytes, but the key stays out of the logs.
    let key = match RuntimeKey::from_seed_b64(&seed_text) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("ap-runtime-shim: the seed file must hold 32 bytes of base64");
            return ExitCode::from(2);
        }
    };

    let authority =
        match Authority::start(&args.identity, &args.session_socket, Arc::new(key)).await {
            Ok(a) => a,
            Err(e) => {
                eprintln!("ap-runtime-shim: hello failed: {e:?}");
                return ExitCode::from(1);
            }
        };

    let listener = match bind_agent_socket(&args.agent_socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ap-runtime-shim: cannot bind the agent socket: {e}");
            return ExitCode::from(1);
        }
    };

    eprintln!("ap-runtime-shim: serving identity {}", args.identity);
    let shim = Shim::new(args.identity.clone(), authority);
    match axum::serve(listener, agent_api::router(shim)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ap-runtime-shim: agent socket stopped: {e}");
            ExitCode::from(1)
        }
    }
}
