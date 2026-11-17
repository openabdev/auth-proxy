//! `auth-proxy`: the credential proxy process. All logic lives in the library.

#[tokio::main]
async fn main() {
    // Kubernetes exec readiness probe: the image has no shell or curl.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--check-ready") {
        std::process::exit(ap_proxy::netguard::check_ready_main(&args));
    }
    let opts = match ap_proxy::parse_args(std::env::args().skip(1)) {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("auth-proxy: {msg}");
            std::process::exit(2);
        }
    };
    std::process::exit(ap_proxy::run(opts).await);
}
