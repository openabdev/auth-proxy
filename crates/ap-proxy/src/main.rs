//! `auth-proxy`: the credential proxy process. All logic lives in the library.

#[tokio::main]
async fn main() {
    let opts = match ap_proxy::parse_args(std::env::args().skip(1)) {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("auth-proxy: {msg}");
            std::process::exit(2);
        }
    };
    std::process::exit(ap_proxy::run(opts).await);
}
