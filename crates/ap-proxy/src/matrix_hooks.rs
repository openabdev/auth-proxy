//! Test-only upstream overrides for the black-box matrix. Compiled only with the `matrix-upstream`
//! feature, which is off by default and is never enabled in a release build.
//!
//! The matrix runs the proxy against throwaway CAs and mock upstreams on loopback. Two environment
//! variables make that possible. Nothing in this module reads the config file, and a binary built
//! without the feature contains none of this code.

use std::net::{IpAddr, SocketAddr};

use reqwest::{Certificate, ClientBuilder};

/// PEM file with the throwaway CA. Its certificate is added to the trust roots.
pub const ENV_CA: &str = "AP_TEST_UPSTREAM_CA";

/// Comma-separated `host=ip` pairs. Each host resolves to that address. The port comes from the URL.
pub const ENV_RESOLVE: &str = "AP_TEST_RESOLVE";

/// Startup banner for a feature-enabled binary. It is printed on every start.
pub const WARNING: &str = "auth-proxy: ***************************************************************
auth-proxy: WARNING: TEST BUILD (feature matrix-upstream). This is not the release artifact.
auth-proxy: Upstream trust roots and DNS are overridden from AP_TEST_UPSTREAM_CA and AP_TEST_RESOLVE.
auth-proxy: Never run this binary in production.
auth-proxy: ***************************************************************";

/// Apply the test overrides to the upstream client builder. A set variable that cannot be used is
/// an error, so the proxy never starts with a half-applied override.
pub fn apply(mut builder: ClientBuilder) -> Result<ClientBuilder, String> {
    if let Some(path) = std::env::var_os(ENV_CA) {
        let pem = std::fs::read(&path).map_err(|e| format!("{ENV_CA}: cannot read: {e}"))?;
        let cert = Certificate::from_pem(&pem).map_err(|e| format!("{ENV_CA}: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    if let Ok(spec) = std::env::var(ENV_RESOLVE) {
        for pair in spec.split(',').filter(|p| !p.is_empty()) {
            let (host, ip) = pair
                .split_once('=')
                .ok_or_else(|| format!("{ENV_RESOLVE}: expected host=ip, got {pair:?}"))?;
            let ip: IpAddr = ip
                .parse()
                .map_err(|e| format!("{ENV_RESOLVE}: {host}: {e}"))?;
            builder = builder.resolve(host, SocketAddr::new(ip, 0));
        }
    }
    Ok(builder)
}
