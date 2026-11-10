//! Test-only name overrides for the black-box matrix. Compiled only with the `matrix-upstream`
//! feature, which is off by default and is never enabled in a release build.
//!
//! `AP_TEST_EGRESS_RESOLVE` holds comma-separated `host=ip` pairs. A listed host resolves to that
//! address. Every other name goes to the system resolver. The override takes the place of the
//! system resolver only, so `resolve()` still runs `check_addr` on every address it returns: a
//! name mapped to loopback or to a private address is refused as a real one would be.

use crate::resolve::{Resolver, SystemResolver};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};

/// Comma-separated `host=ip` pairs. See the module comment.
pub const ENV_RESOLVE: &str = "AP_TEST_EGRESS_RESOLVE";

/// Startup banner for a feature-enabled binary. It is printed on every start.
pub const WARNING: &str =
    "ap-egress: ***************************************************************
ap-egress: WARNING: TEST BUILD (feature matrix-upstream). This is not the release artifact.
ap-egress: Name resolution is overridden from AP_TEST_EGRESS_RESOLVE; address checks still apply.
ap-egress: Never run this binary in production.
ap-egress: ***************************************************************";

/// Name-to-address overrides, read once at startup.
pub struct TestResolver {
    map: HashMap<String, IpAddr>,
}

impl TestResolver {
    /// Parse `host=ip[,host=ip...]`. A malformed pair is an error, so the process never starts
    /// with a partly applied override.
    pub fn from_spec(spec: &str) -> Result<Self, String> {
        let mut map = HashMap::new();
        for pair in spec.split(',').filter(|p| !p.is_empty()) {
            let (host, ip) = pair
                .split_once('=')
                .ok_or_else(|| format!("{ENV_RESOLVE}: expected host=ip, got {pair:?}"))?;
            let ip: IpAddr = ip
                .parse()
                .map_err(|e| format!("{ENV_RESOLVE}: {host}: {e}"))?;
            map.insert(host.to_string(), ip);
        }
        Ok(TestResolver { map })
    }

    /// Read `AP_TEST_EGRESS_RESOLVE`. An unset variable means no overrides.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(ENV_RESOLVE) {
            Ok(spec) => Self::from_spec(&spec),
            Err(_) => Self::from_spec(""),
        }
    }
}

impl Resolver for TestResolver {
    async fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        match self.map.get(host) {
            Some(ip) => Ok(vec![SocketAddr::new(*ip, port)]),
            None => SystemResolver.lookup(host, port).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::resolve;
    use crate::Refuse;

    #[tokio::test]
    async fn name_mapped_to_loopback_is_refused_by_the_address_check() {
        let r = TestResolver::from_spec("loop.test=127.0.0.1").expect("spec");
        assert_eq!(
            resolve(&r, "loop.test", 443).await,
            Err(Refuse::PrivateAddress)
        );
    }

    #[tokio::test]
    async fn name_mapped_to_public_address_passes_the_address_check() {
        let r = TestResolver::from_spec("pub.test=192.0.2.1").expect("spec");
        assert_eq!(
            resolve(&r, "pub.test", 443).await,
            Ok("192.0.2.1:443".parse().expect("addr"))
        );
    }

    #[test]
    fn malformed_spec_is_an_error() {
        assert!(TestResolver::from_spec("no-equals-sign").is_err());
        assert!(TestResolver::from_spec("host=not-an-ip").is_err());
    }
}
