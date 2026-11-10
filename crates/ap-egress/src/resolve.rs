//! Name resolution and the address check (design Q3-E2). ap-egress resolves the name itself,
//! refuses any address in a private or special range, and never resolves a name twice.

use crate::Refuse;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Looks up the addresses of a name. Production uses the system resolver; tests inject a double.
pub trait Resolver: Sync {
    fn lookup(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send;
}

/// The operating system resolver.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    async fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// Resolve `host` once and return the first address.
///
/// Every returned address must pass [`check_addr`]. If any one of them is refused, the whole
/// lookup is refused, so a name cannot mix a public and a private answer to get past the check.
pub async fn resolve<R: Resolver>(
    resolver: &R,
    host: &str,
    port: u16,
) -> Result<SocketAddr, Refuse> {
    let addrs = resolver
        .lookup(host, port)
        .await
        .map_err(|_| Refuse::Upstream)?;
    for addr in &addrs {
        check_addr(addr.ip())?;
    }
    addrs.first().copied().ok_or(Refuse::Upstream)
}

/// Refuse loopback, RFC 1918, 100.64/10 (shared address space), link-local, multicast,
/// unspecified (and the rest of 0/8), broadcast, IPv6 unique-local and link-local, and the
/// IPv4 forms of these: IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`).
pub fn check_addr(ip: IpAddr) -> Result<(), Refuse> {
    let refused = match ip {
        IpAddr::V4(v4) => refused_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => refused_v4(v4),
            None if is_ipv4_compatible(v6) => {
                let [.., a, b, c, d] = v6.octets();
                refused_v4(Ipv4Addr::new(a, b, c, d))
            }
            None => refused_v6(v6),
        },
    };
    if refused {
        Err(Refuse::PrivateAddress)
    } else {
        Ok(())
    }
}

fn refused_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || a == 0
        || (a == 100 && (b & 0xc0) == 64)
}

fn refused_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xffc0) == 0xfe80
        || (first & 0xfe00) == 0xfc00
}

/// First six segments all zero. `::` and `::1` also match, and both are refused as IPv4 0/8.
fn is_ipv4_compatible(ip: Ipv6Addr) -> bool {
    ip.segments()[..6].iter().all(|s| *s == 0)
}
