//! Functional probe for the per-UID netfilter rules.
//!
//! This runs in a pod container whose UID is the agent UID, with no Linux capability. The
//! per-UID rules (`deploy/k8s/netinit/netinit.sh`) reject everything the agent UID sends that is
//! not loopback traffic to the proxy or egress port. So from this UID:
//!
//! 1. a TCP connect to a loopback listener on another port must be refused (rule: any other
//!    loopback packet from the agent UID is rejected),
//! 2. a TCP connect to a routable non-loopback address must be refused (direct egress),
//! 3. a UDP query to the resolver must be refused (DNS is closed).
//!
//! The only passing outcome is "refused". A connect that succeeds, a reply, a timeout and any
//! other error all fail the probe, so a missing rule, a changed UID mapping and an unexpected
//! network answer all fail closed. The refusal is the local `REJECT` (ICMP port unreachable),
//! which arrives at once; the probe never waits for a remote host.
//!
//! The result goes to a status file as one line, `tick=<token> state=ok|fail reason=<code>`.
//! The token changes on every write, so a reader can tell a live probe from a dead one.

use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::time::Duration;

/// What one probe saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The attempt was refused locally. This is the only passing outcome.
    Refused,
    /// The attempt got through: a connection or a reply.
    Open,
    /// A timeout, an unreachable network, a permission error or anything else.
    Inconclusive,
}

/// Documentation address (TEST-NET-1). It is never answered, so a connect that is not refused
/// locally times out instead of reaching a real host.
pub const EGRESS_TARGET: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);
/// Used for the DNS probe when `/etc/resolv.conf` names no resolver.
pub const FALLBACK_RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
/// How long one probe waits. A refusal is immediate, so this only bounds the failing case.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// A DNS query for the root NS record: 12 header bytes, the root label, type NS, class IN.
const DNS_QUERY: [u8; 17] = [
    0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x01,
];

/// Classify a TCP connect result.
pub fn connect_outcome(r: io::Result<TcpStream>) -> Outcome {
    match r {
        Ok(_) => Outcome::Open,
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Outcome::Refused,
        Err(_) => Outcome::Inconclusive,
    }
}

/// Classify the result of a UDP exchange: the send, then the receive of a reply.
pub fn udp_outcome(sent: io::Result<usize>, received: io::Result<usize>) -> Outcome {
    match (sent, received) {
        (Err(e), _) | (Ok(_), Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
            Outcome::Refused
        }
        (Ok(_), Ok(_)) => Outcome::Open,
        _ => Outcome::Inconclusive,
    }
}

/// The first resolver address in `resolv.conf` text, or the fallback.
pub fn resolver_from(text: &str) -> IpAddr {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("nameserver") {
            if let Some(ip) = parts.next().and_then(|a| a.parse::<IpAddr>().ok()) {
                return ip;
            }
        }
    }
    FALLBACK_RESOLVER
}

/// Loopback probe: a listener of our own on an ephemeral loopback port, then a connect to it.
/// Without the rules the connect succeeds. With them it is refused, because the port is neither
/// the proxy nor the egress port.
pub fn probe_loopback() -> Outcome {
    let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else {
        return Outcome::Inconclusive;
    };
    let Ok(addr) = listener.local_addr() else {
        return Outcome::Inconclusive;
    };
    connect_outcome(TcpStream::connect_timeout(&addr, PROBE_TIMEOUT))
}

/// Direct egress probe: a TCP connect to a non-loopback address.
pub fn probe_egress() -> Outcome {
    connect_outcome(TcpStream::connect_timeout(&EGRESS_TARGET, PROBE_TIMEOUT))
}

/// DNS probe: a UDP query to the resolver on port 53.
pub fn probe_dns(resolver: IpAddr) -> Outcome {
    let bind: SocketAddr = match resolver {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let Ok(sock) = UdpSocket::bind(bind) else {
        return Outcome::Inconclusive;
    };
    if sock.set_read_timeout(Some(PROBE_TIMEOUT)).is_err()
        || sock.connect(SocketAddr::new(resolver, 53)).is_err()
    {
        return Outcome::Inconclusive;
    }
    let sent = sock.send(&DNS_QUERY);
    let mut buf = [0u8; 512];
    let received = match sent {
        Ok(_) => sock.recv(&mut buf),
        Err(_) => Ok(0),
    };
    udp_outcome(sent, received)
}

/// The verdict of a full probe run: `Ok(())`, or the failing reason code.
pub fn verdict(loopback: Outcome, egress: Outcome, dns: Outcome) -> Result<(), &'static str> {
    let one = |o: Outcome, open: &'static str, other: &'static str| match o {
        Outcome::Refused => Ok(()),
        Outcome::Open => Err(open),
        Outcome::Inconclusive => Err(other),
    };
    one(loopback, "loopback_open", "loopback_unexpected")?;
    one(egress, "egress_open", "egress_unexpected")?;
    one(dns, "dns_open", "dns_unexpected")
}

/// Run the three probes. All of them run, so a log shows every result, and the first failure
/// names the reason.
pub fn run_probes() -> Result<(), &'static str> {
    let resolver = resolver_from(&fs::read_to_string("/etc/resolv.conf").unwrap_or_default());
    verdict(probe_loopback(), probe_egress(), probe_dns(resolver))
}

/// The status line for a result. The reason is a fixed code, never free text.
pub fn status_line(tick: &str, result: Result<(), &'static str>) -> String {
    match result {
        Ok(()) => format!("tick={tick} state=ok reason=ok\n"),
        Err(reason) => format!("tick={tick} state=fail reason={reason}\n"),
    }
}

/// Write the status file atomically: a temp file next to it, then a rename.
pub fn write_status(path: &Path, line: &str) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, line)?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(kind: io::ErrorKind) -> io::Error {
        io::Error::from(kind)
    }

    #[test]
    fn only_a_refusal_passes_a_connect() {
        assert_eq!(
            connect_outcome(Err(err(io::ErrorKind::ConnectionRefused))),
            Outcome::Refused
        );
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
        ] {
            assert_eq!(
                connect_outcome(Err(err(kind))),
                Outcome::Inconclusive,
                "{kind:?}"
            );
        }
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let s = TcpStream::connect(l.local_addr().expect("addr"));
        assert_eq!(connect_outcome(s), Outcome::Open);
    }

    #[test]
    fn udp_refusal_is_seen_on_send_or_on_receive() {
        let refused = || err(io::ErrorKind::ConnectionRefused);
        assert_eq!(udp_outcome(Err(refused()), Ok(0)), Outcome::Refused);
        assert_eq!(udp_outcome(Ok(17), Err(refused())), Outcome::Refused);
        assert_eq!(udp_outcome(Ok(17), Ok(40)), Outcome::Open);
        assert_eq!(
            udp_outcome(Ok(17), Err(err(io::ErrorKind::WouldBlock))),
            Outcome::Inconclusive
        );
        assert_eq!(
            udp_outcome(Err(err(io::ErrorKind::PermissionDenied)), Ok(0)),
            Outcome::Inconclusive
        );
    }

    #[test]
    fn resolver_is_the_first_nameserver_or_the_fallback() {
        assert_eq!(
            resolver_from("search x\nnameserver 10.43.0.10\nnameserver 1.1.1.1\n"),
            "10.43.0.10".parse::<IpAddr>().expect("ip")
        );
        assert_eq!(
            resolver_from("nameserver fd00::53\n"),
            "fd00::53".parse::<IpAddr>().expect("ip")
        );
        assert_eq!(resolver_from("nameserver not-an-ip\n"), FALLBACK_RESOLVER);
        assert_eq!(resolver_from(""), FALLBACK_RESOLVER);
    }

    #[test]
    fn verdict_names_the_first_failing_probe() {
        use Outcome::*;
        assert_eq!(verdict(Refused, Refused, Refused), Ok(()));
        assert_eq!(verdict(Open, Refused, Refused), Err("loopback_open"));
        assert_eq!(verdict(Refused, Open, Open), Err("egress_open"));
        assert_eq!(verdict(Refused, Refused, Open), Err("dns_open"));
        assert_eq!(
            verdict(Refused, Inconclusive, Refused),
            Err("egress_unexpected")
        );
        assert_eq!(
            verdict(Inconclusive, Refused, Refused),
            Err("loopback_unexpected")
        );
    }

    #[test]
    fn loopback_probe_detects_a_host_without_the_rules() {
        // This test process has no per-UID rule, so the loopback connect gets through.
        assert_eq!(probe_loopback(), Outcome::Open);
    }

    #[test]
    fn status_line_has_a_fixed_shape() {
        assert_eq!(status_line("7-1", Ok(())), "tick=7-1 state=ok reason=ok\n");
        assert_eq!(
            status_line("7-2", Err("dns_open")),
            "tick=7-2 state=fail reason=dns_open\n"
        );
    }

    #[test]
    fn write_status_replaces_the_file() {
        let dir = std::env::temp_dir().join(format!("ap-netprobe-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("status");
        write_status(&path, "a\n").expect("first");
        write_status(&path, "b\n").expect("second");
        assert_eq!(fs::read_to_string(&path).expect("read"), "b\n");
        assert!(!dir.join("status.tmp").exists());
        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
