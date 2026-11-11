//! Refusal list, exact-address connect and single lookup, through doubles for the resolver and
//! the connector. No test touches the network.

use crate::accept::serve_listener;
use crate::allow::allowed;
use crate::connect::{parse_connect, serve_conn, Connector, HostPort};
use crate::resolve::{check_addr, Resolver};
use crate::Refuse;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};

struct FakeResolver {
    answers: Vec<SocketAddr>,
    calls: AtomicUsize,
}

impl FakeResolver {
    fn new(answers: &[&str]) -> Self {
        FakeResolver {
            answers: answers.iter().map(|a| a.parse().expect("addr")).collect(),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Resolver for FakeResolver {
    async fn lookup(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.answers.clone())
    }
}

#[derive(Default)]
struct FakeConnector {
    seen: Mutex<Vec<SocketAddr>>,
}

impl FakeConnector {
    fn seen(&self) -> Vec<SocketAddr> {
        self.seen.lock().expect("lock").clone()
    }
}

impl Connector for FakeConnector {
    type Stream = DuplexStream;

    async fn connect(&self, addr: SocketAddr) -> io::Result<DuplexStream> {
        self.seen.lock().expect("lock").push(addr);
        let (ours, _peer) = tokio::io::duplex(64);
        Ok(ours)
    }
}

async fn read_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> String {
    let mut buf = Vec::new();
    while !buf.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).await.expect("read") == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    String::from_utf8(buf).expect("utf8")
}

/// Send `request` through `serve_conn` and return the status line the client receives.
async fn exchange<R: Resolver, C: Connector>(
    request: &str,
    allow: &[String],
    resolver: &R,
    connector: &C,
) -> String {
    let (mut client, server) = tokio::io::duplex(8192);
    let serve = async {
        serve_conn(server, allow, resolver, connector)
            .await
            .expect("serve")
    };
    let talk = async {
        client.write_all(request.as_bytes()).await.expect("write");
        let head = read_head(&mut client).await;
        drop(client);
        head
    };
    let ((), head) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(serve, talk) })
            .await
            .expect("exchange finished");
    head.lines().next().unwrap_or("").to_string()
}

fn allow_list() -> Vec<String> {
    vec!["api.example.net:443".to_string()]
}

#[tokio::test]
async fn allowed_host_connects_to_exact_validated_address() {
    let resolver = FakeResolver::new(&["192.0.2.1:443"]);
    let connector = FakeConnector::default();
    let request = "CONNECT api.example.net:443 HTTP/1.1\r\nHost: api.example.net:443\r\n\r\n";
    let status = exchange(request, &allow_list(), &resolver, &connector).await;
    assert_eq!(status, "HTTP/1.1 200 Connection Established");
    assert_eq!(resolver.calls(), 1, "one lookup per allowed CONNECT");
    assert_eq!(connector.seen(), vec!["192.0.2.1:443".parse().unwrap()]);
}

#[tokio::test]
async fn unlisted_host_refused_without_any_lookup() {
    let resolver = FakeResolver::new(&["192.0.2.1:443"]);
    let connector = FakeConnector::default();
    let request = "CONNECT other.example.net:443 HTTP/1.1\r\nHost: other.example.net:443\r\n\r\n";
    let status = exchange(request, &allow_list(), &resolver, &connector).await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
    assert_eq!(resolver.calls(), 0);
    assert!(connector.seen().is_empty());
}

#[tokio::test]
async fn listed_host_on_another_port_refused_without_any_lookup() {
    let resolver = FakeResolver::new(&["192.0.2.1:8443"]);
    let connector = FakeConnector::default();
    let request = "CONNECT api.example.net:8443 HTTP/1.1\r\nHost: api.example.net:8443\r\n\r\n";
    let status = exchange(request, &allow_list(), &resolver, &connector).await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
    assert_eq!(resolver.calls(), 0);
    assert!(connector.seen().is_empty());
}

#[tokio::test]
async fn ip_literal_targets_refused_without_any_lookup() {
    for target in ["127.0.0.1:443", "[::1]:443", "127.1:443", "10.0.0.1:443"] {
        let resolver = FakeResolver::new(&["192.0.2.1:443"]);
        let connector = FakeConnector::default();
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        let status = exchange(&request, &allow_list(), &resolver, &connector).await;
        assert_eq!(status, "HTTP/1.1 403 Forbidden", "{target}");
        assert_eq!(resolver.calls(), 0, "{target}");
        assert!(connector.seen().is_empty(), "{target}");
    }
}

#[tokio::test]
async fn allowed_name_resolving_to_loopback_is_refused() {
    let resolver = FakeResolver::new(&["127.0.0.1:443"]);
    let connector = FakeConnector::default();
    let request = "CONNECT api.example.net:443 HTTP/1.1\r\nHost: api.example.net:443\r\n\r\n";
    let status = exchange(request, &allow_list(), &resolver, &connector).await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
    assert_eq!(resolver.calls(), 1);
    assert!(connector.seen().is_empty());
}

#[tokio::test]
async fn allowed_name_with_one_private_answer_is_refused() {
    let resolver = FakeResolver::new(&["192.0.2.1:443", "10.0.0.7:443"]);
    let connector = FakeConnector::default();
    let request = "CONNECT api.example.net:443 HTTP/1.1\r\nHost: api.example.net:443\r\n\r\n";
    let status = exchange(request, &allow_list(), &resolver, &connector).await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
    assert!(connector.seen().is_empty());
}

#[tokio::test]
async fn plain_http_proxy_request_refused_with_405_without_any_lookup() {
    let resolver = FakeResolver::new(&["192.0.2.1:80"]);
    let connector = FakeConnector::default();
    let request = "GET http://api.example.net/ HTTP/1.1\r\nHost: api.example.net\r\n\r\n";
    let status = exchange(request, &allow_list(), &resolver, &connector).await;
    assert_eq!(status, "HTTP/1.1 405 Method Not Allowed");
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn private_and_special_addresses_are_refused() {
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.1.1",
        "169.254.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "::10.0.0.1",
        "64:ff9b::a00:1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::1",
        "2002:0a00:0001::",
        "2002:7f00:0001::",
        "::ffff:0:a00:1",
    ] {
        let addr: IpAddr = ip.parse().expect("ip");
        assert!(check_addr(addr).is_err(), "{ip} must be refused");
    }
}

#[test]
fn public_addresses_pass_the_address_check() {
    for ip in [
        "192.0.2.1",
        "93.184.216.34",
        "2001:db8::1",
        "64:ff9b::5db8:d822",
        "2002:5db8:d822::",
    ] {
        let addr: IpAddr = ip.parse().expect("ip");
        assert!(check_addr(addr).is_ok(), "{ip} must pass");
    }
}

#[test]
fn ip_literal_is_refused_before_a_mismatched_host_header() {
    assert_eq!(
        parse_connect(
            "CONNECT 127.0.0.1:443 HTTP/1.1",
            &["Host: other.example.net:443"]
        ),
        Err(Refuse::IpLiteral)
    );
}

#[tokio::test]
async fn head_over_8_kib_is_refused_when_the_terminator_is_in_a_later_read() {
    let resolver = FakeResolver::new(&["192.0.2.1:443"]);
    let connector = FakeConnector::default();
    let pad = "a".repeat(8600);
    let request = format!(
        "CONNECT api.example.net:443 HTTP/1.1\r\nHost: api.example.net:443\r\nX-Pad: {pad}\r\n\r\n"
    );
    let status = exchange(&request, &allow_list(), &resolver, &connector).await;
    assert_eq!(status, "HTTP/1.1 400 Bad Request");
    assert_eq!(resolver.calls(), 0);
}

#[test]
fn allowlist_matches_host_and_port_exactly() {
    let list = vec!["github.com:443".to_string()];
    assert!(allowed(&list, "github.com", 443));
    assert!(!allowed(&list, "github.com", 80));
    assert!(!allowed(&list, "api.github.com", 443));
    assert!(!allowed(&list, "GitHub.com", 443));
}

#[test]
fn connect_head_rejects_zero_port_and_mismatched_host() {
    assert_eq!(
        parse_connect("CONNECT api.example.net:0 HTTP/1.1", &[]),
        Err(Refuse::BadRequest)
    );
    assert_eq!(
        parse_connect(
            "CONNECT api.example.net:443 HTTP/1.1",
            &["Host: other.example.net:443"]
        ),
        Err(Refuse::BadRequest)
    );
    assert_eq!(
        parse_connect(
            "CONNECT api.example.net:443 HTTP/1.1",
            &["Host: api.example.net:443"]
        ),
        Ok(HostPort {
            host: "api.example.net".to_string(),
            port: 443,
        })
    );
}

/// Upstream double for the accept-loop tests. With `keep` the far end of each upstream stream is
/// held, so a tunnel stays open until the client closes. Without it the far end is dropped at once.
struct Upstreams {
    keep: bool,
    peers: Mutex<Vec<DuplexStream>>,
}

impl Upstreams {
    fn new(keep: bool) -> Self {
        Upstreams {
            keep,
            peers: Mutex::new(Vec::new()),
        }
    }

    fn count(&self) -> usize {
        self.peers.lock().expect("lock").len()
    }

    /// Close the far end of the oldest held upstream stream.
    fn close_oldest(&self) {
        self.peers.lock().expect("lock").remove(0);
    }
}

impl Connector for Upstreams {
    type Stream = DuplexStream;

    async fn connect(&self, _addr: SocketAddr) -> io::Result<DuplexStream> {
        let (ours, peer) = tokio::io::duplex(64);
        if self.keep {
            self.peers.lock().expect("lock").push(peer);
        }
        Ok(ours)
    }
}

const CONNECT: &str = "CONNECT api.example.net:443 HTTP/1.1\r\nHost: api.example.net:443\r\n\r\n";
const ESTABLISHED: &str = "HTTP/1.1 200 Connection Established";

/// Run the accept loop on a loopback listener with the given cap.
async fn start_loop(
    cap: usize,
    connector: Arc<Upstreams>,
) -> (SocketAddr, tokio::task::AbortHandle) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let resolver = Arc::new(FakeResolver::new(&["192.0.2.1:443"]));
    let task = tokio::spawn(serve_listener(
        listener,
        Arc::new(allow_list()),
        resolver,
        connector,
        cap,
    ));
    (addr, task.abort_handle())
}

/// Read a response head. Returns the status line, or an empty string when the server closed or
/// reset the socket first.
async fn read_status(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(1) => buf.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Open a connection, send a CONNECT and return the socket with the status line it received.
async fn open_tunnel(addr: SocketAddr) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let _ = stream.write_all(CONNECT.as_bytes()).await;
    let status = read_status(&mut stream).await;
    (stream, status)
}

/// Retry until a connection is accepted, to wait for a permit to come back.
async fn retry_until_accepted(addr: SocketAddr) -> (TcpStream, String) {
    for _ in 0..200 {
        let (stream, status) = open_tunnel(addr).await;
        if status == ESTABLISHED {
            return (stream, status);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no connection was accepted after the permit should have been released");
}

#[tokio::test]
async fn cap_serves_n_connections_and_closes_the_next() {
    let upstreams = Arc::new(Upstreams::new(true));
    let (addr, task) = start_loop(2, Arc::clone(&upstreams)).await;
    let mut held = Vec::new();
    for _ in 0..2 {
        let (stream, status) = open_tunnel(addr).await;
        assert_eq!(status, ESTABLISHED);
        held.push(stream);
    }
    let (_extra, status) = tokio::time::timeout(Duration::from_secs(2), open_tunnel(addr))
        .await
        .expect("the connection over the cap is closed promptly");
    assert_eq!(status, "", "the connection over the cap gets no answer");
    assert_eq!(
        upstreams.count(),
        2,
        "the refused connection never reached upstream"
    );
    task.abort();
}

#[tokio::test]
async fn permit_returns_after_a_connection_finishes() {
    let upstreams = Arc::new(Upstreams::new(true));
    let (addr, task) = start_loop(1, Arc::clone(&upstreams)).await;
    let (first, status) = open_tunnel(addr).await;
    assert_eq!(status, ESTABLISHED);
    let (_refused, status) = open_tunnel(addr).await;
    assert_eq!(status, "", "the single permit is in use");
    upstreams.close_oldest();
    drop(first);
    let (_second, status) = retry_until_accepted(addr).await;
    assert_eq!(status, ESTABLISHED);
    task.abort();
}

#[tokio::test]
async fn failed_connection_releases_its_permit() {
    // The far end is dropped, so bytes sent after the request head fail the upstream write.
    let upstreams = Arc::new(Upstreams::new(false));
    let (addr, task) = start_loop(1, upstreams).await;
    let mut failing = TcpStream::connect(addr).await.expect("connect");
    failing
        .write_all(format!("{CONNECT}x").as_bytes())
        .await
        .expect("write");
    assert_eq!(read_status(&mut failing).await, ESTABLISHED);
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), failing.read_to_end(&mut rest))
        .await
        .expect("the failed tunnel closes")
        .ok();
    let (_next, status) = retry_until_accepted(addr).await;
    assert_eq!(status, ESTABLISHED);
    task.abort();
}

#[tokio::test]
async fn timed_out_connection_releases_its_permit() {
    let upstreams = Arc::new(Upstreams::new(true));
    let (addr, task) = start_loop(1, upstreams).await;
    // Sends nothing, so the head read times out and the server answers 400 and closes.
    let mut idle = TcpStream::connect(addr).await.expect("connect");
    let (_refused, status) = open_tunnel(addr).await;
    assert_eq!(status, "", "the idle connection holds the only permit");
    let answer = tokio::time::timeout(Duration::from_secs(20), read_status(&mut idle))
        .await
        .expect("the idle connection times out");
    assert_eq!(answer, "HTTP/1.1 400 Bad Request");
    let (_next, status) = retry_until_accepted(addr).await;
    assert_eq!(status, ESTABLISHED);
    task.abort();
}

#[test]
fn egress_max_connections_defaults_to_256_and_honours_override() {
    let key = "0".repeat(64);
    let base = format!(
        "version = 1\n[listen]\nproxy = \"127.0.0.1:8443\"\n[[identity]]\nname = \"ap-egress-test\"\ncaller_key_sha256 = \"{key}\"\n[egress]\nallow = [\"api.example.net:443\"]\n"
    );
    let default = ap_core::config::load(&base).expect("base config is valid");
    assert_eq!(default.egress.max_connections, 256);
    let set =
        ap_core::config::load(&format!("{base}max_connections = 7\n")).expect("override is valid");
    assert_eq!(set.egress.max_connections, 7);
    assert!(ap_core::config::load(&format!("{base}max_connections = 0\n")).is_err());
}
