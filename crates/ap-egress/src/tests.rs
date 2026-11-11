//! Refusal list, exact-address connect and single lookup, through doubles for the resolver and
//! the connector. No test touches the network.

use crate::allow::allowed;
use crate::connect::{parse_connect, serve_conn, Connector, HostPort};
use crate::resolve::{check_addr, Resolver};
use crate::Refuse;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

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
