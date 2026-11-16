use ap_core::testing::sample_toml;
use ap_egress::{forbidden_ip, serve, Egress, Options, ResolveFuture, Resolver};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Scripted answers per call: the nth call returns answers[min(n, len-1)].
struct Script {
    answers: Mutex<HashMap<String, Vec<Vec<SocketAddr>>>>,
    calls: AtomicUsize,
}

impl Resolver for Script {
    fn resolve<'a>(&'a self, host: &'a str, _port: u16) -> ResolveFuture<'a> {
        Box::pin(async move {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let m = self.answers.lock().unwrap();
            let v = m
                .get(host)
                .ok_or_else(|| std::io::Error::other("nxdomain"))?;
            Ok(v[n.min(v.len() - 1)].clone())
        })
    }
}

fn permissive(_: IpAddr) -> bool {
    false
}

struct Rig {
    proxy: SocketAddr,
    accepted: Arc<AtomicUsize>,
    echo: SocketAddr,
    script: Arc<Script>,
    policy: PathBuf,
}

fn policy_text(allow: &str) -> String {
    let t = sample_toml();
    let head = t.split("[egress]").next().unwrap();
    format!("{head}[egress]\nallow = [{allow}]\n")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ape-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("policy.toml")
}

struct ArcResolver(Arc<Script>);
impl Resolver for ArcResolver {
    fn resolve<'a>(&'a self, h: &'a str, p: u16) -> ResolveFuture<'a> {
        self.0.resolve(h, p)
    }
}

async fn rig(
    tag: &str,
    answers: Vec<(&str, Vec<Vec<SocketAddr>>)>,
    forbidden: fn(IpAddr) -> bool,
) -> Rig {
    let echo_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = echo_l.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let acc = accepted.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo_l.accept().await.unwrap();
            acc.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 || s.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let policy = tmp(tag);
    std::fs::write(
        &policy,
        policy_text(r#""tunnel.example.com:443", "other.example.com:443""#),
    )
    .unwrap();
    let script = Arc::new(Script {
        answers: Mutex::new(
            answers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        ),
        calls: AtomicUsize::new(0),
    });
    let eg = Arc::new(Egress {
        store: ap_core::PolicyStore::open(&policy).unwrap(),
        resolver: Box::new(ArcResolver(script.clone())),
        opts: Options {
            forbidden,
            connect_timeout: Duration::from_secs(2),
            ..Options::default()
        },
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = l.local_addr().unwrap();
    tokio::spawn(serve(l, eg));
    Rig {
        proxy,
        accepted,
        echo,
        script,
        policy,
    }
}

/// Send a raw request, return the status line and the open stream.
async fn request(proxy: SocketAddr, raw: &str) -> (String, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(raw.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.unwrap() == 0 {
            break;
        }
        buf.push(b[0]);
    }
    let line = String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    (line, s)
}

fn connect(target: &str) -> String {
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n")
}

#[tokio::test]
async fn allowlisted_connect_tunnels_both_ways() {
    let r = rig("tunnel", vec![], permissive).await;
    r.script
        .answers
        .lock()
        .unwrap()
        .insert("tunnel.example.com".into(), vec![vec![r.echo]]);
    let (line, mut s) = request(r.proxy, &connect("tunnel.example.com:443")).await;
    assert!(line.contains("200"), "{line}");
    s.write_all(b"hello through the tunnel").await.unwrap();
    let mut got = vec![0u8; 24];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello through the tunnel");
    assert_eq!(r.accepted.load(Ordering::SeqCst), 1);
}

async fn refused(r: &Rig, raw: &str, want: &str) {
    let (line, _s) = request(r.proxy, raw).await;
    assert!(line.contains(want), "want {want}, got {line:?} for {raw:?}");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        r.accepted.load(Ordering::SeqCst),
        0,
        "upstream was contacted for {raw:?}"
    );
}

#[tokio::test]
async fn refusals_make_zero_upstream_connections() {
    // Resolver maps every name to the loopback echo, and the default address
    // filter is on, so even allowlisted names are refused as private.
    let mut r = rig("ref", vec![], forbidden_ip).await;
    let echo = r.echo;
    for h in [
        "tunnel.example.com",
        "unlisted.example.com",
        "other.example.com",
    ] {
        r.script
            .answers
            .lock()
            .unwrap()
            .insert(h.into(), vec![vec![echo]]);
    }
    // not listed
    refused(&r, &connect("unlisted.example.com:443"), " 403").await;
    // wrong port
    refused(&r, &connect("tunnel.example.com:8443"), " 403").await;
    // IP literals
    refused(&r, &connect("93.184.216.34:443"), " 403").await;
    refused(&r, &connect("[2606:2800:220:1::1]:443"), " 403").await;
    refused(&r, &connect("[::ffff:7f00:1]:443"), " 403").await;
    // listed, but resolves to loopback
    refused(&r, &connect("tunnel.example.com:443"), " 403").await;
    // plain-HTTP proxy forms
    refused(
        &r,
        "GET http://tunnel.example.com/ HTTP/1.1\r\nHost: tunnel.example.com\r\n\r\n",
        " 405",
    )
    .await;
    refused(
        &r,
        "POST http://tunnel.example.com/ HTTP/1.1\r\nHost: tunnel.example.com\r\n\r\n",
        " 405",
    )
    .await;
    // garbage
    refused(&r, "nonsense\r\n\r\n", " 400").await;
    r = rig("ref2", vec![], forbidden_ip).await;
    refused(&r, &connect("tunnel.example.com:443"), " 502").await; // nxdomain
}

#[test]
fn address_filter_covers_every_class() {
    for ip in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "100.64.0.1",
        "100.127.255.254",
        "::1",
        "::",
        "ff02::1",
        "fe80::1",
        "fc00::1",
        "fd12::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::7f00:1",
    ] {
        assert!(
            forbidden_ip(ip.parse().unwrap()),
            "{ip} should be forbidden"
        );
    }
    for ip in [
        "93.184.216.34",
        "140.82.112.3",
        "100.63.0.1",
        "100.128.0.1",
        "2606:2800:220:1::1",
        "::ffff:8.8.8.8",
    ] {
        assert!(!forbidden_ip(ip.parse().unwrap()), "{ip} should be allowed");
    }
}

#[tokio::test]
async fn private_resolution_mixed_with_public_is_refused() {
    let public: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let private: SocketAddr = "10.0.0.5:443".parse().unwrap();
    let r = rig(
        "mix",
        vec![("tunnel.example.com", vec![vec![public, private]])],
        forbidden_ip,
    )
    .await;
    let (line, _s) = request(r.proxy, &connect("tunnel.example.com:443")).await;
    assert!(line.contains(" 403"), "{line}");
}

#[tokio::test]
async fn one_resolution_and_the_first_answer_is_the_one_connected() {
    let bad: SocketAddr = "10.9.9.9:443".parse().unwrap();
    let r = rig("rebind", vec![], permissive).await;
    // First answer: the echo. Any later answer would be a private address.
    r.script
        .answers
        .lock()
        .unwrap()
        .insert("tunnel.example.com".into(), vec![vec![r.echo], vec![bad]]);
    let (line, mut s) = request(r.proxy, &connect("tunnel.example.com:443")).await;
    assert!(line.contains("200"), "{line}");
    s.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
    assert_eq!(
        r.script.calls.load(Ordering::SeqCst),
        1,
        "resolved more than once"
    );
    assert_eq!(r.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn policy_file_deleted_refuses_all_with_503_then_recovers() {
    let r = rig("pol", vec![], permissive).await;
    r.script
        .answers
        .lock()
        .unwrap()
        .insert("tunnel.example.com".into(), vec![vec![r.echo]]);
    let (line, s) = request(r.proxy, &connect("tunnel.example.com:443")).await;
    assert!(line.contains("200"), "{line}");
    drop(s);
    let before = r.accepted.load(Ordering::SeqCst);
    let saved = std::fs::read(&r.policy).unwrap();
    std::fs::remove_file(&r.policy).unwrap();
    let (line, _s) = request(r.proxy, &connect("tunnel.example.com:443")).await;
    assert!(line.contains(" 503"), "{line}");
    std::fs::write(&r.policy, b"").unwrap();
    let (line, _s) = request(r.proxy, &connect("tunnel.example.com:443")).await;
    assert!(line.contains(" 503"), "0-byte file: {line}");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(r.accepted.load(Ordering::SeqCst), before);
    std::fs::write(&r.policy, saved).unwrap();
    let (line, _s) = request(r.proxy, &connect("tunnel.example.com:443")).await;
    assert!(line.contains("200"), "after restore: {line}");
}
