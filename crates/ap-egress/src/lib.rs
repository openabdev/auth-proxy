//! ap-egress: CONNECT-only allowlist proxy (Q3-E2).
//!
//! Accepts `CONNECT host:port` only, where the exact `host:port` is in the
//! policy's `[egress].allow`. Resolves the name once, refuses the request if
//! any answer is a non-public address, then connects to one of those exact
//! validated addresses (no second resolution) and copies bytes. It never
//! terminates TLS and logs only `host:port` and the decision.

use ap_core::canon::safe_field;
use ap_core::PolicyStore;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_HEAD: usize = 8 * 1024;

pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

/// Name resolution. Injectable so tests can script answers.
pub trait Resolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

/// The system resolver (getaddrinfo through tokio).
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

/// True for every address the proxy must never connect to.
pub fn forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => forbidden_v4(v),
        IpAddr::V6(v) => forbidden_v6(v),
    }
}

fn forbidden_v4(v: Ipv4Addr) -> bool {
    let o = v.octets();
    v.is_loopback()
        || v.is_private()
        || v.is_link_local()
        || v.is_unspecified()
        || v.is_multicast()
        || v.is_broadcast()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15
}

fn forbidden_v6(v: Ipv6Addr) -> bool {
    let s = v.segments();
    if v.is_loopback() || v.is_unspecified() || v.is_multicast() {
        return true;
    }
    if (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 {
        return true; // ULA, link-local
    }
    // v4-mapped ::ffff:a.b.c.d, v4-compatible ::a.b.c.d, NAT64 64:ff9b::/96
    let embedded =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    if s[..5] == [0; 5] && (s[5] == 0xffff || s[5] == 0) {
        return forbidden_v4(embedded(s[6], s[7]));
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        return forbidden_v4(embedded(s[6], s[7]));
    }
    false
}

#[derive(Clone)]
pub struct Options {
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub head_timeout: Duration,
    /// Address filter. Production uses `forbidden_ip`; tests replace it so a
    /// loopback echo server can stand in for an upstream.
    pub forbidden: fn(IpAddr) -> bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            head_timeout: Duration::from_secs(10),
            forbidden: forbidden_ip,
        }
    }
}

pub struct Egress {
    pub store: PolicyStore,
    pub resolver: Box<dyn Resolver>,
    pub opts: Options,
}

enum Refusal {
    Malformed,
    Method,
    NotAllowed(&'static str),
    Unavailable,
    BadGateway(&'static str),
    Timeout,
}

impl Refusal {
    fn status(&self) -> (u16, &'static str) {
        match self {
            Refusal::Malformed => (400, "Bad Request"),
            Refusal::Method => (405, "Method Not Allowed"),
            Refusal::NotAllowed(_) => (403, "Forbidden"),
            Refusal::Unavailable => (503, "Service Unavailable"),
            Refusal::BadGateway(_) => (502, "Bad Gateway"),
            Refusal::Timeout => (504, "Gateway Timeout"),
        }
    }
    fn reason(&self) -> &'static str {
        match self {
            Refusal::Malformed => "malformed",
            Refusal::Method => "method_not_allowed",
            Refusal::NotAllowed(r) | Refusal::BadGateway(r) => r,
            Refusal::Unavailable => "policy_unavailable",
            Refusal::Timeout => "connect_timeout",
        }
    }
}

fn audit(decision: &str, target: &str, reason: &str) {
    println!(
        "ap-egress decision={decision} target={} reason={reason}",
        safe_field(target)
    );
}

/// Accept loop. Runs until the listener fails.
pub async fn serve(listener: TcpListener, egress: Arc<Egress>) -> io::Result<()> {
    loop {
        let (sock, _) = listener.accept().await?;
        let eg = egress.clone();
        tokio::spawn(async move {
            handle(sock, &eg).await;
        });
    }
}

/// Read the request head. Returns the head text and any bytes read past it.
async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> Result<(String, Vec<u8>), Refusal> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            let head = String::from_utf8(buf).map_err(|_| Refusal::Malformed)?;
            return Ok((head, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(Refusal::Malformed);
        }
        let n = s.read(&mut chunk).await.map_err(|_| Refusal::Malformed)?;
        if n == 0 {
            return Err(Refusal::Malformed);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// `CONNECT host:port HTTP/1.x` -> (host lowercased, port, raw target).
fn parse_connect(head: &str) -> Result<(String, u16, String), Refusal> {
    let line = head.split("\r\n").next().unwrap_or("");
    let mut parts = line.split(' ');
    let (method, target, version, extra) = (parts.next(), parts.next(), parts.next(), parts.next());
    let (Some(method), Some(target), Some(version), None) = (method, target, version, extra) else {
        return Err(Refusal::Malformed);
    };
    if !version.starts_with("HTTP/1.") {
        return Err(Refusal::Malformed);
    }
    if method != "CONNECT" {
        return Err(Refusal::Method);
    }
    let raw = target.to_string();
    let (host, port) = target
        .rsplit_once(':')
        .ok_or(Refusal::NotAllowed("not_host_port"))?;
    if host.starts_with('[') || host.parse::<IpAddr>().is_ok() || host.contains(':') {
        return Err(Refusal::NotAllowed("ip_literal"));
    }
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::NotAllowed("bad_port"));
    }
    let port: u16 = port.parse().map_err(|_| Refusal::NotAllowed("bad_port"))?;
    Ok((host.to_ascii_lowercase(), port, raw))
}

async fn handle(mut client: TcpStream, eg: &Egress) {
    let head = tokio::time::timeout(eg.opts.head_timeout, read_head(&mut client)).await;
    let (head, rest) = match head {
        Ok(Ok(v)) => v,
        Ok(Err(r)) => return refuse(&mut client, "-", r).await,
        Err(_) => return refuse(&mut client, "-", Refusal::Malformed).await,
    };
    let (host, port, raw) = match parse_connect(&head) {
        Ok(v) => v,
        Err(r) => {
            let t = head.split(' ').nth(1).unwrap_or("-").to_string();
            return refuse(&mut client, &t, r).await;
        }
    };
    let target = format!("{host}:{port}");
    match connect_upstream(eg, &host, port).await {
        Ok(mut up) => {
            audit("allow", &target, "ok");
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            if !rest.is_empty() && up.write_all(&rest).await.is_err() {
                return;
            }
            tunnel(client, up, eg.opts.idle_timeout).await;
        }
        Err(r) => {
            let t = if matches!(r, Refusal::NotAllowed("ip_literal")) {
                &raw
            } else {
                &target
            };
            refuse(&mut client, t, r).await
        }
    }
}

/// Policy check, one resolution, address check, then connect to one of the
/// validated addresses from that single answer.
async fn connect_upstream(eg: &Egress, host: &str, port: u16) -> Result<TcpStream, Refusal> {
    let policy = eg.store.current().map_err(|_| Refusal::Unavailable)?;
    let listed = policy
        .config()
        .egress
        .entries()
        .iter()
        .any(|(h, p)| h == host && *p == port);
    if !listed {
        return Err(Refusal::NotAllowed("not_allowlisted"));
    }
    let addrs = eg
        .resolver
        .resolve(host, port)
        .await
        .map_err(|_| Refusal::BadGateway("resolve_failed"))?;
    if addrs.is_empty() {
        return Err(Refusal::BadGateway("resolve_empty"));
    }
    if addrs.iter().any(|a| (eg.opts.forbidden)(a.ip())) {
        return Err(Refusal::NotAllowed("forbidden_address"));
    }
    let mut last = Refusal::BadGateway("connect_failed");
    for a in addrs {
        match tokio::time::timeout(eg.opts.connect_timeout, TcpStream::connect(a)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(_)) => last = Refusal::BadGateway("connect_failed"),
            Err(_) => last = Refusal::Timeout,
        }
    }
    Err(last)
}

async fn tunnel(mut client: TcpStream, mut up: TcpStream, idle: Duration) {
    // The idle timeout is a rolling deadline on the whole copy: it restarts on
    // every chunk, which copy_bidirectional does not expose, so wrap both
    // directions in a stream that bumps a shared activity clock.
    let last = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
    let mut c = Tracked {
        inner: &mut client,
        last: last.clone(),
    };
    let mut u = Tracked {
        inner: &mut up,
        last: last.clone(),
    };
    let copy = copy_bidirectional(&mut c, &mut u);
    tokio::pin!(copy);
    loop {
        let deadline = *last.lock().unwrap() + idle;
        tokio::select! {
            _ = &mut copy => return,
            _ = tokio::time::sleep_until(deadline) => {
                if *last.lock().unwrap() + idle <= tokio::time::Instant::now() {
                    return;
                }
            }
        }
    }
}

struct Tracked<'a, S> {
    inner: &'a mut S,
    last: Arc<std::sync::Mutex<tokio::time::Instant>>,
}

impl<S> Tracked<'_, S> {
    fn bump(&self) {
        *self.last.lock().unwrap() = tokio::time::Instant::now();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let r = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if matches!(r, std::task::Poll::Ready(Ok(()))) {
            self.bump();
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let r = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if matches!(r, std::task::Poll::Ready(Ok(n)) if n > 0) {
            self.bump();
        }
        r
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

async fn refuse(client: &mut TcpStream, target: &str, r: Refusal) {
    let (code, text) = r.status();
    audit("refuse", target, r.reason());
    let body = format!("HTTP/1.1 {code} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = client.write_all(body.as_bytes()).await;
    let _ = client.shutdown().await;
}
