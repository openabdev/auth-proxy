//! The public passthrough listener: an accept loop with a connection cap and a header-read
//! timeout, over hyper's HTTP/1 server. The socket still comes from `bind_loopback`.
//!
//! A handler that returns `Err(ConnAbort)` closes the connection with no answer. A panic in a
//! handler ends only its own connection task.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::passthrough::{self, PtApp};

/// Public-listener limits, from `[passthrough]`.
#[derive(Debug, Clone, Copy)]
pub struct PublicLimits {
    pub max_connections: usize,
    pub header_read: Duration,
}

/// Serve until the listener fails. Connections over the cap are accepted and closed at once.
pub async fn serve_public(listener: TcpListener, app: Arc<PtApp>, limits: PublicLimits) {
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => {
                // A transient accept error (descriptor exhaustion) must not spin.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        let app = Arc::clone(&app);
        tokio::spawn(async move {
            let svc = service_fn(move |req: hyper::Request<Incoming>| {
                let app = Arc::clone(&app);
                async move { passthrough::handle(app, req.map(Body::new)).await }
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_read)
                .serve_connection(TokioIo::new(stream), svc)
                .await;
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{buffer_sink, caller_key, client_for, start_upstream, Scratch, HOST};
    use ap_broker::registry::sha256_hex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn start(max: usize, header_read: Duration) -> (std::net::SocketAddr, String, Scratch) {
        let up = start_upstream().await;
        let s = Scratch::new("pub");
        let key = caller_key();
        let text = format!(
            r#"version = 1
[listen]
proxy = "127.0.0.1:8443"
[passthrough]
public_authority = "gate.example.test"
body_read_secs = 1
[[identity]]
name = "muse-pilot"
caller_key_sha256 = "{}"
[[route]]
name = "discord"
host = "{HOST}"
port = {}
mode = "passthrough"
[[grant]]
identity = "muse-pilot"
route = "discord"
methods = ["GET", "POST"]
paths = ["/api/", "/up/"]
"#,
            sha256_hex(&key),
            up.addr.port()
        );
        let path = s.path().join("policy.toml");
        std::fs::write(&path, &text).unwrap();
        let cfg = ap_core::config::load(&text).unwrap();
        let (sink, _audit) = buffer_sink();
        let app = PtApp::new(path, cfg, sink, client_for(&up));
        let l = crate::listener::bind_loopback("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve_public(
            l,
            app,
            PublicLimits {
                max_connections: max,
                header_read,
            },
        ));
        // Keep the upstream alive for the test's duration.
        Box::leak(Box::new(up));
        (addr, key, s)
    }

    fn get(key: &str) -> String {
        format!(
            "GET /discord/api/x HTTP/1.1\r\nHost: gate.example.test\r\nx-ap-caller-key: {key}\r\nauthorization: Bot t\r\n\r\n"
        )
    }

    async fn read_some(c: &mut TcpStream) -> String {
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await {
            Ok(Ok(n)) => String::from_utf8_lossy(&buf[..n]).into_owned(),
            // A reset is a close for these tests.
            Ok(Err(_)) => String::new(),
            _ => "<timeout>".into(),
        }
    }

    #[tokio::test]
    async fn connection_cap_closes_the_extra_connection() {
        let (addr, key, _s) = start(2, Duration::from_secs(5)).await;
        let mut a = TcpStream::connect(addr).await.unwrap();
        let mut b = TcpStream::connect(addr).await.unwrap();
        // Make sure both hold permits before the third arrives.
        a.write_all(get(&key).as_bytes()).await.unwrap();
        assert!(read_some(&mut a).await.starts_with("HTTP/1.1 200"));
        b.write_all(get(&key).as_bytes()).await.unwrap();
        assert!(read_some(&mut b).await.starts_with("HTTP/1.1 200"));
        let mut c = TcpStream::connect(addr).await.unwrap();
        let _ = c.write_all(get(&key).as_bytes()).await;
        assert_eq!(
            read_some(&mut c).await,
            "",
            "third connection must be closed"
        );
        // The first two still work (keep-alive).
        a.write_all(get(&key).as_bytes()).await.unwrap();
        assert!(read_some(&mut a).await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn header_read_timeout_closes_and_proxy_keeps_serving() {
        let (addr, key, _s) = start(8, Duration::from_millis(300)).await;
        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /discord/api/x HTT").await.unwrap();
        assert_eq!(read_some(&mut slow).await, "", "slow header must be closed");
        let mut ok = TcpStream::connect(addr).await.unwrap();
        ok.write_all(get(&key).as_bytes()).await.unwrap();
        assert!(read_some(&mut ok).await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn stalled_body_closes_and_proxy_keeps_serving() {
        let (addr, key, _s) = start(8, Duration::from_secs(5)).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        let head = format!(
            "POST /discord/up/echo2 HTTP/1.1\r\nHost: gate.example.test\r\nx-ap-caller-key: {key}\r\nauthorization: Bot t\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n"
        );
        c.write_all(head.as_bytes()).await.unwrap();
        assert_eq!(
            read_some(&mut c).await,
            "",
            "stalled body must close the connection"
        );
        let mut ok = TcpStream::connect(addr).await.unwrap();
        ok.write_all(get(&key).as_bytes()).await.unwrap();
        assert!(read_some(&mut ok).await.starts_with("HTTP/1.1 200"));
    }
}
