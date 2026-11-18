//! The approval listener: a second hyper HTTP/1 accept loop, on its own socket (design 3.6).
//!
//! It shares nothing with the public listener except the hold table behind [`ApprovalApp`]. The
//! caps are fixed: 16 connections, 10 s to read a header block, and a 16 KiB header buffer. The
//! 1 KiB body limit is enforced by the handler.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::approval::{self, ApprovalApp};

/// Approval-listener limits.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalLimits {
    pub max_connections: usize,
    pub header_read: Duration,
}

impl Default for ApprovalLimits {
    fn default() -> ApprovalLimits {
        ApprovalLimits {
            max_connections: 16,
            header_read: Duration::from_secs(10),
        }
    }
}

/// Serve until the listener fails. Connections over the cap are accepted and closed at once.
pub async fn serve_approval(listener: TcpListener, app: Arc<ApprovalApp>, limits: ApprovalLimits) {
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => {
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
                async move {
                    Ok::<_, std::convert::Infallible>(
                        approval::handle(app, req.map(Body::new)).await,
                    )
                }
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_read)
                .max_buf_size(16 * 1024)
                .serve_connection(TokioIo::new(stream), svc)
                .await;
            drop(permit);
        });
    }
}
