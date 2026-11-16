//! Accept loop with a cap on concurrent connections.

use crate::connect::{serve_conn, Connector};
use crate::resolve::Resolver;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Accept connections and serve each one on its own task, holding one of `max_connections`
/// permits for the life of that task. When no permit is free, the new connection is closed at
/// once and nothing is spawned, so the loop never waits on a connection. The permit returns when
/// the task ends, whether the connection succeeded, failed or timed out.
pub async fn serve_listener<R, C>(
    listener: TcpListener,
    allow: Arc<Vec<String>>,
    resolver: Arc<R>,
    connector: Arc<C>,
    max_connections: usize,
) -> !
where
    R: Resolver + Send + Sync + 'static,
    C: Connector + Send + Sync + 'static,
{
    let permits = Arc::new(Semaphore::new(max_connections));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    eprintln!(
                        "ap-egress: connection cap of {max_connections} reached, closing new connection"
                    );
                    drop(stream);
                    continue;
                };
                let allow = Arc::clone(&allow);
                let resolver = Arc::clone(&resolver);
                let connector = Arc::clone(&connector);
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = serve_conn(stream, &allow, &*resolver, &*connector).await;
                });
            }
            Err(e) => {
                eprintln!("ap-egress: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
