//! HTTP/1.1 over a Unix socket. Each call opens one connection, sends one request and reads the
//! whole reply.

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use std::io;
use std::path::Path;
use std::time::Duration;
use tokio::net::UnixStream;

/// Longest wait for one request and its reply. A stalled proxy must not block the renew loop.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Failure before a reply was read.
#[derive(Debug)]
pub enum UdsError {
    Io(io::Error),
    Http(hyper::Error),
    Build(http::Error),
    Encode(serde_json::Error),
}

/// Status and body of a reply. The body is not interpreted here. There is no `Debug`: a hello
/// reply body carries the authority token.
pub struct Reply {
    pub status: u16,
    pub body: Bytes,
}

/// `GET path` with no body.
pub async fn get_json(sock: &Path, path: &str) -> Result<Reply, UdsError> {
    send(sock, "GET", path, None, None).await
}

/// `POST path` with a JSON body.
pub async fn post_json<T: Serialize + ?Sized>(
    sock: &Path,
    path: &str,
    bearer: Option<&str>,
    body: &T,
) -> Result<Reply, UdsError> {
    send(sock, "POST", path, bearer, Some(encode(body)?)).await
}

/// `PUT path` with a JSON body.
pub async fn put_json<T: Serialize + ?Sized>(
    sock: &Path,
    path: &str,
    bearer: Option<&str>,
    body: &T,
) -> Result<Reply, UdsError> {
    send(sock, "PUT", path, bearer, Some(encode(body)?)).await
}

/// `DELETE path` with no body.
pub async fn delete(sock: &Path, path: &str, bearer: Option<&str>) -> Result<Reply, UdsError> {
    send(sock, "DELETE", path, bearer, None).await
}

/// Aborts the connection driver when dropped. A request that times out drops its exchange, and
/// this stops the driver with it, so the socket closes instead of staying open against a peer
/// that never answers.
struct Driver(tokio::task::JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn encode<T: Serialize + ?Sized>(body: &T) -> Result<Vec<u8>, UdsError> {
    serde_json::to_vec(body).map_err(UdsError::Encode)
}

async fn send(
    sock: &Path,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<Vec<u8>>,
) -> Result<Reply, UdsError> {
    match tokio::time::timeout(IO_TIMEOUT, exchange(sock, method, path, bearer, body)).await {
        Ok(reply) => reply,
        Err(_) => Err(UdsError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "session plane did not answer in time",
        ))),
    }
}

async fn exchange(
    sock: &Path,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<Vec<u8>>,
) -> Result<Reply, UdsError> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, "localhost");
    if let Some(token) = bearer {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(bytes) => builder
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(bytes))),
        None => builder.body(Full::new(Bytes::new())),
    }
    .map_err(UdsError::Build)?;

    let stream = UnixStream::connect(sock).await.map_err(UdsError::Io)?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(UdsError::Http)?;
    let _driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = sender.send_request(request).await.map_err(UdsError::Http)?;
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(UdsError::Http)?
        .to_bytes();
    Ok(Reply { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn silent_peer_times_out() {
        let path = std::env::temp_dir().join(format!("apc-to-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind socket");
        let accept = tokio::spawn(async move {
            // Keep the connection open and never answer.
            let (stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(stream);
        });

        let err = match delete(&path, "/v1/sessions/x/1", None).await {
            Ok(_) => panic!("silent peer must fail"),
            Err(e) => e,
        };
        accept.abort();
        let _ = std::fs::remove_file(&path);

        match err {
            UdsError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected a timeout, got {other:?}"),
        }
    }
}
