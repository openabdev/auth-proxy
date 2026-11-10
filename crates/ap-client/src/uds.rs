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
use tokio::net::UnixStream;

/// Failure before a reply was read.
#[derive(Debug)]
pub enum UdsError {
    Io(io::Error),
    Http(hyper::Error),
    Build(http::Error),
    Encode(serde_json::Error),
}

/// Status and body of a reply. The body is not interpreted here.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub body: Bytes,
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
    tokio::spawn(async move {
        let _ = connection.await;
    });
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
