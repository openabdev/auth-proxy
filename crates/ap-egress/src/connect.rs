//! CONNECT parsing, the allowlist decision and the tunnel (design Q3-E2).

use crate::Refuse;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest request head read before the request is refused.
pub const MAX_HEAD: usize = 8 * 1024;

/// Time the client has to send its request head.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Destination named by a CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

/// Opens the upstream stream to an address that has already been validated.
pub trait Connector: Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    fn connect(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// Parse a CONNECT request. `request_line` is the first line without CRLF. `headers` are the
/// remaining lines without CRLF.
///
/// Refused: any method but CONNECT (405), an absolute-form target, a bad version, a missing or
/// zero port, a second or mismatched Host header (400), and an IP literal target (403).
pub fn parse_connect(request_line: &str, headers: &[&str]) -> Result<HostPort, Refuse> {
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refuse::BadRequest);
    };
    if method != "CONNECT" {
        return Err(Refuse::MethodNotAllowed);
    }
    if version != "HTTP/1.1" || target.contains('/') {
        return Err(Refuse::BadRequest);
    }
    check_host_header(target, headers)?;
    split_target(target)
}

/// At most one Host header, and when present it must name the same authority as the target.
fn check_host_header(target: &str, headers: &[&str]) -> Result<(), Refuse> {
    let mut hosts = headers.iter().filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host").then(|| value.trim())
    });
    match (hosts.next(), hosts.next()) {
        (None, _) => Ok(()),
        (Some(value), None) if value == target => Ok(()),
        _ => Err(Refuse::BadRequest),
    }
}

/// Split `host:port`. IP literals are refused before any name lookup.
fn split_target(target: &str) -> Result<HostPort, Refuse> {
    let (host, port) = target.rsplit_once(':').ok_or(Refuse::BadRequest)?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or(Refuse::BadRequest)?;
    if host.is_empty() {
        return Err(Refuse::BadRequest);
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err(Refuse::IpLiteral);
    }
    match ap_core::canon::canonical_host(host) {
        Ok(()) => Ok(HostPort {
            host: host.to_string(),
            port,
        }),
        Err("IP literal") => Err(Refuse::IpLiteral),
        Err(why) if why.starts_with("numeric TLD") => Err(Refuse::IpLiteral),
        Err(_) => Err(Refuse::BadRequest),
    }
}

/// Read the request head. Returns the head text (without the blank line) and any bytes that
/// followed the blank line in the same reads.
pub async fn read_head<S: AsyncRead + Unpin>(client: &mut S) -> Result<(String, Vec<u8>), Refuse> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&buf[..end])
                .map_err(|_| Refuse::BadRequest)?
                .to_string();
            return Ok((head, buf[end + 4..].to_vec()));
        }
        if buf.len() > MAX_HEAD {
            return Err(Refuse::BadRequest);
        }
        let n = client
            .read(&mut chunk)
            .await
            .map_err(|_| Refuse::BadRequest)?;
        if n == 0 {
            return Err(Refuse::BadRequest);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Answer a refusal and close the connection.
pub async fn refuse<S: AsyncWrite + Unpin>(client: &mut S, why: Refuse) -> io::Result<()> {
    let head = format!(
        "{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        why.status_line()
    );
    client.write_all(head.as_bytes()).await?;
    client.shutdown().await
}

/// Connect to the validated `target`, answer 200, then copy bytes both ways until either side
/// closes. `early` holds client bytes that arrived with the request head; they go upstream first.
/// If the upstream connection fails, the client gets 502 and nothing is tunnelled.
pub async fn tunnel<S, C>(
    mut client: S,
    connector: &C,
    target: SocketAddr,
    early: &[u8],
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: Connector,
{
    let mut upstream = match connector.connect(target).await {
        Ok(stream) => stream,
        Err(_) => return refuse(&mut client, Refuse::Upstream).await,
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    if !early.is_empty() {
        upstream.write_all(early).await?;
    }
    copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}
