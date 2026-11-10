//! Allowlisting CONNECT proxy: library half.
//!
//! Only `CONNECT host:port` is served, and only when `host:port` is in `[egress].allow`. The name
//! is resolved here, every address it returns must be public, and the tunnel connects to that
//! exact address. Bytes are copied without inspection, so no credential is seen or added.

pub mod allow;
pub mod connect;

/// A refused CONNECT. Each variant maps to the status line the client receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refuse {
    /// Malformed request line, header block or target.
    BadRequest,
    /// Any method other than CONNECT, including plain-HTTP proxy requests.
    MethodNotAllowed,
    /// The target host is an IP literal.
    IpLiteral,
    /// The host:port is not in the allowlist.
    NotAllowed,
    /// The name resolves to an address in a refused range.
    PrivateAddress,
    /// The name did not resolve, or the connection to the validated address failed.
    Upstream,
}

impl Refuse {
    /// Status line sent back to the client.
    pub fn status_line(self) -> &'static str {
        match self {
            Refuse::BadRequest => "HTTP/1.1 400 Bad Request",
            Refuse::MethodNotAllowed => "HTTP/1.1 405 Method Not Allowed",
            Refuse::IpLiteral | Refuse::NotAllowed | Refuse::PrivateAddress => {
                "HTTP/1.1 403 Forbidden"
            }
            Refuse::Upstream => "HTTP/1.1 502 Bad Gateway",
        }
    }
}
