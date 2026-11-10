//! Header sets shared by config validation and request forwarding.

/// Headers that can carry a credential. All are removed before forwarding;
/// then exactly one (the route's credential header) is set.
pub const AUTH_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-goog-api-key",
    "api-key",
    "cookie",
    "x-amz-security-token",
];

/// Hop-by-hop headers (RFC 9110 section 7.6.1) plus framing headers the forwarder sets itself.
pub const HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];
