//! The two values computed over a held request (design 3.4 step 4).
//!
//! Both start from one length-prefixed encoding of the complete outbound semantic request: method,
//! route, raw path, raw query, the forwarded header set in order, and the body. Length prefixes
//! make field boundaries unambiguous, so moving a byte between two fields changes the encoding.
//!
//! - The *audit digest* replaces credential header values with a fixed marker, so it can be shown
//!   and logged and reveals nothing about a credential.
//! - The *equality fingerprint* keeps the credential values and is an HMAC-SHA256 under a random
//!   per-process key. It lives in memory only and decides whether two requests are the same.

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::entry::HeldRequest;

/// Stands in for a credential header value in the audit digest.
const CREDENTIAL_MARKER: &[u8] = b"<credential>";
const DOMAIN: &[u8] = b"ap-hold-v1";

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// The length-prefixed encoding. With `blind`, credential header values become the marker.
fn encode(req: &HeldRequest, blind: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256 + req.body.len());
    put(&mut buf, DOMAIN);
    put(&mut buf, req.method.as_bytes());
    put(&mut buf, req.route.as_bytes());
    put(&mut buf, req.path.as_bytes());
    match &req.query {
        Some(q) => {
            buf.push(1);
            put(&mut buf, q.as_bytes());
        }
        None => buf.push(0),
    }
    buf.extend_from_slice(&(req.headers.len() as u64).to_be_bytes());
    for (name, value) in &req.headers {
        put(&mut buf, name.as_bytes());
        if blind && HeldRequest::is_credential(name) {
            put(&mut buf, CREDENTIAL_MARKER);
        } else {
            put(&mut buf, value);
        }
    }
    put(&mut buf, &req.body);
    buf
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Hex sha256 of the credential-blind encoding. Safe to show and to write to the audit stream.
pub fn audit_digest(req: &HeldRequest) -> String {
    hex(&Sha256::digest(encode(req, true)))
}

/// Random lowercase hex of `n` bytes, from the operating system.
pub fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("operating system random source failed");
    hex(&buf)
}

/// HMAC-SHA256 over the credential-inclusive encoding. Compared only for equality, never shown.
#[derive(Clone, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Fingerprint(..)")
    }
}

impl Fingerprint {
    /// Hex form, for tests that check the value never leaks.
    #[cfg(test)]
    pub(crate) fn hex_for_test(&self) -> String {
        hex(&self.0)
    }
}

/// Computes fingerprints under one random key, generated per process.
pub struct Fingerprinter {
    key: [u8; 32],
}

impl fmt::Debug for Fingerprinter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Fingerprinter(..)")
    }
}

impl Default for Fingerprinter {
    fn default() -> Self {
        Fingerprinter::new()
    }
}

impl Fingerprinter {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("operating system random source failed");
        Fingerprinter { key }
    }

    pub fn fingerprint(&self, req: &HeldRequest) -> Fingerprint {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key)
            .expect("HMAC accepts a key of any length");
        mac.update(&encode(req, false));
        Fingerprint(mac.finalize().into_bytes().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hold::Upstream;
    use bytes::Bytes;

    fn req() -> HeldRequest {
        HeldRequest {
            method: "POST".into(),
            route: "discord".into(),
            upstream: Upstream {
                scheme: "https".into(),
                host: "discord.example.test".into(),
                port: 443,
                keep_auth: Vec::new(),
            },
            generation: 1,
            path: "/channels/1/messages".into(),
            query: Some("wait=true".into()),
            headers: vec![
                ("authorization".into(), b"Bot SECRET-ONE".to_vec()),
                ("content-type".into(), b"application/json".to_vec()),
                ("x-api-key".into(), b"KEY-ONE".to_vec()),
            ],
            token_admitted: false,
            body: Bytes::from_static(b"{\"content\":\"hi\"}"),
        }
    }

    #[test]
    fn digest_is_stable_hex_sha256() {
        let d = audit_digest(&req());
        assert_eq!(d, audit_digest(&req()));
        assert_eq!(d.len(), 64);
        assert!(d
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn digest_is_credential_blind() {
        let mut other = req();
        other.headers[0].1 = b"Bot SECRET-TWO".to_vec();
        other.headers[2].1 = b"KEY-TWO".to_vec();
        assert_eq!(audit_digest(&req()), audit_digest(&other));
    }

    #[test]
    fn digest_still_sees_everything_else() {
        let base = audit_digest(&req());
        let mut r = req();
        r.body = Bytes::from_static(b"{\"content\":\"ho\"}");
        assert_ne!(base, audit_digest(&r));
        let mut r = req();
        r.headers[1].1 = b"application/json; charset=utf-8".to_vec();
        assert_ne!(base, audit_digest(&r));
        let mut r = req();
        r.query = None;
        assert_ne!(base, audit_digest(&r));
        let mut r = req();
        r.query = Some(String::new());
        assert_ne!(audit_digest(&r), {
            let mut n = req();
            n.query = None;
            audit_digest(&n)
        });
        let mut r = req();
        r.method = "PUT".into();
        assert_ne!(base, audit_digest(&r));
        let mut r = req();
        r.headers.remove(0);
        assert_ne!(
            base,
            audit_digest(&r),
            "dropping Authorization changes the digest"
        );
    }

    #[test]
    fn encoding_is_length_prefixed() {
        let mut a = req();
        a.route = "ab".into();
        a.path = "c".into();
        let mut b = req();
        b.route = "a".into();
        b.path = "bc".into();
        assert_ne!(audit_digest(&a), audit_digest(&b));
        let mut a = req();
        a.headers = vec![("a".into(), b"bc".to_vec())];
        let mut b = req();
        b.headers = vec![("ab".into(), b"c".to_vec())];
        assert_ne!(audit_digest(&a), audit_digest(&b));
    }

    #[test]
    fn repeated_header_order_matters() {
        let mut a = req();
        a.headers = vec![("x-a".into(), b"1".to_vec()), ("x-a".into(), b"2".to_vec())];
        let mut b = req();
        b.headers = vec![("x-a".into(), b"2".to_vec()), ("x-a".into(), b"1".to_vec())];
        assert_ne!(audit_digest(&a), audit_digest(&b));
    }

    #[test]
    fn fingerprint_sees_credentials() {
        let fp = Fingerprinter::new();
        let mut other = req();
        other.headers[0].1 = b"Bot SECRET-TWO".to_vec();
        assert_eq!(fp.fingerprint(&req()), fp.fingerprint(&req()));
        assert_ne!(fp.fingerprint(&req()), fp.fingerprint(&other));
        let mut other = req();
        other.headers[2].1 = b"KEY-TWO".to_vec();
        assert_ne!(fp.fingerprint(&req()), fp.fingerprint(&other));
    }

    #[test]
    fn fingerprint_key_is_per_instance() {
        let a = Fingerprinter::new();
        let b = Fingerprinter::new();
        assert_ne!(a.fingerprint(&req()), b.fingerprint(&req()));
    }

    #[test]
    fn debug_hides_fingerprint_and_key() {
        let fp = Fingerprinter::new();
        let f = fp.fingerprint(&req());
        let shown = format!("{f:?} {fp:?}");
        assert!(!shown.contains(&f.hex_for_test()));
        assert_eq!(shown, "Fingerprint(..) Fingerprinter(..)");
    }

    #[test]
    fn random_hex_has_requested_length_and_differs() {
        let a = random_hex(16);
        assert_eq!(a.len(), 32);
        assert_ne!(a, random_hex(16));
    }
}
