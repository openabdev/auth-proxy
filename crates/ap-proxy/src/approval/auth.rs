//! The approver credential: HTTP Basic, one user, a stored sha256 of the password (design 3.6).
//!
//! The credential is unrelated to any caller key and is checked only on the approval listener.
//! The password is compared through its sha256 in constant time, so neither its length nor a
//! matching prefix shows in the response time.

use std::fmt;

use ap_core::config::Approval;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::{header, HeaderMap};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The one approver, as the config names it.
pub struct Credentials {
    user: String,
    password_sha256: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials").finish_non_exhaustive()
    }
}

impl Credentials {
    pub fn new(cfg: &Approval) -> Credentials {
        Credentials {
            user: cfg.user.clone(),
            password_sha256: cfg.password_sha256.clone(),
        }
    }

    /// The approver's user name when `headers` carry exactly one `Authorization: Basic` header
    /// with the right user and password.
    pub fn authenticate(&self, headers: &HeaderMap) -> Option<String> {
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let value = values.next()?;
        if values.next().is_some() {
            return None;
        }
        let (user, password) = parse_basic(value.as_bytes())?;
        self.matches(&user, &password).then(|| self.user.clone())
    }

    fn matches(&self, user: &str, password: &str) -> bool {
        let presented = hex_sha256(password.as_bytes());
        let user_ok = user.as_bytes().ct_eq(self.user.as_bytes());
        let pass_ok = presented.as_bytes().ct_eq(self.password_sha256.as_bytes());
        bool::from(user_ok & pass_ok)
    }
}

/// Split `Basic base64(user:password)`. The scheme name is case-insensitive.
pub fn parse_basic(value: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(value).ok()?;
    let (scheme, rest) = text.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = STANDARD.decode(rest.trim_matches(' ')).ok()?;
    let raw = String::from_utf8(raw).ok()?;
    let (user, password) = raw.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

fn hex_sha256(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    pub(crate) fn basic(user: &str, password: &str) -> HeaderValue {
        HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(format!("{user}:{password}"))
        ))
        .unwrap()
    }

    fn creds() -> Credentials {
        Credentials {
            user: "owner".into(),
            password_sha256: hex_sha256(b"pw-0001"),
        }
    }

    fn headers(v: &[HeaderValue]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for x in v {
            h.append(header::AUTHORIZATION, x.clone());
        }
        h
    }

    #[test]
    fn right_user_and_password_authenticate() {
        let c = creds();
        assert_eq!(
            c.authenticate(&headers(&[basic("owner", "pw-0001")])),
            Some("owner".to_string())
        );
    }

    #[test]
    fn wrong_user_or_password_or_shape_is_refused() {
        let c = creds();
        for h in [
            headers(&[]),
            headers(&[basic("owner", "pw-0002")]),
            headers(&[basic("other", "pw-0001")]),
            headers(&[basic("owner", "")]),
            headers(&[HeaderValue::from_static("Bearer pw-0001")]),
            headers(&[HeaderValue::from_static("Basic !!!not-base64")]),
            headers(&[HeaderValue::from_static("Basic b3duZXI=")]),
            // Two Authorization headers, even when one is right.
            headers(&[basic("owner", "pw-0001"), basic("owner", "pw-0001")]),
        ] {
            assert_eq!(c.authenticate(&h), None);
        }
    }

    #[test]
    fn a_password_with_a_colon_and_a_lowercase_scheme_work() {
        let c = Credentials {
            user: "owner".into(),
            password_sha256: hex_sha256(b"a:b"),
        };
        let v = HeaderValue::from_str(&format!("basic {}", STANDARD.encode("owner:a:b"))).unwrap();
        assert!(c.authenticate(&headers(&[v])).is_some());
    }

    #[test]
    fn the_stored_hash_is_compared_with_ct_eq_over_equal_length_hex() {
        // The comparison input is always 64 hex bytes whatever the password length, so the
        // constant-time compare never short-circuits on length.
        for pw in ["", "x", &"y".repeat(5000)] {
            assert_eq!(hex_sha256(pw.as_bytes()).len(), 64);
        }
    }

    #[test]
    fn debug_shows_no_secret() {
        let text = format!("{:?}", creds());
        assert!(!text.contains("owner") && !text.contains(&hex_sha256(b"pw-0001")));
    }
}
