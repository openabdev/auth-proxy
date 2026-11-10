//! Session plane wire types (design Q1-B). Each type is one JSON request or response body.
//!
//! Validation returns the name of the first failing field. Nothing here is applied: the
//! caller applies a whole request only after every entry validates.

use crate::canon::is_lower_hex_64;
use serde::{Deserialize, Serialize};

/// Largest accepted session-plane request body, in bytes.
pub const BODY_CAP: usize = 1_048_576;

/// Most credentials one session may hold.
pub const MAX_CREDENTIALS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloReq {
    pub identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloResp {
    pub authority_token: String,
    pub lease_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRef {
    pub session: String,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub session: String,
    pub generation: u64,
    pub surrogate_sha256: String,
    pub credentials: Vec<String>,
}

/// `POST /v1/sessions` body. Same fields as one [`Entry`].
pub type RegisterReq = Entry;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterResp {
    pub lease_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewReq {
    pub sessions: Vec<SessionRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewResp {
    pub lease_secs: u64,
    /// Sessions the proxy does not know. The caller must register them again.
    pub unknown: Vec<SessionRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResyncReq {
    pub sessions: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResyncResp {
    pub registered: usize,
    pub dropped: usize,
}

/// A rejected field. `field` names the field that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireErr {
    pub field: &'static str,
}

/// Session id: 1 to 128 characters of `[A-Za-z0-9._:-]`.
pub fn validate_session(s: &str) -> Result<(), WireErr> {
    let ok = !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b':' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(WireErr { field: "session" })
    }
}

/// Validate one registration entry. Checks `session`, `surrogate_sha256` (64 lowercase hex)
/// and `credentials` (1 to 16 ids, each `[a-z0-9-]{1,32}`).
pub fn validate_entry(e: &Entry) -> Result<(), WireErr> {
    validate_session(&e.session)?;
    if !is_lower_hex_64(&e.surrogate_sha256) {
        return Err(WireErr {
            field: "surrogate_sha256",
        });
    }
    if e.credentials.is_empty() || e.credentials.len() > MAX_CREDENTIALS {
        return Err(WireErr {
            field: "credentials",
        });
    }
    let ids_ok = e.credentials.iter().all(|c| {
        !c.is_empty()
            && c.len() <= 32
            && c.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if ids_ok {
        Ok(())
    } else {
        Err(WireErr {
            field: "credentials",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn entry() -> Entry {
        Entry {
            session: "sess-1.a_b:c".into(),
            generation: 1,
            surrogate_sha256: SHA.into(),
            credentials: vec!["kiro".into()],
        }
    }

    #[test]
    fn session_accepts_allowed_charset_and_length() {
        assert!(validate_session("a").is_ok());
        assert!(validate_session("A-z_0.9:x").is_ok());
        assert!(validate_session(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn session_rejects_empty_long_and_bad_chars() {
        assert_eq!(validate_session(""), Err(WireErr { field: "session" }));
        assert_eq!(
            validate_session(&"a".repeat(129)),
            Err(WireErr { field: "session" })
        );
        for bad in ["a/b", "a b", "a\nb", "ä", "a?x", "a%20"] {
            assert_eq!(
                validate_session(bad),
                Err(WireErr { field: "session" }),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn entry_accepts_valid_fields() {
        assert_eq!(validate_entry(&entry()), Ok(()));
    }

    #[test]
    fn entry_rejects_bad_session_field() {
        let mut e = entry();
        e.session = "bad/session".into();
        assert_eq!(validate_entry(&e), Err(WireErr { field: "session" }));
    }

    #[test]
    fn entry_rejects_surrogate_not_64_lower_hex() {
        for bad in [
            SHA.to_uppercase(),
            SHA[..63].to_string(),
            format!("{SHA}0"),
            "z".repeat(64),
        ] {
            let mut e = entry();
            e.surrogate_sha256 = bad.clone();
            assert_eq!(
                validate_entry(&e),
                Err(WireErr {
                    field: "surrogate_sha256"
                }),
                "{bad}"
            );
        }
    }

    #[test]
    fn entry_rejects_zero_credentials() {
        let mut e = entry();
        e.credentials.clear();
        assert_eq!(
            validate_entry(&e),
            Err(WireErr {
                field: "credentials"
            })
        );
    }

    #[test]
    fn entry_rejects_more_than_sixteen_credentials() {
        let mut e = entry();
        e.credentials = (0..17).map(|i| format!("c{i}")).collect();
        assert_eq!(
            validate_entry(&e),
            Err(WireErr {
                field: "credentials"
            })
        );
    }

    #[test]
    fn entry_accepts_exactly_sixteen_credentials() {
        let mut e = entry();
        e.credentials = (0..16).map(|i| format!("c{i}")).collect();
        assert_eq!(validate_entry(&e), Ok(()));
    }

    #[test]
    fn entry_rejects_bad_credential_id() {
        let long = "a".repeat(33);
        for bad in ["", "Kiro", "a_b", long.as_str()] {
            let mut e = entry();
            e.credentials = vec![bad.to_string()];
            assert_eq!(
                validate_entry(&e),
                Err(WireErr {
                    field: "credentials"
                }),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn hello_rejects_unknown_key() {
        let r: Result<HelloReq, _> = serde_json::from_str(r#"{"identity":"a","extra":1}"#);
        assert!(r.is_err());
    }

    #[test]
    fn entry_rejects_unknown_key_on_the_wire() {
        let r: Result<Entry, _> = serde_json::from_str(
            r#"{"session":"s","generation":1,"surrogate_sha256":"x","credentials":["k"],"x":1}"#,
        );
        assert!(r.is_err());
    }

    #[test]
    fn renew_response_round_trips() {
        let resp = RenewResp {
            lease_secs: 900,
            unknown: vec![SessionRef {
                session: "s".into(),
                generation: 2,
            }],
        };
        let text = serde_json::to_string(&resp).unwrap();
        let back: RenewResp = serde_json::from_str(&text).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn register_request_is_an_entry() {
        let r: RegisterReq = entry();
        let text = serde_json::to_string(&r).unwrap();
        let back: Entry = serde_json::from_str(&text).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn body_cap_is_one_mebibyte() {
        assert_eq!(BODY_CAP, 1024 * 1024);
    }
}
