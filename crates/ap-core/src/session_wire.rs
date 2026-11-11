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

/// `POST /v1/hello` body. `nonce` and `proof` are optional on the wire, so a body with only
/// `identity` parses and is refused later with `proof_missing`. The proxy checks them in the order
/// in `docs/design/runtime-split.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloReq {
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

/// `GET /v1/hello/challenge` reply: one nonce for one hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloChallenge {
    pub nonce: String,
    pub ttl_secs: u64,
}

/// The bytes the runtime signs for a hello:
/// `"auth-proxy hello v1\n" || u32_be(len(identity)) || identity || "\n" || nonce`.
/// The length prefix keeps the message unambiguous for any identity string.
pub fn hello_message(identity: &str, nonce: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20 + 4 + identity.len() + 1 + nonce.len());
    msg.extend_from_slice(b"auth-proxy hello v1\n");
    msg.extend_from_slice(&(identity.len() as u32).to_be_bytes());
    msg.extend_from_slice(identity.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(nonce.as_bytes());
    msg
}

/// A nonce as the proxy issues it: 64 lowercase hex characters.
pub fn is_nonce(s: &str) -> bool {
    is_lower_hex_64(s)
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
    /// Session keys in the list that were skipped because their stored absolute expiry has
    /// passed. The client must drop them and must not resend them. Absent in responses from an
    /// older proxy, which reads as an empty list. Omitted when empty, so a response with nothing
    /// expired has the older wire shape exactly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expired: Vec<SessionRef>,
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
    fn hello_accepts_identity_alone_so_the_proxy_can_refuse_it_as_proof_missing() {
        let r: HelloReq = serde_json::from_str(r#"{"identity":"pty-team-a"}"#).unwrap();
        assert_eq!(r.nonce, None);
        assert_eq!(r.proof, None);
    }

    #[test]
    fn hello_accepts_nonce_and_proof() {
        let r: HelloReq =
            serde_json::from_str(r#"{"identity":"a","nonce":"n","proof":"p"}"#).unwrap();
        assert_eq!(r.nonce.as_deref(), Some("n"));
        assert_eq!(r.proof.as_deref(), Some("p"));
    }

    #[test]
    fn hello_request_omits_absent_fields_on_the_wire() {
        let r = HelloReq {
            identity: "a".into(),
            nonce: None,
            proof: None,
        };
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"identity":"a"}"#);
    }

    #[test]
    fn hello_message_matches_the_fixed_vector() {
        // "auth-proxy hello v1\n", then the identity length as u32 big-endian (10 for
        // "pty-team-a"), the identity, a newline, and the 64-character nonce.
        let mut want = b"auth-proxy hello v1\n\x00\x00\x00\x0apty-team-a\n".to_vec();
        want.extend(std::iter::repeat_n(b'0', 64));
        assert_eq!(hello_message("pty-team-a", &"0".repeat(64)), want);
    }

    #[test]
    fn hello_message_length_prefix_keeps_identities_apart() {
        // An identity that contains a newline must not be readable as another identity plus nonce.
        let nonce = "0".repeat(64);
        let a = hello_message("a\nb", &nonce);
        let b = hello_message("a", &nonce);
        assert_ne!(a, b);
        assert_eq!(&a[20..24], &[0, 0, 0, 3]);
    }

    #[test]
    fn is_nonce_accepts_only_64_lowercase_hex() {
        assert!(is_nonce(&"a".repeat(64)));
        assert!(!is_nonce(&"A".repeat(64)));
        assert!(!is_nonce(&"a".repeat(63)));
        assert!(!is_nonce(""));
    }

    #[test]
    fn challenge_serializes_to_exactly_two_fields() {
        let c = HelloChallenge {
            nonce: "0".repeat(64),
            ttl_secs: 30,
        };
        let v: serde_json::Value = serde_json::to_value(&c).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 2);
        assert_eq!(v["ttl_secs"], 30);
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
    fn resync_response_without_expired_still_parses() {
        // The shape an older proxy sends: no `expired` field.
        let old: ResyncResp = serde_json::from_str(r#"{"registered":2,"dropped":1}"#).unwrap();
        assert_eq!(
            old,
            ResyncResp {
                registered: 2,
                dropped: 1,
                expired: vec![],
            }
        );
    }

    #[test]
    fn resync_response_with_nothing_expired_keeps_the_old_wire_shape() {
        // An older client denies unknown fields, so an empty `expired` must not be written.
        let resp = ResyncResp {
            registered: 2,
            dropped: 1,
            expired: vec![],
        };
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            r#"{"registered":2,"dropped":1}"#
        );
    }

    #[test]
    fn resync_response_carries_expired_session_keys() {
        let resp = ResyncResp {
            registered: 1,
            dropped: 0,
            expired: vec![SessionRef {
                session: "s1".into(),
                generation: 1,
            }],
        };
        let value: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            value["expired"],
            serde_json::json!([{"session": "s1", "generation": 1}])
        );
        let back: ResyncResp = serde_json::from_value(value).unwrap();
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
