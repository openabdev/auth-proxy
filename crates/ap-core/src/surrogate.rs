//! Surrogate and caller-key formats.
//!
//! A surrogate is `aps_` + 64 lowercase hex, a caller key `apk_` + 64 lowercase
//! hex. The registry is keyed by `sha256` of the whole surrogate string,
//! including the `aps_` prefix, exactly as the CLI presents it in its
//! credential slot. The session authority must hash the same bytes.

use crate::code::Code;
use sha2::{Digest, Sha256};

fn prefixed_hex64(s: &str, prefix: &str) -> bool {
    s.len() == prefix.len() + 64
        && s.starts_with(prefix)
        && s[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn is_surrogate(s: &str) -> bool {
    prefixed_hex64(s, "aps_")
}

pub fn is_caller_key(s: &str) -> bool {
    prefixed_hex64(s, "apk_")
}

/// The registry key for a presented surrogate, or `surrogate_malformed`.
pub fn hash_surrogate(s: &str) -> Result<[u8; 32], Code> {
    if is_surrogate(s) {
        Ok(Sha256::digest(s.as_bytes()).into())
    } else {
        Err(Code::SurrogateMalformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let ok = format!("aps_{}", "0123456789abcdef".repeat(4));
        assert!(is_surrogate(&ok));
        assert!(hash_surrogate(&ok).is_ok());
        for bad in [
            "".to_string(),
            "aps_".to_string(),
            format!("aps_{}", "0".repeat(63)),
            format!("aps_{}", "0".repeat(65)),
            format!("aps_{}", "A".repeat(64)),
            format!("apk_{}", "0".repeat(64)),
            format!("aps_{}g", "0".repeat(63)),
            format!(" aps_{}", "0".repeat(64)),
        ] {
            assert_eq!(
                hash_surrogate(&bad),
                Err(Code::SurrogateMalformed),
                "{bad:?}"
            );
        }
        assert!(is_caller_key(&format!("apk_{}", "f".repeat(64))));
        assert!(!is_caller_key(&format!("aps_{}", "f".repeat(64))));
    }
}
