//! Caller keys: `apk_` followed by 64 lowercase hex characters. The agent carries the key in its
//! URL path; the proxy config holds only its sha256.

use crate::surrogate::{random_hex32, sha256_hex};

/// A new caller key.
pub fn new_caller_key() -> String {
    format!("apk_{}", random_hex32())
}

/// The sha256 of `key` in lowercase hex, the value stored in `[[identity]] caller_key_sha256`.
pub fn caller_sha256(key: &str) -> String {
    sha256_hex(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_core::canon::is_lower_hex_64;

    #[test]
    fn caller_key_has_prefix_and_64_lowercase_hex() {
        let key = new_caller_key();
        assert!(key.starts_with("apk_"));
        assert!(is_lower_hex_64(&key[4..]));
    }

    #[test]
    fn caller_keys_are_unique_and_digest_is_stable() {
        let a = new_caller_key();
        let b = new_caller_key();
        assert_ne!(a, b);
        assert_eq!(caller_sha256(&a), caller_sha256(&a));
        assert!(is_lower_hex_64(&caller_sha256(&a)));
    }
}
