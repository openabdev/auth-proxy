//! Surrogate generation: `aps_` followed by 64 lowercase hex characters. The proxy stores only
//! the sha256 of a surrogate, so this module returns both.

use sha2::{Digest, Sha256};

/// A new surrogate and its sha256 in lowercase hex. The surrogate is the only copy of the
/// value the caller keeps; the proxy receives the digest.
pub fn new_surrogate() -> (String, String) {
    let surrogate = format!("aps_{}", random_hex32());
    let digest = sha256_hex(&surrogate);
    (surrogate, digest)
}

/// Lowercase sha256 of `s` in hex.
pub fn sha256_hex(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes()))
}

/// 32 bytes from the OS, in lowercase hex. The process stops if the OS has no randomness,
/// because a predictable surrogate or caller key is worse than no session.
pub(crate) fn random_hex32() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS randomness unavailable");
    hex(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_core::canon::is_lower_hex_64;

    #[test]
    fn surrogate_has_prefix_and_64_lowercase_hex_and_matching_digest() {
        let (surrogate, digest) = new_surrogate();
        assert!(surrogate.starts_with("aps_"));
        assert!(is_lower_hex_64(&surrogate[4..]));
        assert!(is_lower_hex_64(&digest));
        assert_eq!(digest, sha256_hex(&surrogate));
    }

    #[test]
    fn surrogates_are_unique() {
        let (a, _) = new_surrogate();
        let (b, _) = new_surrogate();
        assert_ne!(a, b);
    }
}
