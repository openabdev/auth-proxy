//! Hello proof: an Ed25519 signature over `hello_message(identity, nonce)` made with the runtime's
//! seed. The proxy holds only the public key. This module checks a proof and keeps the nonce table
//! that makes each proof single-use. See `docs/design/runtime-split.md`, "Hello proof".

use std::collections::VecDeque;

use ap_core::session_wire::hello_message;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

/// How long an issued nonce stays usable.
pub const NONCE_TTL_SECS: u64 = 30;

/// Most nonces outstanding at once. The oldest is evicted first.
pub const NONCE_CAP: usize = 64;

/// Why a proof or a key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofErr {
    /// The configured public key is not standard base64 of 32 bytes that is a valid Ed25519 point.
    KeyInvalid,
    /// The proof is not standard base64 of 64 bytes, or the signature does not verify.
    ProofInvalid,
}

/// Decode a configured public key: standard base64 of exactly 32 bytes.
pub fn parse_public_key(b64: &str) -> Result<VerifyingKey, ProofErr> {
    let bytes = STANDARD.decode(b64).map_err(|_| ProofErr::KeyInvalid)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ProofErr::KeyInvalid)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| ProofErr::KeyInvalid)
}

/// Check `proof_b64` over the hello message for `identity` and `nonce`. The signature is checked
/// with `verify_strict`, which rejects non-canonical signatures and small-order keys.
pub fn verify(
    key: &VerifyingKey,
    identity: &str,
    nonce: &str,
    proof_b64: &str,
) -> Result<(), ProofErr> {
    let raw = STANDARD
        .decode(proof_b64)
        .map_err(|_| ProofErr::ProofInvalid)?;
    let sig = Signature::from_slice(&raw).map_err(|_| ProofErr::ProofInvalid)?;
    key.verify_strict(&hello_message(identity, nonce), &sig)
        .map_err(|_| ProofErr::ProofInvalid)
}

/// Issued nonces, each with its issue time. Bounded at [`NONCE_CAP`] entries.
#[derive(Debug, Default)]
pub struct NonceTable {
    entries: VecDeque<(String, u64)>,
}

impl NonceTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// A new nonce issued at `now` (Unix seconds): 32 OS random bytes as 64 lowercase hex.
    pub fn issue(&mut self, now: u64) -> String {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS randomness unavailable");
        let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        if self.entries.len() == NONCE_CAP {
            self.entries.pop_front();
        }
        self.entries.push_back((nonce.clone(), now));
        nonce
    }

    /// Take `nonce` out of the table. True only when it was issued and is still inside its TTL.
    /// The entry is removed whether or not the caller then passes, so a nonce works once.
    pub fn consume(&mut self, nonce: &str, now: u64) -> bool {
        let Some(pos) = self.entries.iter().position(|(n, _)| n == nonce) else {
            return false;
        };
        let Some((_, issued)) = self.entries.remove(pos) else {
            return false;
        };
        now.saturating_sub(issued) <= NONCE_TTL_SECS
    }

    /// Entries held, expired or not.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const SEED: [u8; 32] = [7u8; 32];
    const OTHER_SEED: [u8; 32] = [9u8; 32];
    const IDENTITY: &str = "pty-team-a";

    fn pubkey_b64(seed: &[u8; 32]) -> String {
        STANDARD.encode(SigningKey::from_bytes(seed).verifying_key().as_bytes())
    }

    fn sign_b64(seed: &[u8; 32], identity: &str, nonce: &str) -> String {
        let sig = SigningKey::from_bytes(seed).sign(&hello_message(identity, nonce));
        STANDARD.encode(sig.to_bytes())
    }

    fn key() -> VerifyingKey {
        parse_public_key(&pubkey_b64(&SEED)).expect("valid key")
    }

    fn nonce() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn right_key_and_nonce_verify() {
        let proof = sign_b64(&SEED, IDENTITY, &nonce());
        assert_eq!(verify(&key(), IDENTITY, &nonce(), &proof), Ok(()));
    }

    #[test]
    fn signature_from_another_key_is_refused() {
        let proof = sign_b64(&OTHER_SEED, IDENTITY, &nonce());
        assert_eq!(
            verify(&key(), IDENTITY, &nonce(), &proof),
            Err(ProofErr::ProofInvalid)
        );
    }

    #[test]
    fn proof_for_one_identity_is_refused_under_another() {
        let proof = sign_b64(&SEED, "pty-team-a", &nonce());
        assert_eq!(
            verify(&key(), "pty-team-b", &nonce(), &proof),
            Err(ProofErr::ProofInvalid)
        );
    }

    #[test]
    fn proof_for_one_nonce_is_refused_under_another() {
        let proof = sign_b64(&SEED, IDENTITY, &nonce());
        let other = "f".repeat(64);
        assert_eq!(
            verify(&key(), IDENTITY, &other, &proof),
            Err(ProofErr::ProofInvalid)
        );
    }

    #[test]
    fn proof_that_is_not_64_bytes_is_refused() {
        let full = sign_b64(&SEED, IDENTITY, &nonce());
        let raw = STANDARD.decode(&full).expect("b64");
        for len in [63usize, 65] {
            let mut bytes = raw.clone();
            bytes.resize(len, 0);
            let short = STANDARD.encode(&bytes);
            assert_eq!(
                verify(&key(), IDENTITY, &nonce(), &short),
                Err(ProofErr::ProofInvalid),
                "{len} bytes"
            );
        }
    }

    #[test]
    fn proof_that_is_not_base64_is_refused() {
        assert_eq!(
            verify(&key(), IDENTITY, &nonce(), "!!not base64!!"),
            Err(ProofErr::ProofInvalid)
        );
    }

    #[test]
    fn public_key_must_be_32_bytes_of_base64() {
        assert_eq!(parse_public_key("not-base64!"), Err(ProofErr::KeyInvalid));
        assert_eq!(
            parse_public_key(&STANDARD.encode([0u8; 31])),
            Err(ProofErr::KeyInvalid)
        );
        assert_eq!(
            parse_public_key(&STANDARD.encode([0u8; 33])),
            Err(ProofErr::KeyInvalid)
        );
    }

    #[test]
    fn issued_nonce_is_64_lowercase_hex_and_consumes_once() {
        let mut t = NonceTable::new();
        let n = t.issue(100);
        assert_eq!(n.len(), 64);
        assert!(n
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert!(t.consume(&n, 101));
        assert!(!t.consume(&n, 101), "a nonce works once");
    }

    #[test]
    fn nonce_never_issued_is_refused() {
        let mut t = NonceTable::new();
        t.issue(100);
        assert!(!t.consume(&"a".repeat(64), 100));
    }

    #[test]
    fn nonce_older_than_its_ttl_is_refused_and_removed() {
        let mut t = NonceTable::new();
        let n = t.issue(100);
        assert!(!t.consume(&n, 100 + NONCE_TTL_SECS + 1));
        assert!(t.is_empty(), "the expired entry is gone");
    }

    #[test]
    fn nonce_exactly_at_its_ttl_is_still_accepted() {
        let mut t = NonceTable::new();
        let n = t.issue(100);
        assert!(t.consume(&n, 100 + NONCE_TTL_SECS));
    }

    #[test]
    fn the_65th_issue_evicts_the_oldest_nonce() {
        let mut t = NonceTable::new();
        let first = t.issue(100);
        let rest: Vec<String> = (1..NONCE_CAP).map(|_| t.issue(100)).collect();
        assert_eq!(t.len(), NONCE_CAP);
        let last = t.issue(100);
        assert_eq!(t.len(), NONCE_CAP);
        assert!(!t.consume(&first, 100), "oldest is evicted");
        assert!(t.consume(&last, 100));
        assert!(t.consume(&rest[0], 100));
    }
}
