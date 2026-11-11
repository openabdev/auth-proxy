//! The runtime's hello key. The runtime holds an Ed25519 seed and signs one hello per nonce. The
//! proxy holds only the public key. See `docs/design/runtime-split.md`, "Hello proof".
//!
//! `RuntimeKey` has no `Debug` or `Display`, so the seed is not printed by accident.

use ap_core::session_wire::hello_message;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

/// Why a seed was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyErr {
    /// The seed is not standard base64 of exactly 32 bytes.
    Malformed,
}

pub struct RuntimeKey {
    signing: SigningKey,
}

impl RuntimeKey {
    /// Load the seed from its text form: standard base64 of 32 bytes. Surrounding whitespace,
    /// such as a trailing newline, is ignored.
    pub fn from_seed_b64(text: &str) -> Result<RuntimeKey, KeyErr> {
        let bytes = STANDARD
            .decode(text.trim())
            .map_err(|_| KeyErr::Malformed)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| KeyErr::Malformed)?;
        Ok(RuntimeKey {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// The public key as standard base64 of 32 bytes. This is the value the proxy config holds
    /// as `runtime_pubkey`.
    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.signing.verifying_key().as_bytes())
    }

    /// Standard base64 of the 64-byte signature over the hello message for `identity` and
    /// `nonce`.
    pub fn sign_hello(&self, identity: &str, nonce: &str) -> String {
        let sig = self.signing.sign(&hello_message(identity, nonce));
        STANDARD.encode(sig.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    const SEED: [u8; 32] = [7u8; 32];
    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn key() -> RuntimeKey {
        RuntimeKey::from_seed_b64(&STANDARD.encode(SEED)).expect("seed")
    }

    #[test]
    fn signature_verifies_under_the_public_key() {
        let k = key();
        let proof = STANDARD
            .decode(k.sign_hello("pty-team-a", NONCE))
            .expect("b64");
        let sig = Signature::from_slice(&proof).expect("64 bytes");
        let pubkey = STANDARD.decode(k.public_key_b64()).expect("b64");
        let vk = VerifyingKey::from_bytes(&pubkey.try_into().expect("32 bytes")).expect("point");
        assert!(vk
            .verify_strict(&hello_message("pty-team-a", NONCE), &sig)
            .is_ok());
    }

    #[test]
    fn signature_is_bound_to_the_identity() {
        let k = key();
        let proof = STANDARD
            .decode(k.sign_hello("pty-team-a", NONCE))
            .expect("b64");
        let sig = Signature::from_slice(&proof).expect("64 bytes");
        let pubkey = STANDARD.decode(k.public_key_b64()).expect("b64");
        let vk = VerifyingKey::from_bytes(&pubkey.try_into().expect("32 bytes")).expect("point");
        assert!(vk
            .verify_strict(&hello_message("pty-team-b", NONCE), &sig)
            .is_err());
    }

    #[test]
    fn seed_must_be_32_bytes_of_base64() {
        assert!(matches!(
            RuntimeKey::from_seed_b64(&STANDARD.encode([0u8; 31])),
            Err(KeyErr::Malformed)
        ));
        assert!(matches!(
            RuntimeKey::from_seed_b64("***"),
            Err(KeyErr::Malformed)
        ));
    }

    #[test]
    fn seed_text_may_end_with_a_newline() {
        let text = format!("{}\n", STANDARD.encode(SEED));
        assert!(RuntimeKey::from_seed_b64(&text).is_ok());
    }
}
