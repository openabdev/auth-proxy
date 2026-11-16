//! The authority lock (Q1-B, Kubernetes).
//!
//! One session authority at a time. `hello` takes the lock and returns a
//! random token; only the token's sha256 is kept, in memory and in a
//! proxy-private state file. The authority renews every 30 s; the lock lapses
//! after 90 s without a renewal, and the caller then revokes every session.
//!
//! The runtime is the authority container's PID 1, so when it dies its shells
//! die with it, and the next `hello` can only come from the restarted runtime,
//! which sends it before any session exists. Until the lease lapses, a `hello`
//! from anyone gets 409.
//!
//! Proxy restart: the persisted hash stays valid, and the lock is treated as
//! live for one full authority lease from the restart (the proxy cannot know
//! how long ago the last renewal was).

use crate::error::PlaneError;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;
use subtle::ConstantTimeEq;

pub const DEFAULT_AUTHORITY_LEASE_SECS: u64 = 90;
/// How often the authority renews. Documented to clients; the lock itself only
/// needs the lease length.
pub const AUTHORITY_RENEW_SECS: u64 = 30;
/// Shorter leases exist only so tests can run fast.
pub const MIN_AUTHORITY_LEASE_SECS: u64 = 3;

struct Active {
    token_hash: [u8; 32],
    expires: Duration,
}

pub struct AuthorityLock {
    lease: Duration,
    state_path: Option<PathBuf>,
    active: Option<Active>,
}

impl AuthorityLock {
    /// `now` is the clock reading at construction (proxy start). A persisted
    /// token hash makes the lock live until `now + lease`.
    pub fn new(
        lease_secs: u64,
        state_path: Option<PathBuf>,
        now: Duration,
    ) -> Result<AuthorityLock, String> {
        if lease_secs < MIN_AUTHORITY_LEASE_SECS {
            return Err(format!(
                "authority lease must be at least {MIN_AUTHORITY_LEASE_SECS} s"
            ));
        }
        let lease = Duration::from_secs(lease_secs);
        let active = state_path
            .as_deref()
            .and_then(load_hash)
            .map(|token_hash| Active {
                token_hash,
                expires: now + lease,
            });
        Ok(AuthorityLock {
            lease,
            state_path,
            active,
        })
    }

    pub fn lease_secs(&self) -> u64 {
        self.lease.as_secs()
    }

    pub fn is_live(&self, now: Duration) -> bool {
        self.active.as_ref().is_some_and(|a| now < a.expires)
    }

    /// Free the lock if its lease has lapsed. Returns true when it just did,
    /// so the caller can revoke the authority's sessions.
    pub fn poll(&mut self, now: Duration) -> bool {
        if self.active.is_some() && !self.is_live(now) {
            self.active = None;
            self.clear_state();
            true
        } else {
            false
        }
    }

    /// Take the lock. Call `poll` first. Returns the token (shown once) or
    /// `AuthorityActive`.
    pub fn hello(&mut self, now: Duration) -> Result<String, PlaneError> {
        if self.is_live(now) {
            return Err(PlaneError::AuthorityActive);
        }
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw)
            .map_err(|_| PlaneError::Internal("no randomness available".into()))?;
        let token = format!("apt_{}", hex::encode(raw));
        let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        // Persist first: if the state cannot be written, the lock is not taken.
        self.persist(&token_hash)?;
        self.active = Some(Active {
            token_hash,
            expires: now + self.lease,
        });
        Ok(token)
    }

    /// Constant-time token check. A lapsed lock accepts no token.
    pub fn verify(&self, token: &str, now: Duration) -> bool {
        match &self.active {
            Some(a) if now < a.expires && token.len() <= 256 => {
                let h: [u8; 32] = Sha256::digest(token.as_bytes()).into();
                bool::from(h.ct_eq(&a.token_hash))
            }
            _ => false,
        }
    }

    /// Extend the lease to `now + lease`. Only the explicit renew call does
    /// this; no other request extends it.
    pub fn renew(&mut self, now: Duration) {
        if let Some(a) = self.active.as_mut() {
            a.expires = now + self.lease;
        }
    }

    fn persist(&self, hash: &[u8; 32]) -> Result<(), PlaneError> {
        let Some(path) = &self.state_path else {
            return Ok(());
        };
        let body = serde_json::json!({"version": 1, "token_sha256": hex::encode(hash)}).to_string();
        write_private(path, body.as_bytes())
            .map_err(|e| PlaneError::Internal(format!("persist authority state: {}", e.kind())))
    }

    fn clear_state(&self) {
        if let Some(path) = &self.state_path {
            // Best effort: a stale file only makes the lock live for one lease
            // after a later restart.
            let _ = std::fs::remove_file(path);
        }
    }
}

fn load_hash(path: &std::path::Path) -> Option<[u8; 32]> {
    let raw = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    if v.get("version")?.as_u64()? != 1 {
        return None;
    }
    let h = v.get("token_sha256")?.as_str()?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(h, &mut out).ok()?;
    Some(out)
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}
