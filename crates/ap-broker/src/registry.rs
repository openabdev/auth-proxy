//! Session registry (Q1-B). Keyed by the sha256 of the surrogate: the proxy
//! never sees a surrogate until a request presents one, and never stores it.
//!
//! All methods take `now` explicitly (time since the clock's origin). The
//! registry has no lock of its own; `SessionPlane` serializes access.

use crate::error::PlaneError;
use ap_core::{Code, Policy};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

/// Per-session lease: 15 minutes from the last renewal.
pub const DEFAULT_SESSION_LEASE_SECS: u64 = 15 * 60;
/// Absolute session TTL: 12 hours from first registration. Renewal never
/// extends past it.
pub const DEFAULT_ABSOLUTE_TTL_SECS: u64 = 12 * 60 * 60;
pub const DEFAULT_MAX_SESSIONS: usize = 256;
const MAX_TOMBSTONES: usize = 1024;

#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub lease: Duration,
    pub absolute_ttl: Duration,
    pub max_sessions: usize,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        RegistryConfig {
            lease: Duration::from_secs(DEFAULT_SESSION_LEASE_SECS),
            absolute_ttl: Duration::from_secs(DEFAULT_ABSOLUTE_TTL_SECS),
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }
}

/// `POST /v1/sessions` body, and one element of a `PUT /v1/sessions` list.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RegisterReq {
    pub session: String,
    pub generation: u64,
    pub surrogate_sha256: String,
    pub credentials: Vec<String>,
}

/// One live session, as named in `renew`.
#[derive(Deserialize, serde::Serialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct SessionRef {
    pub session: String,
    pub generation: u64,
}

/// A `RegisterReq` that passed field validation and the grant check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidEntry {
    pub session: String,
    pub generation: u64,
    pub hash: [u8; 32],
    pub credentials: Vec<String>,
}

impl ValidEntry {
    fn key(&self) -> (String, u64) {
        (self.session.clone(), self.generation)
    }
}

fn session_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

/// Validate one registration against the config. Field problems (400) are
/// reported before grant problems (403), and nothing is changed.
pub fn validate_register(policy: &Policy, req: &RegisterReq) -> Result<ValidEntry, PlaneError> {
    if !session_ok(&req.session) {
        return Err(PlaneError::Invalid(
            "session must be 1-128 characters of [A-Za-z0-9._:-]".into(),
        ));
    }
    let h = &req.surrogate_sha256;
    let mut hash = [0u8; 32];
    let hex_ok = h.len() == 64
        && h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && hex::decode_to_slice(h, &mut hash).is_ok();
    if !hex_ok {
        return Err(PlaneError::Invalid(
            "surrogate_sha256 must be 64 lowercase hex characters".into(),
        ));
    }
    if req.credentials.is_empty() || req.credentials.len() > 16 {
        return Err(PlaneError::Invalid(
            "credentials must list 1 to 16 ids".into(),
        ));
    }
    let mut seen = HashSet::new();
    for c in &req.credentials {
        if !seen.insert(c.as_str()) {
            return Err(PlaneError::Invalid(format!(
                "credential {c:?} listed twice"
            )));
        }
    }
    for c in &req.credentials {
        if policy.credential(c).is_none() {
            return Err(PlaneError::CredentialNotGranted(format!(
                "credential {c:?} is not defined for this identity"
            )));
        }
    }
    Ok(ValidEntry {
        session: req.session.clone(),
        generation: req.generation,
        hash,
        credentials: req.credentials.clone(),
    })
}

#[derive(Debug, Clone)]
struct Entry {
    hash: [u8; 32],
    credentials: Vec<String>,
    identity: String,
    lease_expires: Duration,
    hard_expires: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gone {
    Revoked,
    Expired,
}

/// Remembers why a recently dropped surrogate stopped working, so the CLI
/// sees `surrogate_revoked` or `surrogate_expired` instead of `unknown`.
/// Bounded; forgotten entries read as `surrogate_unknown`.
#[derive(Default)]
struct Tombstones {
    why: HashMap<[u8; 32], Gone>,
    order: VecDeque<[u8; 32]>,
}

impl Tombstones {
    fn add(&mut self, hash: [u8; 32], why: Gone) {
        if self.why.insert(hash, why).is_none() {
            self.order.push_back(hash);
            while self.order.len() > MAX_TOMBSTONES {
                if let Some(old) = self.order.pop_front() {
                    self.why.remove(&old);
                }
            }
        }
    }

    fn remove(&mut self, hash: &[u8; 32]) {
        self.why.remove(hash);
        // `order` keeps a stale slot until it is evicted; harmless.
    }
}

/// What admission needs to know about a live session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    pub session: String,
    pub generation: u64,
    pub identity: String,
    pub credentials: Vec<String>,
}

pub struct SessionRegistry {
    cfg: RegistryConfig,
    by_key: HashMap<(String, u64), Entry>,
    by_hash: HashMap<[u8; 32], (String, u64)>,
    tombs: Tombstones,
}

impl SessionRegistry {
    pub fn new(cfg: RegistryConfig) -> SessionRegistry {
        SessionRegistry {
            cfg,
            by_key: HashMap::new(),
            by_hash: HashMap::new(),
            tombs: Tombstones::default(),
        }
    }

    pub fn lease(&self) -> Duration {
        self.cfg.lease
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    fn drop_key(&mut self, key: &(String, u64), why: Gone) -> bool {
        match self.by_key.remove(key) {
            Some(e) => {
                self.by_hash.remove(&e.hash);
                self.tombs.add(e.hash, why);
                true
            }
            None => false,
        }
    }

    fn lease_until(&self, now: Duration, hard: Duration) -> Duration {
        (now + self.cfg.lease).min(hard)
    }

    /// Remove sessions whose lease has lapsed or whose absolute TTL is reached.
    pub fn sweep(&mut self, now: Duration) {
        let dead: Vec<_> = self
            .by_key
            .iter()
            .filter(|(_, e)| now >= e.lease_expires || now >= e.hard_expires)
            .map(|(k, _)| k.clone())
            .collect();
        for k in dead {
            self.drop_key(&k, Gone::Expired);
        }
    }

    /// Revoke everything (the authority's lease lapsed).
    pub fn revoke_all(&mut self) {
        let keys: Vec<_> = self.by_key.keys().cloned().collect();
        for k in keys {
            self.drop_key(&k, Gone::Revoked);
        }
    }

    /// `POST /v1/sessions`. Returns the session lease.
    pub fn register(
        &mut self,
        now: Duration,
        identity: &str,
        v: ValidEntry,
    ) -> Result<Duration, PlaneError> {
        self.sweep(now);
        let key = v.key();
        if let Some(e) = self.by_key.get(&key) {
            if e.hash != v.hash || e.credentials != v.credentials {
                return Err(PlaneError::Conflict(
                    "session and generation are already registered with another binding".into(),
                ));
            }
            // Idempotent retry: an explicit re-registration renews the lease,
            // capped by the original absolute TTL.
            let until = self.lease_until(now, e.hard_expires);
            self.by_key.get_mut(&key).unwrap().lease_expires = until;
            return Ok(self.cfg.lease);
        }
        if self.by_hash.contains_key(&v.hash) {
            return Err(PlaneError::Conflict(
                "surrogate hash is already bound to another session".into(),
            ));
        }
        if self.by_key.len() >= self.cfg.max_sessions {
            return Err(PlaneError::TooManySessions);
        }
        let hard = now + self.cfg.absolute_ttl;
        self.tombs.remove(&v.hash);
        self.by_hash.insert(v.hash, key.clone());
        self.by_key.insert(
            key,
            Entry {
                hash: v.hash,
                credentials: v.credentials,
                identity: identity.to_string(),
                lease_expires: self.lease_until(now, hard),
                hard_expires: hard,
            },
        );
        Ok(self.cfg.lease)
    }

    /// `POST /v1/renew` for sessions. Returns the refs that are not registered
    /// (never registered, revoked, lapsed, or past their absolute TTL).
    pub fn renew(&mut self, now: Duration, refs: &[SessionRef]) -> Vec<SessionRef> {
        self.sweep(now);
        let mut unknown = Vec::new();
        for r in refs {
            let key = (r.session.clone(), r.generation);
            match self.by_key.get(&key) {
                Some(e) => {
                    let until = self.lease_until(now, e.hard_expires);
                    self.by_key.get_mut(&key).unwrap().lease_expires = until;
                }
                None => unknown.push(r.clone()),
            }
        }
        unknown
    }

    /// `DELETE`. Idempotent: returns whether the session existed.
    pub fn revoke(&mut self, now: Duration, session: &str, generation: u64) -> bool {
        self.sweep(now);
        self.drop_key(&(session.to_string(), generation), Gone::Revoked)
    }

    /// `PUT /v1/sessions`: the list is the whole truth. Validates all of it
    /// before applying anything; on error nothing changes. Returns
    /// `(registered, dropped)`.
    pub fn resync(
        &mut self,
        now: Duration,
        identity: &str,
        list: Vec<ValidEntry>,
    ) -> Result<(usize, usize), PlaneError> {
        self.sweep(now);
        if list.len() > self.cfg.max_sessions {
            return Err(PlaneError::TooManySessions);
        }
        let mut keys = HashSet::new();
        let mut hashes = HashSet::new();
        for (i, v) in list.iter().enumerate() {
            if !keys.insert(v.key()) {
                return Err(
                    PlaneError::Invalid("session and generation listed twice".into()).at_entry(i),
                );
            }
            if !hashes.insert(v.hash) {
                return Err(PlaneError::Conflict("surrogate hash listed twice".into()).at_entry(i));
            }
            if let Some(e) = self.by_key.get(&v.key()) {
                if e.hash != v.hash || e.credentials != v.credentials {
                    return Err(PlaneError::Conflict(
                        "session and generation are already registered with another binding".into(),
                    )
                    .at_entry(i));
                }
            }
        }
        // Everything validated: apply.
        let stale: Vec<_> = self
            .by_key
            .keys()
            .filter(|k| !keys.contains(*k))
            .cloned()
            .collect();
        let dropped = stale.len();
        for k in stale {
            self.drop_key(&k, Gone::Revoked);
        }
        for v in &list {
            let key = v.key();
            if let Some(e) = self.by_key.get(&key) {
                let until = self.lease_until(now, e.hard_expires);
                self.by_key.get_mut(&key).unwrap().lease_expires = until;
            } else {
                let hard = now + self.cfg.absolute_ttl;
                self.tombs.remove(&v.hash);
                self.by_hash.insert(v.hash, key.clone());
                self.by_key.insert(
                    key,
                    Entry {
                        hash: v.hash,
                        credentials: v.credentials.clone(),
                        identity: identity.to_string(),
                        lease_expires: self.lease_until(now, hard),
                        hard_expires: hard,
                    },
                );
            }
        }
        Ok((list.len(), dropped))
    }

    /// Admission lookup by surrogate hash. A lapsed or past-TTL session is
    /// removed here too, so a request never rides on a stale lease.
    pub fn lookup(&mut self, now: Duration, hash: &[u8; 32]) -> Result<SessionView, Code> {
        self.sweep(now);
        match self
            .by_hash
            .get(hash)
            .and_then(|k| self.by_key.get(k).map(|e| (k, e)))
        {
            Some((k, e)) => Ok(SessionView {
                session: k.0.clone(),
                generation: k.1,
                identity: e.identity.clone(),
                credentials: e.credentials.clone(),
            }),
            None => Err(match self.tombs.why.get(hash) {
                Some(Gone::Revoked) => Code::SurrogateRevoked,
                Some(Gone::Expired) => Code::SurrogateExpired,
                None => Code::SurrogateUnknown,
            }),
        }
    }
}
