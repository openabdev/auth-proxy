//! Session registry: one authority token per identity, session leases, surrogate bindings and
//! tombstones for revoked surrogates. Everything is in memory except the authority token hash,
//! which `session::write_token_hash` persists so a proxy restart keeps the authority valid.
//!
//! Methods take `now` as a plain argument. Production callers pass `Clock::now()`, and tests
//! pass fixed values.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use ap_core::canon::is_lower_hex_64;
use ap_core::config::{Config, Sessions};
use ap_core::error::Code;
use ap_core::session_wire::{validate_entry, Entry, RenewResp, SessionRef, WireErr};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::clock::Clock;
use crate::session;

/// Absolute session lifetime from first registration. Matches the openab-pty default of 12 h.
pub const DEFAULT_ABSOLUTE_TTL_SECS: u64 = 12 * 60 * 60;

/// Prefix of an authority token. The token itself is never stored; only its sha256 is.
pub const TOKEN_PREFIX: &str = "apt_";

/// Lease and limit settings the registry applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryCfg {
    pub lease_secs: u64,
    pub authority_lease_secs: u64,
    /// Live sessions allowed per identity.
    pub max_sessions: usize,
    /// Lifetime of a session from first registration, regardless of renewals.
    pub absolute_ttl_secs: u64,
}

impl RegistryCfg {
    /// Settings from the `[sessions]` table, with the default absolute TTL.
    pub fn from_sessions(s: &Sessions) -> Self {
        RegistryCfg {
            lease_secs: s.lease_secs,
            authority_lease_secs: s.authority_lease_secs,
            max_sessions: s.max_sessions as usize,
            absolute_ttl_secs: DEFAULT_ABSOLUTE_TTL_SECS,
        }
    }
}

/// Who may hold which credentials, and which routes each credential covers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Access {
    /// Identity names from config.
    pub identities: Vec<String>,
    /// Identity name to the credential ids granted to it.
    pub grants: HashMap<String, HashSet<String>>,
    /// Credential id to the route names it may be applied to.
    pub credential_routes: HashMap<String, HashSet<String>>,
}

impl Access {
    pub fn from_config(cfg: &Config) -> Self {
        let mut access = Access {
            identities: cfg.identities.iter().map(|i| i.name.clone()).collect(),
            ..Access::default()
        };
        for c in &cfg.credentials {
            access
                .credential_routes
                .insert(c.id.clone(), c.routes.iter().cloned().collect());
        }
        for g in &cfg.grants {
            access
                .grants
                .entry(g.identity.clone())
                .or_default()
                .insert(g.credential.clone());
        }
        access
    }
}

/// Failure of a session-plane operation other than hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessErr {
    /// Authority token missing, wrong, or its lease lapsed. Maps to 401.
    Unauthorized,
    /// A field failed wire validation. Maps to 400.
    Invalid(WireErr),
    /// A credential id is not granted to the identity. Maps to 403 `credential_not_granted`.
    CredentialNotGranted,
    /// Same session and generation with another surrogate or credential set, or a surrogate
    /// already bound elsewhere or revoked. Maps to 409.
    Conflict,
    /// The identity already has `max_sessions` live sessions. Maps to 429.
    TooMany,
}

/// Failure of `hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloErr {
    /// A live authority holds the identity. Maps to 409 with `retry_after` seconds.
    AuthorityActive { retry_after: u64 },
    /// The token could not be generated or persisted. Fails closed.
    Unavailable,
}

/// Why `authorize` refused a surrogate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deny {
    Unknown,
    Revoked,
    Expired,
    WrongCaller,
    WrongRoute,
}

impl Deny {
    /// The refusal code from the design's error table.
    pub fn code(self) -> Code {
        match self {
            Deny::Unknown => Code::SurrogateUnknown,
            Deny::Revoked => Code::SurrogateRevoked,
            Deny::Expired => Code::SurrogateExpired,
            Deny::WrongCaller => Code::SurrogateWrongCaller,
            Deny::WrongRoute => Code::SurrogateWrongRoute,
        }
    }
}

/// A surrogate that passed `authorize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    pub identity: String,
    pub session: String,
    pub generation: u64,
    /// Bound credential ids that cover the requested route.
    pub credentials: Vec<String>,
}

pub(crate) type Key = (String, u64);

pub(crate) struct Authority {
    pub(crate) token_sha256: [u8; 32],
    pub(crate) lease_expiry: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct Session {
    pub(crate) surrogate: String,
    pub(crate) credentials: Vec<String>,
    pub(crate) lease_expiry: u64,
    pub(crate) absolute_expiry: u64,
}

pub struct Registry<C: Clock> {
    pub(crate) clock: C,
    pub(crate) cfg: RegistryCfg,
    pub(crate) access: Access,
    pub(crate) token_dir: Option<PathBuf>,
    pub(crate) authorities: HashMap<String, Authority>,
    pub(crate) sessions: HashMap<String, HashMap<Key, Session>>,
    /// Surrogate sha256 to (identity, key).
    pub(crate) index: HashMap<String, (String, Key)>,
    /// Surrogate sha256 values revoked by this process.
    pub(crate) revoked: HashSet<String>,
}

impl<C: Clock> Registry<C> {
    /// Build a registry. When `token_dir` is set, each identity's authority hash is read from its
    /// file there. A restored hash starts with a full authority lease, so the authority that
    /// still holds the token can renew it, and a hello is refused until that lease lapses.
    pub fn new(clock: C, cfg: RegistryCfg, access: Access, token_dir: Option<PathBuf>) -> Self {
        let now = clock.now();
        let mut authorities = HashMap::new();
        if let Some(dir) = &token_dir {
            for identity in &access.identities {
                let path = session::token_file(dir, identity);
                if let Ok(text) = session::read_token_hash(&path) {
                    if let Some(hash) = parse_hash(text.trim()) {
                        authorities.insert(
                            identity.clone(),
                            Authority {
                                token_sha256: hash,
                                lease_expiry: now + cfg.authority_lease_secs,
                            },
                        );
                    }
                }
            }
        }
        Registry {
            clock,
            cfg,
            access,
            token_dir,
            authorities,
            sessions: HashMap::new(),
            index: HashMap::new(),
            revoked: HashSet::new(),
        }
    }

    /// Current time from the injected clock.
    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Start a new authority for `identity` and return its raw token once.
    ///
    /// Refused with `AuthorityActive` while the previous authority's lease is live. When the
    /// lease has lapsed, or no authority exists, the identity's sessions are revoked first.
    pub fn hello(&mut self, identity: &str, now: u64) -> Result<String, HelloErr> {
        if let Some(a) = self.authorities.get(identity) {
            if now < a.lease_expiry {
                return Err(HelloErr::AuthorityActive {
                    retry_after: a.lease_expiry - now,
                });
            }
        }
        let token = new_token().map_err(|_| HelloErr::Unavailable)?;
        let hash = hash_token(&token);
        if let Some(dir) = &self.token_dir {
            session::write_token_hash(&session::token_file(dir, identity), &hex(&hash))
                .map_err(|_| HelloErr::Unavailable)?;
        }
        self.revoke_all(identity);
        self.authorities.insert(
            identity.to_string(),
            Authority {
                token_sha256: hash,
                lease_expiry: now + self.cfg.authority_lease_secs,
            },
        );
        Ok(token)
    }

    /// Extend the authority lease and every listed session lease. A session that is unknown or
    /// whose lease already lapsed is returned in `unknown`; it is not renewed.
    pub fn renew(
        &mut self,
        identity: &str,
        token: &str,
        refs: &[SessionRef],
        now: u64,
    ) -> Result<RenewResp, SessErr> {
        self.check_token(identity, token, now)?;
        self.touch(identity, now);
        let lease = self.cfg.lease_secs;
        let mut unknown = Vec::new();
        for r in refs {
            let key = (r.session.clone(), r.generation);
            match self
                .sessions
                .get_mut(identity)
                .and_then(|m| m.get_mut(&key))
                .filter(|s| now < s.lease_expiry)
            {
                Some(s) => s.lease_expiry = (now + lease).min(s.absolute_expiry),
                None => unknown.push(r.clone()),
            }
        }
        Ok(RenewResp {
            lease_secs: lease,
            unknown,
        })
    }

    /// Bind a surrogate to one session generation. Returns the session lease in seconds.
    ///
    /// Re-sending an identical entry refreshes the lease. Same session and generation with
    /// another surrogate or credential set is a conflict.
    pub fn register(
        &mut self,
        identity: &str,
        token: &str,
        entry: Entry,
        now: u64,
    ) -> Result<u64, SessErr> {
        self.check_token(identity, token, now)?;
        validate_entry(&entry).map_err(SessErr::Invalid)?;
        self.check_grants(identity, &entry.credentials)?;
        self.prune_expired(identity, now);
        let key = (entry.session.clone(), entry.generation);
        let existing = self
            .sessions
            .get(identity)
            .and_then(|m| m.get(&key))
            .map(|s| (s.surrogate.clone(), s.credentials.clone()));
        if let Some((surrogate, credentials)) = existing {
            if surrogate != entry.surrogate_sha256 || credentials != entry.credentials {
                return Err(SessErr::Conflict);
            }
            self.refresh(identity, &key, now);
            self.touch(identity, now);
            return Ok(self.cfg.lease_secs);
        }
        if self.index.contains_key(&entry.surrogate_sha256)
            || self.revoked.contains(&entry.surrogate_sha256)
        {
            return Err(SessErr::Conflict);
        }
        if self.live_count(identity, now) >= self.cfg.max_sessions {
            return Err(SessErr::TooMany);
        }
        self.touch(identity, now);
        let absolute = now + self.cfg.absolute_ttl_secs;
        self.put(
            identity,
            key,
            entry.surrogate_sha256,
            entry.credentials,
            absolute,
            now,
        );
        Ok(self.cfg.lease_secs)
    }

    /// Revoke one session generation. Returns `Ok` whether or not the session existed.
    pub fn revoke(
        &mut self,
        identity: &str,
        token: &str,
        session: &str,
        generation: u64,
        now: u64,
    ) -> Result<(), SessErr> {
        self.check_token(identity, token, now)?;
        self.touch(identity, now);
        self.revoke_key(identity, &(session.to_string(), generation));
        Ok(())
    }

    /// Decide whether a surrogate may be used on `route` by `identity`. Checks run in this
    /// order: unknown, revoked, expired, wrong caller, wrong route.
    pub fn authorize(
        &self,
        surrogate_sha256: &str,
        identity: &str,
        route: &str,
        now: u64,
    ) -> Result<Bound, Deny> {
        let Some((owner, key)) = self.index.get(surrogate_sha256) else {
            return Err(if self.revoked.contains(surrogate_sha256) {
                Deny::Revoked
            } else {
                Deny::Unknown
            });
        };
        let s = self
            .sessions
            .get(owner)
            .and_then(|m| m.get(key))
            .ok_or(Deny::Unknown)?;
        if now >= s.lease_expiry {
            return Err(Deny::Expired);
        }
        if owner != identity {
            return Err(Deny::WrongCaller);
        }
        let credentials: Vec<String> = s
            .credentials
            .iter()
            .filter(|c| {
                self.access
                    .credential_routes
                    .get(*c)
                    .is_some_and(|r| r.contains(route))
            })
            .cloned()
            .collect();
        if credentials.is_empty() {
            return Err(Deny::WrongRoute);
        }
        Ok(Bound {
            identity: owner.clone(),
            session: key.0.clone(),
            generation: key.1,
            credentials,
        })
    }

    /// Compare the presented token with the stored hash in constant time. Fails when the
    /// lease has lapsed.
    pub(crate) fn check_token(&self, identity: &str, token: &str, now: u64) -> Result<(), SessErr> {
        let a = self
            .authorities
            .get(identity)
            .ok_or(SessErr::Unauthorized)?;
        if now >= a.lease_expiry {
            return Err(SessErr::Unauthorized);
        }
        let presented = hash_token(token);
        if bool::from(presented.as_slice().ct_eq(a.token_sha256.as_slice())) {
            Ok(())
        } else {
            Err(SessErr::Unauthorized)
        }
    }

    pub(crate) fn touch(&mut self, identity: &str, now: u64) {
        let lease = self.cfg.authority_lease_secs;
        if let Some(a) = self.authorities.get_mut(identity) {
            a.lease_expiry = now + lease;
        }
    }

    pub(crate) fn check_grants(
        &self,
        identity: &str,
        credentials: &[String],
    ) -> Result<(), SessErr> {
        let granted = self.access.grants.get(identity);
        let all = credentials
            .iter()
            .all(|c| granted.is_some_and(|g| g.contains(c)));
        if all {
            Ok(())
        } else {
            Err(SessErr::CredentialNotGranted)
        }
    }

    /// Store a session and its surrogate index entry. The lease is `now + lease_secs`, capped
    /// at the absolute expiry.
    pub(crate) fn put(
        &mut self,
        identity: &str,
        key: Key,
        surrogate: String,
        credentials: Vec<String>,
        absolute_expiry: u64,
        now: u64,
    ) {
        let lease_expiry = (now + self.cfg.lease_secs).min(absolute_expiry);
        self.index
            .insert(surrogate.clone(), (identity.to_string(), key.clone()));
        self.sessions
            .entry(identity.to_string())
            .or_default()
            .insert(
                key,
                Session {
                    surrogate,
                    credentials,
                    lease_expiry,
                    absolute_expiry,
                },
            );
    }

    fn refresh(&mut self, identity: &str, key: &Key, now: u64) {
        let lease = self.cfg.lease_secs;
        if let Some(s) = self.sessions.get_mut(identity).and_then(|m| m.get_mut(key)) {
            s.lease_expiry = (now + lease).min(s.absolute_expiry);
        }
    }

    fn live_count(&self, identity: &str, now: u64) -> usize {
        self.sessions
            .get(identity)
            .map_or(0, |m| m.values().filter(|s| now < s.lease_expiry).count())
    }

    /// Drop expired entries of one identity. Their surrogates are not tombstoned, so a later
    /// `authorize` reports them as unknown rather than revoked.
    fn prune_expired(&mut self, identity: &str, now: u64) {
        let Some(map) = self.sessions.get_mut(identity) else {
            return;
        };
        let expired: Vec<Key> = map
            .iter()
            .filter(|(_, s)| now >= s.lease_expiry)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            if let Some(s) = map.remove(&k) {
                self.index.remove(&s.surrogate);
            }
        }
    }

    /// Remove one session and tombstone its surrogate. Returns whether it existed.
    pub(crate) fn revoke_key(&mut self, identity: &str, key: &Key) -> bool {
        let removed = self.sessions.get_mut(identity).and_then(|m| m.remove(key));
        match removed {
            Some(s) => {
                self.index.remove(&s.surrogate);
                self.revoked.insert(s.surrogate);
                true
            }
            None => false,
        }
    }

    /// Revoke every session of one identity. Returns how many there were.
    pub(crate) fn revoke_all(&mut self, identity: &str) -> usize {
        let keys: Vec<Key> = self
            .sessions
            .get(identity)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        for k in &keys {
            self.revoke_key(identity, k);
        }
        keys.len()
    }
}

/// A fresh authority token: `apt_` plus 64 lowercase hex digits from the OS random source.
fn new_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)?;
    Ok(format!("{TOKEN_PREFIX}{}", hex(&bytes)))
}

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Lowercase hex sha256 of a string. Used for identity file names.
pub fn sha256_hex(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes()))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hash(s: &str) -> Option<[u8; 32]> {
    if !is_lower_hex_64(s) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}
