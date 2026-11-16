//! The session plane's state machine: authority lock plus session registry,
//! behind one mutex so a lapse and the revoke-all that follows it cannot be
//! interleaved with another call. No I/O except the authority state file.
//!
//! The HTTP layer (ap-proxy) maps these methods to the five calls in the
//! design doc and the `PlaneError` to its status codes.

use crate::authority::{AuthorityLock, DEFAULT_AUTHORITY_LEASE_SECS};
use crate::clock::Clock;
use crate::error::PlaneError;
use crate::registry::{
    validate_register, RegisterReq, RegistryConfig, SessionRef, SessionRegistry, SessionView,
};
use ap_core::{Code, Policy};
use serde::Serialize;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct PlaneConfig {
    pub registry: RegistryConfig,
    pub authority_lease_secs: u64,
    /// Proxy-private file holding the authority token's hash (and nothing
    /// secret). `None` keeps it in memory only.
    pub authority_state: Option<PathBuf>,
}

impl Default for PlaneConfig {
    fn default() -> Self {
        PlaneConfig {
            registry: RegistryConfig::default(),
            authority_lease_secs: DEFAULT_AUTHORITY_LEASE_SECS,
            authority_state: None,
        }
    }
}

/// `201` body of `hello`. The token is shown once; `Debug` redacts it.
#[derive(Serialize, Clone, PartialEq, Eq)]
pub struct HelloOk {
    pub authority_token: String,
    pub lease_secs: u64,
}

impl fmt::Debug for HelloOk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelloOk")
            .field("authority_token", &"<redacted>")
            .field("lease_secs", &self.lease_secs)
            .finish()
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct LeaseOk {
    pub lease_secs: u64,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct RenewOk {
    pub lease_secs: u64,
    pub unknown: Vec<SessionRef>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ResyncOk {
    pub registered: usize,
    pub dropped: usize,
}

struct Inner {
    authority: AuthorityLock,
    registry: SessionRegistry,
}

pub struct SessionPlane {
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
}

impl SessionPlane {
    pub fn new(cfg: PlaneConfig, clock: Arc<dyn Clock>) -> Result<SessionPlane, String> {
        let authority =
            AuthorityLock::new(cfg.authority_lease_secs, cfg.authority_state, clock.now())?;
        Ok(SessionPlane {
            clock,
            inner: Mutex::new(Inner {
                authority,
                registry: SessionRegistry::new(cfg.registry),
            }),
        })
    }

    /// Apply time: free a lapsed authority lock (revoking every session) and
    /// drop lapsed sessions. Run at the start of every call, so nothing rides
    /// on a lease that has ended.
    fn tick(inner: &mut Inner, now: std::time::Duration) {
        if inner.authority.poll(now) {
            inner.registry.revoke_all();
        }
        inner.registry.sweep(now);
    }

    fn authed(
        &self,
        token: &str,
    ) -> Result<(std::sync::MutexGuard<'_, Inner>, std::time::Duration), PlaneError> {
        let now = self.clock.now();
        let mut g = self.inner.lock().unwrap();
        Self::tick(&mut g, now);
        if g.authority.verify(token, now) {
            Ok((g, now))
        } else {
            Err(PlaneError::Unauthorized)
        }
    }

    /// `POST /v1/hello`.
    pub fn hello(&self) -> Result<HelloOk, PlaneError> {
        let now = self.clock.now();
        let mut g = self.inner.lock().unwrap();
        Self::tick(&mut g, now);
        let token = g.authority.hello(now)?;
        Ok(HelloOk {
            authority_token: token,
            lease_secs: g.authority.lease_secs(),
        })
    }

    /// `POST /v1/sessions`.
    pub fn register(
        &self,
        token: &str,
        policy: &Policy,
        req: &RegisterReq,
    ) -> Result<LeaseOk, PlaneError> {
        let (mut g, now) = self.authed(token)?;
        let v = validate_register(policy, req)?;
        let lease = g.registry.register(now, policy.identity(), v)?;
        Ok(LeaseOk {
            lease_secs: lease.as_secs(),
        })
    }

    /// `POST /v1/renew`: extends the authority's own lease and the listed
    /// sessions' leases (never past their absolute TTL).
    pub fn renew(&self, token: &str, sessions: &[SessionRef]) -> Result<RenewOk, PlaneError> {
        let (mut g, now) = self.authed(token)?;
        g.authority.renew(now);
        let unknown = g.registry.renew(now, sessions);
        Ok(RenewOk {
            lease_secs: g.registry.lease().as_secs(),
            unknown,
        })
    }

    /// `DELETE /v1/sessions/{session}/{generation}`. Idempotent.
    pub fn revoke(&self, token: &str, session: &str, generation: u64) -> Result<(), PlaneError> {
        let (mut g, now) = self.authed(token)?;
        g.registry.revoke(now, session, generation);
        Ok(())
    }

    /// `PUT /v1/sessions`: the whole list is validated before anything is
    /// applied; sessions not in it are revoked.
    pub fn resync(
        &self,
        token: &str,
        policy: &Policy,
        reqs: &[RegisterReq],
    ) -> Result<ResyncOk, PlaneError> {
        let (mut g, now) = self.authed(token)?;
        let mut list = Vec::with_capacity(reqs.len());
        for (i, r) in reqs.iter().enumerate() {
            list.push(validate_register(policy, r).map_err(|e| e.at_entry(i))?);
        }
        let (registered, dropped) = g.registry.resync(now, policy.identity(), list)?;
        Ok(ResyncOk {
            registered,
            dropped,
        })
    }

    /// Admission lookup by surrogate hash.
    pub fn lookup(&self, hash: &[u8; 32]) -> Result<SessionView, Code> {
        let now = self.clock.now();
        let mut g = self.inner.lock().unwrap();
        Self::tick(&mut g, now);
        g.registry.lookup(now, hash)
    }

    pub fn session_count(&self) -> usize {
        let now = self.clock.now();
        let mut g = self.inner.lock().unwrap();
        Self::tick(&mut g, now);
        g.registry.len()
    }

    pub fn authority_live(&self) -> bool {
        let now = self.clock.now();
        let mut g = self.inner.lock().unwrap();
        Self::tick(&mut g, now);
        g.authority.is_live(now)
    }
}
