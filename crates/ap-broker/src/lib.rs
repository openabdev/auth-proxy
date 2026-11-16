//! auth-proxy broker (Q1-B session plane, Q2-A in-process broker, S1 file
//! store). The only crate that ever holds a credential value.
//!
//! No network I/O, no `aws-sm` feature, no network store: those belong to the
//! deferred ECS phase.

pub mod authority;
pub mod broker;
pub mod clock;
pub mod error;
pub mod plane;
pub mod registry;
pub mod store;

pub use authority::{
    AuthorityLock, AUTHORITY_RENEW_SECS, DEFAULT_AUTHORITY_LEASE_SECS, MIN_AUTHORITY_LEASE_SECS,
};
pub use broker::{Binding, Broker, LocalBroker, INTERIM_SESSION};
pub use clock::{Clock, FakeClock, SystemClock};
pub use error::PlaneError;
pub use plane::{HelloOk, LeaseOk, PlaneConfig, RenewOk, ResyncOk, SessionPlane};
pub use registry::{
    validate_register, RegisterReq, RegistryConfig, SessionRef, SessionRegistry, SessionView,
    ValidEntry, DEFAULT_ABSOLUTE_TTL_SECS, DEFAULT_MAX_SESSIONS, DEFAULT_SESSION_LEASE_SECS,
};
pub use store::{FileStore, Secret, Store, StoreError};
