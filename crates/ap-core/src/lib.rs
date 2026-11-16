//! auth-proxy core. No network I/O and no credential values.
//!
//! - `config`: the Q3-A policy file model and its validation
//! - `policy`: compiled snapshot, grant evaluation, the reloading store
//! - `canon`: host and path canonicalization, the `/ap/<caller-key>` prefix
//! - `code`: refusal codes, status mapping, error dialects
//! - `headers`: auth and hop-by-hop header lists and stripping
//! - `surrogate`: surrogate and caller-key formats, the registry hash
//! - `audit`: the audit record (cannot carry the caller-key prefix)

pub mod audit;
pub mod canon;
pub mod code;
pub mod config;
pub mod headers;
pub mod policy;
pub mod stamp;
pub mod surrogate;
#[doc(hidden)]
pub mod testing;

pub use audit::{AuditInput, AuditRec};
pub use canon::{canonical_host, path_ambiguous, ApPath, RoutePath, VerifiedPath};
pub use code::{deny_parts, Code, ErrorShape};
pub use config::{Config, ConfigError, CredentialSource};
pub use headers::{strip_request_headers, AUTH_HEADERS, HOP_HEADERS};
pub use policy::{aws_target_ok, Policy, PolicyStore};
pub use stamp::FileStamp;
