//! Client library for the auth-proxy session plane: a Unix-socket HTTP client, the authority
//! loop, and surrogate and caller key generation.

pub mod caller;
pub mod surrogate;
pub mod uds;
