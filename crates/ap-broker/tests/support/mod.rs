#![allow(dead_code)]

use ap_broker::{FakeClock, PlaneConfig, RegisterReq, SessionPlane, SessionRef};
use ap_core::surrogate::hash_surrogate;
use ap_core::testing::sample_toml;
use ap_core::Policy;
use std::path::PathBuf;
use std::sync::Arc;

pub fn policy() -> Policy {
    Policy::parse(sample_toml().as_bytes()).unwrap()
}

pub fn policy_for_identity(identity: &str) -> Policy {
    Policy::parse(sample_toml().replace("pty-team-a", identity).as_bytes()).unwrap()
}

pub fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ap-broker-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A well-formed surrogate whose bytes depend on `n`.
pub fn surrogate(n: u8) -> String {
    format!("aps_{}", format!("{n:02x}").repeat(32))
}

pub fn hash(n: u8) -> [u8; 32] {
    hash_surrogate(&surrogate(n)).unwrap()
}

pub fn req(session: &str, generation: u64, n: u8, creds: &[&str]) -> RegisterReq {
    RegisterReq {
        session: session.into(),
        generation,
        surrogate_sha256: hex::encode(hash(n)),
        credentials: creds.iter().map(|s| s.to_string()).collect(),
    }
}

pub fn sref(session: &str, generation: u64) -> SessionRef {
    SessionRef {
        session: session.into(),
        generation,
    }
}

pub fn plane_with(cfg: PlaneConfig) -> (Arc<FakeClock>, SessionPlane) {
    let clock = Arc::new(FakeClock::new());
    let plane = SessionPlane::new(cfg, clock.clone()).unwrap();
    (clock, plane)
}

pub fn plane() -> (Arc<FakeClock>, SessionPlane) {
    plane_with(PlaneConfig::default())
}

/// Move time forward in 30 s steps, renewing the authority's lease and the
/// listed sessions, as a live runtime does.
pub fn advance_renewing(
    clock: &FakeClock,
    plane: &SessionPlane,
    token: &str,
    secs: u64,
    sessions: &[SessionRef],
) {
    let mut left = secs;
    while left > 0 {
        let step = left.min(30);
        clock.advance_secs(step);
        left -= step;
        plane.renew(token, sessions).unwrap();
    }
}

/// Same, renewing only the authority's own lease (an empty session list).
pub fn advance_renewing_authority(clock: &FakeClock, plane: &SessionPlane, token: &str, secs: u64) {
    advance_renewing(clock, plane, token, secs, &[]);
}
