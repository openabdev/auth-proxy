//! Header names and values read before the policy match: caller key, surrogate, framing.
//!
//! Input: one header per line, `name:value` (value bytes are raw, CR and NUL included). Lines
//! that `http` itself refuses are dropped, as the wire parser would.
#![no_main]

#[path = "../../crates/ap-core/tests/common/invariants.rs"]
mod invariants;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = data
        .split(|b| *b == b'\n')
        .take(16)
        .filter_map(|line| {
            let i = line.iter().position(|b| *b == b':')?;
            Some((line[..i].to_vec(), line[i + 1..].to_vec()))
        })
        .collect();
    invariants::check_headers(&pairs, "x-ap-caller-key");
});
