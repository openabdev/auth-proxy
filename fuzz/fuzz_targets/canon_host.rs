//! Host normalisation: `canonical_host` accepts only the byte-exact lowercase DNS spelling, never
//! an IP in any spelling the `url` crate reads as one.
#![no_main]

#[path = "../../crates/ap-core/tests/common/invariants.rs"]
mod invariants;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    invariants::check_host(&String::from_utf8_lossy(data));
});
