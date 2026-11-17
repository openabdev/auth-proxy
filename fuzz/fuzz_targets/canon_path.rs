//! Request path: `parse_ap_path` (the `/ap/<caller-key>/<route>/...` form), the header-mode
//! route splitter, `path_ambiguous`, and agreement with the `http` and `url` parsers.
#![no_main]

#[path = "../../crates/ap-core/tests/common/invariants.rs"]
mod invariants;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    invariants::check_path(&String::from_utf8_lossy(data));
    // Shape the same bytes into a request aimed at a hold pattern and run the RFC 3986 oracle.
    invariants::check_gate_bytes(data);
});
