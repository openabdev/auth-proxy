//! Request target and Host header (`check_origin_form`).
//!
//! Input: byte 0 bit 0 selects HTTP/2; line 1 is the request target; every later line is one Host
//! header value (at most four). The route authority is fixed.
#![no_main]

#[path = "../../crates/ap-core/tests/common/invariants.rs"]
mod invariants;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((first, rest)) = data.split_first() else {
        return;
    };
    let mut lines = rest.split(|b| *b == b'\n');
    let target = String::from_utf8_lossy(lines.next().unwrap_or_default()).into_owned();
    let hosts: Vec<Vec<u8>> = lines.take(4).map(<[u8]>::to_vec).collect();
    invariants::check_origin(&target, &hosts, first & 1 == 1, "127.0.0.1:8443");
});
