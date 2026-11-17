# Canonicalization fuzz targets

cargo-fuzz targets for request canonicalization (`crates/ap-core/src/canon.rs`), issue #19. This
crate is outside the root workspace, so `cargo build --workspace` and `cargo test --workspace` never
build it. It needs a nightly toolchain and `cargo install cargo-fuzz --locked`.

| Target | Input | What it checks |
|---|---|---|
| `canon_path` | a request path | `parse_ap_path` (the `/ap/<caller-key>/<route>/...` form), the header-mode route splitter, `path_ambiguous`, and that an accepted path is byte-identical under the `http` and `url` parsers |
| `canon_host` | a host name | `canonical_host` accepts only the byte-exact lowercase DNS spelling, never something `url` reads as an IP |
| `canon_origin` | byte 0 bit 0 = HTTP/2, line 1 = target, later lines = Host values | `check_origin_form`: an accepted request has one Host equal to the route authority |
| `canon_headers` | one `name:value` per line | caller key, surrogate and framing rules over raw header bytes |

The invariants are in `crates/ap-core/tests/common/invariants.rs`, shared with the cargo tests
(`canon_differential`, `canon_regression`), so a fuzz crash and a test failure name the same input.

```
cd fuzz
cargo +nightly fuzz run canon_path -- -max_total_time=300
```

`corpus/<target>/` holds a small hand-written seed set, one file per class in the issue. A crash is
written to `artifacts/<target>/`; copy it into a regression case in
`crates/ap-core/tests/canon_regression.rs` when fixing it. CI runs each target for 45 seconds on pull
requests that touch `canon.rs` and for 300 seconds nightly (`.github/workflows/fuzz.yml`).
