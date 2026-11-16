# Over-design council changes: verification run

Tree: `feat/phase1-k8s` at `d10fd79` (the five commits after `c339bd1`). Run on macmini (aarch64
macOS, rust toolchain from `~/.cargo`), synced with `scripts/sync-and-test.sh` into
`~/repo/auth-proxy-phase1`. Nothing was built on the laptop.

| Step | Result |
|---|---|
| `cargo fmt --check` | pass (the verification commit's `h2_upstream.rs` needed a `cargo fmt`; included in the audit commit) |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass, no warnings |
| `cargo test --workspace` | 171 passed, 0 failed, 0 ignored. `the_upstream_reset_audit_line_records_the_bytes_sent` runs (no longer `#[ignore]`). New: 9 tests in `interim_static.rs`, 1 args test, the `allow_route_hosts` rejection test, the shipped-policy `aws_targets` test, the `test-resolve` test |
| `cargo test -p ap-core` | pass; runs `connect_to_is_rejected_in_a_shipped_build` (the workspace run turns the `test-resolve` feature on for every crate, so that test only exists in this run) |
| `cargo build --release` | pass |
| `scripts/check-no-test-resolve.sh target/release/auth-proxy` | `ok: the shipped auth-proxy rejects route.connect_to (exit 2)` |
| `cargo build --release -p ap-proxy --features test-resolve --target-dir target/matrix-bin`, then `tests/matrix/matrix.py --bin target/matrix-bin/release` | 25/25 Phase 0 rows PASS, 6/6 session-plane and body rows PASS, 31/31 total (X5 no secret in any log: PASS) |
| `scripts/check-egress-deps.sh` | `ok: ap-egress has no ap-broker, reqwest or rustls dependency` |

Not run: the interim pod (`deploy/k8s/pod-interim-static.yaml`) on a cluster, and the real-pod
hello race (release gate, `docs/pre-release-checklist.md` item 3). The matrix runs a
`test-resolve` build of `auth-proxy`; the shipped release binary is covered by the reject check
above, not by the matrix.
