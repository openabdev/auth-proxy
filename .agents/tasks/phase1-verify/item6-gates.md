RESULT: PASS

# Item 6 gates

Code under test: `4ca9bf8` (exported with `git archive` to `~/item6-build` on macmini, cargo at `~/.cargo/bin`).
Python used by the test mocks and the matrix: PATH without `/opt/homebrew/bin` (macOS system python3 3.9.6).
With Homebrew python3 3.14 first on PATH the mock upstream fails to start, so the ap-proxy
integration tests fail with "mock upstream did not come up". That is an environment issue, not a code failure.

| Gate | Result |
|---|---|
| cargo fmt --check | PASS |
| cargo clippy --workspace --all-targets -- -D warnings | PASS |
| cargo test --workspace | PASS (incl. hello_race 3/3) |
| cargo test -p ap-core | PASS (23) |
| scripts/check-session-socket.sh | PASS |
| cargo build --release | PASS |
| tests/matrix/matrix.py (test-resolve build) | PASS 31/31 (25/25 phase 0 + 6/6 added) |
| scripts/check-egress-deps.sh | PASS |
| scripts/check-no-test-resolve.sh target/release/auth-proxy | PASS |
