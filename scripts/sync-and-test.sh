#!/bin/sh
# Sync the worktree to macmini and run the full gate there. Never builds locally.
# Usage: scripts/sync-and-test.sh [worktree-dir]   (default: this repository root)
# The matrix runs a `test-resolve` build of auth-proxy (routes may set connect_to); the
# shipped release binary is checked to reject that key.
# CI (.github/workflows/ci.yml) runs the same commands on a Linux runner.
set -eu
SRC=${1:-$(cd "$(dirname "$0")/.." && pwd)}
rsync -a --delete --exclude .git --exclude target --exclude .worktrees --exclude .agents \
  "$SRC"/ macmini:repo/auth-proxy-phase1/
ssh macmini 'cd ~/repo/auth-proxy-phase1 && export PATH=$HOME/.cargo/bin:$PATH && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo test -p ap-core && cargo build --release && sh scripts/check-no-test-resolve.sh target/release/auth-proxy && cargo build --release -p ap-proxy --features test-resolve --target-dir target/matrix-bin && python3 tests/matrix/matrix.py --bin target/matrix-bin/release && sh scripts/check-egress-deps.sh'
