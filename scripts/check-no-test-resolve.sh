#!/bin/sh
# The shipped auth-proxy binary must reject `route.connect_to` (a test aid that
# exists only in `test-resolve` builds). Usage: scripts/check-no-test-resolve.sh
# [path-to-auth-proxy]   (default target/release/auth-proxy; run from the repo root)
set -eu
bin=${1:-target/release/auth-proxy}
[ -x "$bin" ] || { echo "FAIL: $bin not found (cargo build --release first)" >&2; exit 1; }
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
cat > "$d/policy.toml" <<'TOML'
version = 1
identity = "check"
caller_key_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[[route]]
name = "up"
host = "api.example.com"
connect_to = "127.0.0.1:9"
TOML
rc=0
"$bin" --policy "$d/policy.toml" --listen 127.0.0.1:18999 \
  --session-socket "$d/s.sock" --admin-socket "$d/a.sock" --state-dir "$d/state" \
  >"$d/out" 2>"$d/err" || rc=$?
if [ "$rc" -eq 2 ] && grep -q "unknown field .connect_to." "$d/err"; then
  echo "ok: the shipped auth-proxy rejects route.connect_to (exit 2)"
else
  echo "FAIL: expected exit 2 with an unknown-field error for connect_to; got exit $rc" >&2
  sed 's/^/  /' "$d/err" >&2
  exit 1
fi
