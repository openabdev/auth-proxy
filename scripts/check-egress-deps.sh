#!/bin/sh
# ap-egress must stay credential-free: no ap-broker, no HTTP/TLS client stack,
# and nothing in ap-broker's reverse tree may be ap-egress. Run from the repo root.
set -eu
fail=0
tree=$(cargo tree -p ap-egress -e normal --prefix none)
for dep in ap-broker reqwest rustls hyper-rustls; do
  if printf '%s\n' "$tree" | grep -E "^$dep v" >/dev/null; then
    echo "FAIL: ap-egress depends on $dep" >&2
    fail=1
  fi
done
if cargo tree -i ap-broker -e normal --prefix none 2>/dev/null | grep -E '^ap-egress v' >/dev/null; then
  echo "FAIL: ap-egress appears in ap-broker's reverse dependency tree" >&2
  fail=1
fi
[ "$fail" -eq 0 ] && echo "ok: ap-egress has no ap-broker, reqwest or rustls dependency"
exit "$fail"
