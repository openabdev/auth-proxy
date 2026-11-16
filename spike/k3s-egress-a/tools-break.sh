#!/bin/sh
# Run in the agent container (UID 1000). What else breaks under the per-UID
# egress rule (input for the openab-pty#47 allowlist; nothing is fixed here).
# Prints, per tool: exit code, seconds, last line of output.
cd /tmp && rm -rf tb && mkdir tb && cd tb
t() {
  name=$1; shift
  s=$(date +%s.%N)
  out=$(timeout 120 "$@" 2>&1); rc=$?
  e=$(date +%s.%N)
  printf '%s\trc=%s\t%.1fs\t%s\n' "$name" "$rc" "$(echo "$e - $s" | bc 2>/dev/null || python3 -c "print($e-$s)")" \
    "$(printf %s "$out" | tr -d '\r' | grep -v '^\s*$' | tail -1 | cut -c1-160)"
}
t git-clone-https git clone --depth 1 https://github.com/octocat/Hello-World.git
t curl-https curl -sS -m 20 -o /dev/null https://example.com/
t npm-install npm install --no-audit --no-fund --prefix ./npmp is-number
t pip-download python3 -m pip download --no-deps -d ./pipd six
cargo init -q --name tb ./cg >/dev/null 2>&1 && printf 'itoa = "1"\n' >> ./cg/Cargo.toml
t cargo-fetch cargo fetch --manifest-path ./cg/Cargo.toml
cd / && rm -rf /tmp/tb
