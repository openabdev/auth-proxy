PASS (after two minimal fixes: one test race, one test-harness Python-version issue; neither is aarch64-specific)

# Phase 1 aarch64 verification

- Host: aarch64 Debian host (Debian 13, 4 cores, 8 GB), `uname -m` = `aarch64`
- Toolchain: `rustc 1.96.0 (ac68faa20 2026-05-25)`, `cargo 1.96.0`, Python 3.13.5, OpenSSL 3.5.6 (all pre-installed; nothing installed)
- Source: branch `verify/aarch64` from `feat/phase1-k8s` d69fcbb, rsync'd (no target, no .git) to a temp dir; `CARGO_TARGET_DIR` inside it
- "The matrix" = the gate in `.github/workflows/ci.yml` / `scripts/sync-and-test.sh`: fmt, clippy `-D warnings`, `cargo test --workspace`, `cargo build --release`, `python3 tests/matrix/matrix.py --bin target/release`, `scripts/check-egress-deps.sh`

## Run 1 (unmodified d69fcbb)

| Step | Result |
|---|---|
| cargo fmt --check | pass |
| cargo clippy --workspace --all-targets -D warnings | pass |
| cargo test --workspace | **FAIL**: `ap-core policy::tests::no_half_applied_swap_under_concurrent_requests` (21 passed, 1 failed; cargo stopped before later crates) |
| cargo build --release | pass (1m41s) |
| matrix.py | **30/31**: R4 "cross-host/port/scheme redirect" EXCEPTION `CERTIFICATE_VERIFY_FAILED ... CA cert does not include key usage extension` |
| check-egress-deps.sh | pass |

## Causes and fixes (both in this branch)

1. `crates/ap-core/src/policy.rs`: the 4 reader threads loop `while !stop`; on a 4-core host the writer's 60 swaps finish in ~10 ms, so a reader can be first scheduled after `stop` is set and return `seen == 0`, failing `assert!(seen > 0)`. Test race, not architecture. Fix: readers now do at least one iteration (loop, break after the stop check). Production code untouched.
2. `tests/matrix/harness.py` `direct_tls`: Python >= 3.13 enables `VERIFY_X509_STRICT` by default, which rejects the harness test CA (no keyUsage extension). Python-version issue, not architecture; it would also hit any x86 host with Python 3.13. Fix: the test client clears that one flag. Production code untouched.

## Run 2 (with the fixes)

| Step | Result |
|---|---|
| fmt, clippy | pass |
| `cargo test --workspace --no-fail-fast` | **115 passed, 0 failed, 0 ignored** (broker 0+25+8, client 6, core 22+13, egress 0+0+6, proxy 13+3+1+5+13, doc-tests 0) |
| policy race test, 30 repeated runs | 30/30 pass |
| cargo build --release | pass |
| matrix.py | **31/31 PASS** (Phase 0 rows 25/25, session-plane/body rows 6/6) |
| check-egress-deps.sh | `ok: ap-egress has no ap-broker, reqwest or rustls dependency` |

Failing tests after fixes: none. Skipped/ignored: none.

## Cleanup check

```
ssh <host> 'rm -rf ~/ap-verify-aarch64-tmp /tmp/apm-*; ls -d ~/ap-verify-aarch64-tmp /tmp/apm-*'
ls: cannot access '~/ap-verify-aarch64-tmp': No such file or directory
ls: cannot access '/tmp/apm-*': No such file or directory
pgrep -af "run.sh|run2.sh|ap-broker|ap-proxy|ap-egress|auth-proxy|matrix.py|cargo|rustc"  -> no matches
```

The host's existing `~/.cargo` was used as found (not modified). No tailscale state touched; nothing deployed.
