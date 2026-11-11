# Phase 1 status

## Status

This document describes branch `feat/phase1` at tip `db9e20b`.

Phase 1 is done on this branch. The work covers the policy core, the session broker, the proxy,
the egress proxy, the session client, the fail-closed matrix, and the Kubernetes manifests. The
runtime split (option A) is also done. The final review approved commit `c111949`, and later
commits up to `db9e20b` change documentation only.

The runtime split ran on two test clusters, one arm64 and one amd64, with a mock upstream and dummy
credentials. No pull request was opened, and nothing was merged.

## Features delivered

- Strict TOML configuration, canonicalization, and policy snapshot evaluation.
- Session registry with an authority hello lock, leases, an absolute session TTL of 12 hours,
  a session cap, credential grants, and resync.
- Loopback agent listener with a nine-step request pipeline, a forwarder, and an audit log.
- A CONNECT-only egress proxy with an allowlist.
- A session authority client.
- A fail-closed matrix as a cargo test target, run by a dispatch-only CI workflow.
- Kubernetes manifests (option A), a netinit rule set, and a static manifest validator.
- Runtime split: the agent, runtime, proxy, and egress run as separate UIDs. The runtime holds
  the proof seed for `hello`. The agent reaches the runtime only through a Unix socket.
- Absolute expiry persisted across proxy restarts in a store on its own volume. The proxy
  refuses to start without the store.
- Resync reports sessions whose absolute expiry has passed.

## Owner decisions

- Session identity: option Q1-B, with an amendment letting a surrogate lease last up to the 12 hour TTL, and three conditions.
- Broker placement: Kubernetes only (S1). ECS, S2, and per-bot services are deferred, not rejected.
- Policy and egress: Q3-A with egress option Q3-E2. The council agreed without escalation.
- Absolute TTL across restarts: the proxy persists each expiry and fails closed if the store is unreadable.
- Listen address: keep the `--listen` flag. No `listen.egress` key.
- Hello proof: a runtime-only proof on `hello`, implemented by the runtime split.
- Resync `expired` field rollout: the proxy omits the field when empty, and clients upgrade
  before the proxy returns a non-empty list. The source records that the council chose this
  option and that it was not put to the owner.
- Expiry store volume: a separate volume, a `--expiry-store` flag, a bootstrap that never
  truncates the file, and a proxy that refuses to start without it.
- Expiry record pruning: none in Phase 1.
- Runtime split: `session.sock` owned by UIDs 1001:1002 is approved as a recorded deviation.
- Runtime split: the real pod and a test overlay both show the agent blocked from the runtime
  socket. Both results are kept as evidence.
- Runtime split: UID 1002 gets no TCP rule, by design.
- Runtime split: `CHOWN` and `FSETID` are approved for the `volume-prep` init container only.
- Runtime split: the owner accepted the reworked first-run failures, with disclosure.

## Measured results

Build host, runtime-split run:

| Check | Result |
|---|---|
| `cargo fmt --all --check` | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | PASS |
| `cargo test --workspace --locked` | PASS, 289 passed, 0 failed |
| Release build of the three binaries | PASS |
| Matrix driver | PASS, 41 of 41 rows (gate 28 of 28, phase 1 13 of 13) |
| `cargo test -p ap-proxy --features matrix-upstream --test matrix --locked` | PASS, 1 test |
| Manifest validator | PASS, all checks passed |
| Validator unit tests | PASS, 10 tests |

Cluster checks. The arm64 cluster was a single-node cluster. The amd64 node was a second k3s node.

| Check | arm64 cluster | amd64 node |
|---|---|---|
| Pod starts: init containers exit 0, app containers ready | PASS | PASS |
| Netinit rules for UID 1002 present | PASS | PASS |
| Agent reaches proxy and egress on loopback | PASS | PASS |
| Other loopback ports refused for the agent | PASS | PASS |
| Direct TCP and DNS from the agent blocked | PASS | PASS |
| Register, forwarded request, unknown surrogate, and revoke through `runtime.sock` | PASS | PASS |
| Upstream sees the real credential, never the surrogate or caller key | PASS | PASS |
| No secret in any container log | PASS | PASS |
| Expiry store identical across delete and recreate | PASS | PASS |
| Agent cannot read the runtime key, proxy state, or session plane | PASS | PASS |
| Proxy accepts the runtime's signed `hello` (201) | PASS | PASS |
| `runtime.sock` refuses `hello` for the agent (404) | PASS | PASS |
| Agent cannot open `session.sock` (ENOENT on the real manifest, EACCES on the overlay) | PASS | PASS |
| Lapse probe, runtime killed: `session.sock` unreachable in all samples, no new `hello` | PASS, 60 samples | PASS, 60 samples |
| Same results on the recreated pod | PASS | PASS |

First-run failures, each reworked and rerun:

- arm64 cluster, manifest: `volume-prep` failed in init because `chmod` after `chown` needs
  `FSETID`. The fix added `FSETID` and reordered the calls.
- arm64 cluster, lapse probe: the runtime did not restart under the first probe. The rerun
  wrapped the runtime in a shell so the probe could kill it, and then passed.
- amd64 node, expiry store: the first attempt failed because the reader pod was not ready and
  a command had a quoting bug. No value was read. The second attempt passed.
- The arm64 expiry-store check printed wrong byte counts from a parsing bug. The rerun is the
  valid record.

Test-only changes used in the runs: a proxy built with the `matrix-upstream` feature, test-tagged
images, and a test overlay pod with a wrapper shell for some checks. The shipped manifest and the
release image were not changed.

## Known gaps and deferred work

- The openab-pty runtime change is planned, not implemented. The plan is outside this repository.
- ECS is deferred to a later phase and has not been started.
- Real upstream and real credentials have not been tested. All runs used a mock upstream and
  dummy credentials.
- The 12 hour TTL lapse has only been unit-tested, not exercised on a cluster.
- The signature compare is not constant-time.
- The validator does not check seed exposure through env or `secretKeyRef`.

## How to verify

Run these from the repository root. The cargo commands and validator commands are the ones
recorded for the runtime-split tip in its final checks file.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked -p ap-proxy -p ap-egress -p ap-runtime-shim
cargo test -p ap-proxy --features matrix-upstream --test matrix --locked
python3 tests/matrix/matrix.py --bin target/debug
python3 deploy/k8s/validate_manifests.py
python3 -m unittest discover -s deploy/k8s -v
```

The matrix driver takes `--bin` pointing at the directory of built binaries.
