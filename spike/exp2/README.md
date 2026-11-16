# Experiment 2: proxy base bake-off (A: Rust proxy vs B: Envoy + ext_authz)

Spike code only. This is not the auth-proxy implementation.

Both options share one admission core (`src/lib.rs`): caller key (constant time) →
canonicalize → policy → surrogate resolve at the broker (never cached) → strip and apply
exactly one credential → audit. They differ only in who forwards.

| Path | Purpose |
|---|---|
| `src/lib.rs` | Shared core: config validation (upstream host must be a lowercase DNS name: no IP literal, userinfo, port or trailing dot), policy store (re-read on change; missing, empty or corrupt = deny), broker client, header stripping, error dialects (JSON, AWS `__type`), audit lines. |
| `src/bin/ap_proxy.rs` | **Option A.** axum/hyper server + reqwest/rustls client. Never follows redirects, streams responses chunk by chunk. |
| `src/bin/ap_authz.rs` | **Option B.** Envoy `ext_authz` HTTP service (`serve`) and the Envoy bootstrap renderer (`render-envoy`), so Envoy's clusters come from the same validated config. Fail-closed: `failure_mode_allow=false`, `allow_absolute_url=false`, `status_on_error=503`. |
| `test/matrix.py` | Fail-closed test matrix from RFC #1. Each case checks the client-visible result and what the mock upstreams actually received. |
| `test/bench.py` | Added latency, RSS at idle, warm and under load. |
| `test/live_kiro.py` | Live check: kiro-cli (ACP mode) through A or B to the real Kiro service. The real key stays in the mock broker's env. |
| `test/harness.py`, `upstream.py`, `broker.py`, `acp_timed.py` | Throwaway CAs, mock TLS upstreams (record SNI, Host and every header), mock broker, timed ACP client. |
| `docker/Dockerfile` | `scratch` images for the size comparison. |
| `results/` | Raw output of the runs reported in `.agents/tasks/phase0-spike/report.md`. |

URL scheme the client is given as its base URL: `http://127.0.0.1:<port>/ap/<caller-key>/<route>`.

Build (on a build host, not the laptop) and run (on a Linux x86_64 test host):

```sh
cargo test --lib
cargo zigbuild --release --target x86_64-unknown-linux-musl     # ap-proxy, ap-authz
# Envoy 1.40.2: copy /usr/local/bin/envoy out of envoyproxy/envoy:v1.40.2 (linux/amd64)
python3 test/matrix.py a --bin bin          # option A
python3 test/matrix.py b --bin bin          # option B (bin/ also holds envoy)
python3 test/bench.py  a|b --bin bin --json out.json
python3 test/live_kiro.py a|b --bin bin     # needs kiro-cli and KIRO_API_KEY in ~/.env; 1 paid turn
```
