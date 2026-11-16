FAIL (partial): HTTP/2 upstream relay PASS, `upstream_reset` audit line and client outcome PASS, but one design claim is not implemented: the `upstream_reset` line does not record "the bytes sent".

# Phase 1 verification, item 2: HTTP/2 upstream and `upstream_reset`

Branch `verify/h2-reset` (cut from `feat/phase1-k8s` at d69fcbb). Host: macmini (cargo 1.99.1, rustc via rustup, Python 3.9.6). Proxy code changed: **no**. Only test code and dev-dependencies were added.

## What the design says

- `docs/design/phase1.md` section 5, item 2: the proxy "negotiates HTTP/2 upstream through ALPN, keeping HTTP/1.1 on the agent listener".
- Section 4, "Upstream error mid-stream": "the client stream is closed without a synthetic success; the audit line records `upstream_reset` and the bytes sent."
- Code: `crates/ap-proxy/src/agent.rs` (end of `handle`) maps a failing `bytes_stream()` chunk to `AuditRec::failed(.., "upstream_reset", <status already sent>)`, once per response. `AuditRec` (`crates/ap-core/src/audit.rs`) has the fields identity, session, generation, route, method, path, aws_target, decision, code, status, duration_ms. There is no bytes field.

## Test setup

New file `crates/ap-proxy/tests/h2_upstream.rs`, same conventions as the other integration tests (`mod support;`, real `auth-proxy` binary, `Fixture`, throwaway `api.up.test` certificate and CA).

- **Upstream:** a real HTTP/2-only TLS server built on the `h2` crate. ALPN offers only `h2`. It records, per request, the negotiated ALPN protocol, the HTTP version, method, path, headers and body. Routes: `/v1/echo` (echoes the body), `/v1/chunks` (three DATA frames with gaps, clean end), `/v1/reset-mid` (200 headers, `partial-`, then `RST_STREAM(INTERNAL_ERROR)`), `/v1/reset-early` (`RST_STREAM` before any response header).
- **Proxy:** routes `up`, `upaws`, `other` are repointed to the h2 server through the policy's `connect_to` (read at startup, so the policy is written before the proxy starts). Agent side is HTTP/1.1.
- **Dev-dependencies added to `ap-proxy`:** `bytes`, `h2`, `rustls` (ring), `rustls-pki-types`, `tokio-rustls` (ring). All were already in `Cargo.lock` transitively; the lock gained 5 lines for the new direct edges.

## Results

Command (on macmini, in a temp copy of the worktree, `CARGO_TARGET_DIR` inside it):

```
export PATH=$HOME/.cargo/bin:$PATH CARGO_TARGET_DIR=$HOME/tmp-apx-h2reset/target
cargo test -p ap-proxy --test h2_upstream
```

| Test | Result | What it shows |
|---|---|---|
| `a_request_is_relayed_to_an_http2_upstream` | PASS | A 100 000-byte POST through the proxy reaches an h2-only upstream and is echoed back byte for byte. The upstream saw ALPN `h2`, version `HTTP/2.0`, method and path correct. `authorization` is `Bearer <real credential>`; the surrogate and the caller key appear nowhere in what the upstream saw; the `tokentype` pass-through header survives. |
| `http2_response_chunks_are_streamed_and_audited_as_allowed` | PASS | Three DATA frames with 60 ms gaps arrive as `one\ntwo\nthree\n` (elapsed >= 100 ms, so not buffered into one instant reply). One audit line: `decision=allow code=ok status=200 path=/v1/chunks`. |
| `an_upstream_reset_mid_stream_is_audited_and_closes_the_client_stream` | PASS | Client saw `HTTP/1.1 200` with `transfer-encoding: chunked`, the chunk `partial-`, then EOF with **no** terminating `0\r\n\r\n` (no synthetic success), and no hang (EOF within the 10 s limit; the reset arrives after about 150 ms). Audit: exactly one `allow/ok/200` line, then exactly one line `decision=error code=upstream_reset status=200` (the status already sent) with identity, session `s1`, generation 1, route `up`, method `GET`, path `/v1/reset-mid`, `duration_ms` 164. No `apk_`, `aps_` or credential text in any line. The proxy was still alive and served the next request; stderr has no `panicked`. |
| `an_upstream_reset_before_the_response_is_a_502_upstream_unavailable` | PASS | `RST_STREAM` before headers gives the client `502` with `x-auth-proxy-error: upstream_unavailable`; one audit line `decision=deny code=upstream_unavailable status=502`; proxy alive, no panic. |
| `the_upstream_reset_audit_line_records_the_bytes_sent` | **FAIL** (`#[ignore]`, run with `--ignored`) | The `upstream_reset` line is `{"aws_target":"-","code":"upstream_reset","decision":"error","duration_ms":160,"generation":1,"identity":"agent-1","method":"GET","path":"/v1/reset-mid","route":"up","session":"s1","status":200,"t":...}`. No bytes field exists, so the design sentence "records `upstream_reset` and the bytes sent" is not implemented. |

Stability: the default run (4 passed, 1 ignored) was repeated 9 times with the same result. The `--ignored` run fails deterministically with the message above. `cargo test --workspace` on macmini: every suite ok (ap-broker 25+8, ap-client 6, ap-core 22+13, ap-egress 6, ap-proxy unit 13, h2_upstream 4 + 1 ignored, hello_race 3, no_caller_key_in_logs 1, policy 5, session_plane 13).

Measurement check: the mid-stream test prints the raw client bytes and the audit lines (visible with `--nocapture`); the output above was read from there, not only from the asserts. The upstream asserts ALPN `h2` and `HTTP/2.0` itself, so the tests cannot pass over HTTP/1.1.

## Findings

1. **Gap, design vs code:** the audit line for `upstream_reset` carries no bytes-sent count. Fixing it means adding a field to `AuditRec` (the schema that `no_caller_key_in_logs` and the audit docs cover) and counting bytes in the response stream in `agent.rs`. That changes the audit schema, so it was not done here. Either the design sentence is relaxed, or the field is added; the ignored test is the acceptance test for the second option (remove `#[ignore]` when done; it accepts `bytes_sent`, `bytes`, `bytes_out` or `response_bytes` and expects `8` for `partial-`).
2. No proxy bug was exposed by the h2 relay or by either reset case. No proxy code was changed.
3. Side note, not changed: the test support `pki()` leaves `/tmp/apx-pki-<pid>` directories behind after every test binary run (existing behavior, not part of this change).

## Cleanup check (macmini)

- Temp directory `~/tmp-apx-h2reset` (sources and `target`) deleted: `ls` reports no such directory.
- `pgrep -fl "auth-proxy|upstream.py|apx"` returns nothing: no proxy, mock upstream or h2 upstream process left.
- The test `Fixture` removes its `/tmp/apx-<pid>-<n>` directories on drop (none left). The 16 `/tmp/apx-pki-*` directories created by my runs were removed; 28 older ones from earlier sessions (dated before this run) were left as found.
- No tailscale state touched; nothing deployed; nothing pushed.
