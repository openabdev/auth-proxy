# auth-proxy Phase 0 spike: results

Branch `spike/phase0`: `spike/exp1/` (CLI surrogate probes) and `spike/exp2/` (proxy bake-off, test matrix, benchmarks; raw output in `spike/exp2/results/`).

Every claim below is labelled **measured** (we ran it) or **inferred** (from docs or source, not run).

> **Publication status:** the orchestrator decided to defer publication to the workflow's publish step. Two things are deferred: pushing `spike/phase0`, and posting the summary comment on issue #1. pahud will see the comment before it is posted. Until that step runs, the branch exists only locally.

## TL;DR

- **Experiment 1:** All five CLIs (kiro-cli, Claude Code, Codex, Gemini CLI, OpenCode) can be pointed at a loopback base URL. Each accepts an opaque surrogate, streams through a swapping reverse proxy, and shows the refusal without falling back to a direct connection. kiro-cli was measured live with a real key. **CONNECT interception is not needed for any of them**, so Phase 2/3 are not forced.
- **Experiment 2:** A (Rust proxy) and B (Envoy + our `ext_authz` service) both pass the full fail-closed matrix (25 cases). Both also stream a live kiro-cli turn. B needed two non-default Envoy settings before it passed, and the matrix is what found them. A uses about 25× less memory, adds half the latency, and ships as a 3.6 MB static binary instead of a 171 MB image plus a second process.
- **Recommendation: A**, a minimal Rust proxy on the octobroker stack. The admission core is shared by both options, so moving to Envoy later would mean replacing about 150 lines of forwarding code.

## Experiment 1: CLI surrogate compatibility

Full write-up: `exp1.md`. Versions: kiro-cli 2.37.0 (live, Linux) and 3.1.0 (macOS, refusal modes only), Claude Code 2.1.273, Codex CLI 0.154.0, Gemini CLI 0.67.0, OpenCode 1.19.5. Only kiro-cli had a usable credential. The other CLIs ran against a loopback mock of their vendor API, placed behind the same swap proxy.

| CLI | Endpoint knob (exact) | Opaque surrogate accepted? | Streaming through swap proxy | Refusal behaviour (401 / 403 / expired) | Evidence |
|---|---|---|---|---|---|
| **kiro-cli** | Global settings `api.cps.service`, `api.krs.service`, `api.codewhisperer.service` (+ `api.q.service`). Value `{"endpoint":"http://127.0.0.1:<port>[/prefix]","region":"us-east-1"}`, set via `kiro-cli settings` or `~/.kiro/settings/cli.json`. Global only, not per workspace. | **Yes.** Sent as `Authorization: Bearer` + `TokenType: API_KEY`, the latter must pass through. No format or length check. No SigV4. | **Yes.** AWS eventstream, 32 chunks over 1.8 s. ACP mode works too. | Shows the error and exits 1. No re-login, no direct fallback. An AWS-shaped body (`__type`/`message`) is shown verbatim. | **measured, live** (real `KIRO_API_KEY`) |
| **Claude Code** | `ANTHROPIC_BASE_URL` | **Yes**, in `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and `CLAUDE_CODE_OAUTH_TOKEN`. No prefix check. | **Yes.** 25 chunks over 1.35 s. | Shows the error, no fallback. **In API-key mode a 401 is retried about 10 times over about 3 min**; a 403 fails at once. | measured (mock); not live-tested: no credential |
| **Codex CLI** | Custom `[model_providers.<id>] base_url` + `env_key`, or `openai_base_url` + `CODEX_API_KEY`. `OPENAI_BASE_URL` env is ignored. ChatGPT mode needs `chatgpt_base_url` **and** `openai_base_url`. | API-key modes: **yes**. ChatGPT mode: **only with a JWT-shaped `id_token`**. An unsigned fake JWT is accepted, which is fragile. | **Yes** over HTTPS SSE. The built-in provider tries WebSocket first (about 7 s fallback). | Shows "unexpected status 401/403", exits after 5 retries. No fallback. | measured (mock); not live-tested: no credential |
| **Gemini CLI** | `GOOGLE_GEMINI_BASE_URL` + `GEMINI_API_KEY` **and** `security.auth.selectedType="gemini-api-key"` (0.67.0) | **Yes** (`x-goog-api-key`), no `AIza` check | **Yes.** 20 chunks over 1.03 s. | Shows `_ApiError`, exits 1. No fallback. | measured (mock); not live-tested: no credential |
| **OpenCode** | `provider.<id>.options.baseURL` + `apiKey="{env:VAR}"` in `opencode.json` | **Yes** (`x-api-key`) | **Yes.** 25 chunks over 1.36 s. | Shows "Unauthorized/Forbidden: <msg>", exits 1. No fallback. | measured (mock); not live-tested: no credential |

**Conclusion (measured):** base-URL mode covers all five CLIs. kiro-cli, openab's default backend, does **not** force Phase 2 or 3: it needs three global settings keys and a bearer swap, with no SigV4. Because CONNECT interception is not needed, the brief's optional Phase 2 / SigV4 notes for Experiment 2 are skipped.

## Experiment 2: proxy base bake-off

### What was built (spike/exp2)

- **Shared core** (`src/lib.rs`, 614 code lines). Steps in order:
  1. Caller key, compared in constant time against sha256 hashes.
  2. Surrogate format check (`aps_<32 hex>`, exactly one).
  3. Canonicalization. The request must be in origin form with exactly one Host equal to the listener's authority, and the raw path must have no dot segments, encoded `.`/`/`/`\`/`%`, or empty segments. At config load, the upstream host must be a lowercase DNS name: no IP literal, userinfo, port or trailing dot.
  4. Policy check (caller + route + method + path prefix). An empty, missing or corrupt policy file means deny, and a good policy is never kept after the file goes bad.
  5. Broker resolve on every request, with no cache.
  6. Strip 7 auth headers plus hop-by-hop headers, then set exactly one credential.
  7. Error bodies in the route's dialect (JSON, or AWS `__type`).
  8. Audit lines with identities and codes only.
- **A** (`ap-proxy`, +149 lines): axum/hyper server with a reqwest/rustls client. Redirects are never followed, responses are streamed chunk by chunk, and request bodies are buffered (32 MB cap).
- **B** (`ap-authz`, +172 lines, of which 86 render the Envoy config): an HTTP `ext_authz` service. On allow it returns the credential header plus `x-envoy-auth-headers-to-remove`. Envoy 1.40.2's bootstrap is **rendered from the same validated config**, so Envoy's clusters and the service's routes cannot drift apart. Fail-closed settings: `failure_mode_allow=false`, `allow_absolute_url=false`, `status_on_error=503`, `normalize_path`, `merge_slashes`, `path_with_escaped_slashes_action=REJECT_REQUEST`, route `timeout: 0s`. Upstream TLS checks against `trusted_ca` + `match_typed_subject_alt_names` with `sni` = route host.
- **Base URL given to the CLI:** `http://127.0.0.1:<port>/ap/<caller-key>/<route>`. The caller key goes in the path because kiro-cli cannot add custom headers, while every CLI's knob accepts a path prefix (measured in Exp 1, and live here with kiro-cli).
- **Harness:** throwaway CAs, mock TLS upstreams that record SNI, Host and every header, a mock broker, and the 25-case matrix. Each case checks both the client's status/code and **what the upstreams actually received**.
- **Where it ran:** binaries were cross-built on a build host (`cargo zigbuild`, static musl). Tests and measurements ran on a 4-core Linux x86_64 test host (Intel N150). `cargo clippy --all-targets` is clean and `cargo test --lib` passes.

### A vs B

| | **A: Rust proxy** | **B: Envoy + ext_authz** |
|---|---|---|
| **R1** policy empty / 0-byte / deleted after good load / corrupt / other-path-only → refuse | PASS. 403 `policy_empty`, 503 `policy_unavailable`, 403 `policy_denied`; 0 upstream requests | PASS, 0 upstream. **Unavailable becomes a bare 503 with no reason**: Envoy replaces any authz 5xx with `status_on_error` and drops its body (measured) |
| **R2** broker stopped after a good request, same surrogate → refuse, no stale cache | PASS. 200, then 503 `broker_unavailable`, 0 upstream | PASS. 200, then bare 503 (same caveat), 0 upstream |
| **R3** expired / revoked / unknown / malformed / missing surrogate → explicit 4xx; AWS dialect | PASS. 401 with `surrogate_expired` etc.; AWS route gets `__type: AccessDeniedException` | PASS (identical, because Envoy passes authz 4xx bodies through) |
| **X1** wrong caller key; another caller's or route's surrogate | PASS (403 `caller_rejected`, `surrogate_wrong_caller`, `surrogate_wrong_route`) | PASS (same) |
| **R4** 302 to another host, another port, or `http://` → credential never forwarded | PASS. 302 returned unchanged, 0 requests to the target. A client that follows the redirect itself carries only the surrogate | PASS (same; Envoy does not follow by default) |
| **R5** Host with userinfo, foreign name, `127.1`, trailing dot, IPv6-mapped, two Hosts, no Host, absolute-form foreign / userinfo → reject | PASS (all 400, 0 upstream) | PASS **only after `allow_absolute_url=false`**. With the default, `GET http://u:p@127.0.0.1:<port>/…` was forwarded (200, 1 upstream request): Envoy dropped the userinfo and normalized the request to origin form (measured). No Host gives 426, absolute-form gives 404 |
| **R5** upstream route host is an IP literal (v4/v6/short), userinfo, trailing dot, or uppercase → config rejected | PASS (exit 2) | PASS (`render-envoy` and `serve` both exit 2) |
| **X2** `..`, `%2e%2e`, `%2f`, `//`, route hop `/badca/../up`, `%252e` | PASS: every one refused (400) | PASS: `%2f` and `%252e` refused. `..`, `%2e%2e`, `//` and route hop were **normalized and forwarded**, and policy saw exactly the path upstream received (`/v1/echo` on the route it named) |
| **X3** CONNECT | PASS (405) | PASS (404) |
| **R6** upstream sees SNI == Host == route host; client `X-Forwarded-Host` has no effect | PASS | PASS |
| **R6** certificate name ≠ route host | PASS (502, TLS handshake aborted, 0 requests) | PASS (503, same) |
| **R7** upstream certificate from an untrusted CA → refuse | PASS (502, 0 requests) | PASS (503, 0 requests) |
| **R8** surrogate + 6 junk auth headers + `TokenType` → upstream gets exactly one `authorization` = real; no surrogate, junk or caller key; `TokenType` kept | PASS | PASS (`x-envoy-auth-headers-to-remove` works in HTTP mode) |
| **R8** x-api-key route + junk `Authorization` → exactly one `x-api-key` | PASS | PASS |
| **R8** two surrogate headers → reject | PASS (400) | PASS (400) |
| **X4** enforcement point down | n/a (one process: if it is down, nothing listens) | PASS. Authz stopped gives 403, 0 upstream (`failure_mode_allow=false`) |
| **X5** no real credential, surrogate or caller key in any log or work file | PASS | PASS (Envoy log at `warn`) |
| **X6** SSE via mock, 20 events × 50 ms | PASS: first event 2 ms, spread 0.96 s | PASS: first event 4 ms, spread 0.96 s |
| **Live streaming**, kiro-cli 2.37.0 ACP → real Kiro service (AWS eventstream, not SSE) | PASS: 15 chunks over 0.46 s, 60/60 lines, real key in 0 files | PASS: 15 chunks over 0.34 s, 60/60 lines, real key in 0 files |
| **Matrix total** | **25/25** (X4 n/a) | **25/25**, after 2 config fixes found by the matrix |
| **Added latency**, p50 / p99 over direct (keep-alive, 2000 sequential, 3 runs; includes 1 broker round-trip of 0.20 ms p50) | **+0.34–0.35 ms / +0.31–0.69 ms** | **+0.70–0.87 ms / +1.18–1.43 ms** |
| **Throughput**, 32 connections × 15 s, 0 errors (Python client, upstream and broker are the ceiling) | 3,377–3,398 req/s | 2,408–2,430 req/s |
| **RSS idle** | **2.8 MB** | **68.5–68.9 MB** (Envoy 66.1–66.5 + authz 2.4) |
| **RSS peak under load** | **12.3–13.8 MB** | **79.1–79.8 MB** (Envoy 70.7–71.0 + authz 8.4–8.9) |
| **Image** (linux/amd64) | one 3.6 MB static binary; `scratch` image 1.8 MB compressed | `envoyproxy/envoy:distroless-v1.40.2` 171 MB (44 MB compressed), or 286 MB / 73 MB for the full image, plus the authz binary 3.6 MB (1.8 MB) |
| **Code / config** (non-blank, non-comment) | 614 core + 149 = **763 Rust**, 1 JSON config | 614 core + 172 = **786 Rust** + Envoy bootstrap **461 JSON lines for 5 routes** (about 136 base + 65 per route), generated |
| **Processes in the trust domain** | 1 | 2. The real credential crosses authz → Envoy as a loopback HTTP response header, and both processes hold it |
| **Audit** | one line per request with the upstream status | the authz decision only; upstream status needs a join with Envoy's access log |

All rows are **measured** except the "Processes" and "Audit" rows, which describe the design.

### Things the matrix caught (measured)

- **B, absolute-form with userinfo:** with Envoy's default `allow_absolute_url: true`, the request was forwarded with the real credential. Fixed with `allow_absolute_url: false`. With A, the same input was refused on the first run.
- **B, unavailable becomes opaque:** with `failure_mode_allow=false`, any 5xx from the authz service (policy or broker unavailable) becomes Envoy's fixed `status_on_error`. The reason header and body are lost. The request is still refused, which is safe, but the client and operator cannot see why. The workaround would be to answer 4xx from authz for these cases, which bends HTTP semantics.
- **A, missing TCP_NODELAY:** axum does not set it on accepted sockets. The first A benchmark showed +3 ms p50 and **+44 ms p99** (delayed ACK on the streamed response). Fixed with `tap_io(set_nodelay)`, which gave +0.34 ms. The mock servers had the same bug (42 ms baseline) and were fixed before any number above was taken.
- **Both, one credential across several hosts:** kiro-cli uses one key for 3 upstream hosts, so a surrogate must bind to a **set** of routes. The mock broker was extended to accept a route list.
- **B, inferred from docs:** Envoy's default route timeout of 15 s would cut long model streams, so the spike sets `timeout: 0s`. Not measured. The live turn took under 3 s.

### Phase 2 / SigV4

Not needed. Experiment 1 found no CLI that requires CONNECT interception, and kiro-cli with `KIRO_API_KEY` is bearer-only. For the record (**inferred**, docs only): Envoy has a dynamic forward proxy and SDS-delivered TLS for an interception mode, and its `aws_request_signing` filter signs with one workload credential, much like `credential_injector`. In A both would be our code (e.g. the `aws-sigv4` crate and rustls with minted leaf certificates). Neither option is blocked.

## Recommendation: A, a minimal Rust proxy

Both options can be made fail-closed, and both pass every row of the RFC matrix. The choice therefore comes down to how each gets there and what each costs.

- A is fail-closed by construction, because each check is a line of our code that the matrix exercises.
- B's safety depends on Envoy defaults that are wrong for this job. `allow_absolute_url` leaked a credential in the matrix. `failure_mode_allow`, `status_on_error` and the route timeout are footguns we know about. Any future Envoy default change would need the same matrix to catch it.
- A uses about 25× less memory (2.8 MB vs 69 MB idle, about 13 MB vs 79 MB under load), and that cost is paid in every openab-pty pod and openab sidecar. A also adds half the latency and ships as one 3.6 MB static binary.
- A keeps the real credential in one process, and its audit line includes the upstream status.
- A is on the same stack as octobroker (Rust, hyper/axum, reqwest/rustls), which keeps RFC open question 2 (shared code) open as a cheap option.
- B's real advantages are a battle-tested HTTP parser, HTTP/2 and WebSocket handling, and a ready path to an interception mode. Experiment 1 removed the need for interception. For parsing, A sits on hyper, the same library octobroker already trusts in production.
- The decision is cheap to reverse. Policy, broker client, canonicalization and stripping live in the shared core and are already served as an `ext_authz` service, so moving to Envoy later means replacing the ~150-line forwarder and keeping the matrix. Because of that, I am treating it as a low-risk decision and not escalating it.

## Open questions

**Resolved or narrowed by this spike**

- **RFC Q4** (which CLIs break with a surrogate?): none in their API-key or OAuth-token slots. The exception is Codex ChatGPT mode, which needs a JWT-shaped `id_token` (measured, mock).
- **RFC Q6** (is Phase 2 worth it?): not for the current five CLIs. Requiring base-URL support is viable (measured). Phase 2 can wait until a CLI needs it.
- **Proxy base:** A, as recommended above (measured).
- **RFC Q1, partly** (how the caller key reaches the proxy): putting it in the base-URL path (`/ap/<key>/<route>`) works for kiro-cli live, and every CLI accepts a path prefix. The key is then in the CLI's config file, which is acceptable, since the RFC already treats the caller key as readable by the agent identity. Proxies must not log the path prefix; both options audit only the route-relative path.

**Still open**

- **RFC Q1:** who mints the caller key and binds it to one session or agent process (openab-pty admin plane vs openab).
- **RFC Q2:** broker placement and store backend. With no credential cache, broker availability is proxy availability, and each request pays one broker round-trip (0.2 ms on loopback, measured). A remote broker needs a latency budget and an HA story.
- **RFC Q3:** policy format. The spike used JSON rules (caller, route, methods, path prefixes), re-read on change. It does not yet compose with #47's allowlist.
- **RFC Q5:** rotation, revocation and audit retention ownership. Not exercised beyond revoke and expiry in the mock broker.
- **Refusal status:** Claude Code in API-key mode retries a 401 for about 3 minutes (Exp 1). Should expired or revoked return 403, or a 401 body Claude treats as final? The spike returns 401 for surrogate state and 403 for policy and caller.
- **Not covered by A yet:** WebSocket upgrade (Codex's built-in provider tries WS first; a custom provider avoids it), HTTP/2 upstream, and request-body streaming (bodies are buffered, 32 MB cap).
- **Not covered by the tests:** live runs against the real Anthropic, OpenAI and Google APIs (no credential); SSE was measured only against the mock, while the live stream was kiro-cli's AWS eventstream; subscription OAuth refresh owned by the broker (Claude, Codex ChatGPT, Gemini Google login, kiro-cli SSO); load beyond the Python-bound ~3.4k req/s.
