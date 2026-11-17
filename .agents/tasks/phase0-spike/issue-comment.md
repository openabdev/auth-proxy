## Phase 0 spike: results and decision

Branch: https://github.com/openabdev/auth-proxy/tree/spike/phase0 (head `0d67df8`)

- `spike/exp1/`: CLI surrogate-compatibility probes
- `spike/exp2/`: proxy bake-off (A vs B), 25-case fail-closed matrix, benchmarks; raw output in `spike/exp2/results/`

Each claim is labelled **measured** (we ran it) or **inferred** (from docs or source, not run).

### Decision

- **Phase 1 proxy base: A**, a minimal Rust reverse proxy (hyper/axum, reqwest/rustls), on the same stack as octobroker.
- **Phase 2 (CONNECT interception): not pulled forward.** No CLI needs it today.

### Experiment 1: CLI surrogate compatibility

All five CLIs work in base-URL mode. Each one accepts an opaque surrogate, streams through a swapping reverse proxy, and shows the refusal without falling back to a direct connection. kiro-cli was tested live with a real key. The other four CLIs were tested against loopback mocks of their vendor APIs, because we had no credentials for them.

| CLI | Endpoint knob | Opaque surrogate | Streaming via swap proxy | Refusal behaviour | Evidence |
|---|---|---|---|---|---|
| kiro-cli 2.37.0 | global settings `api.cps.service`, `api.krs.service`, `api.codewhisperer.service` (+ `api.q.service`), value `{"endpoint":"http://127.0.0.1:<port>[/prefix]","region":"us-east-1"}`; global only | yes. Sent as `Authorization: Bearer` with `TokenType: API_KEY`, which must pass through. No SigV4 | yes. AWS eventstream, 32 chunks over 1.8 s; ACP mode works | shows the error and exits 1; no re-login, no fallback | measured, live |
| Claude Code 2.1.273 | `ANTHROPIC_BASE_URL` | yes (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`) | yes. 25 chunks over 1.35 s | no fallback. **In API-key mode a 401 is retried about 10 times over about 3 min**; a 403 fails at once | measured (mock) |
| Codex CLI 0.154.0 | `[model_providers.<id>] base_url` + `env_key`, or `openai_base_url` + `CODEX_API_KEY` (`OPENAI_BASE_URL` env is ignored) | API-key modes: yes. ChatGPT mode only with a JWT-shaped `id_token`, which is fragile | yes over HTTPS SSE; the built-in provider tries WebSocket first (about 7 s fallback) | exits after 5 retries; no fallback | measured (mock) |
| Gemini CLI 0.67.0 | `GOOGLE_GEMINI_BASE_URL` + `GEMINI_API_KEY` + `security.auth.selectedType="gemini-api-key"` | yes (`x-goog-api-key`) | yes. 20 chunks over 1.03 s | exits 1; no fallback | measured (mock) |
| OpenCode 1.19.5 | `provider.<id>.options.baseURL` + `apiKey="{env:VAR}"` | yes (`x-api-key`) | yes. 25 chunks over 1.36 s | exits 1; no fallback | measured (mock) |

kiro-cli, openab's default backend, needs three global settings keys and a bearer swap. It does not force Phase 2 or Phase 3.

### Experiment 2: A (Rust proxy) vs B (Envoy 1.40.2 + our `ext_authz` service)

Both options share one admission core: caller key, surrogate format, request canonicalization, policy check, a broker lookup on every request with no cache, auth-header stripping, and dialect-aware error bodies. A wraps the core in about 150 lines of forwarder. B serves the core as an HTTP `ext_authz` service and renders Envoy's bootstrap from the same validated config. The harness checks the client's status and **what the mock upstreams actually received**. Tests and measurements ran on a 4-core Linux x86_64 test host.

| Matrix row | A | B |
|---|---|---|
| R1 empty, 0-byte, deleted, corrupt or non-matching policy → refuse | PASS, 0 upstream | PASS, 0 upstream. Policy-unavailable becomes a bare 503 with no reason |
| R2 broker down after a good request → refuse, no stale cache | PASS (503 `broker_unavailable`) | PASS (bare 503) |
| R3 expired, revoked, unknown, malformed or missing surrogate → 4xx; AWS dialect | PASS | PASS |
| X1 wrong caller key; another caller's or route's surrogate | PASS | PASS |
| R4 302 to another host, port or `http://` → credential not forwarded | PASS | PASS |
| R5 hostile Host / absolute-form requests → reject | PASS | PASS **only after `allow_absolute_url=false`** |
| R5 upstream route host is an IP literal, has userinfo, a trailing dot or uppercase → config rejected | PASS | PASS |
| X2 `..`, `%2e%2e`, `%2f`, `//`, route hop, `%252e` | PASS (all refused) | PASS (`%2f` and `%252e` refused; the rest normalized, and policy saw the same path the upstream received) |
| X3 CONNECT | PASS (405) | PASS (404) |
| R6 SNI == Host == route host; certificate name mismatch | PASS | PASS |
| R7 untrusted upstream CA | PASS | PASS |
| R8 exactly one real credential reaches upstream; junk auth headers stripped; two surrogates rejected | PASS | PASS |
| X4 enforcement point down | n/a (single process) | PASS (403, 0 upstream) |
| X5 no secret in any log or work file | PASS | PASS |
| X6 SSE, 20 events × 50 ms | PASS (first event 2 ms) | PASS (first event 4 ms) |
| Live kiro-cli ACP turn to the real service | PASS (15 chunks, 0.46 s) | PASS (15 chunks, 0.34 s) |
| **Matrix total** | **25/25** on the first run | **25/25** after 2 config fixes found by the matrix |

Measurements (3 runs each):

| | A | B |
|---|---|---|
| Added latency p50 / p99 over direct (includes a 0.20 ms broker round-trip) | +0.34–0.35 ms / +0.31–0.69 ms | +0.70–0.87 ms / +1.18–1.43 ms |
| Throughput, 32 connections × 15 s, 0 errors (client-bound) | 3,377–3,398 req/s | 2,408–2,430 req/s |
| RSS idle | 2.8 MB | 68.5–68.9 MB |
| RSS peak under load | 12.3–13.8 MB | 79.1–79.8 MB |
| Artifact | one 3.6 MB static binary | 171 MB Envoy distroless image + 3.6 MB authz binary |
| Code / config | 763 lines of Rust | 786 lines of Rust + 461 generated Envoy JSON lines for 5 routes |
| Processes holding the real credential | 1 | 2 |

What the matrix caught (measured):

- **B leaked a credential with Envoy's defaults.** With the default `allow_absolute_url: true`, an absolute-form request with userinfo was forwarded with the real credential. Setting `allow_absolute_url: false` fixed it. A refused the same input on the first run.
- **B hides why it refused.** With `failure_mode_allow=false`, any authz 5xx becomes Envoy's fixed `status_on_error`, and the reason is dropped. The request is still refused, but neither the client nor the operator can see why.
- **A was missing TCP_NODELAY.** Without it, p99 rose by 44 ms. Setting it fixed the problem before the numbers above were taken.
- **One credential spans several hosts.** kiro-cli uses one key for 3 upstream hosts, so a surrogate must bind to a set of routes.
- Inferred, not measured: Envoy's default 15 s route timeout would cut long streams, so the spike sets `timeout: 0s`.

### Rationale

- Both options pass the full matrix. A passed on the first run. B passed only after two non-default Envoy settings, and with the default `allow_absolute_url` it forwarded the real credential.
- B turns every policy-unavailable or broker-unavailable error into a bare 503. A returns explicit `policy_unavailable` / `broker_unavailable` codes.
- A costs less in every pod and sidecar: 2.8 MB vs about 69 MB idle, about half the added latency, and one small static binary instead of a 171 MB image plus a second process.
- A keeps the real credential in one process and writes one audit line per request, including the upstream status.
- The choice is reversible. The policy, broker client, canonicalization and header stripping live in the shared core, which already runs as an `ext_authz` service. Moving to Envoy later means replacing the ~150-line forwarder and reusing the matrix.
- Phase 2 stays deferred because no CLI requires CONNECT interception. Pulling it forward would add TLS minting and SigV4 work that nothing uses yet.

### Phase 1 backlog from the spike

These are base-URL-mode items, not Phase 2:

- WebSocket upgrade (Codex's built-in provider tries WS first; a custom provider avoids it).
- Request-body streaming (bodies are buffered today, 32 MB cap) and HTTP/2 upstream.
- 401 vs 403 for expired or revoked surrogates, since Claude Code retries a 401 for about 3 minutes.

### Still open

- **RFC Q1:** who mints the caller key and binds it to a session (openab-pty admin plane vs openab). Carrying the key in the base-URL path (`/ap/<key>/<route>`) works with kiro-cli live, and every CLI accepts a path prefix.
- **RFC Q2:** broker placement and store backend. With no cache, broker availability is proxy availability.
- **RFC Q3:** policy format, and how it composes with #47's allowlist.
- **RFC Q5:** ownership of rotation, revocation and audit retention.
- Not tested: live runs against the Anthropic, OpenAI and Google APIs (no credentials), broker-owned subscription OAuth refresh, and load above about 3.4k req/s.
