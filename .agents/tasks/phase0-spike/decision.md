# Phase 0 decision

**Decided alone** (no escalation, no decision council). Both choices are low risk and reversible, and the measured evidence in `report.md` and `exp1.md` points one way.

## 1. Phase 1 proxy base: A (minimal Rust reverse proxy, hyper/axum)

- Both options pass the 25-case fail-closed matrix. A passed on the first run; B passed only after two non-default Envoy settings. With Envoy's default `allow_absolute_url: true`, a userinfo absolute-form request was forwarded with the real credential (measured).
- B turns every authz 5xx (policy or broker unavailable) into a bare 503 with no reason. A returns explicit `policy_unavailable` / `broker_unavailable` codes (measured).
- A costs less in every pod/sidecar: 2.8 MB vs 68.5–68.9 MB RSS idle, 12.3–13.8 MB vs 79.1–79.8 MB peak; +0.34–0.35 ms vs +0.70–0.87 ms p50 added latency; one 3.6 MB static binary vs a 171 MB Envoy image plus a second process (measured).
- A keeps the real credential in one process and logs upstream status in one audit line.
- Reversible: policy, broker client, canonicalization and header stripping are in the shared core, which already runs as an `ext_authz` service. Moving to Envoy later replaces the ~150-line forwarder and reuses the matrix.

## 2. Phase 2 (CONNECT interception) pull-forward: none

- Exp 1 measured that all five CLIs (kiro-cli live with a real key; Claude Code, Codex, Gemini CLI, OpenCode against mocks) route model traffic through a base URL, accept an opaque surrogate, stream through the swap proxy, and refuse without falling back to a direct connection. kiro-cli is bearer-only with `TokenType: API_KEY`, no SigV4.
- Nothing forces interception, so pulling it forward would add TLS minting and SigV4 work with no current consumer. Phase 2 stays deferred until a CLI needs it.
- The gaps Exp 1 found (WebSocket upgrade for Codex's built-in provider, request-body streaming, 401 vs 403 for Claude Code's 3-minute 401 retry) are base-URL-mode items. They belong in the Phase 1 backlog, not Phase 2.

## Change needed in report.md's recommendation section

No change. It already recommends A, says Phase 2 can wait, and records the decision as low risk and not escalated.
