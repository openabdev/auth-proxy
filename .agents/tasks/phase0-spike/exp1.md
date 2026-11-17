# Phase 0 / Experiment 1: CLI surrogate compatibility

Spike code: `spike/exp1/` on branch `spike/phase0`.

## Method

- `swapproxy.py` is a loopback reverse proxy (Python stdlib, probe only). It finds the surrogate in an auth header (or a `key=` query parameter), swaps it for the real credential, strips any other client auth header, and forwards upstream over verified TLS. It refuses with 401 when the request does not carry exactly one surrogate. Every auth header is logged as `<redacted len=N match=surrogate|other>`, and a final filter replaces any credential value that reaches a log line. The proxy also answers `CONNECT` by logging the target and returning 403, so pointing `HTTPS_PROXY` at it shows (and blocks) any traffic that skips the base URL.
- Refusal modes: `refuse401`, `refuse403`, `expired` (401 `surrogate_expired`), each answered with no upstream call. `--error-shape aws` sends the refusal as an AWS JSON-protocol error.
- Bypass detection works two ways: the `CONNECT` log above, and a socket watcher that polls for TCP connections from the CLI's own session or process group to non-loopback peers (`ss` on Linux, `lsof` on macOS). Both watchers were self-tested with the proxy env unset. They reported 4 direct peers (kiro-cli) and 2 direct peers (Claude Code), so a "0" in the runs below is a real zero.
- kiro-cli (`kiro-probe.sh`, on a Linux test host): **live**. The real `KIRO_API_KEY` is loaded from the host's `~/.env` by name into a variable that only the proxy reads. kiro-cli gets a random `aps_<32 hex>` surrogate. Settings go into a throwaway `HOME`. Afterwards, a grep of every work dir for the real key value found 0 files.
- Claude Code, Codex, Gemini CLI, OpenCode (`cli_probe.py` + `mock_upstream.py`, on a macOS test host): **not live-tested: no credential**. The only stored logins on the test host were subscription OAuth tokens that had expired weeks earlier. Refreshing them would rotate the owner's tokens, so they were not used. These CLIs ran against a loopback mock of the Anthropic, OpenAI Responses/Chat and Gemini APIs placed behind the same swap proxy. Both the surrogate and the mock's "real" credential are random per run. The mock checks which one arrived: the "real" value means the swap worked, and the surrogate means it leaked. It streams each reply as about 20 SSE events 50 ms apart. This measures each CLI's local behaviour (knob, local token checks, streaming through the hop, refusal handling). It does not show that the real vendor API accepts the swapped request. Each CLI ran with a throwaway `HOME` and with vendor env vars scrubbed.
- Versions: kiro-cli 2.37.0 (Linux, live) and 3.1.0 (macOS, refuse modes only), Claude Code 2.1.273, Codex CLI 0.154.0, Gemini CLI 0.67.0, OpenCode 1.19.5.
- Paid requests spent: kiro-cli, 3 model turns plus 1 rejected call (HTTP 400). All other CLIs: 0.

## Compatibility table

| CLI | Endpoint knob (exact) | Opaque surrogate accepted? | Streaming through swap proxy | Refusal behaviour (401 / 403 / expired) | Evidence | Live? |
|---|---|---|---|---|---|---|
| **kiro-cli** | Global settings `api.cps.service`, `api.krs.service`, `api.codewhisperer.service` (and `api.q.service`, no traffic seen). Value: `{"endpoint":"http://127.0.0.1:<port>[/prefix]","region":"us-east-1"}`, set with `kiro-cli settings <key> '<json>'` or written to `~/.kiro/settings/cli.json`. **Global only**: `--workspace` is refused. Plain `http://` loopback and a path prefix both work. | **Yes.** Sent as `Authorization: Bearer <surrogate>` plus `TokenType: API_KEY` (the proxy must pass `TokenType` through). A 1-character key is also sent unchanged, so there is no local format or length check. | **Yes.** `GenerateAssistantResponse` returns `application/vnd.amazon.eventstream`: 32 chunks forwarded across 1.8 s for a 150-line answer. In ACP mode (`kiro-cli acp`, as openab runs it), the ACP client received 10 `agent_message_chunk` updates. | Surfaces the error and exits 1. It does not re-login and does not fall back to direct (0 `CONNECT` to the API hosts, 0 direct peers). With a plain JSON body: 401 shows "Authentication failed. Your credentials may be invalid or expired."; 403 shows "An unknown error occurred: service error". With an AWS-shaped body (`__type` + `message`), the proxy's message is shown verbatim, e.g. "Access denied: auth-proxy: surrogate expired; re-mint". Calls before exit: `GetProfile` once and `ListAvailableModels` 4 times, then the CLI exited within seconds. | measured | **live** (2.37.0 Linux, API key). 3.1.0 macOS: routing confirmed in refuse mode |
| **Claude Code** | `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>` | **Yes**, in all three credential slots: `ANTHROPIC_API_KEY` → `x-api-key`; `ANTHROPIC_AUTH_TOKEN` → `Authorization: Bearer`; `CLAUDE_CODE_OAUTH_TOKEN` → `Authorization: Bearer`, also sent to the base URL. No `sk-ant-` prefix check and no local decode. | **Yes.** 25 chunks forwarded across 1.35 s, matching the mock's pacing. | Surfaces "Failed to authenticate. API Error: <status> <proxy message>" and exits 1. No re-login and no direct fallback. **But** in `ANTHROPIC_API_KEY` mode a 401 is retried about 10 times with exponential backoff (21 requests across 172 s) before it surfaces. A 403 fails at once (0.4 s). In OAuth-token mode a 401 fails in about 2 s. | measured (mock) | not live-tested: no credential |
| **Codex CLI** | (a) A custom provider: `model_provider="ap"` + `[model_providers.ap] base_url="http://127.0.0.1:<port>/v1"`, `env_key="<VAR>"`, `wire_api="responses"`. (b) The built-in provider with `openai_base_url="…/v1"` + `CODEX_API_KEY`. (c) ChatGPT-subscription mode: `chatgpt_base_url` **and** `openai_base_url="…/backend-api/codex"`, since `chatgpt_base_url` alone leaves model traffic on `chatgpt.com`. **`OPENAI_BASE_URL` env is ignored** (the requests went to `api.openai.com`). With `OPENAI_API_KEY`, (b) sent no auth header at all. | API-key modes: **yes**, sent as `Authorization: Bearer`. ChatGPT mode: **only with a JWT-shaped `id_token`.** With an opaque `id_token`, Codex sent no `Authorization` at all. An unsigned (`alg:none`) fake-claims JWT was accepted (decoded locally, not verified). `access_token` may stay opaque. | **Yes** over HTTPS SSE: 24 chunks across 1.3 s. The built-in provider first tries a **WebSocket** (`ws://…/responses`, 5 reconnects), then falls back to HTTPS after about 7 s. The custom provider in (a) goes straight to HTTPS. | Surfaces "unexpected status 401/403: <proxy body>" and exits 1 after 5 retries (about 6.5 s). No re-login and no direct fallback for model traffic. | measured (mock) | not live-tested: no credential |
| **Gemini CLI** | `GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:<port>` + `GEMINI_API_KEY`. **In 0.67.0 the env var alone fails**: it selects auth type `gateway`, which headless validation rejects ("Invalid auth method selected.", exit 41). `security.auth.selectedType="gemini-api-key"` in `~/.gemini/settings.json` is also required. Headless runs also need `GEMINI_CLI_TRUST_WORKSPACE=true`. | **Yes.** Sent as `x-goog-api-key`, with no `AIza` prefix check. `GEMINI_API_KEY_AUTH_MECHANISM=bearer` switches the header to `Authorization` (from source, not run). | **Yes.** `streamGenerateContent?alt=sse`: 20 chunks across 1.03 s. | Surfaces the proxy body as `_ApiError` with `status`, plus "An unexpected critical error occurred", and exits 1 in under 1 s. No re-login and no direct fallback. | measured (mock). Knob logic read from the bundled source | not live-tested: no credential |
| **OpenCode** | `opencode.json`: `provider.<id>.options.baseURL="http://127.0.0.1:<port>/v1"` and `apiKey="{env:VAR}"` (tested with the `anthropic` provider; the file path comes from `OPENCODE_CONFIG`) | **Yes.** Sent as `x-api-key`. | **Yes.** 25 chunks across 1.36 s. | Surfaces "Error: Unauthorized/Forbidden: <proxy message>" and exits 1 in under 1 s. No re-login and no direct fallback. | measured (mock) | not live-tested: no credential |

### Side traffic that skips the base URL (seen as `CONNECT` and refused; the CLI still worked)

| CLI | Hosts | Note |
|---|---|---|
| kiro-cli | `cognito-identity.us-east-1.amazonaws.com`, `desktop-release.q.us-east-1.amazonaws.com` (`telemetry.us-east-1.kiro.dev` and `client-telemetry…` until `KIRO_DISABLE_TELEMETRY=1`) | Telemetry identity and update check. `SendTelemetryEvent` still goes to `api.codewhisperer.service`. |
| Claude Code | `api.anthropic.com` (4–12 per run) | All gone with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` (measured) |
| Codex | `chatgpt.com`, `ab.chatgpt.com`, `github.com`, `api.github.com` | Not needed for a turn |
| Gemini CLI | `play.googleapis.com` | Telemetry |
| OpenCode | `models.opencode.ai`, `registry.npmjs.org` | Model catalogue and plugin fetches |

We cannot see inside these TLS tunnels, so whether any of them carries the credential is **inferred**. It makes no difference in auth-proxy's design: the agent holds only a surrogate, so a bypassing request carries nothing worth stealing. Reachability belongs to openab-pty#47.

## kiro-cli detail (the deciding case)

- **Measured** routing per settings key (identified by giving each key its own path prefix):
  - `api.cps.service`: `GetProfile` and `KiroControlPlaneBearerService.ListAvailableModels`. Default host `management.<region>.kiro.dev`.
  - `api.krs.service`: `AmazonCodeWhispererStreamingService.GenerateAssistantResponse` (the chat stream). Default host `runtime.<region>.kiro.dev`.
  - `api.codewhisperer.service`: `SendTelemetryEvent` and usage-limit calls. Default host `q.<region>.amazonaws.com`.
  - The default hosts come from strings in the binary and were confirmed when every call returned 200 after the swap.
- **Measured** auth shape with `KIRO_API_KEY`: a bearer token plus `TokenType: API_KEY`. There is **no SigV4**, so header swap is enough. An early run that stripped `TokenType` got 400 "profileArn is required", because the service then treats the key as an SSO token.
- **Measured** no-override behaviour: with no settings, `HTTPS_PROXY` alone sends `CONNECT management.us-east-1.kiro.dev:443`. kiro-cli honours `HTTPS_PROXY`, so CONNECT interception *would* be possible, but it is not needed.
- **Inferred** constraint: the keys are global-only, so the openab/openab-pty integration must own `~/.kiro/settings/cli.json` in the agent's HOME (or run kiro-cli with a dedicated HOME). The agent can edit that file and point kiro-cli back at the real hosts. That is harmless: it then holds only a surrogate, which the real service rejects.
- **Inferred**, not tested: AWS Builder ID / IAM Identity Center sign-in also uses bearer tokens (`TokenType` has `EXTERNAL_IDP`/`API_KEY` variants in the binary), but those tokens refresh through the OIDC endpoint, which the broker would have to own. Phase 0 covers only `KIRO_API_KEY`.

## Conclusion: is CONNECT interception unavoidable?

**No, for none of the five CLIs.** Each one has a documented or discoverable base-URL knob that moves all of its model and credential-bearing API traffic to a loopback proxy. Each one sends an opaque surrogate unchanged, streams through a swapping reverse proxy, and on refusal surfaces the error without falling back to a direct connection or a re-login.

- **kiro-cli** (openab's default backend) works in base-URL mode, measured live end to end with a real `KIRO_API_KEY`, in both `chat` and `acp` modes. It needs 3 global settings keys and bearer swap only, with no SigV4. **kiro-cli does not force Phase 2 or Phase 3.**
- RFC open question 6 (is interception worth it?): nothing in this experiment needs it. Requiring base-URL support looks viable for the current CLI set.
- RFC open question 4 (which CLIs break with a surrogate?): none breaks with an opaque surrogate in its API-key or OAuth-token slot. The one exception is **Codex in ChatGPT-subscription mode**, which needs a JWT-shaped `id_token` surrogate. An unsigned fake JWT works today, but that relies on Codex not verifying the signature. That is undocumented behaviour, so treat it as fragile.

## Requirements this puts on the Phase 1 proxy (input to Experiment 2)

1. Multi-route base-URL mode: one listener with path-prefix routing to several upstream hosts (kiro-cli needs 3).
2. Pass non-secret auth-adjacent headers through (`TokenType`). Strip only real auth headers.
3. Speak each upstream's error dialect, so that kiro-cli shows the proxy's message (AWS JSON `__type`/`message`).
4. Use 403 rather than 401 for policy denial. Claude Code in API-key mode retries 401 for about 3 minutes. Revisit whether expiry should also be 403, or 401 with a body Claude treats as final.
5. WebSocket upgrade support, or accept the roughly 7 s Codex WS→HTTPS fallback. Using Codex with a custom `model_providers` entry avoids WS entirely.
6. Streaming: flush chunk by chunk with no buffering. SSE and AWS eventstream (binary) both have to pass through.
7. Integration recipes need per-CLI quirks: Gemini's `selectedType`, Claude's `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, Codex's `CODEX_API_KEY` (not `OPENAI_API_KEY`) and its custom provider.

## Open / not covered

- Live confirmation against the real Anthropic, OpenAI and Google APIs (no credential). The mock follows each vendor's wire format, but vendor-side checks such as key-to-header binding are untested.
- How the broker owns refresh for subscription OAuth: Claude, Codex ChatGPT mode, Gemini "Login with Google" (`CODE_ASSIST_ENDPOINT` exists in the source, not run), and kiro-cli SSO.
- Prior art found on the way: Codex ships `codex responses-api-proxy`, which reads an API key from stdin and serves the Responses API locally.
