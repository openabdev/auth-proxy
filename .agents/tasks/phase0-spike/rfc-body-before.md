> **Status: Draft (WIP).** First cut from the discussion on openabdev/openab-pty#93. Expect revisions, and please comment.

## Summary

`auth-proxy` is a shared component that lets an AI agent use credentials without ever holding them in plaintext. The agent gets a revocable **surrogate**. A broker and an egress proxy run in a separate trust domain, check policy, and attach or apply the real credential just before the request leaves. This covers every credential an agent needs, not only GitHub. `openab` and `openab-pty` will both integrate it.

## Motivation

Today the usual way to give an agent a credential is to put plaintext in its environment or config. The agent CLI, every child process, transcripts, and logs can then read it. A prompt-injected or compromised agent can also exfiltrate it.

- **openab-pty:** SECURITY.md claim 4 says the shell holds no host credentials. In practice, any authenticated call (`gh`, registries, cloud APIs) means breaking that claim (openab-pty#93).
- **openab:** the agent subprocess is the same kind of target. openab#669 (agent inherited `DISCORD_BOT_TOKEN`) and openab#707 (`CLAUDE_CODE_OAUTH_TOKEN` passed to the agent via env) both show it.
- **Model credentials are the biggest case.** The agent's own model API key or OAuth token is the most valuable credential in the pod, and it is in the agent's env today.

`octobroker` already solves this for GitHub (per-agent key, default-deny policy, short-lived repo-scoped App tokens, `obk` git credential helper). `auth-proxy` generalizes the pattern to other credentials and reuses octobroker for GitHub.

## Goals

1. No plaintext credential in the agent's trust domain: env, files, memory, transcripts, logs.
2. Works for any credential shape (below), not just bearer headers.
3. Fail-closed everywhere: any doubt means no upstream request, never a fallback to direct egress.
4. One contract consumed by both `openab` and `openab-pty`.
5. Default-off and opt-in per credential until proven.

## Non-goals

- **Hiding what the agent can do.** The agent can still *spend* a credential within policy (see Guarantees).
- **Isolating processes inside one agent identity.** A session (openab-pty) or agent process tree (openab) is one trust unit.
- **Egress reachability policy.** That is openab-pty#47. This RFC only decides which credential may go where.
- **Re-implementing GitHub brokering.** Use octobroker.

## Guarantees (stated honestly)

- **The agent cannot read the credential.** It holds only a surrogate and a caller key.
- **The agent can use the credential within policy.** Destination binding alone is not enough. A surrogate bound to `api.github.com` can still act on any repo the token can reach, so policy must cover host + method + path/resource, and upstream tokens must be minimally scoped and short-lived.
- **Caller auth separates agent identities, not processes.** The caller key sits in env, so any same-UID process can read it via `/proc/<pid>/environ`. The claim is "a process outside this agent identity cannot spend the credential", not "no local process can".
- **Reflection is conditional.** If an allowed destination is attacker-controlled and echoes request data, a substituted credential can leak. Policy must not bind credentials to hosts that do that.

## Architecture

```
 agent trust domain (uid 1000)          auth-proxy trust domain (separate container/UID or external)
 ┌───────────────────────────┐          ┌────────────────────────────────────────────────┐
 │ agent CLI / shell         │          │ egress proxy  ── policy ── broker ── store     │
 │ env: surrogate + caller   │ ───────► │ 1 caller auth                    (Vault/SM/K8s)│
 │      key only             │ loopback │ 2 canonicalize + policy check                  │
 └───────────────────────────┘          │ 3 resolve surrogate (only now)                 │
                                        │ 4 apply credential, strip surrogate            │
                                        └──────────────────────────┬─────────────────────┘
                                                                   ▼  upstream (TLS)
```

- **Broker:** owns real credentials and refresh flows, mints surrogates bound to (agent identity, credential, policy, TTL), and handles revocation and rotation.
- **Egress proxy:** the only place the real credential is applied. It must never run inside the agent's process or UID. For openab-pty that rules out the runtime itself (`config.rs`: the crate never resolves secrets; `PR_SET_DUMPABLE=0` must not become the only barrier).
- **Placement options:** a sidecar container with its own UID and credential mount (shares the pod network namespace, so loopback works), or an external gateway. The agent container never mounts the store.

## Credential shapes

| Shape | Examples | Mechanism |
|---|---|---|
| Bearer / basic header | model APIs, npm/PyPI/crates, most REST APIs | surrogate in env → proxy substitutes header |
| Request signing | AWS SigV4 and similar | proxy re-signs the request; header swap cannot work |
| Key-holding | SSH for git | signing socket served from the auth-proxy domain (ssh-agent pattern); the key never enters the agent container |
| Refresh-token flows | CLI OAuth logins | the broker owns refresh; the agent only ever holds a surrogate access token |
| GitHub | `gh`, git over HTTPS, GitHub MCP | delegate to octobroker |

## How clients reach the proxy

1. **Base-URL mode (preferred):** the client points at `http://127.0.0.1:<port>/<route>` (e.g. `*_BASE_URL`, registry URL, git `insteadOf`). The proxy opens TLS upstream. No CA is involved and no traffic is intercepted.
2. **CONNECT + interception (fallback):** for clients without a base-URL override. The proxy terminates TLS only for credential-bound hosts and needs a CA the agent trusts. This adds a new high-trust component and breaks pinning and mTLS. The CA key never enters the agent container.

`HTTPS_PROXY` is only a setting that clients may or may not honor, so it is not a boundary. A client that bypasses the proxy simply has no credential. Blocking direct egress is #47's job.

## Request pipeline (fail-closed, in order)

1. Verify the caller key (constant-time) and the surrogate's format, TTL, and revocation status.
2. Canonicalize scheme/host/port. Reject userinfo, ambiguous hostnames, IP literals, and SNI/Host mismatch.
3. Check the credential policy (host + method + path/resource), intersected with the egress allowlist if present.
4. Only now resolve the surrogate to the real credential.
5. Strip the surrogate, caller key, and any client-supplied auth. Apply exactly one upstream credential.
6. Audit the request (identity, credential id, destination, decision), never the secret.

Refuse with no upstream request if: the policy is empty or unavailable (empty ≠ allow-all), the broker is unreachable (no stale cache), or upstream TLS verification fails. This matrix ships as tests before any merge.

**Redirects:** never forward a credential across a host, port, or scheme change. Any redirect the proxy follows gets the full check again. Redirect handling belongs in the proxy, not in each client.

## TTL and rotation

- Surrogate TTL ≤ 15 min by default, never longer than the upstream credential's remaining lifetime. It is revoked when the agent identity ends.
- Renewal means minting a new surrogate. Surrogates are never silently extended.
- Upstream rotation is an atomic generation switch in the broker. The proxy holds decrypted material only for the duration of a request.
- Expiry returns an explicit 4xx so the client can surface "re-mint", not a generic failure.

## Integration

- **openab-pty** (openab-pty#93): an admin-plane mint at session creation, delivered through the session env allowlist (same shape as the tools-plane mint, CLIENT-CONTRACT §9); a `deploy/` sidecar example for k8s and ECS; NetworkPolicy paired with #47. The runtime never handles real credentials.
- **openab:** replace plaintext credentials in `[agent].env` (e.g. the model OAuth token) with surrogates; one agent identity per agent process.

## Phases

0. **Spike:** model API key via base-URL mode for one CLI, with the fail-closed tests. Confirm which CLIs accept a surrogate (some decode tokens locally).
1. Bearer shape + broker + policy + audit; integrate with openab-pty and openab; GitHub through octobroker.
2. CONNECT/interception mode for clients without base-URL support.
3. Signing (SigV4) and SSH signing socket.

## Open questions

1. Agent identity: how does each project bind a caller key to "one session" / "one agent process", and who mints it?
2. Broker placement and store backends (AWS Secrets Manager, K8s secrets, Vault). Should it share code with octobroker?
3. Policy format and where it lives, and how it composes with #47's allowlist.
4. Which agent CLIs break with a surrogate (local JWT parsing, format checks)?
5. Ownership of rotation, revocation, and audit retention.
6. Is Phase 2 (interception) worth its cost, or do we require base-URL support?

## Prior art

- octobroker: per-agent key, default-deny policy, GitHub App token minting, git credential helper.
- Meta Muse: `authd` surrogates + Sentinel substitution at the network boundary.
- OpenClaw #123216: authenticated egress substitution proxy with destination binding, default-off.
- Envoy `ext_authz`/`ext_proc` (possible proxy base); mitmproxy (prototype only, not a production boundary).

