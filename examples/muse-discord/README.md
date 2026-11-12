# Reference client: Muse as a caller, Discord as the upstream

This example implements the caller side of issue #6: a Muse custom-connector
helper that reaches Discord only through auth-proxy, so every outbound call is
policy-checked, audit-logged, and — once `require_approval` from issue #5
exists — held for the owner's approval before it executes.

It is a reference, not a deployment. Nothing here touches the proxy core.

## Pieces

```mermaid
flowchart LR
    subgraph agent["Muse (agent host)"]
        H["connector helper<br/>(caller.py shape)"]
    end
    subgraph owner["Owner-controlled host"]
        P["auth-proxy<br/>policy / swap / audit"]
        R["registrar<br/>issues + revokes surrogates"]
    end
    A["approval plane<br/>owner's device (#5)"]
    D["discord.com"]

    H -->|"caller key in path,<br/>surrogate in header"| P
    R -->|"register sha256(surrogate)"| P
    P -.->|"write parked (#5)"| A
    A -.->|"approve / deny"| P
    P -->|"real bot token swapped in"| D
```

## Files

| File | What it is |
|---|---|
| `identity.toml` | Example proxy config: `muse` identity, `discord` route, credential reference, grants. |
| `caller.py` | Reference caller (Python, stdlib only). Drop-in shape for a connector helper. |
| `mock_proxy.py` | Stand-in proxy implementing the caller-facing contract, including the proposed approval flow. No real Discord call ever happens. |
| `test_caller.py` | End-to-end tests of the caller against the mock: allow, park → approved, park → denied, park → expired, bad surrogate. |

## Wire protocol (as implemented by the proxy today)

From `crates/ap-client` and `crates/ap-proxy/src/pipeline.rs`:

- Requests are sent to `{base}/ap/<caller-key>/<route><upstream-path>` in
  origin form. The caller key is `apk_` + 64 lowercase hex; the config stores
  only its sha256.
- The session surrogate is `aps_` + 64 lowercase hex, sent in the route's
  surrogate header (default `authorization`) as `Bearer <surrogate>`. The
  proxy registry holds `sha256(surrogate)` per session.
- The proxy canonicalizes the request, checks caller key → identity, route,
  surrogate registration and the grant (identity × credential × route ×
  method × path; a path ending in `/` is a prefix), strips every client auth
  header, sets exactly one credential header with the real secret, and
  forwards upstream. The caller never sees the real credential.

Approval flow (proposed in #5, implemented here as the reference contract):
a write whose grant requires approval is answered `202` with a `request_id`
instead of being forwarded. The outcome is caller-scoped —
`GET {base}/ap/<caller-key>/requests/<request-id>` — and reports `parked`,
`executed` (with the upstream response), `denied`, or `expired`. `caller.py`
polls it; against a Phase 1 proxy nothing returns `202` and that path never
triggers.

## Generating keys

```sh
python3 - <<'EOF'
import hashlib, secrets
key = "apk_" + secrets.token_hex(32)
print("caller key (give to the caller):", key)
print("caller_key_sha256 (config):     ", hashlib.sha256(key.encode()).hexdigest())
print("surrogate (per session):        ", "aps_" + secrets.token_hex(32))
EOF
```

## Policy walkthrough (`identity.toml`)

- **Reads are granted**: `GET` on `/api/v10/channels/` and `/api/v10/guilds/`
  (prefixes). This covers reading message history for mention triage.
- **Writes are present but commented out.** Phase 1 policy only allows or
  denies, so an enabled write grant would execute immediately, with no
  approval. Uncomment the write grants only together with the
  `require_approval` action from #5 — or knowingly, accepting immediate
  execution.
- Write grants are per channel: the create-message endpoint is one exact
  path per channel id. Replies use the same endpoint with a
  `message_reference` in the JSON body. Policy cannot see the body; the
  approval step is what reviews it. That split is intentional.

## Known gap: credential scheme (`Bot` vs `Bearer`)

The forwarder always sets the credential header as `Bearer <secret>`
(`crates/ap-proxy/src/forward.rs`, `credential_value`). Discord bot tokens
must be sent as `Bot <token>`, so a live Discord upstream cannot authenticate
against Phase 1 as shipped — for reads and writes alike. Storing `Bot <token>`
as the secret does not help; the prefix is prepended unconditionally.

Minimal change that unblocks this example (not in this PR, it touches the
proxy core): a per-route credential scheme, e.g. `credential_scheme = "Bot"`,
defaulting to `"Bearer"`, validated against a small allowlist. Everything
else in this directory is ready to run against a proxy with that change and,
for writes, with #5.

## Sessions for a Muse caller

Issue #6 asks how sessions are issued when the caller is Muse. This example
assumes the registrar split from the session plane design:

- The registrar is a small component on the owner's device or home host. It
  holds the identity's runtime Ed25519 key (`runtime_pubkey` in
  `identity.toml`), generates the surrogate per session, and registers its
  sha256 with the proxy. The agent receives only the surrogate.
- Revoke is the same lever as for other callers: unregister the surrogate
  (Muse disconnect, session end) and it stops working immediately, together
  with any requests it has parked (#5).
- The remote-caller transport (Muse's host is not the proxy's host) is the
  open part of #6: the caller plane must be reachable by the agent without
  being reachable by the world — in the owner's deployment that is a
  tailnet-only listener. The proxy itself does not change for this; the
  caller key plus registered surrogate remain the authentication.

## Try it

```sh
python3 test_caller.py        # full contract: allow / approve / deny / expire / refusal
python3 mock_proxy.py &       # or run the mock yourself and drive caller.py by hand
AP_BASE=http://127.0.0.1:<port> \
AP_CALLER_KEY=apk_c6267244721d31df7f7ab84ca4f5d16ad4d3ef9d6d53b06662cd7dac6704c26c \
AP_SURROGATE=aps_ac5e3eca49b3e957da4c8709180f7f62a4336de3e14e68faf46df0735a016b03 \
python3 caller.py get-messages 2222222222222222222 5
```

(The key material above is the worked example from this directory; the mock
accepts exactly it.)

## Security notes

- The caller key travels in the URL path by design of the session plane; it
  is an identifier-grade authenticator that is useless without a registered
  surrogate, and vice versa. Treat proxy access logs as carrying it.
- Neither the caller key nor the surrogate can be exchanged for the real
  credential: the swap happens only inside the proxy, per request, against a
  matching grant.
- Fail closed at every layer you control: an unmatched path, an unregistered
  surrogate, or a missing runtime key is a refusal, never a fallback to a
  direct upstream call. `caller.py` has no direct-to-Discord code path at
  all.
