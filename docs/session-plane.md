# Session plane

The session plane lets a session authority register per-session surrogates with the proxy. The
authority is the process that starts agent sessions: openab-pty's runtime, or openab on ECS.
Each surrogate is a random token that the authority puts in one child process environment. The
proxy stores only `sha256(surrogate)`, so a registered session can be revoked without changing
the caller key or the real credential.

This document is normative for Phase 1 on Kubernetes. The same calls are reused on ECS over HTTPS
in a later phase.

## Transport

- Kubernetes: HTTP/1.1 with JSON bodies over the Unix socket `/run/auth-proxy-session/session.sock`.
  The socket sits in the `session-plane` volume, which only the proxy and the runtime container
  mount. The agent container does not mount it.
- The socket is created with mode 0660 in a setgid directory owned by UID 1001 and group 1002, so
  the socket's group is 1002. Only the proxy (UID 1001) and the runtime (UID 1002) can connect. The
  agent (UID 1000) is in neither group, and no mount shows it the path.
- The admin socket is a separate socket that only the proxy mounts, and it does not serve these
  calls.
- The runtime serves the agent over its own socket, `/run/auth-proxy-agent/runtime.sock`. The
  agent never calls the session socket. See "Agent-runtime socket" below.
- Every call except `hello` and `GET /v1/hello/challenge` carries `Authorization: Bearer
  <authority-token>`.

## Calls

| Call | Body | Success | Failure |
|---|---|---|---|
| `GET /v1/hello/challenge` (Kubernetes only) | none | `200 {nonce, ttl_secs}`. `nonce` is 64 lowercase hex, usable once, for 30 s. | none. The call writes an audit line with no nonce. |
| `POST /v1/hello` (Kubernetes only) | `{identity, nonce, proof}`, where `identity` names an identity in the config and `proof` is the Ed25519 signature described under "Hello proof" | `201 {authority_token, lease_secs}` | the hello error table under "Hello proof"; `503 broker_unavailable` |
| `POST /v1/sessions` | `{session, generation, surrogate_sha256, credentials: [id]}` | `201 {lease_secs}` | `401` bad token; `400` invalid field; `403 credential_not_granted`; `403 session_expired`; `409` same session and generation already registered with another hash; `429` over `max_sessions`; `503 broker_unavailable` |
| `POST /v1/renew` | `{sessions: [{session, generation}]}` | `200 {lease_secs, unknown: [...]}` | `401` |
| `DELETE /v1/sessions/{session}/{generation}` | none | `204` (also when unknown) | `401` |
| `PUT /v1/sessions` (resync) | full list as in `POST /v1/sessions` | `200 {registered, dropped, expired: [{session, generation}]}`; sessions not in the list are revoked; `expired` lists the listed keys skipped because their absolute expiry has passed | `401`, `400` (whole request rejected, nothing applied), `503 broker_unavailable` (nothing applied) |

The `expired` field is additive. The proxy writes it only when the list is not empty, so a resync
response with nothing expired has the older shape exactly. An older client denies unknown fields,
so it fails to decode a resync response that names an expired key. The rollout order below covers
this case.

### `POST /v1/sessions` error codes

| Status and code | Meaning | Registered? | Client action |
|---|---|---|---|
| `403 session_expired` | The session key `(identity, session, generation)` was recorded before, and its absolute TTL has passed. The absolute TTL is a fixed 12 h default in this release (`DEFAULT_ABSOLUTE_TTL_SECS` in `ap-broker`); there is no config key for it yet. The stored expiry survives a proxy restart, so a restart does not reset it. | No. The surrogate stays unknown. | Do not retry this key. A new generation is a new key with its own absolute TTL, so the authority decides whether to start one. |
| `503 broker_unavailable` | The proxy could not write the session expiry store, so it could not record the key's absolute expiry. The proxy fails closed: nothing is recorded and no session is accepted. | No. Nothing changes. | Retry later, after the store is writable again. The same request is safe to resend. |

A `503` whose body says `unavailable` (no `broker_` prefix) is a different condition: the registry
lock is poisoned. It is not a store failure, and it is not the code above.

## Rollout order (Phase 1)

1. Upgrade the proxy first. With nothing expired, its responses keep the older shape, so clients
   that do not know `expired` keep working.
2. Upgrade every client that decodes resync responses (the openab-pty runtime and any other
   authority).
3. Only after step 2, enable expiry-driven resync. Until then, a resync that names an expired key
   can break an older client.
4. The hello proof needs the proxy and the runtime shim together. A proxy with the gate refuses a
   hello with no proof, so a client that does not sign cannot start an authority. Deploy the proxy
   and `ap-runtime-shim` in the same pod revision.

## Validation

Every field is checked before anything is applied. Any failure returns `400` and changes nothing.

- `session`: 1 to 128 characters from `[A-Za-z0-9._:-]`. This fits openab-pty names and openab
  thread keys.
- `generation`: a u64.
- `surrogate_sha256`: exactly 64 lowercase hex characters.
- `credentials`: 1 to 16 ids. Each id must be defined in the config and granted to the identity.
  An id that is defined but not granted returns `403 credential_not_granted`.
- Request bodies over 1 MiB return `413`.
- A resync list is validated in full before anything is applied. A partly invalid list registers
  nothing, and the response names the failing entry.

## Session expiry store

The proxy keeps one absolute-expiry record per session key in a file named
`session-expiry.v1`. The pod keeps this file on its own durable volume, separate from the
authority token hashes. The proxy takes its location from `--expiry-store`. Without the flag the
file sits in the token directory. Records are never removed (see `docs/design/phase1.md`). The
proxy refuses to start when the file is missing, and `deploy/k8s/pod.yaml` creates it once in an
init container without truncating an existing file.

## Hello lock

On Kubernetes the runtime calls `hello` before it binds its agent socket, and it gets an authority
token back.

- The authority holds a lease of 90 s. It renews the lease, and every live session, with one
  `renew` call every 30 s.
- The proxy keeps only the sha256 of the authority token, in its private volume. It can check the
  token after a proxy restart without holding the token itself. The authority keeps the token only
  in memory.
- While the lease is live, another `hello` returns `409 authority_active`.
- When the lease lapses, the proxy revokes every session that the old authority registered, and
  then it accepts a new `hello`.
- Only a `hello` that carries a valid proof can take the lease. The proof is described next.

### Hello proof

The runtime holds an Ed25519 seed. The proxy holds only the public key. A process without the seed
cannot take the authority, even during a lease lapse.

- **Keys.** The runtime's seed is standard base64 of 32 bytes, in Secret `auth-proxy-runtime-key`,
  key `runtime_ed25519.seed`. The runtime container mounts it read-only, and no other container
  does. The proxy's identity config holds the public key as `runtime_pubkey` (standard base64 of 32
  bytes). The public key is not a secret. A malformed key stops the proxy at startup.
- **Flow.** `GET /v1/hello/challenge` returns a nonce. The runtime signs the hello message below
  and posts `{identity, nonce, proof}`, where `proof` is the standard base64 of the 64-byte
  signature.

  ```
  "auth-proxy hello v1\n" || u32_be(len(identity)) || identity || "\n" || nonce
  ```

- **Nonces.** 32 bytes from the OS RNG, as 64 lowercase hex. Each nonce works once and expires
  after 30 s. At most 64 are outstanding, and the oldest is evicted first. Nonces live in memory,
  so a proxy restart clears them.
- **Checks, in order.** The first failure returns, and nothing after it runs.

  | Step | Failure | Status and code |
  |---|---|---|
  | body shape; `nonce`, when present, is 64 lowercase hex | wrong types, unknown fields, or a bad nonce | `400 invalid_body` |
  | identity is in the config | not in the config | `400 identity_unknown` |
  | identity has a `runtime_pubkey` | none configured | `403 runtime_key_missing` |
  | `proof` is present | no proof. A body with only `identity` stops here. | `401 proof_missing` |
  | `nonce` is present, issued, unexpired and unused | missing, unknown, expired or spent. The entry is removed on lookup. | `401 nonce_invalid` |
  | `proof` is 64 bytes and verifies strictly over the message | wrong key, wrong identity, or wrong nonce | `401 proof_invalid` |
  | lease | a live lease holds the identity | `409 authority_active` |

  A refusal before the nonce check does not spend the nonce, so the same nonce works with a proof.
  The audit line for `hello` carries the identity and the result. It never carries the proof, the
  nonce or the token.

- **What the proof does not cover.** A process inside the runtime container can still sign, since
  the seed is in that container's memory. The runtime container runs only `ap-runtime-shim`, so
  this residual is limited to that one image. The proof stops the agent container and any other
  container in the pod. The decision record is `docs/design/runtime-split.md`.

On ECS there is no `hello`. The authority token is set in the proxy config as its hash.

## Agent-runtime socket

Kubernetes only. The runtime container serves this socket. The agent container mounts it, and the
proxy does not. It is the only interface the agent has to the session plane.

- Transport: HTTP/1.1 with JSON bodies over `/run/auth-proxy-agent/runtime.sock`. The socket is
  owned by UID 1002, group 1000, mode 0660. The agent sends no identity and no token. The runtime
  serves one identity, from its own `--identity` argument.
- Bodies are capped at 1 MiB (`413 body_too_large`).

| Operation | Request | Success | Failure |
|---|---|---|---|
| register | `POST /v1/session` with `{session, generation, credentials}` | `201 {surrogate}`. The runtime makes the surrogate (`aps_` plus 64 lowercase hex) and sends the proxy its digest only. | `400 invalid_body`; `400 invalid_field` with `field`; `403 credential_not_granted`; `403 session_expired`; `409 conflict`; `409 revoke_pending`; `429 too_many_sessions`; `503 broker_unavailable` |
| revoke | `DELETE /v1/session/{session}/{generation}` | `204`. A key the runtime did not register also gets `204`, with no proxy call. | `400 invalid_field` with `field`; `503 broker_unavailable` |
| status | `GET /v1/status` | `200 {identity, authority: "live", sessions: [{session, generation}]}` | none beyond `404` and `405` |

- The proxy's refusal codes pass through unchanged. `revoke_pending` is returned while an earlier
  end of the same key is still unconfirmed.
- Every other path returns `404 unknown_operation`. That includes `/v1/hello` and
  `/v1/hello/challenge`, which are the proxy's paths and never the agent's. A listed path with a
  different method returns `405 method_not_allowed`.
- The runtime binds `runtime.sock` only after its `hello` succeeds, so the socket never answers
  before the authority exists.

## Revocation and audit

- A session is revoked when it ends: on exit, kill, restart, absolute TTL, or eviction by the
  authority.
- A process that outlives its session is refused on its next request.
- Every call writes an audit line with the session id, the generation, a short hash prefix and the
  result. An audit line never contains a surrogate, the caller key, a nonce, a proof or a token.

## Amendments to the design table

- The design's Q1-B table lists the `hello` body as `{}`. The implementation requires
  `{identity, nonce, proof}`, and `{identity}` alone is refused with `401 proof_missing`. The
  matrix driver and `ap-client` send the full body. This document uses the implemented body. The
  design copy at `docs/design/phase1.md` is unchanged, and it still names the old session socket
  path and the old hello body.
- The `400 identity_unknown` row is added. It is returned for a name not in the config.
