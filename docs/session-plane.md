# Session plane

The session plane lets a session authority register per-session surrogates with the proxy. The
authority is the process that starts agent sessions: openab-pty's runtime, or openab on ECS.
Each surrogate is a random token that the authority puts in one child process environment. The
proxy stores only `sha256(surrogate)`, so a registered session can be revoked without changing
the caller key or the real credential.

This document is normative for Phase 1 on Kubernetes. The same calls are reused on ECS over HTTPS
in a later phase.

## Transport

- Kubernetes: HTTP/1.1 with JSON bodies over the Unix socket `/run/auth-proxy/session.sock`. The
  socket sits in a volume that the agent container and the proxy container both mount. The admin
  socket is a separate socket that only the proxy mounts, and it does not serve these calls.
- Known limitation: the agent container mounts the session socket volume writable, and the socket
  is created with mode 0666. An agent-UID process can unlink and rebind `session.sock`. That breaks
  the authority's calls, and it can capture the bearer token on `renew`. The effect is limited to
  the identity's own sessions. The pod spec does not yet move the socket out of agent reach.
- Every call except `hello` carries `Authorization: Bearer <authority-token>`.

## Calls

| Call | Body | Success | Failure |
|---|---|---|---|
| `POST /v1/hello` (Kubernetes only) | `{identity}`, where `identity` is the name of an identity in the config | `201 {authority_token, lease_secs}` | `400 identity_unknown` for a name not in the config, `400 invalid_body` for a body without a string `identity`; `409 authority_active` while the current authority's lease is live |
| `POST /v1/sessions` | `{session, generation, surrogate_sha256, credentials: [id]}` | `201 {lease_secs}` | `401` bad token; `400` invalid field; `403 credential_not_granted`; `409` same session and generation already registered with another hash; `429` over `max_sessions` |
| `POST /v1/renew` | `{sessions: [{session, generation}]}` | `200 {lease_secs, unknown: [...]}` | `401` |
| `DELETE /v1/sessions/{session}/{generation}` | none | `204` (also when unknown) | `401` |
| `PUT /v1/sessions` (resync) | full list as in `POST /v1/sessions` | `200 {registered, dropped}`; sessions not in the list are revoked | `401`, `400` (whole request rejected, nothing applied) |

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

## Hello lock

On Kubernetes the runtime calls `hello` before it binds its listeners, and it gets an authority
token back.

- The authority holds a lease of 90 s. It renews the lease, and every live session, with one
  `renew` call every 30 s.
- The proxy keeps only the sha256 of the authority token, in its private volume. It can check the
  token after a proxy restart without holding the token itself. The authority keeps the token only
  in memory.
- While the lease is live, another `hello` returns `409 authority_active`.
- When the lease lapses, the proxy revokes every session that the old authority registered, and
  then it accepts a new `hello`.
- In openab-pty the runtime is PID 1 of its container. A dead runtime takes its shells with it, so
  the next `hello` comes from the restarted runtime before any session exists.

**Open gap (pending owner decision).** The Phase 1 code does not enforce the PID 1 guarantee above.
`hello` takes an identity name and no secret. The agent container shares the session socket and
runs as UID 1000, the same UID as the authority. So during the lease-lapse window, any agent-UID
process that can reach `session.sock` can call `hello` first and become the authority. Its reach is
limited to its own identity's grants. The real credential stays in the proxy, and an unknown
surrogate is still refused. Two options are open, and the owner has not chosen between them:

- (a) Add a runtime-only proof to `hello`. This changes the `hello` call.
- (b) Record acceptance of the gap against design condition 1, and name the test that covers it.

Until the owner decides, the guarantee in the paragraph above is not enforced.

On ECS there is no `hello`. The authority token is set in the proxy config as its hash.

## Revocation and audit

- A session is revoked when it ends: on exit, kill, restart, absolute TTL, or eviction by the
  authority.
- A process that outlives its session is refused on its next request.
- Every call writes an audit line with the session id, the generation, a short hash prefix and the
  result. An audit line never contains a surrogate or the caller key.

## Amendments to the design table

- The design's Q1-B table lists the `hello` body as `{}`. The implementation requires
  `{"identity": "<identity name>"}`, and the matrix driver sends it. This document uses the
  implemented body. The design copy at `docs/design/phase1.md` is unchanged.
- The `400 identity_unknown` row is added. It is returned for a name not in the config.
