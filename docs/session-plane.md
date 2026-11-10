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
- Every call except `hello` carries `Authorization: Bearer <authority-token>`.

## Calls

| Call | Body | Success | Failure |
|---|---|---|---|
| `POST /v1/hello` (Kubernetes only) | `{}` | `201 {authority_token, lease_secs}` | `409 authority_active` while the current authority's lease is live |
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

On ECS there is no `hello`. The authority token is set in the proxy config as its hash.

## Revocation and audit

- A session is revoked when it ends: on exit, kill, restart, absolute TTL, or eviction by the
  authority.
- A process that outlives its session is refused on its next request.
- Every call writes an audit line with the session id, the generation, a short hash prefix and the
  result. An audit line never contains a surrogate or the caller key.
