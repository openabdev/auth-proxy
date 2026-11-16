# Session plane (normative)

Claim tags: [M] measured, [I] inferred, as in `docs/design/phase1.md`. This file is the
protocol a platform implements to register per-session surrogates with auth-proxy. The
design rationale is Q1-B in the design doc; `ap-client` is one implementation.

Phase 1 ships the Kubernetes transport only: HTTP/1.1 with JSON bodies over the Unix
socket `/run/auth-proxy/session.sock`. The HTTPS transport for ECS is **deferred, not
rejected**.

## Roles

- **Session authority**: the platform process that spawns sessions (openab-pty's runtime,
  PID 1 of the agent container). It generates each surrogate, keeps it only to put it in
  the child's environment, and sends the proxy only `sha256(surrogate)`.
- **Proxy**: stores hashes, leases and the authority token's hash. Never stores a surrogate.

## Calls

Every call except `hello` carries `Authorization: Bearer <authority-token>`.

| Call | Body | Success | Failure |
|---|---|---|---|
| `POST /v1/hello` | `{}` | `201 {authority_token, lease_secs}` | `409 authority_active` while the current authority's lease is live |
| `POST /v1/sessions` | `{session, generation, surrogate_sha256, credentials: [id]}` | `201 {lease_secs}` | `401` bad token; `400` invalid field; `403 credential_not_granted`; `409` same session and generation already registered with another hash; `429` over `max_sessions` |
| `POST /v1/renew` | `{sessions: [{session, generation}]}` | `200 {lease_secs, unknown: [...]}` | `401` |
| `DELETE /v1/sessions/{session}/{generation}` | none | `204` (also when unknown) | `401` |
| `PUT /v1/sessions` (resync) | full list as in `POST` | `200 {registered, dropped}`; sessions not in the list are revoked | `401`, `400` (whole request rejected, nothing applied) |

## Validation

All failures are `400` and change nothing.

- `session`: 1 to 128 characters of `[A-Za-z0-9._:-]`.
- `generation`: a u64.
- `surrogate_sha256`: exactly 64 lowercase hex characters.
- `credentials`: 1 to 16 ids, each defined in the policy and granted to the identity, else `403`.
- Bodies over 1 MiB: `413`.
- A resync list is validated in full before anything is applied; the response names the
  failing entry.

## Leases

| Lease | Default | Rule |
|---|---|---|
| Session | 15 min | From the last renewal. Ends a session the authority stopped renewing. |
| Authority | 90 s | Renewed by `renew` (every 30 s). On lapse the proxy revokes every session the authority registered and accepts a new `hello`. |
| Absolute TTL | 12 h | Caps both. Renewal never extends a session past it. |
| Renew interval | 30 s | The authority renews itself and all live sessions in one call. |

Renewal is an explicit call, never a side effect of use. Phase 1 credentials are static API
keys without expiry, so only the session absolute TTL applies as an upper bound.

## Authority lock and restarts

- The proxy stores the authority token's hash in its private state volume, so it survives a
  proxy restart. After a proxy restart the persisted token stays valid and the lock is
  treated as live for one authority lease from the restart [I: plan reading, tested].
- `hello` has no caller authentication on the socket. Protection comes from the container
  shape: the authority is PID 1, its death kills every agent-UID process in the container,
  and the restarted PID 1 sends `hello` before any session exists [I]. After an authority
  restart the old lock holds for up to 90 s, so the new process retries with backoff
  (`ap-client` `hello_retry`).
- After a proxy restart the next `renew` lists every session as `unknown`; the authority
  answers with `PUT /v1/sessions` carrying its full list. Requests in the gap (up to 30 s)
  get `surrogate_unknown`. After the resync the same surrogates work again, because the
  proxy only ever stored hashes.

## Audit and logs

Every call writes an audit line with the session id, generation, a short hash prefix and the
result. The surrogate and the authority token never appear. No log line contains the
`/ap/<caller-key>` prefix; see `docs/operations.md`.

## Status

Q1-B is the accepted design and new work on this protocol is frozen after the over-design
council. The first Kubernetes deployment can run without it, on the interim static session
(`docs/interim-static-session.md`), which has no per-session revocation.
