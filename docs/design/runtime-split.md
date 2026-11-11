# Runtime split (Option A): design note

Status: design only. No code ran to produce this note.

## Summary

The Kubernetes pod splits the agent from the process that talks to the session plane. The agent
runs as UID 1000 and has no path to `session.sock`. A new runtime container (UID 1002) holds the
hello proof, is the only client of `session.sock`, and serves a narrow API to the agent over a
second Unix socket. `hello` requires a proof that only the runtime can produce. The proxy listener
(`127.0.0.1:18080`) and the agent's base URL do not change.

## Containers and UIDs

| Container | Kind | UID | Capabilities | Mounts (new or changed in bold) |
|---|---|---|---|---|
| `volume-prep` | init, new | 0 | `CHOWN` only | `agent-runtime`, `session-plane` (sets owner, group and mode, then exits) |
| `netinit` | init, unchanged rules | 0 | `NET_ADMIN` only | `netinit-run` |
| `expiry-store-bootstrap` | init, unchanged | 1001 | none | `expiry-store` |
| `agent` | app | 1000 | none | `agent-runtime` (at `/run/auth-proxy-agent`); caller key, home, work, tmp. **No `session-plane`.** |
| `proxy` | app | 1001 | none | `session-plane` (at `/run/auth-proxy-session`); admin socket, identity config, proxy state, tokens, expiry store, kiro secret |
| `runtime` | app, new | 1002 | none | **`session-plane`** (at `/run/auth-proxy-session`), **`agent-runtime`** (at `/run/auth-proxy-agent`), **`runtime-key`** (read-only, at `/var/run/auth-proxy-runtime`). Nothing else. |
| `egress` | app | **1003** (was 1002) | none | identity config |

The egress container moves from UID 1002 to 1003 because the runtime takes 1002. Its behavior
does not change.

## Socket paths and ownership

| Path | Served by | Connects | Owner:group | Mode | Visible in |
|---|---|---|---|---|---|
| `/run/auth-proxy-session/session.sock` | proxy | runtime | `1001:1002` | `0660` | proxy, runtime |
| `/run/auth-proxy-agent/runtime.sock` | runtime | agent | `1002:1000` | `0660` | runtime, agent |
| `/run/auth-proxy/admin.sock` (unchanged) | proxy | operator tooling | proxy only | `0600` | proxy |

The parent directories are created by `volume-prep`: `/run/auth-proxy-session` is `1001:1002`
with mode `2750`, and `/run/auth-proxy-agent` is `1002:1000` with mode `2750`. The setgid bit makes
each new socket inherit the group of its directory. A process cannot chown a socket to a group it
does not belong to, so the proxy and the runtime get the group through the directory.

Deviation from the plan: the plan asks for `session.sock` owned by UID 1002. The proxy creates
and binds the socket, and a non-root process cannot give a file to another user (that needs
`CAP_CHOWN`). The owner is therefore UID 1001, and the group is 1002. Only UID 1002 and the proxy's
group can connect. UID 1000 has neither the group nor a mount that shows the path.

The `bind_session_socket` helper changes its mode from `0666` to `0660`.

## Agent-runtime socket operations

Transport: HTTP/1.1 with JSON bodies over `/run/auth-proxy-agent/runtime.sock`. The runtime
identifies the caller by its identity only, the one configured for the runtime. The agent sends no
identity and no token. Any operation not listed below returns `404 unknown_operation`, including
`/v1/hello`, `/v1/hello/challenge`, and every proxy session-plane path. A listed path with the
wrong method returns `405 method_not_allowed`. Bodies are capped at 1 MiB (`413 body_too_large`).

| Operation | Request | Success | Failure codes |
|---|---|---|---|
| register | `POST /v1/session` with `{"session": str, "generation": u64, "credentials": [str]}` | `201 {"surrogate": "<64 lowercase hex>", "lease_secs": u64}` | `400 invalid_body`, `400 invalid_field` (adds `"field"`), `403 credential_not_granted`, `403 session_expired`, `409 session_conflict`, `429 max_sessions`, `503 no_authority`, `503 broker_unavailable` |
| revoke | `DELETE /v1/session/{session}/{generation}` | `204`. Also `204` when the runtime does not track the key. | `400 invalid_field`, `503 no_authority`, `503 broker_unavailable` |
| status | `GET /v1/status` | `200 {"identity": str, "authority": "live" \| "none", "sessions": [{"session", "generation"}]}` | none beyond `404` and `405` |

Behavior that the failure codes depend on:

- **register** generates 32 random bytes with the OS RNG and returns them as the surrogate. The
  runtime keeps only `sha256(surrogate)`. It sends that hash to the proxy with its own authority
  token (`POST /v1/sessions`). The caller's identity is the runtime's identity. The agent cannot
  choose another identity.
- **register** checks `session` and `generation` with the same rules as the proxy
  (`validate_session`, u64) before it contacts the proxy. A bad value returns `400 invalid_field`
  and names the field.
- **revoke** contacts the proxy only for keys the runtime registered. An unknown key returns `204`
  and changes nothing, so the agent cannot revoke sessions that the runtime did not create.
- The proxy's `400` maps to `invalid_field`. Its `403`, `409` and `429` pass through under the
  same code names. Its `503` maps to `broker_unavailable`. A connection failure also maps to
  `broker_unavailable`.
- `no_authority` means the runtime has not completed `hello`. The runtime keeps no session state
  until then.

## Hello proof

### Key material

- The runtime holds an Ed25519 private seed: 32 bytes, base64 text, in the Secret
  `auth-proxy-runtime-key`, key `runtime_ed25519.seed`. It is mounted read-only at
  `/var/run/auth-proxy-runtime/runtime_ed25519.seed` in the runtime container only. Mode `0444`,
  the same as `kiro-secret`. The file is not readable by any other container because the other
  containers do not mount it. The validator enforces that mount rule.
- The proxy holds only the public key: `runtime_pubkey` (base64, 32 bytes) on each
  `[[identity]]` in the identity config. It is not a secret.
- Why Ed25519 and not HMAC: an HMAC proxy must hold the same secret as the runtime. The plan
  allows the proof Secret in the runtime only, so the proxy can verify without a shared secret.
  This adds one dependency, `ed25519-dalek`, to `ap-broker`.

### Challenge and hello

1. `GET /v1/hello/challenge` returns `200 {"nonce": "<64 lowercase hex>", "ttl_secs": 30}`. The
   proxy draws 32 bytes from the OS RNG. Nonces live in memory only. At most 64 are outstanding,
   and the oldest is evicted first. Each nonce is one-shot.
2. `POST /v1/hello` with body `{"identity": str, "nonce": str, "proof": str}`, where `proof` is
   the standard base64 of a 64-byte Ed25519 signature. The body uses `deny_unknown_fields`.
   Success returns `201 {"authority_token", "lease_secs"}`, the same as today.

The signed message is the bytes:

```
"auth-proxy hello v1\n" || u32_be(len(identity)) || identity || "\n" || nonce
```

`nonce` is the 64-character hex string as sent. The length prefix keeps the message unambiguous
for any identity string.

### Verification rule

The proxy runs these checks in this order. The first failure returns and nothing else runs.

1. The body parses, with the shape above (`400 invalid_body` otherwise).
2. `identity` is in the config (`400 identity_unknown`). Unchanged.
3. The identity has a `runtime_pubkey` (`403 runtime_key_missing` otherwise). This fails closed.
4. `proof` is present (`401 proof_missing` otherwise). Nothing is consumed yet.
5. The nonce exists, has not expired and has not been used. It is removed from the table on
   lookup, whether or not the next check passes (`401 nonce_invalid` otherwise).
6. `proof` decodes to 64 bytes and `verify_strict` accepts it over the signed message with the
   identity's public key (`401 proof_invalid` otherwise). Ed25519 verification compares in
   constant time.
7. The lease check and the authority token are unchanged. A live lease returns `409
   authority_active`. A store failure returns `503 broker_unavailable`.

Hello requests are audited with the result code and the identity. The audit line never contains
the proof, the nonce, or the token.

The runtime signs the same message with the seed it loaded at startup. The shim exits non-zero on
any hello failure and logs the code. The restart policy then retries it.

## Failure code summary

| Layer | Code | When |
|---|---|---|
| hello | `400 invalid_body` | body does not match the shape, or the nonce is not 64 lowercase hex |
| hello | `400 identity_unknown` | identity not in the config |
| hello | `403 runtime_key_missing` | identity has no `runtime_pubkey` |
| hello | `401 proof_missing` | no `proof` field. This is the lease-lapse attacker case without the proof. |
| hello | `401 nonce_invalid` | nonce unknown, expired, or already used |
| hello | `401 proof_invalid` | wrong signature, or a proof that is not 64 bytes after base64 decode |
| hello | `409 authority_active` | proof is valid and the lease is still live |
| hello | `503 broker_unavailable` | store or lock failure (unchanged) |
| agent-runtime | `404 unknown_operation`, `405 method_not_allowed` | path or method not in the operation table |
| agent-runtime | `400 invalid_body`, `400 invalid_field`, `413 body_too_large` | request shape or size |
| agent-runtime | `403 credential_not_granted`, `403 session_expired`, `409 session_conflict`, `429 max_sessions` | proxy result passed through |
| agent-runtime | `503 no_authority` | runtime has not completed hello |
| agent-runtime | `503 broker_unavailable` | proxy unreachable or returned 503 |

## Netinit rules per UID

The init container still runs as root with `NET_ADMIN` only. It flushes `OUTPUT` and installs these
rules for `iptables` and `ip6tables`:

| UID | Rules |
|---|---|
| 1000 (agent) | Unchanged. Accept ESTABLISHED. Allow loopback TCP to `PROXY_PORT` and `EGRESS_PORT`. Reject other loopback TCP listed in `OTHER_LO_PORTS`. Reject all other loopback. Reject all non-loopback output. |
| 1001 (proxy) | No rule (unchanged). |
| 1002 (runtime) | Accept ESTABLISHED. Reject all other output. The runtime needs no network: `session.sock` and `runtime.sock` are Unix sockets, which netfilter does not see. |
| 1003 (egress) | No rule (unchanged). |

Deviation from the plan: the plan lists the proxy listener as allowed for UID 1002. The runtime
has no reason to reach it, since the session plane is a Unix socket. Adding that rule would widen
the runtime's network reach for no use. The owner can override this.

`netinit.sh` gets a `RUNTIME_UID` variable (default 1002). It rejects a run where `RUNTIME_UID` equals
`AGENT_UID`, and it rejects any non-numeric value, as it already does.

## Verification plan

Unit tests (`ap-broker`, `ap-core`):

- hello without `proof` returns `proof_missing`.
- hello with a signature from another key returns `proof_invalid`.
- hello with the right key and nonce returns `201`.
- The lease-lapse attacker (UID 1000, no seed) cannot produce a valid proof: `proof_missing`.
- Replayed nonce returns `nonce_invalid`. Expired nonce returns `nonce_invalid`.
- Identity without `runtime_pubkey` returns `runtime_key_missing`.
- Signed-message construction matches a fixed vector.

Shim tests (`ap-runtime-shim`): register returns a surrogate whose hash the proxy accepts; an
unknown revoke returns `204` without a proxy call; `/v1/hello` on the agent socket returns
`404 unknown_operation`; oversized bodies return `413`.

Pod checks: the validator checks that `runtime-key` is mounted only into `runtime`, that
`session-plane` is not mounted into `agent`, and that the runtime UID differs from the agent UID.
In the cluster run, check A has three parts. (i) `connect` to `session.sock` as UID 1000 fails.
Because the agent container has no mount that shows the path, the expected error is "no such
file" and not "permission denied". The permission bits are a second layer, and a unit test
checks them against a socket in a setgid directory. (ii) `hello` on `runtime.sock` returns
`404 unknown_operation`. (iii) A hello attempt from UID 1000 is refused with `proof_missing` or
`404`, and it never reaches the proxy.

## Compatibility

- The hello body changes: `{"identity"}` alone is refused. `ap-client`, the matrix harness
  (`tests/matrix/harness.py`) and any authority built on those must send the nonce and proof.
  The openab-pty runtime is not in this repo. Its change is in a separate plan and is not part of
  this run.
- The proxy rolls out first and the runtime shim second. A pod with the old proxy keeps the old
  hello path and does not have the proof, so the two must ship together.
- The 12 h absolute TTL, resync `expired`, and the expiry store are unchanged.

## Not in this note

- The openab-pty runtime split (it serves `runtime.sock` itself).
- ECS. The proof check and the hello change are Kubernetes-only, as the session plane is.
- Rate limits on `GET /v1/hello/challenge`. The nonce table is bounded, but a rate limit is
  deferred.
