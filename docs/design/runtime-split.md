# Runtime split (Option A): design note

Status: design, amended before implementation. Code that follows this note is in the same series.

## Summary

The Kubernetes pod splits the agent from the process that talks to the session plane. The agent
runs as UID 1000 and has no path to `session.sock`. A runtime container (UID 1002, binary
`ap-runtime-shim`) holds the hello proof, is the only client of `session.sock`, and serves a narrow
API to the agent over a second Unix socket. `hello` requires a proof that only the runtime can
produce. The proxy listener (`127.0.0.1:18080`) and the agent's base URL do not change.

## Containers and UIDs

| Container | Kind | UID:GID | Capabilities | Mounts |
|---|---|---|---|---|
| `volume-prep` | init, new, first | 0:0 | `CHOWN` only | `session-plane` and `agent-runtime` (sets owner, group and mode of both volume roots, then exits) |
| `netinit` | init, rules changed | 0:0 | `NET_ADMIN` only | `netinit-run` |
| `expiry-store-bootstrap` | init, unchanged | 1001 | none | `expiry-store` |
| `agent` | app | 1000:1000 | none | `agent-runtime` at `/run/auth-proxy-agent`; caller key, home, work, tmp. No `session-plane`. |
| `proxy` | app | 1001:1001 | none | `session-plane` at `/run/auth-proxy-session`; admin socket, identity config, proxy state, tokens, expiry store, kiro secret |
| `runtime` | app, new | 1002:1002 | none | `session-plane` at `/run/auth-proxy-session`, `agent-runtime` at `/run/auth-proxy-agent`, `runtime-key` read-only at `/var/run/auth-proxy-runtime`. Nothing else. |
| `egress` | app | 1003:1003 (was 1002) | none | identity config |

The runtime takes UID 1002, so the egress container moves to 1003. Its behavior does not change.
Every app container sets `runAsGroup`, so no container runs with GID 0 by accident.

## Socket paths and ownership

| Path | Served by | Connects | Owner:group | Mode | Visible in |
|---|---|---|---|---|---|
| `/run/auth-proxy-session/session.sock` | proxy | runtime | `1001:1002` | `0660` | proxy, runtime |
| `/run/auth-proxy-agent/runtime.sock` | runtime | agent | `1002:1000` | `0660` | runtime, agent |
| `/run/auth-proxy-admin/admin.sock` (unchanged) | proxy | operator tooling | `1001` | `0600` | proxy |

The two socket directories are the roots of the `session-plane` and `agent-runtime` volumes.
`volume-prep` sets each root to owner and group as above, mode `2750`. The setgid bit makes each
new socket inherit the group of its directory, so the proxy and the runtime both produce sockets
with the group the table shows. Only the group 1002 and UID 1002 can connect to `session.sock`.
UID 1000 has neither the group nor a mount that shows the path.

The proxy creates `session.sock` as UID 1001 (a non-root process cannot give a file to another
user), so the owner is 1001, not 1002. The group is what matters for the connect check.

`bind_session_socket` changes its mode from `0666` to `0660`.

## Agent-runtime socket operations

Transport: HTTP/1.1 with JSON bodies over `/run/auth-proxy-agent/runtime.sock`. The agent sends no
identity and no token. The runtime serves one identity, set by its `--identity` argument. Any path
or method not listed below returns `404 unknown_operation`, including `/v1/hello`,
`/v1/hello/challenge` and every session-plane path of the proxy. A listed path with the wrong method
returns `405 method_not_allowed`. Bodies are capped at 1 MiB (`413 body_too_large`).

| Operation | Request | Success | Failure codes |
|---|---|---|---|
| register | `POST /v1/session`, body `{"session", "generation", "credentials"}` | `201 {"surrogate": "aps_<64 lowercase hex>"}` | `400 invalid_body`; `400 invalid_field` (adds `"field"`); `403 credential_not_granted`; `403 session_expired`; `409 conflict`; `409 revoke_pending`; `429 too_many_sessions`; `503 broker_unavailable` |
| revoke | `DELETE /v1/session/{session}/{generation}` | `204`. Also `204` when the runtime does not track the key. | `400 invalid_field`; `503 broker_unavailable` |
| status | `GET /v1/status` | `200 {"identity", "authority": "live", "sessions": [{"session", "generation"}]}` | none beyond `404` and `405` |

Rules the codes depend on:

- **register** generates the surrogate with `ap_client::surrogate::new_surrogate()`, so its form is
  `aps_` plus 64 hex, the form the proxy's agent path already checks. The runtime sends only the
  digest to the proxy. The identity is always the runtime's own.
- The proxy's refusal codes pass through unchanged (`conflict`, `too_many_sessions`,
  `session_expired`, `credential_not_granted`). `revoke_pending` is new: an earlier revoke of the
  same key is still unconfirmed by the proxy.
- The runtime does not return a lease. It renews the lease itself, so the agent never needs it.
- The runtime binds `runtime.sock` only after `hello` succeeds. A failed `hello` exits the process.
  So the socket never answers before authority exists, and there is no `no_authority` code.
- `status.authority` is `"live"` while the socket serves.
- **revoke** contacts the proxy only for keys the runtime registered. An unknown key returns `204`
  and changes nothing, so the agent cannot end sessions the runtime did not create.
- `session` and `generation` are checked with the proxy's rules (`validate_session`, u64) before
  any proxy call. A bad value returns `400 invalid_field` and names the field.
- A proxy `503` or a connection failure maps to `503 broker_unavailable`.

## Hello proof

### Key material

- The runtime holds an Ed25519 seed: 32 bytes, standard base64 text, in the Secret
  `auth-proxy-runtime-key`, key `runtime_ed25519.seed`. The runtime container mounts it read-only
  at `/var/run/auth-proxy-runtime/runtime_ed25519.seed`, mode `0444`. No other container mounts the
  Secret, and the validator enforces that.
- The proxy holds only the public key: `runtime_pubkey` (standard base64, 32 bytes) on each
  `[[identity]]`. It is not a secret. A malformed key makes the proxy refuse to start.
- Ed25519 rather than HMAC: an HMAC proxy would hold the same secret as the runtime, and the
  proof Secret is meant to exist in the runtime alone.

### Challenge and hello

1. `GET /v1/hello/challenge` returns `200 {"nonce": "<64 lowercase hex>", "ttl_secs": 30}`. The
   proxy draws 32 bytes from the OS RNG. Nonces live in memory only, at most 64 are outstanding,
   and the oldest is evicted first. Each nonce works once. This call writes one audit line with op
   `hello_challenge` and no nonce value.
2. `POST /v1/hello` with body `{"identity", "nonce", "proof"}`. `nonce` and `proof` are optional on
   the wire, and `deny_unknown_fields` applies. `proof` is the standard base64 of a 64-byte Ed25519
   signature. Success returns `201 {"authority_token", "lease_secs"}`, as today.

The signed message is the bytes:

```
"auth-proxy hello v1\n" || u32_be(len(identity)) || identity || "\n" || nonce
```

`nonce` is the 64-character hex string as sent. The length prefix keeps the message unambiguous for
any identity string.

### Verification order

The first failing step returns, and nothing after it runs.

| # | Check | Failure (status, code) |
|---|---|---|
| 1 | Body parses. Wrong types, unknown fields, or a present `nonce` that is not 64 lowercase hex. | `400 invalid_body` |
| 2 | `identity` is in the config. | `400 identity_unknown` |
| 3 | The identity has a `runtime_pubkey`. This fails closed. | `403 runtime_key_missing` |
| 4 | `proof` is present. A body with only `{identity}` stops here. This is the lease-lapse attacker case. | `401 proof_missing` |
| 5 | `nonce` is present and the nonce table has it, unexpired and unused. The entry is removed on lookup. A missing `nonce` with a present `proof` lands here. | `401 nonce_invalid` |
| 6 | `proof` decodes to 64 bytes and `verify_strict` accepts it over the signed message. | `401 proof_invalid` |
| 7 | The lease check, unchanged. A live lease returns `409 authority_active` with `retry_after`. A store failure returns `503 broker_unavailable`. | as before |

A refusal before step 5 leaves the nonce unused, so the next attempt with the right proof succeeds.
Hello writes one audit line with the identity and the result code. The line never holds the proof,
the nonce or the token.

The runtime signs with the seed it loaded at startup. The shim exits non-zero when hello fails, and
the restart policy retries it.

## Failure codes

| Layer | Status and code | When |
|---|---|---|
| hello | `400 invalid_body` | body shape, or nonce not 64 lowercase hex |
| hello | `400 identity_unknown` | identity not in the config |
| hello | `403 runtime_key_missing` | identity has no `runtime_pubkey` |
| hello | `401 proof_missing` | no `proof` field |
| hello | `401 nonce_invalid` | nonce unknown, expired or already used |
| hello | `401 proof_invalid` | wrong signature, or proof not 64 bytes after decode |
| hello | `409 authority_active` | proof valid, lease still live |
| hello | `503 broker_unavailable` | store or lock failure |
| agent-runtime | `404 unknown_operation`, `405 method_not_allowed` | path or method not in the table |
| agent-runtime | `400 invalid_body`, `400 invalid_field`, `413 body_too_large` | request shape or size |
| agent-runtime | `403 credential_not_granted`, `403 session_expired`, `409 conflict`, `409 revoke_pending`, `429 too_many_sessions` | proxy result, passed through |
| agent-runtime | `503 broker_unavailable` | proxy unreachable or failing |

## Netinit rules per UID

The init container still runs as root with `NET_ADMIN` only. It flushes `OUTPUT` and installs the
rules for `iptables` and `ip6tables`:

| UID | Rules |
|---|---|
| 1000 (agent) | Unchanged: accept ESTABLISHED, allow loopback to `PROXY_PORT` and `EGRESS_PORT`, reject other listed loopback ports, reject other loopback, reject all non-loopback output. |
| 1001 (proxy) | None (unchanged). |
| 1002 (runtime) | Accept ESTABLISHED. Reject all other output. The runtime needs no network: `session.sock` and `runtime.sock` are Unix sockets, which netfilter does not see. |
| 1003 (egress) | None (unchanged). |

The runtime gets no rule for the proxy listener. Its session plane is a Unix socket, so a rule
would only widen its network reach. `netinit.sh` takes `RUNTIME_UID` (default 1002), rejects a
value equal to `AGENT_UID`, and rejects non-numeric values as before.

## Verification

Unit tests (`ap-core`, `ap-broker`, `ap-proxy`): the signed-message vector; each row of the order
table, including the lease-lapse case (`{identity}` alone is `proof_missing`); a replayed or expired
nonce; identity without `runtime_pubkey`; a refusal that leaves the nonce unused.

Shim tests (`ap-runtime-shim`): register returns an `aps_` surrogate that the proxy accepts; revoke
of an unknown key returns `204` with no proxy call; `POST /v1/hello` and `GET /v1/hello/challenge`
on the agent socket return `404 unknown_operation`; an oversized body returns `413`.

Manifest checks (`validate_manifests.py`): the proof Secret is mounted only into `runtime`;
`session-plane` is not mounted into `agent`; the runtime UID differs from the agent UID; each app
container sets `runAsGroup`.

Pod checks (run after the code): check A has three parts. (i) As UID 1000, `connect` to
`session.sock` fails. The real manifest does not mount the path into the agent, so the expected
error is "no such file". A test-only overlay mounts the volume at a probe path and expects
"permission denied", which shows the mode bits work alone. (ii) As UID 1000, `hello` and the
challenge on `runtime.sock` return `404 unknown_operation`. (iii) As UID 1000, a lease-lapse attempt
is refused and never reaches the proxy.

## Compatibility

- The hello body changes. `{identity}` alone is refused. `ap-client`, the matrix harness
  (`tests/matrix/harness.py`) and any other authority must send the nonce and proof. The
  openab-pty runtime is outside this repo. Its change has its own plan.
- Proxy and runtime shim ship together. A proxy without the gate accepts any hello. A shim without
  the proof is refused by a gated proxy.
- The 12 h absolute TTL, resync `expired` and the expiry store are unchanged.

## Not in this note

- The openab-pty runtime split. Its runtime serves `runtime.sock` itself.
- ECS. The proof and the agent-runtime socket are Kubernetes-only, as the session plane is.
- Rate limits on the challenge route. The nonce table is bounded, and a rate limit is deferred.
