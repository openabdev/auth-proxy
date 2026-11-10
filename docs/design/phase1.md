# auth-proxy Phase 1 design

- **Status:** Q1, Q2 and Q3 are decided (Q1-B, Q2-A for Kubernetes only, Q3-A with egress
  Q3-E2). Each question section records who decided it and the conditions attached. The ECS
  (Option C) parts are **deferred to a later phase, not rejected**; sections that describe them
  are marked. Everything else in this document follows from decisions already made or is proposed
  for review with the doc.
- **RFC:** openabdev/auth-proxy#1 (including "Placement and egress enforcement" and the Phase 0
  results comment).
- **Evidence:** branch `spike/phase0`: `spike/exp1/` (CLI surrogate probes), `spike/exp2/`
  (proxy bake-off and the 25-case fail-closed matrix, raw output in `spike/exp2/results/`),
  `spike/k3s-egress-a/` (Option A on a single-node k3s test cluster with kube-router, raw output
  in `spike/k3s-egress-a/results/`, findings F1 to F3).
- **Related:** openabdev/octobroker (GitHub brokering), openabdev/openab-pty#47 (egress
  allowlist) and #93 (credential discussion), openabdev/openab (`crates/openab-core/src/acp/`).

## How claims are labelled

Every factual claim carries one of two tags.

- **[M]** measured: we ran it. The tag names the evidence, e.g. `[M exp1]`, `[M exp2 R3]`,
  `[M k3s 7]` (test 7 of the k3s egress validation), `[M k3s F1]`.
- **[I]** inferred: from documentation, from reading source code, or from reasoning, and not run.
  `[I src: <file>]` means read from source in a sibling repo.

Statements of the form "Phase 1 does X" are design proposals and carry no tag.

## 1. Overview

Phase 1 turns the Phase 0 spike into a component that openab-pty (on Kubernetes) and openab (on
ECS Fargate) can run in production for bearer-shaped credentials. The agent gets a base URL on
loopback and an opaque surrogate. The proxy, running in its own trust domain, checks the caller
key, canonicalizes the request, checks policy, looks up the surrogate, applies exactly one real
credential and forwards over verified TLS. The spike already showed that this works with all
five CLIs in base-URL mode [M exp1] and that a minimal Rust proxy passes the 25-case fail-closed
matrix on its first run [M exp2]. What Phase 1 adds is the part the spike stubbed with a mock
broker: who mints the identities and surrogates and how they are bound to one session (Q1),
where the broker and the credential store live (Q2), and what the policy looks like and how it
fits with the egress allowlist that openab-pty#47 asks for (Q3).

```
 Kubernetes pod (Option A)                                                    upstream
 ┌────────────────────────────────────────────────────────────────────────┐
 │ agent container, uid 1000                proxy container, uid 1001     │
 │ ┌──────────────────────────────┐         ┌───────────────────────────┐ │
 │ │ session authority            │ session │ auth-proxy                │ │
 │ │ (openab-pty runtime)         │──plane──► session registry         │ │
 │ │   │ spawns                   │  (UDS)  │ policy · canonicalize     │ │ TLS
 │ │   ▼                          │         │ in-process broker ────────┼─┼──► model API
 │ │ CLI: base URL 127.0.0.1:P    │──TCP P──► credential store (Secret, │ │
 │ │      env: surrogate only     │         │   proxy mount only)       │ │
 │ │                              │──TCP E──► ap-egress (allowlist)     ├─┼──► git, registries
 │ └──────────────────────────────┘         └───────────────────────────┘ │
 │ init: netinit (NET_ADMIN) installs the per-UID rule set                │
 └────────────────────────────────────────────────────────────────────────┘
```

The diagram shows the decided options (Q1-B, Q2-A, Q3-A with egress Q3-E2). On ECS (Option C)
the proxy is a separate service and the session authority is the openab process; section Q2
covers the mapping. The ECS rollout is deferred out of Phase 1 (Q2 decision), so Phase 1 ships
the Kubernetes shape only.

## 2. Fixed inputs

These are decided and are not reopened here.

| Decision | Source |
|---|---|
| Proxy base is A: a minimal Rust reverse proxy on the octobroker stack (axum/hyper, reqwest/rustls) | Phase 0 decision; [M exp2]: 25/25 first run, +0.34 ms p50, 2.8 MB RSS idle |
| Phase 2 (CONNECT plus TLS interception) is deferred | Phase 0 decision; [M exp1]: no CLI needs it |
| openab-pty on Kubernetes uses Option A: proxy sidecar plus per-UID iptables, loopback base URL written by the platform at session start | RFC #1 "Placement and egress enforcement" |
| openab on ECS Fargate uses Option C: proxy as a separate service, security groups | same |
| F1: the proxy sidecar binds nothing on loopback except its listener. Broker client and any admin endpoint use a Unix socket in a volume only the proxy can read | [M k3s F1]: with "agent may use only `lo`", the agent called the sidecar's broker port and got the real credential back |
| DNS stays blocked for the agent UID | [M k3s 2]: UDP `EPERM`, TCP refused, model turns still work |

Measured constraints that shape the options:

- **kiro-cli's endpoint settings are global only** (`~/.kiro/settings/cli.json`; `--workspace`
  is refused) and accept a path prefix and plain `http://` on loopback [M exp1]. kiro-cli has no
  knob for custom request headers [M exp1], so its caller key can only travel in the URL path or
  in the credential slot.
- **Every CLI accepts a path prefix in its base URL** and an opaque surrogate in its credential
  slot, with no prefix or length check [M exp1]. kiro-cli accepted a 1-character key [M exp1].
- **HOME is shared.** openab-pty runs every session in one pod as uid 1000 with one HOME
  [I src: openab-pty `runtime/src/tools.rs`, `CLIENT-CONTRACT.md` §9.3, issue #76]. openab passes
  the real HOME to every agent process [I src: openab `crates/openab-core/src/acp/connection.rs`].
  So one `cli.json` serves every session in a pod, and anything per session must travel in the
  process environment, not in kiro-cli's settings file.
- **A process's environment is fixed at spawn.** A surrogate delivered through env cannot be
  replaced in a running CLI [I]. That collides with the RFC's "TTL ≤ 15 min, renewal means
  minting a new surrogate" for any session longer than 15 minutes (openab-pty's default absolute
  session TTL is 12 h [I src: openab-pty `runtime/src/config.rs`]). Q1 deals with this.
- **Same-UID processes are one trust unit.** Sessions in one openab-pty pod share a UID, and a
  shell in session A can read session B's `/proc/<pid>/environ` [I src: openab-pty
  `runtime/src/tools.rs`, which states this as a non-goal]. Any per-session binding stops
  processes outside the pod and stale sessions, not a hostile neighbour session.
- **openab-pty's userspace overlay-network sidecar forwards inbound connections to every
  loopback port of the pod** [I src: openab-pty `runtime/src/tools.rs`, measured in openab-pty's
  own spike]. The proxy listener on loopback is therefore reachable by overlay peers, and the
  caller key is the barrier against them. The iptables rules only filter the agent UID's
  outbound packets.
- **The openab-pty runtime refuses broker configuration.** Its startup check treats "any
  evidence of an unresolved secret reference or broker config" as fatal [I src: openab-pty
  `DESIGN.md`, startup order]. The runtime can generate random keys and keep hashes (it does so
  for the tools plane), but it must not talk to a credential broker.
- **openab already mints and revokes a per-session token** for its MCP facade through a
  `SessionTokenRegistrar` (mint at `get_or_create`, synchronous revoke on eviction, including hung
  eviction) [I src: openab `crates/openab-core/src/acp/pool.rs`]. That is the integration point
  for openab.

## 3. Vocabulary

| Term | Meaning in this document |
|---|---|
| **Identity** | The unit the policy grants to: one openab-pty pod, or one openab bot. Identified at the proxy by its **caller key**. |
| **Caller key** | `apk_` + 64 lowercase hex. Carried in the base-URL path, `/ap/<caller-key>/<route>/…`. One per identity. The proxy stores only its sha256. |
| **Session** | One openab-pty session generation, or one openab ACP connection (thread key). |
| **Session authority** | The process that knows when a session starts and ends: the openab-pty runtime, or the openab process. It never holds a real credential. |
| **Surrogate** | `aps_` + 64 lowercase hex. Placed in the CLI's credential slot (e.g. `KIRO_API_KEY`). Bound by the proxy to (identity, session, generation, credential ids, lease). The proxy stores only its sha256. |
| **Route** | A named upstream: DNS host, port 443, headers to swap, error dialect. |
| **Credential** | A real secret plus the set of routes it may be applied to. kiro-cli needs one credential across 3 to 4 routes [M exp2]. |
| **Session plane** | The channel the session authority uses to register, renew and revoke sessions. A Unix socket on Kubernetes, HTTPS on ECS. |
| **Store** | Where real credential values come from (K8s Secret file, AWS Secrets Manager, ...). |

---

## Q1. Who mints the caller key, and how does it bind to one session or one agent process?

**Decision:** Q1-B, decided by the owner. Both council members recommended Q1-B (medium risk,
reversible) and escalated it, because it amends the RFC's credential-lifetime rule. The owner
accepted the amendment: the session authority renews a surrogate's lease up to the session's
absolute TTL (12 h default) instead of a new surrogate being minted every 15 minutes or less.
Q1-B is the only option that gives per-session revocation while kiro-cli's settings are global and
HOME is shared, and the runtime sends only hashes, so it never talks to a broker. These conditions
are binding for Phase 1:

1. A test covers the `hello` race after an authority container restart: the 90 s authority lock
   holds, and only the fresh runtime process (PID 1) can win `hello`, never an orphaned
   agent-UID process.
2. No audit or access log contains the `/ap/<caller-key>` prefix.
3. The documentation states that audit attribution between sessions of the same UID is best
   effort, because a same-UID neighbour can read and spend another session's surrogate.

The question covers four things: who mints, lifetime, delivery to the agent, and revocation when
the session ends, plus whether the key rides in the base-URL path.

### Q1-A. One identity per pod or bot, minted by the proxy, file handoff

The proxy mints one caller key and one surrogate when it first starts, keeps them in a
proxy-private volume, and hands both to the agent side through a shared `emptyDir` the agent
mounts read-only. This is the spike's shape: the k3s validation used exactly this handoff, and a
proxy restart kept the caller key and minted a new surrogate [M k3s 8b]. The startup hook writes
the base URLs (with the caller key in the path) into `cli.json` once, and the runtime forwards the
surrogate into every session as `KIRO_API_KEY`. On ECS the same pair is generated by the operator
and stored in Secrets Manager for the bot.

- **Lifetime:** the pod or task. The surrogate is long-lived.
- **Revocation:** pod deletion, or an operator command on the proxy's admin socket. There is no
  per-session revocation.
- **Key in the path:** yes, and it can be, because the key is the same for every session.

### Q1-B. Per-identity caller key in the path, per-session surrogate registered by the session authority (recommended)

The caller key stays per identity and rides in the path, written once into shared config, as in
Q1-A. The per-session secret is the surrogate, and the session authority creates it:

1. At startup the session authority opens the session plane. openab-pty: the runtime sends
   `hello` over the session-plane Unix socket before it binds its listeners, gets an authority
   token back, and keeps it only in memory (the runtime sets `PR_SET_DUMPABLE=0` before handling
   any secret [I src: openab-pty `runtime/src/containment.rs`]). The proxy stores the token's
   hash in its private volume, so it survives a proxy restart, and refuses another `hello` while
   the current authority is live. The authority has its own short lease (renewed every 30 s,
   lapses after 90 s); when it lapses, the proxy revokes every session the authority registered
   and accepts a new `hello`. In openab-pty the runtime is the container's PID 1, so a dead
   runtime means its shells are gone too, and the next `hello` can only come from the restarted
   runtime, which sends it before any session exists [I]. openab on ECS: no `hello`; the
   authority token is configured, with its hash in the proxy's config.
2. At session spawn the authority generates a random surrogate, keeps it only to put it in the
   child's environment, and registers `sha256(surrogate)` with (session id, generation, credential
   ids). The proxy answers with the lease length.
3. The authority renews itself and all its live sessions in one call every 30 s.
4. At session end (exit, kill, restart, absolute TTL, openab eviction including hung eviction) the
   authority revokes the session synchronously. openab already does this for its facade token at
   the same call sites [I src: openab `pool.rs`].
5. If the proxy restarts, its next `renew` answer lists every session as unknown, and the
   authority re-sends its full list of live sessions (`PUT /v1/sessions`). Requests in the gap
   (at most one authority renew interval, 30 s) are refused with `surrogate_unknown`. After the
   resync the same surrogates work again, because the proxy only ever stored hashes and the CLIs
   still hold the surrogates in their environment. This is why the authority generates the
   surrogate: a proxy-generated surrogate would be lost on a proxy restart, and the new one could
   not reach a running CLI [I].

- **Lifetime:** the session. Each session has a lease of 15 min from its last renewal, which ends
  a session the authority stopped renewing; the authority's own 90 s lease ends all its sessions at
  once if the authority disappears; the session's absolute TTL caps both. This replaces the RFC's
  "TTL ≤ 15 min, renewal mints a new surrogate" for env-delivered surrogates, because env cannot
  change in a running process [I]. Renewal is an explicit call from the authority, never a side
  effect of use, so "surrogates are never silently extended" still holds. **This is an RFC
  amendment; the owner accepted it (see the Q1 decision).**
- **Delivery:** the surrogate goes into the child env under the CLI's credential variable
  (`KIRO_API_KEY`, `ANTHROPIC_API_KEY`, ...), named in the platform config. openab-pty: a new
  runtime feature next to `OPENAB_TOOLS_MCP_TOKEN`. openab: `pool.rs` adds the variable per spawn,
  alongside `[agent].env`. Base URLs (`/ap/<caller-key>/<route>`) are session-independent and go
  into the shared CLI config.
- **Revocation:** synchronous at session end, plus lease lapse when the authority dies. A process
  that outlives its session (openab-pty's teardown is best effort [I src: openab-pty
  `DESIGN.md`]) is refused on its next request.

What it does not stop: a session in the same pod reading a neighbour's surrogate from
`/proc/<pid>/environ` and spending it, which also spoofs the audit attribution. On ECS the agent
can also reach the openab task role and therefore the authority token if it lives in Secrets
Manager under that role [I]. In both cases the attacker can register or use surrogates only
inside the identity's own grants: the real credential never leaves the proxy. Per-session
binding is exact against a well-behaved agent and against processes outside the identity,
and best effort against a hostile process inside it. The RFC already scopes the guarantee to
"agent identities, not processes".

### Q1-C. Per-session caller key in the path, surrogate minted by the broker through the admin plane

This is the RFC's original sketch: an admin-plane mint at session creation. The operator
(Connect, Remote, or a control plane) asks the broker for a caller key and a surrogate for session
S, then passes them to `POST /admin/sessions` so the runtime puts them in the child env, the way
`§9.1 tools-attach` hands a secret out of band [I src: openab-pty `CLIENT-CONTRACT.md` §9.1].

- **Key in the path:** only if every session has its own CLI config. kiro-cli's settings are
  global [M exp1], so each session would need its own HOME (a throwaway HOME works for kiro-cli
  [M exp1]), which splits the user's workspace state across sessions.
- **Lifetime and revocation:** per session, strong. The operator owns re-minting, but cannot
  update the env of a running CLI, so it has the same TTL problem as Q1-B without the lease.
- **Cost:** the operator client needs broker access, and the runtime's admin API has to accept
  injected env, which its "no broker config" rule pushes against [I src: openab-pty `DESIGN.md`].

### Q1 trade-offs

| | Q1-A pod/bot identity | Q1-B registered per-session surrogate | Q1-C admin-plane mint |
|---|---|---|---|
| **Security** | One surrogate for the pod. No per-session revocation; a lingering process keeps working until the pod ends. Caller key still blocks overlay peers | Per-session revocation and lease. Real credential stays in the proxy. Same-UID neighbours can still spend each other's surrogates [I] | Strongest on paper: per-session key and surrogate. Same same-UID caveat. Operator gains broker access, which widens who can mint |
| **Operability** | Nothing to run beyond the sidecar. Audit shows only the pod | Audit per session. Proxy restart costs up to 30 s of refusals, then resync. Authority restart waits up to the 90 s authority lease for the `hello` lock [I] | Every session start depends on the operator and the broker being reachable |
| **Effort** | Small: the spike already did it [M k3s 8b] | Medium: session-plane protocol (5 calls), runtime env feature, openab registrar | Large: per-session HOME, admin API change in openab-pty, operator-side broker client |
| **Reversibility** | Easy to move to Q1-B later: Q1-A is Q1-B with one session that lives as long as the pod | Can fall back to Q1-A by registering one long-lived session | Hard: per-session HOME changes the user-visible workspace layout |

### Q1 recommendation: Q1-B

Q1-B is the only option that gives per-session revocation without changing kiro-cli's global
settings or HOME, and it keeps the openab-pty rule that the runtime never talks to a broker: the
runtime talks only to the proxy's session plane, sends hashes, and holds no real credential. It
reuses patterns both platforms already ship (openab-pty's hash-only tools key, openab's
mint/revoke registrar). Ship Q1-A's handoff as the fallback mode for images whose runtime does not
yet speak the session plane: the proxy then registers one session for the pod itself.

Caller key in the path: **yes, per identity.** It is what separates identities at a shared proxy
(matrix X1 [M exp2]) and what stops overlay peers that reach the loopback listener [I src:
openab-pty]. It is not the per-session secret. Logs must never contain the path prefix; the
audit line records the route-relative path only, as in the spike [M exp2 X5].

### Session-plane protocol (for Q1-B)

HTTP/1.1 with JSON bodies. On Kubernetes over the Unix socket `/run/auth-proxy/session.sock`
(mounted into the agent container, see Q2 for why this is not the admin socket). On ECS over HTTPS
on the proxy service. Every call except `hello` carries `Authorization: Bearer <authority-token>`.

| Call | Body | Success | Failure |
|---|---|---|---|
| `POST /v1/hello` (Kubernetes only) | `{}` | `201 {authority_token, lease_secs}` | `409 authority_active` while the current authority's lease is live |
| `POST /v1/sessions` | `{session, generation, surrogate_sha256, credentials: [id]}` | `201 {lease_secs}` | `401` bad token; `400` invalid field; `403 credential_not_granted`; `409` same session and generation already registered with another hash; `429` over `max_sessions` |
| `POST /v1/renew` | `{sessions: [{session, generation}]}` | `200 {lease_secs, unknown: [...]}` | `401` |
| `DELETE /v1/sessions/{session}/{generation}` | none | `204` (also when unknown) | `401` |
| `PUT /v1/sessions` (resync) | full list as in `POST` | `200 {registered, dropped}`; sessions not in the list are revoked | `401`, `400` (whole request rejected, nothing applied) |

Validation, all fail with `400` and change nothing: `session` 1 to 128 characters of
`[A-Za-z0-9._:-]` (fits openab-pty names and openab thread keys); `generation` a u64;
`surrogate_sha256` exactly 64 lowercase hex; `credentials` 1 to 16 ids, each defined in the
config and granted to the identity, else `403`. Bodies over 1 MiB are refused with `413`. A
resync list is validated in full before anything is applied, so a partly bad list registers
nothing and the response says which entry failed. Every call writes an audit line with the session
id, generation, a short hash prefix and the result, never the surrogate.

---

## Q2. Broker placement and store backend

**Decision:** Q2-A for Kubernetes (store S1) only in Phase 1, decided by the owner. Both council
members recommended Q2-A (reversible; one rated risk low, the other medium) and escalated it,
because the ECS mapping spends recurring money on one on-demand proxy service per bot, changes
IAM, secrets and execution roles on production bots, and needs the S2 cache bound as an exception
to the RFC's "never cached" rule. The owner chose to ship the Kubernetes shape now: the broker
runs inside the proxy process and reads a Secret file mounted only into the proxy. Q2-A keeps one
credential holder and meets F1 by construction, because no broker endpoint exists.

The ECS rollout is **deferred to a later phase, not rejected**. Deferred: the S2 Secrets Manager
store, the per-bot proxy services and `ap-relay`, the IAM, Secrets Manager and execution-role
changes, and the S2 cache bound (refresh 300 s, max age 900 s). Because S2 is deferred, the RFC's
"never cached" wording stays unchanged in Phase 1. Sections below that describe S2 or ECS are kept
as the design for that later phase and are marked deferred.

The broker answers "is this surrogate live, and what real credential does it map to". Phase 0
fixed that the proxy never caches that answer: with the broker stopped, a surrogate that worked a
moment earlier is refused [M exp2 R2]. So broker availability is proxy availability, and the
placement decides both the failure domain and how many processes hold the real credential.

### Q2-A. Broker in the proxy process (recommended)

The session registry and the store reader are modules of the proxy binary. There is no broker
listener and no broker client on the network.

- **F1:** satisfied by construction. The agent cannot call a resolve endpoint because none exists.
  The proxy binds one TCP listener for the agent (its loopback port), plus two Unix sockets: the
  session plane, which the agent container must reach and which exposes only the calls in the
  table above, and the admin socket, in a volume mounted only into the proxy container. Neither
  socket has a call that returns a credential.
- **Availability:** the broker fails with the proxy and never separately. A credential store
  outage affects only what the store reader can refresh (below).
- **Credential holders:** one process per identity. The spike counted this as A's advantage over
  B [M exp2]. The real credential stays in memory in the auth-proxy trust domain for the life of
  the process, which is already true of the Secret file mounted into the proxy container
  [M k3s 5d, 6]. The RFC sentence "the proxy holds decrypted material only for the duration of a
  request" should read "only inside the auth-proxy trust domain".
- **Blast radius:** one identity's credentials per proxy instance.
- **Central operations:** rotation is a store update that every proxy picks up (below). Revocation
  of a session goes through its session authority. An operator-wide "revoke everything for
  identity X" is deleting the pod, or a call on that pod's admin socket.

### Q2-B. Separate in-cluster broker service

A Deployment in its own namespace (at least 2 replicas), holding every identity's credentials.
Each sidecar calls it per request over mTLS.

- **F1:** the sidecar only dials out, so it binds nothing new on loopback, and the agent UID cannot
  reach the broker because all its non-loopback traffic is rejected [M k3s 2].
- **Availability:** one broker outage refuses every agent in the cluster. The registry has to be
  shared across replicas (a database or signed surrogates plus a revocation list), which is new
  stateful infrastructure. Each request pays a network round trip; the spike measured 0.20 ms on
  loopback [M exp2], and an in-cluster hop is more [I].
- **Credential holders:** two processes per request, broker and sidecar, with the credential on
  the wire between them. This is the property B lost in the bake-off [M exp2].
- **Gains:** sidecars mount no Secret; rotation, revocation and audit are in one place.

### Q2-C. Shared with octobroker

octobroker gains a `resolve` endpoint and becomes the store for non-GitHub credentials, reusing
its per-agent keys, secret references (`env:`, `aws:secretsmanager:`, `k8s:`) and audit
[I src: octobroker `config.example.toml`, `docs/DESIGN.md`].

- **Availability:** coupled to octobroker, which runs as a single replica while MCP is enabled,
  because its MCP session pins are in process memory [I src: octobroker `docs/DESIGN.md`].
- **Blast radius:** the GitHub App private key and every model credential in one process.
- **Effort:** low for the store (it exists), high for the coupling: octobroker's release cadence
  and risk profile would gate every agent's model access.

### Store backends

| Backend | Read path | Rotation | Fit |
|---|---|---|---|
| **S1. File** (K8s Secret volume mounted only into the proxy; also Vault Agent or the Secrets Store CSI driver, which render files [I]) | `stat` on every request, re-read when mtime or size changes (the spike's policy-store logic [M exp2 R1]). Missing or unreadable file means `broker_unavailable` | Kubelet replaces Secret volume contents with an atomic symlink swap [I], so the switch is atomic and needs no restart | Kubernetes. Mount rules from the k3s validation: `defaultMode: 0444` on a volume mounted only into the proxy, no `fsGroup` [M k3s] |
| **S2. AWS Secrets Manager** (deferred with the ECS rollout) | Fetched with the proxy's own task role, held in memory, refreshed every `refresh_secs` (default 300). A failed refresh keeps the value until `max_age_secs` (default 900), then requests are refused with `broker_unavailable` | Rotation shows up within one refresh | ECS. The agent's task role gets no access to these secrets |
| **S3. Vault (native client)** | Token auth and lease renewal in the proxy | Vault leases | No consumer yet; S1 through Vault Agent covers it without code [I] |

The "never cached" rule applies to the binding decision (is this surrogate live, for this
identity, on this route): the registry is consulted on every request and revocation takes effect
on the next request. S1 also re-checks the credential value on every request. S2 cannot call
Secrets Manager per request (latency and API quotas [I]), so it holds the value for a bounded
time and fails closed after `max_age_secs`. That bound would be a deliberate exception to the
RFC; it is deferred with S2 and needs owner approval when the ECS rollout is taken up.

### Mapping onto ECS (Option C), deferred to a later phase

Not part of Phase 1 (Q2 decision). Kept as the starting design for the ECS rollout.

- The proxy runs as its own ECS service with the broker in process (Q2-A) and S2 as the store.
  Phase 1 runs **one proxy service per bot**, on on-demand capacity instead of Spot, so one bot's
  proxy holds one bot's credentials. A shared multi-identity service is the later scale-out path:
  X1 already separates identities by caller key [M exp2], but it widens the blast radius.
- Security groups: the openab task's group may reach the proxy service on 443. Only the proxy's
  group reaches the model APIs. openab itself shares the task's network with its agent process,
  so the task group still has to allow openab's chat-platform endpoints, which the agent can also
  reach [I]. Option C enforces "model credentials only through the proxy", not a full egress deny.
- Session plane: HTTPS on the proxy service, authority token per bot. The token's hash is in the
  proxy config. openab loads the token from Secrets Manager into memory at boot (openab's
  `aws-sm://` references [I src: openab `docs/adr/secrets-management.md`]) and never into env.
- Base URL: CLIs were verified with loopback `http://` only; whether each accepts a non-loopback
  `http://` URL, or a private CA on `https://`, is not verified (RFC #1 notes). Phase 1 therefore
  puts a small relay (`ap-relay`, no credentials, loopback TCP in, TLS to the proxy service out)
  in the openab container, so the base URL stays `http://127.0.0.1:<port>/ap/<caller-key>/<route>`
  on both platforms and the caller key is encrypted on the VPC network [I]. The relay is not a
  security boundary: the agent may bypass it and talk to the proxy service directly, and still
  needs both keys.
- Admin socket: a Unix socket inside the proxy task, reached with ECS exec.
- Availability: a proxy task restart refuses requests until the replacement is healthy, then
  openab's resync restores every live session. Two replicas with fan-out registration (openab
  registers each session with every replica) is backlog.

### Q2 trade-offs

| | Q2-A in-process | Q2-B central broker | Q2-C octobroker |
|---|---|---|---|
| **Security** | No resolve endpoint anywhere; one process holds the credential; blast radius one identity | Credential crosses the network per request; two holders; blast radius the cluster | One process holds GitHub App key and model keys |
| **Operability** | Nothing extra to run; rotation through the store; per-pod audit to stdout | One more HA service plus shared registry state; central audit | One fewer service, but octobroker becomes the availability bottleneck |
| **Effort** | Smallest: registry plus file and SM readers | Large: HA, shared state, mTLS | Medium in code, high in coupling |
| **Reversibility** | The registry and store reader sit behind one trait; moving them behind a network call later is a new implementation of that trait | Hard to undo once sidecars mount no Secret and depend on the service | Hard to separate later |

### Q2 recommendation: Q2-A with S1 (Kubernetes) and S2 (ECS)

Decided as Q2-A with S1 for Phase 1; the S2 and ECS half of this recommendation is deferred.

Q2-A keeps the properties that decided the bake-off (one holder of the credential, explicit
refusal codes, no extra process) and meets F1 without a rule to maintain, because no broker
endpoint exists. Share code with octobroker at the crate level instead of the service level:
adopt octobroker's secret-reference syntax (`env:`, `k8s:`, `aws:secretsmanager:`) so operators
write the same strings in both, and treat octobroker as an upstream route (Q3) instead of a store.
Vault stays in the backlog behind S1.

---

## Q3. Policy format, location, and composition with openab-pty#47

**Decision:** Q3-A with egress Q3-E2, decided by the council. Both members chose it independently,
rated it low risk and reversible, and did not escalate. One validated TOML file per identity lets
the loader cross-check routes, grants and egress, extends the spike's measured policy store, and
fails closed with `policy_unavailable`. Q3-E2 keeps non-credential traffic out of the credential
process, never terminates TLS, needs no privilege after the init container, and is easy to remove.
Follow-ups attached to the decision:

- `ap-egress` connects to the exact address it validated and never resolves the name a second
  time (DNS rebinding).
- The platform sets `NO_PROXY=127.0.0.1,localhost` next to `HTTPS_PROXY`.
- A test confirms that kiro-cli sends `X-Amz-Target` before any grant relies on `aws_targets`.
- The combined Option A rule set is measured in one pod before release.

Remaining risk, accepted: the agent can still send data to allowlisted hosts such as github.com,
and tools that ignore the proxy variables fail slowly.

Policy has to express host + method + path or resource, and a credential bound to a set of routes
(kiro-cli uses one key for 3 hosts, plus `api.q.service` [M exp1, exp2]). It also has to say how
traffic that carries no credential (git, npm, pip, cargo) leaves the pod, because under the
Option A deny all of those fail at DNS: git and curl at once, pip after 7.9 s, cargo after 11.0 s,
npm after 70.7 s [M k3s 7].

### What path rules cannot express

kiro-cli's calls all arrive as `POST /` on their route: the k3s audit shows `cps` and `krs`
requests with path `/` [M k3s 1a]. The operation (`GetProfile`, `ListAvailableModels`,
`GenerateAssistantResponse`, `SendTelemetryEvent` [M exp1]) is presumably named in the
`X-Amz-Target` header of the AWS JSON protocol [I]. A path-prefix rule can therefore only say
"anything on this route". Phase 1 adds an `aws_targets` matcher, an exact list of operation names
compared against the single `X-Amz-Target` value (zero or two headers means deny), and the first
Phase 1 test confirms the header with kiro-cli.

Policy format options are Q3-A to Q3-C; the egress options for non-credential traffic are
Q3-E1 to Q3-E3.

### Q3-A. One TOML file per identity, validated as a whole (recommended)

The file holds routes, credentials and their route sets, the identity's caller-key hash, grants,
and the egress allowlist. It is loaded, validated completely, compiled into an immutable snapshot
and swapped atomically. Any failure (missing file, 0 bytes, parse error, failed validation) refuses
every request with `policy_unavailable`, and a good snapshot is never kept after the file goes bad,
as in the spike [M exp2 R1]. Location: a ConfigMap mounted only into the proxy container on
Kubernetes; a Secrets Manager value (it holds hashes and references, no secret values) on ECS,
re-fetched with S2's refresh and max-age rules.

### Q3-B. Split files

Routes and credentials in config, grants in a hot-reloaded policy file, the egress allowlist in its
own file owned by openab-pty#47. This is the spike's split (`config.json` plus `policy.json`)
[M exp2] extended with a third file. Each owner edits its own file, but nothing can check one file
against another (for example that a credential route host is not also in the egress allowlist), and
three files can drift.

### Q3-C. Kubernetes CRDs

CRDs (`AuthProxyRoute`, `AuthProxyGrant`, `EgressAllowlist`) reconciled by an operator into each
sidecar's file. Native to cluster tooling and RBAC, but adds an operator, a controller's
availability, and has no ECS equivalent.

### Q3-A file sketch and validation

```toml
version = 1
identity = "pty-team-a"                  # audit name
caller_key_sha256 = "<64 hex>"

[[route]]
name = "kiro-krs"
host = "runtime.us-east-1.kiro.dev"      # lowercase DNS name, no IP literal/userinfo/port/trailing dot
error_shape = "aws"                      # kiro-cli shows AWS-shaped bodies verbatim [M exp1]
surrogate_header = "authorization"       # scheme "Bearer"
credential_header = "authorization"
pass_headers = ["tokentype"]             # must pass through, else 400 "profileArn is required" [M exp1]
# ... kiro-cps, kiro-cw, kiro-q

[[credential]]
id = "kiro"
source = "k8s:auth-proxy-kiro:api_key"   # octobroker reference syntax; aws:secretsmanager:... on ECS
routes = ["kiro-cps", "kiro-krs", "kiro-cw", "kiro-q"]

[[grant]]
credential = "kiro"
route = "kiro-krs"
methods = ["POST"]
paths = ["/"]                            # exact "/" or prefixes ending in "/"
aws_targets = ["AmazonCodeWhispererStreamingService.GenerateAssistantResponse"]

[egress]                                 # read by ap-egress only (see below)
allow = ["github.com:443", "registry.npmjs.org:443", "pypi.org:443",
         "files.pythonhosted.org:443", "index.crates.io:443", "static.crates.io:443"]
```

Validation, all at load time, any failure makes the whole file unavailable (exit code 2 at
startup, `policy_unavailable` at reload): `version` is 1; unknown keys are errors
(`deny_unknown_fields`, as in the spike); route names unique, `[a-z0-9-]{1,32}`; route hosts pass
the spike's canonical-host check [M exp2 R5]; every credential route exists; every grant names a
credential and one of its routes; methods are upper-case tokens; paths start with `/` and contain
no dot segment, `%` or `//`; at most 256 grants; egress entries are `host:port`, with a canonical
host and a port from 1 to 65535, and no host that is also a credential route host (otherwise a
CONNECT tunnel could carry another credential the agent found straight to a credential host; an
explicit `allow_route_hosts = true` turns the check off).

### Getting git, npm, pip and cargo out under the Option A deny

#### Q3-E1. Through auth-proxy as credential-less reverse-proxy routes

npm `registry`, pip `index-url`, cargo `source.replace-with` and git `url.<base>.insteadOf` all
accept a base URL [I]. Package metadata links to other hosts (PyPI's index links to
`files.pythonhosted.org`, the crates.io index config points downloads at `static.crates.io`, npm
metadata carries tarball URLs [I]), so the proxy would have to rewrite response bodies or the tool
would follow a link it cannot resolve. That turns the credential proxy into a content-rewriting
proxy for formats it does not own, inside the process that holds the credential.

#### Q3-E2. A separate allowlisting CONNECT proxy, `ap-egress` (recommended)

A second small binary in its own container and UID, with no Secret mount and no dependency on the
broker crate. The agent's tools get `HTTPS_PROXY=http://127.0.0.1:<egress-port>` from the
platform; git, npm, pip, cargo and curl honour it [I]. Plain-HTTP proxy requests are refused. `ap-egress` accepts only
`CONNECT host:port` where `host:port` is in the allowlist, resolves the name itself (the proxy UIDs
keep DNS [M k3s 3]), refuses IP literals and names that resolve to loopback, link-local or private
ranges, and then copies bytes. It never terminates TLS, so it never sees or adds a credential. The
agent UID stays without DNS, and a tool that ignores the proxy variables fails, as today [M k3s 7].
Registries that need an auth token (private npm, crates with a token) get a credential route in
auth-proxy later, since an opaque tunnel cannot swap a header.

#### Q3-E3. Name-based allowlisting resolved proxy-side, with a filtering DNS resolver

A sidecar resolver on loopback answers only allowlisted names and adds the returned addresses to an
nft set that the agent UID may connect to. Tools need no proxy variables. But the sidecar needs
`NET_ADMIN` for its whole life instead of only in the init container, the rules depend on DNS TTLs,
and an allowed address on a shared CDN lets the agent reach any other host served from it [I].

**GitHub.** GitHub stays with octobroker, as the RFC says. Under the Option A deny the agent cannot
reach octobroker either, so octobroker becomes an auth-proxy route: its credential is the
identity's `X-Octobroker-Key`, the agent's `obk` gets `OCTOBROKER_URL=http://127.0.0.1:<port>/ap/
<caller-key>/octobroker` and a surrogate in `OCTOBROKER_KEY` [I src: octobroker `obk/src/main.rs`].
The short-lived single-repository token octobroker returns for `git push` is then used through
`ap-egress` to `github.com:443`. Route upstreams must be HTTPS with a verified certificate
[M exp2 R6, R7], so this needs TLS in front of octobroker (it listens on plain HTTP today [I src:
octobroker `src/main.rs`]).

**Composition with #47.** One file, two lists, two enforcers:

- `[[route]]` hosts are reachable only through auth-proxy, with a credential, under grants.
- `[egress].allow` hosts are reachable only through `ap-egress`, with no credential.
- Everything else is unreachable for the agent UID: the iptables rule set rejects it and DNS is
  closed [M k3s 2].

#47's "documented allowlist" becomes the `[egress]` section plus per-CLI defaults shipped as
examples (model API routes; git hosts; npm, PyPI and crates; kiro-cli's embedding model host
`desktop-release.q.<region>.amazonaws.com` if semantic search is wanted [M k3s 4]). A CNI with FQDN
policy (Cilium, Calico) can restrict the proxy containers' own egress pod-wide on top of this; it
cannot replace the per-UID rule, because it applies to the whole pod [I, RFC #1].

Option A rule set with Q3-E2 (`P` = auth-proxy listener, `E` = `ap-egress` listener; repeat with
`ip6tables`):

```
-A OUTPUT -m owner --uid-owner <agent> -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A OUTPUT -o lo -p tcp --dport P -m owner --uid-owner <agent> -j ACCEPT
-A OUTPUT -o lo -p tcp --dport E -m owner --uid-owner <agent> -j ACCEPT
-A OUTPUT -o lo -p tcp --dport <each other sidecar port> -m owner --uid-owner <agent> -j REJECT --reject-with tcp-reset
-A OUTPUT ! -o lo -m owner --uid-owner <agent> -j REJECT
```

The session-plane and admin endpoints are Unix sockets, so they need no port rule. With Q2-A the
proxy binds no other loopback port, so the third line has nothing to list unless a later feature
adds one; config validation refuses any proxy listener on loopback other than `P`. The
`ESTABLISHED` and per-port parts were measured in separate pods [M k3s F1, F2]; the combined set
is [I] until the Phase 1 k8s test runs it in one pod.

### Q3 trade-offs

| | Q3-A one file | Q3-B split files | Q3-C CRDs |
|---|---|---|---|
| **Security** | Cross-checks between routes, grants and egress at load; one atomic snapshot | No cross-file checks; partial updates possible | Same checks as Q3-A if the operator renders one file; adds a controller with write access to sidecar config |
| **Operability** | One artifact per identity, same on Kubernetes and ECS | Three owners, three reload paths | Kubernetes only |
| **Effort** | Small: the spike's loader plus validation | Small | Large |
| **Reversibility** | Q3-B or Q3-C can render this file later | Merging later means migration | Hard to remove once adopted |

| | Q3-E1 reverse-proxy routes | Q3-E2 `ap-egress` CONNECT | Q3-E3 filtering DNS + nft sets |
|---|---|---|---|
| **Security** | Response rewriting inside the credential process | Separate UID, no credential, name checked before connect; agent can still send data to allowed hosts | Long-lived `NET_ADMIN`; shared CDN addresses widen the allowlist |
| **Operability** | Per-tool config plus per-registry rewrite rules | One env pair per session; tools that ignore it fail as today | Transparent to tools |
| **Effort** | Large and open-ended | Small (CONNECT parse, allowlist, copy) | Large |
| **Reversibility** | Hard to back out once tools depend on rewritten URLs | Easy: delete the container and the port rule | Medium |

### Q3 recommendation: Q3-A with Q3-E2

One validated file per identity is the smallest change from the spike's measured policy store and
is the same artifact on both platforms. Q3-E2 keeps the credential process free of non-credential
traffic, needs no privilege beyond the init container that Option A already has, and leaves DNS
closed for the agent.

---

## 4. Phase 1 request pipeline and error contract

With Q1-B, Q2-A and Q3-A the pipeline is the spike's, with the mock broker replaced by the
registry and store reader. Every refusal sends nothing upstream.

1. Refuse `CONNECT` (405) and WebSocket upgrades (501 `websocket_unsupported`, see backlog).
2. Canonicalize: origin-form only, exactly one `Host` equal to a listener authority, no ambiguous
   path (400) [M exp2 R5, X2].
3. Parse `/ap/<caller-key>/<route>/…`; caller key by constant-time sha256 compare (403); route
   lookup (404).
4. Exactly one surrogate in the route's surrogate header, format `aps_<64 hex>` (400 if two, 403 if
   missing or malformed).
5. Registry lookup by `sha256(surrogate)`: unknown, revoked or lease lapsed (403); bound to another
   identity (403); route not in the bound credentials' route sets (403).
6. Policy snapshot: unavailable (503), empty (403), no grant matching method, path and AWS target
   (403).
7. Store read for the credential: unavailable or past `max_age_secs` (503 `broker_unavailable`).
8. Strip auth and hop-by-hop headers, keep `pass_headers`, set exactly one credential header
   [M exp2 R8]; forward over rustls with SNI = Host = route host and the system or configured
   roots [M exp2 R6, R7]; never follow redirects [M exp2 R4]; stream the response chunk by chunk
   with `TCP_NODELAY` on both sides [M exp2: without it p99 rose by 44 ms].
9. Audit one JSON line to stdout: identity, session id, generation, route, method, route-relative
   path, AWS target, decision, code, status, duration. Never the caller key, surrogate, credential
   or query string.

| Code | Status | Body dialect | Logged at | Notes |
|---|---|---|---|---|
| `absolute_form`, `host_rejected`, `path_ambiguous`, `surrogate_ambiguous` | 400 | route's, or JSON if no route | info | |
| `caller_rejected`, `surrogate_missing`, `surrogate_malformed`, `surrogate_unknown`, `surrogate_revoked`, `surrogate_expired`, `surrogate_wrong_caller`, `surrogate_wrong_route`, `policy_empty`, `policy_denied` | **403** | route's | info (warn for `caller_rejected` bursts) | Spike used 401 for surrogate state; Phase 1 uses 403 (backlog item 3) |
| `route_unknown` | 404 | JSON | info | |
| `connect_refused` | 405 | JSON | info | |
| `body_too_large` | 413 | route's | info | |
| `websocket_unsupported` | 501 | JSON | info | |
| `upstream_unavailable` (TLS failure, connect failure) | 502 | route's | warn | |
| `policy_unavailable`, `broker_unavailable` | 503 | route's | error, rate-limited | Always with the code in the body; this is what B lost [M exp2] |

Other failures:

- **Config or policy invalid at startup:** exit code 2 with the validation error on stderr. The
  pod stays in CrashLoopBackOff, and since the agent has no other path out, nothing leaks; agent
  requests fail with connection refused.
- **Session-plane socket cannot be bound** (path exists and is live, or the directory is not
  writable): exit code 2. A stale socket file left by a dead proxy is replaced only after a connect
  probe gets no answer, because file identity alone (device and inode) can match a successor's
  socket on ext4 [I].
- **Upstream error mid-stream:** the client stream is closed without a synthetic success; the audit
  line records `upstream_reset` and the bytes sent.
- **Audit write failure:** stdout is the sink in Phase 1, and a failed write is counted in a
  metric and does not refuse the request. Durable, fail-closed audit belongs to RFC Q5.
- **Session plane errors:** as in the table under Q1. An authority whose renew fails keeps retrying
  with backoff until its lease lapses; it does not tear sessions down itself, because the proxy's
  lease is what enforces the end.

---

## 5. Phase 1 backlog from Phase 0

Each item says what Phase 1 does with it.

1. **WebSocket upgrade.** Codex's built-in provider tries `ws://…/responses` first and falls back
   to HTTPS after about 7 s; a custom `model_providers` entry goes straight to HTTPS [M exp1].
   Phase 1 refuses upgrades with 501 and documents the custom provider in the Codex recipe.
   Pass-through WebSocket, with the same admission on the upgrade request, waits until a CLI needs
   it.
2. **Request-body streaming and HTTP/2 upstream.** Bodies are buffered today with a 32 MB cap
   [M exp2]. Phase 1 streams request bodies with a configurable cap (default 32 MiB, 413 above it)
   and negotiates HTTP/2 upstream through ALPN, keeping HTTP/1.1 on the agent listener. The matrix
   gains a large-body case and a slow-body case.
3. **401 vs 403 on expiry and revocation.** Claude Code in API-key mode retries a 401 about 10
   times over about 3 minutes (21 requests in 172 s) and fails a 403 in 0.4 s [M exp1]. An
   env-delivered surrogate cannot be re-minted inside a running CLI [I], so a retry can never
   succeed. Phase 1 returns 403 for every surrogate state, with the AWS-shaped body on AWS routes
   so kiro-cli shows the reason verbatim [M exp1]. Matrix row R3 changes its expected status from
   401 to 403.
4. **`KIRO_DISABLE_TELEMETRY=1`.** With telemetry on, kiro-cli lingers 3.9 s after the reply
   (n=1); with it off, 0.02 to 0.11 s (n=2) [M k3s 4]. The platform sets it in the session
   environment (openab-pty startup hook and env, openab `[agent].env` recipe). Claude Code's
   equivalent is `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` [M exp1].
5. **kiro-cli's embedding download.** The semantic-search model download from
   `desktop-release.q.<region>.amazonaws.com/models/all-MiniLM-L6-v2.zip` fails under the deny in
   both telemetry modes [M k3s 4]. Phase 1 offers two documented choices: an `[egress]` entry
   through `ap-egress` (Q3-E2), or pre-seeding the model in the image. Whether kiro-cli picks up a
   pre-seeded model is not verified [I].
6. **Combined Option A rule set in one pod.** Measured only in two pods [M k3s F1, F2]. The Phase 1
   k8s test runs the full set above.
7. **Non-loopback base URLs (Option C).** Not verified for any CLI (RFC #1). Avoided with
   `ap-relay`; verifying it is still worth doing.
8. **Slow failure on tampering.** kiro-cli retries for about 44 s after its settings are rewritten
   [M k3s 5a, 5b], npm for 71 s under the deny [M k3s 7]. Not fixable in the proxy; the recipes say
   so.
9. **Pod Security Admission.** The `NET_ADMIN` init container needs the namespace at PSA
   `privileged` [I, RFC #1]. Phase 1 documents it; a CNI plugin is later work.

---

## 6. Crate layout

A Cargo workspace at the repository root. Rust 2021, axum 0.8 / hyper 1, reqwest 0.12 with
`rustls-tls`, tokio, serde with `deny_unknown_fields`, `toml`, `sha2`, `subtle`; `aws-sdk-
secretsmanager` behind a feature, as in octobroker [I src: octobroker `Cargo.toml`]. Release
binaries are static musl builds.

```
Cargo.toml                    workspace
crates/
  ap-core/                    lib. Config model and validation (Q3-A), canonicalization,
                              policy snapshot and evaluation, header stripping, error dialects,
                              audit record. No network I/O, no credential values.
  ap-broker/                  lib. Session registry with leases and resync (Q1-B), credential
                              sources (file; aws-sm feature), the `Broker` trait the proxy calls.
                              The only crate that ever holds a credential value.
  ap-proxy/                   bin `auth-proxy`. Agent listener (loopback TCP), session-plane and
                              admin Unix sockets (HTTPS session plane on ECS), forwarder.
  ap-egress/                  bin `ap-egress`. Allowlisting CONNECT proxy (Q3-E2). Depends on ap-core
                              for config parsing only; must not depend on ap-broker (checked in CI
                              with `cargo tree`).
  ap-client/                  lib + bin `ap-relay`. Session-plane client for openab and the
                              openab-pty runtime, surrogate generation, and the ECS loopback relay.
                              Small dependency set so both platforms can take it.
deploy/
  k8s/                        netinit image (iptables-nft rule set), sidecar manifests, PSA note
  ecs/                        deferred with the ECS rollout: proxy service task definition, security-group example
docs/
  design/phase1.md            this document
  session-plane.md            normative protocol (Q1-B), so a platform can implement it without ap-client
  recipes/                    per CLI: base-URL settings, credential variable, quirks from Exp 1
tests/
  matrix/                     the fail-closed matrix, ported from spike/exp2/test
  k8s-egress/                 Option A rule-set test (from spike/k3s-egress-a), manual or nightly
```

The spike's `lib.rs` splits along these lines: canonicalization, policy and stripping into
`ap-core`, the broker client into `ap-broker` (replaced by the registry), the 149-line forwarder
into `ap-proxy`. The Envoy `ext_authz` binary from the spike is not carried forward.

---

## 7. CI gate: the fail-closed matrix

The 25 cases from Phase 0 are the merge gate on `main`. A pull request that fails a case, deletes
one, or loosens an expectation does not merge; changing an expectation needs the reason in the
PR's review contract.

The CI job runs on a GitHub-hosted Linux runner: `cargo fmt --check`, `cargo clippy --all-targets
-- -D warnings`, `cargo test`, a release build, then `python3 tests/matrix/matrix.py --bin
target/release` against throwaway CAs, mock TLS upstreams, and the real session plane instead of
the mock broker. The job fails unless every row reports PASS. The run's text and JSON output are
uploaded as artifacts.

| Row | Cases | Phase 1 expectation |
|---|---|---|
| R1 policy empty or unavailable | 5 (empty rules, 0 bytes, deleted after good load, corrupt, other path or method only) | unchanged: 403 `policy_empty` / 503 `policy_unavailable` / 403 `policy_denied`, 0 upstream |
| R2 broker unreachable, no stale cache | 1 | the broker is in process (Q2-A), so the row becomes "session revoked through the session plane after a good request, same surrogate": 403, 0 upstream, no stale allow |
| R3 surrogate state | 4 (expired, revoked after use, unknown/malformed/missing, AWS dialect) | **403** instead of 401; AWS body `__type: AccessDeniedException` |
| X1 caller key and surrogate binding | 1 | unchanged |
| R4 redirects | 1 | unchanged |
| R5 hostile Host / request target; bad route hosts in config | 2 | unchanged |
| X2 path canonicalization | 1 | unchanged |
| X3 CONNECT on the credential listener | 1 | unchanged (405) |
| R6 SNI = Host = route host; certificate name mismatch | 2 | unchanged |
| R7 untrusted upstream CA | 1 | unchanged |
| R8 one credential upstream; junk stripped; two surrogates | 3 | unchanged |
| X4 enforcement point down | 1 | was n/a for A [M exp2]; becomes "credential store unreadable after a good request" (S1 file removed): 503 `broker_unavailable`, 0 upstream |
| X5 no secret in any log or work file | 1 | extended to session-plane logs and the authority token |
| X6 SSE streaming | 1 | unchanged |

That is 25 cases. Phase 1 adds cases and removes none: session-plane authentication (no token,
wrong token, `hello` while an authority is live), lease lapse, resync after a proxy restart (same
surrogate works, dropped sessions stay dropped), `aws_targets` deny, large and slow request bodies,
WebSocket upgrade refused, and for `ap-egress`: allowlisted CONNECT tunnels, and a non-listed
host, an IP literal, a name resolving to a private address and a wrong port are refused. The
k8s rule-set test (F1 per-port reject, F2 inbound replies, DNS blocked, proxy reachable) runs
nightly or by hand, because it needs a cluster with `NET_ADMIN`.

---

## 8. Out of scope and still open

- **ECS rollout (Option C)**, deferred by the Q2 decision: the S2 Secrets Manager store and its
  cache bound, per-bot proxy services, `ap-relay`, and the IAM, Secrets Manager and
  execution-role changes. The `aws-sm` feature, the HTTPS session plane and `deploy/ecs/` wait
  for it.
- **RFC Q5**, ownership of rotation, revocation and audit retention. Phase 1 writes audit lines to
  stdout and leaves durable audit to Q5.
- Phase 2 (interception) and Phase 3 (SigV4 re-signing, SSH signing socket).
- Broker-owned OAuth refresh for subscription logins (Claude, Codex ChatGPT mode, Gemini Google
  login, kiro-cli SSO). Phase 1 covers API-key credentials only.
- Live runs against the Anthropic, OpenAI and Google APIs. Only kiro-cli was run live [M exp1].
- Multi-replica proxy (fan-out registration) and a shared multi-identity proxy on ECS.
- Dual-stack clusters (simulated only [M k3s 2]).

## Appendix: evidence index

| Tag | Where |
|---|---|
| `exp1` | `spike/exp1/` on `spike/phase0`; summary in the RFC #1 Phase 0 comment |
| `exp2 <row>` | `spike/exp2/results/matrix-a.txt`, `matrix-a.json`, `bench-a-*.json`, `live-kiro.json` |
| `k3s <n>`, `k3s F<n>` | `spike/k3s-egress-a/results/` (`01a-audit.jsonl` for test 1a, `02-03-egress-ap-a.jsonl` for 2 and 3, `04-chat-telemetry-on.txt` for 4, `05-tamper.txt` for 5, `06-*` for 6, `07-tools.txt` for 7, `08-restart.txt` for 8); findings F1 to F3 in the k3s validation report on the same branch |
