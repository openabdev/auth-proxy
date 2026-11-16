# Operations (Kubernetes, Phase 1)

Claim tags: [M] measured, [I] inferred. Design: `docs/design/phase1.md`. Protocol:
`docs/session-plane.md`. Deploy assets: `deploy/k8s/`.

## Audit attribution is best effort between sessions of the same UID

Sessions of one agent container share a UID. A same-UID neighbour can read another
session's `/proc/<pid>/environ`, take its surrogate and spend it, which also spoofs the audit
attribution (the audit line names the session whose surrogate was taken, not the
process that spent it). So **audit
attribution between sessions of the same UID is best effort**. What stays exact:

- The real credential never leaves the proxy. The Secret is mounted only into the proxy
  container.
- Surrogates work only through the identity's own grants, so the damage is bounded by what
  the identity may do anyway.
- Per-session revocation and leases are exact against a well-behaved agent and against
  processes outside the identity; they are best effort against a hostile process inside it.

The RFC already scopes the guarantee to "agent identities, not processes".

## No caller key in any log

The agent's base URL is `http://127.0.0.1:<P>/ap/<caller-key>/<route>`. No audit line or
access log contains the `/ap/<caller-key>` prefix, the caller key, a surrogate, an authority
token or a credential value.

- The audit record takes only the route-relative path, which is cut once after the caller key
  has been verified.
- Requests refused before verification log the path as `-`.
- There is no URI-logging middleware. Do not add one, and do not put a sidecar or a platform
  access log in front that records the request line.
- Tested by `crates/ap-proxy/tests/no_caller_key_in_logs.rs` and matrix X5.

## RFC amendment (accepted by the owner)

The RFC said surrogate TTL is at most 15 minutes and renewal mints a new surrogate. An
environment variable cannot change in a running process [I], so Phase 1 keeps the surrogate
for the session and renews its lease instead: 15 min lease, renewed by the authority every
30 s, capped by a 12 h absolute TTL. Renewal is explicit, never a side effect of use.

## Exit codes

| Binary | Code | Meaning |
|---|---|---|
| `auth-proxy` | 0 | clean stop |
| `auth-proxy` | 2 | invalid arguments, invalid policy, or socket setup failed (startup) |
| `ap-egress` | 0 | clean stop |
| `ap-egress` | 2 | invalid arguments, invalid policy, bind failed, or accept loop failed |

A policy that becomes invalid after startup does not stop the process: requests get 503
`policy_unavailable` and recover when a valid file is back.

## Proxy restart gap (fallback)

After a proxy restart sessions are unknown until the authority's next renew (at most 30 s)
resyncs them. In that window requests get `surrogate_unknown` (403). Plan for up to 30 s of
refusals after each proxy restart. The authority token hash is persisted in `--state-dir`
(`proxy-state` volume), so the authority does not need a new `hello`.

## Authority container restart

The old authority lock holds for up to 90 s. The restarted PID 1 retries `hello` with backoff
and wins once the lease lapses; the lapse revokes all of the old authority's sessions. The
automated test is `crates/ap-proxy/tests/hello_race.rs`; the real-pod check is item 3 of
`docs/pre-release-checklist.md`.

## Pod Security Admission

The `NET_ADMIN` init container needs the namespace at PSA `privileged`.

## Release builds

Release binaries are static musl builds. The musl release job is documented, not run in this
repository yet: `cargo build --release --target x86_64-unknown-linux-musl -p ap-proxy -p
ap-egress` on a Linux host with the musl target and linker installed.

## Open items

- **One registered session per pod (Q1-A fallback)** for runtimes that do not speak the
  session plane: the design recommends it, gives no config shape, and Phase 1 does not build
  it. Open.
- The combined iptables rule set is [I] until `tests/k8s-egress/run.sh` has run on a cluster.

## Deferred, not rejected

These are out of Phase 1 by the Q2 decision. They are not built and no code or config for
them exists in this tree:

- ECS rollout (Option C), including `deploy/ecs/`, the HTTPS session plane and the IAM,
  Secrets Manager and execution-role changes.
- Store S2 (Secrets Manager) and its cache bound; the `aws-sm` feature.
- `ap-relay` (the ECS loopback relay).
- Per-bot proxy services.
