# INTERIM: static session (Q1-A) for the first Kubernetes deployment

**Status: interim path. Not the design.** Q1-B (per-session surrogates registered over the
session plane) stays the formal, accepted design, and new work on it is frozen. This page
describes the one thing built next to it so the first end-to-end Kubernetes deployment can run
before any agent runtime speaks the session plane.

## What the interim deployment does not have

**It has no per-session revocation. The owner (pahud) accepted this for the interim period.**

In plain words:

- One surrogate is valid for the whole life of the proxy process. Every process in the agent
  container that holds it can use it until the proxy stops.
- You cannot revoke it, or any one session's use of it, while the pod runs. There is no call,
  lease or timeout that ends it. `POST /admin/revoke-all`, session-plane `DELETE`/`PUT`, and an
  authority lapse do not touch it.
- It ends when the proxy container ends: delete the pod, or remove the flag and restart the
  proxy container.
- Audit lines show one session, `interim-static` (generation 0). They cannot tell sessions apart.

What stays exact: the real credential never leaves the proxy container; the surrogate works
only through the identity's own grants (policy), on the policy's routes, with the caller key in
the path; no log line holds the key, the surrogate or the credential.

Rotate the surrogate by running `deploy/k8s/interim-keygen.sh` again, updating the Secret and
the proxy argument, and recreating the pod.

## What it is

One optional proxy flag, `--interim-static-surrogate-sha256 <64 lowercase hex>` (environment
`AP_INTERIM_STATIC_SURROGATE_SHA256`). When it is set:

- The proxy admits requests that present the surrogate with that sha256, as the session
  `interim-static`, generation 0, bound to every credential defined in the policy **at proxy
  start** (a credential added by a later policy reload needs a proxy restart).
- Everything else in the pipeline is unchanged: caller key, route, policy grants, canonical
  paths, credential swap, audit. A policy that now names another identity refuses the surrogate
  (`surrogate_wrong_caller`), as for any session.
- The proxy prints one line at every start that names the path and says "NO per-session
  revocation".
- The Q1-B session plane is still built and still tested. It is a separate admission branch in
  `LocalBroker`; the registry, leases, authority lock and resync were not changed. In the example
  pod nothing in the agent container can reach the session socket, so it cannot take the
  authority lock or register sessions.

Without the flag the proxy behaves exactly as before.

## Deploy

1. `sh deploy/k8s/interim-keygen.sh ./keys` makes the caller key and the surrogate (mode 0600)
   and prints the caller-key hash, the surrogate hash and the `kubectl create secret` command.
2. Put the caller-key hash in your policy (`caller_key_sha256`), fill in the policy from
   `deploy/k8s/policy.example.toml`, and create the credential Secret (`auth-proxy-kiro`).
3. Put the surrogate hash into `deploy/k8s/pod-interim-static.yaml` and fill in the images.
4. Apply the pod. The init container `kiro-settings` writes kiro-cli's endpoint settings with
   the caller key in each base URL; the agent container gets `KIRO_API_KEY` from the Secret.
5. Delete `./keys`.

`deploy/k8s/pod-interim-static.yaml` differs from `deploy/k8s/pod.yaml` only in the items its
header lists. It has not been applied to a cluster yet.

## Open items before the first deployment can run

- The `kiro-cps` route host in `deploy/k8s/policy.example.toml` is a placeholder. See
  `docs/pre-release-checklist.md` for exactly what is needed.
- The real-pod hello-race check (checklist item 3) is still a release gate. The interim path
  does not call `hello`, but the gate stays: it protects the Q1-B path this interim path is
  waiting for, and the release is not done without it.

## Moving to Q1-B

Nothing to undo. Remove the flag, mount the session socket into the agent container, and use a
runtime that speaks the session plane (`docs/session-plane.md`). Q1-A is Q1-B with one session
that lives as long as the pod, as the design says.

## Tests

`crates/ap-proxy/tests/interim_static.rs` covers: the surrogate works and the upstream sees the
real credential; the audit session is `interim-static`; the startup line is labelled and nothing
leaks; no flag means no static session; caller key, grants and unknown surrogates still apply;
revoke-all, `hello` + empty resync and `DELETE` do not end it; it survives a lease and TTL that
would have ended a Q1-B session; a proxy restart needs no resync; Q1-B sessions work beside it
and are still revoked per session; a malformed hash is exit code 2. The Q1-B suites
(`session_plane.rs`, `hello_race.rs`, the matrix rows P1 and P2) run unchanged.
