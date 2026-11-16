# Interim Q1-A pod and the hello race on a real k3s node

Verdict: **PASS**. Code under test: `4bf8ae3`. Run date (node clock): 2026-11-16. One x86_64 k3s v1.36.2 node, flannel,
glibc builds of `auth-proxy`, `ap-egress` and a test runtime built on the node. Test aids: a stub HTTPS upstream, a
throwaway CA, a random dummy credential, `hostAliases` for the route hosts, and `port = 8443` on the routes. No real
credential and no real model call. Claim tags: [M] measured.

## Interim pod (`deploy/k8s/pod-interim-static.yaml`)
- [M] All containers start, including the `kiro-settings` init container; it writes `api.krs.service` and
  `api.cps.service` into the agent's `~/.kiro/settings/cli.json` with the caller key in the base URL path.
- [M] The proxy prints the `INTERIM static session enabled ... NO per-session revocation` line. The agent container has
  no session socket and no admin socket.
- [M] With only the surrogate in its environment, the agent reaches the stub through the proxy, and the stub sees the
  real (dummy) credential. `kiro-cli chat --no-interactive` (2.37.0) sends the model call and the control-plane calls
  through it; the audit lines show `session=interim-static`.
- [M] A wrong surrogate, no surrogate and a wrong caller key are refused with 403 and never reach the stub.
- [M] The credential value is absent from the agent container (environment, command lines, files, mounts) and from
  every audit line.
- [M] As the agent UID, direct HTTPS, direct DNS (system resolver and cluster DNS), and raw TCP to a public address are
  refused in under 0.25 s; the allowlisted host works through `ap-egress` and an unlisted one does not.

## Hello race on `deploy/k8s/pod.yaml` (group 2000, mode 0660, no `AP_SESSION_SOCKET_MODE`)
- [M] The agent UID (1000, group 2000) reaches `session.sock` (`srw-rw---- 1001:2000`); `ap-egress` mounts neither
  socket and the agent has no admin socket.
- [M] After SIGKILL of the agent container, no same-UID orphan survives. For the 90 s authority lease the proxy
  answered every `hello` with 409 (27 of them, none won). The fresh PID 1 won its first attempt after the lapse. The
  old session's surrogate then got `403 surrogate_revoked`.

## Limits
kiro-cli 2.37.0, not 3.3.0. The runtime is a stand-in, not a real one. The `kiro-cps` host is still open
(`docs/pre-release-checklist.md` item 5).
