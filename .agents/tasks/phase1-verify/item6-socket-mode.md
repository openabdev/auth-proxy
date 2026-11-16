RESULT: PASS (manifest + script; in-cluster proof is partB)

# Item 6: session socket reachable by the agent UID without a world-writable socket

Problem (item 5 finding): proxy UID 1001 creates `session.sock` 0660 `1001:1001`; the agent (UID 1000) shares no group, so `hello` got PermissionDenied and the runtime retried forever. Item 5 worked around it with `AP_SESSION_SOCKET_MODE=666`.

## Mechanism
`proxy` and `agent` containers both set `runAsGroup: 2000`. The proxy creates the socket with its primary group, so it is `srw-rw---- 1001:2000` (mode unchanged, default 660). The agent UID 1000 connects as a group member. ap-egress (1002:1002) cannot. No proxy code change.

Why smallest: one `runAsGroup` value on two containers; no new capability, no code, no pod-wide setting.

## Admin socket
`/run/auth-proxy-admin/admin.sock`, mode 0600, in emptyDir `admin-sock` mounted only into `proxy`. The agent has neither the path nor the group.

## Rejected
- `fsGroup` / `supplementalGroups`: pod-level only, adds the group to ap-egress too; fsGroup also changes Secret mount ownership (the pod header records it was measured harmful).
- mode 666: any UID in the pod (incl. ap-egress).
- chown socket to 1000: needs CAP_CHOWN in the proxy.
- proxy as UID 1000: breaks the UID separation netinit and the credential mount rely on.

## Same-UID caveat
Every process in the agent container is in group 2000 and can speak to the session socket. Nothing new beyond the documented best-effort attribution between same-UID sessions: `hello` is unauthenticated by design and refused (409) while the lease is live; all other calls need the authority token.

## Values
- `/run/auth-proxy/session.sock`, 0660, owner 1001, group 2000 (proxy UID 1001, GID 2000; agent UID 1000, GID 2000; ap-egress 1002:1002).
- `/run/auth-proxy-admin/admin.sock`, 0600, owner 1001, group 2000 (proxy only volume).
- `pod-interim-static.yaml`: unchanged config (agent does not mount the session socket; proxy stays 1001:1001), comment only.

## Check
`scripts/check-session-socket.sh`:
- static (default, no cluster): both manifests; shared GID only where the agent mounts the session socket, ap-egress outside it, no fsGroup/supplementalGroups, no socket-mode override, agent has no admin-sock or credential Secret, ap-egress mounts no socket volume. Wired into `.github/workflows/ci.yml` and `scripts/sync-and-test.sh`.
- live: `LIVE=1 NS=.. POD=.. sh scripts/check-session-socket.sh` runs as UID 1000 in the agent container: connect to session.sock must succeed, admin.sock must be absent/denied, socket stat must be 0660 group 2000. NOT run yet (needs a cluster; partB).

## Files
deploy/k8s/pod.yaml, deploy/k8s/pod-interim-static.yaml (comment), scripts/check-session-socket.sh (new), scripts/sync-and-test.sh, .github/workflows/ci.yml, docs/design/phase1.md (new section "Session socket access"), docs/interim-static-session.md.

## Commands run
- `sh scripts/check-session-socket.sh`: 18 PASS, 0 FAIL on both manifests; a mutated pod.yaml (agent GID 1000) FAILs as expected.
- `sh scripts/sync-and-test.sh` (macmini: fmt --check, clippy --workspace --all-targets -D warnings, cargo test --workspace, ap-core test, release build, check-no-test-resolve, matrix, egress-deps): exit 0.
