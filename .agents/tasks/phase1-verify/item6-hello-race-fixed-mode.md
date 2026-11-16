RESULT: PASS (hello race holds with the fixed socket mode, no override)

# Item 6b: hello race on `deploy/k8s/pod.yaml` with group 2000 and mode 0660

Same method as item 5 (`item5-hello-race.md`): `hr-authority` stand-in runtime (production `ap-client` `Authority`,
default 90 s lease, 30 s renew), PID 1 of the agent container, one same-UID child "orphan" hello-ing every 1 s.
Code `4bf8ae3`. Pod = `deploy/k8s/pod.yaml` with only image and `hostAliases`/CA test edits (`pod6.sh`, `INTERIM=0`).
**`AP_SESSION_SOCKET_MODE` is not set**: `kubectl get pod -o yaml | grep -ci "SESSION_SOCKET_MODE\|session-socket-mode"` -> `0`;
proxy args are `["--policy","/etc/auth-proxy/policy.toml"]`, env empty. Raw: `item6-evidence/hello-run.out`, `hello-post.out`.

| Claim | Result | Evidence ([M]) |
|---|---|---|
| UID 1000 reaches the session socket without a 666 override | PASS | agent: `uid=1000 gid=2000`; `srw-rw---- 1 1001 2000 session.sock`; the first `hello` won (201) at the container's first attempt, 1 ms after start (proxy audit `hello ok 201`, then `register ok 201`). Item 5 saw `PermissionDenied` here. |
| Admin socket not reachable from the agent | PASS | `ls /run/auth-proxy-admin` in agent: No such file or directory (volume mounted only into `proxy`) |
| ap-egress (1002) has neither socket | PASS | in `ap-egress` (`id -u`=1002): `/run/auth-proxy` and `/run/auth-proxy-admin` do not exist (not mounted) |
| Same-UID orphan blocked while the lease is live | PASS | orphan (pid 11) `hello` every 1 s, all 409 `authority_active` (proxy audit shows each) |
| After SIGKILL of the agent container no orphan survives | PASS | kill 19:21:09.43 (`crictl stop --timeout 0`), new PID 1 `AUTH_START` 19:21:09.90 (0.5 s); `ps` after: only pid 1 and the exec'd `ps`; last orphan line 19:21:07.878, none after the kill |
| The 90 s lock holds; only the fresh PID 1 wins | PASS | proxy clock: last renew t0 = ...861678 ms. Between t0 and the winner: 27 hellos, all 409, last at +83.2 s; **0** 201s. Exec'd rival probe (UID 1000, 10 hellos every 5 s, +10 s to +60 s) all 409, "never won". Winner `201` at +98.2 s = lapse (+90 s) + the fresh PID 1's own backoff (attempts at +83.2 and +98.2 s); `HELLO_WON pid=1` 19:22:39.919 matches proxy `...959918` |
| Old session revoked at the lapse | PASS | as UID 1000: POST with the old surrogate -> `403 x-auth-proxy-error: surrogate_revoked`; audit `kiro-krs deny surrogate_revoked 403` |
| New session admitted | PASS | the new PID 1's surrogate gets past admission (audit `session=sess-1794856959`); the pod has no `--ca-file`, so the stub TLS fails and the call ends `502 upstream_unavailable`, which is after admission (a revoked/unknown surrogate would give 403) |
| Restarts | PASS | agent=1, proxy=0, ap-egress=0 |

Limits: as in item 5, the attempts did not fall inside the 83 to 98 s window, so the 90.000 s boundary is pinned by the
unit test `hello_race.rs`, not here. The `hr-authority get` helper from item 5 now gets `400 host_rejected` (it sends a
Host the proxy refuses); the revocation check above used curl with the correct Host instead. The helper was a test tool.
