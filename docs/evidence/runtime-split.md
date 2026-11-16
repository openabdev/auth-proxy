# Runtime split: pod-run evidence

This file records the runtime-split pod checks on two clusters, and the openab-pty spec hash before and after the runs. Source: `REPORT.md` and the pod-run evidence logs in the runtime-split task folder.

## OrbStack arm64

| Check | Result | Exit code or observed result |
|---|---|---|
| 3(a) | PASS | Pod Running after the manifest fix (see First runs). Init containers `volume-prep`, `netinit`, `expiry-store-bootstrap` exit 0. `agent`, `proxy`, `runtime`, `egress` ready, restarts 0. |
| 3(b) | PASS | Proxy listener HTTP 403. Egress listener HTTP 405. Other loopback port refused for UID 1000, curl exit 7. Direct TCP to upstream curl exit 7. DNS lookup rc 1. |
| 3(c) | PASS | Register 201, surrogate prefix `aps_`. Granted request 200. Unknown surrogate 403. Revoke 204, then 403. Runtime hello 201 in proxy audit. Upstream POSTs 2 before recreate, real credential seen, surrogate and caller key not seen. |
| 3(d) | PASS | Secret hits 0 in 39 log lines. 0 in 41 lines after recreate. 0 in 40 lines of overlay logs. |
| 3(e) | PASS | Store sha256 prefix `779620227f8b1122`, 333 bytes, 5 lines. Identical before delete, after delete, after recreate. |
| 3(f) | PASS | Env hits 0, process hits 0, filesystem scan hits 0. |
| A(i) | not recorded | not recorded |
| A(i-a) | PASS | Connect to `session.sock` as UID 1000: ENOENT. |
| A(i-b) | PASS | Connect to the same socket path through the test-only overlay: EACCES. Socket owner:group and mode `1001:1002 660`. |
| A(ii) | PASS | `POST /v1/hello` and `GET /v1/hello/challenge` both 404 `unknown_operation`. |
| A(iii) | PASS | Rerun (see Reruns). 60 samples over about 4 min. `session.sock` EACCES in all 60. Runtime hello never 201. Proxy audit: 201, 409 `authority_active` three times, 201. Runtime restarted 4 times. |

The first pass of 3(e) on this cluster printed the store fields wrong (a parsing bug, per REPORT.md). Its byte and line values are not used. The table shows the valid rerun only.

## Second node amd64

| Check | Result | Exit code or observed result |
|---|---|---|
| 3(a) | PASS | Pod Running, init containers exit 0, app containers ready, restarts 0. Netinit rules for UID 1002 present in the log. |
| 3(b) | PASS | Proxy listener HTTP 403. Egress listener HTTP 405. Other loopback port refused, curl exit 7. Direct TCP to upstream curl exit 7. DNS lookup rc 1. |
| 3(c) | PASS | Register 201, granted request 200, unknown surrogate 403, revoke 204 then 403. Runtime hello 201 in audit. Upstream POSTs 2 before recreate, real credential seen, no surrogate or caller key seen. |
| 3(d) | PASS | Secret hits 0 in 39 log lines. 0 in 41 lines after recreate. 0 in 40 lines of overlay logs. |
| 3(e) | PASS | Rerun after two FAIL attempts (see First runs). Store sha256 prefix `3fb29a547c722a07`, 181 bytes, 3 lines. Identical before delete, after delete, after recreate. |
| 3(f) | PASS | Env hits 0, process hits 0, filesystem scan hits 0. |
| A(i) | not recorded | not recorded |
| A(i-a) | PASS | Connect to `session.sock` as UID 1000: ENOENT. |
| A(i-b) | PASS | Connect to the same socket path through the overlay: EACCES. Socket owner:group and mode `1001:1002 660`. |
| A(ii) | PASS | `POST /v1/hello` and `GET /v1/hello/challenge` both 404 `unknown_operation`. |
| A(iii) | PASS | 60 samples over about 4 min. `session.sock` EACCES in all 60. Runtime hello never 201. Proxy audit: 201, 409 `authority_active` three times, 201. Runtime restarted 4 times after the kill. |

## First runs (FAIL)

| Cluster | Check | Result | Exit code or observed result |
|---|---|---|---|
| OrbStack, first run | 3(a) | FAIL | Pod stayed Pending in Init, and `volume-prep` restarted. `chmod` returned EPERM after `chown`, because the manifest gave CHOWN as the only capability. The netinit rules check also FAILed in this run; the source gives no separate cause. Fixed by adding FSETID and running chmod before chown. Rerun: PASS (see Reruns). |
| OrbStack, first run | A(iii) | FAIL | 60 samples; `session.sock` EACCES in all; runtime hello never 201; `restarted=False`. Reason: the probe sent `kill -9` to PID 1 of the runtime container. The kill returned rc 0 and did not stop PID 1, so no restart could be seen. This run also recorded `proxy_hello_only_runtime=False`; the logs do not say why. Rerun: PASS (see Reruns). |
| Second node, first run | 3(e) | FAIL | The log shows two FAIL attempts (REPORT.md mentions one). Both printed the store sha256, bytes and lines as `?`, so no value was read. Reason as recorded: the reader pod was not ready, and the store-read command had a quoting bug. The harness was then changed to wait for the reader pod and to quote the command. Rerun: PASS (see Reruns). |

## Reruns (PASS)

| Cluster | Check | Result | Exit code or observed result |
|---|---|---|---|
| OrbStack, rerun | 3(a) | PASS | Pod Running after the manifest fix. Init containers exit 0, app containers ready, restarts 0. Netinit rules check PASS. |
| OrbStack, rerun | A(iii) | PASS | The runtime shim ran as a child of a wrapper shell, and the probe killed that child (`killed-pid 6`, rc 0). 60 samples; `session.sock` EACCES in all; runtime hello never 201; `restarted=True`; restarts 4; proxy audit 201, 409 three times, 201; `proxy_hello_only_runtime=True`. |
| Second node, rerun | 3(e) | PASS | Store sha256 prefix `3fb29a547c722a07`, 181 bytes, 3 lines. Identical before delete, after delete, after recreate. |

## openab-pty before and after

| Cluster | Check | Result | Exit code or observed result |
|---|---|---|---|
| OrbStack | before | PASS | Spec hash `7a3bf0a4...216ad`. 1 pod, Running. |
| OrbStack | after | PASS | Spec hash `7a3bf0a4...216ad`, identical to before. 1 pod, Running. |
| Second node | before | PASS | Spec hash `4e171458...95430`. 6 pods. One Pending pod was already Pending before the run and was not touched. |
| Second node | after | PASS | Spec hash `4e171458...95430`, identical to before. 6 pods. |

## Matrix

Result: **41 of 41, PASS**. Run on the build host.

- Exit code: not recorded.
- Observed: 41 rows run, 41 expected. Summary 41 PASS of 41 rows. Gate 28 of 28. Phase 1 13 of 13.
