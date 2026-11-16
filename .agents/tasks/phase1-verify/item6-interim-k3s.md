RESULT: PASS (all five claims). One note on version: kiro-cli on `mini` is 2.37.0, not the 3.3.0 of item 4.

# Item 6a: INTERIM Q1-A pod on real k3s (stub upstream, no real credential)

Code under test: `4bf8ae3` exported with `git archive` (not the moving worktree). Node: `mini`
(LAN alias, Ubuntu 24.04 x86_64, k3s v1.36.2, single node). Namespace `ap-item6` (PSA privileged).
Run date (node clock): 2026-11-16. Tags: [M] measured. Raw output: `item6-evidence/interim-run.out`.

## Method
- Linux binaries built ON `mini` (`cargo build --release --locked -p ap-proxy -p ap-egress`, glibc, throwaway
  `CARGO_HOME`/target under `/tmp/ap-item6-build`). No cargo on the laptop or macmini.
- Images built on macmini (OrbStack docker, linux/amd64, ubuntu:24.04), moved as a tar, imported with
  `k3s ctr -n k8s.io images import`. Names `docker.io/ap-item6/{proxy,egress,agent,hr,netinit}:dev`.
  The agent image carries the kiro-cli binaries copied from `mini`'s own install (binaries only; the agent HOME
  is an emptyDir, so no login state and no `~/.kiro` content went into the pod).
- Keys: `deploy/k8s/interim-keygen.sh` (shipped, unmodified) generated the caller key and surrogate. The "real"
  credential is a random dummy (`real-dummy-<hex>`) generated on `mini`; no value was printed or committed.
- Stub upstream: an HTTPS python server (pod `stub`, Service) with a throwaway CA. It logs method, path,
  `X-Amz-Target`, header NAMES, body length, and classifies the Authorization header as REAL / SURROGATE-prefix /
  other / none. It never prints a header value.
- Manifest: `deploy/k8s/pod-interim-static.yaml` applied via `item6-evidence/pod6.sh` with these TEST-ONLY edits
  (all other lines untouched; the unmodified diff is in the script):
  1. image placeholders -> the imported images, `imagePullPolicy: Never`;
  2. `--interim-static-surrogate-sha256=` filled with the real hash;
  3. proxy gets `--ca-file /etc/ap-ca/ca.pem` + a ConfigMap volume (to trust the stub CA);
  4. `hostAliases` on the pod map `runtime.us-east-1.kiro.dev` and the cps placeholder host to the stub Service IP;
  5. policy: example policy + caller hash + `port = 8443` on both routes (stub listens on 8443).
  No `AP_SESSION_SOCKET_MODE` anywhere.

## Claims

| # | Claim | Result | Evidence ([M]) |
|---|---|---|---|
| 1 | Pod starts: netinit, **`kiro-settings` init container** (`kiro-cli settings`), proxy, ap-egress, agent | PASS | pod 3/3 Running; `netinit exit=0 kiro-settings exit=0`; `~/.kiro/settings/cli.json` in the agent HOME holds `api.krs.service` and `api.cps.service` endpoints `http://127.0.0.1:18080/ap/apk_<masked>/kiro-krs` and `/kiro-cps`, region us-east-1; `kiro-cli settings api.krs.service` reads them back |
| 2 | Interim start line and no session socket in the agent | PASS | proxy log: `INTERIM static session enabled (Q1-A): ... NO per-session revocation ...`; agent: `ls /run/auth-proxy` and `/run/auth-proxy-admin` -> "No such file or directory" |
| 3 | Agent holding only the surrogate reaches the stub through the proxy; upstream sees the REAL credential | PASS | agent env has only `KIRO_API_KEY=aps_<masked>`. `curl` as UID 1000 to `127.0.0.1:18080/ap/<key>/kiro-krs/` with `authorization: Bearer <surrogate>` -> `status=400` (the stub's answer); stub log: `host=runtime.us-east-1.kiro.dev:8443 POST / target=AmazonCodeWhispererStreamingService.GenerateAssistantResponse authorization_class=REAL`; same for `kiro-cps` / `GetProfile`. Negatives: wrong surrogate 403 `surrogate_malformed`, none 403 `surrogate_missing`, wrong caller key 403 `caller_rejected`; none reached the stub |
| 4 | Real credential never in the agent container | PASS | scan as UID 1000 with the dummy value passed on stdin: `/proc/*/environ` + `cmdline` hits 0 (4 procs); files containing it under home, tmp, work, etc, run, var, opt, usr/local, root: 0; no `/run/secrets`; 0 secret mounts in `mountinfo`. Positive control (value planted in /tmp) found 1. Proxy audit has 0 lines containing `apk_`, `aps_` or the dummy |
| 5 | Direct egress and DNS from the agent UID refused | PASS | all fail in 0.16 to 0.24 s (incl. `kubectl exec` overhead): `curl --noproxy` example.com -> "Could not resolve host" (exit 6); `--resolve` to a literal IP -> connect refused (7); direct `https://<stub ClusterIP>:8443` refused (7); `getent hosts github.com` exit 2; `dig @kube-dns` "no servers could be reached"; `nc 1.1.1.1:443` refused; python socket to 8.8.8.8:53 `ConnectionRefusedError`. Via the pod's `HTTPS_PROXY` (ap-egress): `github.com` 200, `example.com` 000 (403 from ap-egress) |
| 6 | Q1-A interim session works with kiro-cli | PASS | `kiro-cli chat --no-interactive --trust-tools= "say hi"` (HTTPS_PROXY/settings from the pod): stub saw 1 `GenerateAssistantResponse` on the krs host, 42 `GetProfile` + 4 `ListAvailableModels` on the cps host (kiro-cli retries on the stub's 400), all `authorization_class=REAL`; chat printed the stub's error text, so the response came back through the proxy. Proxy audit: all allowed lines `session=interim-static`, `decision=allow`, 0 leaks |

## Notes (not failures)
- kiro-cli 2.37.0 honours `api.krs.service` / `api.cps.service` in `~/.kiro/settings/cli.json` and sends
  `Authorization: Bearer <KIRO_API_KEY>` with `tokentype`. A bare `authorization: <surrogate>` without `Bearer`
  gets `surrogate_malformed`; that is the proxy's format check, not a defect.
- The test image's `ubuntu` user (UID 1000) is in the distro groups `adm`, `sudo`, etc. from `/etc/group`. That is
  an artefact of the test image, not of the manifest (no `sudo` binary, no capabilities). Real agent images
  should not add UID 1000 to such groups.
- The kiro-cli retry storm (46 control-plane calls in one `chat`) is kiro-cli reacting to the stub's HTTP 400.
- Not exercised: a real model response, the real kiro hosts, kiro-cli 3.3.0.

## Defects found
None in the manifests or scripts. Two stale sentences updated (see commit): "has not been applied to a cluster yet"
in `docs/interim-static-session.md` and the matching line in `pod-interim-static.yaml`.
