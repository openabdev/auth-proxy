# Option A on k3s: sidecar proxy + per-UID iptables — validation report

Spike files: `spike/p1-egress-a/` on branch `spike/phase0` (manifests, scripts, raw output in
`results/`). Test cluster: single-node k3s v1.36 with kube-router (NetworkPolicy enforced),
Ubuntu 24.04, kernel 6.8, containerd 2.3. Namespace `auth-proxy-spike` only; no other workload
was touched.

## Setup as tested

- Pod `ap-a`, `shareProcessNamespace: false`, `automountServiceAccountToken: false`,
  seccomp `RuntimeDefault`:
  - `netinit` (init): root, `capabilities: {drop: [ALL], add: [NET_ADMIN]}`, read-only rootfs.
    Installs with iptables-nft 1.8.10, for both `iptables` and `ip6tables`:
    `-A OUTPUT -o lo -p tcp --dport 18190 -m owner --uid-owner 1000 -j REJECT --reject-with tcp-reset`
    (the sidecar's broker port, see finding F1) and the RFC rule
    `-A OUTPUT -m owner --uid-owner 1000 ! -o lo -j REJECT`. A test-only ULA is added to eth0 so
    IPv6 has a non-lo route.
  - `proxy`: UID/GID 1001, all caps dropped, `allowPrivilegeEscalation: false`, read-only rootfs.
    The only container that mounts Secret `ap-kiro`. Runs spike/exp2 `ap-proxy` (Option A, glibc
    build on the node) on `127.0.0.1:18100`, plus the exp2 mock broker on `127.0.0.1:18190`
    holding the real key in its environment (stand-in for the remote Phase 1 broker). It mints a
    surrogate and hands the surrogate and caller key to the agent through a shared emptyDir that
    the agent mounts read-only.
  - `agent`: UID/GID 1000, all caps dropped, `NoNewPrivs: 1`, `CapBnd: 0`, read-only rootfs. No
    Secret mount and no `KIRO_API_KEY`. Its entrypoint (the platform step) writes
    `~/.kiro/settings/cli.json` with `api.cps.service`, `api.krs.service`,
    `api.codewhisperer.service` and `api.q.service` →
    `http://127.0.0.1:18100/ap/<caller-key>/<route>`, region us-east-1. kiro-cli 2.37.0 is started
    later with the surrogate as `KIRO_API_KEY`.
- Pod `ap-b`: the same, except the RFC rule only (no broker-port rule), an extra
  `-m owner --uid-owner 1000 -m conntrack --ctstate ESTABLISHED -j ACCEPT` before it, and
  `shareProcessNamespace: true`. Used for test 6 and findings F1 and F2.
- Live kiro-cli invocations: **6**. Four reached the model (tests 1a, 1b, 4, and one wasted turn
  in test 5 where a quoting error left cli.json unchanged). Two (tests 5a, 5b) never left the pod.
  The remaining checks used `curl` to `ListAvailableModels`, a control-plane call, not a model turn.

## Test results

| # | Test | Result | Measured / inferred | Evidence (`spike/p1-egress-a/results/`) |
|---|---|---|---|---|
| 1a | `kiro-cli chat --no-interactive` through the loopback proxy | **PASS.** rc 0, reply "1…40", 6.6 s wall. Audit: 2× `cps` 200, 1× `krs` 200, all `forwarded` with caller `agent-1`. stdout arrived in 10 reads (the CLI prints in bursts) | measured | `01a-chat-telemetry-off.json`, `01a-audit.jsonl` |
| 1b | `kiro-cli acp` (one prompt) | **PASS.** `ok: true`, **15 `agent_message_chunk` updates** between 1.85 s and 2.17 s, 60 lines. Audit: 2× `cps`, 1× `krs`, all 200 | measured | `01b-acp-telemetry-off.txt`, `01b-audit.jsonl` |
| 2 | Direct egress as UID 1000 | **PASS (blocked).** IPv4 TCP :443 to runtime.us-east-1.kiro.dev, 1.1.1.1 and github.com: `ECONNREFUSED` in 0 ms. DNS to kube-dns: UDP `EPERM`, TCP `ECONNREFUSED`, `getaddrinfo` fails in 2 ms. IPv6 to public addresses: `ENETUNREACH` (the pod is IPv4 single-stack). IPv6 over the test on-link route: TCP `ECONNREFUSED`, UDP `EPERM`; UID 1001 on the same route gets `EHOSTUNREACH`/timeout (no neighbour), so the ip6tables rule is what stops UID 1000. Counters on the node: v4 7 packets, v6 5 packets rejected. Loopback `:18100` (proxy) ok; `:18190` (broker) refused | measured | `02-03-egress-ap-a.jsonl`, `00-nft-ruleset-ap-a.txt` |
| 2 | Is DNS blocked, and is that wanted? | **Yes, blocked** for UID 1000, over UDP and TCP. **Wanted:** the base URL is an IP literal, so kiro-cli needs no DNS for model traffic (tests 1a/1b worked with DNS blocked), and open port 53 would be an exfiltration channel. The cost is that every name-based tool fails (test 7) | measured (blocked, turns still work) / inferred (desirability) | same |
| 3 | Upstream egress as UID 1001 | **PASS.** TCP :443 to all three targets ok (4–9 ms), DNS UDP and TCP answered, `getaddrinfo` ok. Also every proxied call in tests 1/4/8 | measured | `02-03-egress-ap-a.jsonl` |
| 4 | Telemetry and update hosts unreachable, with and without `KIRO_DISABLE_TELEMETRY=1` | **PASS: starts and finishes in both modes; no startup delay.** First proxied request 0.07–0.16 s after process start in all three runs. **With telemetry on, the process lingers 3.9 s after the reply** (last stdout 2.79 s, exit 6.71 s); with it off, 0.02–0.11 s (n=2). Rejected packets: 20 in one telemetry-on run vs 12 across two telemetry-off runs (DNS sends). kiro-chat.log with telemetry on: `Failed to post toolkit metric … cognito-identity.us-east-1.amazonaws.com`. In **both** modes: `semantic_search_client … HTTP request failed … desktop-release.q.us-east-1.amazonaws.com/models/all-MiniLM-L6-v2.zip` (embedding model download, so semantic search is degraded). No `SendTelemetryEvent` reached the `cw` route | measured (n=1 on, n=2 off); cause of the 3.9 s tail inferred (telemetry flush) | `04-chat-telemetry-on.txt`, `01a-*` |
| 5a | Agent rewrites cli.json to the real hosts | **PASS (fails closed).** rc 1 after 43.9 s: "Encountered an error in the response stream: An unknown error occurred: dispatch failure". 0 new proxy audit lines | measured | `05-tamper.txt` |
| 5b | Agent removes the four settings (kiro-cli defaults) | **PASS (fails closed).** rc 1 after 44.3 s, same error, 0 audit lines | measured | `05-tamper.txt` |
| 5c | The surrogate itself, sent straight to the real control plane | Rejected: `ListAvailableModels` with the surrogate from UID 1001 (which has egress) → 400 `AccessDeniedException` "Invalid token". The same call via the proxy → 200 | measured | `05-tamper.txt` |
| 5d | No real credential reaches the agent | **PASS.** Node-side scan: 0 of 2 agent-container processes hold the key in `environ`/`cmdline`; 0 files in the agent's whole filesystem view (image + all its mounts). Positive control: 1 file under the proxy's Secret mount | measured | `05-tamper.txt` |
| 6 | UID 1000 reads the proxy's credential (`ap-a`, `shareProcessNamespace: false`) | **PASS.** The agent sees 0 processes of other UIDs; `/run/ap-secret` and `/var/run/ap-secret` do not exist in its mount namespace | measured | `06-cred-read-ap-a.txt` |
| 6 | Same with `shareProcessNamespace: true` (`ap-b`) | **Still no read, but more exposure.** The agent sees `pause`, `ap-proxy` and the broker. `environ`, `mem`, `maps` and `/proc/<pid>/root/run/ap-secret/…`: all `EACCES` (different UID, no `CAP_SYS_PTRACE`, yama `ptrace_scope=1`). `cmdline` is readable. `kill -0` on the proxy: `EPERM`. Positive control on the node: the broker's `environ` does hold the key | measured | `06-cred-read-ap-b.txt` |
| 7 | What else breaks for the agent | git clone over HTTPS: rc 128, immediately (cannot resolve host). curl https: rc 6, immediately. npm install: rc 1 after **70.7 s** (retries). pip download: rc 1 after 7.9 s. cargo fetch: rc 101 after 11.0 s. All fail at DNS first. Control as UID 1001 in the same pod: all five succeed | measured | `07-tools.txt` |
| 7 | Inbound connection to a UID-1000 listener on eth0 | With the RFC rule only: **broken**, the TCP handshake never completes (curl timeout, 5 s). With `ESTABLISHED` accepted first (`ap-b`): HTTP 200 in 1 ms, and outbound from UID 1000 is still refused (`02-egress-ap-b.jsonl`) | measured | `07b-inbound.txt`, `02-egress-ap-b.jsonl` |
| 8a | Agent container restart (`crictl stop`) | **Rules survive**: same sandbox, 4 `skuid 1000` rules, egress still refused, proxy reachable. The platform entrypoint rewrote cli.json (this also undoes any tampering) | measured | `08-restart.txt` |
| 8b | Proxy container restart | **Rules survive.** Caller key kept (proxy-private emptyDir); new surrogate minted and handed off; proxy path 200 | measured | `08-restart.txt` |
| 8c | Pod delete + recreate | New sandbox, `netinit` runs again, the same 4 rules, egress refused, proxy path 200 | measured | `08-restart.txt` |
| 8d | Init container without `NET_ADMIN` | **Fails closed.** `RTNETLINK answers: Operation not permitted`, pod stays `Init:0/1`, the agent container stays `PodInitializing` and never runs | measured | `08-restart.txt` |

## Findings that change the design

- **F1. "The agent UID may use only `lo`" exposes every loopback listener in the pod.** With
  the RFC rule alone (`ap-b`), the agent connected to the sidecar's broker port, called
  `/v1/resolve` with its own surrogate, and got back the real credential (HTTP 200, 36-byte
  `credential`; the value was not printed). With the extra per-port REJECT (`ap-a`) the same
  call was refused. Here the broker is a spike stand-in, but the same holds for any admin,
  metrics, health or cache endpoint the proxy sidecar binds on loopback. The rule must confine
  the agent to the proxy's listener port, not to `lo`. (measured)
- **F2. The rule breaks inbound connections to agent-UID servers over eth0** (Service traffic,
  kubelet httpGet probes against an agent-UID port, openab-pty's runtime ports if exposed on the
  pod IP). The handshake does not complete. Accepting `ESTABLISHED` for the agent UID before the
  REJECT fixes it and does not open outbound, because the agent's own SYNs and first UDP
  datagrams are NEW and still rejected. (measured)
- **F3. `shareProcessNamespace` must stay off,** although the UID split is what blocks the read.
  When it is on, the agent can enumerate the proxy's processes and read their command lines. It
  cannot read `environ`, memory or the mount through `/proc/<pid>/root`. (measured)

## Gotchas

- **Kernel owner match:** iptables-nft 1.8.10 translated `-m owner --uid-owner` into native nft
  `meta skuid`, so the rules work without the `xt_owner` module loaded. `nft list ruleset` on the
  node still printed "Warning: Extension owner is not supported, missing kernel module?" while
  listing them. The node counters confirm the rules matched. (measured)
- **`NET_ADMIN` alone is enough** for the init container; `NET_RAW` was not needed. (measured)
- **kube-router:** it programs the node's netns (veth and FORWARD chains). The pod-netns
  `OUTPUT` rules were never touched: unchanged after more than 10 minutes and across container
  restarts. No NetworkPolicy exists in the test namespace. A pod-level egress NetworkPolicy
  would apply to the proxy too, which is the constraint the RFC already states. (measured
  persistence; interaction inferred from kube-router's design)
- **ip6tables:** the pod is IPv4 single-stack, so public IPv6 fails with `ENETUNREACH` before
  netfilter for both UIDs, and the ip6tables rule does nothing here. Showing that it works
  needed a test-only on-link IPv6 address. Keep the rule for dual-stack clusters. (measured)
- **The agent UID inherits the image's groups.** UID 1000 is `ubuntu` in the base image, and
  kubelet added its `/etc/group` memberships (adm, sudo, …). That is harmless here (no sudo,
  `NoNewPrivs`), but production images should not map the agent UID to a privileged image user.
  (measured)
- **Secret file mode:** kubelet makes Secret files root-owned. A non-root proxy needs either
  `fsGroup` or a world-readable `defaultMode`. `fsGroup` is pod-wide: it adds the group to the
  agent container too. This spike used `defaultMode: 0444` on a volume mounted only into the
  proxy. The mount namespace is the boundary, and with a shared PID namespace `/proc/<pid>/root`
  was still `EACCES`. (measured)
- **`/var/run` is a symlink to `/run`** in Ubuntu images, so a mount at `/var/run/x` appears at
  `/run/x` when seen through `/proc/<pid>/root`. A probe of the `/var/run/...` path reports a false
  "not found". (measured)
- **The tampering failure is slow.** kiro-cli retries for about 44 s before it gives up.
  npm takes 71 s to fail. Under a full deny, users see hangs rather than errors.
- **Pod Security Admission:** adding `NET_ADMIN` is not allowed under the `baseline` or
  `restricted` levels, so the agent namespace must be `privileged` for the init container.
  Istio solves the same problem with a CNI plugin. (inferred, not tested)
- **Incident during this spike:** a `bash -x` trace of `scan-agent.sh` printed the real
  `KIRO_API_KEY` into the operator's session output. It was never written to a file on the test
  node. It is in that session's transcript, so **rotating the key is recommended**.

## Recommended edits to `rfc-section-egress.md`

1. In the Option A row, replace the single rule with a rule set that confines the agent to the
   proxy port and still allows replies to inbound connections:
   ```
   -A OUTPUT -m owner --uid-owner <agent> -m conntrack --ctstate ESTABLISHED -j ACCEPT
   -A OUTPUT -o lo -p tcp --dport <proxy-port> -m owner --uid-owner <agent> -j ACCEPT
   -A OUTPUT -o lo -p tcp --dport <each other sidecar port> -m owner --uid-owner <agent> -j REJECT --reject-with tcp-reset
   -A OUTPUT ! -o lo -m owner --uid-owner <agent> -j REJECT
   (same with ip6tables)
   ```
   Add a requirement: "The proxy sidecar binds nothing on loopback except its listener. A
   broker client, admin or metrics endpoint uses a Unix socket in a proxy-only volume, or is
   rejected for the agent UID." Cite the measured broker bypass (F1). The agent's own
   loopback servers stay reachable, which is why this rejects named ports rather than
   allowing only the proxy port. (measured: F1, F2; the combined rule set as written is
   inferred: the two parts were measured in separate pods)
2. Add to the Option A cost column: "Inbound connections to agent-UID servers over the pod IP
   need the `ESTABLISHED` accept (measured: the handshake fails without it)", "the
   namespace needs PSA `privileged` for the `NET_ADMIN` init container (or a CNI plugin as in
   Istio CNI)", and "fails closed: without `NET_ADMIN` the pod never leaves Init".
3. State the pod settings Option A depends on: `shareProcessNamespace: false`, distinct
   UIDs, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]` on both long-running
   containers, no `fsGroup` (it would give the agent the Secret's group), and the Secret
   mounted only into the proxy. Add "measured on k3s + kube-router: rules live in the pod
   netns, survive app-container restarts, are reinstalled on pod recreation".
4. Replace the kiro-cli note with the measured result: "Under the Option A deny, kiro-cli 2.37
   starts and completes chat and ACP turns, with no startup delay. With telemetry on, it
   lingers about 4 s at exit (n=1). Set `KIRO_DISABLE_TELEMETRY=1` in the platform-written
   environment. The semantic-search embedding download from `desktop-release.q.<region>` fails
   in both modes, so that feature is degraded unless the model is pre-seeded or the proxy
   routes that host."
5. Add a DNS line: "Option A blocks DNS for the agent UID too (UDP `EPERM`, TCP refused). That
   is intended: base URLs are IP-literal loopback, and port 53 would be an exfiltration path.
   Any name-based allowlist from openab-pty#47 must resolve names on the proxy or egress side,
   not reopen kube-dns to the agent."
6. Under Notes, add the measured breakage list for openab-pty#47: git and curl over HTTPS fail
   immediately, pip after about 8 s, cargo after about 11 s, npm after about 71 s. All of them
   fail at DNS.
7. Add a tampering line: "An agent that rewrites or deletes the platform-written settings gets
   no service. kiro-cli fails after about 44 s of retries, and the surrogate sent directly to
   the real service is rejected ('Invalid token'). The platform rewrites the settings when the
   container restarts, but not mid-session."
8. Add an IPv6 line: "Keep the ip6tables rule. On IPv4 single-stack clusters it is inert, because
   IPv6 fails at routing. On dual-stack clusters it is what blocks the agent."
9. Change "Current direction … being validated on a test cluster" to "validated on k3s +
   kube-router (Phase 0, p1-egress-a)", once the edits above are accepted.

## Not covered

- Dual-stack clusters (only simulated with an on-link test address).
- A real remote broker. The loopback mock broker is what made F1 visible.
- PSA enforcement and Istio-CNI-style alternatives (not tested).
- Repeat timings: the telemetry-on run is n=1.

## Cleanup

Done after the report was approved. Other namespaces on the test node were not touched (the
`openab-pty` namespace still had its 5 pods afterwards).

| Item | Action | Verification |
|---|---|---|
| Namespace `auth-proxy-spike` (pods `ap-a`, `ap-b`, Secret `ap-kiro`) | `kubectl delete ns --wait` | `kubectl get ns \| grep -c auth-proxy-spike` → 0 |
| containerd image `localhost/ap-spike-p1:dev` | `k3s ctr -n k8s.io images rm` | `ctr -n k8s.io images ls -q \| grep -c ap-spike` → 0 |
| podman images `localhost/ap-spike-p1:dev`, `ubuntu:24.04` (pulled for the build) | `podman rmi` (5 layers deleted) | `podman images \| grep -cE 'ap-spike\|ubuntu:24.04'` → 0; dangling images created in the last day → 0 (older dangling images predate the spike and were left alone) |
| Work dir on the test node (build context, cargo `target/`, `results/`, 527 MB) and `/tmp/apfmt.*` | `rm -rf` | `ls` → no such file, for both |
| Build host | nothing was created | no `auth-proxy` checkout, 0 `ap-*` entries in `~` or `/tmp` |

Key scan: the real key was read into a variable on the test node inside the same command, and
only match counts and file names were printed. Laptop data was streamed to the node through a
tar pipe and grepped there per file, so nothing was written on the node; the scan script was
deleted afterwards.

| Scope | Files containing the key |
|---|---|
| Test node: `/tmp`, `/var/tmp`, home directory (except the source `.env`) | **0** |
| Laptop: `auth-proxy` working tree, including `.agents/` and `.git/` | **0** |
| Laptop: `git log -p --all` of `auth-proxy` (all refs, including `spike/p1-egress-a/results/`) | **0** |
| Laptop: `/tmp/ap-diff.txt` (left over from an earlier exp2 review, not this spike) | **0** |
| Laptop: agent session transcripts modified in the last 4 h | **1** file, in the experiment session (the `bash -x` incident above). Not a work dir; rotate the key |
