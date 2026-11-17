# Option A on k3s: sidecar proxy + per-UID iptables (spike)

Spike code only. Validates RFC egress Option A on a single-node k3s test cluster
(kube-router, NetworkPolicy enforced): an init container with `NET_ADMIN` confines
the agent UID to `lo`, the proxy sidecar (spike/exp2 `ap-proxy`) is the only UID
that reaches upstream, and the platform writes kiro-cli's loopback base URLs
before kiro-cli starts. Report: `.agents/tasks/k3s-egress-a/report.md`.

| File | Role |
|---|---|
| `Containerfile` | One image for all three containers (ubuntu 24.04 + iptables, python3, git, npm, pip, cargo, kiro-cli 2.37, `ap-proxy`). Roles differ by UID, mounts and capabilities only. |
| `build.sh` | On the node: `cargo build --release` of spike/exp2, `podman build`, `podman save \| k3s ctr images import`. |
| `create-secret.sh` | Secret `ap-kiro` from `~/.env` by key name; the value only travels on a pipe to `kubectl --from-file=/dev/stdin`. |
| `pod-a.yaml` | Namespace + pod `ap-a`: `netinit` (root, `NET_ADMIN` only) → `proxy` (UID 1001, Secret mount) + `agent` (UID 1000, no Secret, no `KIRO_API_KEY`). `shareProcessNamespace: false`. |
| `pod-b.yaml` | Variant `ap-b`: the RFC draft's rule only, plus `ALLOW_INBOUND_REPLIES=1`, and `shareProcessNamespace: true`. |
| `netinit.sh` | The rules. `DENY_LO_PORTS` closes the sidecar's private loopback ports to the agent; `ALLOW_INBOUND_REPLIES` accepts `ESTABLISHED` agent packets; `TEST_V6_ADDR` (test aid) gives IPv6 a non-lo route so the ip6tables rule can be observed. |
| `proxy-entry.sh` | Proxy-side platform role: caller key (kept across container restarts), ap-proxy config/policy, mock broker on loopback holding the real key, surrogate mint, handoff to the agent, `exec ap-proxy`. |
| `agent-entry.sh` | Agent-side platform role: writes `~/.kiro/settings/cli.json` with the four `api.*.service` loopback endpoints, then idles. |
| `kiro-run` | Starts kiro-cli with the surrogate from the handoff dir. |
| `probe.py` | TCP/UDP/DNS egress probe (errno + time per target). |
| `chat_timed.py` | Times stdout chunks of `kiro-cli chat --no-interactive`. ACP uses spike/exp2 `test/acp_timed.py`. |
| `tamper.py` | Test 5: agent points cli.json at the real hosts / removes the keys / restores. |
| `scan-agent.sh` | Node-side: counts agent-visible processes and files holding the real key (counts only), with a positive control on the proxy's Secret mount. |
| `memread.py` | Test 6, as the agent: `/proc/<pid>/{environ,mem,maps,root/...}` of every other-UID process. |
| `lo_gap.py` | As the agent: can it reach the sidecar's broker port and resolve its own surrogate? Prints status, key names and length only. |
| `tools-break.sh` | Test 7: git clone, curl, npm, pip, cargo under the rule (and as UID 1001 for control). |
| `restart-test.sh` | Test 8: container restarts via `crictl stop`, pod recreation, and a pod without `NET_ADMIN`. |
| `results/` | Raw output of the runs in the report. |

Redactions in `results/`: cluster, pod and resolved upstream addresses are replaced by
labels (`<kube-dns>`, `<pod-ip>`, `<runtime.us-east-1.kiro.dev-v4>`, ...). The caller key and
surrogate never appear. `fd00:a9::/64` is a test-only ULA. During the runs the probes used
the literal kube-dns address; `probe.py` now also accepts `resolv` for it. Scripts added
after the image was built (`chat_timed.py`, `tamper.py`, `lo_gap.py`, `tools-break.sh`, and
the fixed `memread.py`) were piped into the containers on stdin.

Run order on the node: `build.sh`, `kubectl create ns auth-proxy-spike`, `create-secret.sh`,
`kubectl apply -f pod-a.yaml`, then the tests as listed in the report. Cleanup:
`kubectl delete ns auth-proxy-spike`, `k3s ctr -n k8s.io images rm localhost/ap-spike:dev`,
`podman rmi localhost/ap-spike:dev`, remove the work dir.
