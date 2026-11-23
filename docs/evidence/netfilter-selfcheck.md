# Evidence: netfilter self-check on a real k3s node (issue #20)

Design and operation: [docs/runbooks/netfilter-selfcheck.md](../runbooks/netfilter-selfcheck.md).

## Setup

- Node: one single-node k3s v1.36.2 host (Ubuntu 24.04, amd64). Namespace `ap-nfcheck`, PSA `privileged`.
- Pod: `deploy/k8s/pod.yaml` at the commit under test, with test-only edits: namespace name, `storageClassName: local-path`, image references (three locally built images, `imagePullPolicy: Never`). Default interval 30 s, so the stale limit is 65 s.
- Binaries: `cargo build --release --locked` on the node, with a throwaway `CARGO_HOME` and target directory. Images built on a separate macOS builder (linux/amd64: `ubuntu:24.04` for the Rust binaries, `alpine:3.22` plus iptables for `netinit` and `netcheck`, `alpine` plus curl as the agent), moved as a tar and imported with `ctr`.
- Secrets: random dummy values generated on the node. The real credential is a dummy. No value was printed.
- The agent container runs `sleep`; requests are made with `kubectl exec -c agent` as UID 1000 against `127.0.0.1:18080`. A request through a healthy proxy reaches the policy step and gets `403 surrogate_missing` (no surrogate is sent), which proves the pipeline is serving. A closed gate gives `503 netfilter_unverified`.
- Rules are removed and restored from inside the pod with `kubectl exec -c netcheck` (it has `NET_ADMIN`). Restore replays the snapshot `netinit` wrote.

## Findings during the run

- The first real run showed `probe:dns_unexpected`. In a pod, a UDP `send` into the local `REJECT` returns `EPERM` rather than an ICMP-driven `ECONNREFUSED` (TCP connects return `ECONNREFUSED`). The probe now counts a permission error on the UDP send as a local refusal, with a unit test, and the probe logs what it saw (`send: PermissionDenied, recv: ok`).

## Results

All times are from the node clock. "Request" is `GET /ap/<caller key>/kiro-krs/` through the agent container.

| Step | Action | Result |
|---|---|---|
| A. Baseline | Pod up, rules in place | 6/6 containers Ready. Request: `403 surrogate_missing` (policy pipeline answers). `auth-proxy --check-ready` exit 0, kubelet `proxy.ready=true`. As UID 1000: `curl https://<ip>` fails (`http=000`), `nslookup` "no servers could be reached". `ap-netprobe --once`: loopback Refused, egress Refused, dns Refused. |
| Startup | Proxy log from a fresh pod | `unverified: starting`, `unverified: rules:missing`, then `ready: ok` about 1 s later, when the first status files appeared. |
| B. Remove all rules (`iptables -F OUTPUT; ip6tables -F OUTPUT`) | | Proxy audit line `{"event":"netfilter","reason":"rules:rules_changed","state":"failed"}` 4.6 s after the removal (that is where the removal fell in the 30 s cycle; the worst case is one interval plus the 1 s poll). Request: `503`, `x-ap-decision: unavailable`, `connection: close`, body `{"ap_decision":"unavailable","code":"netfilter_unverified"}`. `--check-ready` exit 1. Kubelet showed `proxy.ready=false` 10.1 s after the removal (pod 5/6, `Ready=False`; the exec probe runs every 5 s). With the rules gone the agent boundary really was open: `nslookup example.com` resolved. `ap-netprobe --once`: loopback Open, dns Open, `reason=loopback_open`. |
| C. Restore the snapshot | | Request back to `403 surrogate_missing` 24.1 s after the restore (one `netcheck` interval). Kubelet `proxy.ready=true` after 27.8 s. Agent direct egress refused again. |
| D. Remove only the IPv6 rules | | The IPv4 probe stays `ok`. `netcheck` catches it: `rules:rules_changed`, request `503` after 24.0 s. Restore: `403` after 30.0 s. |
| E. `netcheck` hangs (container frozen with `ctr tasks pause`) | | The status line stops ticking. Gate closed after 65.8 s (limit 65 s): `{"event":"netfilter","reason":"rules:stale","state":"failed"}`. Resumed: request served again 0.5 s later. |
| F. `netinit` skipped (init container does nothing: no rules, no snapshot) | Fresh pod, 75 s | Never ready: pod 5/6, request `503`, `--check-ready` exit 1, proxy log `unverified` with `rules:missing`, then `rules:expected_missing`. `netcheck: fail: expected_missing`. `netprobe: fail: loopback_open: loopback Open ...; dns Open`. |
| Secret scan | Logs of proxy, netcheck, netprobe, agent | 0 hits for the dummy credential and the caller key. |

Every transition in B to E reopened automatically. No container restarted: restarts stayed at 0.

## Cleanup check

Snapshot before and after (`namespaces`, pods, `ctr -n k8s.io images`, listening sockets, tailscale header, home and cargo listings, container count, host `iptables -S OUTPUT`, disk):

```
namespaces                : default kube-node-lease kube-public kube-system openab  (same)
ctr images md5            : <md5> before and after
crictl containers         : 13 before, 13 after
host iptables OUTPUT md5  : <md5> before and after
home listing md5          : <md5> before and after (cargo dir untouched)
iptables rules naming the test: 0; matching processes: 0; PVs: 1 before (not ours), 1 after
tailscale                 : state never touched; header identical
```

Created and removed: namespace `ap-nfcheck` (pod, claim, Secrets, ConfigMap), the three imported images and the six index entries the import added, the build directory and tar files on the node, the images and context on the builder. The only other differences between the snapshots are other tenants' activity on the node: peers' online status in the tailscale listing, and `/tmp/oab-jobs-*` directories created by an unrelated service during the run.
