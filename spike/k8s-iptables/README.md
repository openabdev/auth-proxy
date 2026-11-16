# Phase 1 K8s combined iptables verification (Q3-E2)

Test assets for `docs/verification/phase1-k8s-iptables.md`. Spike code, not shipped.

| File | Role |
|---|---|
| `Containerfile.runtime` | Test-only images `proxy`, `egress`, `agent` (ubuntu 24.04, glibc binaries, curl/git/pip/npm/cargo). The netinit image is `deploy/k8s/Containerfile` unmodified. |
| `setup.sh` | Node-side: namespace (PSA privileged), dummy Secret, policy ConfigMap, and `deploy/k8s/pod.yaml` with only image names and two netinit test env vars substituted. |
| `agent-battery.sh` | Check battery, run with `bash -s` inside a pod container as that container's UID. Sections: `rules`, `noproxy`, `refused`, `via-egress`, `ignore`, `uid`. |
| `run-tests.sh` | Node-side driver: decoy loopback listeners, all sections, inbound/ESTABLISHED check, rule counters from the pod netns. |
| `extras.sh` | ESTABLISHED negative control (rule removed and restored in the test pod's netns) and cluster DNS latency. |
| `probe.py` | Copy of `spike/k3s-egress-a/probe.py` (TCP/UDP/DNS probe). |
| `results/` | Raw output of the reported run (`run1-initial/` is the first run, kept because it hit a transient upstream timeout and had two script flaws, see the report). Public upstream addresses and the node's pod-network gateway are replaced by labels. |

Order: build the two binaries on an x86_64 Linux host (`cargo build --release -p ap-proxy -p ap-egress`),
build and import the four images into k3s containerd (`k3s ctr -n k8s.io images import`), run
`setup.sh`, `run-tests.sh`, `extras.sh`, then delete the namespace and the imported images.
