# Evidence: runtime container hardening on a real k3s node (issue #24)

Settings and rules: README "Runtime container hardening".

## Setup

- Node: one single-node k3s v1.36.2 host (Ubuntu 24.04, amd64, AppArmor enabled). Namespace `ap-hard`, PSA `privileged`.
- Pod: `deploy/k8s/pod.yaml` at the commit under test. Test-only edits: namespace name, `storageClassName: local-path`, image references (`imagePullPolicy: Never`), and a `sleep infinity` command for the agent. No `securityContext` line was touched.
- Binaries: `cargo build --release --locked -p ap-proxy -p ap-egress -p ap-runtime-shim -p ap-netprobe` on the node, with a throwaway `CARGO_HOME` and target directory. Images built on a separate macOS builder (`gcr.io/distroless/cc-debian12` for the four Rust images as in `Containerfile`, `alpine:3.22` for `volume-prep`, `expiry-store-bootstrap`, `netinit` and `netcheck`, `alpine` plus curl for the agent), moved as a tar, imported with `ctr`.
- Secrets: random dummy values generated on the node; the seed and public key came from `openssl` (Ed25519). No value was printed.
- The runtime image is distroless and has no shell, so its process was inspected from the node through `crictl inspect` and `/proc/<pid>`. The agent was inspected through `kubectl exec`.

## Results

| Check | Result |
|---|---|
| Start | 6/6 containers ready, restarts 0. `volume-prep`, `netinit`, `expiry-store-bootstrap` exit 0. Proxy log: `netfilter self-check ready: ok`. Runtime log: `serving identity pty-team-a`. Proxy audit: `hello_challenge` 200, `hello` 201. |
| Runtime under the settings | From the agent (UID 1000) through `runtime.sock`: register 201, status lists the session, revoke 204, status empty. `POST /v1/hello` through `runtime.sock` 404. The proxy audit shows `register` 201. The runtime has `session-plane` mounted read-only (`ro,relatime` in its mountinfo), so connect, hello, register and renew work without write access to that directory. |
| Seccomp | Every container (init excluded, already exited) shows `Seccomp: 2`, `Seccomp_filters: 1`, `NoNewPrivs: 1`. The runtime ran hello, register, renew with no denial. No custom profile was needed. |
| Capabilities | Runtime, proxy, egress, netprobe, agent: `CapEff` and `CapBnd` 0000000000000000. `netcheck`: `0000000000001000` (`NET_ADMIN` only). Agent through `kubectl exec`: `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb` all zero. |
| Read-only root | Agent through `kubectl exec`: `touch /rootfs-probe` gives "Read-only file system", mountinfo `/` is `ro`; `/tmp` and `/home/agent` (emptyDirs) are writable. Runtime, proxy, egress, netprobe, netcheck: `touch /proc/<pid>/root/rootfs-probe` gives "Read-only file system". Runtime mounts: `/` ro, `/run/auth-proxy-session` ro, `/run/auth-proxy-agent` rw, `/var/run/auth-proxy-runtime` ro. A write to `/tmp`, to the seed directory and to `session-plane` in the runtime all fail with "Read-only file system". |
| Seed file | As seen by the runtime: `runtime_ed25519.seed` mode 444, owner 0:0 (kubelet-written, `..data` symlink). In the agent container: `cat /var/run/auth-proxy-runtime/runtime_ed25519.seed` gives "No such file or directory", `find / -name 'runtime_ed25519*'` finds nothing, `/var/run/auth-proxy-runtime` is not in its mountinfo, `/run/auth-proxy-session` does not exist. Scan of the agent's process environments and its writable paths for the seed and the credential: 0 hits. The seed's protection is the missing mount, not the file mode. |
| PID namespace | Runtime and proxy are in different PID namespaces and the same network namespace. The agent sees 5 PIDs (its own). |
| AppArmor | containerd's default profile is applied with no field set: `/proc/<pid>/attr/current` of every container reads `cri-containerd.apparmor.d (enforce)`. A test pod with `appArmorProfile: {type: RuntimeDefault}` reads the same; one with `Unconfined` reads `unconfined`. The manifest does not set the field, because a node without AppArmor refuses it; the validator refuses `Unconfined`. |
| Black-box pod checks | Agent: proxy gate answers `403 surrogate_missing`; egress listener `405`; other loopback ports refused (curl exit 7); direct `https://<ip>` refused (exit 7); DNS "no servers could be reached". Log scan of all seven containers for the credential, caller key and seed: 0 hits. |
| Expiry store | Owned 1001:1001 mode 0600 (`runAsGroup: 1001` added to `expiry-store-bootstrap`). Same sha256 before pod delete, after delete and after recreate. The recreated pod reached 6/6 and got `hello` 201. |
| Grace period | `terminationGracePeriodSeconds: 10`. Pod delete to gone: 10.8 s. The binaries run as PID 1 with no SIGTERM handler, so deletion waits for the whole grace period; the default is 30 s. |

Not run: the sidecar and passthrough matrices on the node (they run on the build host, see the PR), the real upstream, and a node without AppArmor.

## Cleanup check

Snapshot before and after: namespaces, `ctr -n k8s.io images` listing, host `iptables -S OUTPUT`, PVs, home listing, tailscale status header.

```
namespaces                 : default kube-node-lease kube-public kube-system openab  (same)
ctr images md5 / count     : <md5> / 44, before and after
host iptables OUTPUT md5   : <md5> before and after
PV listing md5             : <md5> before and after
home listing md5           : <md5> before and after
tailscale                  : state never touched; header identical
build directory, scripts   : removed from the node's temp directory
crictl containers (all)    : 13 before, 14 after: one exited local-path `helper-pod` in kube-system (the claim cleanup), garbage-collected by the kubelet
```

Created and removed: namespace `ap-hard` (pod, claim and its volume, Secrets, ConfigMap), the seven imported image names and the seven index entries the import added, the build and run directories on the node, and the builder's image context.
