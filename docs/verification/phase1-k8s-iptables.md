PASS

# Phase 1 K8s combined iptables rule set (Q3-E2), one pod on real k3s

Verdict: **PASS**. The combined Option A rule set from `docs/design/phase1.md` Q3-E2, as shipped in
`deploy/k8s/netinit.sh` and `deploy/k8s/pod.yaml`, behaves as designed in one pod with the real
`auth-proxy` and `ap-egress` binaries and an agent-UID container. No bug found in the rule set or
the manifest; nothing in the repo was changed except the added test assets.
Date of run: 2026-11-16. Claim tags: [M] measured.

## Setup

| Item | Value |
|---|---|
| Node | x86_64 k3s node, Ubuntu 24.04, k3s v1.36.2, single node, flannel CNI, host iptables 1.8.9 nf_tables in the netinit image |
| Pod | `deploy/k8s/pod.yaml` applied as is, with three test-only substitutions (see below), namespace labelled PSA `privileged` |
| Containers | `netinit` (root, `NET_ADMIN` only, UID 0), `proxy` (UID 1001, real `auth-proxy`), `ap-egress` (UID 1002, real `ap-egress`), `agent` (UID 1000, `sleep infinity`) |
| Env on agent | `HTTPS_PROXY=http://127.0.0.1:3128`, `NO_PROXY=127.0.0.1,localhost` (from the manifest) |
| Ports | P = 18080 (auth-proxy), E = 3128 (ap-egress) |
| Policy | `deploy/k8s/policy.example.toml` with the placeholder caller-key hash replaced; `[egress].allow` = github.com, registry.npmjs.org, pypi.org, files.pythonhosted.org, index.crates.io, static.crates.io (all :443) |
| Secret | dummy value, mounted only into `proxy` |
| Builds | `auth-proxy` and `ap-egress` built with `cargo build --release --locked` on the node, with a throwaway `CARGO_HOME`/`CARGO_TARGET_DIR` under a temp directory (glibc, not musl, since the node has no musl target). Images built outside the node with docker (`--platform linux/amd64`), moved as tar to the node, imported with `k3s ctr -n k8s.io images import`. Nothing pushed to a registry. |

Test-only substitutions in `setup.sh` (everything else in `pod.yaml` is untouched):

1. The four `REPLACE/...:TAG` image placeholders point at the locally imported images
   (`netinit` is `deploy/k8s/Containerfile` unmodified; the other three are test images from
   `spike/k8s-iptables/Containerfile.runtime`, which add curl/git/pip/npm/cargo and differ only by ENTRYPOINT).
2. `netinit` gets `OTHER_PORTS=18190`, so the "other sidecar loopback port" rule has a port to act on.
   A decoy listener on 18190 is run as the proxy UID. A second decoy on 19999 is not listed.
3. `netinit` gets `TEST_V6_ADDR=fd00:a9::2/64`, the same test aid as the Phase 0 spike, so IPv6 has a
   non-loopback route and reaches OUTPUT.

All three containers were `ready`, 0 restarts (`results/01-pod-status.txt`).

## Rules installed (netinit log, `results/00-netinit.txt`)

```
-A OUTPUT -m owner --uid-owner 1000 -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A OUTPUT -o lo -p tcp -m tcp --dport 18080 -m owner --uid-owner 1000 -j ACCEPT
-A OUTPUT -o lo -p tcp -m tcp --dport 3128  -m owner --uid-owner 1000 -j ACCEPT
-A OUTPUT -o lo -p tcp -m tcp --dport 18190 -m owner --uid-owner 1000 -j REJECT --reject-with tcp-reset
-A OUTPUT ! -o lo -m owner --uid-owner 1000 -j REJECT --reject-with icmp-port-unreachable
```

`ip6tables` has the same five rules (`icmp6-port-unreachable` on the last).

## Results

### 1. Agent UID (1000): what the rules allow and block (`results/10-agent-rules.txt`)

| Probe as UID 1000 | Result | Time |
|---|---|---|
| TCP 127.0.0.1:18080 (auth-proxy, P) | connects | 0 ms |
| TCP 127.0.0.1:3128 (ap-egress, E) | connects | 0 ms |
| TCP 127.0.0.1:18190 (decoy, in `OTHER_PORTS`) | ECONNREFUSED (tcp-reset rule, 2 packets counted) | 0 ms |
| TCP 127.0.0.1:19999 (decoy, **not** in `OTHER_PORTS`) | connects | 0 ms |
| DNS, UDP to kube-dns | EPERM | 0 ms |
| DNS, TCP to kube-dns | ECONNREFUSED | 0 ms |
| `getaddrinfo github.com` | "Temporary failure in name resolution" | 2 ms |
| TCP 1.1.1.1:443, TCP to a literal github address :443, TCP to the node's pod-network gateway :22 | ECONNREFUSED | 0 ms |
| TCP6 to the test ULA route `fd00:a9::1` | ECONNREFUSED | 1042 ms (neighbour discovery on the test-aid prefix, then REJECT) |
| TCP6 to a public address | ENETUNREACH (no v6 route in this cluster; the ip6tables reject rule counted 4 hits from the ULA probes) | 0 ms |

Reading: the agent reaches exactly the two allowed loopback ports. DNS and every direct egress path
are closed, and refused immediately. The unlisted loopback port 19999 is reachable by design: the
rule set only rejects ports listed in `OTHER_PORTS`, and the design relies on the proxy binding no
other TCP port (`docs/design/phase1.md`, "config validation refuses any proxy listener on loopback
other than P"). Any future sidecar port has to be added to `OTHER_PORTS`.

### 2. Proxy UID (1001) and ap-egress UID (1002) are not confined (`results/60-other-uids.txt`)

Both UIDs: DNS over the system resolver succeeds, DNS over UDP to kube-dns answers, TCP to 1.1.1.1:443
and to a github address connects. TCP6 to a public address is ENETUNREACH (no v6 route, same as the
agent). So the per-UID rules confine only UID 1000, and `ap-egress` can resolve and dial upstream.

### 3. NO_PROXY and the loopback listener (`results/20-noproxy.txt`)

A tool given `HTTP_PROXY=http://127.0.0.1:3128` and fetching `http://127.0.0.1:18080/`:

| NO_PROXY | HTTP status | Meaning |
|---|---|---|
| `127.0.0.1,localhost` (as in the pod) | 404 | went straight to auth-proxy |
| unset | 405 | went to ap-egress, which refuses plain-HTTP proxy requests |

So `NO_PROXY` keeps auth-proxy traffic off `ap-egress`. A direct POST from the agent to
`/ap/<caller-key>/kiro-krs/` without a surrogate returns auth-proxy's own 403 `surrogate_missing`
(AWS-shaped body), which shows the agent reaches the real auth-proxy listener.

### 4. Only allowlisted hosts work through ap-egress

Allowlisted, with the pod's proxy variables (`results/40-via-egress.txt`, all exit 0):

| Check | Result | Time |
|---|---|---|
| curl https://github.com/ | 200 | 0.35 s |
| curl https://registry.npmjs.org/is-number | 200 | 2.25 s |
| curl https://pypi.org/simple/six/ | 200 | 3.64 s |
| curl https://files.pythonhosted.org/ | 404 (tunnel works, root path has no page) | 3.39 s |
| curl https://index.crates.io/config.json | 200 | 0.59 s |
| curl https://static.crates.io/ | 404 (same) | 0.70 s |
| git clone --depth 1 (github.com) | cloned | 0.55 s |
| npm install is-number (fresh cache) | added 1 package | 1.08 s |
| pip download six (no cache) | downloaded | 8.52 s |
| cargo fetch itoa (fresh CARGO_HOME) | downloaded | 1.25 s |

Not allowlisted or malformed (`results/30-refused.txt`), all refused by ap-egress in 0.01 s with
`CONNECT tunnel failed, response 403`: example.com, api.github.com (a subdomain of an allowed host),
runtime.us-east-1.kiro.dev (an auth-proxy route host), github.com:80, github.com:22, a literal github IP :443,
1.1.1.1:443, 127.0.0.1:18080 and localhost:18080 as CONNECT targets, gitlab.com via git. A plain-HTTP
proxy request returns 405. Raw `CONNECT` status lines: `github.com:443` 200; `example.com:443`,
`github.com:22`, literal IP and `127.0.0.1:18080` all 403.

### 5. Tools that ignore the proxy variables (`results/50-ignore-proxy.txt`)

Run as UID 1000 with all proxy variables unset and fresh caches. The kernel rejects at once; the
slow part is the tool's own retry loop.

| Tool | Exit | Time to fail |
|---|---|---|
| curl by name | 6 | 0.01 s |
| curl with `--resolve` to a literal github IP | 7 | 0.01 s |
| wget | 4 | 0.03 s |
| git clone | 128 | 0.02 s |
| python urllib | 1 | 0.08 s |
| getent hosts | 2 | 0.00 s |
| dig (UDP) | 9 | 0.02 s |
| nc to a literal IP (github, 1.1.1.1) | 1 | 0.00 s |
| pip download, `--retries 0` | 1 | 0.37 s |
| **pip download, default retries** | 1 | **7.89 s** |
| **cargo fetch, default retries** | 101 | **10.88 s** |
| **npm install, default retries** | 1 | **70.66 s** |

Slow-failure cost: curl, wget, git, python, getent, dig and nc fail in under 0.1 s. pip, cargo and
npm retry and cost 8 s, 11 s and 71 s before giving up. A runtime that wants quick feedback
should set `HTTPS_PROXY` (and tool retry knobs) rather than rely on the failure.

### 6. ESTABLISHED rule (`results/70-established.txt`, `results/90-extras.txt`)

An agent-UID listener on the pod IP answers a connection from outside the pod:

| Rule 1 (ESTABLISHED accept) | Result |
|---|---|
| present | reply received |
| deleted in the test pod's netns | timeout, no reply |
| restored | reply received |

This is the combined-set confirmation of the earlier separate-pod measurement [M k3s F1].
Rule counters from the pod netns (`results/80-counters.txt`): rule 1 502 packets, P 7, E 61,
port 18190 reset 2, final REJECT 100 (v6: 4); only UID 1000 traffic is counted.

## Observations that are not failures

1. **Transient upstream timeout in the first run** (`results/run1-initial/`): for a couple of minutes
   `curl https://github.com/` through ap-egress returned nothing after 10.01 s, and a raw
   `CONNECT github.com:443` returned `504 Gateway Timeout`. At that time a direct TCP connect from UIDs
   1001 and 1002 to one github address also timed out after 5 s, while the same address connected from the
   node and again a few minutes later. The second run was clean. ap-egress behaved as designed (10 s
   connect timeout, 504). This is upstream or Wi-Fi flakiness on the test LAN, not the rule set.
2. **Multi-second first lookups.** The 3 to 8 s times for pypi.org and pythonhosted.org come from the
   cluster resolver: as UID 1002 (no iptables rule applies) `getent` took 6.2 s then 2.2 s for pypi.org, and
   2.2 to 2.3 s on the first call for files.pythonhosted.org and index.crates.io, then 0.17 s.
   Not a rule-set effect (`results/90-extras.txt`).
3. **First run script flaws, fixed for the second run.** npm hit a warm cache (`npm-noproxy` returned
   success from cache), the plain-HTTP and loopback-target curl checks printed no status. The second
   run uses fresh cache directories and prints the status. Both runs are kept.
4. The pod's `NO_PROXY` lists only `127.0.0.1,localhost`. auth-proxy and ap-egress both bind IPv4
   loopback, so `[::1]` is not a target.

## Limits of this verification

- Binaries are glibc builds on Ubuntu 24.04, not the static musl release builds. The rule set does not
  depend on libc.
- IPv6 was exercised only through the test-aid ULA route and counters; public IPv6 was unreachable in
  this cluster, so "agent blocked from public IPv6" rests on the ip6tables rules and their hit counters.
- No CNI NetworkPolicy was in play (k3s default flannel), and the auth-proxy credential swap to a real
  upstream was not exercised: the credential is a dummy and the route hosts are placeholders. That is
  covered by the repo's own tests, not by this item.
- Phase 1 design doc line "the combined set is [I] until the Phase 1 k8s test runs it in one pod" can
  now be changed to [M]; left for the caller so parallel verification branches do not conflict on
  `docs/design/phase1.md`.

## Cleanup check (host left as found)

Commands run on the test node after the test, with output:

```
$ k3s kubectl delete ns <test namespace> --wait=true
namespace "<test namespace>" deleted
$ k3s kubectl get ns -o name
namespace/default  namespace/kube-node-lease  namespace/kube-public  namespace/kube-system  namespace/openab
   (identical to the list before the test)
$ k3s ctr -n k8s.io images rm --sync <4 test images + 3 dangling config digests created by my imports>
$ k3s ctr -n k8s.io images ls -q | grep -c ap-verify
0
$ ls -A ~ | md5sum                       # before: 573255538318e555fbedd46e38caa2ce
573255538318e555fbedd46e38caa2ce
$ iptables -S OUTPUT | md5sum            # host rules, before: 6aa9113fa8015deb4c7a93b5c2f03524
6aa9113fa8015deb4c7a93b5c2f03524
$ diff <(/tmp listing before) <(/tmp listing after)
36c36  (only an ssh-agent socket directory name, created by the ssh sessions themselves)
$ ls /tmp | grep ap-verify ; ps -eo args | grep -E "auth-proxy|ap-egress"
(no output)
```

- Temp directory on the node (source copy, build target, throwaway cargo home, image tars, results) removed.
- Image-build machine: the five test images removed from its docker; the temp build context deleted.
  Its docker build cache is shared with other work and was not pruned.
- Laptop temp files removed. No cargo or rustc ran on the laptop.
- The node's image count is 2 higher than at the start: `ghcr.io/openabdev/openab:0.9.0-beta.9-kiro`
  and its digest alias appeared during the window and are not from this test (another job on the same host).
- No tailscale state, systemd unit or host iptables rule was touched; all rules lived in the test pod's netns.
