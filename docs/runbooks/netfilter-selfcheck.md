# Netfilter self-check (sidecar profile)

Issue #20. In the Kubernetes pod the agent UID is kept off the network by owner-match rules that
the `netinit` init container installs. If those rules are missing or ineffective (init skipped, a
rule flushed, a changed UID mapping, a lost capability) the boundary is gone, and before this check
the proxy kept serving. Now it fails closed.

Single-host and passthrough deployments (a loopback listener behind a private-network TLS front, no
per-UID rules) are out of scope and unchanged. The check exists only when the proxy is started with
the `--netfilter-*` flags, and a passthrough-only config refuses to start with them.

## What is checked

Two checks, run by two containers, because the proxy container has no Linux capability and must not
get one.

| Check | Container | Privilege | What it does |
|---|---|---|---|
| Rule presence | `netcheck` | root, `NET_ADMIN` only | Compares `iptables -S OUTPUT` and `ip6tables -S OUTPUT` with the snapshot `netinit` wrote when it installed the rules. Any difference (a missing, extra, reordered or changed rule, or a changed default policy) fails. |
| Functional probe | `netprobe` | agent UID, no capability | Runs as UID 1000, so the rules apply to it exactly as to the agent. Tries a TCP connect to a loopback port that is not the proxy or egress port, a TCP connect to a routable non-loopback address (`192.0.2.1:443`, TEST-NET-1, never answered), and a UDP DNS query to the first resolver in `/etc/resolv.conf`. Each must be refused: a refused connect, or for UDP a send that fails with a permission error (what a local `REJECT` returns for UDP, measured on k3s). A refusal can also come from the network (a CNI policy or an upstream `REJECT`), so the loopback leg, which nothing outside the pod can answer, and the exact rule comparison by `netcheck` carry the local guarantee. A connection, a reply, a timeout or any other error fails. |

Each container writes one line to its own status file every interval (default 30 s):

```
tick=<token> state=ok|fail reason=<code>
```

`tick` changes on every write. Reason codes are fixed strings:

- `netcheck`: `ok`, `expected_missing` (no snapshot), `rules_unreadable` (the call failed or timed out), `rules_changed`.
- `netprobe`: `ok`, `loopback_open`, `egress_open`, `dns_open` (the attempt got through), `loopback_unexpected`, `egress_unexpected`, `dns_unexpected` (anything other than a refusal, such as a timeout or no route).

## What the proxy does

The proxy mounts both status volumes read-only and reads them once a second. The gate is open only
when both files parse, both say `ok`, and both ticks keep changing.

| Situation | Gate | Reason in the log |
|---|---|---|
| Proxy just started, no status yet | closed (`unverified`) | `rules:missing`, `probe:missing` |
| A checker reports `fail` | closed (`failed`) | `rules:rules_changed`, `probe:egress_open`, ... |
| A checker stops writing (killed, hung, crashed) | closed after `2 * interval + 5 s` | `rules:stale`, `probe:stale` |
| A status file is deleted, empty, malformed or has extra fields | closed | `rules:missing`, `rules:malformed` |
| Both healthy again | open, automatically | `ready` |

A status file left over from a dead checker is aged by its modification time on first sight, so a
restarted proxy does not trust a stale `ok`.

While the gate is closed:

- the agent listener answers every request with `503`, header `X-AP-Decision: unavailable`, body `{"ap_decision":"unavailable","code":"netfilter_unverified"}`, and closes the connection. Nothing is sent upstream;
- `GET /admin/v1/ready` on the admin socket returns `503` with the state and reason, and the Kubernetes readiness probe (`auth-proxy --check-ready`) fails, so the pod leaves its Service endpoints;
- the session socket and the admin socket stay up, so `revoke-all` still works during an incident.

Nothing restarts the proxy: there is no liveness probe on the self-check, because restarting the
proxy cannot bring netfilter rules back. Recovery is automatic once the checks pass.

## Log lines

On a state change the proxy writes one audit line and one stderr line. Neither holds a request,
identity, path or secret, only fixed codes:

```
{"event":"netfilter","state":"failed","reason":"probe:egress_open"}
auth-proxy: netfilter self-check failed: probe:egress_open
```

Each refused request writes:

```
{"event":"netfilter","decision":"deny","code":"netfilter_unverified","status":503}
```

`state` is `unverified` (never healthy since start), `failed` (healthy once, then not) or `ready`.

## Reading the failure

1. `kubectl logs <pod> -c proxy | grep netfilter` gives the reason. Then the container named in it: `-c netcheck` or `-c netprobe` prints its failure on stderr.
2. `rules:rules_changed`: the live chain differs from the snapshot. Compare `kubectl exec <pod> -c netcheck -- iptables -S OUTPUT` with `kubectl exec <pod> -c netcheck -- cat /run/netinit/expected-iptables`. Restart the pod to reinstall the rules; the init container is the only thing that installs them.
3. `probe:*_open`: the rules do not stop the agent UID. Treat it as a boundary failure, not a flake.
4. `probe:*_unexpected`: the probe saw something other than a refusal. A pod with no default route, or a resolver address that cannot be routed, lands here. The check fails closed.
5. `*:stale` or `*:missing`: the checker is not running. `kubectl get pod` shows its restart count.

## Design note: where the check runs

The hard constraint is that the proxy container gets no new capability. Reading netfilter rules
needs `CAP_NET_ADMIN`, so the proxy cannot do it. Options considered:

| Option | Privilege added | Verdict |
|---|---|---|
| Proxy reads the rules itself | `NET_ADMIN` on the container that holds the credential | Rejected: breaks the constraint, and a proxy compromise could rewrite the rules. |
| Keep `netinit` alive as a native sidecar (init container with `restartPolicy: Always`) | `NET_ADMIN` for the pod's life, in the container that also installs the rules | Not chosen: needs Kubernetes 1.29 or later and changes init ordering, and the functional probe still needs a separate container at the agent UID. |
| Functional probe only (`netprobe`) | None | Not enough alone: it does not see ip6tables, the runtime UID rules or a partly removed rule set. Kept as the second check. |
| Probe from the proxy container | None | Meaningless: the proxy UID is not the confined UID. |
| **`netcheck` regular container plus `netprobe` at the agent UID** | `NET_ADMIN` in one extra long-running shell script container; nothing on the proxy | **Chosen.** |

Chosen design, compared on the points that matter:

- **Privilege added.** `NET_ADMIN` in `netcheck` only, a `/bin/sh` loop with no listener, no Secret and no input except a read-only snapshot. The namespace is already PSA `privileged` for `netinit`. `netprobe` has no capability. The proxy, agent, runtime and egress containers add none, and the manifest validator asserts it.
- **Blast radius.** The checkers can write only their own status volume. One volume per writer, so neither can replace the other's file. The proxy reads both read-only. The agent, runtime and egress containers mount neither, so the agent cannot forge an `ok`. A compromised `netcheck` could change rules, which is the same power `netinit` already had at pod start; it has no inbound channel to reach it.
- **Failure modes.** The only way to an open gate is two fresh, healthy, ticking files. A checker that dies or hangs stops its tick and the gate closes after `2 * interval + 5 s`. A checker that restarts resumes by itself. A wrong or missing snapshot fails `rules_changed` or `expected_missing`.
- **Startup race.** Regular containers start after every init container, so the rules exist before the checkers run. The proxy may start first, and it is closed until both files exist, so the order does not matter.
- **Checker death.** Counts as failure (fail closed), as above.

## Limits

- Detection takes up to one interval plus the proxy's 1 s poll. A rule removed just after a check runs is open until the next one. Lower `INTERVAL` for a tighter window; each check costs two `iptables` calls and three probe attempts.
- Only the `filter` `OUTPUT` chain is compared, which is what `netinit` manages. Rules in other tables or chains are not.
- The functional probe covers IPv4 loopback, IPv4 TCP and one resolver. An IPv6-only gap is caught by the `ip6tables` comparison, not by the probe.
- The probe sends one SYN to `192.0.2.1` and one DNS query to the resolver only when the rules are missing. Nothing is sent when they work, because the local reject comes first.

## Configuration

Proxy flags (all in the manifest):

| Flag | Meaning |
|---|---|
| `--netfilter-rules-status <file>` | Status file written by `netcheck`. |
| `--netfilter-probe-status <file>` | Status file written by `netprobe`. |
| `--netfilter-interval-secs <n>` | The checkers' interval, 1 to 3600, default 30. The stale limit is `2n + 5` seconds. |
| `--netfilter-rules-uid <uid>` | The only owner accepted for the rules status file. Default 0 (`netcheck` runs as root). |
| `--netfilter-probe-uid <uid>` | The only owner accepted for the probe status file. Default 1000 (`netprobe` runs as the agent UID). |

Both status flags go together; with neither, there is no gate. Keep the interval the same in
`netcheck` (`INTERVAL`), `netprobe` (`--interval-secs`) and the proxy flag. The manifest validator
checks that the three agree.

## Status files are untrusted input

The agent UID shares the pod, so the proxy does not trust a status path just because it is mounted.
Each file is opened with `O_NONBLOCK` and `O_NOFOLLOW`, then the opened descriptor is checked. It
must be a regular file, owned by the expected UID, not writable by group or world, and at most 512
bytes. A FIFO, socket, directory, symlink, device, oversized file or wrong owner counts as a failing
check (`503 netfilter_unverified`, not ready). Reads run on a blocking thread with a 2 s deadline, so
no status path can stall a worker or the admin socket. The gate also closes by itself
(`gate:stale`) if the monitor stops publishing for 5 s. A file whose age is unknown is stale until a
new tick arrives.

Write surface in the pod (the manifest validator asserts each point):

- The agent UID (1000) mounts neither status volume. It can write only `home`, `work`, `tmp` and the
  `agent-runtime` socket directory. It cannot create, replace or link anything in either status
  volume.
- `netcheck-rules` is writable only by `netcheck` (root). `netcheck-probe` is writable only by
  `netprobe` (UID 1000, the agent UID, but a separate process that mounts nothing else). The proxy
  mounts both read-only. Both are `emptyDir`; there is no `hostPath` volume and no `fsGroup`.
- Files are created with mode 0644, so the owner check and the no-group/world-write rule hold.

## Interaction with the Muse gate (holds and approvals)

The netfilter gate and the hold table never run in the same process. The gate belongs to the sidecar
profile, where the agent shares the pod with per-UID egress rules. Holds, the approval listener and
the notifier belong to a passthrough-only config (the Muse gate), which has no per-UID rules. A
passthrough-only config started with any `--netfilter-*` flag exits with status 2 (covered by
`passthrough_config_with_the_netfilter_check_exits_with_status_2`), so no process can park a request
in a world where the check is failing, and no approval can be granted into one. The fail-closed
choice is therefore enforced at startup: the combination is refused, not degraded. Passthrough and
single-host runs without the flags are unaffected by the gate. In the sidecar profile the admin socket
and `/ready` stay responsive while the gate is closed; only the agent listener answers
`503 netfilter_unverified`.
