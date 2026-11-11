# auth-proxy

## How it works

An agent never holds a real credential. It sends requests to a loopback proxy with a caller key
and a surrogate. The proxy checks both, applies one real credential, and forwards the request
over TLS. A runtime registers each session's surrogate with the proxy over a Unix socket, and it
proves its identity to the proxy with a signature only it can make. Non-model traffic such as git
goes through a separate allowlisting CONNECT proxy.

```mermaid
flowchart LR
    agent["Agent CLI<br/>caller key + surrogate only"]
    runtime["Runtime<br/>ap-runtime-shim, holds the hello proof"]
    egress["ap-egress<br/>CONNECT allowlist"]
    git["git, registries"]
    upstream["Model API<br/>over TLS"]

    subgraph proxy["ap-proxy (loopback)"]
        direction TB
        check["Caller check<br/>and canonicalize"]
        lookup["Per-identity policy<br/>and surrogate lookup"]
        swap["Credential swap"]
        audit["Audit line"]
        check --> lookup --> swap --> audit
    end

    subgraph broker["ap-broker"]
        registry["Session registry<br/>lease, resync, revoke"]
        expiry[("Expiry store<br/>durable volume, fail closed")]
        store[("Credential files<br/>proxy-only mount")]
    end

    agent -- "runtime.sock<br/>register, revoke, status" --> runtime
    runtime -- "session.sock<br/>hello with proof, register, renew" --> registry
    registry --> expiry
    agent -- "base URL on loopback" --> check
    lookup --> registry
    swap --> store
    swap -- "TLS" --> upstream
    agent -- "CONNECT" --> egress
    egress --> git
```

## Features

Implemented and tested in Phase 1:

- Caller-key routing and surrogate credential swap ([design](docs/design/phase1.md))
- Runtime proof for `hello`: Ed25519, the seed held by the runtime container only ([session plane](docs/session-plane.md))
- Agent-runtime socket: the agent registers, revokes and reads status through the runtime, and nothing else ([session plane](docs/session-plane.md))
- Per-identity TOML policy with fail-closed checks ([design](docs/design/phase1.md))
- Canonicalization, and refusal of ambiguous hosts and paths
- 12 h absolute session TTL, lease renewal, and synchronous revoke ([session plane](docs/session-plane.md))
- Absolute expiry persisted across proxy restarts; the proxy fails closed without the store ([session plane](docs/session-plane.md))
- Resync with an explicit `expired` list ([session plane](docs/session-plane.md))
- ap-egress CONNECT allowlist; ap-egress resolves DNS itself and refuses private and IP-literal targets
- File-backed credential store that re-reads a file when it changes
- Kubernetes pod with per-UID iptables (Option A) and separate volumes ([pod.yaml](deploy/k8s/pod.yaml))
- 41-row fail-closed matrix, run by the manual-dispatch CI workflow ([matrix](tests/matrix/matrix.py))

## Todos

- ECS / Fargate deployment (Option C): deferred to a later phase
- Secrets Manager store (S2): deferred with ECS
- Phase 2 TLS interception (CONNECT with CA): no current CLI needs it
- Runtime-proof for `hello`: only the target is documented; same-UID processes can still read the proof
- Connection cap for ap-egress: every connection spawns a task
- Pruning of expiry records: pruning would let a re-registered key reset its 12 h cap
- 12 h absolute TTL has no config key: it is a fixed default
- Matrix positive rows run against a feature-enabled test binary, not the release binary
- Live run of the K8s pod on a cluster is not in CI: the validator checks the manifest only

## Kubernetes deployment (Option A)

One pod runs four app containers (agent, runtime, proxy, egress) and three init containers
(volume-prep, netinit, expiry-store-bootstrap). The agent reaches the proxy and egress over
loopback, and the runtime over its own Unix socket. It has no path to the session socket, and it
cannot read the proxy's credential Secret or the runtime's proof seed.

Measured so far: a single-node k3s run measured the pod before the runtime container existed, with
the agent, the proxy and the netinit rules. The runtime container, the socket permissions and the
proof path are not yet measured on a cluster. The egress container and the expiry store in
`pod.yaml` were not part of that run either. ECS is not done yet.

```mermaid
flowchart TB
    subgraph pod["Pod auth-proxy-phase1, shareProcessNamespace false"]
        volprep["init volume-prep<br/>root, CHOWN only<br/>sets socket directory owners"]
        netinit["init netinit<br/>root, NET_ADMIN only<br/>per-UID iptables and ip6tables"]
        bootstrap["init expiry-store-bootstrap<br/>UID 1001"]
        agent["agent<br/>UID 1000, read-only root fs"]
        runtime["runtime<br/>UID 1002, ap-runtime-shim, no network"]
        proxy["proxy<br/>UID 1001, loopback port 18080"]
        egress["egress<br/>UID 1003, loopback port 18081"]
        agentrt[("agent-runtime emptyDir<br/>runtime.sock, agent and runtime")]
        session[("session-plane emptyDir<br/>session.sock, proxy and runtime")]
        proof[("Secret auth-proxy-runtime-key<br/>runtime only, read-only")]
        tokens[("proxy-tokens emptyDir<br/>proxy only")]
        store[("expiry-store PVC<br/>proxy only")]
        kiro[("Secret auth-proxy-kiro<br/>proxy only")]
        callerkey[("Secret auth-proxy-caller<br/>agent, read-only")]
        cfg[("ConfigMap auth-proxy-identity<br/>proxy and egress, read-only")]
    end
    model["Model API<br/>over TLS"]
    git["git, registries<br/>allowlist"]

    volprep -. "owners and modes" .-> agentrt
    volprep -. "owners and modes" .-> session
    netinit -. "rules for UID 1000 and 1002" .-> agent
    bootstrap -- "creates store file once" --> store
    agent -- "loopback 18080" --> proxy
    agent -- "loopback 18081" --> egress
    agent -- "register, revoke, status" --> agentrt
    runtime --- agentrt
    runtime -- "hello with proof, register, renew" --> session
    proof --- runtime
    proxy --- session
    proxy --- tokens
    store --- proxy
    kiro --- proxy
    callerkey --- agent
    cfg --- proxy
    cfg --- egress
    proxy -- "one credential swapped" --> model
    egress -- "CONNECT" --> git
```

- **Loopback rules:** netinit lets UID 1000 reach only ports 18080 and 18081 on loopback. Any other
  packet from that UID that leaves loopback is rejected. Replies on established connections stay
  allowed. The rules repeat for IPv6. Without them, the agent could reach the sidecar's internal
  ports and read the real credential, which the k3s run measured. UID 1002 (the runtime) gets
  replies on established connections and nothing else, since its sockets are all Unix sockets.
- **Runtime split:** the agent holds no hello proof and no route to `session.sock`. Its one
  session-plane path is `runtime.sock`, which serves register, revoke and status. The socket
  directories are owned by the proxy and runtime UIDs and setgid, so the agent is in neither group
  that can connect to `session.sock` (mode 0660).
- **shareProcessNamespace is false:** the agent container cannot list or read the proxy's processes
  through `/proc`.
- **DNS is blocked for UID 1000:** the same reject rule drops the agent's DNS queries. Names resolve
  in the egress container.
- **NetworkPolicy alone is not enough:** containers in one pod share a network namespace, so a
  NetworkPolicy sees one pod address and cannot tell agent traffic from proxy traffic. The per-UID
  iptables owner match is what separates them.
- **Names come from `deploy/k8s/pod.yaml`:** container, volume and port names match that file.
  Image references are placeholders until a release pins digests.
