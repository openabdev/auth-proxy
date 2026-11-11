# auth-proxy

## How it works

An agent never holds a real credential. It sends requests to a loopback proxy with a caller key
and a surrogate. The proxy checks both, applies one real credential, and forwards the request
over TLS. A session authority registers each session's surrogate over a Unix socket. Non-model
traffic such as git goes through a separate allowlisting CONNECT proxy.

```mermaid
flowchart LR
    agent["Agent CLI<br/>caller key + surrogate only"]
    authority["Session authority<br/>ap-client"]
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

    authority -. "spawns child with surrogate" .-> agent
    authority -- "Unix socket<br/>hello, register, renew" --> registry
    registry --> expiry
    agent -- "base URL on loopback" --> check
    lookup --> registry
    swap --> store
    swap -- "TLS" --> upstream
    agent -- "CONNECT" --> egress
    egress --> git
```

Implemented:

- Caller key and surrogate checks, canonicalization, per-identity policy, credential swap, and
  audit lines that never contain a key, surrogate, or credential.
- Session plane over a Unix socket: `hello` lock on Kubernetes, register, renew, resync, and
  revoke. Each session has an absolute TTL of 12 h, stored durably. The proxy fails closed when
  the expiry store is not writable.
- Credentials read from files in a proxy-only mount, re-read when the file changes.
- ap-egress: CONNECT allowlist, DNS resolved by ap-egress itself, and refusal of private
  addresses and IP-literal targets.

Not implemented:

- ECS/Fargate deployment
- Secrets Manager credential store
- Phase 2 TLS interception
- Runtime-proof `hello` (today `hello` takes only an identity name)
- Connection cap in ap-egress
- Pruning of expiry records (records are never removed)
