## Placement and egress enforcement

auth-proxy keeps the real credential out of the agent's hands whether or not egress is enforced: an agent that bypasses the proxy only has a surrogate, and the real service rejects it. Enforcing egress is a second layer. It stops an agent from sending data out directly, and from using some other credential it found to connect directly.

**Constraint:** Kubernetes NetworkPolicy and ECS security groups apply to a whole pod or task, not to one container. A sidecar shares the agent's network namespace, so a pod-level egress deny also blocks the sidecar's upstream traffic. NetworkPolicy alone cannot say "the agent may reach only the proxy, the proxy may reach upstream". NetworkPolicy only allows or denies traffic and never redirects it. "Forcing" traffic through the proxy therefore means pointing the client's base URL at the proxy and denying every other path, so a bypass fails instead of being rerouted.

| Option | Mechanism | Fits | Cost |
|---|---|---|---|
| **A. Sidecar + per-UID iptables** | An init container with `NET_ADMIN` installs rules in the pod netns that confine the agent UID to the proxy's listener port. Only the proxy UID reaches upstream. This is the same pattern as Istio's init container. The base URL stays on loopback. Rule set (repeat with `ip6tables`): see below. | Kubernetes | The init container needs `NET_ADMIN`, so the agent namespace needs Pod Security Admission level `privileged`. An Istio-CNI-style plugin avoids that (inferred, not tested). The agent and the proxy must run as different UIDs. The credential is mounted in the same pod as the agent, but only into the proxy container. Fails closed: without `NET_ADMIN` the pod never leaves Init (measured). |
| **B. Separate Deployment + NetworkPolicy** | auth-proxy runs in its own namespace, and its credentials live in a Secret the agent namespace cannot read (RBAC). The agent pod's egress policy allows only DNS and the auth-proxy pods. The base URL points at the proxy Service. | Standard Kubernetes; no extra privileges | Benefit: one place for credentials, policy, audit and rotation, shared by every agent pod. Cost: a larger blast radius (a compromised proxy exposes every agent's credentials) and a shared failure point (run ≥2 replicas, since the broker is never cached). The proxy must keep callers apart by caller key (Phase 0 matrix X1). Caller-key traffic is plaintext on the cluster network unless the Service uses TLS. |
| **C. Separate service + security groups (ECS Fargate)** | B on ECS. Fargate has no `NET_ADMIN`, and security groups apply per task, so a sidecar cannot be isolated. The agent task's SG allows egress only to the proxy service; only the proxy's SG reaches upstream. | ECS Fargate | Same as B. |

### Option A rule set

```
-A OUTPUT -m owner --uid-owner <agent> -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A OUTPUT -o lo -p tcp --dport <proxy-port> -m owner --uid-owner <agent> -j ACCEPT
-A OUTPUT -o lo -p tcp --dport <each other sidecar port> -m owner --uid-owner <agent> -j REJECT --reject-with tcp-reset
-A OUTPUT ! -o lo -m owner --uid-owner <agent> -j REJECT
```

- **Do not confine the agent to "`lo` only".** That rule also exposes every loopback listener in the pod. In the spike, the agent reached the sidecar's broker port, called its resolve endpoint with its own surrogate, and got the real credential back (measured). The proxy sidecar must bind nothing on loopback except its listener. Its broker client and any admin, metrics or health endpoint use a Unix socket in a proxy-only volume, or are rejected for the agent UID. The agent's own loopback servers stay reachable, which is why the rule rejects named ports instead of allowing only the proxy port.
- **Accept `ESTABLISHED` first.** Without it, inbound connections to agent-UID servers over the pod IP (Service traffic, kubelet probes, the openab-pty runtime ports) never complete the handshake. With it, the agent's own outbound SYNs and first UDP datagrams are still NEW and still rejected (measured).
- The two parts above were measured in separate pods. The combined rule set as written is inferred.
- **Keep the `ip6tables` copy.** On IPv4 single-stack clusters it is inert, because IPv6 fails at routing. On dual-stack clusters it is what blocks the agent (measured with a test-only on-link address).

### Pod settings Option A depends on

`shareProcessNamespace: false` (when it is on, the agent can list the proxy's processes and read their command lines, though not their environment, memory or mounts; measured), distinct UIDs, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]` on both long-running containers, no `fsGroup` (it would give the agent the Secret's group), and the Secret mounted only into the proxy. The agent UID must not map to a privileged image user, because the container inherits that user's groups.

Measured on k3s with kube-router: the rules live in the pod netns, kube-router does not touch them, they survive restarts of the app containers, and they are reinstalled when the pod is recreated.

### Notes

- **DNS:** Option A also blocks DNS for the agent UID (UDP `EPERM`, TCP refused). This is intended. Base URLs are IP-literal loopback, so model traffic needs no DNS, and port 53 would be an exfiltration path. Any name-based allowlist from openab-pty#47 must resolve names on the proxy or egress side, not reopen kube-dns to the agent.
- **What else breaks** under the deny (measured, input for openab-pty#47): `git` and `curl` over HTTPS fail immediately, pip after about 8 s, cargo after about 11 s, npm after about 71 s. All of them fail at DNS. GitHub goes through octobroker.
- **kiro-cli:** under the Option A deny, kiro-cli 2.37 starts and completes chat and ACP turns, with no startup delay. With telemetry on, it lingers about 4 s at exit (n=1). Set `KIRO_DISABLE_TELEMETRY=1` in the platform-written environment. The semantic-search embedding download from `desktop-release.q.<region>.amazonaws.com` fails in both modes, so that feature is degraded unless the model is pre-seeded or the proxy routes that host.
- **Tampering:** an agent that rewrites or deletes the platform-written settings gets no service. kiro-cli fails after about 44 s of retries, and the surrogate sent directly to the real service is rejected ("Invalid token"). The platform rewrites the settings when the container restarts, but not mid-session.
- Restricting the proxy itself to specific FQDNs needs a CNI with FQDN policy (Cilium, Calico). Otherwise the proxy's own route policy, which already allows only configured upstream hosts, is the control.
- Not yet verified: whether each CLI accepts a non-loopback plaintext `http://` base URL (Options B and C), dual-stack clusters, a real remote broker, and PSA enforcement.

**Transparency:** none of A, B or C is transparent at the network level, because the client must be pointed at the proxy. A fully transparent setup, where nothing changes on the client side, needs DNAT plus TLS interception: that is Phase 2, with a CA the agent must trust. Instead, the platform writes the base URL settings at session start (e.g. kiro-cli's `~/.kiro/settings/cli.json`, `*_BASE_URL`), so neither the agent nor the user configures anything.

**Current direction:** A (sidecar + per-UID iptables, loopback base URL written by the platform) for openab-pty on Kubernetes, validated on k3s with kube-router (branch `spike/phase0`, `spike/k3s-egress-a/`). C for openab on ECS Fargate. B remains the option where `NET_ADMIN` or PSA `privileged` is not acceptable.
