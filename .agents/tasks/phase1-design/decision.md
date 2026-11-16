# auth-proxy Phase 1 design: council decision

Design doc: `docs/design/phase1.md`
Council members: Reviewer 1, Reviewer 2.

Decision rule: a question is decided by the council only when both members pick the same option, both rate risk low or medium, both mark it reversible, and neither sets escalate. Otherwise it goes to the owner.

## Summary

| Question | Reviewer 1 | Reviewer 2 | Outcome | Final status | Option |
|----------|-----|-------|---------|--------------|--------|
| Q1 session/caller identity | Q1-B, medium, reversible, escalate | Q1-B, medium, reversible, escalate | escalate (both members set escalate) | decided by owner (option 1) | Q1-B |
| Q2 broker placement and store | Q2-A, low, reversible, escalate | Q2-A, medium, reversible, escalate | escalate (both members set escalate) | decided by owner (option 3) | Q2-A, Kubernetes (S1) only; ECS deferred |
| Q3 policy format and egress | Q3-A + Q3-E2, low, reversible, no escalate | Q3-A + Q3-E2, low, reversible, no escalate | decided | decided by council | Q3-A (egress Q3-E2) |

## Q1

### Member verdicts

**Reviewer 1**: option Q1-B, risk medium, reversible yes, escalate yes, confidence 0.8.
Rationale: Q1-B is the only option that gives per-session revocation without a per-session HOME. kiro-cli settings are global with no custom-header knob (exp1), and HOME is shared in openab-pty. The runtime sends only hashes to the proxy, so openab-pty's "no broker config" rule holds, and openab's existing SessionTokenRegistrar mint and revoke sites are reused. Because the authority generates the surrogate, surrogates survive a proxy restart after resync. Residual weaknesses: a same-UID neighbour can spend another session's surrogate, and on ECS the agent can reach the authority token through the task role. Both stay within the identity's own grants. Falling back to Q1-A means registering one pod-lifetime session. Conditions: owner accepts the RFC amendment to lease renewal capped by the session's absolute TTL; tests cover the `hello` race after the authority dies (container restart, 90 s lock, no orphaned agent-UID process sends `hello` first); audit attribution between same-UID sessions is documented as best-effort.
Escalate reason: the RFC rule "TTL ≤ 15 min, renewal mints a new surrogate" becomes lease renewal for up to the session's absolute TTL (12 h default). That is a security-policy amendment, and the doc says the owner must accept it.

**Reviewer 2**: option Q1-B, risk medium, reversible yes, escalate yes, confidence 0.8.
Rationale: same core argument. Global kiro-cli settings and shared HOME (measured in exp1, confirmed in source) leave Q1-B as the only option with per-session revocation. The authority holds surrogates and the proxy holds only hashes, so proxy restarts are handled. Q1-A cannot revoke per session. Q1-C needs per-session HOME and broker access for the operator. The same-UID `/proc/<pid>/environ` weakness matches the RFC's "identities, not processes" scope. Conditions: test the hello lock against a runtime container restart with the proxy up, proving only the fresh PID 1 can win `hello`; never log the `/ap/<caller-key>` prefix in audit or access logs.
Escalate reason: same RFC amendment; the owner should also sign off on the same-UID and ECS task-role caveats.

### Outcome

```json
{"status":"escalate","question":"Q1: Both members recommend Q1-B (per-identity caller key in the base-URL path, authority-minted per-session surrogate in the child env, sha256 registered over the session plane, 15 min session lease / 90 s authority lease, synchronous revocation, Q1-A file handoff as fallback). It amends the RFC: surrogates are lease-renewed up to the session's absolute TTL (12 h default) instead of re-minted every ≤15 min, and it accepts that a same-UID neighbour can read another session's surrogate and that on ECS the agent can reach the authority token via the task role. Do you accept this?","options":["1 Accept Q1-B with the RFC amendment and both members' conditions: hello-race test after an authority container restart (90 s lock, only the fresh PID 1 wins), no /ap/<caller-key> prefix in any log, audit attribution between same-UID sessions documented as best-effort","2 Accept Q1-B but keep a shorter absolute surrogate TTL than 12 h (e.g. 1 h) so the amendment's exposure window is smaller, at the cost of more session restarts for long agent runs","3 Ship only Q1-A (file handoff, no per-session revocation) for Phase 1 and defer the RFC amendment"],"recommended":1,"reason":"Both members agree on Q1-B, medium risk, reversible, but both set escalate because it changes the RFC's credential-lifetime rule, which only the owner can approve. They differ only in conditions: Reviewer 1 adds best-effort audit documentation, Reviewer 2 adds the no-caller-key-in-logs rule; option 1 includes both."}
```

Owner decision (pahud): **option 1, Q1-B accepted.** The owner accepts the RFC amendment: the authority renews the surrogate lease up to the session's absolute TTL (12 h default), instead of minting a new surrogate every 15 min or less. All three conditions are binding:
- (a) A hello-race test after an authority container restart: the 90 s lock holds, and only the fresh PID 1 can win `hello`.
- (b) No `/ap/<caller-key>` prefix appears in any audit or access log.
- (c) Audit attribution between same-UID sessions is documented as best-effort.

## Q2

### Member verdicts

**Reviewer 1**: option Q2-A, risk low, reversible yes, escalate yes, confidence 0.85.
Rationale: Q2-A keeps the Phase 0 bake-off properties: one process holds the credential, explicit refusal codes, no extra hop (exp2). No broker port exists for the agent to call, so the F1 failure class is gone (k3s F1). The broker cannot fail separately from the proxy, and blast radius is one identity. Q2-B adds HA shared state and two credential holders with the credential on the wire. Q2-C couples model access to a single-replica service that also holds the GitHub App private key. A networked broker later is a new implementation of the same trait. Layout: S1 on Kubernetes (proxy-only Secret mount, mtime/size check per request), S2 on ECS (proxy task role, refresh 300 s, max age 900 s, then fail closed); one loopback listener, a session-plane socket exposing only the 5 session calls, an admin socket only the proxy mounts; on ECS one proxy service per bot with security groups, authority token loaded into openab's memory from Secrets Manager, `ap-relay` in the openab container. Share octobroker's secret-reference syntax at crate level only. Stated limit: Option C on ECS does not deny agent egress from the openab task.
Escalate reason: one on-demand (not Spot) Fargate service per bot is a recurring cost across B0 to B15; new Secrets Manager secrets, IAM grants and execution-role allowlist entries on production bots; the S2 bounded cache is an exception to the RFC's no-cache rule.

**Reviewer 2**: option Q2-A, risk medium, reversible yes, escalate yes, confidence 0.82.
Rationale: same core argument. F1 met by construction, one credential holder, one-identity blast radius. Q2-B sends the credential over the network per request and needs HA registry state; Q2-C puts every model key and the GitHub App key in single-replica octobroker. The ECS mapping and the relay (avoiding untested non-loopback base URLs) are inferred, not measured, but not blockers. Keep the authority token out of env.
Escalate reason: recurring on-demand ECS cost per bot; S2 keeps real credentials in memory up to 900 s after Secrets Manager stops answering, an exception to "never cached"; the RFC text "holds decrypted material only for the duration of a request" needs rewording.

### Outcome

```json
{"status":"escalate","question":"Q2: Both members recommend Q2-A (broker inside the proxy process; S1 proxy-only Secret file on Kubernetes, S2 Secrets Manager via the proxy's task role on ECS; one proxy service per bot plus ap-relay on ECS). Do you approve the recurring cost of one on-demand (not Spot) Fargate proxy service per bot across B0–B15, the new Secrets Manager secrets / IAM grants / execution-role allowlist entries on production bots, and the S2 cache bound (refresh 300 s, max age 900 s, then fail closed) as an exception to the RFC's 'never cached' rule?","options":["1 Approve Q2-A as designed: per-bot on-demand proxy service, S2 refresh 300 s / max age 900 s, authority token kept out of env, RFC 'only for the duration of a request' text reworded","2 Approve Q2-A but run the per-bot proxy service on Fargate Spot to cut cost, accepting that a Spot interruption takes that bot's model access down until the task is replaced","3 Approve Q2-A for Kubernetes (S1) only in Phase 1 and defer the ECS rollout (S2, per-bot services, IAM changes) to a later phase"],"recommended":1,"reason":"Both members agree on Q2-A and reversibility; Reviewer 1 rates risk low, Reviewer 2 medium. Both set escalate because it spends recurring AWS money, changes IAM and secrets on production bots, and makes an explicit exception to the RFC's no-cache rule, all of which need owner approval."}
```

Owner decision (pahud): **option 3, Q2-A for Kubernetes only in Phase 1.** The broker runs inside the proxy process, with S1 (a Secret file mounted only into the proxy) as the store.

The ECS rollout is **deferred to a later phase, not rejected.** The deferred parts are:
- the S2 Secrets Manager store;
- the per-bot proxy services and `ap-relay`;
- the IAM, Secrets Manager and execution-role changes;
- the S2 cache-bound exception (refresh 300 s, max age 900 s).

S2 is deferred, so the RFC's "never cached" wording stays unchanged in Phase 1. The design doc must mark its ECS sections as deferred, not rejected. This aggregation step did not edit the design doc, as instructed; a later step should make that change.

## Q3

### Member verdicts

**Reviewer 1**: option Q3-A (egress Q3-E2), risk low, reversible yes, escalate no, confidence 0.8.
Rationale: one validated TOML file per identity lets the loader cross-check routes, grants and egress (a credential route host is never an egress host), extends the spike's measured policy store (exp2 R1), and is the same artifact on Kubernetes and ECS. Q3-B loses cross-file checks; Q3-C adds an operator with no ECS equivalent. Q3-E2 keeps response rewriting out of the credential process (Q3-E1 needs it), needs no NET_ADMIN after init and is not widened by shared CDN addresses (Q3-E3), never terminates TLS, and is easy to remove. Known costs: exfiltration to allowed hosts and slow failure for tools ignoring proxy variables (npm ~71 s, k3s 7). Additions: `NO_PROXY=127.0.0.1,localhost`; confirm `X-Amz-Target` with kiro-cli before relying on `aws_targets`; run the combined iptables rule set in one pod before release. The octobroker TLS front and moving openab-pty#47's allowlist are same-owner coordination work.

**Reviewer 2**: option Q3-A (egress Q3-E2), risk low, reversible yes, escalate no, confidence 0.8.
Rationale: same reasoning on single-file cross-checks, Q3-B drift, Q3-C operator cost, and Q3-E2 versus E1/E3. Remaining risk is data sent to allowlisted hosts such as github.com, which the doc acknowledges. Conditions: ap-egress connects to the exact address it validated with no second resolution (DNS rebinding); the combined Option A rule set is measured in one pod before the design is called done; `aws_targets` gated on a test that kiro-cli sends `X-Amz-Target`.

### Outcome

```json
{"status":"decided","option":"Q3-A","reason":"council agreed"}
```

Merged rationale: one TOML policy file per identity, validated as a whole, swapped atomically, failing closed with `policy_unavailable`, stored in a proxy-only ConfigMap (Kubernetes) or Secrets Manager with S2 rules (ECS). Non-credential egress uses Q3-E2: a separate CONNECT-only `ap-egress` in its own container and UID, no Secret mount, no ap-broker dependency (CI-checked with cargo tree), resolving DNS itself and connecting to the exact validated address, refusing IP literals and private/loopback/link-local targets; agent UID keeps DNS blocked. GitHub goes through octobroker as an auth-proxy route behind TLS; git push via ap-egress to github.com:443; openab-pty#47's allowlist becomes the `[egress]` section. Follow-ups from both members: set `NO_PROXY=127.0.0.1,localhost`, confirm kiro-cli sends `X-Amz-Target` before any grant uses `aws_targets`, and measure the combined iptables rule set in one pod before release.

## Over-design council (2026-11-16) and the owner's decision on Q1

After the Phase 1 verification (`.agents/tasks/phase1-verify/`), two council members (sol and
opus5) reviewed the built system for over-design. Both set escalate on one question: whether the
first end-to-end Kubernetes deployment may run on the Q1-A fallback (one session registered for
the pod's lifetime, no per-session revocation) while Q1-B stays built, and whether `ap-egress` may
ever be folded into the credential-holding proxy.

### Owner decision (pahud, binding)

Option 1 of the escalation:

- **Q1-B stays the formal accepted design. New work on it is frozen.**
- Build **only** the minimal Q1-A static configuration (one session registered for the pod's
  lifetime) as a **clearly labelled interim path** for the first end-to-end Kubernetes deployment.
- **The owner accepts that the interim deployment has no per-session revocation.** The
  documentation says so in plain words (`docs/interim-static-session.md`, `docs/design/phase1.md`).
- The real-pod `hello` race test remains a **release gate** (`docs/pre-release-checklist.md`, item 3).
- **`ap-egress` stays a separate container and UID. It is never folded into the credential-holding
  proxy.**

### Council verdicts applied (council-level, low risk, reversible)

| Item | Verdict | What was done |
|---|---|---|
| `aws_targets` | Freeze: keep parser, validation and tests dormant; forbid it in shipped policies | Test `shipped_policies_parse_and_use_no_aws_targets` fails if any policy under `deploy/` uses it. kiro-cli 3.3.0 was measured to send exactly one `X-Amz-Target` per call (model call `AmazonCodeWhispererStreamingService.GenerateAssistantResponse`, `docs/verification/phase1-xamz-target.md`), so the assumption holds, but no grant uses it yet. |
| `egress.allow_route_hosts` | Remove (security fix; only sol flagged it) | The field existed in `ap-core` `EgressCfg` and switched off the rule "an egress host is never a credential route host". Removed with no replacement; a policy that sets it is an unknown-field error. Tests: such a policy is rejected, and an egress entry that is a credential route host is rejected. |
| `route.connect_to` | Remove from production syntax or restrict to test builds | Restricted to the `test-resolve` cargo feature. No shipped build has it, and a policy that sets it is rejected (unit test plus `scripts/check-no-test-resolve.sh` on the release binary). Tests and the matrix use a `test-resolve` build. |
| Admin socket, revoke-all, status | Councils split (sol: remove; opus5: keep); lean was simplify | **Kept**, because tests depend on it: `crates/ap-proxy/tests/session_plane.rs` reads the session count from `GET /admin/status` in many tests and has `admin_socket_status_and_revoke_all`; `policy.rs` and the shared fixture start the proxy with `--admin-socket`; the matrix harness waits for the admin socket. The pre-release checklist does not depend on it. It is never merged into the agent-mounted session socket. Revisit when those tests get another way to count sessions. |
| Broker trait, `ap-client` | Freeze at the UDS client only | No code change. No networked-broker work in Phase 1. |
| `upstream_reset` audit gap (verification item 2) | Owner chose option A | `AuditRec` has a `bytes_sent` field (response-body bytes already relayed; `null` on other lines), counted in `agent.rs`. `#[ignore]` removed from `the_upstream_reset_audit_line_records_the_bytes_sent`. The audit stays free of secrets and of the `/ap/<caller-key>` prefix; matrix X5 passes. |
| Combined iptables rule set | Measured in one pod (verification item 1, PASS) | Design doc tag changed from [I] to [M]; evidence `docs/verification/phase1-k8s-iptables.md`. |
| `kiro-cps` route host placeholder | Not resolvable from the item 4 capture | Listed as an open item with what is needed (`docs/pre-release-checklist.md`). |

### Q1 summary row, as amended

| Question | Final status |
|---|---|
| Q1 session/caller identity | Q1-B accepted and frozen. Q1-A static session built as an **interim** path, with no per-session revocation, accepted by the owner. |
