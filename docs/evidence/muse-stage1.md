# Muse stage 1: measurement results

Records the stage 1 measurements of the Muse passthrough (design: `docs/design/muse-gated-passthrough.md`).
Redacted: no hostnames, addresses, logins, URLs or keys.
Companion file for the front and framing checks: `docs/evidence/muse-stage1-front-measurements.md`.

Tags: **[M]** measured on our gate (audit and evidence log on the gate host). **[M-reported]** reported by the
Muse side, not observed by us.

## Scope and versions

- Stage 1 merged to `main` as `2f61f5f` (PR #17). The deployed binary was built from the PR #17 head, whose source tree is identical to merge commit `2f61f5f`.
- Measurements ran on 2026-11-16 and 2026-11-17.
- Upstream was Discord with a dummy credential. The real Discord token was never used.

## Method

- The Muse side ran a helper through its connector registered for the gate host. The caller key sits in a URL
  path segment, placement `/ap/{}`.
- The gate side recorded the audit log and the stage 1 evidence log on its own host. Probe `elapsed_ms` values
  below come from that log.

## Muse helper facts [M-reported]

Original Discord helper:

- Base URL hard-coded to discord.com. No custom request header.
- 30 s socket timeout for JSON requests (60 s for multipart). No retries.
- No trace, request or idempotency headers. Redirects not followed.
- `Host` includes the port.
- Message-create bodies are `application/json` with `Content-Length` (not chunked). No gzip. No
  `Expect: 100-continue`.
- The agent could still reach Discord directly through the old connector.

Registration:

- A separate connector was registered for the gate host only.
- Placement `/ap/{}`. The first attempt, `/ap/{}/discord`, did not cover the probe paths, so probes arrived with
  the surrogate as the key and were refused `caller_rejected`. This was a Muse-side registration scope issue,
  not a gate bug.
- The credential injection placement is chosen once at registration and cannot be edited.
- The helper timeout is a per-helper parameter.

## Results

### Held connection [M gate-side elapsed, M-reported helper-side elapsed]

Through the real Muse helper and the owner's private-network TLS front:

| Probe | Helper timeout | Helper result | Gate evidence `elapsed_ms`, status |
|---|---|---|---|
| 10 s | default | 200 in about 10.6 s | 10000, 200 |
| 30 s | default 30 s | `TimeoutError` after 30.81 s (Muse side) | 30000, 200 |
| 60 s | 120 s | 200 in 60.7 s | 60000, 200 |
| 120 s | 180 s | 200 in 120.7 s | 120001, 200 |
| 300 s | 330 s | 200 in 300.7 s | 300001, 200 |

- The 30 s timeout is expected: the helper gave up first. The gate still completed the probe.

### Refusals

- [M-reported] Probes returning 503, 410 and 423 reached the agent with the matching status, the decision JSON
  body `{"ap_decision":...,"code":...}` and the `X-AP-Decision` header. The new helper surfaces each. None was
  retried. [M] The gate evidence records the three probes with statuses 503, 410 and 423 (10 s each).
- [M-reported] A write attempt (`POST` messages) got 423 `no_grant`. The agent treated it as terminal and did not
  retry.
- [M-reported] A read got Discord's own 401 body unchanged (dummy credential), with no `X-AP-Decision`.

### Scope of the swap [M-reported]

- Any path under `/ap/` on the registered host is swapped. An unknown route returns 423 `route_unknown`
  (caller accepted; [M] the gate log also records this).
- The helper refuses every other host in 0.000 s before any network call (discord.com, example.com, another
  private-network host).

### Identical retries

- [M-reported] Header names are identical across repeated identical requests.
- [M] The gate's forwarded-names digest was identical across repeats.

### Reachability (open question 3)

- [M-reported] The gate host was reachable from the Muse side over the private network.
- [M] Requests from the pilot identity appear in the gate audit log, so they reached the gate through the front.
- Not claimed: the ACL restriction to Muse's node was an owner action and is not verified by us.

### Framing gap

Unchanged: documented, not built.

## Open and unmeasured

- Platform-internal swap logs, and what the platform logs after the swap. Cannot be observed from our side.
- Whether any ceiling exists above 300 s.
- ACL isolation (design stage 1 item 11): not measured. Whether only the public port is reachable from the Muse
  node, with SSH and other ports failing, is unconfirmed.
- Client disconnect during a hold, direct and through the front, and Muse's reaction to a dropped connection
  (design stage 1 item 10, last part): not measured.
- Behaviour once the old direct-to-Discord connection is removed.

## Conclusions

- The stage 2 stop rule (measured window shorter than a realistic human approval) did **not** trigger. Combined
  result: the gate held and completed probes up to 300 s [M]; the Muse helper received them end to end, with its
  timeout raised to 330 s for the 300 s probe [M-reported].
- Hard condition for stage 2: the connector's helper timeout for gated routes must exceed the hold window. The
  default 30 s is not enough.
- The gate constrains the agent only if the connector for the gate host is the agent's only route to Discord.
  The old connector must be removed, or its credential unregistered, before the gate is relied on.
