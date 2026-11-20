# Muse gated passthrough, stage 2 runbook

Design: `docs/design/muse-gated-passthrough.md` (sections 3.4 to 3.9, 5, 7 stage 2). Stage 2 adds the
`hold` verdict, the approval listener and a notification hook to the stage 1 passthrough. Everything
here is generic: use your own hosts, and never commit real host names, addresses, logins, topics or keys.

**The gate constrains the agent, not the Muse platform.** Muse's egress holds the real Discord token, so
Muse or anyone who compromises it can call Discord directly and skip the gate.

## 1. Build and run

```
cargo build --release -p ap-proxy
```

A default build has no probe route and no test hooks. Do not run the `matrix-upstream` or `stage1-probe`
builds in production. `auth-proxy` exits 2 on an invalid policy, and a restart forgets every held request.

## 2. Policy keys

`[passthrough]` (all optional, shown with defaults):

| Key | Default | Meaning |
|---|---|---|
| `hold_secs` | 120 (5..=600) | how long a request waits for a decision, then 410 `expired` |
| `held_body_max_bytes` | 1 MiB | largest body a held request may carry |
| `max_held_total` | 32 | hold table size, then 503 `table_full` |
| `max_held_per_identity` | 4 | per caller, then 503 `identity_cap` |
| `cooldown_secs` | 60 (0 disables, max 3600) | after a deny or expiry, new holds from that identity get 503 `cooldown` |

A hold grant uses `decision = "hold"` and `path_patterns` (a segment is a literal or `*`), never prefix
`paths`, and only on a passthrough route. Hold wins over allow when both match, but policy load refuses an
allow grant (prefix or pattern) of the same identity, route and method that overlaps a hold pattern, so an
overlap is never relied on: the trailing-slash spelling of a held path is not a hold match and would otherwise
reach the allow grant. A percent-escape of an unreserved character (`A-Z a-z 0-9 - . _ ~`, for example
`%6D` for `m`) in the path is refused as `path_ambiguous` on the passthrough listener (the sidecar keeps accepting them),
so the path that policy matches is the path that is sent. The query is not matched by policy, is forwarded byte for byte and is not subject to this rule. A route
path or query that repeats the caller's own key, in any spelling, is refused as `caller_key_ambiguous`. The held body must be
`application/json`, uncompressed, and the request must carry `Authorization`.

`[approval]` (required when any grant holds): `listen` (loopback only, a port other than `listen.proxy`),
`user`, `password_sha256`, `public_base_url` (http or https, no userinfo or query; it only builds the
notification link) and an optional `realm`.

`[[token_identity]]` (option B pilot, design 4.5; optional): `name`, `route` (a passthrough route),
`token_sha256` (sha256 of the exact `Authorization` value, for example `Bot <token>`) and `expires`
(`YYYY-MM-DD`, UTC; refused from the next day). It lets a keyless request on that route authenticate, and only
for a `hold` grant of that identity. One per route. Pilot value: `expires = "2026-12-20"`. Without the table
(the default), every request needs a caller key.

`[approval]` (required when any grant holds): `listen` (loopback only, a port other than `listen.proxy`),

`[notify]` (optional; without it holds just wait and expire): `kind = "ntfy"`, `base_url`, `topic_file`,
and an optional `token_file`.

## 3. Approver password and secret files

```
pw="$(openssl rand -hex 32)"
printf '%s' "$pw" | shasum -a 256          # put the hex digest in password_sha256
```

Keep `$pw` in a password manager. The proxy stores only the digest. The notification topic and token are
read at startup from the files named in `[notify]`. Each must be a regular file with mode 0600 (no group or
other bits); anything else refuses to start. Treat the topic like a password: whoever knows it can read the
notifications, and the notification carries only a fixed sentence and a link.

## 4. Network placement

The approval listener binds loopback. Put it behind a front that only the approver can reach, on a
different name and path from the one Muse uses, and keep the approval port off the caller path. This is a
deployment control; the code cannot prove it. The approver authenticates with Basic auth plus a per-view,
single-use CSRF token.

## 5. Timeouts and the old connector

- The connector's helper timeout must be longer than `hold_secs`, and so must every idle timeout between
  Muse and the gate (the TLS front, any load balancer). The effective window is the smallest of them.
  Measure it before relying on a long `hold_secs`.
- Remove the previous direct connector once the gate is the only path, or the agent can still write
  without approval.

## 6. Behaviour to expect

- An approved request is forwarded once and Discord's answer is returned unchanged.
- An identical retry while the first is waiting supersedes it: the first caller gets 503 `superseded`, the
  new entry is the one to approve, and the owner is not notified again. Its page shows the superseded
  banner and a link to the newest entry.
- Deny and expiry start the cooldown. Audit failures and notification failures do not.
- Shutdown (SIGTERM) answers every waiting request 503 `shutdown` and lets approved forwards finish or
  reach `request_deadline_secs`.
- Reload: every waiting request is checked again against the new policy about once a second. A hold whose
  identity, route, method or path is no longer held (identity, route or hold grant removed, method removed,
  pattern narrowed) is answered 503 `dropped_on_reload`, and so is every waiting request when the policy file
  disappears or stops being valid. An approve is checked against the current policy too: it answers
  `policy_changed` (410) and sends nothing if the grant is gone, and it is checked once more just before
  the first upstream byte, so a reload between the approve and the send also sends nothing.
- A hold remembers the upstream (scheme, host, port) its route named, shown on the approval page as "Sent
  to" and in the `held` audit record. Changing a route's host or port (or its `keep_auth_headers`) drops the
  holds on it with `dropped_on_reload`; an approve for such a hold answers `policy_changed`.
- Proxies: the notifier and the upstream client ignore `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, their
  lowercase forms and system proxy settings. There is no setting that turns this off. The notifier never
  follows a redirect.
- Two passthrough routes cannot share one host and port; the policy is refused at load.
- Audit: `held` and `forward_started` are written before the action and are fail-closed. If the audit write
  fails the request is refused 503 `audit_unavailable`.

## 7. Duplicate delivery window

If the gate forwarded an approved request, Discord acted on it, and the response was lost on the way back,
Muse may retry. The retry is a new request, the owner can approve it, and it will run twice. Exactly-once
is not claimed. A `forward_started` audit record with no `completed` marks the requests where this can
have happened.

## 8. Not claimed

- Protection from the Muse platform or anything that holds the real token.
- Exactly-once delivery (section 7).
- That the approval plane is unreachable from the caller path (network placement, section 4).
- A measured hold window or disconnect signal through the real front (stage 2 measures the direct path in
  CI only).
- Hold behaviour on `multipart/*` uploads (refused) or compressed bodies (refused).

## 9. Automated checks

```
cargo test --workspace
cargo build -p ap-proxy -p ap-egress --features ap-proxy/matrix-upstream,ap-proxy/stage1-probe,ap-egress/matrix-upstream
cargo test -p ap-proxy --features matrix-upstream,stage1-probe --test matrix_passthrough
python3 tests/matrix/passthrough.py --bin target/debug
```

The in-process suites include a sentinel leak test over every hold outcome and a refusal table that
generates each row of design section 3.5 through the real pipeline.
