# Muse async poll for held writes
Status: implemented on main (#45); operator steps are in `docs/runbooks/muse-stage2.md`. Terms follow `muse-gated-passthrough.md` 3.4 and 4.5.
## Scope
Only the Muse route `POST /channels/*/messages` (held), per route. Config keys on the `[[route]]` table: `hold_mode = "blocking"|"async"` (default `blocking`) and
`async_hold_secs` (5..=600, default 120, used only in `async`). Async needs a passthrough route with a hold
grant; otherwise the policy is refused at load. Else unchanged.
## POST
1. Write the `held` audit record first. On failure refuse 503 `audit_unavailable`, before any entry
   exists and before any notification.
2. Run the existing admission checks (cooldown, `max_held_per_identity`, `max_held_total`). A refusal
   writes a terminal audit record with the existing code (`cooldown`, `identity_cap`, `table_full`)
   after the `held` record and returns the existing 503. No token is issued. In async mode the fingerprint dedupe and supersede are
   not applied, so every POST is an independent pending entry and there is no `superseded` status.
3. Insert into the in-memory pending table and send the existing Telegram notification.
4. Return 202 with `request_id` and a random poll token (at least 128 bits, stored only as a hash,
   constant-time compare). Body and `Authorization` are never echoed.

## GET /poll/<token>?wait=N
The token is the only credential. The poll needs no `Authorization` and returns the same 404
whatever headers are sent. `wait` is an integer, missing means 0, values above 25 are capped at 25;
anything else is 400, without revealing whether the token exists. Response is `pending` or final:

| status | HTTP | fields |
|---|---|---|
| `approved_and_sent` | 200 | `status`, `request_id`, `discord_status`, `body`, `truncated` |
| `denied`, `expired`, `dropped`, `send_failed` | 200 | `status`, `request_id` |
| `send_unknown` | 200 | `status`, `request_id`, `error_class` (`reset`, `timeout`, `write_failed`) |

`body` is a string (the Discord response as lossy UTF-8 text, which the caller parses itself), at most 64 KiB, `truncated=true` if cut. The token is read-only and never approves, denies
or changes state. A final status stays readable for a fixed 60 s window starting at the final
transition (for `approved_and_sent`, when the Discord response is fully read or cut at 64 KiB).
After that, and for any unknown token, the response is a uniform 404. No retained-entry cap.

## Retries
No `Idempotency-Key`, no store. Muse never retries a POST blindly; after a lost or unknown POST
response it submits a NEW request. Safe because each message needs its own Telegram approval.

## States and races
- `forward_started` is written after the upstream connection is established and before the first
  request byte. A connect failure writes no `forward_started` and ends as `send_failed`, audit code
  `connect_failed`.
- Nothing sent before the first byte (start-claim failure, `connect_failed`, `audit_unavailable` on
  the `forward_started` write, shutdown): start-claim failure (`dropped_on_reload`) and shutdown give
  `dropped`, the others give `send_failed`. Anything after the first byte that is not a confirmed
  Discord response gives `send_unknown`, never `dropped`.
- Approve versus expiry race on one mutex. The first transition wins.
- Restart drops all pending entries; a poll then returns the uniform 404. A `held` record with no
  completion is the expected trace.

## Approval and audit
Approval stays on Telegram only, with the existing start-claim checks. Audit records keep their
current shape and never carry a token, `Authorization`, hash or body. Unapproved entries end as
`expired` after `async_hold_secs` (default 120).

## Departures
Connection-as-state is replaced for this route. No cancel on Muse disconnect. Discord response
headers are not returned verbatim. `X-AP-Decision` is not returned after admission. Fingerprint dedupe and supersede do not apply.
These departures are as implemented.
## Tests
Poll after each final status; uniform 404 after the window and for unknown tokens; `send_unknown`
path; restart loses pending entries; audit shape with no token in audit.
