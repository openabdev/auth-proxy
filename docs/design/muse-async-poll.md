# Muse async poll: replacing the held connection with a poll token

Status: design only, no code. Terms (hold, start claim, `forward_started`, the audit records) are those of
[muse-gated-passthrough.md](muse-gated-passthrough.md), called "the gated design" below. The key words MUST
and MUST NOT are normative. Every token, hash, chat id and address in this file is a placeholder.

## 1. Scope

Only the Muse route `POST /channels/*/messages` (the held route). Every other route, every allowed read and
the blocking mode are unchanged. Blocking stays selectable by configuration; async is chosen per route.

## 2. POST: admit and return

The proxy MUST, in this order:

1. Validate the Idempotency-Key (section 5).
2. Under the table lock: look up (identity, key) (same key and payload returns the existing entry, so a retry
   at a cap still gets the same token), then apply the existing cooldown, `max_held_per_identity` and
   `max_held_total` checks and their refusals, unchanged.
3. Write the `held` audit record. If that write fails, answer 503 `audit_unavailable`; no entry or key record exists and nothing is notified (gated design 3.4 step 5).
4. Insert the entry and the key record (still under the same lock), send the Telegram notification (the existing PR #41 path), and return `202` with a JSON body `{"request_id": "<id>", "poll_token": "<token>"}`.

A refused or repeated request therefore writes no `held` record. The token is random, at least 128 bits, stored
only as a hash and compared in constant time. The response MUST NOT echo the request body or
`Authorization`. The request still passes every check of gated design 3.1 to 3.3 and 3.4 steps 1 to 3 before admission.
The Idempotency-Key replaces the fingerprint dedupe and `superseded` for this route.

## 3. GET /poll/<token>?wait=N

The call waits up to N seconds (N capped at 25) and answers as follows:

| Status | HTTP | JSON fields |
|---|---|---|
| `pending` | 200 | `status`, `request_id` |
| `approved_and_sent` | 200 | `status`, `request_id`, `discord_status`, bounded `body`, `body_truncated` (bool; cap set in configuration) |
| `denied`, `expired`, `dropped` | 200 | `status`, `request_id`; nothing was sent (`expired`: `async_hold_secs` passed unapproved; `dropped`: section 8) |
| `send_unknown`, `send_failed` | 200 | `status`, `request_id`, `error_class` (`reset`, `timeout` or `write_failed`; section 7) |
| unknown, malformed or expired-window token | 404 | uniform body |
| poll rate exceeded | 429 | uniform error body, `Retry-After` header |
| bad `wait` | 400 | uniform error body; does not reveal whether the token exists |

`wait` missing means 0; the per-token poll limit is configured (default 2 per second, burst 5); values above 25 are capped to 25; a non-numeric or negative value is 400.

The token is read-only. It MUST NOT approve, deny or change any state. An unknown, expired-window or
malformed token returns one uniform `404` with an identical body and timing class. Polls are rate limited
per token (429 above).

## 4. State kept

Pending entries, plus one fixed 60 s final window that starts when the entry reaches a final status. During the window the final status stays readable and
the Idempotency-Key stays recorded. Afterwards the token returns the uniform 404 and the key is forgotten.
There is no retained-entry cap beyond this window and no per-identity retained count.

## 5. Idempotency

The Idempotency-Key is required and is scoped to the caller identity: the table is keyed on (identity, key), so
another identity never receives this identity's token. A POST with a missing, empty, over-long (more than 64 characters) or
malformed key (anything outside `[A-Za-z0-9_-]`) is refused with `400` before admission. The key is bound
to the payload hash over the method, the raw route-relative path (including the channel id), the raw query
and the body digest. Forwarded headers and the credential are excluded: they are rewritten by the proxy and
the identity already scopes the key. So the same key and body on a different channel gives `409`. Admission is atomic under the table lock:

- Same key, same payload, while pending or inside the 60 s final window: return the same `request_id` and
  token. A retry MUST NOT become a newly admitted send.
- Same key, different payload: `409`.
- Same key after the window: a new request (this can be a second send of an `approved_and_sent` request).

## 6. Approval

The owner decides on Telegram only (unchanged). Approve runs the existing start claim before any upstream
byte: policy, token-identity expiry and hash, and that the hold is still live (gated design 3.9, 4.5).
`forward_started` MUST be durable before the upstream connect. The audit records `held`, `approved`,
`forward_started`, `completed`, `expired`, `denied` keep their current shape and never carry a token,
`Authorization`, hash or body.

## 7. Past forward_started

A request that has passed `forward_started` MUST NOT end as `dropped`. If the process cannot confirm
Discord's result (connection reset, timeout), the status is `send_unknown` with the error class. The proxy
MUST NOT retry blindly. A failure before any request
byte left is `send_failed`. Audit mapping: an unconfirmed result is `completed` with code `send_unknown`
(poll status `send_unknown`); a connect failure (`connect_failed`) or a failed `forward_started` write
(`audit_unavailable`, nothing sent) is `completed` with that code (poll status `send_failed`). A
`forward_started` with no `completed` is a crash trace only. Muse treats `send_unknown` as possibly delivered and submits a NEW request with
a NEW Idempotency-Key only after the owner decides, never as a blind retry.

## 8. Restart, reload, expiry

Pending entries are lost on restart. A token whose entry was lost returns the uniform 404. A `held` record
in the audit with no completion is the expected trace of such a loss, and needs no extra record. Every
start-claim failure (policy reload, token-identity expiry or hash change) ends the entry as `dropped`
with the existing audit code `dropped_on_reload`, before any byte is sent (gated design 3.9, 4.5); this is
possible only before `forward_started`. Approve and expiry race on one mutex and the first transition wins
(retained from gated design 3.4 step 6).

## 9. Limits

A configured maximum of pending entries (a full table refuses with 503 `table_full`) and `async_hold_secs`
(default 120). A pending entry not approved by then ends as `expired`, nothing sent. Poll rate limit per
token (section 3).

## 10. What this replaces

This replaces requirement 6 and section 5 of the gated design ("the connection is the state"), requirement
4 (Discord's response returned verbatim with headers), requirement 5 (`X-AP-Decision` and 423/410 on this
route after admission) and, for this route only, 3.4 steps 7 to 9 (disconnect detection, `approved_but_abandoned` and its milestones,
the verbatim response) and the `Abandoned` and `Superseded` parts of step 6. First-transition-wins of step 6 is retained. No longer guaranteed: a Muse disconnect no longer cancels the hold, so `abandoned` and
`abandoned_after_approve` do not occur on this route, and an approved request is sent although Muse has
stopped polling. Still holds: fail-closed, nothing is forwarded without an approval in the same process
lifetime, at most one forward per admitted request, and exactly-once is still not claimed.

## 11. Owner confirmation: departures from the blocking design

1. No cancel on Muse disconnect; an approved request is sent even if Muse never polls again.
2. Muse needs a poll loop and an Idempotency-Key; blocking clients are unaffected.
3. Final results are readable for 60 s only, then the 404.
4. `send_unknown` is a new outcome that needs the owner's decision.
5. A restart loses every pending request silently from Muse's view (404).
6. `async_hold_secs` (120) and the pending maximum are new limits.
7. The response is no longer verbatim: status and a bounded body only, no Discord headers, and no
   `X-AP-Decision` or 423/410 after admission (gated requirements 4 and 5, 3.4 steps 6 to 9: only `Abandoned`, `Superseded`, disconnect detection and `approved_but_abandoned` are dropped).

## 12. Tests

1. Idempotency: same key and payload returns the same id and token while pending and inside 60 s, a new
   request after, and 409 for a different payload.
2. Poll after each final status (`approved_and_sent`, `denied`, `expired`, `dropped`) inside and after the
   window.
3. Unknown, malformed and expired tokens return the identical uniform 404.
4. `send_unknown` (reset after `forward_started`) and `send_failed` (before any byte); neither retries.
5. A restart loses pending entries; the old token returns 404 and the audit shows `held` only.
6. Audit shape: the six records are unchanged and no output holds a token, `Authorization`, hash or body.
