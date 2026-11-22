# Muse async poll: replacing the held connection with a poll token

Status: design only, no code. Terms (hold, start claim, `forward_started`, the audit records) are those of
[muse-gated-passthrough.md](muse-gated-passthrough.md), called "the gated design" below. The key words MUST
and MUST NOT are normative. Every token, hash, chat id and address in this file is a placeholder.

## 1. Scope

Only the Muse route `POST /channels/*/messages` (the held route). Every other route, every allowed read and
the blocking mode are unchanged. Blocking stays selectable by configuration; async is chosen per route.

## 2. POST: admit and return

The proxy MUST, in this order: admit the request into the in-memory pending table (section 5), write the
`held` audit record, send the Telegram notification (the existing PR #41 path), and return `202` with a
JSON body `{"request_id": "<id>", "poll_token": "<token>"}`. The token is random, at least 128 bits, stored
only as a hash and compared in constant time. The response MUST NOT echo the request body or
`Authorization`. The request still passes every check of gated design 3.1 to 3.4 before admission.

## 3. GET /poll/<token>?wait=N

The call waits up to N seconds, with N capped at 25, and returns one of:

| Status | Meaning |
|---|---|
| `pending` | No decision yet. |
| `approved_and_sent` | Discord's status and a bounded body (cap set in configuration). |
| `denied`, `expired` | Owner denied, or `async_hold_secs` passed unapproved. Nothing was sent. |
| `send_unknown` | Section 7. |
| `send_failed` | Section 7. |
| `dropped` | Section 8. |

The token is read-only. It MUST NOT approve, deny or change any state. An unknown, expired-window or
malformed token returns one uniform `404` with an identical body and timing class. Polls are rate limited
per token.

## 4. State kept

Pending entries, plus one fixed 60 s final window. During the window the final status stays readable and
the Idempotency-Key stays recorded. Afterwards the token returns the uniform 404 and the key is forgotten.
There is no retained-entry cap beyond this window and no per-identity retained count.

## 5. Idempotency

The Idempotency-Key is bound to the payload hash (method, route, body digest). Admission is atomic under
the table lock:

- Same key, same payload, while pending or inside the 60 s final window: return the same `request_id` and
  token. A retry MUST NOT become a newly admitted send.
- Same key, different payload: `409`.
- Same key after the window: a new request.

## 6. Approval

The owner decides on Telegram only (unchanged). Approve runs the existing start claim before any upstream
byte: policy, token-identity expiry and hash, and that the hold is still live (gated design 3.9, 4.5).
`forward_started` MUST be durable before the upstream connect. The audit records `held`, `approved`,
`forward_started`, `completed`, `expired`, `denied` keep their current shape and never carry a token,
`Authorization`, hash or body.

## 7. Past forward_started

A request that has passed `forward_started` MUST NOT end as `dropped`. If the process cannot confirm
Discord's result (connection reset, timeout), the status is `send_unknown` with the error class. The proxy
MUST NOT retry blindly. Crash recovery cannot apply, because memory is lost. A failure before any request
byte left is `send_failed`. Muse treats `send_unknown` as possibly delivered and submits a NEW request with
a NEW Idempotency-Key only after the owner decides, never as a blind retry.

## 8. Restart, reload and expiry

Pending entries are lost on restart. A token whose entry was lost returns the uniform 404. A `held` record
in the audit with no completion is the expected trace of such a loss, and needs no extra record. A policy
reload that removes the hold before the start claim ends the entry as `dropped` (gated design 3.9,
`dropped_on_reload`); this is possible only before `forward_started`.

## 9. Limits

A configured maximum of pending entries (a full table refuses with 503 `table_full`) and `async_hold_secs`
(default 120). A pending entry not approved by then ends as `expired`, nothing sent. Poll rate limit per
token (section 3).

## 10. What this replaces

This replaces requirement 6 and section 5 of the gated design ("the connection is the state") for this
route only. No longer guaranteed: a Muse disconnect no longer cancels the hold, so `abandoned` and
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

## 12. Tests

1. Idempotency: same key and payload returns the same id and token while pending and inside 60 s, a new
   request after, and 409 for a different payload.
2. Poll after each final status (`approved_and_sent`, `denied`, `expired`, `dropped`) inside and after the
   window.
3. Unknown, malformed and expired tokens return the identical uniform 404.
4. `send_unknown` (reset after `forward_started`) and `send_failed` (before any byte); neither retries.
5. A restart loses pending entries; the old token returns 404 and the audit shows `held` only.
6. Audit shape: the six records are unchanged and no output holds a token, `Authorization`, hash or body.
