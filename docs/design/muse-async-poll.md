# Muse async poll for held writes

Status: draft, awaiting owner confirmation. Terms (held, start claim, `forward_started`,
`dropped_on_reload`) are as in `muse-gated-passthrough.md` 3.4 and 4.5.

## 1. Scope

Only the Muse route `POST /channels/*/messages` (held). Blocking mode stays selectable by config.
Everything else is unchanged.

## 2. POST

1. Write the `held` audit record first. If the write fails, refuse 503 `audit_unavailable` before any
   entry exists and before any notification.
2. Run the existing admission checks (cooldown, `max_held_per_identity`, `max_held_total`) with their
   existing refusals.
3. Insert the entry in the in-memory pending table, send the existing Telegram notification.
4. Return 202 with `request_id` and a random poll token (at least 128 bits, stored only as a hash,
   compared in constant time). The body and `Authorization` are never echoed.

## 3. GET /poll/<token>?wait=N

`wait` missing means 0, capped at 25 s. Non-numeric or negative is 400, without revealing whether the
token exists. Response is `pending` or a final status:

| status | HTTP | fields |
|---|---|---|
| `approved_and_sent` | 200 | `status`, `request_id`, `discord_status`, bounded `body`, `truncated` |
| `denied`, `expired`, `dropped` | 200 | `status`, `request_id` |
| `send_failed` | 200 | `status`, `request_id` |
| `send_unknown` | 200 | `status`, `request_id`, `error_class` (`reset`, `timeout`, `write_failed`) |

The token is read-only. It can never approve, deny or change state.

## 4. Retention

A final status stays readable for one fixed 60 s window. After that, and for any unknown token, the
response is a uniform 404. No retained-entry cap beyond this window.

## 5. Retries

No `Idempotency-Key` and no idempotency store. Muse never retries a POST blindly. After a lost or
unknown POST response it submits a NEW request. This is safe because every message needs its own
Telegram approval: a duplicate is a separate approval the owner can deny, so there is no unapproved
double send.

## 6. States and races

- A request that has passed `forward_started` never ends as `dropped`. An unconfirmed result is
  `send_unknown` with an error class.
- `forward_started` is durable before the upstream connect.
- A start-claim failure before any byte maps to `dropped`, audit code `dropped_on_reload`.
- Approve versus expiry race on one mutex. The first transition wins.

## 7. Restart

Restart drops all pending entries. A poll then returns the uniform 404. An audit `held` record with no
completion is the expected trace.

## 8. Approval and audit

Approval stays on Telegram only, with the existing start-claim checks. Audit records keep their current
shape and never carry a token, `Authorization`, hash or body. `async_hold_secs` (default 120) bounds a
pending entry. Unapproved entries end as `expired`.

## 9. Departures

- Connection-as-state is replaced for this route.
- No cancel on Muse disconnect.
- Discord response headers are not returned verbatim.
- `X-AP-Decision` is not returned after admission.

Owner confirmation is needed for these four departures before implementation.

## 10. Tests

- Poll after each final status.
- Uniform 404 after the window and for unknown tokens.
- `send_unknown` path.
- Restart loses pending entries.
- Audit shape, and no token in audit.
