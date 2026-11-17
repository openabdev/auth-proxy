# Durable, fail-closed audit: an opt-in mode

Status: **draft for council review, not final.** Design note only. No code in this change.
Issue: #32 (p2, enhancement). Related: #1 (RFC, open question 5), #5 (approval lines), PR #29
(Muse stage 2, **in review, not merged**).

## How claims are labelled

- **[read]**: read in code or docs. Code facts are for `origin/main` at `3878421` unless the text says
  "PR #29".
- **[M]**: measured. The only measurement in this note is the fsync cost in section 4.6.
- **[I]**: inferred from what I read or from general system behaviour. Not checked here.
- **[A]**: assumed. A value or a decision I picked and the owner may change.

PR #29 is described as I read it on branch `feat/muse-stage2` at `6f3e678`. It is in review, so every
statement about it is [I] about a moving target. This design depends on its *shape* (a fallible
write that must succeed before a write is forwarded), not on names, signatures or line numbers.

## 1. Problem and what exists today

### 1.1 What the code does [read]

- `AuditSink` holds one `Mutex<Box<dyn Write>>` and a failure counter. `write_line` writes the
  bytes, writes a newline if missing, calls `flush`, and on any error adds one to an in-memory
  counter. It returns nothing. The header of `audit_sink.rs` says a failure never refuses a request.
- The binary builds the sink as `AuditSink::stdout()` in two places in `lib.rs`: the sidecar
  pipeline (`App::new`) and the passthrough app (`PtApp::new`).
- One record per request, `AuditRec`: `identity, session, generation, route, method, path,
  aws_target, decision, code, status, duration_ms`, and `bytes_sent` only on `upstream_reset`. There
  is **no request id, no timestamp and no sequence number** [read audit.rs]. The collector that reads
  stdout supplies the time [I].
- Refusals write their line at the moment of refusal (`refuse` in `pipeline.rs` and
  `passthrough.rs`).
- The `allow` line is written **after** the fact, from `Drop for StreamAudit`, when the response
  body ends or the client drops it, with the final status and duration. Before the upstream call
  there is no record of an allowed request [read pipeline.rs, passthrough.rs].
- `flush` on stdout reaches a pipe or a container log driver. It says nothing about a disk [I].
- Other writers through the same sink, with their own JSON shapes [read]: `netfilter` state changes and
  `netfilter_unverified` refusals (`netguard.rs`), `session` operations (`session_http.rs`, includes a
  12-hex-character prefix of the surrogate's sha256), `admin revoke-all` (`admin_http.rs`), the
  stage 1 `probe` lines (`probe.rs`) and the stage 1 evidence line (`evidence.rs`, behind the
  `Trail`).
- `failures()` is read by no code outside the sink, and no crate exposes a metrics endpoint [read, as
  the issue states]. The admin socket exists only in the sidecar profile and serves
  `GET /admin/v1/ready` (`netguard::ready_router`), `/admin/v1/sessions` and `/admin/v1/revoke-all`.
  A passthrough-only deployment binds **no** admin socket [read lib.rs, `run_passthrough` comment].
- `docs/design/phase1.md` says the same in its "Audit write failure" row: counted, never refuses,
  durable audit belongs to RFC question 5 [read].

### 1.2 The stage 2 rule in PR #29 (in review)

The settled stage 2 rule is in `docs/design/muse-gated-passthrough.md` sections 3.9 and 5 [read]:
on held (write) routes a failed `held` or `forward_started` write refuses the request with 503
`unavailable`, code `audit_unavailable`, sends nothing upstream, and a failed `held` write creates
no entry and no notification. Allowed reads keep Phase 1's best-effort behaviour.

In the PR #29 branch the mechanism is `AuditSink::try_write_hold` and `try_write_line`, which return
`io::Result<()>`. `Ok` means `write_all` and `flush` returned `Ok` [read, PR #29 `audit_sink.rs`].
The `held` write runs inside the hold table's `admit`, under the table lock, before anything
changes [read, PR #29 `hold/mod.rs`]. The `forward_started` write runs after the upstream
connection exists and before the first request byte [read, section 3.9 and `hold_path.rs`].

That rule is fail-closed in the sense "no record accepted, no write". It is **not durable**: on a
file, `flush` of a `File` is a no-op in std and the bytes sit in the page cache until the kernel
writes them [I]. A power loss or a kernel panic after `Ok` can lose a `forward_started` record for a
write that already reached the upstream. The rule also covers only held routes.

### 1.3 What this note adds

An opt-in mode that gives, for every request the proxy forwards, a record that is **durable before
the action**, and refuses the action when it cannot be made durable. It makes PR #29's rule one
instance of a general rule and adds the durability that rule lacks. The default stays as it is.

The requirement behind it is the outer-layer item "every step is audited before it runs, and if the
record cannot be written the step does not run" (openab issue 1606, definition of done, item 7, as
quoted in #32) [read #32].

## 2. Goals and non-goals

Goals:

1. `audit.mode = fail_closed`: no upstream contact and no credential swap unless a record of the
   decision is on stable storage, as far as the operating system can report it (section 4.1).
2. State exactly what each mode guarantees and what a reader of the log may conclude from it,
   including after crashes.
3. Keep `best_effort` byte for byte as today when no `[audit]` table is configured (section 3.4).
4. Dependency-light: standard library and the `libc` crate that `ap-proxy` already depends on
   [read `Cargo.toml`]. One writer thread, no async file crate, no database, no message queue.
5. Recover by itself when the sink works again. No operator action.
6. Never put a secret in a record, and never let a failure message carry one.

Non-goals:

- No networked audit service, no syslog or remote shipping, no blockchain, no signing service.
  Shipping, retention and deletion of files stay with the deployment (RFC question 5, other half).
- No hash chain in the first version. Section 6.3 describes it as an optional follow-up with its
  trade-off.
- No protection against an attacker who can delete or rewrite the file. The agent must not be able
  to reach the file, and that is a deployment matter (as #32 says). Section 6.3 says what the
  sequence numbers do and do not detect.
- No change to the default and no change to refusal codes other than adding `audit_unavailable` to
  the sidecar pipeline.
- No audit of the runtime side (openab-pty floor endpoint, tracked in openab-pty issue 100).
- Revocation is never blocked by audit failure (section 3.3).

## 3. The option

### 3.1 Configuration [A, names are proposals]

```toml
[audit]
mode = "best_effort"            # default. "fail_closed" is the opt-in
sink = "stdout"                 # "stdout" (default) or "file"
path = "/var/log/auth-proxy/audit.jsonl"   # required when sink = "file"
fsync = "per_record"            # fail_closed only: "per_record" or "group_commit". No "none"
group_commit_max_ms = 5         # group_commit only
write_timeout_ms = 2000         # fail_closed only: bound on one durable append
max_segment_bytes = 67108864    # fail_closed only: rotation threshold (section 4.5)
heartbeat_secs = 30             # fail_closed only: 0 disables (section 8)
```

No `[audit]` table means `best_effort` on stdout, exactly today. `fail_closed` with `sink = "stdout"`,
without `path`, with `fsync` missing or unknown, or with `write_timeout_ms = 0` is a startup error,
exit code 2, like other configuration errors [read lib.rs, exit code 2 for config failures]. The full
startup rejection list is in section 4.8.

### 3.2 What each mode guarantees

| | `best_effort` (default) | `fail_closed` |
|---|---|---|
| Sidecar pipeline, allowed request | One record after the fact. A write failure is counted. The request is never refused for audit reasons | A **decision record** is durable before the credential swap and before upstream contact. If it cannot be made durable the request is refused `audit_unavailable`. An **outcome record** is written after, best effort |
| Passthrough read (allowed) | As today: one record after the fact, best effort | Same as the sidecar row |
| Passthrough held write (PR #29, in review) | PR #29's rule as written: `held` and `forward_started` must be written and flushed (`Ok`), otherwise 503 `audit_unavailable`. Not durable | Same refusals, but "written" means durable (fsynced). Plus `approved` is required before `forward_started` (section 3.3) |
| Refusal (deny, `unavailable`, ...) | One record at refusal time, best effort | One record at refusal time, attempted. If it cannot be written the refusal stands and the failure is counted |
| Sink | stdout or file, no durability claim | file only, durable per section 4 |
| What a reader may conclude | Records that exist are true. Absence proves nothing | Section 7.3: for a request the proxy forwarded, a decision (or `forward_started`) record exists, unless the sink reported a gap |

[A, design]. The exact guarantee of `fail_closed` is one sentence:

> If the proxy contacted an upstream for a request, a record `decision` (or, for a held write,
> `held`, `approved` and `forward_started`) for that request was reported durable by the operating
> system before the contact, or a `gap` record says records may be missing from the interval
> that contains it.

What it does not say: that the outcome is recorded; that the record is on the *medium* (a disk that
lies about flush defeats it, see 4.6); that nothing else touched the file.

### 3.3 Record kinds and when they are written

"Write-ahead" means: the record must be durable before the action it describes, and the action is
refused if it cannot be. "Gating" is the same thing seen from the request. Everything else is
"after": attempted, counted when it fails, and it never changes what the request sees.

| Kind | Pipeline | When | Write-ahead (gating) in `fail_closed`? | If the write fails |
|---|---|---|---|---|
| `decision` (allow) | sidecar, passthrough read | after policy allows, before the credential swap and before the upstream connect | **yes** | refuse 503 `audit_unavailable`, no contact, no swap |
| `outcome` | sidecar, passthrough | when the response body ends or the client drops it (today's `allow` line). Carries final status, duration, `code` (`upstream_reset`, `body_failed_after_send`), `bytes_sent` | no, **after** | counted (`outcome` bucket). The stream is not aborted |
| `deny` | both | at the refusal | no, the refusal is the outcome | refusal stands, counted |
| `held` (PR #29) | passthrough held write | at admission, before the entry exists | **yes** | 503 `audit_unavailable`, no entry, no notification [read, PR #29] |
| `approved` (PR #29) | passthrough held write | when the waiting handler sees the approval | **yes, proposed** (PR #29 writes it with the best-effort `write_hold` [read, PR #29 `hold_path.rs`]) | refuse `audit_unavailable`, nothing sent, approver is told `audit_unavailable` (the result code exists in PR #29 for the `forward_started` failure) |
| `forward_started` (PR #29) | passthrough held write | after the upstream connection exists, before the first request byte | **yes** | 503 `audit_unavailable`, nothing sent |
| `denied`, `expired`, `abandoned`, `superseded`, `dropped_on_reload`, `abandoned_after_approve`, `connect_failed` (PR #29) | held write | at the transition. In every one of them nothing was sent | no, **after** | counted. The reader still concludes "not sent" from the absence of `forward_started` (7.3) |
| `completed` (PR #29) | held write | when the response body ends | no, **after** | counted |
| `audit_unavailable` (PR #29 transition name) / `outcome` with `code=audit_unavailable` | both | when a gating write failed | no, **after**, best effort. The sink is probably down. Written with a non-waiting append, section 4.7 | counted |
| `notify_failed` (PR #29) | held write | when the notifier fails | no | counted |
| `netfilter` | sidecar | state change, and each `netfilter_unverified` refusal | no (a refusal, as `deny`) | counted |
| `session`, `admin revoke-all` | sidecar | after the operation | **no, proposed** (open question 5). Revocation is never gated: an action that reduces authority must not be blockable by a full disk [I] | counted |
| `probe`, evidence | stage 1 measurement only | as today | no | counted |
| `start` | both | once at startup, durable, before the listener accepts | yes (a failure is a startup error) | exit 2 |
| `gap` | both | first record after a recovery from a failed durable write (4.4) | yes, it is the first record of the new segment | the sink stays unhealthy |
| `heartbeat` | both | every `heartbeat_secs` while idle or busy | no, but it feeds health (section 8) | counted, marks unhealthy |
| `segment_start` | both | first record of each segment (4.5) | yes | rotation is abandoned, old segment stays in use |

[A]. The `held`, `forward_started` rows and the transition names come from PR #29 and may change. The
design requirement on them is only: *the records that gate a held write are the ones that precede its
first byte upstream*.

Two properties follow from the file being written by one writer in order:

1. **`fsync` is file-wide [I].** When the acknowledgement for record N arrives, every record appended
   before N in the same segment is on stable storage too, including a best-effort `outcome` of an
   earlier request. So `approved` can be appended just before `forward_started` and one sync covers
   both (this is the group-commit effect of section 4.2).
2. **A record's position gives happens-before for records of the same boot**, through `seq`
   (section 5). It does not give wall-clock order (section 7.4).

### 3.4 `best_effort` stays byte for byte [A, design]

The envelope fields added in this note (`v`, `boot`, `seq`, `ts_ms`, `mono_ms`, `kind`,
`request_id`) are emitted **only in `fail_closed`**. In `best_effort` the lines are the ones the
tests pin today (`json_keys_are_exactly_the_allowed_set` in `audit.rs` [read]). The same holds
for PR #29's `HoldRec` key set. A test compares the bytes of both pipelines' lines before and after the
change (acceptance criterion 1 of #32).

Whether `best_effort` may also use a file sink without durability is open question 9.

## 4. Durability

### 4.1 What "durable" means here

A record is durable when `write_all` of the whole line (one `write` loop, short writes
continued), then `sync_data` on the file descriptor, all returned `Ok`. `sync_data` is enough for
the record bytes and the file length [I: on Linux `fdatasync` flushes data and the metadata needed
to read it back, which includes the size when it changed]. When a file is **created**, or a segment is
renamed, the containing directory is also synced (open the directory, `sync_all`) before the first
record is relied on.

This is "reported durable by the operating system". A disk or controller that acknowledges a flush
and does not honour it is outside the guarantee [I]. Section 4.6 shows the platform difference that
makes this concrete.

### 4.2 The file sink

- Opened with `OpenOptions::new().append(true).create(true)`, mode `0600`, close-on-exec, and
  `O_NOFOLLOW` through `custom_flags` so a symlink at the path is refused [I, `libc` is already a dependency].
  `O_APPEND` means each write goes to the end even if another descriptor wrote or the file was truncated
  [I]. No `O_TRUNC` ever.
- At startup, after open: `fstat` and require a **regular file**; take an exclusive advisory lock
  without blocking (`flock(LOCK_EX|LOCK_NB)` through `libc`) and refuse to start if another process
  holds it, so two proxies cannot interleave in one file [A]. Check the last byte of an existing file:
  if it is not `\n`, a previous process died inside a write. Append one `\n` first, so the torn line
  stays a separate unparsable line, and the `start` record says `prev_tail = "torn"` (otherwise
  `"clean"` or `"empty"`).
- **One writer thread** (`std::thread`), not a `spawn_blocking` task, owns the file descriptor. A
  blocked `fsync` cannot then exhaust the runtime's blocking pool or a tokio worker, and the single
  writer gives the ordering in section 3.3 [A, design]. Requests send `(line bytes, ack channel,
  cancel flag)` through a bounded channel (capacity [A] 1024) and `await` the ack with
  `tokio::time::timeout(write_timeout_ms)`. A full channel is an immediate refusal, which is the
  "no queueing of requests while the sink is down" rule of #32: the channel holds records of requests
  that are *waiting for an ack*, not requests parked for later.
- `per_record`: the writer takes one job, writes it, `sync_data`, acks, next job. One sync per record.
- `group_commit`: the writer takes the first job, then collects further jobs until
  `group_commit_max_ms` has passed or [A] 256 records are pending, writes all, calls `sync_data` once,
  then acks every job in the batch. **No ack is sent before the sync that covers that record
  returns.** The cost to the first request in a batch is up to `group_commit_max_ms` of waiting.
  Config validation requires `group_commit_max_ms * 2 <= write_timeout_ms` [A].
- A job whose request already timed out has its cancel flag set. The writer skips cancelled jobs
  that it has not yet written. This stops a stalled disk, once it wakes, from writing a flood of
  `decision` records for requests that were already refused.
- The sync call is never made while holding any lock shared with request handling. This is a hard
  requirement on integration with PR #29: its `held` write runs **inside the hold table's lock**
  [read, PR #29 `hold/mod.rs`, `admit`]. A durable append that waits milliseconds, or up to
  `write_timeout_ms` on a stalled disk, must not run there, because it would stall every admission,
  approval and drain on the table. Stage 5 changes `admit` to reserve under the lock, persist
  outside it, and commit or roll back under it (section 10). Until then `fail_closed` must not be
  enabled together with held routes [A].

### 4.3 What each failure looks like

| Event | Writer behaviour | Request sees | Health |
|---|---|---|---|
| `write` returns an error (EIO, EBADF, EDQUOT, ...) | stop using this descriptor, mark unhealthy, run recovery (4.4) | 503 `audit_unavailable` for gating records; nothing for after records (counted) | unhealthy |
| Short write (fewer bytes than the line, then an error) | try `ftruncate` back to the last known good length. If that fails the segment is abandoned at recovery | same as above | unhealthy |
| `ENOSPC` on `write` | same as a write error, with `reason = "enospc"`. Possibly a torn line is left, repaired by the truncate above or tolerated by readers | same | unhealthy |
| `ENOSPC` or `EIO` on `sync_data` | the batch is **not** acknowledged. The descriptor is treated as untrusted (4.4) | same, for every request in the batch | unhealthy |
| Writer blocked in `write` or `sync_data` (slow disk, stuck NFS-like mount) | the thread cannot be cancelled. Callers time out after `write_timeout_ms` | 503 `audit_unavailable` after `write_timeout_ms` | unhealthy while any job is older than `write_timeout_ms` |
| Channel full | not enqueued | immediate 503 `audit_unavailable` | unhealthy while it stays full |
| Open or directory sync fails during recovery or rotation | stay on the old descriptor if it is healthy, otherwise unhealthy | as above | per case |

[A, design] on all rows. The write timeout starts when the request calls `append` and ends at the ack.
It is **not** a bound on the disk: the stuck thread stays stuck. That is why the writer is a
separate thread (4.2) and why the health bit is derived from the age of the oldest unacknowledged job.

**What a request sees on a slow sink.** Every gating request waits up to `write_timeout_ms` (default
[A] 2000 ms), then receives the refusal of section 9.1. While the writer is stuck, new gating requests
also wait their own `write_timeout_ms`, unless the channel is full, then they fail at once. To avoid a
slow sink holding up thousands of requests for two seconds each, once the sink is marked unhealthy
for a timeout, further requests fail fast and **one probe write per `retry_ms`** ([A] 250) is let
through (4.4). This narrows #32's wording "each request tries its own write" to "each request may
be the probe". Open question 7.

A refused request whose record is **still written later** (the writer was only slow) leaves a
`decision` record with no upstream contact. The reader rule in 7.3 already treats a decision without
an outcome as "authorized, possibly executed", so this stays on the safe side. The `outcome` record
that the handler tries to write after the refusal (`code=audit_unavailable`) narrows it when it
lands.

### 4.4 After an error: no retry of `fsync`, a new segment, a gap marker

On Linux, after `fsync` reports an error the kernel may have marked the affected pages clean, so a
second `fsync` on the same descriptor can return success while the data never reached the disk [I,
widely documented behaviour after the PostgreSQL fsync findings; not reproduced here]. The design
therefore **never retries `fsync` on a descriptor that failed**:

1. The writer marks the sink unhealthy and notes `last_durable_seq`, the highest `seq` that was
   acknowledged durable in this boot.
2. The next probe (at most one per `retry_ms`, or the next request when no failure is recent)
   closes the old descriptor, creates a **new segment** (4.5), syncs the directory, and writes as the
   first record a `gap`:
   `{"kind":"gap","reason":"fsync|write|enospc|timeout|open|rotate","last_durable_seq":N,"lost_from_seq":N+1,"lost_to_seq":M,"prev_segment":"<name>"}`
   where `M` is the highest `seq` the writer had assigned before the failure. Records with
   `lost_from_seq <= seq <= lost_to_seq` may be absent from the previous segment, or present and
   not durable, or present and durable. The marker says "may", not "are lost".
3. When the `gap` record and its sync succeed the sink is healthy again, and gating records flow.
   The record **after** the gap carries nothing special: `seq` continues from `M + 1`.
4. If recovery fails (disk still full, directory unwritable) the sink stays unhealthy and the cycle
   repeats at the next probe.

A segment where the write failed but `sync_data` was never reached (no fsync error) uses the same
path with `reason = "write"`. A reader that finds a `seq` discontinuity **without** a `gap` marker
(a crash, a lost segment) must treat it as a gap too (7.2).

### 4.5 Rotation without losing records

[A, design]. Segments are owned by the proxy so that no record is written to a file that is being
moved. Names: the active file is `path`; a closed segment is `path.<boot>.<first_seq>-<last_seq>`.

Rotation happens when `max_segment_bytes` is reached, between jobs, on the writer thread:

1. `sync_data` on the active file. Any error goes to 4.4.
2. `rename(path, path.<boot>.<first_seq>-<last_seq>)`.
3. Create the new `path` (`O_CREAT|O_EXCL|O_APPEND`, `0600`).
4. Sync the directory. Now both names are durable.
5. Write `segment_start` with `prev_segment` and `prev_last_seq`, then `sync_data`.

A crash after step 2 and before step 3 leaves no `path`. Startup creates it and the `start` record says
`prev_tail = "missing"`. The renamed segment is found by name and its `last_seq` is in its name, so a
reader joins them without help. A crash between 3 and 5 leaves an empty `path`, handled as
`prev_tail = "empty"`. If step 3 or 4 fails, rotation is abandoned and the writer continues on the old
descriptor (renamed, still valid); rotation is retried after the next threshold. No record is lost
and health is unchanged, but `audit_rotate_failures_total` rises.

External rotation (logrotate with `rename`, then a "reopen" command) is not part of this design.
`copytruncate` must not be used: it loses the records appended between the copy and the truncate
[I]. A reopen operation on the admin socket can be added later (open question 8). Retention and
shipping of closed segments remain the deployment's job.

### 4.6 What fsync costs [M]

One scratch file in a temporary directory on the internal SSD of a Mac mini (APFS), 220-byte
records, one writer, idle machine, record appended with `write`, then the flush call timed. This is
**macOS, not the Linux filesystem the proxy will run on**, and shows only the order of magnitude.

| Flush call | n | p50 | p99 | max |
|---|---|---|---|---|
| `fsync` | 300 | 0.012 ms | 0.022 ms | 0.023 ms |
| `fcntl(F_FULLFSYNC)` | 300 | 3.93 ms | 4.21 ms | 9.34 ms |
| 8 records, then one `F_FULLFSYNC` | 100 batches | 3.83 ms per batch | 4.86 ms | |

Reading, [I] where stated: on macOS plain `fsync` does not ask the drive to flush its cache, so the
12 microsecond figure shows the call is cheap, not that data is stable. `F_FULLFSYNC` is the call
that does. Whether Rust's `sync_data` uses it on macOS is not checked here. For the proxy's Linux
target the numbers must be remeasured on the stated disk (stage 3 acceptance). Arithmetic [I]: at
about 4 ms per sync, `per_record` caps one process near 250 durable records per second, and each
allowed request needs one (the `decision`); eight records per sync lifts that near 2000 per second.
`group_commit` is the answer when that is not enough.

### 4.7 The outcome record is a non-waiting append

`StreamAudit::drop` writes the outcome today, synchronously, in a destructor on a runtime worker [read].
A durable wait there would block a worker for a sync. In `fail_closed` the outcome is a **non-waiting
append**: put the job in the writer's channel and return. The writer syncs it with the next batch. If
the channel is full the record is dropped and counted. The client never waits for it.

### 4.8 Startup rejection (exit code 2, message on stderr, nothing listens)

`fail_closed` is refused at startup when any of the following holds [A, design]:

- `sink` is `stdout`, or missing, or `path` is missing or empty;
- `fsync` is missing, `none`, or unknown;
- `write_timeout_ms` is 0, or `group_commit_max_ms * 2 > write_timeout_ms`;
- the path cannot be opened for append, is not a regular file, is a symlink, or the directory is not
  writable;
- the lock is held by another process;
- the directory sync or the first durable `start` record fails (the sink is not able to do what the
  mode promises, so start refuses instead of starting unhealthy).

The message names the setting, never a path's contents and never an `io::Error` string that could
echo input (it prints the `ErrorKind` and a fixed phrase).

## 5. A request id that joins the records

### 5.1 The field

`request_id` is 16 random bytes from the operating system's random source, hex encoded (32 characters),
minted when the request enters the handler, before policy, so it also exists on refusals. It is **not
derived from any input**: not the caller key, the surrogate, the path, the time or the body [A, design].
It is unique with overwhelming probability across restarts, so it needs no `boot` to be joined.

`boot` is a separate 8-byte random value minted per process start. With `seq` it names a record:
`(boot, seq)` is unique, and `seq` is a counter from 1 that grows by one for every record assigned to the
writer, including `gap`, `heartbeat` and best-effort ones.

### 5.2 What joins what

- `decision` and `outcome` of one request share `request_id`. A `deny` is one record with its own id.
- Records written for a held write share `request_id` with the **hold entry id**. PR #29's `HoldRec` has
  `request_id` set to the hold entry id, and the id is minted inside `admit` **after** the cooldown,
  duplicate and cap checks [read, PR #29 `hold/mod.rs`]. Two consequences, both [I]:
  - the requests refused before that point (`cooldown`, `identity_cap`, `table_full`, `shutdown`) have
    no hold id today, so their `deny` record would have no join key;
  - a held request that also writes a `decision` record needs the two ids to be the same.

  The design asks for **one id per request, minted at handler entry, and used as the hold entry id**.
  This is a small change in PR #29's shape (pass the id into `admit`), but PR #29 is in review. It is
  therefore stage 5, after it merges, and open question 3 asks whether to do it inside the PR instead.
  A fallback that needs no change in PR #29 exists: add a `req` field to `HoldRec` records and keep the
  hold id as is, then join on `req`.
- Superseded requests (PR #29): the older entry's records keep its own request id. How the `superseded`
  record names the newer entry is PR #29's business and is not specified here.

## 6. Secrecy and tamper evidence

### 6.1 Allow-list of fields

A record is built from a fixed struct per kind. No field is a free-form string from the request or an
`io::Error` message. The allow-list below is complete; adding a field is a design change with review.

| Field | Kinds | Content |
|---|---|---|
| `v` | all | schema version, integer |
| `boot`, `seq`, `ts_ms`, `mono_ms` | all | boot id, counter, wall-clock ms since epoch, monotonic ms since process start |
| `kind` | all | one of the kinds in 3.3 |
| `request_id` | request kinds | random id, 5.1 |
| `pipeline` | request kinds | `sidecar` or `passthrough` |
| `identity` | request kinds | identity **name** from config |
| `session`, `generation` | request kinds | session id and generation, as today |
| `route`, `method` | request kinds | route name, HTTP method |
| `path` | request kinds | route-relative, query and fragment dropped, `webhooks`/`interactions` token segments replaced by `<redacted>` (PR #29's `redact_path`, in review) |
| `aws_target` | request kinds | `X-Amz-Target` value, as today |
| `decision`, `code`, `status`, `duration_ms`, `bytes_sent` | request kinds | as today |
| `digest` | held kinds (PR #29) | hex sha256 of the credential-blind outbound request digest |
| `approver` | `approved`, `denied` | approver identity name |
| `auth_present` | held kinds | boolean |
| `reason`, `errno` | `gap`, health | fixed enum and numeric errno; no error text |
| `last_durable_seq`, `lost_from_seq`, `lost_to_seq`, `prev_segment`, `prev_last_seq`, `prev_tail` | `gap`, `segment_start`, `start` | sequence numbers and a segment **file name** the proxy itself generated |
| `surrogate_sha256_prefix` | `session` | 12 hex characters of a hash, as today [read session_http.rs] |
| `mode`, `fsync`, `version` | `start` | config enum values and the build version |

Never present in any record, metric, log line or stderr message: a caller key, the `/ap/<key>/` prefix
(the path is route-relative by construction [read audit.rs]), a surrogate, a credential, any
`Authorization` or other header value, a request or response body, a query string, a full file path
of the sink, an `io::Error` display string.

### 6.2 How it is enforced

The existing tests already pin the key set of `AuditRec` and the absence of the query [read audit.rs
tests]. This design extends them: one key-set test per kind, and a **canary test** that sends requests
carrying a canary caller key, surrogate, `Authorization` value, query string and body, forces every
failure of section 4.3, then searches the sink file, the metrics output, the readiness body and the
captured stderr for the canary. Tests that "the check and the code use the same rule" are satisfied by
using the serialized output, not the struct.

### 6.3 Tamper evidence: optional follow-up, not part of this change

`seq` and `boot` already make **deletion or reordering in the middle** of a boot's records visible
(a discontinuity), and `gap` records state known losses. They do not stop a writer with file access from
rewriting the file with consistent numbers [I].

Optional follow-up, `audit.chain = "sha256"` [A]: each record carries `prev`, the hex sha256 of the
previous line's bytes, and the first record of a segment carries the last hash of the previous one. The
writer already serializes records, so the cost is one hash per record (microseconds [I]).

| | Gain | Cost or limit |
|---|---|---|
| Hash chain | detects edit, insertion or deletion in the middle of a chain by a reader that verifies | does **not** detect truncation at the tail, or a full rewrite by someone who recomputes the chain, unless the head hash is anchored somewhere the attacker cannot write (a second system, which this design excludes) |
| | | the chain must survive restarts and rotation (anchor in `start` and `segment_start`), and a `gap` breaks it by design |
| | | every reader and every shipper must preserve bytes exactly |

Recommendation: do not make it mandatory. Revisit if a deployment needs evidence rather than a log.
The Muse design dropped the hash-chained store for the PoC with the same reasoning
(`muse-gated-passthrough.md` section 5.2, "Hash-chained audit store: Drop") [read].

## 7. Failure analysis

### 7.1 Crash points

Records are numbered here as the proxy sees them: D = decision (or `held`/`forward_started` for a
held write), A = the action (credential swap and upstream contact; the first request byte for a held
write), O = outcome.

| Crash or kill at | State on disk | State upstream | What the client sees | What a reader must conclude |
|---|---|---|---|---|
| before D is written | no record | nothing | connection error | request not seen. No evidence either way |
| D written, not yet synced | the record may be there, may be missing | nothing (A waits for the ack) | connection error | **not executed**, but the record may be absent. A missing D never means "executed": A did not run |
| D durable, before A | D, no O | nothing | connection error | "authorized, possibly executed" (the reader cannot tell this from the next row, for `decision` records) |
| after A began, before O | D, no O | **maybe** executed | connection error or a partial response | "authorized, **possibly executed**". See 7.3 |
| after O | D and O | executed, response ended | normal | executed, with outcome |
| held write: before `forward_started` | `held` (and maybe `approved`), no `forward_started` | nothing sent | connection error | **not sent**. Ordering guarantees no first byte before `forward_started` is durable [I, relies on PR #29's ordering, in review] |
| held write: after `forward_started`, before `completed` | `forward_started`, no `completed` | maybe sent | connection error | "possibly executed", exactly the row in section 5.1 of the Muse design: "audit `forward_started` without `completed`" [read] |

### 7.2 What a reader must do

- Group by `request_id`. For one request the legal sequences are: `deny`; `decision` then `outcome`;
  `decision` alone; `held`, ..., `forward_started`, `completed` or not; `held`, ..., a terminal
  that is not `forward_started`.
- Sort by `(boot, seq)` within a boot. Order boots by the `start` records' `ts_ms`, and treat any
  wall-clock comparison as informational (7.4).
- A `seq` discontinuity inside a boot with no `gap` covering it is a **gap**: records may be missing
  between those sequence numbers.
- A decision with no outcome and no `gap` is "authorized, possibly executed". A held write with
  `forward_started` and no `completed` is the same. Do not infer "failed" from a missing outcome.
- An unparsable line is skipped and counted. It is either a torn tail (7.1, `prev_tail = "torn"`) or
  corruption.

### 7.3 The sentence the log supports

For a request that has a durable `decision` (or `held` + `approved` + `forward_started`):
the proxy authorized it **before** acting. Whether it acted is known only when the outcome exists.
For a request the upstream received, the log contains the `decision` unless a `gap` covers its
`seq`. For a request with no `decision` and no gap the proxy did not contact the upstream. Nothing
here says the upstream *executed* a side effect: it says the proxy sent the request.

### 7.4 Duplicates, restarts and clock jumps

- **Duplicates after restart.** The proxy keeps no queue and replays nothing: a held request dies
  with its connection (Muse design section 5.1 [read]). The record of a refused-by-timeout request that
  lands later is not a duplicate, it is the ambiguous case in 4.3. A reader dedupes on `(boot, seq)`;
  two `outcome` records for one `request_id` are an anomaly to report, not to merge.
- **Restart in the middle of a group-commit batch.** Jobs not yet acked were never acknowledged; their
  requests see a connection error. Records of that batch may be on disk. They keep their old `boot`
  and `seq` and are not rewritten.
- **Clock jumps.** `ts_ms` is `SystemTime` and can jump backward or forward (NTP step, VM resume). It is
  only informational. Order is `seq` within a boot and `mono_ms` as a cross-check (non-decreasing
  within a boot). A reader that sees `ts_ms` go backward while `seq` grows reports a clock step and
  trusts `seq`. The `start` record carries both clocks so boots can be placed in time without trusting
  a later clock. Durations use `Instant`, as `duration_ms` does today [read].
- **Disk full then recovered.** Handled by the gap marker (4.4). The first record after recovery is
  `gap`, not a request record.
- **Shutdown.** On SIGTERM the proxy stops accepting, lets the writer drain and sync, then exits. Outcomes
  of in-flight streams cut off by the exit are lost and not counted by the proxy (it is gone) [A];
  readers treat them as "possibly executed" by 7.2.

## 8. Metrics and readiness

### 8.1 Exposure

There is no metrics endpoint today [read]. Smallest exposure that works [A]: JSON on the existing admin
socket, `GET /admin/v1/audit`, mode `0600` like the rest of the socket. No new port, no Prometheus text
format in the first version (open question 6).

```
{ "mode":"fail_closed", "healthy":1, "write_failures_total":{"decision":0,"outcome":0,"other":0},
  "refused_total":0, "timeouts_total":0, "gaps_total":0, "rotate_failures_total":0,
  "outcome_dropped_total":0, "queue_depth":0, "last_error_class":"none",
  "fsync_seconds":{"count":0,"sum":0.0,"max":0.0,"buckets":[...]} }
```

These map to #32's required names: `audit_write_failures_total` split by record kind (`decision` for
gating records, `outcome` for the rest), `audit_refused_total`, `audit_fsync_seconds` (a fixed-bucket
histogram: count, sum, max and the buckets, no dependency), and `audit_sink_healthy` (0 or 1).
`last_error_class` is a fixed enum (`none|write|fsync|enospc|timeout|open|rotate`), never an error string.
In `best_effort` mode the endpoint returns the existing failure counter only.

A passthrough-only deployment has no admin socket [read]. In `fail_closed` it binds one, on the
same path flag the sidecar uses, mode `0600` (open question 4: or PR #29's approval listener, which is
in review).

### 8.2 Health bit

`healthy` is 1 when the last durable write (any record, including `heartbeat`) succeeded and no job
is older than `write_timeout_ms`. It is 0 otherwise. With `heartbeat_secs > 0` the writer appends a
`heartbeat` record at that interval, so a disk that fails while the proxy is idle becomes visible within
one interval and a silent break cannot hide until the first real request [A].

### 8.3 Readiness

When `fail_closed` and the sink is unhealthy, `GET /admin/v1/ready` answers 503 with the existing JSON
shape and state `audit_unavailable` (the same endpoint and `--check-ready` exec probe that the netfilter
gate uses [read netguard.rs]); otherwise unchanged. Rules:

- Readiness only. **Never a liveness failure.** Restarting the proxy does not fix a disk, and a restart
  loop would drop held requests.
- The admin socket and its handlers do not touch the sink for a read, so they stay responsive when the
  sink is stuck (writer thread blocked, request path timed out). `revoke-all` still revokes; its audit
  line is non-waiting (3.3) and the revocation is not conditional on it.
- Flap control [A]: the sink becomes healthy only after the `gap` record is durable, and readiness
  returns after two consecutive healthy heartbeats, to avoid flapping on a marginal disk.
- In the sidecar profile readiness `503` takes the pod out of Service endpoints, but the agent still
  reaches the proxy on pod loopback and gets `audit_unavailable`. That is the intended behaviour: an
  unhealthy sink must be loud and must not cause a restart [I].

## 9. Compatibility

### 9.1 The refusal on the wire

`audit_unavailable` is already specified for held routes in PR #29 (in review) [read]. Main has no such
code [read: no `AuditUnavailable` in `error.rs` on `origin/main`]. Reuse it:

- Passthrough pipeline: HTTP **503**, header `X-AP-Decision: unavailable`, `Content-Type:
  application/json`, body exactly `{"ap_decision":"unavailable","code":"audit_unavailable"}`
  (the `render_passthrough` shape, as PR #29 tests it: two keys only) [read, PR #29 `outcome.rs`].
- Sidecar pipeline: HTTP **503**, `Code::AuditUnavailable` rendered by `render(code, shape)` in the
  route's dialect [read main `error.rs`]: generic `{"error":"audit_unavailable","message":"the audit
  log is unavailable"}` (the message string from PR #29's `Code::message`, in review) or the AWS shape
  `{"__type":"AccessDeniedException","message":"auth-proxy: audit_unavailable: ..."}`. The code
  table in `phase1.md` gets one row, 503, route's dialect, logged at `error`, rate limited, like
  `broker_unavailable`.
- No `Retry-After` is invented: main sets none today [read, no match in `ap-core`/`pipeline.rs`].
- No part of the body carries a path, an errno or any detail. The refusal is not distinguishable by
  cause (disk full, timeout, fsync error): the cause is in the metrics (`last_error_class`).
- The refusal itself is audited best effort (`deny`/`outcome` with `code=audit_unavailable`).
  When the sink is down this record usually fails and is counted.

This is one additional refusal code, in both pipelines, produced only in `fail_closed` or, for held
routes, by the existing PR #29 rule.

### 9.2 Behaviour by traffic class

| Class | `best_effort` | `fail_closed` |
|---|---|---|
| Sidecar request (swap) | never refused for audit | refused before swap and before contact when `decision` is not durable |
| Passthrough read | never refused for audit | **refused when `decision` is not durable** (open question 1: whether reads should be gated or only writes) |
| Held write (PR #29, in review) | refused when `held` or `forward_started` cannot be written and flushed | same refusals, durable. `approved` becomes required |
| Refusals | audited, never changed | audited, never changed. A refusal is not turned into `audit_unavailable` because its record failed |
| Session create, renew; revoke; revoke-all | audited after, best effort | same. Never gated by default (open question 5). Revocation never gated |
| Netfilter gate state | audited after | same |
| Response streams already forwarded | untouched | untouched. A failing outcome record does not abort the stream |

### 9.3 Migration from PR #29's rule

1. PR #29 merges as it is. Under `best_effort`, held routes keep its rule: try-writes that must return
   `Ok`. This is "today's stage 2 behaviour" and this design must not weaken it. Because of it the first
   column of the table in 3.2 is *not* "never refuses" for held routes.
2. Stage 2 of this plan replaces the sink's two families (`write_*` and `try_write_*`) with one entry
   point, `append(record, need)`, where `need` is `Durable` (gating), `Enqueue` (outcomes) or
   `BestEffort`. With a stdout or non-fsync sink `Durable` means "written and flushed", which is what
   `try_write_*` means in PR #29. With the file sink it means fsynced. No observable change to
   `best_effort`.
3. Under `fail_closed`, held routes use the same call sites with the file sink, so the PR #29 rule becomes the
   durable rule without a second code path. The two additions are `approved` as a gating record and
   the removal of the table-lock wait (section 4.2, stage 5).
4. PR #29's `HoldRec` stays as is in `best_effort`, byte for byte. In `fail_closed` its lines gain the envelope
   fields of 6.1.
5. Config: existing configs without `[audit]` are valid and unchanged. A config that has held routes and
   `fail_closed` before stage 5 lands is a startup error (4.2) [A].
6. `docs/design/phase1.md` ("Audit write failure"), `docs/design/muse-gated-passthrough.md` (3.9) and the
   README get a sentence each when the code lands: default best effort, held-route rule, where this mode
   is described (acceptance criterion of #32). Not edited here.

### 9.4 Interaction with #5

#5's `parked`, `approved`, `denied`, `expired`, `executed` lines need the same guarantee: a request
cannot become `parked` or `approved` without a durable record [read #32]. They map directly onto the
`Durable` need for `held` and `approved`, with `executed` as `forward_started`. #5's hash-chained store
is the optional follow-up of 6.3.

## 10. Staged plan and acceptance tests

Each stage is a separate PR and ends with tests that pass in CI. Fault injection uses a `SinkBackend`
trait seam (write, sync, open, dir-sync) in the writer so most tests need no real fault. System tests
use the real kernel failure modes listed. A test-only Cargo feature `audit-failpoints` (off by default,
never in a release build, like the existing `matrix-upstream` and `stage1-probe` features [read
`Cargo.toml`]) gives pause and kill points.

### Stage 0: this note

Council review. No code.

### Stage 1: envelope, request id, sink trait

- Add `request_id` at handler entry and the envelope fields, emitted only in `fail_closed` (3.4).
- Introduce `append(record, need)` and the `SinkBackend` seam. The stdout sink implements it with
  today's behaviour.
- Tests: byte-for-byte equality of both pipelines' lines against the current output (golden files)
  in `best_effort`; key-set tests per kind; `request_id` is 32 hex characters, differs per request, and
  is the same on `decision` and `outcome` of one request; the id does not change when the caller key or
  path changes (not derived from input).

### Stage 2: file sink, writer thread, startup validation

- Append-only open flags, lock, torn-tail check, `start` record, per-record `sync_data`, bounded channel,
  `write_timeout_ms`, health bit.
- Tests:
  - every startup rejection of 4.8 exits 2 with a fixed message; `best_effort` unchanged;
  - write error, short write, `sync_data` error and ack timeout at the backend seam each end in a
    refusal, counters and health 0;
  - the real kernel: `RLIMIT_FSIZE` with `SIGXFSZ` ignored gives a real short write and `EFBIG`;
    a tiny `tmpfs` (`mount -t tmpfs -o size=64k` inside `unshare -rm`, [A] available in CI; skipped with a
    visible message otherwise) gives real `ENOSPC` on write and on sync; `/dev/full` gives `ENOSPC` on write
    (test seam only, it is not a regular file);
  - slow sink: a FIFO whose reader never reads (or a seam backend that blocks) stalls the writer; the
    request is refused after `write_timeout_ms` (within a tolerance), the metrics show a timeout, the
    admin socket answers `ready` and `audit` within 200 ms during the stall [A] (the FIFO cannot be
    fsynced, so it exercises the write path through the seam only; stated in the test);
  - SIGKILL: the harness kills the real binary at failpoints (before D, D written not synced, D durable
    before A, after A before O) and the checker applies the 7.2 reader to the file and asserts the
    section 7.1 conclusion for each point. A torn tail is produced by killing during a large write.

### Stage 3: write-ahead decisions in both pipelines, refusal wire

- `decision` before the swap and before contact; `outcome` as a non-waiting append; refusal shape.
- Tests:
  - the mock upstream records zero contacts and no credential swap for every failure of stage 2;
  - order test: the seam backend and the mock upstream stamp one shared counter; assert
    `sync(decision) < first upstream accept`. (A file-level check that the line is *visible* proves only
    that it was written, not synced, and is not used for this assertion.)
  - the exact body, status and `X-AP-Decision` of 9.1, in both dialects;
  - the refused request's `deny`/`outcome` record is attempted;
  - a stream already forwarded is not aborted when only its outcome fails;
  - canary test of 6.2;
  - measurement: added latency of `per_record` on the stated Linux disk (filesystem, device, kernel),
    reported in the PR, no threshold promised.

### Stage 4: group commit, rotation, gap markers, heartbeat

- Tests:
  - `group_commit`: with a delayed sync at the seam, N concurrent requests all wait, none is acked before
    the sync returns, and one sync serves the batch (count syncs);
  - after a sync error and recovery, the next segment begins with `gap` carrying `last_durable_seq`,
    `lost_from_seq`, `lost_to_seq` and `prev_segment`; `seq` continues; no retry of sync on the failed
    descriptor (the seam asserts that);
  - rotation: crash (SIGKILL) injected after each of steps 1 to 5 of 4.5; the reader reassembles all records,
    with `prev_tail` as specified; concurrent load during rotation loses no acked record;
  - cancelled jobs are skipped after a stall.
- Measurement: `group_commit` latency and throughput on the same disk.

### Stage 5: metrics, readiness, held routes (after PR #29 merges)

- `/admin/v1/audit`, the readiness state, the admin socket in passthrough-only deployments.
- Change `admit` so that no sink wait happens under the table lock (reserve, persist, commit); share
  the request id with the hold id; `approved` as gating; remove the "held routes with `fail_closed`"
  startup block.
- Tests: with a blocked sink, `approve`, other admissions and `drain` all finish within bounds while a
  `held` write is waiting (the lock is free); `approved` failure answers the approver `audit_unavailable`
  and sends nothing; readiness 503 while unhealthy and 200 after the `gap`; `--check-ready` exit codes.

### Stage 6 (optional): hash chain (6.3)

Only on the owner's request.

### Acceptance criteria of #32, mapped

| #32 criterion | Stage |
|---|---|
| `best_effort` byte for byte | 1 |
| every request refused with a failing sink, zero upstream contacts | 3 |
| write error, short write, fsync error, blocking sink, each refusal and counters | 2 |
| gap marker after fsync error and recovery | 4 |
| decision on disk before upstream, ordered test | 3 |
| `group_commit` never acks early | 4 |
| forwarded stream not aborted when only the outcome fails | 3 |
| stdout or `fsync = none` rejected, exit 2 | 2 |
| latency measurement on a stated disk | 3 (per_record), 4 (group_commit) |
| `phase1.md` row and README updated | with the code, not in this note |

## 11. Open questions for the owner

1. **Gate reads?** Under `fail_closed`, a down disk refuses every passthrough read as well as writes. The
   stage 2 rule and #32 differ here (stage 2: writes only; #32: every request). Proposal: gate every
   forwarded request in `fail_closed`. Alternative: `audit.gate = "all" | "writes"`, a second knob.
2. **`approved` as a gating record** for held writes: without it a forward can be recorded without the
   approver's identity in the durable record. It is a change to PR #29's behaviour. Accept?
3. **Request id and PR #29.** Mint one id at handler entry and use it as the hold entry id (a change in the
   PR), or keep the hold id and add a `req` field (no change to its ids)? Should this wait until PR #29 merges?
4. **Where does a passthrough-only deployment serve readiness and metrics?** A new admin socket, or the
   approval listener that PR #29 adds?
5. **Do `session`, `renew` and admin operations gate?** Proposed: no, and revocation never. Creating a
   session grants authority; one could argue it should gate.
6. **Metric format.** JSON on the admin socket (proposed) or Prometheus text. The proxy has no
   metrics dependency today.
7. **Fast-fail with one probe per `retry_ms`** instead of "every request tries its own write" (#32 wording).
   It spares a failing disk and a 2-second wait per request. Accept the narrowing?
8. **Rotation ownership.** Built-in size-based rotation only (proposed). Add an admin "reopen" for external
   rotation tools later?
9. **May `best_effort` use a file sink?** It is not required by #32. If allowed, it would be
   write plus flush, no fsync, no envelope.
10. **Defaults.** `write_timeout_ms = 2000`, `group_commit_max_ms = 5`, `heartbeat_secs = 30`,
    `max_segment_bytes = 64 MiB`, channel 1024, batch 256, `retry_ms = 250` are all [A].
11. **Reads without a second write-ahead record.** For the sidecar and for reads the `decision` record is
    also the only "about to contact" record, so "decision without outcome" means "possibly executed" even
    if the crash came before the connect. A second `forward_started` record per request would sharpen it
    at the cost of a second sync. Not proposed. Accept?
12. **Linux `flock` and `O_NOFOLLOW`** are used for the sink file. Any deployment (a read-only root with a
    volume, a network filesystem) where they are not available or not wanted?
13. **Torn-tail repair writes a newline into an existing file.** Acceptable, or refuse to start on a file
    whose last byte is not `\n` and make an operator move it?

## 12. Evidence and method

- Code read on `origin/main` at `3878421`: `crates/ap-core/src/audit.rs`,
  `crates/ap-proxy/src/audit_sink.rs`, `pipeline.rs`, `passthrough.rs`, `netguard.rs`,
  `session_http.rs`, `admin_http.rs`, `probe.rs`, `evidence.rs`, `lib.rs`, `ap-core/src/error.rs`, `Cargo.toml`.
- Docs read: `docs/design/phase1.md` audit sections, `docs/design/muse-gated-passthrough.md` sections 3.9
  and 5 (on `origin/main`; also on `origin/feat/muse-stage2`).
- PR #29 (in review): `git show origin/feat/muse-stage2:crates/ap-proxy/src/audit_sink.rs`,
  `git diff origin/main...origin/feat/muse-stage2 -- crates/ap-core/src/audit.rs`, `outcome.rs`,
  `hold/mod.rs`, `passthrough/hold_path.rs`, at `6f3e678`.
- Issues read: #32 (no comments), #1 (question 5), #5 (the audit-before-action comment).
- The measurement in 4.6: a short script, 300 appends with `fsync`, 300 with `F_FULLFSYNC`, 100
  batches of 8, on an internal APFS volume, scratch directory removed afterwards.
- Not done: no code was run against this design; no Linux measurement; no fault injection.
