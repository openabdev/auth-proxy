# Durable, fail-closed audit: an opt-in mode

Status: **draft, revision 3. Not final, no implementation before a confirming council review.** Revision 3
resolves the three blockers that the second council review (opus5) raised; section 0 lists them.
Design note only. No code in this change.
Issue: #32 (p2, enhancement). Related: #1 (RFC, open question 5), #5 (approval lines), PR #29
(Muse stage 2, **in review, not merged, and still changing**).

## How claims are labelled

- **[read]**: read in code, docs or library source. Code facts are for `origin/main` at `3878421`
  unless the text says "PR #29". PR #29 facts say the commit they were read at.
- **[M]**: measured. The only measurement in this note is the fsync cost in section 4.6, on macOS.
- **[I]**: inferred from what I read or from general system behaviour. Not checked here.
- **[A]**: assumed. A value or a decision I picked and the owner may change.

PR #29 is in review and moves. The first revision of this note read it at `6f3e678`; this revision
re-read the points that matter at `e7818ad` (section 12). Every statement about PR #29 is a fact about
those commits only. This design depends on the *shape* of PR #29 (a fallible write that must succeed
before a write is forwarded, and a `forward_started` record that must be durable before the upstream
connect and the first request byte, which PR #29 must move to; section 1.2), not on names, signatures or line numbers.

Decisions are marked in section 11 as **DECIDED** (settled in review, change only with a new review) or
**OWNER APPROVED DEFAULT (2026-11-19)** (the owner approved these values; any one can still be replaced).
Where the text depends on a pending default it says so.

## 0. Revision 3: resolved blockers, chosen direction, and what is not guaranteed

**Chosen direction: option B**, the durable fail-closed mode described in this note, for held writes
first. Both council members chose B and rated it reversible. This note does not restate the alternatives
labelled A and C; the labels are not defined in revisions 1 and 2.

Blocker 1, `forward_started` and the first byte (section 3.2, 4.2, 7.1, 10 test 6). **Resolved by
moving the durable write earlier.** `forward_started` is durable before the proxy connects upstream and
before the request is handed to the HTTP client. No body poll, connection poll or other task in the
forward path waits on the audit sink. If the write fails, or the table is closed or the policy changed
while it waits, the request is refused with 503 `audit_unavailable`: **no connection is opened and no
request byte is sent.**

Blocker 2, stage-1 quota (4A, 4.3, 4.4, 4.8, 8.3, 10 test 7, section 11 item 21). **Resolved by keeping
the quota fail-closed until restart, with no automatic recovery.** Stage 1 has no rotation. When the
quota trips, the proxy refuses every gating write until the process restarts. It deletes nothing. The
operator sees the signals listed in 4A item 3. The file holds only held-route records in stage 1, so read
traffic cannot fill it (section 11 item 20).

Blocker 3, directory checks versus `emptyDir` and `fsGroup` (4.1, 4.2, 4.8). **Resolved by removing the
ancestor and directory mode and owner checks.** The proxy checks the segment file it creates: created
with `O_EXCL`, a regular file, owned by the proxy's euid, no group or other bits in its mode, one link,
and a group equal to the proxy's egid or the directory's group. The checks work on `emptyDir` with or
without `fsGroup`. Section 4.2 lists what they do not prove.

**Guaranteed** (for a held write, in `fail_closed`, on supported local storage): no connection and no
request byte leave the proxy unless `held`, `approved` and `forward_started` were reported durable first,
and a refused request sends nothing.

**Not guaranteed:** that the outcome of a sent request is recorded; anything about records of reads,
sidecar traffic, denials or refusals (they stay on stdout in stage 1 and are not durable); that the file
is not deleted, truncated or replaced by someone with file access; the disk's flush honesty; restart
recovery of records that were queued but not acknowledged; anything after an `emptyDir` pod is deleted,
unless the records were shipped first; read access to the file by any UID that can bypass file mode
(root in the container); and the dependence on PR #29's shape, which is in review and must change in one
place (section 1.2).

**Council points not addressed in this revision** (raised by sol or opus5, still open): the 2000 ms audit
timeout versus PR #29's 2 s approval confirmation (sol 1, opus5 item 2); `approved` and the `Stuck` rule
with channel 1024 (opus5 item (d)); the `prev_tail` predecessor choice and the clean-shutdown marker
(sol 9); the segment-creation collision after a failed directory sync (sol 5); the gap arithmetic when a
quota refusal happens before sequence assignment (sol 6, now answered by 4A item 3: quota writes no gap);
the EXT4 magic family (sol 11); the shipper's UID (sol 12); the UID separation check (sol 10); the late
`Ok` readiness rule (opus5 item (d)). These need a further revision before the note is final.

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
`io::Result<()>`. `Ok` means `write_all` and `flush` returned `Ok` [read, PR #29 at `e7818ad`,
`audit_sink.rs`]. Two placements matter for this design [read, PR #29 at `e7818ad`]:

- The `held` write runs **inside `HoldTable::admit`, under the table lock**, through the `persist`
  closure, after every check passed and before anything changes.
- The `forward_started` write runs on the first poll of the request body, **after the upstream
  connection exists and before the first request byte is flushed** (the code comment says "the
  connection exists and no request byte has been flushed"), inside `HoldTable::claim_start`, again
  under the table lock. The closed-table check, the last policy look and the write are one critical
  section.
- `approved` is written with the best-effort `write_hold`, when the waiting handler sees the decision.
  It is not a gating record there.

The consequence for wording: **PR #29 does not write `forward_started` before contacting the upstream.
It writes it after the TCP/TLS connection and before the first request byte.** Section 3.2 defines the
guarantee on the first request byte for that reason.

Revision 3 changes where the write sits. In a poll-based design, the write cannot wait on the disk inside
the body poll: hyper flushes the buffered request head when a body poll returns `Pending`, so the head
would leave before the write is durable [read by the council, hyper 1.9.0 `proto/h1/dispatch.rs`, not
re-read in this revision]. Revision 3 therefore requires the `forward_started` write to move out of
`HoldTable::claim_start` and `HeldBody::poll_next` to the point before the request is handed to the HTTP
client (section 4.2). This is a change to PR #29, which is still in review. It is not made here.

That rule is fail-closed in the sense "no record accepted, no write". It is **not durable**: on a
file, `flush` of a `File` is a no-op in std [read std, `File::flush`] and the bytes sit in the page
cache until the kernel writes them [I]. A power loss or a kernel panic after `Ok` can lose a
`forward_started` record for a write that already reached the upstream. The rule also covers only
held routes.

Another consequence, independent of this design and worth a review comment on PR #29: its `held`
record goes to **stdout while the hold-table lock is held**. A blocked stdout pipe therefore already
stalls admission, approval and drain today [read, PR #29 at `e7818ad`, `admit`]. This note does not
change PR #29; the comment is raised there.

### 1.3 What this note adds

An opt-in mode that gives, for every request in its scope, a record that is **durable before the
action**, and refuses the action when it cannot be made durable. It makes PR #29's rule one instance
of a general rule and adds the durability that rule lacks. The default stays as it is.

The first implementation is deliberately small: **durable fail-closed for held writes** (section 10,
stage 1). Gating every forwarded request is designed here but not part of the first stage (open
question 1, proposed default).

The requirement behind it is the outer-layer item "every step is audited before it runs, and if the
record cannot be written the step does not run" (openab issue 1606, definition of done, item 7, as
quoted in #32) [read #32].

## 2. Goals and non-goals

Goals:

1. `audit.mode = fail_closed`: no first request byte upstream (and no credential swap, in the pipelines
   in scope) unless a record of the decision is on stable storage, **on supported local Linux
   storage** (section 4.1), as far as the operating system can report it.
2. State exactly what each mode guarantees and what a reader of the log may conclude from it,
   including after crashes, and what the log cannot show.
3. Keep `best_effort` byte for byte as today when no `[audit]` table is configured (section 3.4).
4. Dependency-light: standard library and the `libc` crate that `ap-proxy` already depends on
   [read `Cargo.toml`]. One writer thread, no async file crate, no database, no message queue.
5. Recover by itself when the sink works again. No operator action, except freeing space when the
   quota is reached (section 4A).
6. Never put a secret in a record, and never let a failure message carry one.
7. Bound what an unauthenticated or hostile caller can make the audit log cost (section 4A).

Non-goals:

- No networked audit service, no syslog or remote shipping, no blockchain, no signing service.
  Shipping, retention and deletion of files stay with the deployment (RFC question 5, other half).
  The proxy **never deletes a record**.
- No hash chain in the first version. Section 6.3 describes it as an optional follow-up.
- No protection against an attacker who can delete or rewrite the files. The agent must not be able
  to reach them (section 4.2 lists what that requires). Section 6.3 says what the sequence numbers do
  and do not detect.
- No change to the default and no change to refusal codes other than adding `audit_unavailable` to
  the sidecar pipeline when that pipeline is gated.
- No audit of the runtime side (openab-pty floor endpoint, tracked in openab-pty issue 100).
- Revocation is never blocked by audit failure (section 3.3).
- stdout and journald as fail-closed sinks (section 4.1).

## 3. The option

### 3.1 Configuration [A, names are proposals]

```toml
[audit]
mode = "best_effort"            # default. "fail_closed" is the opt-in
sink = "stdout"                 # "stdout" (default) or "file"
dir = "/var/lib/auth-proxy/audit"   # required when sink = "file": a directory, not a file
fsync = "per_record"            # fail_closed only: "per_record". No "none". ("group_commit": later stage)
write_timeout_ms = 2000         # fail_closed only: bound on one durable append (PROPOSED DEFAULT)
retry_ms = 250                  # fail_closed only: recovery attempt interval (PROPOSED DEFAULT)
channel_capacity = 1024         # fail_closed only (PROPOSED DEFAULT)
max_record_bytes = 4096         # fail_closed only: size cap of one serialized line (section 4A)
max_total_bytes = 1073741824    # fail_closed only: quota over all segments in `dir` (section 4A, owner decides)
shutdown_grace_ms = 5000        # fail_closed only: bound on draining the writer at exit (section 4.3)
```

No `[audit]` table means `best_effort` on stdout, exactly today. `fail_closed` with `sink = "stdout"`,
without `dir`, with `fsync` missing or unknown, or with `write_timeout_ms = 0` is a startup error,
exit code 2, like other configuration errors [read lib.rs, exit code 2 for config failures]. The full
startup rejection list is in section 4.8. Later stages add `group_commit_max_ms`, `max_segment_bytes`
and `heartbeat_secs`; they are not part of stage 1.

### 3.2 What each mode guarantees

**The action boundary is the first request byte** sent upstream (for a held write: the first byte
flushed on the upstream connection; for the sidecar and for reads, when stage 3 gates them: the
moment the request is handed to the HTTP client). Revision 3 adds a stricter rule for held writes:
`forward_started` is durable **before the connect and before the request is handed to the HTTP client**,
so the connect is also after the record. The connect itself is not the action; it is ordered after the
record only so that a refused request opens no connection.

For a held write the order, with its durability points, is:

1. `held` is durable **before admission**: no entry, no notification, no cooldown exists until it is.
2. `approved` is enqueued when the approval is seen and is durable **no later than the ack of
   `forward_started`** (same writer, same file, one sync covers both, section 3.3). If `approved` cannot
   be enqueued the forward is refused.
3. `forward_started` is durable **before the upstream connect and before any request byte**. If it cannot
   be made durable the request is refused with 503 `audit_unavailable`, and nothing is connected or sent.
4. The upstream connection is made, after the ack of step 3.
5. The first request byte is sent.

No code path in the forward (body poll, connection task, pool) waits on the audit sink after step 3
starts. Step 3 runs in the request handler before the request is given to the HTTP client, which is the
only place where a blocking wait cannot leave a request head buffered and flushed behind it.

| | `best_effort` (default) | `fail_closed` (stage 1: held writes) |
|---|---|---|
| Passthrough held write (PR #29, in review) | PR #29's rule as written: `held` and `forward_started` must be written and flushed (`Ok`), otherwise 503 `audit_unavailable`. Not durable. `approved` is best effort | Same refusals, same wire (section 9.1), but "written" means durable (section 4.1). `approved` is required: it is enqueued before the forward and covered by the ack of `forward_started` |
| Passthrough read, sidecar request | One record after the fact. A write failure is counted. Never refused for audit reasons | **Unchanged in stage 1.** Not covered by the guarantee. Gated in stage 3 only if the owner accepts (open question 1) |
| Refusal (deny, `unavailable`, ...) | One record at refusal time, best effort | One record at refusal time on the non-waiting path. If it cannot be written the refusal stands and the failure is counted |
| Sink | stdout or file, no durability claim | held-route records to the file, on supported local Linux storage (4.1). Other records stay on stdout (3.3) and carry no durability claim |
| What a reader may conclude | Records that exist are true. Absence proves nothing | Section 7.3, with its conditions |

[A, design]. The exact guarantee of `fail_closed`, for a request in scope, is one sentence:

> If the proxy sent the first request byte of a request upstream, the records that authorize it
> (`held` before admission, `approved`, and `forward_started` before the connect) were reported durable
> by the operating system, on supported local Linux storage, before that byte. A request whose gating
> record was not acknowledged is refused and sends nothing.

What it does not say: that the outcome is recorded; that the record is on the *medium* (a disk that
lies about flush defeats it); that the file was not deleted or truncated afterwards (section 7.3);
that anything outside the proxy's observation happened. For a request out of scope (stage 1: reads and
the sidecar) it says nothing. Section 0 lists the rest.

### 3.3 Record kinds and when they are written

"Write-ahead" means: the record must be durable before the action it describes, and the action is
refused if it cannot be. "Gating" is the same thing seen from the request. Everything else is
"after" and goes through the **non-waiting path** (4.7): attempted, counted when it fails, and it never
changes what the request sees.

**Stage 1 placement.** In `fail_closed` the file sink carries only **held-route** records (the rows
marked PR #29 below, plus `start`, `gap` and `segment_start`). Records of reads, sidecar traffic,
refusals on other routes, `netfilter`, `session` and `probe` stay on stdout exactly as today, in both
modes. This keeps read volume from filling the file and latching the held-write quota (4A item 3,
section 11 item 20).

| Kind | Pipeline | When | Write-ahead (gating) in `fail_closed`? | If the write fails |
|---|---|---|---|---|
| `held` (PR #29) | passthrough held write | before the entry becomes visible (reserve, persist, commit, 4.2) | **yes** | 503 `audit_unavailable`, no entry, no notification [read, PR #29] |
| `approved` (PR #29) | passthrough held write | when the waiting handler sees the approval, enqueued immediately before `forward_started` | **yes, decided** (open question 2): durable by the ack of `forward_started` | refuse `audit_unavailable`, nothing sent, approver is told `audit_unavailable` (the result code exists in PR #29) |
| `forward_started` (PR #29) | passthrough held write | after the claim check, **before the connect and before any request byte** (3.2, 4.2) | **yes** | 503 `audit_unavailable`, no connection, nothing sent |
| `denied`, `expired`, `abandoned`, `superseded`, `dropped_on_reload`, `abandoned_after_approve`, `connect_failed` (PR #29) | held write | at the transition. In every one of them nothing was sent | no, **after** (non-waiting) | counted. The reader concludes "not sent" from the absence of `forward_started` (7.3) |
| `completed` (PR #29) | held write | when the response body ends | no, **after** | counted |
| `audit_unavailable` (PR #29 transition) | held write | when a gating write failed | no, **after**, non-waiting. The sink is probably down | counted |
| `notify_failed` (PR #29) | held write | when the notifier fails | no | counted |
| `decision` (allow), `outcome` | sidecar, passthrough read | **stage 3 only**, if open question 1 is accepted: `decision` before the credential swap and before the request is handed to the client; `outcome` when the body ends | `decision` yes, `outcome` no | refuse 503 `audit_unavailable` / counted |
| `deny` | both | at the refusal | no, the refusal is the outcome | refusal stands, counted. Rate bounded (4A) |
| `netfilter` | sidecar | state change, and each `netfilter_unverified` refusal | no | counted |
| `session` (create, renew), `admin revoke-all`, revoke | sidecar | after the operation | **no.** Revoke and revoke-all are **never** gated. Create and renew gating is deferred (open question 5, proposed default) | counted |
| `probe`, evidence | stage 1 measurement only | as today | no | counted |
| `start` | both | once at startup, durable, before the listener accepts | yes (a failure is a startup error) | exit 2 |
| `gap` | both | first record after a recovery from a failed durable write (4.4). Has its own `seq` | yes, it is the first record of the new segment | the sink stays unhealthy |
| `segment_start` | both | first record of each later segment (4.5) | yes | segment creation fails, old segment stays in use |
| `heartbeat` | both | **later stage** | no | counted |

[A]. The `held` and `forward_started` rows and the transition names come from PR #29 and may change. The
design requirement on them is only: *the records that gate a held write are the ones that precede its
first request byte upstream*.

Two properties follow from the file being written by one writer in order:

1. **`sync_data` is file-wide [I].** When the acknowledgement for record N arrives, every record appended
   before N in the same segment is on stable storage too, including a non-waiting `outcome` of an
   earlier request. So `approved` can be enqueued just before `forward_started` and one sync covers
   both. Why not wait for `approved` before the connect: it costs a second sync per held write for a
   record that the next sync covers anyway, and the connect is not the action [A, design].
2. **A record's position gives happens-before for records of the same boot**, through `seq`
   (section 5). It does not give wall-clock order (section 7.4).

### 3.4 `best_effort` stays byte for byte [A, design]

The envelope fields added in this note (`v`, `boot`, `seq`, `ts_ms`, `mono_ms`, `kind`,
`request_id`) are emitted **only in `fail_closed`**. In `best_effort` the lines are the ones the
tests pin today (`json_keys_are_exactly_the_allowed_set` in `audit.rs` [read]). The same holds
for PR #29's `HoldRec` key set. A test compares the bytes of both pipelines' lines before and after the
change (acceptance criterion 1 of #32).

A file sink in `best_effort` is not part of this design (open question 9, decided).

## 4. Durability

### 4.1 What "durable" means here, and where it holds

A record is durable when `write_all` of the whole line (one `write` loop, short writes
continued), then `sync_data` on the file descriptor, all returned `Ok`. On Linux `sync_data` is
`fdatasync` [read std, `File::sync_data`, section 12], which flushes the data and the metadata needed to
read it back, including a changed size [I]. When a segment is **created** the containing directory is
also synced (`fsync` on the directory descriptor) before the first record is relied on.

**Supported storage.** "Durable" is claimed only for a **local Linux filesystem on persistent block
storage** whose `fdatasync` reaches the device: ext4 and XFS [A, owner decides, open question 12].
Everywhere else a successful `sync_data` proves nothing:

| Storage | Why it is not supported |
|---|---|
| tmpfs, ramfs (including a memory-backed `emptyDir`) | `fsync` succeeds and nothing is durable [I] |
| NFS, CIFS/SMB | `O_APPEND` is not atomic and `flock` is emulated or advisory only across clients [I]; `fsync` semantics depend on the server |
| FUSE | `fsync` is up to a userspace daemon [I] |
| Container overlay (`overlayfs`) | `fsync` passes to the upper layer, which is fine only if that layer is a local disk. The proxy cannot see that from `statfs`, so it is refused rather than guessed [I, A] |
| A disk or controller that acknowledges a flush it does not honour | outside the guarantee. Say so in the deployment notes |

**Startup check.** In `fail_closed` the proxy calls `fstatfs` on the opened audit directory and refuses
to start unless the filesystem type is ext4 (`EXT4_SUPER_MAGIC`, shared by ext2/3/4) or XFS. The named
refusals (`TMPFS_MAGIC`, `RAMFS_MAGIC`, `NFS_SUPER_MAGIC`, `CIFS_MAGIC_NUMBER`, `SMB2_MAGIC_NUMBER`,
`FUSE_SUPER_MAGIC`, overlayfs) give a specific message; any other type is refused as "unsupported".
There is no configuration override. Tests use a build-time `audit-failpoints` feature that disables the
check (section 10). [A]

**stdout and journald are never fail-closed sinks.** A pipe write or a journald acknowledgement does not
prove a record reached storage. A `fail_closed` configuration that names them does not start.

**Kubernetes `emptyDir`.** Even on node disk it is deleted with the pod. It survives a container
restart and, while the node's disk is intact, a node crash with the same pod [I]; it does not survive
pod deletion, eviction or rescheduling. So "durable" on `emptyDir` means "survives a crash of the
node's kernel, not the loss of the pod". The kubelet creates the volume root as world-writable (0777), and
with `fsGroup` as group-writable with setgid [I, kubelet behaviour, not checked here]. Section 4.2 therefore
does not check the directory's mode or owner. An `emptyDir` is acceptable only with shipping off the pod
before the records matter (open question 16). Otherwise a persistent volume is a **deployment
requirement** (open question 12).

**macOS.** Not a supported target. Rust's std on Apple targets implements **both** `sync_all` and
`sync_data` as `fcntl(F_FULLFSYNC)`, and on Linux `sync_data` as `fdatasync` [read std at rustc
commit `0ef1bc386`, `library/std/src/sys/fs/unix.rs`, `File::fsync` and `File::datasync`, section 12].
So Rust's `sync_data` on macOS is the slow call of section 4.6, not the fast one.

### 4.2 The file sink

**Directory and file security.** [A, design, except where tagged]

- `dir` is an absolute path. The proxy opens it by walking the components from `/` with
  `openat(O_DIRECTORY|O_NOFOLLOW)`, which makes a symlink in any component fail. If the final component
  does not exist the proxy creates it with `mkdirat(0700)`. If it exists the proxy uses it **as found**:
  no owner, group or mode check is applied to the directory or to its ancestors. This is what lets the
  same rule run on an `emptyDir` (the kubelet creates it 0777, or group-writable with `fsGroup`) and on a
  PVC. All later operations (create, `fstat`, directory sync, size scan) use the directory descriptor with
  `openat`/`fstatat`, never a path string.
- The file checks in the next bullets are the protection this section relies on. They are made on the
  **segment file the proxy created**, not on the directory.
- The proxy's UID must **differ from the agent's UID**. Where the profile declares the agent UID (the
  netfilter owner match and the probe status file's expected owner are configured today [read
  `netguard.rs`]), startup compares them and refuses to start on equality. Elsewhere it is a documented
  deployment requirement. The directory must be on **no volume mounted into the agent container**; the
  proxy cannot check that, and it is a deployment requirement [A].
- A segment is created with `openat(dirfd, name, O_WRONLY|O_APPEND|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,
  0600)`. `O_EXCL` guarantees the file is new, so the `0600` applies. **`open(..., 0600)` does not change
  the mode or owner of a file that already exists**, so the proxy never reuses an existing file: every
  segment is new (4.5).
- After open, on the opened descriptor, `fstat` and require: a regular file; `st_uid == euid`; `st_gid` equal
  to the proxy's egid or to the directory's group (read with `fstat` on the directory descriptor, which is
  the `fsGroup` case); `mode & 0o077 == 0`; and `st_nlink == 1`. Any other result is a startup or
  recovery failure. These checks run on the file, so they hold on `emptyDir` with or without `fsGroup`:
  `fsGroup` changes the group of the file and the directory, not the mode the proxy passed to `open`.
- **What the file checks give, and what they do not** [A, design]:
  - They confirm that the descriptor is the file the proxy just created, with the expected owner and no
    group or other access at creation. `O_EXCL` already guarantees the file did not exist, so a symlink or
    a planted file at that name makes the open fail.
  - They do **not** stop another UID that can write the directory from renaming or unlinking the file, or
    from creating a new file, while the proxy runs. A world-writable `emptyDir` lets any UID in the pod
    that mounts it do that. The directory is not checked for this, so the protection is that only the
    proxy's container mounts the volume, which is a deployment requirement.
  - They do not stop a reader with `CAP_DAC_OVERRIDE` (root in the container) from reading the file.
  - The owner check is close to a tautology: `O_EXCL` creates the file with the proxy's euid. It is kept
    because it is cheap and because it catches a filesystem that reports another owner.
  - Nothing here verifies that the agent runs under another UID (4.8, deployment precondition).
- Take `flock(LOCK_EX|LOCK_NB)` on the **directory** descriptor and refuse to start if another process
  holds it, so two live proxies cannot write one directory. It is advisory and only stops cooperating
  processes [I]; the directory permissions above are the actual protection.
- No `O_TRUNC` ever. A previous boot's segments are never opened for writing (4.5).
- `O_APPEND` makes each `write` land at the current end on a supported local filesystem [I]. It does
  not make a record written by several `write` calls atomic. That does not matter here: there is
  exactly one writer thread, the lock excludes a second proxy, and the **per-record size cap**
  (section 4A) keeps every record small.

**The writer.**

- **One writer thread** (`std::thread`), not a `spawn_blocking` task, owns the file descriptor. A
  blocked `sync_data` cannot then exhaust the runtime's blocking pool or a tokio worker, and the single
  writer gives the ordering of section 3.3 [A, design]. Requests send `(line bytes, ack channel,
  cancel flag)` through a bounded channel (`channel_capacity`, proposed default 1024) and `await` the
  ack with `tokio::time::timeout(write_timeout_ms)`. A full channel is an immediate refusal, which is
  the "no queueing of requests while the sink is down" rule of #32: the channel holds records of
  requests that are *waiting for an ack*, not requests parked for later.
- **`seq` is assigned by the writer when it takes a job**, never by the requester, so a job cancelled
  before the writer took it leaves no hole in the numbering (4.3).
- `per_record` (the only mode in stage 1): the writer takes one job, writes it, `sync_data`, acks,
  next job. One sync per record.
- `group_commit` (later stage): the writer takes the first job, then collects further jobs until
  `group_commit_max_ms` has passed or [A] 256 records are pending, writes all, calls `sync_data` once,
  then acks every job in the batch. **No ack is sent before the sync that covers that record
  returns.** It needs a Linux measurement to be justified (4.6).
- A job whose request already timed out has its cancel flag set. The writer skips cancelled jobs
  that it has not yet taken. This stops a stalled disk, once it wakes, from writing a flood of
  records for requests that were already refused.

**No sink wait under the hold-table lock.** The sync is never made while holding any lock shared with
request handling. PR #29 writes `held` inside `admit` and `forward_started` inside `claim_start`, both
under the table lock [read, PR #29 at `e7818ad`]. A durable append that waits milliseconds, or up to
`write_timeout_ms` on a stalled disk, must not run there: it would stall every admission, approval and
drain. This change is part of **stage 1**, not deferred: if it were deferred, the opt-in would
exclude held writes, the one path the mode exists for. The state machine:

*Admission (reserve, persist, commit).*

1. **Reserve** under the lock: run the existing checks (closed, cooldown, duplicate, caps), mint the id,
   and insert a `Reserved` entry that **counts toward the identity and table caps** (so concurrent
   admissions cannot overshoot) but is invisible to `list`, `view`, approval, supersede and
   notification. Release the lock.
2. **Persist** outside the lock: enqueue `held` and await the durable ack. An RAII guard holds the
   reservation, so a handler that is cancelled (client disconnect) releases it.
3. **Commit** under the lock: re-check `closed` and the policy generation. If both still hold, turn
   the entry `Pending`, run the duplicate-supersede step, start the notification. If the table was
   closed or the policy changed, **roll back**: drop the reservation, refuse with `shutdown` or the
   reload code, and enqueue a non-waiting `abandoned` record (the durable `held` is then followed by
   a terminal record, so a reader sees a held request that was never sent).
4. If persist failed: drop the reservation, no cooldown, no supersede, refuse `audit_unavailable`.

A second identical request that arrives while the first is `Reserved` is not a duplicate yet; it takes
its own reservation, and duplicates are resolved at commit, in commit order [A].

*Forward claim.*

1. Under the lock: `closed` check, the policy look, and mark the entry `Claiming`. Release the lock.
2. Outside the lock: enqueue `forward_started` and await the durable ack. The handler does this **before it
   opens any connection and before it gives the request to the HTTP client**. Nothing else in the forward
   path waits on the sink.
3. Under the lock: if the table was closed or the policy changed while waiting, **do not connect and do not
   send**: record a non-waiting `claim_aborted` and refuse. The durable `forward_started` then exists for a
   request that sent nothing, which the reader treats as "possibly sent" (7.3), the conservative direction.
   Otherwise mark `Forwarding`, open or reuse the connection, and send the first byte.
4. If the ack is an error or times out, the entry is released, nothing is connected and nothing is sent. The
   request is refused with 503 `audit_unavailable` (section 9.1), and the refusal is a non-waiting record.

`drain_pending` (shutdown) closes the table, then waits for entries in `Claiming` for at most
`shutdown_grace_ms`; an entry that is still `Claiming` at the deadline is not sent. This keeps the
property PR #29 has today ("shutdown either comes before the claim or after the whole claim") without
holding the lock across the sync. `Reserved` and `Claiming` entries are never visible to `approve`,
`list`, reload or supersede as `Pending` entries.

### 4.3 What each failure looks like

The sink is in one of four states, and the transitions are the whole recovery story:

| State | Meaning | Gating requests |
|---|---|---|
| `Healthy` | the writer is free or working, no job older than `write_timeout_ms` | enqueue and wait up to `write_timeout_ms` |
| `Stuck` | the oldest job is older than `write_timeout_ms` and the writer has not returned | refused at once (fast fail) |
| `Failed` | the last write or sync returned an error | refused at once |
| `Recovering` | the writer is free and is creating a segment and writing the `gap` | refused at once |
| `Quota` | the directory reached `max_total_bytes` (4A item 3). **Latched until the process restarts**; no recovery attempt | refused at once |

| Event | Writer behaviour | Request sees | State |
|---|---|---|---|
| `write` returns an error (EIO, EBADF, EDQUOT, ...) | descriptor untrusted, goes to 4.4 | 503 `audit_unavailable` for gating records; nothing for after records (counted) | `Failed` |
| Short write, then an error | the segment is abandoned at recovery. **No truncate of the live file**: the torn line stays as an unparsable line (7.2) | same | `Failed` |
| `ENOSPC` on `write` | as a write error with `reason = "enospc"` | same | `Failed` |
| `ENOSPC` or `EIO` on `sync_data` | the batch is **not** acknowledged. The descriptor is untrusted (4.4) | same, for every request in the batch | `Failed` |
| Writer blocked in `write` or `sync_data` (slow disk, stuck mount) | the thread cannot be cancelled. See "a blocked writer" below | 503 `audit_unavailable` after `write_timeout_ms`, then at once | `Stuck` |
| Channel full | not enqueued | immediate 503 `audit_unavailable` | unchanged |
| Quota reached (4A item 3): the next record would exceed `max_total_bytes` | the record is not written and **no `seq` is assigned**; the latch is set; the writer makes no further attempt. No `gap` is written, because no sequence number is lost | immediate 503 `audit_unavailable` until restart | `Quota` |
| Segment creation or directory sync fails during recovery | stays `Failed`, retried at the next attempt | as above | `Failed` |

[A, design] on all rows. The write timeout starts when the request enqueues the job and ends at the ack.

**A blocked writer.** The writer is the only thread that can touch the descriptor, so while it is inside
a blocked `sync_data` nothing else can probe, close or replace that descriptor. "The next probe closes
the old descriptor" is therefore impossible in that state. What the design does instead:

- The **probe is "writer free"**: it asks whether the writer thread is idle (an atomic flag the writer
  sets when it returns to its loop). Gating requests do not probe the disk. When the writer is not free,
  every gating request fails at once with the refusal, with no wait. [A] That narrows #32's wording
  "each request tries its own write" (open question 7, decided).
- Once the writer returns, it itself does the recovery, **on its own timer every `retry_ms`, not on a
  request**: if the call returned an error, close the descriptor, create a new segment, write the
  `gap`, and become `Healthy` (4.4). If the stuck call returned `Ok`, see "a late success".
  Recovery must not depend on traffic: a pod whose readiness is 503 receives none (section 8).
- If the call never returns, the sink stays `Stuck` until the process is restarted. Request handlers,
  the approval plane and readiness stay responsive, because they share neither a runtime worker nor a
  lock with the writer. **Durable audit stays unavailable** and held writes stay refused; that is the
  fail-closed outcome, and the signal is readiness 503, never a liveness failure (section 8).
- **A late success is uncertainty, not loss.** A request refused after `write_timeout_ms` may have its
  record written and synced later. The disk did not fail: the record exists for a request that sent
  nothing. The reader sees a `held` (or `forward_started`) with no terminal record and concludes
  "authorized, possibly sent" (7.3), which errs in the safe direction. The descriptor is trusted again
  after a late `Ok` (no error was reported), no gap is written, and `late_acks_total` is counted.
  A `gap` is written only after an **error**.
- **Cancellation versus ack.** A request sets the cancel flag when its timeout fires. If the writer has
  not taken the job it is skipped and consumes no `seq`. If the writer already took it, the record is
  written whatever happens to the request; there is no way to withdraw it.

**Shutdown.** On SIGTERM the proxy stops accepting, closes the hold table (4.2), then asks the writer to
drain what is queued. The wait is bounded by `shutdown_grace_ms` (proposed default 5000). At the deadline
the process exits without joining the writer, so a stuck `sync_data` cannot block termination. Records
still queued then are lost and not counted (the process is gone); readers apply the 7.2 rules.

**Deny and refusal records go through the non-waiting path (4.7).** They never wait for a sync, so
a failing sink cannot add a wait to a refusal, and a flood of refusals cannot hold request tasks.

**What a request sees on a slow sink.** The first gating requests wait up to `write_timeout_ms`
(proposed default 2000 ms), then receive the refusal of section 9.1. After the first timeout the sink is
`Stuck`, and further requests fail at once. The bounded wait is also bounded in number by the hold
table caps for held writes.

### 4.4 After an error: no retry of `fsync`, a new segment, a gap marker

On Linux, after `fsync` reports an error the kernel may have marked the affected pages clean, so a
second `fsync` on the same descriptor can return success while the data never reached the disk [I,
widely documented behaviour after the PostgreSQL fsync findings; not reproduced here]. The design
therefore **never retries `fsync` on a descriptor that failed**:

1. The writer marks the sink `Failed` and notes `N = last_durable_seq`, the highest `seq` that was
   acknowledged durable in this boot, and `M`, the highest `seq` it had **assigned** before the
   failure.
2. On its next attempt (at most one per `retry_ms`, and only when the writer is free), the writer
   closes the old descriptor, creates a **new segment** (4.5) whose name uses `first_seq = M + 1`,
   syncs the directory, and writes as the first record a `gap`:
   `{"kind":"gap","seq":M+1,"reason":"fsync|write|enospc|timeout|open","last_durable_seq":N,"lost_from_seq":N+1,"lost_to_seq":M,"prev_segment":"<name>"}`.
   Records with `lost_from_seq <= seq <= lost_to_seq` may be absent from the previous segment, or present
   and not durable, or present and durable. The marker says "may", not "are lost".
3. **The gap has its own sequence number, `M + 1`.** The first record after it carries `M + 2`. The
   ranges are exact: `seq <= N` durable; `N+1 .. M` assigned and not acknowledged (the `lost_from_seq`
   to `lost_to_seq` range of the gap); `M+1` the gap itself; `M+2` onward the new segment. A cancelled
   job never took a `seq` and appears nowhere.
4. When the `gap` record and its sync succeed the sink is `Healthy` for gating purposes after the
   readiness rule of section 8.3, and gating records flow.
5. If recovery fails (disk still full, directory unwritable) the sink stays `Failed` and the cycle
   repeats at the next attempt. A `Quota` latch is not a recovery failure: it is not retried (4A item 3).

A reader that finds a `seq` discontinuity **without** a `gap` marker (a crash, a lost segment) must treat
it as a gap too (7.2).

### 4.5 Segments: immutable, never renamed

[A, design]. The first revision renamed the active file at rotation. That protocol was unsound: a rename
is not durable until its directory is synced, and if the later steps failed the writer kept appending to
the renamed file whose name now claimed a `last_seq` that was false. This revision never renames.

- A segment is `audit.<boot>.<first_seq>.jsonl`, where `<boot>` is the 16-hex-character boot id and
  `<first_seq>` is the `seq` of its first record, zero padded to 20 digits so names sort. The name
  states only a fact that is true when the file is created. The last `seq` is **not** in the name; a reader
  gets it from the content.
- It is created with `O_CREAT|O_EXCL` through the directory descriptor (4.2), then the **directory is
  synced**, then the first record (`start` for the first segment of a boot, `gap` after a failure,
  `segment_start` for a later rotation) is written and synced. A segment is trusted only after both.
- **A new segment at every boot.** The proxy never opens a previous boot's file for writing. That removes
  the torn-tail repair (the first revision appended a newline into an old file), the "missing" and "empty"
  crash windows of the old rotation, and the need for any lock to cover an old file. The `start` record
  carries `prev_tail`: the proxy reads (never writes) the newest earlier segment and records `clean`
  (last byte `\n` and the last line parses), `torn` (it does not), or `none` (no earlier segment). A torn
  file stays as it is, as evidence.
- A crash after `O_EXCL` create and before the first record leaves an empty segment. A reader treats an
  empty segment as zero records.
- **Rotation inside a boot is a later stage** (`max_segment_bytes`): finish the active segment with
  `sync_data`, create the next segment under the same rules, with `prev_segment` and `prev_last_seq` in
  its `segment_start`. If creation or the directory sync fails, the writer **keeps appending to the old
  segment** (its name remains true) and retries later. Stage 1 has one segment per boot, bounded by the
  quota (4A).
- Crash points and what remains discoverable: every acknowledged record is in a file that existed
  durably (directory synced) before the record was acknowledged, so it is found by listing the
  directory; no step moves a file.

External rotation (logrotate, a "reopen" command) and `copytruncate` are not supported (open question 8,
decided): `copytruncate` loses records appended between the copy and the truncate [I]. Shippers read
closed segments, or follow the active one without touching it.

### 4.6 What fsync costs [M]

One scratch file in a temporary directory on the internal SSD of a Mac mini (APFS), 220-byte
records, one writer, idle machine, record appended with `write`, then the flush call timed. This is
**macOS, not the Linux filesystem the proxy runs on, and the numbers are for scale only.**

| Flush call | n | p50 | p99 | max |
|---|---|---|---|---|
| libc `fsync` | 300 | 0.012 ms | 0.022 ms | 0.023 ms |
| `fcntl(F_FULLFSYNC)` | 300 | 3.93 ms | 4.21 ms | 9.34 ms |
| 8 records, then one `F_FULLFSYNC` | 100 batches | 3.83 ms per batch | 4.86 ms | |

Reading: on macOS libc `fsync` does not ask the drive to flush its cache, so the 12 microsecond row
shows the call is cheap, not that data is stable. **Rust's `sync_data` on macOS is `F_FULLFSYNC`**
(4.1, [read std]), so the Rust-visible cost there is the 4 ms row; the 12 microsecond row is what a
direct libc `fsync` call would show and is not what this design would call. None of this is evidence
for Linux. A Linux measurement on the stated disk (filesystem, device, kernel) is required **before**
group commit is justified, and its result goes in the PR, with no threshold promised. Arithmetic [I]:
if one sync costs about 4 ms, `per_record` caps one process near 250 durable records per second; that is
ample for held writes (bounded by a human approval) and the reason group commit is deferred.

### 4.7 The non-waiting path

`StreamAudit::drop` writes the outcome today, synchronously, in a destructor on a runtime worker [read].
A durable wait there would block a worker for a sync. In `fail_closed` the **held-route** records that are
not gating (`denied`, `expired`, `abandoned`, `superseded`, `dropped_on_reload`, `abandoned_after_approve`,
`connect_failed`, `completed`, `claim_aborted`, `audit_unavailable`) are **non-waiting appends**: put the
job in the writer's channel and return. The writer syncs it with the next record. If the channel's
non-waiting share is full the record is dropped and counted (4A). The client never waits for it, and the
refusal of a request is never changed because its record could not be queued. Records of other routes stay
on stdout in stage 1 (3.3). The non-waiting share and the deny token bucket are **in** stage 1 (section 10).

### 4.8 Startup rejection (exit code 2, message on stderr, nothing listens)

`fail_closed` is refused at startup when any of the following holds [A, design]:

- `sink` is `stdout` or `journald`, or missing, or `dir` is missing, empty or not absolute;
- `fsync` is missing, `none`, or unknown;
- `write_timeout_ms` is 0, `max_record_bytes` or `max_total_bytes` is 0, or `channel_capacity` is 0;
- `dir` exists and is not a directory, a path component is a symlink, or the directory cannot be opened
  with the walk of 4.2;
- the segment file fails a check of 4.2 (not a regular file, owner, group, mode or link count);
- the proxy's UID equals the declared agent UID (where the profile declares it; otherwise a deployment
  precondition, 4.2);
- the filesystem is not ext4 or XFS (4.1);
- the lock is held by another process;
- the directory sync, the creation of the first segment or the first durable `start` record fails (the
  sink cannot do what the mode promises, so start refuses instead of starting unhealthy);
- the directory already holds `max_total_bytes` or more in audit files (4A). This is how a restart after a quota
  trip behaves until the shipped segments are removed (4A item 3).

The message names the setting and the `ErrorKind` with a fixed phrase, never a path's contents and
never an `io::Error` string that could echo input.

## 4A. Disk and denial-of-service bound

The first revision had no bound on how much audit data a caller could cause. Every request can add a
record, refusals add records, and a hostile or buggy caller controls the volume. At 300 bytes per record
and 1000 requests per second that is about 1.1 GB per hour [I, arithmetic]. Without a bound the volume
fills, every gating write then fails, and everything in scope is refused with `audit_unavailable`; on
node-local disk a full volume can also trigger the node's ephemeral-storage eviction [I].

Bounds [A, design; the numbers are OWNER APPROVED DEFAULT (2026-11-19), section 11]:

1. **Per-record cap.** `max_record_bytes` (4096). Request-derived fields are truncated when serialized:
   `path` to 256 bytes, `aws_target` to 128 bytes, each with a trailing marker and `"trunc":true` on the
   record. Names from configuration are bounded when the config is validated. A serialized line over the
   cap after truncation is an internal error: it is refused for a gating record and dropped and counted
   for a non-waiting one. The size cap is a test (an oversized path and an oversized `X-Amz-Target`).
2. **Rate bound.** Gating records are bounded by the writer's sync rate and the channel (4.6, memory
   bounded by `channel_capacity * max_record_bytes`, about 4 MiB), and for held writes by the hold table
   caps and cooldown [read, PR #29]. Non-waiting records may use at most **half** of the channel, so a
   flood of refusals cannot make gating records fail with "channel full"; beyond that they are dropped and
   counted. A caller who can cause unlimited denies can still cause unlimited **counted drops** but not
   unlimited disk. Denies are additionally bounded by a token bucket (200 per second, burst 400 [A]):
   past it, denies are counted and one `deny_rate_limited` record with the count is written per second.
   In stage 1 the bucket covers the held-route denies that go to the file (3.3); deny records of other routes
   stay on stdout as today.
   This loses individual deny records on purpose; it is an owner-visible trade (section 11).
3. **Total quota.** `max_total_bytes` over **all** `audit.*` files in the directory. The proxy scans the directory
   at startup, then keeps a running count of the bytes it appends in this boot. The count does not see
   deletions made by a shipper while the proxy runs, so the count only grows until restart. **In stage 1
   the quota is fail-closed until restart, with no automatic recovery** [owner question 21]:
   - When the next record would exceed `max_total_bytes`, the record is not written and no `seq` is
     assigned. The writer latches the `Quota` state (4.3). It makes no further attempt in this process.
   - **What the operator sees.** (a) Every new held request and every approval that needs `forward_started` is
     refused with 503 `audit_unavailable` (9.1). (b) One line on stderr, written once at the trip, with a
     fixed phrase: `auth-proxy: audit quota reached, durable held-route audit refused until restart`. No path
     and no count of records. (c) The `last_error_class` of 8.1 is `quota`, but stage 1 binds no endpoint
     that exposes it. (d) The pod stays Running. In the passthrough pipeline, which has no readiness gate
     in stage 1, the pod also stays Ready. A sidecar profile reports 503 at `/admin/v1/ready` (8.3). (e) The
     file holds no record of the trip, and the reader cannot see it from the file: the last record is the
     last durable one, and there is no `gap`, because no sequence number was lost. Non-held records are on
     stdout and are not affected by the file's quota.
   - **Recovery is manual and restart-only.** The proxy never deletes or truncates a segment. The operator
     stops the proxy, which closes the active segment, copies and removes the segments the shipper has
     delivered (the tripped segment included, once it is closed), and starts the proxy again. The proxy
     does not resume while the quota is latched. On start the scan (4.8) refuses to start with exit code 2
     and a fixed message if the directory still holds `max_total_bytes` or more, so a restart without
     removing shipped segments stays down and is visible as a crash loop.
   - Rotation inside a boot (`max_segment_bytes`) would let the proxy close a segment and continue without a
     restart. It is **not** in stage 1 (section 10 stage 2). The active segment of a running boot grows until
     the latch is set. Deleting the oldest segment instead of latching is a retention decision that silently
     destroys unshipped evidence; it is not proposed (section 11 item 14).
4. **Isolated volume.** The directory should be a dedicated volume sized to `max_total_bytes` plus
   headroom, so audit exhaustion cannot consume the node's root filesystem or another workload's space.
   The quota protects the volume; the volume protects the node. The startup check of 4.1 refuses a
   directory on an unsupported filesystem but cannot prove isolation; it is a deployment requirement.
5. **Throughput coupling.** All records share one writer. In stage 1 only held-write records are gating,
   so reads cannot starve them. If stage 3 gates reads, a burst of reads and held writes share the
   writer's sync budget (about 250 per second at 4 ms); gating jobs of the held class are then dequeued
   first [A], and a full channel refuses everyone, so the cap of item 2 matters more.
6. **Retention and shipping** belong to the deployment: a shipper that reads closed segments, confirms
   delivery, then deletes them. Who runs it, and the retention period, are owner questions (section 11).

Tests: hostile-load tests (section 10) prove bounded memory, bounded line size, prompt fail-fast and
the quota refusal.

## 5. A request id that joins the records

### 5.1 The field

`request_id` is 16 random bytes from the operating system's random source, hex encoded (32 characters).
It is **not derived from any input**: not the caller key, the surrogate, the path, the time or the body
[A, design]. It is unique with overwhelming probability across restarts, so it needs no `boot` to be
joined.

`boot` is a separate 8-byte random value minted per process start. With `seq` it names a record:
`(boot, seq)` is unique, and `seq` is a counter from 1 that the writer advances by one for every record it
takes, including `gap` and non-waiting ones (4.2).

**A retry gets a new id.** If a client retries after a possible duplicate (7.4), the retry is a new
request with a new `request_id`; nothing in the log links the two.

### 5.2 What joins what [DECIDED, open question 3]

- **Stage 1 does not change PR #29's ids.** Records of a held write share `request_id` with the **hold
  entry id** that PR #29 mints inside `admit` after the cooldown, duplicate and cap checks [read, PR #29
  at `e7818ad`]. The requests refused before that point (`cooldown`, `identity_cap`, `table_full`,
  `shutdown`) have no hold id, so their non-waiting `deny` record has no join key in stage 1. That is
  accepted: those records carry route and identity and are counted.
- **After PR #29 merges** (stage 3), one id is minted at handler entry, before policy, and is used as the
  hold entry id, so refusals also carry it and `decision`/`outcome` records of non-held requests join. It
  is a small change in `admit`'s signature, made after the merge, not inside the PR. Not blocking PR #29.
- `decision` and `outcome` of one request (stage 3) share `request_id`. A `deny` is one record with its
  own id.
- Superseded requests (PR #29): the older entry's records keep its own request id. How the `superseded`
  record names the newer entry is PR #29's business and is not specified here.

## 6. Secrecy and tamper evidence

### 6.1 Allow-list of fields

A record is built from a fixed struct per kind. **The allow-list below is complete; adding a field is a
design change with review.** Almost every field is a value the proxy generated or read from its own
configuration. The fields that carry **request-derived content** are listed separately, because the first
revision's sentence "no field is a free-form string from the request" was false.

| Field | Kinds | Content | Origin |
|---|---|---|---|
| `v` | all | schema version, integer | proxy |
| `boot`, `seq`, `ts_ms`, `mono_ms` | all | boot id, counter, wall-clock ms since epoch, monotonic ms since process start | proxy |
| `kind` | all | one of the kinds in 3.3 | proxy |
| `request_id` | request kinds | random id, 5.1 | proxy |
| `pipeline` | request kinds | `sidecar` or `passthrough` | proxy |
| `identity` | request kinds | identity **name** from config | config. **Sensitive: names a principal. Owner approval, section 11** |
| `session`, `generation` | request kinds | session id and generation, as today | proxy |
| `route`, `method` | request kinds | route name from config, HTTP method (a known method, else `other`) | config |
| `path` | request kinds | **request-derived.** Route-relative, query and fragment dropped, `webhooks`/`interactions` token segments replaced by `<redacted>` (PR #29's `redact_path`, in review), truncated to 256 bytes with a marker. JSON-escaped by the serializer. **Sensitive: a path segment can still carry caller data.** Owner approval for the raw redacted form, section 11. The proposed default is the redacted, bounded form | request |
| `aws_target` | request kinds | **the one reviewed header-value exception.** The `X-Amz-Target` value, as today, truncated to 128 bytes with a marker, JSON-escaped. It is a request header value; it is allowed because the AWS dialect needs it to identify the operation | request |
| `decision`, `code`, `status`, `duration_ms`, `bytes_sent` | request kinds | as today | proxy |
| `digest` | held kinds (PR #29) | **Sensitive.** Hex sha256 of the credential-blind outbound request digest, which includes a body-derived part. A full digest lets someone with the log test guesses against a low-entropy body offline. Proposed default: the first 12 hex characters only, or omitted if the owner prefers. Owner approval, section 11 | request-derived |
| `approver` | `approved`, `denied` | approver identity name | config / approval plane. **Sensitive: names a principal. Owner approval, section 11** |
| `auth_present` | held kinds | boolean | proxy |
| `reason`, `errno` | `gap`, health | fixed enum and numeric errno; no error text | proxy |
| `trunc` | request kinds | boolean, true when a request-derived field was cut | proxy |
| `last_durable_seq`, `lost_from_seq`, `lost_to_seq`, `prev_segment`, `prev_last_seq`, `prev_tail` | `gap`, `segment_start`, `start` | sequence numbers and a segment **file name** the proxy itself generated | proxy |
| `surrogate_sha256_prefix` | `session` | 12 hex characters of a hash, as today [read session_http.rs] | proxy |
| `mode`, `fsync`, `version` | `start` | config enum values and the build version | config |
| `count` | `deny_rate_limited` | number of denies not written (4A) | proxy |

So the request-derived fields are exactly three: `path`, `aws_target`, and the body-derived `digest`.
Each is length-capped, and JSON-escaped by the serializer. A caller can still choose characters inside
the path, and the deployment must accept that.

Never present in any record, metric, log line or stderr message: a caller key, the `/ap/<key>/` prefix
(the path is route-relative by construction [read audit.rs]), a surrogate, a credential, any
`Authorization` or other header value (the single exception being `aws_target`), a request or response
body, a query string, a full file path of the sink, an `io::Error` display string.

### 6.2 How it is enforced

The existing tests already pin the key set of `AuditRec` and the absence of the query [read audit.rs
tests]. This design extends them: one key-set test per kind, and a **canary test** that sends requests
carrying a canary caller key, surrogate, `Authorization` value, query string and body, **an oversized
path and an oversized `X-Amz-Target`**, forces every failure of section 4.3, then searches the sink
files, the readiness body and the captured stderr for the canary. The check uses the serialized output,
not the struct (the same rule as the code).

### 6.3 Tamper evidence: optional follow-up, not part of this change

`seq` and `boot` already make **deletion or reordering in the middle** of a boot's records visible
(a discontinuity), and `gap` records state known losses. They do **not** detect truncation at the tail
of a boot, the deletion of a whole boot's segments, or a rewrite by a writer with file access who
renumbers [I]. **Sequence numbers alone are not tamper evidence.**

Optional follow-up, `audit.chain = "sha256"` [A]: each record carries `prev`, the hex sha256 of the
previous line's bytes, and the first record of a segment carries the last hash of the previous one. The
writer already serializes records, so the cost is one hash per record (microseconds [I]).

| | Gain | Cost or limit |
|---|---|---|
| Hash chain | detects edit, insertion or deletion in the middle of a chain by a reader that verifies | does **not** detect truncation at the tail, or a full rewrite by someone who recomputes the chain, unless the head hash is anchored somewhere the attacker cannot write (a second system, which this design excludes) |
| | | the chain must survive restarts and segments (anchor in `start` and `segment_start`), and a `gap` breaks it by design |
| | | every reader and every shipper must preserve bytes exactly |

Recommendation: deferred. Revisit if a deployment needs evidence rather than a log. The Muse design
dropped the hash-chained store for the PoC with the same reasoning (`muse-gated-passthrough.md`
section 5.2, "Hash-chained audit store: Drop") [read].

## 7. Failure analysis

### 7.1 Crash points

Records are numbered here as the proxy sees them: D = the gating record (`held`/`approved`/
`forward_started` for a held write, `decision` when stage 3 gates other requests), A = the action
(the first request byte), O = outcome (`completed` or `outcome`).

| Crash or kill at | State on disk | State upstream | What the client sees | What a reader must conclude |
|---|---|---|---|---|
| before D is written | no record | nothing | connection error | request not seen. No evidence either way |
| D written, not yet synced | the record may be there, may be missing | nothing (A waits for the ack) | connection error | **not sent**, but the record may be absent. A missing D never means "sent": A did not run |
| D durable, before A | D, no O | nothing | connection error | "authorized, possibly sent" (indistinguishable from the next row) |
| after A began, before O | D, no O | **maybe** sent | connection error or a partial response | "authorized, **possibly sent**". See 7.3 |
| after O | D and O | sent, response ended as the outcome says | normal | sent, with the outcome the proxy observed |
| held write: before `forward_started` is durable | `held` (and maybe `approved`), no `forward_started` | nothing sent, no connection opened (4.2 step 3) | connection error | **not sent**, under the complete-set conditions of 7.3. The ordering guarantees no connect and no byte before `forward_started` is durable |
| held write: `forward_started` durable, then crash before the connect | `forward_started`, no `connect_failed` | nothing sent | connection error | "authorized, possibly sent": the `connect_failed` record is non-waiting and may be lost |
| held write: after `forward_started`, before `completed` | `forward_started`, no `completed` | maybe sent | connection error | "authorized, possibly sent", exactly the row in section 5.1 of the Muse design [read] |
| held write: `forward_started` durable, table closed or policy changed, `claim_aborted` queued | `forward_started`, maybe `claim_aborted` | nothing sent | refusal | "authorized, possibly sent" unless `claim_aborted` is present; both are conservative |

### 7.2 What a reader must do

- Group by `request_id`. For one request the legal sequences are: `deny`; `decision` then `outcome`;
  `decision` alone; `held`, ..., `forward_started`, `completed` or not; `held`, ..., a terminal
  that is not `forward_started`.
- List **all** segments in the directory and sort them by `(boot, first_seq)`. Order boots by their
  `start` records' `ts_ms`, and treat any wall-clock comparison as informational (7.4).
- A `seq` discontinuity inside a boot with no `gap` covering it is a **gap**: records may be missing
  between those sequence numbers.
- A decision with no outcome and no `gap` is "authorized, possibly sent". A held write with
  `forward_started` and no terminal record is the same. Do not infer "failed" from a missing outcome.
- An unparsable line is skipped and counted. It is either a torn tail (7.1, `prev_tail = "torn"`) or
  corruption.
- A boot whose last segment ends without a clean shutdown marker may have lost its tail (7.3).

### 7.3 What the log supports, and what it does not

For a request that has a durable gating record (`held` + `approved` + `forward_started`, or `decision`):
the proxy authorized it **before** the action. **A decision without an outcome means authorized and
possibly sent**, never "sent" and never "not sent".

- **An outcome proves only what the proxy observed.** `completed` or `outcome` says the proxy saw a
  response end, or saw a reset. It does not say the upstream executed, rolled back or ignored a side effect.
- **The absence of a decision proves that nothing was sent only if** the reader has a **complete, trusted
  set of segments** (no deleted file, no whole boot missing) and **no `gap` and no `seq` discontinuity
  covers the interval**, and the boot did not end by a truncated tail. If any of these fails, absence
  proves nothing.
- **Sequence numbers cannot detect tail truncation or the deletion of a whole boot.** Someone with file
  access can cut the tail of the last segment and nothing in the log shows it. Only an anchor outside
  the proxy's reach (a shipped copy, a periodically published head) can (6.3).
- For a request the upstream received, the log contains the gating record unless a `gap` covers its `seq`
  or the files were altered after the fact.

### 7.4 Duplicates, restarts and clock jumps

- **Duplicate execution after a retry.** A request can be sent, the response lost or the proxy
  restarted, the client retries, and a human approves again. Two requests, two `request_id`s, two
  possibly-sent upstream effects. The log shows both authorizations; it **cannot** deduplicate them,
  because the retry is a different request (5.1). Deduplication is the caller's and upstream's business.
- **Duplicates in the log after restart.** The proxy keeps no queue and replays nothing: a held request
  dies with its connection (Muse design section 5.1 [read]). The record of a refused-by-timeout request
  that lands later is not a duplicate, it is the ambiguous case in 4.3. A reader dedupes on
  `(boot, seq)`; two terminal records for one `request_id` are an anomaly to report, not to merge.
- **Restart in the middle of a batch.** Jobs not yet acked were never acknowledged; their requests see a
  connection error. Records of that batch may be on disk in the old boot's segment. They keep their old
  `boot` and `seq` and are not rewritten; the new boot starts a new segment (4.5).
- **Clock jumps.** `ts_ms` is `SystemTime` and can jump backward or forward (NTP step, VM resume). It is
  only informational. Order is `seq` within a boot and `mono_ms` as a cross-check (non-decreasing
  within a boot). A reader that sees `ts_ms` go backward while `seq` grows reports a clock step and
  trusts `seq`. The `start` record carries both clocks so boots can be placed in time without trusting
  a later clock. Durations use `Instant`, as `duration_ms` does today [read].
- **Disk full then recovered.** Handled by the gap marker (4.4). The first record after recovery is
  `gap`, not a request record.
- **Shutdown.** On SIGTERM the proxy stops accepting, closes the hold table, lets the writer drain and
  sync **until `shutdown_grace_ms`**, then exits (4.3). Outcomes of in-flight streams cut off by the exit
  are lost and not counted by the proxy (it is gone) [A]; readers treat them as "possibly sent" by 7.2.

## 8. Metrics and readiness

### 8.1 Exposure

There is no metrics endpoint today [read]. **Stage 1 builds no new endpoint.** The sink keeps its health
and counters in atomics that the writer updates, so reading them never takes a lock the writer holds
[A]. Held writes exist only in the passthrough pipeline, which binds no admin socket [read], so stage 1 has
nowhere to serve them. Its signals are the 503s clients see, the `gap` and `start` records in the log, the
existing failure counter and a one-line stderr summary at startup. The sidecar's readiness body (8.3)
carries the audit state from stage 3, when the sidecar is gated. This is a gap in operability and is stated, not hidden.

Later (stage 4) [A]: a JSON document, `GET /admin/v1/audit`, for passthrough on **a local Unix socket,
mode `0600`**, **not on the approval listener**: the approval listener is a different trust boundary
(open question 4, decided). No Prometheus text format and no new dependency (open question 6, decided).

```
{ "mode":"fail_closed", "state":"healthy", "write_failures_total":{"gating":0,"non_waiting":0},
  "refused_total":0, "timeouts_total":0, "late_acks_total":0, "gaps_total":0,
  "dropped_total":0, "deny_rate_limited_total":0, "queue_depth":0, "quota_used_bytes":0,
  "last_error_class":"none", "fsync_seconds":{"count":0,"sum":0.0,"max":0.0,"buckets":[...]} }
```

These map to #32's required names: `audit_write_failures_total` by record class, `audit_refused_total`,
`audit_fsync_seconds` (a fixed-bucket histogram, no dependency), and `audit_sink_healthy` (0 or 1).
`last_error_class` is a fixed enum (`none|write|fsync|enospc|timeout|open|quota`), never an error string.
In `best_effort` mode the endpoint returns the existing failure counter only.

### 8.2 Health

The state of 4.3 is the health: `Healthy` is 1, the others are 0. It is derived from atomics (the writer's
free flag, the age of the oldest queued job, the last error), so it does not depend on traffic and does
not wait for the writer. **There is no heartbeat in stage 1** (it needs the writer for nothing the
recovery timer does not already do). A heartbeat record, if built later, only makes a disk that fails while
idle visible sooner in the log.

### 8.3 Readiness

When `fail_closed` and the sink is not `Healthy`, `GET /admin/v1/ready` answers 503 with the existing JSON
shape and state `audit_unavailable` (the same endpoint and `--check-ready` exec probe that the netfilter
gate uses [read netguard.rs]); otherwise unchanged. The sidecar's readiness becomes healthy only when
**both** the netfilter check and the audit check pass; passthrough has no netfilter gate. Rules:

- Readiness only. **Never a liveness failure.** Restarting the proxy does not fix a disk, and a restart
  loop would drop held requests.
- **Putting audit health in the gate also blocks pod readiness at startup when the sink is bad.** That is
  intended: a pod that cannot audit should not be Ready.
- **Readiness must not rely on `heartbeat_secs`.** The first revision said readiness returns "after two
  healthy heartbeats", which with `heartbeat_secs = 0` never happens. The rule is: the sink is `Healthy`
  again for readiness once the `gap` record is durable **and** either 3 further durable writes have
  succeeded or 10 seconds have passed, whichever comes first [A]. The recovery timer of 4.3 writes the
  `gap` on its own, so recovery needs no traffic, and a pod removed from Service endpoints by a 503
  still recovers. The `Quota` latch (4.3, 4A item 3) is **not** cleared by this rule: it stays 503 until the
  process restarts.
- **The approval plane stays reachable while audit is unhealthy**, so a denial and a revocation remain
  possible. Approving fails *before* forwarding if its durable record cannot be written (3.3). The admin
  socket and its handlers do not touch the sink for a read, so they stay responsive when the sink is stuck.
  `revoke-all` still revokes; its audit line is non-waiting and the revocation is not conditional on it.
- In the sidecar profile readiness `503` takes the pod out of Service endpoints, but the agent still
  reaches the proxy on pod loopback. That is the intended behaviour: an unhealthy sink must be loud and
  must not cause a restart [I].

## 9. Compatibility

### 9.1 The refusal on the wire [DECIDED]

`audit_unavailable` is already specified for held routes in PR #29 (in review) [read]. Main has no such
code [read: no `AuditUnavailable` in `error.rs` on `origin/main`]. This design **keeps PR #29's exact
refusal** and adds nothing to it:

- Passthrough pipeline: HTTP **503**, header `X-AP-Decision: unavailable`, `Content-Type:
  application/json`, body exactly `{"ap_decision":"unavailable","code":"audit_unavailable"}` (the
  `render_passthrough` shape, as PR #29 tests it: two keys only) [read, PR #29 `outcome.rs`]. **Nothing is
  sent upstream.** A failed `held` write creates no entry and no notification.
- Sidecar pipeline (stage 3 only): HTTP **503**, `Code::AuditUnavailable` rendered by `render(code, shape)`
  in the route's dialect [read main `error.rs`]: generic `{"error":"audit_unavailable","message":"the audit
  log is unavailable"}` (the message string from PR #29's `Code::message`, in review) or the AWS shape
  `{"__type":"AccessDeniedException","message":"auth-proxy: audit_unavailable: ..."}`. The code table in
  `phase1.md` gets one row, 503, route's dialect, logged at `error`, rate limited, like `broker_unavailable`.
- No `Retry-After` is invented: main sets none today [read, no match in `ap-core`/`pipeline.rs`].
- No part of the body carries a path, an errno or any detail. The refusal is not distinguishable by cause
  (disk full, timeout, fsync error, quota): the cause is in the metrics (`last_error_class`).
- The refusal itself is audited on the non-waiting path (`outcome` with `code=audit_unavailable`). When the
  sink is down this record usually fails and is counted.

### 9.2 Behaviour by traffic class

| Class | `best_effort` | `fail_closed`, stage 1 | `fail_closed`, stage 3 (if accepted) |
|---|---|---|---|
| Held write (PR #29, in review) | refused when `held` or `forward_started` cannot be written and flushed | same refusals, durable. `approved` required | same |
| Sidecar request (swap) | never refused for audit | unchanged, not covered | refused before swap and before the request is handed to the client when `decision` is not durable |
| Passthrough read | never refused for audit | unchanged, not covered | refused when `decision` is not durable (open question 1) |
| Refusals | audited, never changed | held-route refusals audited on the non-waiting path, other refusals on stdout as today. Never changed, and a refusal is not turned into `audit_unavailable` because its record failed | same |
| Session create, renew | audited after, best effort | same. Not gated. Gating deferred (open question 5, proposed default) | same |
| Revoke, revoke-all | audited after, best effort | same. **Never gated** | same |
| Netfilter gate state | audited after | same | same |
| Response streams already forwarded | untouched | untouched. A failing outcome record does not abort the stream | same |

### 9.3 Migration from PR #29's rule

1. PR #29 merges as it is. Under `best_effort`, held routes keep its rule: try-writes that must return
   `Ok`. This is "today's stage 2 behaviour" and this design must not weaken it. Because of it the first
   column of the table in 3.2 is *not* "never refuses" for held routes.
2. Stage 1 of this plan replaces the sink's two families (`write_*` and `try_write_*`) with one entry
   point, `append(record, need)`, where `need` is `Durable` (gating), `Enqueue` (non-waiting) or
   `BestEffort`. With a stdout sink `Durable` means "written and flushed", which is what `try_write_*`
   means in PR #29. With the file sink it means fsynced. No observable change to `best_effort`.
3. Under `fail_closed`, held routes use the same call sites with the file sink, so the PR #29 rule becomes
   the durable rule without a second code path. The additions are `approved` as a gating record and the
   reserve/persist/commit change of 4.2, which removes the table-lock wait.
4. PR #29's `HoldRec` stays as is in `best_effort`, byte for byte. In `fail_closed` its lines gain the
   envelope fields of 6.1.
5. Config: existing configs without `[audit]` are valid and unchanged.
6. `docs/design/phase1.md` ("Audit write failure"), `docs/design/muse-gated-passthrough.md` (3.9) and the
   README get a sentence each when the code lands: default best effort, held-route rule, where this mode
   is described (acceptance criterion of #32). Not edited here.

### 9.4 Interaction with #5

#5's `parked`, `approved`, `denied`, `expired`, `executed` lines need the same guarantee: a request
cannot become `parked` or `approved` without a durable record [read #32]. They map directly onto the
`Durable` need for `held` and `approved`, with `executed` as `forward_started`. #5's hash-chained store
is the optional follow-up of 6.3.

## 10. Staged plan and acceptance tests

Each stage is a separate PR and ends with tests that pass in CI. **Stage order follows dependency:** the
records exist before tests about their ids, and request integration lands before tests about request
refusals (the first revision had it the other way round).

Fault injection uses a `SinkBackend` trait seam (open, write, sync, dir-sync, free-space) in the writer.
**The seam is how fsync errors, partial writes and permanent blocks are tested**, because a real kernel
fault is hard to produce for them. Real kernel faults are used only where they are real, and each is labelled:

- **Real `ENOSPC` only on `write`**: a tiny `tmpfs` (`mount -t tmpfs -o size=64k`) allocates at write
  time and returns real `ENOSPC` on `write`. It does **not** produce `ENOSPC` on `fsync` (`fsync` on tmpfs
  is a no-op [I]), and tmpfs is not a supported sink (4.1), so this test uses the failpoints build that
  disables the filesystem check. Needs root: **`sudo mount`**, or the test is skipped with a visible
  message. `unshare -rm` is not used: unprivileged user namespaces are restricted on the `ubuntu-24.04`
  GitHub runners [I, AppArmor policy].
- **Real `fsync` `EIO` or `ENOSPC`** needs a loop-mounted ext4 with `dm-error` or `dm-flakey` (root). That
  is **optional, outside default CI**, labelled as such. Otherwise the seam covers it.
- `RLIMIT_FSIZE` with `SIGXFSZ` ignored gives a real short write and `EFBIG` on a regular file.
- **A FIFO or `/dev/full` is seam-only.** Startup requires a regular file on a supported filesystem, so
  neither can be the sink; they appear only inside a test seam backend that stands in for a slow or full
  device, and the test says so. A realistic slow disk needs `dm-delay`, optional.
- A test-only Cargo feature `audit-failpoints` (off by default, never in a release build, like the existing
  `matrix-upstream` and `stage1-probe` features [read `Cargo.toml`]) gives pause and kill points and
  disables the filesystem-type check.

### Stage 0: this note

Review. No code. Revision 2 answers the first review; **a re-review of this revision is required before
any implementation.**

### Stage 1: durable fail-closed for held writes (after PR #29 merges)

The smallest honest first version. In: a secure file sink (4.2) with the file-level checks, `sync_data` per
record, a bounded dedicated writer, durable `held`, `approved` and `forward_started` with the reserve /
persist / commit change and the forward claim of 4.2 (`forward_started` before the connect), the exact 503
wire, the per-record size cap, the quota latch of 4A item 3 (fail-closed until restart), the stage-1
placement of 3.3 (the file holds held-route records only), the non-waiting share and the deny token bucket
for held-route records. Out, deferred: rotation inside a boot (`max_segment_bytes`), group commit,
heartbeat, hash chain, the admin socket and rich metrics, gating of reads and the sidecar.

Changes to PR #29 that stage 1 needs, listed here so the PR #29 author can see them: move the
`forward_started` write from `claim_start` / `HeldBody::poll_next` to before the request is handed to the
HTTP client, and keep `approved` on the path of 4.2. Under `best_effort` the refusal rule is unchanged.

Tests, in this order:

1. **Records and startup** (no writer yet): key-set test per kind; the size cap with an oversized path
   and an oversized `X-Amz-Target`; every startup rejection of 4.8 exits 2 with a fixed message
   (including dir not a directory, symlink in the walk, segment file owner, group, mode, link count and
   type, wrong filesystem type, quota already reached, UID equal to the agent's when declared); an emptyDir
   layout with mode 0777 and with a setgid group directory **is accepted**; `best_effort` unchanged byte for
   byte (golden files).
2. **Writer at the seam:** write error, short write, `sync_data` error, ack timeout, permanent block, late
   success after timeout (no gap, `late_acks_total`, descriptor trusted), cancellation versus ack, the
   gap arithmetic (`gap` has `seq = M + 1`, next record `M + 2`, `lost_from_seq = N + 1`, no retry of
   `sync_data` on the failed descriptor, asserted by the seam), "probe is writer free" (no probe while
   the writer is blocked), a recovery that needs no traffic, a shutdown that exits by `shutdown_grace_ms`
   with the writer blocked. **Quota latch:** at `max_total_bytes` the next record is refused with no `seq`
   assigned and no `gap` written; the latch holds after the seam reports space free; the process writes
   nothing further and deletes nothing; the stderr line is printed once; a restart with the directory still
   at the cap exits 2, and a restart after the test removes the closed segments starts a new segment.
3. **Segments:** `O_EXCL` creation, directory sync before the first record, a new segment per boot, a
   `prev_tail = torn` after a killed boot, an old file never opened for write, crash injected after each
   namespace step with restart discovery of every acknowledged record.
4. **Hold table integration:** with a blocked sink, `approve`, other admissions, `list` and `drain` all
   finish within bounds while a `held` write waits (the lock is free); `Reserved` and `Claiming` entries
   are invisible to approve, reload and supersede; a cancelled handler releases its reservation;
   shutdown between persist and commit rolls back with `abandoned`.
5. **Request refusals** (only after item 4): the exact status, `X-AP-Decision` and body of 9.1; the mock
   upstream records **zero request bytes and zero connections** for every failure of item 2 and for every
   refusal of this item, because every audit failure in this design happens before the connect (4.2 step 3).
   A failed `held` creates no entry and no notification; a failed `approved` enqueue refuses the forward; a
   failed `forward_started` opens no connection and sends nothing; the refused request's non-waiting record
   is attempted.
6. **Order test:** the seam backend and the mock upstream stamp one shared counter; assert
   `sync(held) < entry visible`, `sync(approved) and sync(forward_started) < TCP accept at the mock upstream`,
   and `TCP accept < first request byte accepted by the mock upstream`. The connect **must not** precede
   `forward_started`. A file-level check that the line is *visible* proves only that it was written, not
   synced, and is not used for this assertion.
7. **Hostile load:** a sustained flood of requests, denies and oversized paths with the sink failing
   and with the sink healthy. Assert: memory stays under `channel_capacity * max_record_bytes` plus a
   fixed margin; no line exceeds `max_record_bytes`; refusals are prompt once `Stuck` (fast fail, no
   `write_timeout_ms` wait per request); the approval plane and readiness answer within 200 ms during the
   stall [A]; no unbounded thread or task growth; the quota latches at the cap, nothing is deleted, and
   the latch holds with the sink healthy again; non-waiting records cannot fill the gating share of the
   channel; a flood of read outcomes on stdout does not change the file's byte count.
8. **SIGKILL:** the harness kills the real binary at failpoints (before D, D written not synced, D durable
   before A, after A before O) and the checker applies the 7.2 reader and asserts the 7.1 conclusion. **These
   tests prove ordering and the reader's logic, not durability:** SIGKILL leaves the page cache intact, so
   "written, not synced" cannot show a loss. The reader's assertion must accept both the presence and the
   absence of unsynced bytes. Durability needs `dm-log-writes`, `dm-flakey` with dropped writes, or a VM
   hard reset; optional, outside default CI.
9. **Canary** of 6.2.
10. **Measurement:** added latency of `per_record` on the stated Linux disk (filesystem, device, kernel),
   reported in the PR, no threshold promised. This is the number that decides whether stage 2 is needed.

### Stage 2: group commit and rotation inside a boot

Only if the Linux measurement shows 250 syncs per second is not enough, and for rotation when a boot's
volume requires it. Tests: `group_commit` with a delayed sync at the seam (all wait, none acked early,
one sync serves the batch, count syncs); rotation crash injected after each namespace step, concurrent
load during rotation, creation failure keeps appending to the old segment with a true name.

### Stage 3: gate every forwarded request, and one request id per request

Only if the owner accepts open question 1. Request id at handler entry used as the hold id (after PR #29
merges), `decision` before the swap and before the request is handed to the client, the sidecar
`audit_unavailable` rendering in both dialects, the envelope fields in `fail_closed`. Tests: zero upstream
contacts and no swap on every failure; the order test of stage 1 for `decision`; both dialects' bodies; a
stream already forwarded is not aborted when only its outcome fails; throughput coupling (a burst of reads
does not starve held writes).

### Stage 4: heartbeat, metrics endpoint, readiness for passthrough

`/admin/v1/audit` on a local Unix socket, the readiness composition of 8.3 including the sidecar's
netfilter-and-audit rule, optional heartbeat. Tests: readiness 503 while unhealthy and 200 after the
`gap` and the recovery rule; `--check-ready` exit codes; the approval plane stays reachable while
unhealthy; the metrics output is free of the canary.

### Stage 5 (optional): hash chain (6.3)

Only on the owner's request.

### Acceptance criteria of #32, mapped

| #32 criterion | Stage |
|---|---|
| `best_effort` byte for byte | 1 |
| every request refused with a failing sink, zero upstream contacts | 1 for held writes (zero request bytes, zero connections, 10 item 5); 3 for the rest |
| write error, short write, fsync error, blocking sink, each refusal and counters | 1 |
| gap marker after fsync error and recovery | 1 |
| decision on disk before upstream, ordered test | 1 for held writes; 3 for the rest |
| `group_commit` never acks early | 2 |
| forwarded stream not aborted when only the outcome fails | 3 |
| stdout or `fsync = none` rejected, exit 2 | 1 |
| latency measurement on a stated disk | 1 (per_record), 2 (group_commit) |
| `phase1.md` row and README updated | with the code, not in this note |

## 11. Open questions

**DECIDED** means settled in review. **OWNER APPROVED DEFAULT (2026-11-19)** means the owner approved the value and the text above
already uses it. The owner can still replace any one without changing the rest of the design except where noted.

### Decided

2. **`approved` as a gating record** for held writes. **DECIDED: yes**, in `fail_closed` only. `approved`
   is enqueued immediately before `forward_started`; the single writer and the file-wide sync mean the
   ack of `forward_started` covers it, so no extra sync. A failed or dropped `approved` enqueue is
   `audit_unavailable`. PR #29's `best_effort` behaviour is unchanged.
3. **Request id and PR #29.** **DECIDED:** do not change PR #29's ids and do not block PR #29. After it
   merges, mint one id at handler entry and use it as the hold id (5.2).
4. **Where passthrough serves readiness and metrics.** **DECIDED:** never on the approval listener (a
   different trust boundary). If needed later, a local Unix socket, mode `0600` (stage 4).
6. **Metric format.** **DECIDED:** dependency-free JSON, no Prometheus dependency.
7. **Fast-fail instead of "every request tries".** **DECIDED:** fast fail, one recovery attempt per
   `retry_ms`, defined as "writer free" (4.3). It refuses more, never less. It supersedes #32's wording.
8. **Rotation ownership.** **DECIDED:** built-in segments only, no external reopen and no `copytruncate`
   (4.5). Retention is an owner question below.
9. **File sink in `best_effort`.** **DECIDED:** no, not in v1. It adds a mode without helping the
   guarantee.
11. **Reads without a second write-ahead record.** **DECIDED:** no second record. For the sidecar and for
    reads (stage 3) the `decision` is the only "about to send" record, so a decision without an outcome
    means "authorized, possibly sent" (7.3).
13. **Torn tail.** **DECIDED:** moot with a new segment per boot. Never write into a previous boot's
    file; the new `start` record carries `prev_tail` (4.5).

### Owner-approved defaults (2026-11-19)

1. **Gate scope.** **OWNER APPROVED DEFAULT (2026-11-19):** in v1, **held writes only**. Reads and the
   sidecar are unchanged and not covered by the guarantee. Alternative: gate every forwarded request from
   the start, as #32 specifies (stage 3 would then move into stage 1, at the cost of availability when the
   disk is down and a shared writer).
5. **Session create, renew and revoke.** **OWNER APPROVED DEFAULT (2026-11-19):** **never gate revoke
   or revoke-all.** Gating of create and renew is deferred (creating a session grants authority and could
   be gated later; it is not in stage 1).
10. **Timing defaults.** **OWNER APPROVED DEFAULT (2026-11-19):** `write_timeout_ms = 2000`,
    `retry_ms = 250`, `channel_capacity = 1024`, `shutdown_grace_ms = 5000`; heartbeat 30 if built later.
    Provisional until the Linux measurement and the hostile-load tests inform them.
12. **Storage requirement.** **OWNER APPROVED DEFAULT (2026-11-19):** require a **dedicated
    persistent local ext4 or XFS volume**; **refuse tmpfs, ramfs, NFS, CIFS, FUSE and container overlay**
    (4.1). `flock` and `O_NOFOLLOW` are used; a read-only root with a volume is supported.
14. **Total disk cap and behaviour at the cap.** **OWNER APPROVED DEFAULT (2026-11-19):**
    `max_total_bytes` = 1 GiB per directory (a placeholder: the owner sets the value), **fail closed at
    the cap, never delete unshipped records silently** (4A). In stage 1 the latch holds until restart (item 21).
    Alternative: delete the oldest segment, which destroys evidence and is not proposed.
15. **Retention and shipping ownership.** **OWNER APPROVED DEFAULT (2026-11-19):** the deployment
    ships closed segments and deletes them after delivery; the proxy deletes nothing. The owner names who
    runs the shipper and the retention period.
16. **Is `emptyDir` acceptable?** **OWNER APPROVED DEFAULT (2026-11-19):** only if the records are also
    **shipped off the pod**, because `emptyDir` is deleted with the pod (4.1). Otherwise a persistent
    volume. On `emptyDir` the directory's mode and owner are not checked (4.2), so the file checks carry the
    weight and item 22 applies.
17. **Retention of sensitive fields.** **OWNER APPROVED DEFAULT (2026-11-19):** `path` and `digest`
    only in redacted, bounded form (path redacted by PR #29's rule and truncated to 256 bytes; digest as a
    12-hex-character prefix or omitted). `identity` and `approver` names are kept, because binding the
    approver to the action is the purpose of the record. The owner may drop any of them.
18. **Who may read the audit files.** **OWNER APPROVED DEFAULT (2026-11-19):** only the proxy's UID
    and the shipper's. The file is created `0600` and is checked (4.2). The directory mode is no longer
    enforced (4.2), so the agent must not mount the volume; the owner names the shipper's identity (it must
    run as the proxy's UID, or with a reviewed ACL or group, because the file is `0600`) and any human readers.
19. **Deny rate bound.** **OWNER APPROVED DEFAULT (2026-11-19):** a token bucket of 200 denies per
    second with a per-second summary record (4A), accepting that individual deny records are lost under a
    flood. In stage 1 it covers held-route denies only (4A item 2).
20. **Where non-held records go in stage 1.** **OWNER APPROVED DEFAULT (2026-11-19):** the file sink
    carries held-route records only. Reads, sidecar traffic, other refusals, `netfilter`, `session` and
    `probe` stay on stdout as today, in both modes (3.3). Reason: read volume must not fill the file and latch
    the held-write quota. Alternative: all records to the file, with a rate bound on reads, and a quota that
    reads can reach. Owner accepts that the audit trail is then split across two sinks, and that a reader needs
    both.
21. **Quota recovery in stage 1.** **OWNER APPROVED DEFAULT (2026-11-19):** the quota is fail-closed until
    the process restarts, with no automatic recovery, and the operator's procedure is the one in 4A item 3:
    stop, ship and remove closed segments, start. Owner accepts the operator signals of 4A item 3 (503s, one
    stderr line, the exit-2 crash loop when the cap is still reached), and that a passthrough pod stays Ready
    while the quota is latched because stage 1 has no passthrough readiness gate. Alternative for later: segment
    rollover inside a boot (`max_segment_bytes`, section 10 stage 2), which lets the proxy continue without a
    restart.
22. **Directory and volume ownership.** **OWNER APPROVED DEFAULT (2026-11-19):** the proxy creates a missing
    audit directory with mode `0700` and uses an existing one as found (4.2). The file checks of 4.2 apply to
    every segment. On `emptyDir` the directory is not protected from other UIDs that mount it, so the deployment
    mounts it in the proxy container only. The owner chooses between an init container that creates and chowns
    the directory (for a PVC with `fsGroup` or a different owner) and the proxy's own `mkdirat`.

## 12. Evidence and method

- Code read on `origin/main` at `3878421`: `crates/ap-core/src/audit.rs`,
  `crates/ap-proxy/src/audit_sink.rs`, `pipeline.rs`, `passthrough.rs`, `netguard.rs`,
  `session_http.rs`, `admin_http.rs`, `probe.rs`, `evidence.rs`, `lib.rs`, `ap-core/src/error.rs`, `Cargo.toml`.
- Docs read: `docs/design/phase1.md` audit sections, `docs/design/muse-gated-passthrough.md` sections 3.9
  and 5 (on `origin/main`; also on `origin/feat/muse-stage2`).
- PR #29 (in review, **moves**): first read with `git show origin/feat/muse-stage2:<path>` at `6f3e678`
  (`audit_sink.rs`, `outcome.rs`, `hold/mod.rs`, `passthrough/hold_path.rs`, and `git diff
  origin/main...origin/feat/muse-stage2 -- crates/ap-core/src/audit.rs`). **Re-read at `e7818ad`** for the
  points this revision relies on: `HoldTable::admit` runs the `persist` closure (the `held` write) under the
  table lock; `HoldTable::claim_start` runs the `forward_started` write under the table lock, on the first
  body poll, after the upstream connection exists and before the first request byte (code comment:
  "the connection exists and no request byte has been flushed"); `approved` is written with the
  best-effort `write_hold` (the `record` method of the hold path); `AuditSink::try_write_hold` returns the
  result of write and flush.
- Rust std, `library/std/src/sys/fs/unix.rs` at rustc commit `0ef1bc386` (the installed toolchain's
  `rustc -V` commit; the toolchain on the build host has no `rust-src` component, so the file was read from
  the rust-lang repository at that commit): `File::fsync` and `File::datasync` call `fcntl(F_FULLFSYNC)`
  under `target_vendor = "apple"`, and `fdatasync` on Linux. [read]
- Issues read: #32 (no comments), #1 (question 5), #5 (the audit-before-action comment).
- The measurement in 4.6: a short script, 300 appends with libc `fsync`, 300 with `F_FULLFSYNC`, 100
  batches of 8, on an internal APFS volume, scratch directory removed afterwards. Scale only.
- Review feedback incorporated in revision 2: the action boundary, supported storage, file security, the
  blocked-writer state machine, immutable segments, secrecy, reader conclusions, readiness, test order,
  the disk and DoS bound, and a smaller first stage.
- Revision 3 (second council review, opus5 blockers 1 to 3): the hyper behaviour behind blocker 1 is the
  council's reading of hyper 1.9.0 `proto/h1/dispatch.rs` (poll_loop calls poll_write, then poll_flush, and a
  Pending body poll leaves the buffered head to be flushed). It was not re-read in this revision. The
  `forward_started` placement, the quota latch, the stage-1 placement and the file-level checks are design
  decisions in this note, not measurements.
- Not done: no code was run against this design; no Linux measurement; no fault injection; no test of the
  file checks on a real emptyDir or fsGroup volume.
