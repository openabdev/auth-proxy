# WebAuthn approval bound to the held request

Status: design note, no code. Draft for the standing design review; not final. Issue:
[#37](https://github.com/openabdev/auth-proxy/issues/37). Based on `origin/main` at `3878421`.
Builds on `docs/design/muse-gated-passthrough.md` (sections 3.4 to 3.9, 5.2, open question 7) and on the
stage 2 implementation in draft PR [#29](https://github.com/openabdev/auth-proxy/pull/29), which is **in
review and not merged**. Everything below that names a PR #29 function, type or endpoint describes the
branch head `e7818ad` as read on the day of writing. It may change, so this note depends on the
*behaviour* PR #29 gives (an in-memory hold table, one critical section for the approve transition, a
policy re-check inside it) and lists in section 11 the few places where it needs a change.

## How claims are labelled

- **[read]** read in code or docs (the file or URL is named).
- **[M]** measured: run during this work. The tag names what was run. All builds, `cargo tree` and
  `cargo audit` runs were on a build host in a scratch crate (`/tmp/wa-scratch`), none on the laptop.
- **[I]** inferred from what was read.
- **[A]** assumed. A risk until someone checks it. Section 12 and the stage 0 spike in section 10 say how.

Text of the form "the gate does X" is a proposal and carries no tag.

## 0. What the approver should do today (Basic auth, stage 2 as in review)

Today the approval page is protected by HTTP Basic auth and a per-page CSRF token [read PR #29
`approval/auth.rs`, `approval/csrf.rs`]. Until WebAuthn exists:

1. Keep the approver password in a password manager and use a long random value (the runbook generates
   `openssl rand -hex 32`) [read `docs/runbooks/muse-stage2.md` on PR #29].
2. Open the link from the notification, and read the page before pressing anything: method, route, the
   "Sent to" upstream, path, query and body. The digest on the page is not something you can check by eye,
   so the page itself is the only review.
3. Reach the approval port only over the private network, from your own devices.
4. Do not tap anything inside the notification itself. It carries a fixed sentence and a link
   [read PR #29 `notify.rs`, runbook section 3].

Whether iOS Safari offers to save the credentials from an HTTP Basic prompt, and whether autofilling them
is then gated by Face ID or Touch ID: **[A], not verified.** Apple documents Face ID or Touch ID gating
for AutoFill of saved passwords in general
([Meet Face ID and Touch ID for the web](https://developer.apple.com/videos/play/wwdc2020/10670/) covers
WebAuthn, not Basic prompts). I found no Apple page that says Safari saves Basic-auth credentials, and the
community answers disagree
([Ask Different 319953](https://apple.stackexchange.com/questions/319953/how-can-i-have-ios-safari-remember-credentials-for-websites-with-https-basic-a/459875)
says it does not;
[Stack Overflow 26236753](https://stackoverflow.com/questions/26236753/how-to-make-ios-safari-saves-password-for-basic-authentication-website)
says the keyboard offers saved passwords). Try it once on the phone before relying on it.

Even if it works, **it is not a substitute for request-bound WebAuthn.** A Basic password proves that
someone knows a string. It does not prove a person was present, it can be replayed from anywhere the
header can be sent, and it is not tied to the request on the screen. The rest of this note is about those
three gaps.

## 1. Problem and non-goal

**Problem.** PR #29 holds a write until the owner approves it. The notification channel (a self-hosted ntfy
server) is one way: it wakes the phone and opens a link [read issue #37]. The approval itself is a Basic
credential plus a CSRF token. There is no user-verification step, and nothing ties the credential's use to the
specific request. The design already accepted that for the pilot and named WebAuthn as the later
replacement [read muse-gated-passthrough.md section 3.6 and open question 7].

**Non-goal: no approve button inside a notification, ever.** An ntfy `http` action or a link that approves
on GET is out, for four reasons:

- A notification can be tapped from a lock screen [A, platform behaviour; issue #37 states it].
- To approve from a notification the credential has to be carried or implied by it. It would sit on the
  ntfy server and on the device, readable by anyone who knows the topic [I].
- The approver would approve something they have not looked at, which breaks the approve-what-you-see
  principle that the whole gate rests on [read muse-gated-passthrough.md section 5.2, row "Canonicalized
  request, approval bound to its hash"].
- A GET that approves can be fired by a link preview or a scanner, with no human at all [I].

The notification stays a doorbell: a fixed sentence and a link to the page [read PR #29 `notify.rs`].

## 2. Threat model

### 2.1 What Basic auth plus CSRF does not give

| Property | Basic + CSRF today | Why |
|---|---|---|
| Biometric presence | no | The browser sends the stored password on its own. Nothing asks a person to be there [I]. |
| Hardware-bound, non-replayable credential | no | The credential is a string. Anyone who has it can build the header. The CSRF token is per page, so it stops a hostile page, not a holder of the password [read `csrf.rs` doc comment]. |
| Binding to the specific request | no | The POST names an entry id and echoes a CSRF token. Nothing the approver signed or typed covers the content [read `approval/mod.rs` `decide`]. |

### 2.2 What WebAuthn adds

- **User verification, enforced by the server.** The assertion carries the UV flag. Every approval requires
  user verification: the gate refuses an assertion whose UV flag is clear. A device passcode counts as user
  verification, so a biometric is not the only way to pass it. The option `userVerification: "required"` is a request to the browser, so it is not
  relied on: Apple reports that some Safari-adjacent paths ignore it
  ([Apple developer forum 813784](https://developer.apple.com/forums/thread/813784)), and the spec makes
  the flag the only thing the server can check [I].
- **A private key that stays in the authenticator.** The key is never sent to the server and cannot be typed or
  autofilled. A synced passkey does leave one device, since iCloud Keychain copies it to the owner's other
  devices. Section 2.3 covers the consequence.
- **Origin binding.** The browser signs over the origin it is on, so a lookalike page cannot collect a
  usable assertion [I, W3C WebAuthn model].
- **Request binding.** The challenge is derived from the entry id, the canonical request digest, the
  upstream authority, the hold expiry and a server nonce (section 4.2). An assertion cannot approve another
  entry or a changed request.

### 2.3 What WebAuthn does NOT add

- **An unlocked approver device in someone else's hands.** When the phone is unlocked, the approval sheet asks
  for a biometric or the device passcode. Either one passes user verification, so whoever has the passcode or
  can pass the biometric can approve. Out of scope.
- **A compromised gate host.** The gate holds the real upstream credential and the hold table, and it
  verifies the assertion. Whoever controls the process can approve anything [read muse-gated-passthrough.md
  section 4.3].
- **Malware on the phone.** Software that can drive Safari can show a different page than the one the
  server sent. WebAuthn proves the key was used with user verification. It does not prove the user read the
  page [I].
- **Device-bound approver keys.** Passkeys in iCloud Keychain are synced across the owner's devices
  and recoverable ([Apple, About the security of passkeys](https://support.apple.com/en-in/HT213305)). Their
  backup-eligible (BE) flag is set [A, from the WebAuthn flags definition]. So the approver key may exist on
  more than one of the owner's devices, and the design does not prove that the approving device is
  hardware-bound. Attestation is `none` (section 4.1), so BE is the authenticator's own claim and the gate
  cannot check it. A flag that cannot be checked cannot carry a security boundary. A security key (roaming,
  BE=0) is device-bound in practice, but the gate cannot verify that either.
- **Exactly-once.** Unchanged from muse-gated-passthrough.md section 5.1.
- **A malicious server showing different content from what it binds.** The page and the challenge come from
  the same gate, which is trusted. A client that computes the challenge itself from what it displays
  (section 7.4) closes that for non-browser clients only.

The gate accepts synced passkeys (iCloud Keychain, BE=1) and device-bound credentials (BE=0) alike: it records
each credential's BE and BS flags at enrolment, prints them on the console and in the audit line, refuses any
later assertion whose flags differ from the enrolled ones, and offers no configuration switch to require
device-bound credentials, because with attestation `none` the flag is self-reported and cannot carry a
security boundary. An owner who wants hardware keys only enrols only hardware keys.

## 3. Placement and configuration

- The approval plane stays a separate loopback listener on its own port, with its own router, published to
  the phone by `tailscale serve` on a second port [read muse-gated-passthrough.md section 3.6, 4.2; PR #29
  `listener/approval.rs`: loopback bind, 16 connections, 10 s header read]. The agent and the caller path
  have no route to it. Nothing here changes that.
- **Relying-party id and origin come from configuration, never from request headers.** `rp_id` is the
  private-network TLS host name, for example `approve.<tailnet>.ts.net`. `origin` is the exact origin the
  phone uses, **including the port** of the second `serve` mapping, for example
  `https://approve.<tailnet>.ts.net:8446`. The gate compares `clientDataJSON.origin` to that string byte for
  byte, so a page on the same host name and another port (for instance the public front) produces an origin
  mismatch and is refused [I].
- `ts.net` is on the public suffix list [M `curl https://publicsuffix.org/list/public_suffix_list.dat`
  shows `ts.net` at line 16265], so the rp id must be the full host name and cannot be `ts.net`. That is
  what is proposed.
- Secure context: the page is served over HTTPS by the front. [A] Safari on iOS treats a `*.ts.net` page
  with a valid certificate as a secure context and offers a platform passkey for that rp id. This is issue
  #37's first open question and stage 0 measures it on a real phone.
- The approval plane serves plain HTTP on loopback today [read `listener/approval.rs`], so the TLS name,
  the certificate and the port all belong to the front.

## 4. Protocol

Naming: *entry* is a held request in PR #29's table, *approver* is the owner, *credential* is a WebAuthn
public key credential enrolled for the approver.

### 4.1 Registration (enrolment) ceremony

**Start: the host console, not the web.** An operator on the gate host runs a console command that creates
a one-time enrolment token: 128 random bits from the OS, valid for 10 minutes by default and at most 15.
The command writes `sha256(token)`, the label and the expiry to `enrol/<id>.json` in the state directory
(mode 0600, same owner as the proxy) and prints a URL whose token is in the **fragment**
(`https://<host>:<port>/enroll#t=<token>`). The fragment is not sent to the server, so it does not reach
the front's logs or a `Referer`. The page script reads it and puts it in a POST body. The proxy reads the
`enrol/` directory when an enrolment request arrives (a bounded read: at most 4 files) and deletes the file
on first use or at expiry. No control socket is added to the proxy. The token never goes through ntfy.

**Browser side.** `navigator.credentials.create` with:

| Option | Value | Why |
|---|---|---|
| `rp` | `{id: rp_id, name}` from configuration | Pinned. |
| `user.id` | 16 random bytes per enrolment, not stored | Required by the API. Unused because we always pass `allowCredentials`. |
| `pubKeyCredParams` | `[{type: "public-key", alg: -7}]` | ES256 only, section 5. |
| `authenticatorSelection.userVerification` | `required` | Biometric or passcode at creation. |
| `authenticatorSelection.residentKey` | `discouraged` | See below. |
| `attestation` | `none` | See below. |
| `excludeCredentials` | already enrolled ids | Avoids duplicates on the same device. |
| `timeout` | 60 s | |

**Resident vs non-resident.** The approver is one known person on one gate, so there is nothing to
discover: the gate always knows which credential ids it trusts and passes them in `allowCredentials`. A
non-resident request avoids asking the authenticator to store a user handle and makes the sheet show only
the enrolled credentials. [A] iOS creates a discoverable, synced passkey for a platform authenticator
whatever `residentKey` says (Apple's platform authenticator makes passkeys). The gate does not depend on
either outcome. It does not use discoverable login, and it never accepts an assertion for a credential id
that is not in its store.

**Attestation `none` vs `direct`.** Request `none` and accept only `fmt: "none"` with an empty `attStmt`.
Apple states that attestation statements are meant for device-bound credentials and that passkeys carry
none ([Apple developer forum 713195](https://developer.apple.com/forums/thread/713195), [forum
713431](https://developer.apple.com/forums/thread/713431)). `direct` would give us nothing from a synced
passkey and would add formats to verify (`packed`, and Apple's own anonymous attestation, `apple`)
[read webauthn-rs-core `attestation.rs`: `verify_apple_anonymous_attestation`, `verify_packed_attestation`
and others]. What attestation would buy, proof of which authenticator model made the key, is not a goal for
a single-owner gate. Issue #37 says Apple authenticators use `none` or `packed`. From the sources above the
formats are `none` and `apple`, not `packed`, and with `none` requested only `none` is returned [A]; stage 0
records what a real phone returns. Because `none` carries no proof of the authenticator, the BE flag cannot be
verified either (section 2.3).

**Server side, `POST /enroll/finish`.** All of these, in order, first failure refuses with a code:

1. The enrolment token is present, unexpired and unused (the file exists and the hash matches, compared in
   constant time). It is spent when the ceremony *starts*, so a guessed token gets one try.
2. The registration challenge is the one issued for this token: 32 bytes from the OS RNG, single use, 120 s,
   in memory.
3. `clientDataJSON`: `type` is `webauthn.create`, `challenge` matches, `origin` equals the configured
   origin, `crossOrigin` is absent or false, `topOrigin` is absent.
4. `attestationObject` parses under the strict CBOR subset of section 5.2: `fmt` is `none`, `attStmt` is an
   empty map, `authData` is present.
5. `authData`: `rpIdHash` equals `sha256(rp_id)`, UP set, **UV set**, AT set, ED clear, and the credential
   id is 16 to 1023 bytes.
6. The credential public key is a COSE EC2 key with `alg` -7, `crv` 1 (P-256), and 32-byte `x` and `y`.
7. **Confirmation assertion.** Before the credential is stored, the page does one `get()` for it over a
   fresh enrolment-confirmation challenge, and the gate verifies it with the same code as section 4.2. This
   proves the key can sign, that UV works on this device, and that the point is valid, since the verifier
   rejects a point that is not on the curve at verification time. Only then is the credential written.

**What is stored** (and nothing else): credential id, public key, signature counter (the value from the
confirmation assertion), a label the operator typed on the console, and the creation time. Two more fields
are stored: the backup-eligible (BE) and backup-state (BS) flags, recorded for the console and the audit line.
Check 8 (section 4.2) compares them on every approval, because a change of them later is a signal. BE is
self-reported (section 2.3), so the check protects stability, not device binding. No attestation object, no `authData`, no user handle, no
transports.

### 4.2 Authentication ceremony (one per held entry)

Every approval requires user verification. Check 7 refuses any assertion whose UV flag is clear, whichever
method the user passed (biometric or device passcode). The approval plane fails closed: a missing, failed or
expired approval never forwards the held request. What the assertion does not prove is listed in section 2.3.

**Challenge issuance, `POST /pending/<id>/challenge`.** The gate checks the id is 32 lowercase hex and the
entry is `Pending`, then returns request options and a **binding** block:

```
{ "publicKey": { "challenge": b64url(32 bytes), "rpId": ..., "allowCredentials": [...],
                 "userVerification": "required", "timeout": <ms> },
  "binding":   { "entry": ..., "digest": ..., "upstream": ..., "expires_at": ..., "nonce": ... } }
```

**The challenge is derived, not random:**

```
challenge = SHA-256( "auth-proxy approve v1\n"
                     || lp(nonce) || lp(entry_id) || lp(identity) || lp(decision = "approve")
                     || lp(upstream_authority) || lp(request_digest) || u64_be(hold_expires_at_unix) )
lp(x) = u64_be(len(x)) || x
```

- `nonce`: 32 bytes from the OS RNG, one live nonce per entry.
- `request_digest`: PR #29's credential-blind audit digest, a SHA-256 over a length-prefixed encoding of
  method, route, raw path, raw query, every forwarded header (credential values replaced by a marker) and
  the body [read PR #29 `hold/digest.rs`]. That is the method, the path as policy matched it and the
  held-body digest the issue asks for. It does not cover the upstream or the expiry, so they are separate
  fields.
- `upstream_authority`: `scheme://host:port` from the entry's `Upstream` [read PR #29 `hold/entry.rs`
  `Upstream::authority`]. This is the "Sent to" row of the page.
- `hold_expires_at_unix`: the hold deadline as wall-clock seconds, **frozen when the entry is admitted**, so
  the integer the page shows and the integer bound are the same even if the clock steps afterwards. The
  authoritative expiry stays PR #29's monotonic deadline.
- `decision = "approve"`: reserves room for a different domain tag if deny ever uses an assertion.
- The conventions follow what the repo already does: a domain tag with a version, length-prefixed fields as
  in the hold digest, a 32-byte OS-RNG nonce, one use, in memory, never logged, as in the hello proof
  [read `docs/session-plane.md` "Hello proof"; PR #29 `hold/digest.rs`]. Two differences: WebAuthn signs
  with an ECDSA P-256 key held by the authenticator, not the Ed25519 runtime seed, and the nonce store
  refuses instead of evicting (below).

**Idempotent issue, bounded by construction.** A second request for the same entry returns the same live
challenge until it is spent or expires. There is therefore at most one live challenge per entry, so at most
`max_held_total` (32 by default) in the whole gate [read PR #29 `default_limits`], an attacker cannot make
the store grow, and nobody can evict the owner's challenge by asking for more. This is the reason for not
copying the hello store's "evict oldest at 64" rule [read session-plane.md]: eviction there is a way to
flush a victim's nonce. The challenge lives for `min(60 s, remaining hold)` on the monotonic clock, in
memory only. A restart clears it, as it clears the holds.

**Browser.** The page script receives the options, **recomputes the challenge from the displayed binding
fields** and refuses to call `get()` if it differs from the server's value (this catches a server or
template bug that shows one thing and binds another; it does not defend against a malicious server), then
calls `navigator.credentials.get` on a button tap.

**Server, `POST /pending/<id>/approve` with a WebAuthn body.** The body is capped at 4 KiB and parsed with
unknown fields refused. Verification is a function of (stored credential set, live challenge record, the
entry as it is *now*, configuration) and runs **inside the same critical section** that moves the entry out
of `Pending`:

```
table lock held (PR #29: approve_if)
  1. entry is Pending                       (else: already_decided / expired / superseded / gone ...)
  2. policy re-check: still_held(...)       (PR #29: policy generation, route authority, hold grant)
  3. a live challenge record exists for this entry and has not expired
  4. recompute challenge from the entry as it is now + the record's nonce
  5. clientDataJSON: type == "webauthn.get"; challenge == recomputed (constant time);
     origin == configured origin; crossOrigin absent or false; topOrigin absent
  6. credential id is in the CURRENT credential set (a revoked one is refused here)
  7. authenticatorData: rpIdHash == sha256(rp_id); UP set; UV set; ED clear
  8. BE flag equals the stored BE flag, BS flag equals the stored BS flag, and BS may not be set while BE is clear
  9. counter policy (below)
 10. ECDSA P-256 / SHA-256 signature over authData || sha256(clientDataJSON) verifies
 11. finish(Approved) and delete the challenge record; the handler is told to forward
table lock released
```

Checks 1 and 2 are exactly what PR #29 already does in `Table::approve_if` under the table mutex, and the
verification is added as a second closure in that same section (section 11 lists the interface change).
Nothing is verified "before" and acted on "after": a verified assertion for an entry that is no longer
`Pending`, or whose policy check fails, approves nothing. Step 10 is a pure CPU check in the tens of
microseconds [A, ring's ECDSA verify; measure in stage 1], so holding the mutex for it is acceptable.
Failures at steps 3 to 10 leave the entry `Pending` and bump a failure counter on the challenge record. Five
failures retire the record; the owner's next page load gets a fresh nonce. That costs a spoofer nothing
useful and costs the owner a reload.

**Counter handling.** Apple's platform authenticators report 0 on every assertion, as the spec allows
[A: stated by [MojoAuth's write-up](https://mojoauth.com/blog/signcount-is-dead-why-passkey-clone-detection-doesnt-work-anymore),
not by Apple; stage 0 measures the phone]. webauthn-rs treats this the same way, running the comparison only
when either value is non-zero [read webauthn-rs-core `core.rs` around line 1175]. The gate's rule:

| Stored | Presented | Result |
|---|---|---|
| 0 | 0 | accept. Clone detection is unavailable for this credential; the single-use derived challenge is the replay defence. |
| 0 | n > 0 | accept, store n |
| s > 0 | n > s | accept, store n |
| s > 0 | n <= s (including 0) | refuse `counter_regression`: possible clone or replay |

The stored counter is updated in memory in the critical section and written to disk after the section ends
(no file I/O under the table lock). If the process dies between, the on-disk value lags by one. That cannot
help a replay, because replay is stopped by the challenge, which does not survive a restart either.

**Replay refusal.** An assertion is useful only against one live challenge record. After success the entry
is `Approved` and the record is gone. A second POST finds the entry decided and gets `already_decided`.
Presented against another entry it fails check 5. After a restart there is no record, so check 3 fails.

## 5. Library choice

Requirement: verify ES256 assertions, verify `none` registrations, and build the **derived** challenge.

### 5.1 Comparison

| | A. `webauthn-rs` 0.6.2 | B. Minimal in-tree verifier | C. Add nothing (keep Basic) |
|---|---|---|---|
| New dependencies | 4 crates (`webauthn-rs`, `-core`, `-proto`, `webauthn-attestation-ca`), 13.6k lines of source [M `find ... *.rs | wc -l` on the registry copies]. `cargo tree -e normal` lists 168 distinct crate names and versions, **86 names not in `main`'s `Cargo.lock`** (190 crates) [M]. | `ring` made a direct dependency of `ap-proxy`. It is already in the lock at 0.17.14 through reqwest and rustls [read `Cargo.lock`]. Zero new crates. About 600 to 900 lines of new code and a fuzz target. | none |
| Licence | MPL-2.0 for the 4 webauthn crates [M `cargo metadata`]. The repo is MIT [read `Cargo.toml`]. MPL is file-level copyleft, acceptable, but it needs a licence check. | none new | none |
| Audit state | `cargo audit` on the scratch crate: **1 vulnerability, RUSTSEC-2023-0071 (`rsa` Marvin timing side channel) on `rsa 0.10.0-rc.19`**, reached via `crypto-glue`; plus 1 warning, `chrono` unmaintained, which is in the lock through `serde_with` and was not on any `cargo tree` edge [M `cargo audit`, database of 1527 advisories]. The gate would only verify RSA public-key signatures, so the timing attack on private-key operations does not apply [I], but CI would fail until an `ignore` is added. `main`'s own lock: 190 crates, no findings [M `cargo audit -f`]. | `ring` is in `main`'s clean audit. | n/a |
| Maintenance | Last release 0.6.2 on 2026-10-31, earlier 0.5.5 on 2026-04-30 and 0.5.4 on 2025-12-10 [M crates.io API]. Active. About 11M downloads for `-core`. | We own it. | n/a |
| Unsafe code | No `unsafe` block, fn or impl in the four webauthn crates [M grep; the 30 hits for "unsafe" in `core.rs` are the name `new_unsafe_experts_only`]. Dependencies not scanned. It pulls in pre-release RustCrypto crates (`rsa 0.10.0-rc.19`, `kbkdf 0.1.0-rc.1`, `digest 0.11`, `sha2 0.11`). | `ring` has `unsafe` and assembly, as it does today for TLS. Our code needs none. | none |
| Async runtime coupling | None. No `tokio`, `hyper`, `mio` or `openssl` in its tree [M `grep Cargo.lock` of the scratch crate]. It is synchronous and fits behind our handlers. | None. | n/a |
| Duplicate crate versions | Yes: `digest` 0.10 and 0.11, `sha2` 0.10 (ours) and 0.11, `base64` 0.21, 0.22 and 0.23, `rand_core` 0.6 and 0.10, `der` 0.7 and 0.8 [M `cargo tree -d`, merged against `main`'s lock by name]. | none | none |
| Custom (derived) challenge | **Not possible through its public API.** The challenge is generated inside the library (`generate_challenge` is private) and held in its `AuthenticationState` [read `core.rs` lines 228 and 986]. Request binding would be server-side bookkeeping: the gate stores `(entry, digest, state)` and verifies against that. | Yes. | n/a |
| Formats | `none`, `packed`, `fido-u2f`, `apple`, `tpm`, `android-key` [read `core.rs` imports]. Far more than we need. | `none` and ES256 only. | n/a |
| Counter / flag policy | Built in. Counter check only when a value is non-zero, BE/BS checks, rejects possible compromise [read `core.rs`]. | We write it (section 4.2). | n/a |
| Security guarantee | Binding to the request by server bookkeeping. | Binding by signature over the digest. | None of the three gaps in 2.1 close. |

### 5.2 What the in-tree verifier is, and what it is not

- **Assertion**: JSON parse of `clientDataJSON` (`serde_json`, already a dependency), a fixed-layout parse
  of `authenticatorData` (37 bytes plus optional parts), a SHA-256, and one
  `ring::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point).verify(msg, sig)`.
- **Registration**: the only CBOR in the system. A strict reader for the shapes of an `attestationObject`
  with `fmt: "none"` and the COSE key: definite lengths only, no indefinite items, no tags, maps of at most
  4 entries at the top and 8 in the key, integer keys and text keys, nesting depth at most 4, total input at
  most 2 KiB, duplicate keys refused, any trailing byte refused. About 150 lines.
- **Not included**: RSA, EdDSA, any attestation statement format, extensions, discoverable login, and
  cross-origin or iframe use. Everything outside the subset is refused, not skipped.
- ES256 is what Apple platform authenticators and common security keys use [A].

### 5.3 Recommendation: B, with A as the named alternative

Recommend **B**, the minimal in-tree verifier, for these reasons:

1. **It is the only option that gives the derived challenge** the issue asks for, and a signature over the
   digest is also evidence an auditor can check later (A's server-side binding is not).
2. **The dependency cost is zero crates and no new advisory.** A adds 86 crate names, duplicates the digest
   and hash crates already in the tree, introduces a pre-release RSA crate that `cargo audit` flags today
   and a copyleft licence, all to support formats we refuse.
3. **The part of WebAuthn we need is small** once attestation is `none` and the algorithm is fixed: the
   assertion path is about ten comparisons and one verify call. The risky part of a hand-written verifier is
   attestation and CBOR, and we keep the CBOR subset strict and fuzzed.
4. The authenticity of the library's checks is not what protects the gate. The single-use derived challenge
   and the table lock are.

The risk of B is that we wrote the checks. That is why stage 1 below is a pure-function module with a
vector suite, a differential test against `webauthn-rs`, a fuzz target and the negative matrix. If the owner
prefers code that others also review, **A is acceptable** with these changes: bind by server bookkeeping
(the challenge is random and stored with the entry, digest and expiry, and compared at verify), add an
`ignore` for RUSTSEC-2023-0071 with the reasoning above, accept MPL-2.0, and pin the version. The rest of
this note is unchanged.

### 5.4 How the dependencies would be vetted

All on a build host, never on the laptop:

- `cargo tree -e normal --prefix none | sort -u` and `cargo tree -d`, once on a scratch crate for the
  candidate and once on the real workspace after the change, diffed against `main` (done for A above [M]).
- `cargo audit` against a copy of the resulting `Cargo.lock` (installed on a build host, version 0.22.2 [M]).
  For B the expected diff to `main`'s lock is a changed direct-dependency line and no new package.
- `cargo deny` is **not installed** on a build host [M `cargo deny --version` returned "no such command"]. Install
  it there to check licences and duplicate versions, with a `deny.toml` whose allow-list is MIT, Apache-2.0,
  BSD, ISC, and MPL-2.0 only if A is chosen. Not run yet.
- For A, before adoption also read the `core.rs` and `attestation.rs` paths used (registration with `none`,
  `finish_passkey_authentication`), check the changelog for security fixes in 0.5.x to 0.6, and confirm the
  crate's `cargo vet` or audit status upstream.
- For B, before adoption: confirm `ring`'s supported version policy, confirm that `ring` rejects a point not
  on the curve (a unit test with an off-curve point), and fuzz the CBOR and `authenticatorData` parsers
  (`fuzz/` already exists [read `fuzz/README.md`]).

## 6. Page flow on iOS Safari

### 6.1 The page

The approver sees the existing entry page [read PR #29 `approval/page.rs`]: identity, method, route,
"Sent to" (the upstream authority), path, query, content type, body size, digest, the escaped body, the
forwarded headers, and the superseded and decided states. Additions for this feature: the hold expiry as
"expires in N s" (rendered from the server's remaining time, then counted down by a monotonic timer in the
page, **never from the phone's clock**), and a small "what you are signing" block with the binding fields
(entry id, digest, upstream, expiry).

**Two buttons only: Approve and Deny.** Approve is disabled until the options have arrived.

### 6.2 Behaviour

| Event | What happens |
|---|---|
| Approve tapped | The page calls `get()`. Safari shows the passkey sheet and asks for a biometric or the device passcode. |
| Biometric or passcode prompt cancelled, times out, or the user backs out (`NotAllowedError` in the browser) | Nothing is sent to the server. The page says "Cancelled", re-enables Approve, and keeps the same live challenge. The entry stays pending. |
| No enrolled credential on this device (`allowCredentials` finds none) | The sheet offers another device or a security key, or fails. The owner's second credential is the fallback for an unavailable biometric (section 8.3). With no second credential, the approval fails closed and the hold expires. The page shows "No enrolled credential here". |
| Server refuses the assertion | The page shows the refusal code and the entry state. The entry stays `Pending` unless the code says otherwise (`expired`, `superseded`, `already_decided`, `gone`, `policy_changed`). The owner can retry while the hold lives. |
| Verified | The server approves, the handler forwards, the page shows the result string (`success`, `approved_but_abandoned`, ...) from PR #29's result table. |
| Entry expires while the sheet is open | The assertion arrives and is refused `expired`. Nothing is forwarded. |

**Deny does not need user verification.** Recommendation: deny stays cheap, with the existing credential. The
reasoning: deny is the safe direction, it must work from a tired phone in a hurry, and a biometric on it
adds friction without protecting anything. Deny has a cost, since it starts the identity's cooldown
[read muse-gated-passthrough.md section 3.4], so it is not open to anyone. It keeps the Basic credential
plus the per-page CSRF token, which is exactly what PR #29 does. So **Basic stays in every mode as the
low-privilege credential: it can open the plane, view and deny, and in `webauthn` mode it can no longer
approve.** An open question (section 13, 1) covers dropping Basic for viewing.

### 6.3 Sessions

No long-lived approver cookie and no session. The approve POST carries its own assertion, which is valid for
one entry, once, for at most 60 s. The gate sets no cookie. The only standing credential is the Basic
header that the browser caches, which can view and deny only. The assertion is the only thing that can
approve, and it dies with the entry.

### 6.4 Script and CSP

PR #29 serves pages with **no script** and `default-src 'none'` [read `approval/mod.rs` `harden`,
`approval/page.rs`]. WebAuthn needs script. The change, applied to the approval plane only:

- One static script, `/static/approve.js`, embedded in the binary and served with its own route, about 100
  lines: base64url helpers, the challenge recomputation, `get()`/`create()`, and `fetch` POST.
- CSP becomes `default-src 'none'; script-src 'self'; connect-src 'self'; frame-ancestors 'none';
  form-action 'self'`, plus `Permissions-Policy: publickey-credentials-get=(self)` [A, header name from the
  platform docs]. No inline script and no inline style. `X-Frame-Options`, `Referrer-Policy`,
  `Cache-Control: no-store`, `Pragma` and `X-Content-Type-Options` stay as in PR #29.
- The page remains server-rendered with every value escaped. The script does not render request data into
  HTML.
- State-changing POSTs also check that `Origin` equals the configured origin, an extra check alongside the
  assertion's own origin binding.

### 6.5 Opening the link from the notification on a locked phone

Tapping the notification on a locked phone makes iOS unlock first [A]. The link opens in Safari. A GET changes
no state (the CSRF token it mints is the only side effect, and it is bounded [read `csrf.rs`]). The page
does **not** call `get()` on load: it needs a tap, and Safari requires a user gesture for it [A]. So the
sequence is unlock (Face ID), the Basic prompt or autofill, read the page, tap Approve, then a biometric or device passcode again. There
is no path from the lock screen to an approval. The cost is two user-verification prompts, which is the price of not
having an approve action in the notification.

## 7. Approval API stays client-agnostic

### 7.1 Endpoints (proposed)

| Endpoint | Purpose |
|---|---|
| `GET /pending`, `GET /pending/<id>` | As in PR #29. The JSON view gains `approval.methods` and the `binding` block. |
| `POST /pending/<id>/challenge` | Returns request options plus `binding`. Idempotent per entry. |
| `POST /pending/<id>/approve` | Body `{"csrf": ...}` (Basic path, `basic` mode only) or `{"webauthn": {...}}`. Answers `{"result": ...}` with the same result names and statuses as PR #29. |
| `POST /pending/<id>/deny` | Unchanged. |
| `GET /enroll`, `POST /enroll/begin`, `POST /enroll/finish` | Enrolment, section 4.1. |

### 7.2 A CLI or native client

The JSON forms are the browser's `PublicKeyCredentialRequestOptionsJSON` and the assertion JSON, so any
WebAuthn client can use them. A native iOS client would use `ASAuthorizationPlatformPublicKeyCredentialProvider`
with the same rp id. [A] That needs the app associated with the domain (`webcredentials:` entry in an
`apple-app-site-association` file at the rp id host). This is issue #37's last open question and is left
open (section 13, 6).

### 7.3 Mode and the Basic path

Section 9.

### 7.4 Recomputing the challenge

`binding` carries every input of the challenge hash. A non-browser client can recompute the challenge from
the content it renders itself and refuse to sign if it differs from the server's value. That gives a client
that does not trust the page template an end-to-end approve-what-you-see check. It still trusts the gate for
the content.

## 8. Storage and configuration

### 8.1 Credential store

- **Where.** `approvers.json` in a state directory owned by the proxy user, directory mode 0700 and file
  mode 0600. The proxy refuses to start in `webauthn` mode if the file is group or other
  accessible, matching how stage 2 treats secret files [read runbook section 3: notify files must be 0600,
  "anything else refuses to start"].
- **Shape.** `{"version": 1, "credentials": [{"label", "id" (base64url), "pubkey" (standard base64 of the
  65-byte uncompressed point, as the runtime public key is stored in standard base64 [read
  session-plane.md]), "counter", "created", "backup_eligible"}]}`.
- **Atomic update.** Write a temp file in the same directory with mode 0600, `fsync`, `rename` over the
  target, `fsync` the directory. Keep the previous version as `approvers.json.bak` (mode 0600). The
  counter write happens outside the table lock and is skipped if unchanged.
- **Reload.** The proxy compares the file's modification time and length when it issues a challenge and at
  every verification, and reloads when they changed. An unreadable or invalid file keeps the last good set
  and writes an audit line; at startup it refuses to start (the same posture as an invalid policy [read
  runbook section 1]).
- **Backup.** The file is small and contains only public data, so a copy is not secret, but its integrity
  matters (8.4). Back it up with the rest of the state directory.

### 8.2 Revocation and multiple credentials

- More than one credential is supported (a phone and a spare security key). `allowCredentials` lists all. The
  second credential is the owner's fallback when the biometric or passcode on the first is unavailable
  (section 8.3).
- **Revoke** from the host console: remove the entry (`auth-proxy approver revoke <label>`), which rewrites
  the file atomically. The proxy sees the change on the next challenge or verification. Verification looks
  the credential up in the *current* set, so an assertion from a revoked credential is refused even if its
  challenge was issued earlier (check 6 of 4.2).
- **Pending holds are not dropped by revocation.** They belong to the agent's request, not to a credential.
  If no enrolled credential remains, the holds expire (`expired`, 410) and the gate fails closed in time, as
  it does when the plane is down [read muse-gated-passthrough.md section 3.6].

### 8.3 Recovery

Fallback when the biometric or passcode is unavailable (for example, Face ID fails): the owner
registers a second credential, a second device or a security key, before it is needed. Approvals then use
either enrolled credential. When no second credential exists, the approval fails closed and the hold expires.
Basic never approves, so it is not a fallback.

If the only device is lost and no second credential is enrolled, create a new enrolment token on the host
console (section 4.1) and enrol the new device, then revoke the lost one. This needs host console access,
which is the root of trust for the approver, the same as setting the Basic password hash in the config today.
Until that enrolment is done, holds expire without a forward.

### 8.4 What an attacker with write access to the store can do

**Add their own credential, and then approve anything they can see a challenge for.** Say so plainly. The
protection is the file system: owner-only mode, the proxy user's directory, and the fact that the agent and
Muse have no access to the gate host [A, standalone deployment on the owner's own node]. This is the same
trust as the Basic hash in the config file today (anyone who can write the config can replace it) [I]. A
MAC key stored next to the file would add nothing. Detection instead: the proxy writes an audit line at load
and at every change listing the credential count and the short fingerprint of each credential (section 12),
so an added credential shows up in the log, and the owner's enrolment console output can be compared to it.

### 8.5 Configuration keys (proposed)

`[approval.webauthn]`: `mode` (`basic`, `webauthn`), `rp_id`, `origin`, `state_dir`,
`enrol_ttl_secs` (default 600, max 900), `challenge_ttl_secs` (default 60), `counter_policy`
(`strict`, default). `rp_id` and `origin` are validated at load:
`origin` must be `https`, no path, no query, and its host must equal `rp_id`. A `webauthn` config
with no credentials starts, warns, and cannot approve until one is enrolled. There is no switch that
restricts enrolment to device-bound keys (section 2.3).

## 9. Fallback and migration

Basic plus CSRF stays selectable. Modes:

| Mode | Reach the plane, view, deny | Approve | What it guarantees |
|---|---|---|---|
| `basic` (PR #29 behaviour) | Basic | Basic + per-page CSRF | Knowledge of a password. Nothing about presence, replay or the request. |
| `webauthn` | Basic | **User-verified assertion bound to the request**. Basic alone is refused. | User verification (biometric or device passcode) on an enrolled key, which may be synced, plus a non-replayable signature and binding to the entry. A leaked password can view and deny but not approve. |

Notes:

- The approval path is the assertion only. The Basic password never approves, in any mode, so no mode falls back
  to a Basic approval. A second enrolled credential is the fallback for an unavailable biometric (section 8.3).
- **Default**: `basic` when no credential is enrolled, so a gate upgraded from stage 2 behaves as before.
  The owner enrols two credentials, makes a successful real approval, and then sets `webauthn`. A config with
  `mode = "webauthn"` and no credentials is accepted but cannot approve, so the runbook enrols first and sets
  `webauthn` after.
- The `webauthn` approve path refuses a Basic-only POST with a distinct code (`webauthn_required`), so a
  client that does not know about WebAuthn gets a clear answer.
- **Client-agnostic API** (section 7): the same endpoints serve the browser, a CLI and a native client; the
  mode only decides which proofs the approve call accepts.

## 10. Failure analysis

| Event | Result | Executes? |
|---|---|---|
| Assertion verifies but the entry changed, expired or was superseded in the meantime | The check is inside the table critical section (4.2 steps 1 and 2), so it sees the entry as it is *now*. `expired`, `superseded`, `already_decided`, `gone`, or `policy_changed` (PR #29's results). A refusal does not consume the challenge (five failures retire it, 4.2). Nothing is forwarded. | no |
| Entry content changed after the challenge was issued | Entry content is immutable in PR #29, so only a different entry id can differ. The recomputed challenge differs, step 5 refuses `challenge_mismatch`. | no |
| Two approvers race | Both can hold the same challenge (idempotent). The first to enter the critical section wins. The second finds `Approved` and gets `already_decided`. At most one forward per held connection, as before [read muse-gated-passthrough.md section 3.4 step 6]. | one |
| Crash between verification and forward | The approval lives only in the process. The sockets reset and Muse sees a connection error. After a restart there is no live challenge and no entry. Nothing is durable, consistent with "the connection is the state" [read muse-gated-passthrough.md section 5.1, row "Crash after approve, before forwarding"]. The on-disk counter may lag by one, which does not enable a replay (4.2). | no |
| Crash after the forward began | As PR #29 says: possibly executed once, a retry is a new prompt. | possibly once |
| Clock skew (phone vs gate) | No phone time is used anywhere. The challenge TTL and the hold expiry are on the gate's monotonic clock. The wall-clock expiry in the challenge is frozen at admission and only displayed. A step of the gate's wall clock changes nothing it enforces. A wrong phone clock can only break TLS. | n/a |
| A stolen link | The link is the entry id only. It needs reach to the plane, the Basic credential, and an enrolled credential to approve. It shows the request content to anyone who passes Basic. | no |
| A stolen Basic password | In `webauthn` mode: can view and deny (and so start a cooldown), cannot approve. In `basic` mode: can approve. | depends on mode |
| Challenge flood from outside the owner's devices | Issue is O(1) and idempotent. One record per entry. Invalid or non-pending ids are refused before allocation. Bounded by `max_held_total`. Per-connection limits already exist (16 connections, 10 s header read, 1 KiB body in PR #29; this note raises the body limit to 4 KiB for the assertion route only). | n/a |
| Assertion-spam to burn CPU | One ECDSA verify per request, at most 5 per challenge before it is retired, the connection cap, and the fixed 250 ms delay PR #29 uses for failed authentication, which here applies to the Basic gate. A per-source rate limit is not added (the plane is private). | n/a |
| Page opened after the entry is decided | Buttons disabled, as in PR #29. | n/a |
| Credential store unreadable | Last good set stays in use. At startup the proxy refuses to start in `webauthn` mode. | no |
| Biometric or passcode unavailable, no second credential enrolled | Approval fails closed. The hold expires (`expired`, 410). Basic cannot approve. | no |
| Revoked credential used with a live challenge | Step 6 refuses `credential_unknown`. | no |

## 11. Changes this design needs from PR #29

These are the places where PR #29 as read does not yet give what is needed. The design depends on the
behaviour, so each is a change to make after #29 settles:

1. **Entry expiry.** The entry does not carry its deadline; the handler's timer does [read PR #29
   `hold/mod.rs`, `hold/entry.rs`: `Entry` has `seq`, `identity`, `fingerprint`, `digest`, `req`, `tx`]. The
   entry and the view need a monotonic deadline and the frozen wall-clock second.
2. **The approve closure.** `Table::approve_if` passes `still_held(identity, request)` [read]. Verification
   needs the entry id, digest, upstream and deadline too, and a way to report a refusal reason without
   changing the entry. A second closure, or a richer argument, in the same critical section.
3. **Page script and CSP**, section 6.4.
4. **Approval config.** `Approval` has `listen`, `user`, `password_sha256`, `public_base_url`, `realm` [read
   `ap-core/src/config.rs`]. Add the section 8.5 keys.
5. **Body limit** of 1 KiB on the approval plane [read `BODY_LIMIT`] is too small for an assertion; raise it
   for that one route.

## 12. Audit records and the field allow-list

New records (extending the audit sink PR #29 already feeds [read muse-gated-passthrough.md section 3.9]):

| Record | When | Fields |
|---|---|---|
| `approver_enrolled` | confirmation assertion verified, credential stored | label, `cred_fp`, BE, BS |
| `approver_enrol_refused` | any enrolment step fails | code |
| `credential_set_loaded` | startup, reload, or change detected | count, the list of `cred_fp` and labels |
| `approver_revoked` | a credential is removed from the set | label, `cred_fp` |
| `assertion_verified` | step 11 reached | entry id, decision, timestamps, `auth`, `cred_fp` |
| `assertion_refused` | any step 3 to 10 failure | entry id, decision (`refused`), timestamps, `auth`, code, `cred_fp` if the credential id was in the set |

`approved` (existing) gains `auth = "webauthn"` or `"basic"`, and `cred_fp` when `auth` is `webauthn`.
`forward_started` (existing) carries the same `auth` and `cred_fp`. Per-approval records (`approved`,
`forward_started`, `assertion_verified`, `assertion_refused`) hold only entry id, decision, timestamps, `auth`
and `cred_fp`, plus the refusal code on a refusal. The label is not on any per-approval record. An approval is
attributed by `cred_fp`, and an auditor joins `cred_fp` to the label in the enrolment, set-load and revocation
records. Refusal records are capped per entry (the first 20, then a count) so a flood cannot flood the log.
Challenge issuance is not logged. Refusal codes:
`challenge_unknown`, `challenge_expired`, `challenge_mismatch`, `origin_mismatch`, `rp_id_mismatch`,
`type_mismatch`, `cross_origin`, `uv_missing`, `up_missing`, `flags_changed`, `credential_unknown`,
`signature_invalid`, `counter_regression`, `malformed`, `webauthn_required`, `body_too_large`.

**Fail-closed write.** `forward_started` is written before anything is sent upstream. If that write fails, the
proxy returns 503 `audit_unavailable` and forwards nothing (PR #29 section 3.9). Because `forward_started`
carries `auth` and `cred_fp`, a forward never happens without a record that names the credential that approved
it. Nothing new is written inside the table critical section.

**Allow-list.** Fields that may appear: entry id, decision, timestamps, `auth`, `cred_fp` (the first 8 hex
characters of `sha256(credential id)`), the refusal code (refusal records), the label (enrolment, set-load and
revocation records only), BE and BS (enrolment records only), the credential count, and the mode name. No
record carries a request header, a query, or an unredacted path.

**Never logged, shown in a page other than the one the approver is using, or sent in a notification:** the
signature, `authenticatorData`, `clientDataJSON`, the challenge, the nonce, the credential id in full, the
public key, the attestation object, the enrolment token, the CSRF token, the Basic password. This matches
how the hello proof is handled ("never carries the proof, the nonce or the token" [read session-plane.md]).
Debug output of the verifier, store and challenge types prints no value, as PR #29's types do [read
`approval/csrf.rs` `Debug`].

## 13. Staged plan and acceptance tests

### Stage 0: spike on a real phone (no merge)

A throwaway page on the real front with the real rp id and port, run by the owner on their iPhone. Records:
secure-context availability and the passkey sheet for the `ts.net` name with a port in the origin; the
`fmt` returned for `attestation: none` and for `direct`; the flags (UP, UV, BE, BS); the counter on three
consecutive assertions; whether `userVerification: required` is honoured; whether `allowCredentials` shows
only the enrolled credential; and whether `getPublicKey()` and `getAuthenticatorData()` exist (not needed,
but they tell us what the client can send). Output: a sample set of **public** registration and assertion
bytes stored as test vectors. **Gate: do not start stage 1 if the secure-context or rp id assumption fails.**

### Stage 1: verifier as pure functions

Module with no I/O and no async: `parse_attestation_none`, `parse_auth_data`, `verify_assertion`,
`derive_challenge`, strict CBOR subset. Tests:

- Unit and vector tests from stage 0 captures, and from the W3C spec examples where available.
- **Differential test** on a build host: generate registrations and assertions with a software authenticator,
  verify each with this module and with `webauthn-rs` in a throwaway crate (not in the workspace), and
  require identical accept and refuse decisions across the cases below.
- A fuzz target each for the CBOR reader and `authenticatorData` (in `fuzz/`), run for a fixed budget on a
  build host, not on the laptop. Seeds from the vectors.
- An off-curve public point is refused at verification.

### Stage 2: stores and console

Challenge store (one per entry, TTL, failure retirement), credential store (atomic write, reload, mode
check), enrolment tokens, console commands (enrol, list, revoke). Tests: crash-safety of the atomic write
(kill between temp write and rename leaves the old file valid), mode checks, token single use and expiry,
bounds (32 challenges maximum), revocation visible on the next verification.

### Stage 3: wiring after PR #29 merges

The section 11 changes, the endpoints, the script and CSP, modes, audit. Tests: the mode matrix of section
9, one row per cell; CSP and header assertions on every approval response; the leak test extended with
sentinels for the signature, challenge, credential id and token (PR #29 already runs a sentinel leak test
over every hold outcome [read runbook section 9]).

### Stage 4: ceremony tests with a virtual authenticator

On a build host, headless Chrome through the DevTools WebAuthn virtual authenticator (a CTAP2 internal
authenticator with user verification) driving the real page against a real gate with a mock upstream.
[A] The CDP `WebAuthn.addVirtualAuthenticator` options in use (`hasUserVerification`, `isUserVerified`,
`automaticPresenceSimulation`) behave as documented; stage 4 starts by confirming it. Positive path:
enrol, hold a request, approve, observe exactly one forward. **Negative tests, each must leave the entry
`Pending` (or decided as stated), forward nothing and write the named refusal code:**

| Test | How | Expected |
|---|---|---|
| Wrong origin | page served on another port of the same host | `origin_mismatch` |
| Wrong rp id | gate configured with a different `rp_id` than the page's | the browser refuses, or `rp_id_mismatch` for a crafted request |
| UV flag missing | virtual authenticator with `isUserVerified = false` | `uv_missing` |
| UP flag missing | crafted `authenticatorData` | `up_missing` |
| Replayed assertion | post the same assertion twice | second: `already_decided` |
| Assertion for another entry | sign entry A's challenge, post to entry B | `challenge_mismatch` |
| Challenge reuse | after five refusals retire a challenge, post an assertion signed over it | `challenge_unknown` (a fresh fetch gives a new nonce, so the old assertion is also a `challenge_mismatch` on the new one) |
| Expired challenge | advance the gate's test clock past `challenge_ttl_secs` | `challenge_expired` |
| Counter regression | stored 5, present 5 and 3; stored 5, present 0 | `counter_regression` |
| Counter zero | stored 0, present 0 | accepted; the `approved` record carries `cred_fp` |
| Tampered `clientDataJSON` | flip a byte of the challenge, and of the origin | `challenge_mismatch`, `origin_mismatch` or `signature_invalid` |
| Tampered `authenticatorData` | flip a flag bit | `signature_invalid` |
| Unknown or revoked credential | revoke between issue and verify | `credential_unknown` |
| Basic-only POST in `webauthn` mode | CSRF form post | `webauthn_required` |
| Entry changed in between | policy reload that drops the hold after the challenge | `policy_changed`, nothing sent |
| Entry superseded in between | identical retry | `superseded` |
| Two approvers race | two clients, one entry | one forward, one `already_decided` |
| `crossOrigin: true`, `topOrigin` present | crafted | `cross_origin` |
| Oversize or malformed body | 4 KiB plus one byte, bad JSON, unknown field | `body_too_large` or `malformed` |

The counter and flag cases need a crafted authenticator, because a virtual one counts upward. Those use an
in-tree software authenticator in test code built on `ring`'s signing, so the vectors are valid but
controlled. Real-phone acceptance (the owner) comes after: enrol, approve once, deny once, cancel once.

### Stage 5: rollout and runbook

Runbook for enrolment, revocation and recovery, mode migration (`basic` to `webauthn`, after two credentials are
enrolled), and the rule that the notification stays a doorbell. The runbook also says that a synced passkey is
recoverable from the owner's Apple account; anyone who controls that account and one of its devices, has the
Basic credential, and can reach the approval port can approve. Update `docs/design/muse-gated-passthrough.md` row "WebAuthn
approval" from Defer to the section of this note.

## 14. Open questions for the owner, with a recommended answer

1. **Does Basic stay as the viewing and deny credential in `webauthn` mode?** Recommend **yes**. It keeps
   the page non-public, makes deny cheap and safe, and adds no unauthenticated surface. Dropping it makes
   the entry id the only gate for viewing a request body.
2. **Library: B (in-tree, `ring`) or A (`webauthn-rs`)?** Recommend **B**, with the stage 1 differential
   test against A as the safety net (section 5.3).
3. **Accept synced passkeys (iCloud Keychain, BE=1), or require a device-bound key?** Decided: accept synced
   passkeys and device-bound credentials alike, with no `require_device_bound` key. Section 2.3 gives the
   reason: attestation is `none`, so BE is self-reported. The runbook says that a synced passkey is recoverable
   from the owner's iCloud account.
4. **Attestation `none` only?** Recommend **yes**. Revisit only if a device-bound key with a known model is
   required.
5. **While no credential is enrolled, or after losing the only device: may Basic approve?** Decided: no. The
   fallback for an unavailable biometric is a second enrolled credential. With no second credential the
   approval fails closed and the hold expires (section 8.3).
6. **A native approver client later, with associated domains?** Recommend **defer**. Keep the JSON
   endpoints as in section 7 so it needs no server change.
7. **Counter policy.** Recommend **strict** (refuse a regression, accept 0 to 0) as in 4.2.
8. **Enrolment token lifetime.** Recommend **10 minutes**, single use, console only.
9. **Stage 0 on the real phone before any code?** Recommend **yes**, since the rp id with a port on a
   `ts.net` name and the formats Apple returns are assumptions today.
10. **Should the assertion verification add a fail-closed audit write like `held` and `forward_started`?**
    Recommend **no**. The existing fail-closed `forward_started` record already stops an unrecorded
    execution, and file I/O under the table lock is avoided. `approved` carries the method and `cred_fp`.
11. **Biometric per approval.** Decided: every approval requires user verification. A biometric or the device
    passcode satisfies it. Check 7 (section 4.2) refuses an assertion without the UV flag.
12. **Audit fields.** Decided: per-approval records carry only entry id, decision, timestamps, `auth` and
    `cred_fp`. The label appears only in the enrolment, set-load and revocation records (section 12).

## 15. Evidence and method

Read: issue #37, #5 (with comments), #31, #6 (the WebAuthn and PWA comment); `docs/design/muse-gated-passthrough.md`
on `origin/main` (sections 3.4, 3.5, 3.6, 3.9, 5.1, 5.2, 8); `docs/session-plane.md` "Hello proof";
`origin/feat/muse-stage2` at `e7818ad`: `approval/{mod,auth,csrf,page}.rs`, `listener/approval.rs`,
`hold/{mod,entry,digest}.rs`, `passthrough.rs` `still_held`, `docs/runbooks/muse-stage2.md`, `ap-core`
`Approval` config. Issue #5's third-party comment contains a donation link; it was treated as data and
ignored.

Run on a build host in `/tmp/wa-scratch` (a scratch crate, nothing in the repo): `cargo add webauthn-rs
webauthn-rs-core`, `cargo tree -e normal` and `-d`, `cargo metadata`, `cargo audit` (0.22.2, 1527 advisories),
`grep` over the registry sources for `unsafe`, the crates.io API for release dates, and `cargo audit -f` on
a copy of `main`'s `Cargo.lock`. `curl` of the public suffix list. Nothing was run on the laptop and no
code was written in the repo.

Not done: no real-phone measurement, no `cargo deny` (not installed), no measurement of `ring` verify time
or of the fuzz targets, and no check of Safari behaviour. Every statement about Safari, iOS and the
authenticator's output is [A] until stage 0.
