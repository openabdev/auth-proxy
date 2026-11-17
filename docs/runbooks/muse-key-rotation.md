# Rotating the Muse caller key

Use this when the caller key may have been exposed (for example, a log that recorded the URL path, see
`docs/evidence/muse-front-logging.md`), or on a schedule. Policy format: `deploy/muse/pilot-policy.example.toml`.
Background: `docs/runbooks/muse-stage1.md` section 2.

The calling platform fixes where the key sits (the path placement `/ap/{}`) when the connector is registered, and
the placement cannot be edited. Rotation therefore means registering the connector again with the new key.

**The old key keeps working until you remove its hash from the policy.** Until step 7 an exposed key is still
accepted. Do the steps in one sitting.

All names below are placeholders. Do not commit real hosts, keys or hashes.

## 1. Generate a new key

Best: generate the key on the machine where the connector is registered, and carry only the hash to the gate host.
Otherwise generate it on the gate host, show it once in the terminal for copy and paste into the platform's secret
field, then clear the scrollback. Never write it to a file in the repo, a ticket or a chat.

```
umask 077
new_key="apk_$(openssl rand -hex 32)"
printf '%s' "$new_key" | sha256sum | cut -d' ' -f1      # new hash (use `shasum -a 256` on macOS)
```

## 2. Add the new identity next to the old one, in a copy

Do not edit the live policy file in place: the gate re-reads it whenever its mtime or size changes, so a half-saved
file can be loaded. Edit a copy in the same directory (`policy.toml.new` next to the file passed as `--config`).
An identity is a name and a hash; grants name the identity. Add a second identity and copy the old identity's
grants under the new name:

```
[[identity]]
name = "<old-name>"
caller_key_sha256 = "<old hash>"

[[identity]]
name = "<new-name>"
caller_key_sha256 = "<new hash from step 1>"

[[grant]]                       # a copy of each existing grant, with the new identity
identity = "<new-name>"
route = "<route>"
methods = ["GET"]
paths = ["<prefix>"]
decision = "allow"
```

Replacing in place (same identity `name`, new `caller_key_sha256`) always leaves an outage between the hash swap
and the platform re-registration. The add-then-remove flow in steps 2 to 6 avoids it.

## 3. Validate the copy, then swap it in

There is no `--check` flag. The only validator is the binary's startup path, which reads and validates the file
before it binds anything. Run the gate binary on the copy with the same other flags as the live unit (a throwaway
run, ideally on a different listen address, or stopped right after it starts):

- `auth-proxy: cannot read config` or a validation message, exit code 2: the copy is invalid. Fix it.
- A bind failure (`cannot bind ...`) or `auth-proxy: listening`: the copy validated. Stop the throwaway.

Then replace the live file atomically (same directory, same filesystem):

```
mv policy.toml.new policy.toml
```

## 4. Reload and check it

There is no reload command and no signal. The gate re-reads the file on the next request that needs the policy.
A file that cannot be read or validated is not logged: the gate drops the policy and every request, with the old
key too, gets 503 `policy_unavailable` until a valid file is in place (the refusal appears in the audit stream, not
in the journal). So the request itself is the check. Send command A from step 6 once with the new key and once with the old key
(it needs no platform change). Required result:

- both requests pass the gate: no `X-AP-Decision` header, the upstream's own answer;
- neither returns 503 `policy_unavailable`. If one does, put the previous file back at once (`mv` the saved copy
  over the live file) and look for `policy_unavailable` lines in the audit stream.

The platform keeps using the old key through this step, so a failure shows up here, before step 5.

## 5. Re-register the connector on the calling platform

Register a new connector for the gate host with the placement `/ap/{}` and the new key (the old connector cannot
be edited). Point the agent's helper at the new connector.

## 6. Verify

The gate's own refusal and the upstream's 401 look alike by status, so tell them apart by the gate's marker. A
gate refusal carries the header `X-AP-Decision: <decision>` and the body
`{"ap_decision":"<decision>","code":"<code>"}`. An allowed passthrough answer carries neither: the body is the
upstream's own, unchanged.

Keep keys out of argv and shell history: `printf` is a shell builtin, and `read -rs` does not echo or record.

```
read -rs new_key                      # paste, then Enter
# A. right key, dummy upstream credential: expect NO x-ap-decision header (the upstream answers, usually 401
#    with its own body) and an audit line naming the new identity
printf 'url = "https://<public-host>/ap/%s/<route>/<granted path>"\n' "$new_key" \
  | curl -sS -K - -o /dev/null -D - -H 'Authorization: Bot dummy' | grep -i '^HTTP\|^x-ap-decision'

# B. right key, a method outside the grants: expect 423, x-ap-decision: denied, code no_grant
printf 'url = "https://<public-host>/ap/%s/<route>/<granted path>"\n' "$new_key" \
  | curl -sS -K - -X POST -o - -D - | grep -i '^HTTP\|^x-ap-decision\|ap_decision'
```

Then check the old key is refused (step 7 removes it; run this after step 7):

```
read -rs old_key
printf 'url = "https://<public-host>/ap/%s/<route>/<granted path>"\n' "$old_key" \
  | curl -sS -K - -o - -D - -H 'Authorization: Bot dummy' | grep -i '^HTTP\|^x-ap-decision\|ap_decision'
# expect: 401, x-ap-decision: rejected, {"ap_decision":"rejected","code":"caller_rejected"}
```

A bare 401 without `x-ap-decision` means the request passed the gate: the key is still accepted.

## 7. Remove the old identity

Make the edit in a copy and swap it in as in step 3. Delete the old `[[identity]]` block and every `[[grant]]`
that names it, in one edit (deleting only the identity leaves grants naming an unknown identity: the file stops
validating and every request gets 503). Validate the copy, `mv` it over the live file, then run the old-key check
from step 6 and the new-key check A again.

Remove the old connector registration on the calling platform, and clear any copy of the old key. Clear `old_key`
and `new_key` from the shell (`unset old_key new_key`).

## 8. If a log held the old key

Rotating makes the logged key useless once step 7 is done. Then delete or expire the log that held it if you can,
and turn off URL logging in that layer.
