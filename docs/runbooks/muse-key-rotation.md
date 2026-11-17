# Rotating the Muse caller key

Use this when the caller key may have been exposed (for example, a log that recorded the URL path, see
`docs/evidence/muse-front-logging.md`), or on a schedule. Policy format: `deploy/muse/pilot-policy.example.toml`.
Background: `docs/runbooks/muse-stage1.md` section 2.

The calling platform fixes where the key sits (the path placement `/ap/{}`) when the connector is registered, and
the placement cannot be edited. Rotation therefore means registering the connector again with the new key.

**The old key keeps working until you remove its hash from the policy.** Until step 6 an exposed key is still
accepted. Do the steps in one sitting.

All names below are placeholders. Do not commit real hosts, keys or hashes.

## 1. Generate a new key (on the gate host)

```
umask 077
new_key="apk_$(openssl rand -hex 32)"
printf '%s' "$new_key" | sha256sum | cut -d' ' -f1      # new hash (use `shasum -a 256` on macOS)
```

Keep `$new_key` in the shell only. Do not write it to a file in the repo, a ticket or a chat.

## 2. Add the new identity next to the old one

Edit the policy file (the one passed as `--config`). An identity is a name and a hash; grants name the identity.
Add a second identity and copy the old identity's grants under the new name:

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

To replace instead of add, keep the same identity `name` and swap only `caller_key_sha256`. The old key then stops
working at once, so register the new key on the platform first only if you accept a gap.

## 3. Reload

The policy file is checked on every read by mtime and size, so a saved edit is picked up with no restart or signal.
Validate the file first: an invalid file makes every request fail 503 until it is fixed (a grant that names an
unknown identity is invalid). Check the reload:

```
journalctl -u <gate-unit> --no-pager -n 20      # no policy error lines
```

## 4. Re-register the connector on the calling platform

Register a new connector for the gate host with the placement `/ap/{}` and the new key (the old connector cannot
be edited). Point the agent's helper at the new connector.

## 5. Verify

- A request through the front with the new key and a granted read returns the upstream's response.
- A request with the new key and a method outside the grants returns 423 `no_grant`.
- The audit file shows the new identity name on those requests.

```
curl -sS -o /dev/null -w '%{http_code}\n' "https://<public-host>/ap/$new_key/<route>/<granted path>"
```

## 6. Remove the old identity

Delete the old `[[identity]]` block and every `[[grant]]` that names it, in one edit (deleting only the identity
leaves grants naming an unknown identity: the file stops validating and every request gets 503). Then check the
old key is refused:

```
curl -sS -o /dev/null -w '%{http_code}\n' "https://<public-host>/ap/<old key>/<route>/<granted path>"   # expect 401
```

Remove the old connector registration on the calling platform, and clear any copy of the old key.

## 7. If a log held the old key

Rotating makes the logged key useless once step 6 is done. Then delete or expire the log that held it if you can,
and turn off URL logging in that layer.
