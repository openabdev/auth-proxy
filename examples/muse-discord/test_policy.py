#!/usr/bin/env python3
"""Policy check: the shipped identity.toml against ap-core's matching rules.

This is a line-by-line Python MIRROR of two small functions in
crates/ap-core -- valid_path (src/config.rs) and Policy::evaluate's
method + raw starts_with path match (src/policy.rs) -- run against the
caller's real request paths. It exists because the mock in this directory
does no policy evaluation at all: without this check, the example's own
tests happily accept a grant shape the real policy would deny (round-2
review F1/F3). The mirror is deliberately tiny and cites its sources;
if config.rs or policy.rs change their rules, this file must change with
them. It does NOT replace running the caller against the real proxy.

What it pins down:

  1. every grant path in the shipped identity.toml passes valid_path,
  2. the shipped read grants authorize the caller's read paths,
  3. the documented write trap: the /messages/ prefix grant (the only
     per-message prefix valid_path accepts) can NEVER authorize the
     create-message request, whose path has no trailing slash -- while
     it WOULD authorize sub-paths such as threads and crossposts,
  4. the whole-channel prefix is the only Phase 1 grant shape that
     authorizes create-message -- and it also authorizes the
     bulk-delete, webhooks and invites endpoints under the channel
     (the blast radius that implies), while NOT authorizing
     DELETE/PATCH on the channel path itself (no trailing slash).

Run: python3 test_policy.py   (stdlib only, no network)
"""

import os
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
CHANNEL = "1111111111111111111"

failures = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


# -- mirrors of crates/ap-core -------------------------------------------
def valid_path(p: str) -> bool:
    """Mirror of valid_path in crates/ap-core/src/config.rs."""
    if not p.startswith("/"):
        return False
    if "%" in p:
        return False
    if "//" in p:
        return False
    if any(seg in (".", "..") for seg in p.split("/")):
        return False
    if not p.endswith("/"):
        return False
    return True


def evaluate(grants: list[dict], method: str, path: str) -> bool:
    """Mirror of Policy::evaluate in crates/ap-core/src/policy.rs:
    a grant matches when the method matches and the request path starts
    with any of the grant's path prefixes (raw starts_with, no segment
    boundary)."""
    return any(
        method in g["methods"] and any(path.startswith(prefix) for prefix in g["paths"])
        for g in grants
    )


def main() -> int:
    with open(os.path.join(HERE, "identity.toml"), "rb") as fh:
        config = tomllib.load(fh)
    shipped = config.get("grant", [])

    # 1. shipped grant paths are loadable by the real config validation
    check("shipped grant paths pass valid_path",
          all(valid_path(p) for g in shipped for p in g["paths"]),
          str([p for g in shipped for p in g["paths"] if not valid_path(p)]))

    # 2. shipped read grants authorize the caller's read paths
    check("read grant matches message history path",
          evaluate(shipped, "GET", f"/api/v10/channels/{CHANNEL}/messages"))
    check("read grant does NOT cover guild reads (caller.py does not use them)",
          not evaluate(shipped, "GET", f"/api/v10/guilds/{CHANNEL}/channels"))
    # /users/@me/guilds is the real "list my guilds" endpoint. It is NOT
    # under the granted prefixes, so the example does not claim it.
    check("read grant does NOT cover /users/@me/guilds",
          not evaluate(shipped, "GET", "/api/v10/users/@me/guilds"))

    # M-1: the default read grant is a prefix and cannot be narrowed to
    # messages only (valid_path forbids the exact path). It therefore
    # DOES authorize listing webhooks, which returns webhook tokens when
    # the bot holds Manage Webhooks. Documented in README/identity.toml;
    # pinned here so a change in either direction is noticed.
    check("DOCUMENTED RISK: read grant authorizes GET .../webhooks (tokens if bot has Manage Webhooks)",
          evaluate(shipped, "GET", f"/api/v10/channels/{CHANNEL}/webhooks"))
    check("guild webhooks are not covered",
          not evaluate(shipped, "GET", f"/api/v10/guilds/{CHANNEL}/webhooks"))

    # 3. the documented write trap (round-2 F1/F2)
    narrow = [{"methods": ["POST"], "paths": [f"/api/v10/channels/{CHANNEL}/messages/"]}]
    check("narrow /messages/ prefix passes valid_path (it loads fine)",
          valid_path(narrow[0]["paths"][0]))
    check("...but can NEVER authorize create-message (no trailing slash)",
          not evaluate(narrow, "POST", f"/api/v10/channels/{CHANNEL}/messages"))
    check("...while it WOULD authorize thread creation from a message",
          evaluate(narrow, "POST", f"/api/v10/channels/{CHANNEL}/messages/1570000000000000000/threads"))
    check("...and crossposting a message",
          evaluate(narrow, "POST", f"/api/v10/channels/{CHANNEL}/messages/1570000000000000000/crosspost"))
    check("exact create-message path is rejected by valid_path",
          not valid_path(f"/api/v10/channels/{CHANNEL}/messages"))

    # 4. the only Phase 1 shape that authorizes create-message
    broad = [{"methods": ["POST"], "paths": [f"/api/v10/channels/{CHANNEL}/"]}]
    check("whole-channel prefix authorizes create-message",
          evaluate(broad, "POST", f"/api/v10/channels/{CHANNEL}/messages"))
    # ...and its blast radius (round-3 F1): the same POST grant also
    # authorizes destructive and proxy-escaping endpoints under the
    # channel. bulk-delete needs Discord's Manage Messages permission
    # and webhooks need Manage Webhooks, so the README/identity.toml
    # advice is to grant the bot neither (nor Create Instant Invite).
    check("whole-channel prefix also authorizes bulk-delete",
          evaluate(broad, "POST", f"/api/v10/channels/{CHANNEL}/messages/bulk-delete"))
    check("whole-channel prefix also authorizes webhook creation (mints a proxy-bypassing token)",
          evaluate(broad, "POST", f"/api/v10/channels/{CHANNEL}/webhooks"))
    check("whole-channel prefix also authorizes invite creation",
          evaluate(broad, "POST", f"/api/v10/channels/{CHANNEL}/invites"))
    # ...but not the channel itself: /api/v10/channels/<id> has no
    # trailing slash, so it does not start with the prefix.
    broad_rw = [{"methods": ["POST", "PATCH", "DELETE"], "paths": [f"/api/v10/channels/{CHANNEL}/"]}]
    check("whole-channel prefix does NOT authorize DELETE on the channel itself",
          not evaluate(broad_rw, "DELETE", f"/api/v10/channels/{CHANNEL}"))
    check("whole-channel prefix does NOT authorize PATCH on the channel itself",
          not evaluate(broad_rw, "PATCH", f"/api/v10/channels/{CHANNEL}"))

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
