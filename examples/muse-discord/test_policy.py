#!/usr/bin/env python3
"""Policy check: the shipped pilot policy against the gate's matching rules.

This is a Python MIRROR of two small pieces of crates/ap-core, run against the
paths this caller actually uses: valid_prefix_path (src/config.rs, the path
rule for passthrough grants) and Policy::evaluate's method match plus raw
starts_with on the route-relative path (src/policy.rs). The mock does not
evaluate policy independently of this file's source (it reads the same TOML),
so this check pins what that policy does and does not authorize. If config.rs
or policy.rs change their rules, this file must change with them. It does NOT
replace running the caller against the real gate.

The policy is deploy/muse/pilot-policy.example.toml (stage 1, reads only).

What it pins down:

  1. every grant path passes valid_prefix_path and no grant carries a
     credential or a hold decision (stage 1 grants are allow only),
  2. the read grants authorize the caller's read paths,
  3. create-message and every other write is NOT authorized: the gate answers
     423 no_grant in stage 1,
  4. the read-side blast radius of the raw prefixes: GET .../channels/<id>/webhooks
     and the guild reads are authorized too.

Run: python3 test_policy.py   (stdlib only, no network)
"""

import os
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY = os.path.join(HERE, "..", "..", "deploy", "muse", "pilot-policy.example.toml")
CHANNEL = "1111111111111111111"

failures = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def valid_prefix_path(p: str) -> bool:
    """Mirror of valid_prefix_path in crates/ap-core/src/config.rs."""
    return (
        p.startswith("/")
        and "%" not in p
        and "//" not in p
        and not any(seg in (".", "..") for seg in p.split("/"))
    )


def evaluate(grants: list[dict], route: str, method: str, path: str) -> bool:
    """Mirror of Policy::evaluate for a passthrough grant."""
    return any(
        g["route"] == route and method in g["methods"] and any(path.startswith(p) for p in g["paths"])
        for g in grants
    )


def main() -> int:
    with open(POLICY, "rb") as fh:
        config = tomllib.load(fh)
    grants = config.get("grant", [])

    check("the policy has at least one grant", bool(grants))
    check("every grant path passes valid_prefix_path",
          all(valid_prefix_path(p) for g in grants for p in g["paths"]))
    check("stage 1 grants are allow-only and carry no credential",
          all(g.get("decision") == "allow" and "credential" not in g for g in grants))
    check("stage 1 grants are reads only", all(g["methods"] == ["GET"] for g in grants))

    ok = lambda m, p: evaluate(grants, "discord", m, p)  # noqa: E731
    check("GET channel messages is authorized", ok("GET", f"/api/v10/channels/{CHANNEL}/messages"))
    check("GET users/@me is authorized", ok("GET", "/api/v10/users/@me"))

    check("POST create-message is NOT authorized (423 no_grant in stage 1)",
          not ok("POST", f"/api/v10/channels/{CHANNEL}/messages"))
    for method, path in [
        ("PUT", f"/api/v10/channels/{CHANNEL}/pins/1"),
        ("PATCH", f"/api/v10/channels/{CHANNEL}/messages/1"),
        ("DELETE", f"/api/v10/channels/{CHANNEL}/messages/1"),
        ("POST", f"/api/v10/channels/{CHANNEL}/messages/bulk-delete"),
        ("POST", f"/api/v10/channels/{CHANNEL}/webhooks"),
        ("POST", f"/api/v10/channels/{CHANNEL}/invites"),
    ]:
        check(f"{method} {path.split(CHANNEL)[-1] or path} is NOT authorized", not ok(method, path))

    # Raw prefixes are broader than message history: a read grant on
    # /api/v10/channels/ also reaches the webhooks list, which returns webhook
    # tokens if the bot holds Manage Webhooks. Not narrowable in stage 1.
    check("READ-SIDE RISK: GET .../webhooks is authorized by the channel prefix",
          ok("GET", f"/api/v10/channels/{CHANNEL}/webhooks"))
    check("READ-SIDE RISK: GET guild reads are authorized by the guild prefix",
          ok("GET", "/api/v10/guilds/1/members"))
    check("the read prefix does not cover other trees", not ok("GET", "/api/v10/applications/@me"))
    check("an unknown route is not authorized", not evaluate(grants, "nowhere", "GET", "/api/v10/users/@me"))

    print(f"\n{'ALL PASSED' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
