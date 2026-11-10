#!/usr/bin/env python3
"""Static checks for deploy/k8s. Contacts no cluster.

Exits 0 when every check passes and 1 otherwise. Prints one PASS or FAIL line per check.
Needs PyYAML. TOML is parsed with tomllib or tomli when either is importable; otherwise a
structural check runs and the output says so.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
FAILURES = []

try:
    import yaml
except ImportError:
    print("FAIL pyyaml-available: PyYAML is required")
    sys.exit(1)

try:
    import tomllib as toml_lib

    TOML_MODE = "tomllib"
except ImportError:
    try:
        import tomli as toml_lib

        TOML_MODE = "tomli"
    except ImportError:
        toml_lib = None
        TOML_MODE = "structural fallback"

CREDENTIAL_SECRET = "auth-proxy-kiro"
CREDENTIAL_KEY = "api_key"
CALLER_SECRET = "auth-proxy-caller"
SECRET_FILE_MODE = 0o444  # 292 decimal, the value written in pod.yaml
EXPECTED_UIDS = {"agent": 1000, "proxy": 1001, "egress": 1002}


def check(name, ok, detail=""):
    if ok:
        print("PASS " + name)
    else:
        print("FAIL " + name + (": " + detail if detail else ""))
        FAILURES.append(name)


def load_docs(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return [d for d in yaml.safe_load_all(f) if d is not None]


def walk(obj):
    """Yield every (key, value) pair in a nested dict/list structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from walk(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk(item)


def rule_index(lines, pred):
    for i, line in enumerate(lines):
        if pred(line):
            return i
    return -1


def main():
    print("INFO toml parser: " + TOML_MODE)

    # pod.yaml
    docs = load_docs("pod.yaml")
    namespaces = [d for d in docs if d.get("kind") == "Namespace"]
    pods = [d for d in docs if d.get("kind") == "Pod"]
    check(
        "namespace-psa-privileged",
        len(namespaces) == 1
        and namespaces[0]["metadata"].get("labels", {}).get(
            "pod-security.kubernetes.io/enforce"
        )
        == "privileged",
    )
    check("single-pod", len(pods) == 1, "found %d Pod documents" % len(pods))
    if not pods:
        return
    spec = pods[0]["spec"]

    inits = spec.get("initContainers", [])
    check(
        "init-netinit-only",
        [c.get("name") for c in inits] == ["netinit"],
        "initContainers are %s" % [c.get("name") for c in inits],
    )
    netinit = inits[0] if inits else {}
    sc = netinit.get("securityContext", {})
    check(
        "netinit-net-admin-only",
        sc.get("capabilities", {}).get("add") == ["NET_ADMIN"]
        and sc.get("capabilities", {}).get("drop") == ["ALL"],
    )
    check("netinit-runs-as-root", sc.get("runAsUser") == 0)

    containers = {c.get("name"): c for c in spec.get("containers", [])}
    check(
        "containers-agent-proxy-egress",
        set(containers) == set(EXPECTED_UIDS),
        "containers are %s" % sorted(containers),
    )
    for name, uid in sorted(EXPECTED_UIDS.items()):
        c = containers.get(name, {})
        check(
            "uid-%s-%d" % (name, uid),
            c.get("securityContext", {}).get("runAsUser") == uid,
        )

    check(
        "share-process-namespace-false",
        spec.get("shareProcessNamespace") is False,
    )

    fs_group = [k for k, _ in walk(pods[0]) if k == "fsGroup"]
    check("no-fsgroup", not fs_group, "fsGroup found %d times" % len(fs_group))

    env_names = [
        e.get("name")
        for c in inits + spec.get("containers", [])
        for e in c.get("env", [])
    ]
    check("no-kiro-api-key-env", "KIRO_API_KEY" not in env_names)

    volumes = {v["name"]: v for v in spec.get("volumes", [])}
    secret_vols = {
        n: v for n, v in volumes.items() if "secret" in v
    }
    cred_vols = [
        n for n, v in secret_vols.items()
        if v["secret"].get("secretName") == CREDENTIAL_SECRET
    ]
    check("credential-volume-present", len(cred_vols) == 1)
    if cred_vols:
        cv = volumes[cred_vols[0]]["secret"]
        check(
            "credential-secret-mode-0444",
            cv.get("defaultMode") == SECRET_FILE_MODE,
            "defaultMode is %s" % cv.get("defaultMode"),
        )

    def mount_names(container_name):
        return {
            m.get("name")
            for m in containers.get(container_name, {}).get("volumeMounts", [])
        }

    check(
        "agent-has-no-credential-mount",
        not (mount_names("agent") & set(cred_vols)),
    )
    check(
        "egress-has-no-secret-mount",
        not (mount_names("egress") & set(secret_vols)),
    )
    check(
        "proxy-mounts-credential",
        bool(mount_names("proxy") & set(cred_vols)),
    )
    check(
        "agent-caller-key-mount",
        any(
            volumes.get(n, {}).get("secret", {}).get("secretName") == CALLER_SECRET
            for n in mount_names("agent")
        ),
    )

    # Container hardening on the three app containers (FEAT-006 step 2).
    for name in sorted(EXPECTED_UIDS):
        c = containers.get(name, {})
        sec = c.get("securityContext", {})
        problems = []
        if sec.get("capabilities", {}).get("drop") != ["ALL"]:
            problems.append("capabilities.drop is not [ALL]")
        if sec.get("allowPrivilegeEscalation") is not False:
            problems.append("allowPrivilegeEscalation is not false")
        if sec.get("readOnlyRootFilesystem") is not True:
            problems.append("readOnlyRootFilesystem is not true")
        if sec.get("runAsNonRoot") is not True:
            problems.append("runAsNonRoot is not true")
        check("hardening-%s" % name, not problems, "; ".join(problems))

    # --token-dir: the proxy writes the authority hash there at hello, so the path must be a
    # writable mount of a proxy volume. Without it, the first hello fails.
    proxy_args = containers.get("proxy", {}).get("command", [])

    def flag_value(flag):
        if flag in proxy_args:
            i = proxy_args.index(flag)
            if i + 1 < len(proxy_args):
                return proxy_args[i + 1]
        return None

    token_dir = flag_value("--token-dir")
    proxy_mounts = containers.get("proxy", {}).get("volumeMounts", [])
    token_mounts = [m for m in proxy_mounts if m.get("mountPath") == token_dir]
    check(
        "token-dir-is-proxy-mount",
        token_dir is not None and len(token_mounts) == 1,
        "--token-dir %s is not a proxy volumeMount mountPath" % token_dir,
    )
    if token_mounts:
        tv = volumes.get(token_mounts[0].get("name"), {})
        check(
            "token-dir-volume-writable-emptydir",
            "emptyDir" in tv and not token_mounts[0].get("readOnly", False),
            "token-dir volume must be an emptyDir mounted read-write",
        )
        check(
            "token-dir-not-mounted-by-agent-or-egress",
            token_mounts[0].get("name")
            not in (mount_names("agent") | mount_names("egress")),
        )
    for flag in ("--session-socket", "--admin-socket"):
        path = flag_value(flag)
        parent = os.path.dirname(path) if path else None
        check(
            "%s-dir-is-proxy-mount" % flag.lstrip("-"),
            parent is not None
            and any(m.get("mountPath") == parent for m in proxy_mounts),
            "%s %s has no proxy volumeMount for its directory" % (flag, path),
        )

    # Port consistency: netinit, agent proxy env and the identity file must agree.
    netinit_env = {e["name"]: e.get("value") for e in netinit.get("env", [])}
    agent_env = {e["name"]: e.get("value") for e in containers["agent"].get("env", [])}
    check(
        "netinit-agent-uid-matches-agent",
        netinit_env.get("AGENT_UID") == str(EXPECTED_UIDS["agent"]),
    )
    egress_port = netinit_env.get("EGRESS_PORT", "")
    check(
        "agent-https-proxy-is-egress-port",
        agent_env.get("HTTPS_PROXY") == "http://127.0.0.1:" + egress_port,
    )

    # identity-configmap.yaml
    cm = load_docs("identity-configmap.yaml")[0]
    text = cm["data"]["identity.toml"]
    proxy_port = netinit_env.get("PROXY_PORT", "")
    check(
        "identity-listen-is-proxy-port",
        ('proxy = "127.0.0.1:%s"' % proxy_port) in text,
    )
    key_match = re.search(r'caller_key_sha256 = "([0-9a-f]+)"', text)
    check(
        "caller-key-sha256-is-64-hex",
        bool(key_match) and len(key_match.group(1)) == 64,
    )
    src = re.search(r'source = "k8s:([a-z0-9._-]+):([a-z0-9._-]+)"', text)
    check(
        "credential-source-matches-secret-volume",
        bool(src)
        and src.group(1) == CREDENTIAL_SECRET
        and src.group(2) == CREDENTIAL_KEY,
    )
    if toml_lib is not None:
        parsed = toml_lib.loads(text)
        check("identity-toml-parses", parsed.get("version") == 1)
        check(
            "identity-has-one-identity",
            len(parsed.get("identity", [])) >= 1,
        )
    else:
        check(
            "identity-toml-structure",
            re.search(r"^version = 1$", text, re.M) is not None
            and "[[identity]]" in text
            and "[[route]]" in text
            and "[[credential]]" in text
            and "[[grant]]" in text
            and "[egress]" in text,
            "required tables missing",
        )

    # netinit.sh rule order (F1, F2, design Q3-E2)
    with open(os.path.join(ROOT, "netinit", "netinit.sh")) as f:
        lines = f.read().splitlines()
    loop = rule_index(lines, lambda l: l.startswith("for T in iptables ip6tables"))
    check("netinit-loops-iptables-and-ip6tables", loop >= 0)
    check(
        "netinit-flushes-output",
        rule_index(lines, lambda l: "$T -F OUTPUT" in l) >= 0,
    )
    est = rule_index(
        lines, lambda l: "ctstate ESTABLISHED" in l and "ACCEPT" in l
    )
    proxy_acc = rule_index(
        lines,
        lambda l: '--dport "$PROXY_PORT"' in l and "ACCEPT" in l,
    )
    egress_acc = rule_index(
        lines,
        lambda l: '--dport "$EGRESS_PORT"' in l and "ACCEPT" in l,
    )
    other_rej = rule_index(
        lines,
        lambda l: '--dport "$p"' in l and "REJECT" in l,
    )
    lo_catch = rule_index(
        lines,
        lambda l: "-o lo -m owner" in l
        and "! -o lo" not in l
        and "-p tcp" not in l
        and "REJECT" in l,
    )
    non_lo = rule_index(
        lines, lambda l: "! -o lo" in l and "REJECT" in l
    )
    found = [est, proxy_acc, egress_acc, other_rej, lo_catch, non_lo]
    check(
        "netinit-all-rules-present",
        all(i >= 0 for i in found),
        "indexes ESTABLISHED, proxy, egress, other, lo catch-all, non-lo = %s" % found,
    )
    check(
        "netinit-rule-order",
        all(i >= 0 for i in found)
        and all(a < b for a, b in zip(found, found[1:])),
        "order must be ESTABLISHED < proxy < egress < other-lo < lo-catch-all < non-lo",
    )

    print()
    if FAILURES:
        print("%d check(s) failed: %s" % (len(FAILURES), ", ".join(FAILURES)))
    else:
        print("all checks passed")


if __name__ == "__main__":
    main()
    sys.exit(1 if FAILURES else 0)
