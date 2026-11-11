#!/usr/bin/env python3
"""Static checks for deploy/k8s. Contacts no cluster.

Exits 0 when every check passes and 1 otherwise. Prints one PASS or FAIL line per check.
Needs PyYAML. TOML is parsed with tomllib or tomli when either is importable; otherwise a
structural check runs and the output says so.

    --root <dir>   check the manifests under <dir> (default: this script's directory). The
                   mutation tests in test_validate_manifests.py use it on modified copies.
"""

import argparse
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
RUNTIME_KEY_SECRET = "auth-proxy-runtime-key"
RUNTIME_KEY_ITEM = "runtime_ed25519.seed"
BOOTSTRAP_NAME = "expiry-store-bootstrap"
PREP_NAME = "volume-prep"
STORE_FILE_NAME = "session-expiry.v1"
SECRET_FILE_MODE = 0o444  # 292 decimal, the value written in pod.yaml
SESSION_DIR = "/run/auth-proxy-session"
AGENT_DIR = "/run/auth-proxy-agent"
EXPECTED_UIDS = {"agent": 1000, "proxy": 1001, "runtime": 1002, "egress": 1003}
# Every app container sets runAsGroup to its UID, so no container runs with GID 0 by default.
EXPECTED_GIDS = dict(EXPECTED_UIDS)
APP_CONTAINERS = ("agent", "proxy", "runtime", "egress")


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


def mount_names_of(container):
    return {m.get("name") for m in container.get("volumeMounts", [])}


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
    init_names = [c.get("name") for c in inits]
    check(
        "init-volume-prep-netinit-and-store-bootstrap",
        init_names == [PREP_NAME, "netinit", BOOTSTRAP_NAME],
        "initContainers are %s" % init_names,
    )
    netinit = next((c for c in inits if c.get("name") == "netinit"), {})
    sc = netinit.get("securityContext", {})
    check(
        "netinit-net-admin-only",
        sc.get("capabilities", {}).get("add") == ["NET_ADMIN"]
        and sc.get("capabilities", {}).get("drop") == ["ALL"],
    )
    check("netinit-runs-as-root", sc.get("runAsUser") == 0)

    prep = next((c for c in inits if c.get("name") == PREP_NAME), {})
    psc = prep.get("securityContext", {})
    check(
        "volume-prep-root-chown-only",
        psc.get("runAsUser") == 0
        and psc.get("capabilities", {}).get("drop") == ["ALL"]
        and psc.get("capabilities", {}).get("add") == ["CHOWN"]
        and psc.get("allowPrivilegeEscalation") is False
        and psc.get("readOnlyRootFilesystem") is True,
    )

    containers = {c.get("name"): c for c in spec.get("containers", [])}
    check(
        "containers-agent-proxy-runtime-egress",
        set(containers) == set(EXPECTED_UIDS),
        "containers are %s" % sorted(containers),
    )
    for name, uid in sorted(EXPECTED_UIDS.items()):
        c = containers.get(name, {})
        check(
            "uid-%s-%d" % (name, uid),
            c.get("securityContext", {}).get("runAsUser") == uid,
        )
    for name, gid in sorted(EXPECTED_GIDS.items()):
        c = containers.get(name, {})
        check(
            "gid-%s-%d" % (name, gid),
            c.get("securityContext", {}).get("runAsGroup") == gid,
        )
    check(
        "runtime-uid-differs-from-agent",
        containers.get("runtime", {}).get("securityContext", {}).get("runAsUser")
        != containers.get("agent", {}).get("securityContext", {}).get("runAsUser"),
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

    # The runtime-key Secret: one volume, mode 0444, mounted read-only into the runtime alone.
    runtime_key_vols = [
        n for n, v in secret_vols.items()
        if v["secret"].get("secretName") == RUNTIME_KEY_SECRET
    ]
    check("runtime-key-secret-volume-present", len(runtime_key_vols) == 1)
    rk_name = runtime_key_vols[0] if len(runtime_key_vols) == 1 else None
    if rk_name:
        rk = volumes[rk_name]["secret"]
        check(
            "runtime-key-mode-0444",
            rk.get("defaultMode") == SECRET_FILE_MODE,
            "defaultMode is %s" % rk.get("defaultMode"),
        )
        items = [i.get("key") for i in rk.get("items", [])]
        check(
            "runtime-key-item-is-the-seed",
            items == [RUNTIME_KEY_ITEM],
            "items are %s" % items,
        )
    holders = sorted(
        [c.get("name") for c in containers.values()
         if rk_name in mount_names_of(c)]
        + [c.get("name") for c in inits if rk_name in mount_names_of(c)]
    ) if rk_name else []
    check(
        "runtime-key-mounted-only-by-runtime",
        rk_name is not None and holders == ["runtime"],
        "runtime-key is mounted by %s" % holders,
    )
    rk_mounts = [
        m for m in containers.get("runtime", {}).get("volumeMounts", [])
        if m.get("name") == rk_name
    ] if rk_name else []
    check(
        "runtime-key-mount-read-only",
        len(rk_mounts) == 1 and rk_mounts[0].get("readOnly") is True,
    )

    # The two socket volumes. session-plane holds session.sock: the proxy and the runtime, never
    # the agent. agent-runtime holds runtime.sock: the runtime and the agent.
    session_vol = "session-plane"
    agent_vol = "agent-runtime"
    check(
        "session-plane-is-emptydir",
        "emptyDir" in volumes.get(session_vol, {}),
    )
    check(
        "agent-runtime-is-emptydir",
        "emptyDir" in volumes.get(agent_vol, {}),
    )
    holders = sorted(
        [c.get("name") for c in containers.values() if session_vol in mount_names_of(c)]
        + [c.get("name") for c in inits if session_vol in mount_names_of(c)]
    )
    check(
        "session-plane-mounted-only-by-proxy-runtime-volume-prep",
        holders == sorted(["proxy", "runtime", PREP_NAME]),
        "session-plane is mounted by %s" % holders,
    )
    check(
        "session-plane-not-in-agent",
        session_vol not in mount_names("agent")
        and not any(
            m.get("mountPath", "").startswith(SESSION_DIR)
            for m in containers.get("agent", {}).get("volumeMounts", [])
        ),
    )
    holders = sorted(
        [c.get("name") for c in containers.values() if agent_vol in mount_names_of(c)]
        + [c.get("name") for c in inits if agent_vol in mount_names_of(c)]
    )
    check(
        "agent-runtime-mounted-only-by-agent-runtime-volume-prep",
        holders == sorted(["agent", "runtime", PREP_NAME]),
        "agent-runtime is mounted by %s" % holders,
    )

    runtime_mounts = containers.get("runtime", {}).get("volumeMounts", [])
    runtime_mount_paths = {m.get("mountPath") for m in runtime_mounts}
    check(
        "runtime-mounts-only-sockets-and-key",
        runtime_mount_paths == {SESSION_DIR, AGENT_DIR, "/var/run/auth-proxy-runtime"},
        "runtime mounts %s" % sorted(p or "" for p in runtime_mount_paths),
    )

    for name in sorted(APP_CONTAINERS):
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

    def flag_value(flag, args=proxy_args):
        if flag in args:
            i = args.index(flag)
            if i + 1 < len(args):
                return args[i + 1]
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
    # --expiry-store (M-3): the store file is on its own volume. Read "the authority container" as
    # the proxy container, which runs the session authority. Agent, egress and netinit must not
    # mount the store.
    store_path = flag_value("--expiry-store")
    store_dir = os.path.dirname(store_path) if store_path else None
    store_mounts = [m for m in proxy_mounts if m.get("mountPath") == store_dir]
    check(
        "expiry-store-flag-points-at-store-file",
        store_path is not None
        and os.path.basename(store_path) == STORE_FILE_NAME
        and len(store_mounts) == 1,
        "--expiry-store %s has no proxy volumeMount for its directory" % store_path,
    )
    store_vol = store_mounts[0].get("name") if len(store_mounts) == 1 else None
    store_volume = volumes.get(store_vol, {}) if store_vol else {}
    # (1) store volume is separate from the token volume.
    token_vol_name = None
    proxy_token_mounts = [m for m in proxy_mounts if m.get("mountPath") == flag_value("--token-dir")]
    if len(proxy_token_mounts) == 1:
        token_vol_name = proxy_token_mounts[0].get("name")
    check(
        "expiry-store-volume-separate-from-token-volume",
        store_vol is not None
        and store_vol != token_vol_name
        and "persistentVolumeClaim" in store_volume
        and store_volume != volumes.get(token_vol_name),
        "store volume %s must be a PVC and differ from token volume %s"
        % (store_vol, token_vol_name),
    )
    # (2) the bootstrap init container exists, creates the file, and never truncates it.
    bootstrap = next((c for c in inits if c.get("name") == BOOTSTRAP_NAME), {})
    cmd_text = "\n".join(str(x) for x in bootstrap.get("command", []))
    bootstrap_mounts = {m.get("name") for m in bootstrap.get("volumeMounts", [])}
    check(
        "store-bootstrap-creates-store-file",
        bool(bootstrap)
        and STORE_FILE_NAME in cmd_text
        and "printf" in cmd_text
        and "mv " in cmd_text
        and "[ ! -e" in cmd_text
        and store_vol in bootstrap_mounts,
        "bootstrap init must mount the store volume and create %s only when absent" % STORE_FILE_NAME,
    )
    # (3) the store volume is mounted only into the proxy and the bootstrap init container.
    mounting = sorted(
        [c.get("name") for c in containers.values()
         if store_vol in {m.get("name") for m in c.get("volumeMounts", [])}]
        + [c.get("name") for c in inits
           if store_vol in {m.get("name") for m in c.get("volumeMounts", [])}]
    )
    check(
        "store-volume-mounted-only-by-proxy-and-bootstrap",
        mounting == sorted(["proxy", BOOTSTRAP_NAME]),
        "store volume is mounted by %s" % mounting,
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
    check(
        "session-socket-path-is-in-session-plane",
        flag_value("--session-socket") == SESSION_DIR + "/session.sock",
        "--session-socket is %s" % flag_value("--session-socket"),
    )

    # The runtime's flags point into its own mounts, and the seed is under the runtime-key mount.
    runtime_args = containers.get("runtime", {}).get("command", [])
    rt_session = flag_value("--session-socket", runtime_args)
    rt_agent = flag_value("--agent-socket", runtime_args)
    rt_seed = flag_value("--seed-file", runtime_args)
    rt_key_mount = next(
        (m.get("mountPath") for m in runtime_mounts if m.get("name") == rk_name), None
    )
    check(
        "runtime-flags-point-into-its-mounts",
        rt_session is not None
        and rt_session.startswith(SESSION_DIR + "/")
        and rt_agent is not None
        and rt_agent.startswith(AGENT_DIR + "/")
        and rt_seed is not None
        and rt_key_mount is not None
        and rt_seed.startswith(rt_key_mount + "/"),
        "runtime flags: session=%s agent=%s seed=%s" % (rt_session, rt_agent, rt_seed),
    )

    # Port consistency: netinit, agent proxy env and the identity file must agree.
    netinit_env = {e["name"]: e.get("value") for e in netinit.get("env", [])}
    agent_env = {e["name"]: e.get("value") for e in containers["agent"].get("env", [])}
    check(
        "netinit-agent-uid-matches-agent",
        netinit_env.get("AGENT_UID") == str(EXPECTED_UIDS["agent"]),
    )
    check(
        "netinit-runtime-uid-matches-runtime",
        netinit_env.get("RUNTIME_UID") == str(EXPECTED_UIDS["runtime"]),
    )
    egress_port = netinit_env.get("EGRESS_PORT", "")
    check(
        "agent-https-proxy-is-egress-port",
        agent_env.get("HTTPS_PROXY") == "http://127.0.0.1:" + egress_port,
    )

    # secrets.template.yaml names the runtime-key Secret.
    secret_names = {d.get("metadata", {}).get("name") for d in load_docs("secrets.template.yaml")}
    check(
        "secrets-template-names-runtime-key",
        RUNTIME_KEY_SECRET in secret_names,
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
        identities = parsed.get("identity", [])
        check(
            "identity-has-one-identity",
            len(identities) >= 1,
        )
        check(
            "identity-has-runtime-pubkey",
            bool(identities) and all("runtime_pubkey" in i for i in identities),
            "an [[identity]] has no runtime_pubkey",
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
        check(
            "identity-has-runtime-pubkey",
            re.search(r"^\s*runtime_pubkey = ", text, re.M) is not None,
            "an [[identity]] has no runtime_pubkey",
        )

    # netinit.sh rule order (F1, F2, design Q3-E2, and the runtime rules)
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
    runtime_est = rule_index(
        lines,
        lambda l: "$RUNTIME_UID" in l and "ctstate ESTABLISHED" in l and "ACCEPT" in l,
    )
    runtime_rej = rule_index(
        lines,
        lambda l: "$RUNTIME_UID" in l and "REJECT" in l and "ctstate" not in l,
    )
    check(
        "netinit-runtime-rules-present",
        runtime_est > non_lo >= 0 and runtime_rej > runtime_est,
        "runtime ESTABLISHED = %d, runtime REJECT = %d, after the agent non-lo rule (%d)"
        % (runtime_est, runtime_rej, non_lo),
    )

    print()
    if FAILURES:
        print("%d check(s) failed: %s" % (len(FAILURES), ", ".join(FAILURES)))
    else:
        print("all checks passed")


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=ROOT, help="directory holding pod.yaml and friends")
    return ap.parse_args(argv)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    ROOT = os.path.abspath(args.root)
    main()
    sys.exit(1 if FAILURES else 0)
