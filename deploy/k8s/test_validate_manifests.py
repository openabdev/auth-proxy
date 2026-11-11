#!/usr/bin/env python3
"""Mutation tests for validate_manifests.py. Stdlib unittest plus PyYAML.

Each test copies deploy/k8s to a temp directory, breaks one property, runs the validator with
--root on the copy, and asserts the exit code and the FAIL line that names the broken check. The
baseline copy must pass. Run from any directory:
    python3 deploy/k8s/test_validate_manifests.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
VALIDATOR = os.path.join(HERE, "validate_manifests.py")


def run_validator(root):
    proc = subprocess.run(
        [sys.executable, VALIDATOR, "--root", root],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout


class Copy:
    """A temp copy of deploy/k8s with a pod.yaml and netinit.sh that tests can edit."""

    def __init__(self, test):
        self.dir = tempfile.mkdtemp(prefix="k8s-validate-")
        test.addCleanup(shutil.rmtree, self.dir, True)
        shutil.copytree(HERE, os.path.join(self.dir, "k8s"),
                        ignore=shutil.ignore_patterns("__pycache__", "test_validate_manifests.py"))
        self.root = os.path.join(self.dir, "k8s")

    def load_pod(self):
        with open(os.path.join(self.root, "pod.yaml")) as f:
            docs = list(yaml.safe_load_all(f))
        return docs, next(d for d in docs if d and d.get("kind") == "Pod")

    def save_pod(self, docs):
        with open(os.path.join(self.root, "pod.yaml"), "w") as f:
            yaml.safe_dump_all(docs, f, sort_keys=False)

    def container(self, pod, name):
        return next(c for c in pod["spec"]["containers"] if c["name"] == name)

    def edit_pod(self, fn):
        docs, pod = self.load_pod()
        fn(pod)
        self.save_pod(docs)

    def edit_netinit(self, old, new):
        path = os.path.join(self.root, "netinit", "netinit.sh")
        with open(path) as f:
            text = f.read()
        assert text.count(old) == 1, "netinit edit anchor not unique"
        with open(path, "w") as f:
            f.write(text.replace(old, new))


class ValidatorTests(unittest.TestCase):
    def assert_fails(self, copy, check_name):
        code, out = run_validator(copy.root)
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL " + check_name, out, out)

    def test_baseline_copy_passes(self):
        copy = Copy(self)
        code, out = run_validator(copy.root)
        self.assertEqual(code, 0, out)
        self.assertIn("all checks passed", out)

    def test_agent_mounting_the_session_plane_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "agent")["volumeMounts"].append(
                {"name": "session-plane", "mountPath": "/run/auth-proxy-session"})

        copy.edit_pod(mutate)
        self.assert_fails(copy, "session-plane-mounted-only-by-proxy-runtime-volume-prep")
        code, out = run_validator(copy.root)
        self.assertIn("FAIL session-plane-not-in-agent", out)

    def test_agent_mounting_the_proof_secret_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "agent")["volumeMounts"].append(
                {"name": "runtime-key", "mountPath": "/var/run/auth-proxy-runtime", "readOnly": True})

        copy.edit_pod(mutate)
        self.assert_fails(copy, "runtime-key-mounted-only-by-runtime")

    def test_proof_secret_mounted_writable_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for m in copy.container(pod, "runtime")["volumeMounts"]:
                if m["name"] == "runtime-key":
                    m.pop("readOnly", None)

        copy.edit_pod(mutate)
        self.assert_fails(copy, "runtime-key-mount-read-only")

    def test_runtime_running_as_the_agent_uid_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "runtime")["securityContext"]["runAsUser"] = 1000

        copy.edit_pod(mutate)
        self.assert_fails(copy, "runtime-uid-differs-from-agent")

    def test_session_plane_moved_from_proxy_to_runtime_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            proxy = copy.container(pod, "proxy")
            proxy["volumeMounts"] = [m for m in proxy["volumeMounts"] if m["name"] != "session-plane"]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "session-plane-mounted-only-by-proxy-runtime-volume-prep")

    def test_app_container_without_run_as_group_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            del copy.container(pod, "agent")["securityContext"]["runAsGroup"]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "gid-agent-1000")

    def test_runtime_key_secret_with_the_wrong_mode_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for v in pod["spec"]["volumes"]:
                if v["name"] == "runtime-key":
                    v["secret"]["defaultMode"] = 384  # 0600

        copy.edit_pod(mutate)
        self.assert_fails(copy, "runtime-key-mode-0444")

    def test_netinit_without_the_runtime_rules_is_refused(self):
        copy = Copy(self)
        copy.edit_netinit(
            '  $T -A OUTPUT -m owner --uid-owner "$RUNTIME_UID" -j REJECT\n', "")
        self.assert_fails(copy, "netinit-runtime-rules-present")

    def test_identity_without_a_runtime_pubkey_is_refused(self):
        copy = Copy(self)
        path = os.path.join(copy.root, "identity-configmap.yaml")
        with open(path) as f:
            text = f.read()
        self.assertEqual(text.count('    runtime_pubkey = "REPLACE"\n'), 1)
        with open(path, "w") as f:
            f.write(text.replace('    runtime_pubkey = "REPLACE"\n', ""))
        self.assert_fails(copy, "identity-has-runtime-pubkey")


if __name__ == "__main__":
    unittest.main()
