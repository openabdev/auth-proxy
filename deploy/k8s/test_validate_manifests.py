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

    def _mount_credential(self, copy, container, **extra):
        def mutate(pod):
            m = {"name": "kiro-secret", "mountPath": "/var/run/cred-copy", "readOnly": True}
            m.update(extra)
            copy.container(pod, container)["volumeMounts"].append(m)

        copy.edit_pod(mutate)

    def test_credential_mounted_in_the_runtime_is_refused(self):
        copy = Copy(self)
        self._mount_credential(copy, "runtime")
        self.assert_fails(copy, "credential-mounted-only-by-proxy")

    def test_credential_mounted_in_the_egress_is_refused(self):
        copy = Copy(self)
        self._mount_credential(copy, "egress")
        self.assert_fails(copy, "credential-mounted-only-by-proxy")

    def test_credential_mounted_in_the_agent_is_refused(self):
        copy = Copy(self)
        self._mount_credential(copy, "agent")
        self.assert_fails(copy, "credential-mounted-only-by-proxy")

    def test_credential_mounted_in_an_init_container_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            pod["spec"]["initContainers"][0]["volumeMounts"].append(
                {"name": "kiro-secret", "mountPath": "/cred", "readOnly": True})

        copy.edit_pod(mutate)
        self.assert_fails(copy, "credential-mounted-only-by-proxy")

    def test_credential_on_a_pvc_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for v in pod["spec"]["volumes"]:
                if v["name"] == "kiro-secret":
                    del v["secret"]
                    v["persistentVolumeClaim"] = {"claimName": "auth-proxy-kiro"}

        copy.edit_pod(mutate)
        self.assert_fails(copy, "credential-volume-is-secret-type")

    def test_credential_through_a_projected_volume_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for v in pod["spec"]["volumes"]:
                if v["name"] == "kiro-secret":
                    del v["secret"]
                    v["projected"] = {"defaultMode": 292, "sources": [
                        {"secret": {"name": "auth-proxy-kiro"}}]}

        copy.edit_pod(mutate)
        self.assert_fails(copy, "credential-volume-is-secret-type")

    def test_other_volume_under_the_credential_directory_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            pod["spec"]["volumes"].append({"name": "stray", "emptyDir": {}})
            copy.container(pod, "proxy")["volumeMounts"].append(
                {"name": "stray", "mountPath": "/var/run/auth-proxy/secrets/other"})

        copy.edit_pod(mutate)
        self.assert_fails(copy, "credential-dir-only-holds-credential-volume")

    def test_credential_with_the_wrong_mode_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for v in pod["spec"]["volumes"]:
                if v["name"] == "kiro-secret":
                    v["secret"]["defaultMode"] = 256  # 0400, unreadable to the proxy UID
                    # Documented in README: a Secret volume file is not owned by the proxy UID.

        copy.edit_pod(mutate)
        self.assert_fails(copy, "credential-secret-mode-0444")

    def test_credential_mount_not_read_only_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for m in copy.container(pod, "proxy")["volumeMounts"]:
                if m["name"] == "kiro-secret":
                    m.pop("readOnly")

        copy.edit_pod(mutate)
        self.assert_fails(copy, "credential-mount-read-only")

    def test_credential_in_agent_env_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "agent")["env"].append({"name": "KEY", "valueFrom": {
                "secretKeyRef": {"name": "auth-proxy-kiro", "key": "api_key"}}})

        copy.edit_pod(mutate)
        self.assert_fails(copy, "credential-not-referenced-by-env")

    def test_credential_in_runtime_envfrom_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "runtime")["envFrom"] = [{"secretRef": {"name": "auth-proxy-kiro"}}]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "credential-not-referenced-by-env")

    def _add_ephemeral(self, copy, **fields):
        def mutate(pod):
            c = {"name": "debugger", "image": "busybox"}
            c.update(fields)
            pod["spec"]["ephemeralContainers"] = [c]

        copy.edit_pod(mutate)

    def test_credential_mounted_in_an_ephemeral_container_is_refused(self):
        copy = Copy(self)
        self._add_ephemeral(copy, volumeMounts=[
            {"name": "kiro-secret", "mountPath": "/cred", "readOnly": True}])
        self.assert_fails(copy, "credential-mounted-only-by-proxy")

    def test_credential_dir_mount_in_an_ephemeral_container_is_refused(self):
        copy = Copy(self)
        self._add_ephemeral(copy, volumeMounts=[
            {"name": "home", "mountPath": "/var/run/auth-proxy/secrets/x"}])
        self.assert_fails(copy, "credential-dir-only-holds-credential-volume")

    def test_credential_secretkeyref_in_an_ephemeral_container_is_refused(self):
        copy = Copy(self)
        self._add_ephemeral(copy, env=[{"name": "KEY", "valueFrom": {
            "secretKeyRef": {"name": "auth-proxy-kiro", "key": "api_key"}}}])
        self.assert_fails(copy, "credential-not-referenced-by-env")

    def test_credential_secretref_in_an_ephemeral_container_is_refused(self):
        copy = Copy(self)
        self._add_ephemeral(copy, envFrom=[{"secretRef": {"name": "auth-proxy-kiro"}}])
        self.assert_fails(copy, "credential-not-referenced-by-env")

    def test_credential_item_mode_override_is_refused(self):
        for mode in (256, 511):
            copy = Copy(self)

            def mutate(pod, mode=mode):
                for v in pod["spec"]["volumes"]:
                    if v["name"] == "kiro-secret":
                        v["secret"]["items"][0]["mode"] = mode

            copy.edit_pod(mutate)
            self.assert_fails(copy, "credential-secret-mode-0444")

    def test_runtime_key_item_mode_override_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for v in pod["spec"]["volumes"]:
                if v["name"] == "runtime-key":
                    v["secret"]["items"][0]["mode"] = 256

        copy.edit_pod(mutate)
        self.assert_fails(copy, "runtime-key-mode-0444")

    def test_hostpath_volume_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            pod["spec"]["volumes"].append(
                {"name": "hp", "hostPath": {"path": "/var/lib/kubelet/pods"}})

        copy.edit_pod(mutate)
        self.assert_fails(copy, "no-hostpath-volumes")

    def test_credential_subpath_mount_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for m in copy.container(pod, "proxy")["volumeMounts"]:
                if m["name"] == "kiro-secret":
                    m["subPath"] = "api_key"

        copy.edit_pod(mutate)
        self.assert_fails(copy, "credential-mount-no-subpath")

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
