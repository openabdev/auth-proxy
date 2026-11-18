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

    def test_runtime_key_through_a_projected_volume_in_the_agent_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            pod["spec"]["volumes"].append({"name": "pj", "projected": {"sources": [
                {"secret": {"name": "auth-proxy-runtime-key"}}]}})
            copy.container(pod, "agent")["volumeMounts"].append(
                {"name": "pj", "mountPath": "/k", "readOnly": True})

        copy.edit_pod(mutate)
        self.assert_fails(copy, "runtime-key-volume-is-secret-type")
        self.assert_fails(copy, "runtime-key-not-in-any-other-container-list")

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

    # ---- netfilter self-check (issue #20) ----
    def edit_script(self, copy, name, old, new):
        path = os.path.join(copy.root, "netinit", name)
        with open(path) as f:
            text = f.read()
        self.assertEqual(text.count(old), 1, "anchor not unique: " + old)
        with open(path, "w") as f:
            f.write(text.replace(old, new))

    def test_proxy_with_net_admin_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "proxy")["securityContext"]["capabilities"]["add"] = ["NET_ADMIN"]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "no-capability-added-proxy")
        code, out = run_validator(copy.root)
        self.assertIn("FAIL net-admin-only-in-netinit-and-netcheck", out)

    def test_proxy_with_net_raw_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "proxy")["securityContext"]["capabilities"]["add"] = ["NET_RAW"]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "no-capability-added-proxy")
        code, out = run_validator(copy.root)
        self.assertIn("FAIL no-net-raw-sys-admin-or-all", out)

    def test_netprobe_with_a_capability_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "netprobe")["securityContext"]["capabilities"]["add"] = ["NET_ADMIN"]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "no-capability-added-netprobe")

    def test_netprobe_running_as_another_uid_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "netprobe")["securityContext"]["runAsUser"] = 1003

        copy.edit_pod(mutate)
        self.assert_fails(copy, "netprobe-runs-as-the-agent-uid-unprivileged")

    def test_netcheck_with_more_than_net_admin_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "netcheck")["securityContext"]["capabilities"]["add"] = [
                "NET_ADMIN", "NET_RAW"]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "netcheck-root-net-admin-only-hardened")

    def test_netcheck_mounting_a_secret_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "netcheck")["volumeMounts"].append(
                {"name": "kiro-secret", "mountPath": "/k", "readOnly": True})

        copy.edit_pod(mutate)
        self.assert_fails(copy, "netcheck-no-secret-and-no-port")

    def test_netcheck_snapshot_mount_must_be_read_only(self):
        copy = Copy(self)

        def mutate(pod):
            for m in copy.container(pod, "netcheck")["volumeMounts"]:
                if m["name"] == "netinit-run":
                    m.pop("readOnly", None)

        copy.edit_pod(mutate)
        self.assert_fails(copy, "netcheck-mounts-only-snapshot-ro-and-its-status")

    def test_agent_mounting_a_status_volume_is_refused(self):
        for vol in ("netcheck-rules", "netcheck-probe"):
            copy = Copy(self)

            def mutate(pod, vol=vol):
                copy.container(pod, "agent")["volumeMounts"].append(
                    {"name": vol, "mountPath": "/forge"})

            copy.edit_pod(mutate)
            self.assert_fails(copy, vol + "-mounted-only-by-" + (
                "netcheck" if vol == "netcheck-rules" else "netprobe") + "-and-proxy")

    def test_proxy_status_mount_must_be_read_only(self):
        copy = Copy(self)

        def mutate(pod):
            for m in copy.container(pod, "proxy")["volumeMounts"]:
                if m["name"] == "netcheck-rules":
                    m.pop("readOnly", None)

        copy.edit_pod(mutate)
        self.assert_fails(copy, "netcheck-rules-read-only-in-proxy")

    def test_netprobe_sharing_the_rules_volume_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "netprobe")["volumeMounts"].append(
                {"name": "netcheck-rules", "mountPath": "/r"})

        copy.edit_pod(mutate)
        self.assert_fails(copy, "netprobe-mounts-only-its-status")

    def test_status_flag_pointing_at_the_wrong_file_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            cmd = copy.container(pod, "proxy")["command"]
            cmd[cmd.index("--netfilter-probe-status") + 1] = "/run/auth-proxy-netcheck/probe/other"

        copy.edit_pod(mutate)
        self.assert_fails(copy, "proxy-netfilter-flags-match-the-checker-status-files")

    def test_proxy_without_the_self_check_flags_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            cmd = copy.container(pod, "proxy")["command"]
            i = cmd.index("--netfilter-rules-status")
            del cmd[i:i + 2]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "proxy-netfilter-flags-match-the-checker-status-files")

    def test_interval_mismatch_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for e in copy.container(pod, "netcheck")["env"]:
                if e["name"] == "INTERVAL":
                    e["value"] = "300"

        copy.edit_pod(mutate)
        self.assert_fails(copy, "self-check-interval-agrees")

    def _flag(self, copy, flag, value):
        def mutate(pod):
            cmd = copy.container(pod, "proxy")["command"]
            cmd[cmd.index(flag) + 1] = value
        copy.edit_pod(mutate)

    def test_wrong_rules_owner_uid_flag_is_refused(self):
        copy = Copy(self)
        self._flag(copy, "--netfilter-rules-uid", "1000")
        self.assert_fails(copy, "proxy-status-owner-uids-match-the-writers")

    def test_wrong_probe_owner_uid_flag_is_refused(self):
        copy = Copy(self)
        self._flag(copy, "--netfilter-probe-uid", "0")
        self.assert_fails(copy, "proxy-status-owner-uids-match-the-writers")

    def test_missing_owner_uid_flags_are_refused(self):
        copy = Copy(self)

        def mutate(pod):
            cmd = copy.container(pod, "proxy")["command"]
            i = cmd.index("--netfilter-probe-uid")
            del cmd[i:i + 2]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "proxy-status-owner-uids-match-the-writers")

    def test_agent_mounting_a_status_volume_is_refused(self):
        for vol in ("netcheck-rules", "netcheck-probe"):
            copy = Copy(self)

            def mutate(pod, vol=vol):
                copy.container(pod, "agent")["volumeMounts"].append(
                    {"name": vol, "mountPath": "/x"})

            copy.edit_pod(mutate)
            self.assert_fails(copy, "agent-cannot-write-the-status-volumes")

    def test_fsgroup_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            pod["spec"]["securityContext"]["fsGroup"] = 1000

        copy.edit_pod(mutate)
        self.assert_fails(copy, "no-fsgroup-and-no-hostpath-volumes")

    def test_hostpath_status_volume_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for v in pod["spec"]["volumes"]:
                if v["name"] == "netcheck-probe":
                    v.pop("emptyDir")
                    v["hostPath"] = {"path": "/tmp/x"}

        copy.edit_pod(mutate)
        self.assert_fails(copy, "no-fsgroup-and-no-hostpath-volumes")

    def test_unconfined_seccomp_on_netcheck_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "netcheck")["securityContext"]["seccompProfile"] = {
                "type": "Unconfined"}

        copy.edit_pod(mutate)
        self.assert_fails(copy, "pod-seccomp-runtime-default-and-no-container-override")

    def test_pod_without_seccomp_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            pod["spec"]["securityContext"].pop("seccompProfile")

        copy.edit_pod(mutate)
        self.assert_fails(copy, "pod-seccomp-runtime-default-and-no-container-override")

    def test_host_namespaces_are_refused(self):
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            copy = Copy(self)

            def mutate(pod, key=key):
                pod["spec"][key] = True

            copy.edit_pod(mutate)
            self.assert_fails(copy, "no-host-namespaces")

    def test_netcheck_with_another_command_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "netcheck")["command"] = [
                "/bin/sh", "-c", "while true; do echo state=ok > /run/netcheck/status; sleep 1; done"]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "netcheck-and-netprobe-run-the-expected-programs")

    def test_netprobe_with_another_command_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "netprobe")["command"] = ["/bin/true"]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "netcheck-and-netprobe-run-the-expected-programs")

    def test_proxy_without_the_readiness_probe_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "proxy").pop("readinessProbe")

        copy.edit_pod(mutate)
        self.assert_fails(copy, "proxy-readiness-probe-asks-its-admin-socket")

    def test_liveness_probe_on_the_proxy_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            copy.container(pod, "proxy")["livenessProbe"] = {
                "exec": {"command": ["auth-proxy", "--check-ready"]}}

        copy.edit_pod(mutate)
        self.assert_fails(copy, "proxy-has-no-liveness-probe-on-the-self-check")

    def test_netinit_without_the_snapshot_is_refused(self):
        copy = Copy(self)
        self.edit_script(copy, "netinit.sh",
                         "ip6tables -S OUTPUT > /run/expected-ip6tables\n", "")
        self.assert_fails(copy, "netinit-writes-the-snapshot-netcheck-reads")

    def test_netcheck_that_changes_rules_is_refused(self):
        copy = Copy(self)
        self.edit_script(copy, "netcheck.sh", "  echo ok\n}", "  \"$tool\" -F OUTPUT\n  echo ok\n}")
        self.assert_fails(copy, "netcheck-never-changes-rules")

    def test_netcheck_that_reads_the_wrong_snapshot_name_is_refused(self):
        copy = Copy(self)
        self.edit_script(copy, "netcheck.sh", 'exp="$EXPECT_DIR/expected-$tool"',
                         'exp="$EXPECT_DIR/rules-$tool"')
        self.assert_fails(copy, "netinit-writes-the-snapshot-netcheck-reads")

    def test_dropping_a_checker_container_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            pod["spec"]["containers"] = [
                c for c in pod["spec"]["containers"] if c["name"] != "netprobe"]

        copy.edit_pod(mutate)
        self.assert_fails(copy, "containers-agent-proxy-runtime-egress")

    # ---- Runtime container hardening (issue #24): one minimal bad manifest per rule ----

    def init_container(self, pod, name):
        return next(c for c in pod["spec"]["initContainers"] if c["name"] == name)

    def test_pod_seccomp_unconfined_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: pod["spec"]["securityContext"].__setitem__(
            "seccompProfile", {"type": "Unconfined"}))
        self.assert_fails(copy, "every-container-has-an-enforcing-seccomp-profile")

    def test_missing_pod_seccomp_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: pod["spec"]["securityContext"].pop("seccompProfile"))
        self.assert_fails(copy, "every-container-has-an-enforcing-seccomp-profile")

    def test_runtime_container_seccomp_unconfined_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: copy.container(pod, "runtime")["securityContext"].__setitem__(
            "seccompProfile", {"type": "Unconfined"}))
        self.assert_fails(copy, "every-container-has-an-enforcing-seccomp-profile")

    def test_localhost_seccomp_without_a_profile_name_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: pod["spec"]["securityContext"].__setitem__(
            "seccompProfile", {"type": "Localhost"}))
        self.assert_fails(copy, "every-container-has-an-enforcing-seccomp-profile")

    def test_apparmor_runtime_default_on_the_runtime_is_accepted(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: copy.container(pod, "runtime")["securityContext"].__setitem__(
            "appArmorProfile", {"type": "RuntimeDefault"}))
        code, out = run_validator(copy.root)
        self.assertEqual(code, 0, out)

    def test_apparmor_unconfined_field_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: copy.container(pod, "runtime")["securityContext"].__setitem__(
            "appArmorProfile", {"type": "Unconfined"}))
        self.assert_fails(copy, "apparmor-profile-if-set-is-not-unconfined")

    def test_apparmor_unconfined_annotation_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: pod["metadata"].setdefault("annotations", {}).__setitem__(
            "container.apparmor.security.beta.kubernetes.io/runtime", "unconfined"))
        self.assert_fails(copy, "apparmor-profile-if-set-is-not-unconfined")

    def test_init_container_with_a_writable_root_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: self.init_container(pod, "expiry-store-bootstrap")[
            "securityContext"].__setitem__("readOnlyRootFilesystem", False))
        self.assert_fails(copy, "every-container-drops-all-and-is-read-only-root")

    def test_privileged_egress_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: copy.container(pod, "egress")["securityContext"].__setitem__(
            "privileged", True))
        self.assert_fails(copy, "every-container-drops-all-and-is-read-only-root")

    def test_extra_capability_on_the_runtime_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: copy.container(pod, "runtime")["securityContext"][
            "capabilities"].__setitem__("add", ["NET_BIND_SERVICE"]))
        self.assert_fails(copy, "every-container-drops-all-and-is-read-only-root")

    def test_extra_capability_on_volume_prep_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: self.init_container(pod, "volume-prep")["securityContext"][
            "capabilities"].__setitem__("add", ["CHOWN", "FSETID", "DAC_OVERRIDE"]))
        self.assert_fails(copy, "every-container-drops-all-and-is-read-only-root")

    def test_bootstrap_running_as_root_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: self.init_container(pod, "expiry-store-bootstrap")[
            "securityContext"].__setitem__("runAsUser", 0))
        self.assert_fails(copy, "only-volume-prep-netinit-netcheck-run-as-root")

    def test_bootstrap_without_a_group_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: self.init_container(pod, "expiry-store-bootstrap")[
            "securityContext"].pop("runAsGroup"))
        self.assert_fails(copy, "non-root-containers-have-a-fixed-uid-and-gid")

    def test_runtime_with_a_writable_session_plane_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            for m in copy.container(pod, "runtime")["volumeMounts"]:
                if m["name"] == "session-plane":
                    m.pop("readOnly")

        copy.edit_pod(mutate)
        self.assert_fails(copy, "runtime-only-writable-mount-is-the-agent-socket-dir")

    def test_runtime_with_an_env_var_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: copy.container(pod, "runtime").__setitem__(
            "env", [{"name": "X", "value": "1"}]))
        self.assert_fails(copy, "runtime-has-no-env-port-or-envfrom")

    def test_seed_flag_naming_another_file_is_refused(self):
        copy = Copy(self)

        def mutate(pod):
            cmd = copy.container(pod, "runtime")["command"]
            cmd[cmd.index("--seed-file") + 1] = "/var/run/auth-proxy-runtime/other.seed"

        copy.edit_pod(mutate)
        self.assert_fails(copy, "runtime-seed-flag-is-the-secret-item")

    def test_ephemeral_container_mounting_the_seed_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: pod["spec"].__setitem__("ephemeralContainers", [{
            "name": "dbg", "image": "x",
            "volumeMounts": [{"name": "runtime-key", "mountPath": "/k", "readOnly": True}]}]))
        self.assert_fails(copy, "runtime-key-not-in-any-other-container-list")

    def test_seed_secret_as_env_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: copy.container(pod, "egress").__setitem__("env", [{
            "name": "SEED", "valueFrom": {"secretKeyRef": {
                "name": "auth-proxy-runtime-key", "key": "runtime_ed25519.seed"}}}]))
        self.assert_fails(copy, "runtime-key-not-referenced-by-env")

    def test_missing_grace_period_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: pod["spec"].pop("terminationGracePeriodSeconds"))
        self.assert_fails(copy, "termination-grace-period-is-short")

    def test_long_grace_period_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: pod["spec"].__setitem__("terminationGracePeriodSeconds", 300))
        self.assert_fails(copy, "termination-grace-period-is-short")

    def test_service_account_token_automount_is_refused(self):
        copy = Copy(self)
        copy.edit_pod(lambda pod: pod["spec"].__setitem__("automountServiceAccountToken", True))
        self.assert_fails(copy, "no-service-account-token-and-no-service-links")


if __name__ == "__main__":
    unittest.main()
