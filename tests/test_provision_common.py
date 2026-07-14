from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "infra" / "provision" / "common"
VERSIONS_JSON = ROOT / "infra" / "versions.json"
GENERATED_MANIFEST = COMMON / "versions.env"


def run_bash(body: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/bash", "-c", body, "test", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
    )


def parse_manifest(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise AssertionError(f"invalid generated manifest line: {raw_line!r}")
        values[key] = value
    return values


class CommonProvisionContractTests(unittest.TestCase):
    def test_generated_manifest_is_exactly_in_sync_with_versions_json(self) -> None:
        result = subprocess.run(
            [
                "python3",
                str(COMMON / "render_versions.py"),
                "--check",
                "--source",
                str(VERSIONS_JSON),
                "--output",
                str(GENERATED_MANIFEST),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        source = json.loads(VERSIONS_JSON.read_text(encoding="utf-8"))
        manifest = parse_manifest(GENERATED_MANIFEST)
        self.assertEqual(manifest["UBUNTU_VERSION"], source["ubuntu"]["version"])
        self.assertEqual(manifest["UBUNTU_IMAGE_ARCH"], source["ubuntu"]["arch"])
        self.assertEqual(
            manifest["KUBERNETES_VERSION"], f'v{source["kubernetes"]["version"]}'
        )
        self.assertEqual(
            manifest["KUBERNETES_PACKAGE_VERSION"],
            f'{source["kubernetes"]["version"]}-1.1',
        )
        self.assertEqual(
            manifest["CONTAINERD_RUNTIME_VERSION"], source["containerd"]["version"]
        )
        self.assertEqual(manifest["CONTAINERD_PACKAGE_NAME"], source["containerd"]["package"])
        self.assertEqual(manifest["CRI_TOOLS_VERSION"], source["crictl"]["version"])

    def test_shell_entrypoints_have_valid_syntax_and_strict_mode(self) -> None:
        for script in sorted(COMMON.glob("*.sh")):
            with self.subTest(script=script.name):
                syntax = subprocess.run(
                    ["/bin/bash", "-n", str(script)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(syntax.returncode, 0, syntax.stderr)
        for entrypoint in (COMMON / "install.sh", COMMON / "check.sh"):
            text = entrypoint.read_text(encoding="utf-8")
            self.assertIn("set -Eeuo pipefail", text)
            self.assertIn("IFS=$'\\n\\t'", text)
            self.assertTrue(os.access(entrypoint, os.X_OK), f"{entrypoint} is not executable")

    def test_manifest_loader_accepts_only_the_generated_allowlisted_contract(self) -> None:
        library = str(COMMON / "lib.sh")
        loaded = run_bash(
            'source "$1"; load_manifest "$2" || exit; printf "%s|%s|%s" "$KUBERNETES_VERSION" "$CONTAINERD_RUNTIME_VERSION" "$CRI_TOOLS_VERSION"',
            library,
            str(GENERATED_MANIFEST),
        )
        self.assertEqual(loaded.returncode, 0, loaded.stderr)
        self.assertEqual(loaded.stdout, "v1.35.6|2.2.6|1.35.0")

        readonly_caller = run_bash(
            'readonly manifest="$2"; source "$1"; load_manifest "$manifest"; '
            'printf "%s" "$KUBERNETES_VERSION"',
            str(COMMON / "lib.sh"),
            str(COMMON / "versions.env"),
        )
        self.assertEqual(readonly_caller.returncode, 0, readonly_caller.stderr)

        lima_hostname = run_bash(
            'source "$1"; assert_node_hostname "$2" "lima-$2"',
            library,
            "cks-0123456789abcdef-candidate",
        )
        self.assertEqual(lima_hostname.returncode, 0, lima_hostname.stderr)
        self.assertEqual(readonly_caller.stdout, "v1.35.6")

        with tempfile.TemporaryDirectory() as temporary:
            hostile = Path(temporary) / "versions.env"
            hostile.write_text(
                GENERATED_MANIFEST.read_text(encoding="utf-8") + "PATH=/tmp/hostile\n",
                encoding="utf-8",
            )
            rejected = run_bash(
                'source "$1"; load_manifest "$2"', library, str(hostile)
            )
            self.assertNotEqual(rejected.returncode, 0)

            duplicate = Path(temporary) / "duplicate.env"
            duplicate.write_text(
                GENERATED_MANIFEST.read_text(encoding="utf-8") + "KUBERNETES_VERSION=v0.0.0\n",
                encoding="utf-8",
            )
            rejected = run_bash(
                'source "$1"; load_manifest "$2"', library, str(duplicate)
            )
            self.assertNotEqual(rejected.returncode, 0)

            corrupted = Path(temporary) / "corrupted.env"
            corrupted.write_text(
                GENERATED_MANIFEST.read_text(encoding="utf-8").replace(
                    "KUBERNETES_APT_KEY_URL=https://", "KUBERNETES_APT_KEY_URL=--output=/tmp/pwned#https://"
                ),
                encoding="utf-8",
            )
            rejected = run_bash(
                'source "$1"; load_manifest "$2"', library, str(corrupted)
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_identity_contract_rejects_forged_or_unsafe_arguments(self) -> None:
        library = str(COMMON / "lib.sh")
        lab_id = "01234567-89ab-cdef-8000-000000000001"
        valid = run_bash(
            'source "$1"; validate_identity_args "$2" "$3" "$4" "$5" "$6"',
            library,
            "worker1",
            lab_id,
            "cks-0123456789abcdef-worker1",
            "cks-0123456789abcdef-worker1",
            "192.0.2.31",
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)

        invalid_cases = (
            ("worker-1", lab_id, "cks-0123456789abcdef-worker-1", "node", "192.0.2.31"),
            ("worker1", "not-a-uuid", "cks-0123456789abcdef-worker1", "node", "192.0.2.31"),
            ("worker1", lab_id, "unmanaged-worker1", "node", "192.0.2.31"),
            ("worker1", lab_id, "cks-0123456789abcdef-worker1", "-option", "192.0.2.31"),
            ("worker1", lab_id, "cks-0123456789abcdef-worker1", "node", "999.1.2.3"),
        )
        for case in invalid_cases:
            with self.subTest(case=case):
                result = run_bash(
                    'source "$1"; validate_identity_args "$2" "$3" "$4" "$5" "$6"',
                    library,
                    *case,
                )
                self.assertNotEqual(result.returncode, 0)

        readonly_caller = run_bash(
            'readonly role=candidate lab_id=01234567-89ab-cdef-8000-000000000001 '
            'handle=cks-0123456789abcdef-candidate node_name=cks-0123456789abcdef-candidate '
            'node_ip=192.0.2.20; source "$1"; '
            'validate_identity_args "$role" "$lab_id" "$handle" "$node_name" "$node_ip"',
            library,
        )
        self.assertEqual(readonly_caller.returncode, 0, readonly_caller.stderr)

    def test_cluster_input_contract_rejects_cidr_and_port_failures(self) -> None:
        library = str(COMMON / "lib.sh")
        valid = run_bash(
            'source "$1"; validate_cluster_inputs "$2" "$3" "$4" "$5" "$6"',
            library,
            "control-plane",
            "192.0.2.20",
            "10.244.0.0/16",
            "10.96.0.0/12",
            "6443,2379,2380,10250,10257,10259",
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)

        invalid_cases = (
            ("control-plane", "192.0.2.20", "10.96.1.0/24", "10.96.0.0/12", "6443,2379,2380,10250,10257,10259"),
            ("worker1", "10.244.0.9", "10.244.0.0/16", "10.96.0.0/12", "10250,10256"),
            ("worker2", "192.0.2.32", "invalid", "10.96.0.0/12", "10250,10256"),
            ("worker1", "192.0.2.31", "10.244.0.0/16", "10.96.0.0/12", "10250,22"),
            ("candidate", "192.0.2.10", "10.244.0.0/16", "10.96.0.0/12", "10250"),
        )
        for case in invalid_cases:
            with self.subTest(case=case):
                result = run_bash(
                    'source "$1"; validate_cluster_inputs "$2" "$3" "$4" "$5" "$6"',
                    library,
                    *case,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_behavioral_preconditions_fail_closed(self) -> None:
        library = str(COMMON / "lib.sh")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
            (root / "swaps").write_text("Filename Type Size Used Priority\n", encoding="utf-8")
            (root / "fstab").write_text("UUID=root / ext4 defaults 0 1\n", encoding="utf-8")
            sysctl_root = root / "sysctl"
            for relative in (
                "net/ipv4/ip_forward",
                "net/bridge/bridge-nf-call-iptables",
                "net/bridge/bridge-nf-call-ip6tables",
            ):
                path = sysctl_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("1\n", encoding="utf-8")

            passed = run_bash(
                'source "$1"; assert_cgroup_v2 "$2"; assert_swap_disabled "$3" "$4"; assert_forwarding_sysctls "$5"',
                library,
                str(root / "cgroup.controllers"),
                str(root / "swaps"),
                str(root / "fstab"),
                str(sysctl_root),
            )
            self.assertEqual(passed.returncode, 0, passed.stderr)

            (root / "cgroup.controllers").unlink()
            failed = run_bash(
                'source "$1"; assert_cgroup_v2 "$2"', library, str(root / "cgroup.controllers")
            )
            self.assertNotEqual(failed.returncode, 0)

            (root / "swaps").write_text(
                "Filename Type Size Used Priority\n/swapfile file 1024 0 -2\n",
                encoding="utf-8",
            )
            failed = run_bash(
                'source "$1"; assert_swap_disabled "$2" "$3"',
                library,
                str(root / "swaps"),
                str(root / "fstab"),
            )
            self.assertNotEqual(failed.returncode, 0)

            (sysctl_root / "net/ipv4/ip_forward").write_text("0\n", encoding="utf-8")
            failed = run_bash(
                'source "$1"; assert_forwarding_sysctls "$2"', library, str(sysctl_root)
            )
            self.assertNotEqual(failed.returncode, 0)

    def test_containerd_and_port_checks_are_behavioral(self) -> None:
        library = str(COMMON / "lib.sh")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            containerd = root / "config.toml"
            crictl = root / "crictl.yaml"
            listeners = root / "listeners"
            containerd.write_text(
                "version = 3\n[grpc]\n  address = \"/run/containerd/containerd.sock\"\n"
                "[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]\n"
                "  SystemdCgroup = true\n",
                encoding="utf-8",
            )
            crictl.write_text(
                "runtime-endpoint: unix:///run/containerd/containerd.sock\n"
                "image-endpoint: unix:///run/containerd/containerd.sock\n",
                encoding="utf-8",
            )
            listeners.write_text("LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n", encoding="utf-8")

            passed = run_bash(
                'source "$1"; assert_containerd_configuration "$2" "$3"; assert_ports_available "$4" "$5"',
                library,
                str(containerd),
                str(crictl),
                "6443,2379,2380,10250,10257,10259",
                str(listeners),
            )
            self.assertEqual(passed.returncode, 0, passed.stderr)

            containerd.write_text(containerd.read_text().replace("true", "false"), encoding="utf-8")
            failed = run_bash(
                'source "$1"; assert_containerd_configuration "$2" "$3"',
                library,
                str(containerd),
                str(crictl),
            )
            self.assertNotEqual(failed.returncode, 0)

            listeners.write_text("LISTEN 0 4096 0.0.0.0:6443 0.0.0.0:*\n", encoding="utf-8")
            failed = run_bash(
                'source "$1"; assert_ports_available "$2" "$3"',
                library,
                "6443,2379,2380,10250,10257,10259",
                str(listeners),
            )
            self.assertNotEqual(failed.returncode, 0)

    def test_hostname_and_kubelet_endpoint_checks_fail_closed(self) -> None:
        library = str(COMMON / "lib.sh")
        with tempfile.TemporaryDirectory() as temporary:
            defaults = Path(temporary) / "kubelet"
            defaults.write_text(
                "KUBELET_EXTRA_ARGS=--container-runtime-endpoint=unix:///run/containerd/containerd.sock --node-ip=192.0.2.31\n",
                encoding="utf-8",
            )
            passed = run_bash(
                'source "$1"; assert_node_hostname "$2" "$3"; assert_kubelet_defaults "$4" "$5"',
                library,
                "cks-0123456789abcdef-worker1",
                "cks-0123456789abcdef-worker1",
                "192.0.2.31",
                str(defaults),
            )
            self.assertEqual(passed.returncode, 0, passed.stderr)

            wrong_hostname = run_bash(
                'source "$1"; assert_node_hostname "$2" "$3"',
                library,
                "cks-0123456789abcdef-worker1",
                "unmanaged",
            )
            self.assertNotEqual(wrong_hostname.returncode, 0)
            wrong_ip = run_bash(
                'source "$1"; assert_kubelet_defaults "$2" "$3"',
                library,
                "192.0.2.99",
                str(defaults),
            )
            self.assertNotEqual(wrong_ip.returncode, 0)

    def test_common_provisioning_excludes_candidate_tools_and_solved_policies(self) -> None:
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(COMMON.glob("*"))
            if path.is_file() and path.suffix in {".sh", ".env"}
        )
        forbidden = (
            "falco",
            "trivy",
            "kube-bench",
            "runsc",
            "gvisor",
            "helm",
            "cilium",
            "networkpolicy",
            "apparmor_parser",
            "docker daemon",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, combined.lower())

    def test_node_convergence_checks_pins_and_avoids_unconditional_runtime_restart(self) -> None:
        install = (COMMON / "install.sh").read_text(encoding="utf-8")
        check = (COMMON / "check.sh").read_text(encoding="utf-8")
        for package in (
            '"$CONTAINERD_PACKAGE_NAME" "$CONTAINERD_PACKAGE_VERSION"',
            'kubelet "$KUBERNETES_PACKAGE_VERSION"',
            'kubeadm "$KUBERNETES_PACKAGE_VERSION"',
            'kubectl "$KUBERNETES_PACKAGE_VERSION"',
            'cri-tools "$CRI_TOOLS_PACKAGE_VERSION"',
        ):
            with self.subTest(package=package):
                self.assertIn(f"assert_package_version {package}", install)
                self.assertIn(f"assert_package_version {package}", check)
        self.assertIn("containerd_config_changed=$CKS_INSTALL_TEXT_CHANGED", install)
        self.assertIn('if [[ "$containerd_config_changed" == 1 ]]', install)
        self.assertIn("--allow-downgrades --allow-change-held-packages", install)
        self.assertIn("/etc/systemd/zram-generator.conf", install)
        self.assertIn('assert_ports_available "$required_ports"', check)
        self.assertNotIn("systemctl restart containerd\nsystemctl", install)


if __name__ == "__main__":
    unittest.main()
