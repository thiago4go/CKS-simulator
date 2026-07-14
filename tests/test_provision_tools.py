import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "infra" / "provision" / "tools"
RELEASE_GATE = ROOT / "infra" / "provision" / "verify_u5_artifacts.py"


def script(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def run_bash(body: str, *args: str, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/bin/bash", "-c", body, "test", *args],
        text=True,
        capture_output=True,
        env=env,
    )


class ProvisionToolsContractTests(unittest.TestCase):
    def test_release_integrity_gate_covers_every_installed_manifest_pin(self) -> None:
        gate = RELEASE_GATE.read_text(encoding="utf-8")
        pins = {
            line.split("=", 1)[0]
            for line in (TOOLS / "versions.env").read_text(encoding="utf-8").splitlines()
            if "_INSTALLED_SHA256=" in line
        }
        self.assertEqual(len(pins), 10)
        for pin in pins:
            with self.subTest(pin=pin):
                self.assertIn(f'"{pin}"', gate)
        self.assertIn("artifact_content_sha256", gate)
        self.assertIn("_kube_bench", gate)
        self.assertIn("_docker", gate)
        self.assertIn('os.fdopen(descriptor, "wb")', gate)
        self.assertIn("_validate_release_url(response.geturl())", gate)
        self.assertNotIn('temporary.open("wb")', gate)

    def test_missing_artifact_check_is_strict_shell_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = run_bash(
                'set -u; source "$1"; artifact_is_current "' + "a" * 64 + '" "$2/missing"',
                str(TOOLS / "lib.sh"),
                temporary,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertNotIn("unbound variable", completed.stderr)

    def test_host_pinned_artifact_digest_detects_content_mode_and_type_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "tool"
            artifact.write_bytes(b"trusted tool\n")
            artifact.chmod(0o755)
            fingerprinted = run_bash(
                'source "$1"; artifact_content_sha256 "$2"',
                str(TOOLS / "lib.sh"),
                str(artifact),
            )
            self.assertEqual(fingerprinted.returncode, 0, fingerprinted.stderr)
            expected = fingerprinted.stdout.strip()
            accepted = run_bash(
                'source "$1"; artifact_is_current "$2" "$3"',
                str(TOOLS / "lib.sh"),
                expected,
                str(artifact),
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            artifact.write_bytes(b"learner modified tool\n")
            tampered = run_bash(
                'source "$1"; artifact_is_current "$2" "$3"',
                str(TOOLS / "lib.sh"),
                expected,
                str(artifact),
            )
            self.assertEqual(tampered.returncode, 1)

            artifact.write_bytes(b"trusted tool\n")
            artifact.chmod(0o644)
            wrong_mode = run_bash(
                'source "$1"; artifact_is_current "$2" "$3"',
                str(TOOLS / "lib.sh"),
                expected,
                str(artifact),
            )
            self.assertEqual(wrong_mode.returncode, 1)

            protected = root / "protected"
            protected.write_bytes(b"protected sentinel\n")
            artifact.unlink()
            artifact.symlink_to(protected)
            substituted = run_bash(
                'source "$1"; artifact_is_current "$2" "$3"',
                str(TOOLS / "lib.sh"),
                expected,
                str(artifact),
            )
            self.assertEqual(substituted.returncode, 1)
            self.assertEqual(protected.read_bytes(), b"protected sentinel\n")

            bundle = root / "bundle"
            bundle.mkdir()
            nested = bundle / "nested"
            nested.mkdir()
            (nested / "config").write_bytes(b"config")
            (bundle / "one").write_bytes(b"one")
            (bundle / "two").write_bytes(b"two")
            fingerprinted = run_bash(
                'source "$1"; artifact_content_sha256 "$2"',
                str(TOOLS / "lib.sh"),
                str(bundle),
            )
            self.assertEqual(fingerprinted.returncode, 0, fingerprinted.stderr)
            expected_tree = fingerprinted.stdout.strip()
            bundle.chmod(0o700)
            wrong_root_mode = run_bash(
                'source "$1"; artifact_is_current "$2" "$3"',
                str(TOOLS / "lib.sh"),
                expected_tree,
                str(bundle),
            )
            self.assertEqual(wrong_root_mode.returncode, 1)
            bundle.chmod(0o755)
            nested.chmod(0o700)
            wrong_directory_mode = run_bash(
                'source "$1"; artifact_is_current "$2" "$3"',
                str(TOOLS / "lib.sh"),
                expected_tree,
                str(bundle),
            )
            self.assertEqual(wrong_directory_mode.returncode, 1)
            nested.chmod(0o755)
            (bundle / "one").chmod(0o600)
            wrong_mode = run_bash(
                'source "$1"; artifact_is_current "$2" "$3"',
                str(TOOLS / "lib.sh"),
                expected_tree,
                str(bundle),
            )
            self.assertEqual(wrong_mode.returncode, 1)
            (bundle / "one").chmod(0o644)

            # This exactly collides under an unframed path/mode/content stream:
            # move member two's old header and bytes into member one, then delete two.
            (bundle / "one").write_bytes(b"one" + b"F\0two\0" + b"644\0" + b"two")
            (bundle / "two").unlink()
            boundary_attack = run_bash(
                'source "$1"; artifact_is_current "$2" "$3"',
                str(TOOLS / "lib.sh"),
                expected_tree,
                str(bundle),
            )
            self.assertEqual(boundary_attack.returncode, 1)
            (bundle / "one").write_bytes(b"one")
            (bundle / "two").write_bytes(b"two")
            (bundle / "two").unlink()
            (bundle / "two").symlink_to(protected)
            tampered = run_bash(
                'source "$1"; artifact_is_current "$2" "$3"',
                str(TOOLS / "lib.sh"),
                expected_tree,
                str(bundle),
            )
            self.assertEqual(tampered.returncode, 1)
            self.assertEqual(protected.read_bytes(), b"protected sentinel\n")

            (bundle / "two").unlink()
            os.mkfifo(bundle / "two")
            non_regular = run_bash(
                'source "$1"; artifact_is_current "$2" "$3"',
                str(TOOLS / "lib.sh"),
                expected_tree,
                str(bundle),
            )
            self.assertEqual(non_regular.returncode, 1)

    def test_artifact_tree_accepts_4096_descendants_and_rejects_4097(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(4096):
                (root / f"member-{index:04d}").touch()
            accepted = run_bash(
                'source "$1"; artifact_content_sha256 "$2"',
                str(TOOLS / "lib.sh"),
                str(root),
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            (root / "member-4096").touch()
            rejected = run_bash(
                'source "$1"; artifact_content_sha256 "$2"',
                str(TOOLS / "lib.sh"),
                str(root),
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_entrypoints_are_static_strict_shell(self) -> None:
        paths = tuple(TOOLS / name for name in ("install.sh", "addons.sh", "check.sh"))
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(path.is_file())
                contents = script(path)
                self.assertTrue(contents.startswith("#!/usr/bin/env bash\n"))
                self.assertIn("set -Eeuo pipefail", contents)
                self.assertIn("IFS=$'\\n\\t'", contents)
                self.assertIn(
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    contents,
                )
                self.assertIn("umask 077", contents)
                self.assertNotIn("eval ", contents)
                subprocess.run(["/bin/bash", "-n", str(path)], check=True)

    def test_manifest_parser_is_allowlisted_non_executable_and_fail_closed(self) -> None:
        library = TOOLS / "lib.sh"
        contents = script(library)
        self.assertIn("validate_tools_manifest_key", contents)
        self.assertNotIn('source "$CKS_TOOLS_MANIFEST"', contents)

        generated = run_bash(
            'source "$1"; load_tools_manifest "$2"; printf "%s" "$DOCKER_INSTALLED_SHA256"',
            str(library),
            str(TOOLS / "versions.env"),
        )
        self.assertEqual(generated.returncode, 0, generated.stderr)
        self.assertRegex(generated.stdout, r"^[0-9a-f]{64}$")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "valid.env"
            valid.write_text("HELM_VERSION=3.21.3\nHELM_SHA256=" + "a" * 64 + "\n")
            accepted = run_bash(
                'source "$1"; load_tools_manifest "$2"; printf "%s" "$HELM_VERSION"',
                str(library),
                str(valid),
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout, "3.21.3")

            duplicate = root / "duplicate.env"
            duplicate.write_text("HELM_VERSION=3.21.3\nHELM_VERSION=3.21.4\n")
            rejected = run_bash(
                'source "$1"; load_tools_manifest "$2"', str(library), str(duplicate)
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("duplicate manifest key", rejected.stderr)

            unknown = root / "unknown.env"
            unknown.write_text("HELM_VERSION=3.21.3\nSHELL_PAYLOAD=$(touch /tmp/nope)\n")
            rejected = run_bash(
                'source "$1"; load_tools_manifest "$2"', str(library), str(unknown)
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("not allowlisted", rejected.stderr)

            linked = root / "linked.env"
            linked.symlink_to(valid)
            rejected = run_bash(
                'source "$1"; load_tools_manifest "$2"', str(library), str(linked)
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("non-symlink", rejected.stderr)

    def test_downloads_are_https_checksum_pinned_bounded_and_remove_failures(self) -> None:
        library = TOOLS / "lib.sh"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            payload = root / "payload"
            payload.write_bytes(b"authenticated artifact\n")
            curl_log = root / "curl.args"
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                "#!/bin/bash\n"
                "set -eu\n"
                'printf "%s\\n" "$@" > "$FAKE_CURL_LOG"\n'
                "destination=\n"
                "while (($#)); do\n"
                '  if [[ $1 == --output ]]; then destination=$2; shift 2; else shift; fi\n'
                "done\n"
                'cp "$FAKE_CURL_PAYLOAD" "$destination"\n',
                encoding="utf-8",
            )
            fake_curl.chmod(0o755)
            destination = root / "download"
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:/sbin:/usr/bin:/bin",
                    "FAKE_CURL_LOG": str(curl_log),
                    "FAKE_CURL_PAYLOAD": str(payload),
                    "CKS_CONNECT_TIMEOUT_SECONDS": "7",
                    "CKS_DOWNLOAD_TIMEOUT_SECONDS": "11",
                }
            )
            accepted = run_bash(
                'source "$1"; download_sha256 test-artifact "$2" "$3" "$4"',
                str(library),
                "https://example.invalid/artifact",
                digest,
                str(destination),
                env=environment,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            arguments = curl_log.read_text(encoding="utf-8")
            for expected in (
                "--fail",
                "--location",
                "--retry",
                "--retry-all-errors",
                "--connect-timeout",
                "7",
                "--max-time",
                "11",
            ):
                self.assertIn(expected, arguments)

            rejected = run_bash(
                'source "$1"; download_sha256 test-artifact "$2" "$3" "$4"',
                str(library),
                "https://example.invalid/artifact",
                "0" * 64,
                str(destination),
                env=environment,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(destination.exists())

            rejected = run_bash(
                'source "$1"; download_sha256 test-artifact "$2" "$3" "$4"',
                str(library),
                "http://example.invalid/artifact",
                digest,
                str(destination),
                env=environment,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("HTTPS", rejected.stderr)

    def test_role_installation_is_pinned_idempotent_and_preserves_cluster_runtime(self) -> None:
        contents = script(TOOLS / "install.sh")
        for role in ("control-plane", "worker1", "worker2"):
            self.assertIn(f"{role})", contents)
        for version in ("3.21.3", "3.6.6", "0.15.6", "29.6.1"):
            self.assertIn(version, contents)
        for installer in (
            "install_control_plane_tools",
            "install_kube_bench",
            "install_gvisor_systrap",
            "install_apparmor_smoke_profile",
            "install_isolated_docker",
        ):
            self.assertIn(installer, contents)
        self.assertIn("artifact_is_current", contents)
        self.assertNotIn("record_artifact_digest", contents)
        self.assertIn("INSTALLED_SHA256", contents)
        self.assertNotIn("apt-get", contents)

        self.assertIn('default_runtime_name = "runc"', contents)
        self.assertIn('runtime_type = "io.containerd.runsc.v1"', contents)
        self.assertIn('platform = "systrap"', contents)
        self.assertIn("containerd_config_changed", contents)
        self.assertIn("gvisor-applied.sha256", contents)
        self.assertIn("restart_required", contents)
        self.assertLess(
            contents.index("systemctl restart containerd"),
            contents.index('printf \'%s\\n\' "$desired_digest"'),
        )
        self.assertNotIn("systemctl stop containerd", contents)
        self.assertNotIn("systemctl disable containerd", contents)
        self.assertNotIn("systemctl disable kubelet", contents)

        self.assertIn("cks-docker.service", contents)
        self.assertIn("unix:///run/docker.sock", contents)
        self.assertIn('"ip-forward-no-drop": true', contents)
        self.assertIn("/var/lib/cks-docker", contents)
        self.assertNotIn("docker.service docker.socket", contents)

    def test_checks_are_behavioral_and_training_label_is_explicit(self) -> None:
        contents = script(TOOLS / "check.sh")
        for token in (
            "apparmor_allow_deny_smoke",
            "gvisor_pod_smoke",
            "docker_and_kubernetes_smoke",
            "falco_fresh_event_smoke",
            "ingress_generated_tls_smoke",
            "kubernetes_cilium_health",
            "cilium_network_policy_smoke",
            "etcdctl_endpoint_health",
            "KUBE_BENCH_TRAINING_ONLY",
            "runtimeClassName: ${runtime}",
            "appArmorProfile:",
            "run --rm",
            "cilium status --wait",
            "kubectl get --raw=/readyz",
            "openssl req -x509",
            "curl --fail",
            "--since-time",
        ):
            self.assertIn(token, contents)
        self.assertIn("CKS_KUBE_BENCH_TIMEOUT_SECONDS", contents)
        self.assertIn("CKS_CLUSTER_CHECK_TIMEOUT_SECONDS", contents)
        for target in ("health", "apparmor-pod", "gvisor-pod", "falco", "ingress"):
            self.assertIn(f"{target})", contents)
        self.assertRegex(contents, r"case \"?\$\{?rc\}?\"? in\s*\n\s*0\|1\)")

    def test_addons_use_verified_local_charts_and_digest_pinned_images(self) -> None:
        contents = script(TOOLS / "addons.sh")
        for version in ("0.44.1", "9.1.0", "1.15.1", "4.15.1"):
            self.assertIn(version, contents)
        self.assertIn("modern_ebpf", contents)
        self.assertIn("download_sha256", contents)
        self.assertIn("assert_rendered_images_pinned", contents)
        self.assertIn("assert_digest_pinned_image", contents)
        self.assertIn("@sha256:", script(TOOLS / "lib.sh"))
        self.assertIn("helm upgrade --install falco", contents)
        self.assertIn("helm upgrade --install ingress-nginx", contents)
        self.assertNotIn("helm repo add", contents)
        self.assertNotIn("helm install falco falcosecurity/", contents)
        self.assertNotIn("helm install ingress-nginx ingress-nginx/", contents)

    def test_capability_assets_do_not_ship_solved_scenario_state(self) -> None:
        combined = "\n".join(script(path) for path in sorted(TOOLS.glob("*.sh"))).lower()
        for forbidden in (
            "cks-deny-write",
            "reference solution",
            "scenario 09",
            "scenario 10",
            "scenario 16",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined)
        self.assertIn("cks-simulator-capability-smoke", combined)


if __name__ == "__main__":
    unittest.main()
