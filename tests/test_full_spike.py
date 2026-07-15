import importlib.util
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import ANY, patch


ROOT = Path(__file__).resolve().parents[1]
HOST_PATH = ROOT / "infra" / "spike" / "host.py"


def load_host_module():
    spec = importlib.util.spec_from_file_location("cks_full_spike_host", HOST_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load full-spike host module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FullSpikeContractTests(unittest.TestCase):
    def create_validated_lab(self, host, root: Path, lab_id: str = "cks-spike-test"):
        claim = host.new_claim(lab_id)
        claim["status"] = "base-validated"
        claim["addresses"] = {"worker1": "192.0.2.10"}
        host.write_claim(host.claim_path(lab_id), claim)
        receipt = {
            "schema": 1,
            "lab_id": lab_id,
            "scope": "base",
            "checks": [],
            "passed": True,
            "provenance": claim["provenance"],
        }
        host.write_receipt(lab_id, claim, receipt)
        return claim

    def test_version_manifest_freezes_release_inputs(self):
        manifest = json.loads((ROOT / "infra" / "versions.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["lima"]["version"], "2.1.4")
        self.assertEqual(
            manifest["lima"]["darwin_arm64_sha256"],
            "14c5b283f1c5eb4078e5a300b8d241f69197a3e41326dfc685a69c9455917acf",
        )
        self.assertEqual(manifest["kubernetes"]["version"], "1.35.6")
        self.assertEqual(manifest["cilium"]["version"], "1.19.5")
        self.assertEqual(manifest["ubuntu"]["release"], "release-20260615")
        self.assertEqual(
            manifest["ubuntu"]["image_digest"],
            "sha256:cafa1a965b591b7c4184b484ffd8e625981a79d48f9b4ae8a4adf7b4c5ade927",
        )
        self.assertEqual(manifest["gvisor"]["platform"], "systrap")
        self.assertEqual(manifest["falco"]["driver"], "modern_ebpf")
        self.assertRegex(manifest["falco"]["image"], r"@sha256:[0-9a-f]{64}$")
        self.assertTrue(manifest["docker"]["ip_forward_no_drop"])
        self.assertEqual(manifest["kube_bench"]["mode"], "training-only")
        load_host_module().load_versions()

    def test_every_role_has_a_zero_mount_vz_template(self):
        for role in ("candidate", "control-plane", "worker1", "worker2"):
            with self.subTest(role=role):
                contents = (ROOT / "infra" / "spike" / "lima" / f"{role}.yaml").read_text(encoding="utf-8")
                self.assertIn("vmType: vz", contents)
                self.assertIn("arch: aarch64", contents)
                self.assertIn("mounts: []", contents)
                self.assertIn("user-v2", contents)
                self.assertNotIn("hostSocket", contents)

    def test_release_cilium_matrix_is_local_and_deterministic(self):
        script = (ROOT / "infra" / "spike" / "guest" / "60-validate-capabilities.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("CILIUM_LOCAL_TESTS", script)
        self.assertIn('cilium connectivity test --test "$CILIUM_LOCAL_TESTS"', script)
        self.assertIn("Test [pod-to-itself-via-service]", script)
        self.assertIn("Test [no-unexpected-packet-drops]", script)
        self.assertIn("All 2 tests (4 actions) successful", script)
        self.assertIn("rollout status daemonset/cilium --timeout=5m", script)
        self.assertIn("rollout status daemonset/cilium-envoy --timeout=5m", script)
        self.assertIn("get daemonset cilium-envoy -o json", script)
        self.assertIn("post_docker_cilium_probe() {\n  cilium_version_probe\n  cilium_connectivity_probe\n}", script)
        self.assertIn(
            "probe cilium-connectivity-after-docker post_docker_cilium_probe",
            script,
        )
        self.assertIn("pod-to-itself-via-service/pod-to-itself-via-service", script)
        self.assertIn("no-unexpected-packet-drops/no-unexpected-packet-drops", script)
        self.assertNotIn("client-ingress|client-egress", script)
        self.assertNotIn("pod-to-world", script)
        self.assertNotIn("to-fqdns", script)

    def test_control_plane_consumes_the_verified_local_cilium_chart(self):
        script = (ROOT / "infra" / "spike" / "guest" / "30-control-plane.sh").read_text(
            encoding="utf-8"
        )
        manifest = (ROOT / "infra" / "spike" / "guest" / "versions.env").read_text(
            encoding="utf-8"
        )
        self.assertIn("CILIUM_CHART_URL=", manifest)
        self.assertRegex(manifest, r"CILIUM_CHART_SHA256=[0-9a-f]{64}")
        self.assertIn('download_verified cilium-chart "$CILIUM_CHART_URL"', script)
        self.assertIn('--chart-directory "$chart_dir"', script)

    def test_falco_probe_is_pinned_and_does_not_require_mutable_metadata_plugins(self):
        script = (ROOT / "infra" / "spike" / "guest" / "60-validate-capabilities.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("@sha256:", script)
        self.assertIn("collectors:\n  enabled: false", script)
        self.assertIn("config_files: []", script)
        self.assertIn(".falco.config_files == []", script)
        self.assertIn('rules_files == ["/etc/falco/rules.d"]', script)
        self.assertIn("CKS_RUNTIME_EVENT nonce=$nonce", script)
        self.assertIn("fd.name = /tmp/$probe_file", script)
        self.assertNotIn("%k8s.pod.name", script)
        self.assertNotIn("CKS_SENSITIVE_FILE", script)

    def test_lab_ids_and_claims_are_fail_closed(self):
        host = load_host_module()
        for invalid in ("", "-leading", "has space", "has\nnewline", "a" * 49):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                host.validate_lab_id(invalid)
        self.assertEqual(host.validate_lab_id("cks-spike-a1b2c3"), "cks-spike-a1b2c3")

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "claim.json"
            claim = host.new_claim("cks-spike-test")
            expected = claim["instances"]
            host.write_claim_exclusive(path, claim)
            with self.assertRaises(FileExistsError):
                host.write_claim_exclusive(path, claim)
            loaded = host.load_owned_claim(path, "cks-spike-test")
            self.assertEqual(loaded["instances"], expected)
            path.write_text('{"managed_by":"other"}\n', encoding="utf-8")
            with self.assertRaises(RuntimeError):
                host.load_owned_claim(path, "cks-spike-test")

    def test_destroy_uses_only_claimed_exact_handles(self):
        host = load_host_module()
        calls = []

        def runner(argv, **_kwargs):
            calls.append(argv)
            return host.CommandResult(0, "", "")

        claim = host.new_claim("cks-spike-test")
        claim["created_instances"] = claim["instances"][:2]
        host.destroy_instances(claim, runner=runner)
        self.assertEqual(
            calls,
            [
                ["limactl", "stop", "--force", claim["instances"][1]],
                ["limactl", "delete", "--force", claim["instances"][1]],
                ["limactl", "stop", "--force", claim["instances"][0]],
                ["limactl", "delete", "--force", claim["instances"][0]],
            ],
        )

    def test_provider_handles_are_unpredictable_and_bound_to_the_claim_uuid(self):
        host = load_host_module()
        first = host.new_claim("cks-spike-test")
        second = host.new_claim("cks-spike-test")

        self.assertNotEqual(first["claim_uuid"], second["claim_uuid"])
        self.assertNotEqual(first["instances"], second["instances"])
        self.assertEqual(
            first["instances"],
            host.instance_names("cks-spike-test", first["claim_uuid"]),
        )
        for handle in first["instances"]:
            self.assertRegex(handle, r"^cks-[0-9a-f]{16}-(candidate|control-plane|worker1|worker2)$")
            self.assertLessEqual(len(handle), 63)

    def test_standalone_preflight_rejects_an_existing_lab_claim(self):
        host = load_host_module()
        lab_id = "cks-spike-test"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            claim = host.new_claim(lab_id)
            host.write_claim_exclusive(host.claim_path(lab_id), claim)

            def runner(argv, **_kwargs):
                if argv[-1] == "--version":
                    return host.CommandResult(0, "limactl version 2.1.4", "")
                if argv[-1] == "--list-drivers":
                    return host.CommandResult(0, "vz\n", "")
                return host.CommandResult(0, "", "")

            checks = host.preflight(lab_id, runner=runner)
            availability = next(check for check in checks if check["name"] == "lab id available")
            self.assertFalse(availability["passed"])
            self.assertIn("reserves this lab id", availability["detail"])

    def test_pending_instance_closes_creation_crash_window_and_is_exactly_owned(self):
        host = load_host_module()
        lab_id = "cks-spike-test"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ), patch.object(host, "preflight", return_value=[]):
            with self.assertRaises(KeyboardInterrupt):
                host.provision_vms(
                    lab_id,
                    runner=lambda argv, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
                )
            claim = host.load_owned_claim(host.claim_path(lab_id), lab_id)
            self.assertEqual(claim["pending_instance"], claim["instances"][0])
            self.assertEqual(claim["created_instances"], [])

            calls = []

            def cleanup_runner(argv, **_kwargs):
                calls.append(argv)
                return host.CommandResult(0, "", "")

            host.destroy_instances(claim, runner=cleanup_runner)
            self.assertEqual(
                calls,
                [
                    ["limactl", "stop", "--force", claim["instances"][0]],
                    ["limactl", "delete", "--force", claim["instances"][0]],
                ],
            )

    def test_known_start_failure_keeps_pending_instance_for_exact_cleanup(self):
        host = load_host_module()
        lab_id = "cks-spike-test"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ), patch.object(host, "preflight", return_value=[]):
            with self.assertRaisesRegex(RuntimeError, "failed to start"):
                host.provision_vms(lab_id, runner=lambda argv, **kwargs: host.CommandResult(2, "", "no"))
            claim = host.load_owned_claim(host.claim_path(lab_id), lab_id)
            self.assertEqual(claim["pending_instance"], claim["instances"][0])
            self.assertEqual(claim["created_instances"], [])

    def test_diagnostics_are_redacted_and_control_sanitized(self):
        host = load_host_module()
        value = "token=abcdef.0123456789abcdef\x1b[31m\x00"
        sanitized = host.redact(value)
        self.assertNotIn("0123456789abcdef", sanitized)
        self.assertNotIn("\x1b", sanitized)
        self.assertNotIn("\x00", sanitized)
        bounded = host._bounded("x" * 8192, 4096)
        self.assertLessEqual(len(bounded.encode("utf-8")), 4096)
        self.assertTrue(bounded.endswith("<truncated>\n"))

    def test_diagnostics_redact_kubeconfigs_pem_and_authorization_secrets(self):
        host = load_host_module()
        value = """client-certificate-data: Y2VydA==
client-key-data: a2V5
certificate-authority-data: Y2E=
certificate-key: abcdef
secret=top-secret
Authorization: Basic dXNlcjpwYXNz
-----BEGIN PRIVATE KEY-----
private-material
-----END PRIVATE KEY-----
"""
        sanitized = host.redact(value)
        for secret in ("Y2VydA==", "a2V5", "Y2E=", "abcdef", "top-secret", "dXNlcjpwYXNz", "private-material"):
            self.assertNotIn(secret, sanitized)
        self.assertIn("client-certificate-data: <redacted>", sanitized)
        self.assertIn("Authorization: Basic <redacted>", sanitized)
        self.assertIn("-----BEGIN PRIVATE KEY-----", sanitized)

    def test_bounded_redacts_before_enforcing_utf8_byte_limit(self):
        host = load_host_module()
        marker = "\n<truncated>\n"

        expanded = host._bounded("password=x " + "z" * 20, 24)
        self.assertNotIn("password=x", expanded)
        self.assertLessEqual(len(expanded.encode("utf-8")), 24)
        self.assertTrue(expanded.endswith(marker))

        multibyte = host._bounded("é" * 20, 18)
        self.assertLessEqual(len(multibyte.encode("utf-8")), 18)
        self.assertTrue(multibyte.endswith(marker))
        self.assertNotIn("�", multibyte)

        self.assertEqual(host._bounded("anything", 0), "")
        self.assertEqual(host._bounded("anything", 1), "\n")
        self.assertEqual(host._bounded("x" * 14, len(marker.encode("ascii"))), marker)
        self.assertEqual(host._bounded("é", 2), "é")

    def test_timeout_partial_bytes_are_preserved_and_redacted(self):
        host = load_host_module()
        expired = subprocess.TimeoutExpired(
            ["probe"],
            3,
            output=b"partial \xc3\xa9 token=abcdef.0123456789abcdef",
            stderr=b"still running",
        )
        with patch.object(host.subprocess, "run", side_effect=expired):
            result = host.run_command(["probe"], timeout=3)
        self.assertEqual(result.returncode, 124)
        self.assertIn("partial é", result.stdout)
        self.assertNotIn("0123456789abcdef", result.stdout)
        self.assertIn("still running", result.stderr)
        self.assertIn("timed out after 3s", result.stderr)

    def test_claim_provenance_hashes_every_staged_input_and_detects_drift(self):
        host = load_host_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest = root / "guest"
            guest.mkdir()
            templates = root / "lima"
            templates.mkdir()
            host_file = root / "host.py"
            versions = root / "versions.json"
            script_a = guest / "10-a.sh"
            script_b = guest / "20-b.sh"
            host_file.write_text("host source\n", encoding="utf-8")
            versions.write_text("{}\n", encoding="utf-8")
            script_a.write_text("a\n", encoding="utf-8")
            script_b.write_bytes(b"b\x00\n")
            template_files = {}
            for role in host.INSTANCE_ROLES:
                template = templates / f"{role}.yaml"
                template.write_text(f"role: {role}\n", encoding="utf-8")
                template_files[f"infra/spike/lima/{role}.yaml"] = hashlib.sha256(
                    template.read_bytes()
                ).hexdigest()

            with (
                patch.object(host, "HOST_PATH", host_file),
                patch.object(host, "VERSIONS_PATH", versions),
                patch.object(host, "GUEST_DIR", guest),
                patch.object(host, "TEMPLATES_DIR", templates),
            ):
                claim = host.new_claim("cks-spike-test")
                identities = claim["provenance"]["sha256"]
                self.assertEqual(claim["provenance"]["claim_uuid"], claim["claim_uuid"])
                self.assertEqual(
                    identities,
                    {
                        "infra/spike/guest/10-a.sh": hashlib.sha256(script_a.read_bytes()).hexdigest(),
                        "infra/spike/guest/20-b.sh": hashlib.sha256(script_b.read_bytes()).hexdigest(),
                        "infra/spike/host.py": hashlib.sha256(host_file.read_bytes()).hexdigest(),
                        "infra/versions.json": hashlib.sha256(versions.read_bytes()).hexdigest(),
                        **template_files,
                    },
                )
                calls = []
                script_a.write_text("changed\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "source identity"):
                    host.stage_guest_assets(claim, runner=lambda argv, **kwargs: calls.append(argv))
                self.assertEqual(calls, [])

    def test_probe_result_denominators_are_exact(self):
        host = load_host_module()
        for phase, expected in host.EXPECTED_PROBE_IDS.items():
            transcript = "\n".join(f"PROBE_RESULT {probe_id} PASS" for probe_id in expected)
            parsed = host.parse_probe_results(phase, transcript)
            self.assertEqual([item["id"] for item in parsed], list(expected))

            bad_transcripts = {
                "missing": "\n".join(transcript.splitlines()[:-1]),
                "duplicate": transcript + f"\nPROBE_RESULT {expected[0]} PASS",
                "failed": transcript.replace(
                    f"PROBE_RESULT {expected[0]} PASS", f"PROBE_RESULT {expected[0]} FAIL"
                ),
                "unknown": transcript + "\nPROBE_RESULT undeclared-probe PASS",
                "malformed": transcript + "\nPROBE_RESULT malformed",
            }
            for problem, bad in bad_transcripts.items():
                with self.subTest(phase=phase, problem=problem), self.assertRaises(RuntimeError):
                    host.parse_probe_results(phase, bad)

    def test_capability_failure_persists_bounded_receipt_with_stdout(self):
        host = load_host_module()
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            claim = self.create_validated_lab(host, Path(temporary))
            calls = 0

            def runner(argv, **_kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    return host.CommandResult(9, "useful stdout " + "é" * 5000, "password=hunter2")
                return host.CommandResult(0, "ok", "")

            with self.assertRaisesRegex(RuntimeError, "gVisor systrap installation"):
                host.validate_security_capabilities(claim["lab_id"], runner=runner)

            receipt = json.loads(host.receipt_path(claim["lab_id"]).read_text(encoding="utf-8"))
            self.assertEqual(receipt["capability_status"], "failed")
            self.assertFalse(receipt["passed"])
            self.assertEqual(len(receipt["capability_checks"]), 2)
            failed = receipt["capability_checks"][-1]
            self.assertFalse(failed["passed"])
            self.assertIn("useful stdout", failed["detail"])
            self.assertNotIn("hunter2", failed["detail"])
            self.assertLessEqual(len(failed["detail"].encode("utf-8")), 4096)
            persisted_claim = host.load_owned_claim(host.claim_path(claim["lab_id"]), claim["lab_id"])
            self.assertEqual(persisted_claim["status"], "capability-degraded")

    def test_capability_transcripts_are_recorded_as_structured_results(self):
        host = load_host_module()
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            claim = self.create_validated_lab(host, Path(temporary))

            def runner(argv, **_kwargs):
                if any(part.endswith("/60-validate-capabilities.sh") for part in argv):
                    phase = "baseline" if "baseline" in argv else "post-docker"
                    stdout = "\n".join(
                        f"PROBE_RESULT {probe_id} PASS" for probe_id in host.EXPECTED_PROBE_IDS[phase]
                    )
                    return host.CommandResult(0, stdout, "")
                return host.CommandResult(0, "ok", "")

            receipt = host.validate_security_capabilities(claim["lab_id"], runner=runner)
            self.assertTrue(receipt["passed"])
            self.assertEqual(receipt["capability_status"], "complete")
            probe_checks = [check for check in receipt["capability_checks"] if "probe_results" in check]
            self.assertEqual([check["probe_phase"] for check in probe_checks], ["baseline", "post-docker"])
            self.assertEqual(
                [len(check["probe_results"]) for check in probe_checks],
                [len(host.EXPECTED_PROBE_IDS["baseline"]), len(host.EXPECTED_PROBE_IDS["post-docker"])],
            )
            self.assertEqual(receipt["provenance"], claim["provenance"])

    def test_base_validation_waits_for_all_nodes_before_snapshot(self):
        host = load_host_module()
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            claim = self.create_validated_lab(host, Path(temporary))
            calls = []
            nodes = "\n".join(
                [
                    "control-plane Ready control-plane 1m v1.35.6",
                    "worker1 Ready <none> 1m v1.35.6",
                    "worker2 Ready <none> 1m v1.35.6",
                ]
            )

            def runner(argv, **_kwargs):
                calls.append(argv)
                if "get" in argv and "nodes" in argv:
                    return host.CommandResult(0, nodes, "")
                return host.CommandResult(0, "healthy", "")

            receipt = host.validate_base_stack(claim["lab_id"], runner=runner)
            self.assertTrue(receipt["passed"])
            wait_argv = [
                "limactl",
                "shell",
                claim["instances"][1],
                "--",
                "sudo",
                "env",
                "KUBECONFIG=/etc/kubernetes/admin.conf",
                "kubectl",
                "wait",
                "--for=condition=Ready",
                "nodes",
                "--all",
                "--timeout=5m",
            ]
            snapshot_argv = [
                "limactl",
                "shell",
                claim["instances"][1],
                "--",
                "sudo",
                "env",
                "KUBECONFIG=/etc/kubernetes/admin.conf",
                "kubectl",
                "get",
                "nodes",
                "--no-headers",
            ]
            self.assertIn(wait_argv, calls)
            self.assertLess(calls.index(wait_argv), calls.index(snapshot_argv))

    def test_bootstrap_revokes_join_token_and_scrubs_host_secrets(self):
        host = load_host_module()
        lab_id = "cks-spike-test"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            claim = host.new_claim(lab_id)
            claim["status"] = "vms-ready"
            host.write_claim_exclusive(host.claim_path(lab_id), claim)
            script_calls = []

            def scripts(instance, script, env, **kwargs):
                script_calls.append((instance, script, list(kwargs.get("script_args", ()))))
                return host.CommandResult(0, "", "")

            def runner(argv, **_kwargs):
                if argv[:2] == ["limactl", "copy"] and ":" in argv[2]:
                    Path(argv[3]).write_text("secret material\n", encoding="utf-8")
                return host.CommandResult(0, "", "")

            accounts = {"uid": "501", "gid": "20", "home": "/home/operator"}
            with (
                patch.object(host, "stage_guest_assets"),
                patch.object(host, "guest_ip", return_value="192.0.2.10"),
                patch.object(host, "guest_account", return_value=accounts),
                patch.object(host, "run_guest_script", side_effect=scripts),
                patch.object(host, "shell", return_value=host.CommandResult(0, "", "")),
            ):
                host.bootstrap_base_stack(lab_id, runner=runner)

            revoke = (claim["instances"][1], "30-control-plane.sh", ["revoke-token"])
            worker2 = (claim["instances"][3], "40-worker.sh", [])
            self.assertIn(revoke, script_calls)
            self.assertGreater(script_calls.index(revoke), script_calls.index(worker2))
            bootstrap_dir = host.claim_path(lab_id).parent / "bootstrap"
            self.assertFalse((bootstrap_dir / "join.env").exists())
            self.assertFalse((bootstrap_dir / "candidate-kubeconfig").exists())

    def test_bootstrap_failure_and_destroy_failure_still_scrub_host_secrets(self):
        host = load_host_module()
        lab_id = "cks-spike-test"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            claim = host.new_claim(lab_id)
            claim["status"] = "vms-ready"
            host.write_claim_exclusive(host.claim_path(lab_id), claim)
            bootstrap_dir = host.claim_path(lab_id).parent / "bootstrap"
            bootstrap_dir.mkdir()
            (bootstrap_dir / "join.env").write_text("secret\n", encoding="utf-8")
            (bootstrap_dir / "candidate-kubeconfig").write_text("secret\n", encoding="utf-8")

            with (
                patch.object(host, "stage_guest_assets", side_effect=RuntimeError("bootstrap failed")),
                self.assertRaisesRegex(RuntimeError, "bootstrap failed"),
            ):
                host.bootstrap_base_stack(lab_id, runner=lambda argv, **kwargs: None)
            self.assertFalse((bootstrap_dir / "join.env").exists())
            self.assertFalse((bootstrap_dir / "candidate-kubeconfig").exists())

            bootstrap_dir.mkdir()
            (bootstrap_dir / "join.env").write_text("secret\n", encoding="utf-8")
            with (
                patch.object(host, "destroy_instances", side_effect=RuntimeError("delete failed")),
                self.assertRaisesRegex(RuntimeError, "delete failed"),
            ):
                host.destroy_lab(lab_id, runner=lambda argv, **kwargs: None)
            self.assertFalse((bootstrap_dir / "join.env").exists())

    def test_secret_scrub_failure_does_not_mask_primary_failure(self):
        host = load_host_module()
        lab_id = "cks-spike-test"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            claim = host.new_claim(lab_id)
            claim["status"] = "vms-ready"
            host.write_claim_exclusive(host.claim_path(lab_id), claim)
            unsafe = host.claim_path(lab_id).parent / "bootstrap" / "join.env"
            unsafe.mkdir(parents=True)

            with (
                patch.object(host, "stage_guest_assets", side_effect=RuntimeError("primary bootstrap failure")),
                self.assertRaisesRegex(RuntimeError, "primary bootstrap failure"),
            ):
                host.bootstrap_base_stack(lab_id, runner=lambda argv, **kwargs: None)

            persisted = host.load_owned_claim(host.claim_path(lab_id), lab_id)
            self.assertEqual(persisted["host_secret_cleanup"]["status"], "failed")
            self.assertIn("unexpected directory", persisted["host_secret_cleanup"]["detail"])

    def test_lifecycle_records_receipt_identity_mismatch_as_primary_error(self):
        host = load_host_module()
        lab_id = "cks-spike-test"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            def provision(_lab_id, *, runner):
                claim = host.new_claim(_lab_id)
                host.write_claim_exclusive(host.claim_path(_lab_id), claim)
                forged = {
                    "schema": 1,
                    "lab_id": _lab_id,
                    "passed": True,
                    "provenance": {"claim_uuid": "forged", "sha256": claim["provenance"]["sha256"]},
                }
                host.receipt_path(_lab_id).write_text(json.dumps(forged), encoding="utf-8")
                return claim

            with (
                patch.object(host, "provision_vms", side_effect=provision),
                patch.object(host, "bootstrap_base_stack", side_effect=RuntimeError("primary failed")),
                patch.object(host, "destroy_lab", return_value=[]),
            ):
                receipt = host.run_full_lifecycle(lab_id, runner=lambda *args, **kwargs: None)

            self.assertFalse(receipt["passed"])
            self.assertIn("primary failed", receipt["errors"]["primary"])
            self.assertIn("receipt identity does not match claim", receipt["errors"]["primary"])

    def test_full_lifecycle_passes_only_after_cleanup(self):
        host = load_host_module()
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            lab_id = "cks-spike-test"

            def provision(_lab_id, *, runner):
                claim = host.new_claim(_lab_id)
                host.write_claim_exclusive(host.claim_path(_lab_id), claim)
                return claim

            def base(_lab_id, *, runner):
                claim = host.load_owned_claim(host.claim_path(_lab_id), _lab_id)
                claim["status"] = "base-validated"
                host.write_claim(host.claim_path(_lab_id), claim)
                receipt = {"schema": 1, "lab_id": _lab_id, "passed": True, "provenance": claim["provenance"]}
                host.write_receipt(_lab_id, claim, receipt)
                return receipt

            def capabilities(_lab_id, *, runner):
                return base(_lab_id, runner=runner)

            cleanup = [{"instance": "cks-spike-test-candidate", "delete_returncode": 0}]
            with (
                patch.object(host, "provision_vms", side_effect=provision),
                patch.object(host, "bootstrap_base_stack", return_value={}),
                patch.object(host, "validate_base_stack", side_effect=base),
                patch.object(host, "validate_security_capabilities", side_effect=capabilities),
                patch.object(host, "destroy_lab", return_value=cleanup),
            ):
                receipt = host.run_full_lifecycle(lab_id, runner=lambda *args, **kwargs: None)

            self.assertTrue(receipt["passed"])
            self.assertEqual(receipt["lifecycle_status"], "complete")
            self.assertEqual(receipt["cleanup"]["status"], "passed")
            self.assertEqual(receipt["cleanup"]["results"], cleanup)

    def test_full_lifecycle_preserves_primary_and_cleanup_errors(self):
        host = load_host_module()
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            lab_id = "cks-spike-test"

            def provision(_lab_id, *, runner):
                claim = host.new_claim(_lab_id)
                host.write_claim_exclusive(host.claim_path(_lab_id), claim)
                return claim

            with (
                patch.object(host, "provision_vms", side_effect=provision),
                patch.object(host, "bootstrap_base_stack", side_effect=RuntimeError("primary password=hunter2")),
                patch.object(host, "destroy_lab", side_effect=RuntimeError("cleanup token=secret")),
            ):
                receipt = host.run_full_lifecycle(lab_id, runner=lambda *args, **kwargs: None)

            self.assertFalse(receipt["passed"])
            self.assertEqual(receipt["lifecycle_status"], "failed")
            self.assertEqual(receipt["cleanup"]["status"], "failed")
            self.assertIn("primary", receipt["errors"]["primary"])
            self.assertIn("cleanup", receipt["errors"]["cleanup"])
            self.assertNotIn("hunter2", json.dumps(receipt))
            self.assertNotIn("secret", json.dumps(receipt))

    def test_receipt_persistence_failure_cannot_bypass_cleanup(self):
        host = load_host_module()
        lab_id = "cks-spike-test"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            def provision(_lab_id, *, runner):
                claim = host.new_claim(_lab_id)
                host.write_claim_exclusive(host.claim_path(_lab_id), claim)
                return claim

            with (
                patch.object(host, "provision_vms", side_effect=provision),
                patch.object(host, "bootstrap_base_stack", side_effect=RuntimeError("bootstrap failed")),
                patch.object(host, "write_receipt", side_effect=OSError("receipt disk failed")),
                patch.object(host, "destroy_lab", return_value=[]) as destroy,
                self.assertRaisesRegex(OSError, "receipt disk failed"),
            ):
                host.run_full_lifecycle(lab_id, runner=lambda *args, **kwargs: None)

            destroy.assert_called_once_with(lab_id, runner=ANY)

    def test_keyboard_interrupt_cleans_up_before_it_is_reraised(self):
        host = load_host_module()
        lab_id = "cks-spike-test"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            host.os.environ, {"CKS_FULL_SPIKE_STATE_DIR": temporary}
        ):
            def provision(_lab_id, *, runner):
                claim = host.new_claim(_lab_id)
                host.write_claim_exclusive(host.claim_path(_lab_id), claim)
                return claim

            with (
                patch.object(host, "provision_vms", side_effect=provision),
                patch.object(host, "bootstrap_base_stack", side_effect=KeyboardInterrupt()),
                patch.object(host, "destroy_lab", return_value=[]) as destroy,
                self.assertRaises(KeyboardInterrupt),
            ):
                host.run_full_lifecycle(lab_id, runner=lambda *args, **kwargs: None)

            destroy.assert_called_once_with(lab_id, runner=ANY)


if __name__ == "__main__":
    unittest.main()
