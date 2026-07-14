import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cks_simulator import cli as simulator
from cks_simulator.grading import evaluate_rule


ROOT = Path(__file__).resolve().parents[1]


def cli(*args, state=None):
    env = os.environ.copy()
    if state:
        env["CKS_STATE_DIR"] = str(state)
    return subprocess.run(
        [sys.executable, "-m", "cks_simulator", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )


def seed_tls_fixture(destination):
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "tls.crt").write_text("test certificate", encoding="utf-8")
    (destination / "tls.key").write_text("test key", encoding="utf-8")
    os.chmod(destination / "tls.key", 0o600)


class CliTests(unittest.TestCase):
    def test_catalog_has_all_seventeen_scenarios(self):
        result = cli("list", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        catalog = json.loads(result.stdout)
        self.assertEqual(len(catalog), 17)
        self.assertEqual([item["id"] for item in catalog], [f"{n:02d}" for n in range(1, 18)])
        self.assertTrue(simulator.LIVE_FIXTURE_IDS.issubset({item["id"] for item in catalog}))
        for identifier in simulator.LIVE_FIXTURE_IDS:
            self.assertTrue((ROOT / "scenarios" / "fixtures" / identifier / "resources.json").is_file())

    def test_help_is_available(self):
        result = cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("scenario", result.stdout)

    def test_doctor_json_is_machine_readable(self):
        result = cli("doctor", "--json")
        self.assertIn(result.returncode, (0, 1))
        payload = json.loads(result.stdout)
        self.assertIn("checks", payload)
        self.assertTrue(any(check["name"] == "kind (pinned fallback)" for check in payload["checks"]))

    def test_create_and_reset_seed_task_and_fixture_without_cluster(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            created = cli("scenario", "create", "04", state=state)
            self.assertEqual(created.returncode, 0, created.stderr)
            scenario = state / "scenarios" / "04"
            self.assertTrue((scenario / "TASK.md").is_file())
            self.assertTrue((scenario / "fixture" / "resources.json").is_file())
            refused = cli("scenario", "create", "04", state=state)
            self.assertEqual(refused.returncode, 1)
            self.assertIn("scenario reset", refused.stderr)
            reset = cli("scenario", "reset", "04", state=state)
            self.assertEqual(reset.returncode, 0, reset.stderr)
            self.assertTrue((scenario / "artifacts").is_dir())

    def test_artifact_check_is_deterministic_and_cluster_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            self.assertEqual(cli("scenario", "create", "06", state=state).returncode, 0)
            failed = cli("check", "06", state=state)
            self.assertEqual(failed.returncode, 1)
            artifact = state / "scenarios" / "06" / "artifacts" / "immutable-deployment-new.yaml"
            artifact.write_text(
                "securityContext:\n  readOnlyRootFilesystem: true\n"
                "volumeMounts:\n- mountPath: /tmp\n  name: tmp\n"
                "volumes:\n- name: tmp\n  emptyDir: {}\n",
                encoding="utf-8",
            )
            passed = cli("check", "06", state=state)
            self.assertEqual(passed.returncode, 0, passed.stdout + passed.stderr)
            self.assertIn("PASS", passed.stdout)

    def test_grade_awards_partial_credit_but_check_remains_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "immutable-deployment-new.yaml").write_text(
                "readOnlyRootFilesystem: true\nmountPath: /tmp\n",
                encoding="utf-8",
            )
            result = cli("grade", "06", "--root", str(root), "--json")
            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["score"], 66.7)
            self.assertEqual(payload["status"], "incomplete")
            self.assertEqual(payload["earned"], 2)
            self.assertEqual(payload["possible"], 3)

    def test_grade_all_is_machine_readable_and_covers_every_scenario(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = cli("grade", "all", "--root", temporary, "--json")
            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["scenario_count"], 17)
            self.assertEqual(len(payload["scenarios"]), 17)
            self.assertEqual(payload["validation_scope"], "artifact evidence; not an official CKS exam score")

    def test_cluster_health_requires_every_reported_node_to_be_ready(self):
        with patch.object(
            simulator,
            "node_statuses",
            return_value=[{"name": "cp", "ready": True}, {"name": "worker", "ready": False}],
        ):
            self.assertFalse(simulator.cluster_healthy("test", announce=False))
        with patch.object(
            simulator,
            "node_statuses",
            return_value=[
                {"name": "cp", "ready": True},
                {"name": "worker", "ready": True},
                {"name": "worker2", "ready": True},
            ],
        ):
            self.assertTrue(simulator.cluster_healthy("test", announce=False))
        for nodes in ([], [{"name": "cp", "ready": True}], [{"name": str(index), "ready": True} for index in range(4)]):
            with self.subTest(nodes=len(nodes)), patch.object(simulator, "node_statuses", return_value=nodes):
                self.assertFalse(simulator.cluster_healthy("test", announce=False))

    def test_every_grading_rule_family_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "value.txt").write_text("alpha\nbeta\n", encoding="utf-8")
            (root / "value.json").write_text('{"outer":{"enabled":true}}', encoding="utf-8")
            cases = [
                ({"path": "value.txt", "kind": "file_exists"}, True),
                ({"path": "value.txt", "kind": "text_contains", "values": ["alpha", "beta"]}, True),
                ({"path": "value.txt", "kind": "text_not_contains", "values": ["gamma"]}, True),
                ({"path": "value.txt", "kind": "text_exact_lines", "values": ["alpha", "beta"]}, True),
                ({"path": "value.json", "kind": "json_pointer", "pointer": "/outer/enabled", "expected": True}, True),
                ({"path": "missing", "kind": "text_not_contains", "values": ["gamma"]}, False),
                ({"path": "value.txt", "kind": "unknown"}, False),
            ]
            for rule, expected in cases:
                with self.subTest(kind=rule["kind"], path=rule["path"]):
                    self.assertEqual(evaluate_rule(root, rule)["passed"], expected)
            (root / "invalid.txt").write_bytes(b"\xff\xfe")
            invalid = evaluate_rule(root, {"path": "invalid.txt", "kind": "text_contains", "values": ["alpha"]})
            self.assertFalse(invalid["passed"])

    def test_fixture_validator_exercises_real_apply_get_and_wait_contract(self):
        item = simulator.scenario_by_id("04")
        expected = json.loads((ROOT / "scenarios" / "fixtures" / "04" / "resources.json").read_text(encoding="utf-8"))
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        observed = subprocess.CompletedProcess([], 0, stdout=json.dumps(expected), stderr="")
        with (
            patch.object(simulator, "run_command", return_value=completed) as run_mock,
            patch.object(simulator, "command_output", side_effect=[observed, completed]) as output_mock,
            patch.object(simulator, "cluster_kubectl", side_effect=lambda _name, args: ["kubectl", *args]),
        ):
            ok, detail = simulator._validate_fixture("test", item, announce=False)
        self.assertTrue(ok, detail)
        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(output_mock.call_count, 2)

    def test_scenario_07_e2e_uses_server_dry_run(self):
        item = simulator.scenario_by_id("07")
        completed = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        with (
            patch.object(simulator, "run_command", return_value=completed) as run_mock,
            patch.object(simulator, "command_output", return_value=completed) as output_mock,
            patch.object(simulator, "cluster_kubectl", side_effect=lambda _name, args: ["kubectl", *args]),
        ):
            ok, detail = simulator._validate_fixture("test", item, announce=False)
        self.assertTrue(ok, detail)
        self.assertIn("without scheduling", detail)
        self.assertIn("create", run_mock.call_args.args[0])
        self.assertIn("--dry-run=server", output_mock.call_args.args[0])

    def test_scenario_15_live_validator_exercises_generated_tls(self):
        item = simulator.scenario_by_id("15")
        expected = json.loads((ROOT / "scenarios" / "fixtures" / "15" / "resources.json").read_text(encoding="utf-8"))
        completed = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        observed = subprocess.CompletedProcess([], 0, stdout=json.dumps(expected), stderr="")
        ingress = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps({"spec": {"tls": [{"secretName": "secure-tls"}]}}), stderr=""
        )
        with tempfile.TemporaryDirectory() as temporary:
            tls_dir = Path(temporary)
            (tls_dir / "tls.crt").write_text("test", encoding="utf-8")
            (tls_dir / "tls.key").write_text("test", encoding="utf-8")
            with (
                patch.object(simulator, "run_command", return_value=completed),
                patch.object(simulator, "command_output", side_effect=[observed, completed, completed, ingress]) as output_mock,
                patch.object(simulator, "cluster_kubectl", side_effect=lambda _name, args: ["kubectl", *args]),
            ):
                ok, detail = simulator._validate_fixture("test", item, announce=False, tls_dir=tls_dir)
        self.assertTrue(ok, detail)
        self.assertIn("verified generated TLS", detail)
        flattened = [part for call in output_mock.call_args_list for part in call.args[0]]
        self.assertIn("secure-tls", flattened)
        self.assertIn("patch", flattened)

    def test_scenario_15_generates_private_tls_fixture_without_seeding_solution(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            result = cli("scenario", "create", "15", state=state)
            self.assertEqual(result.returncode, 0, result.stderr)
            fixture = state / "scenarios" / "15" / "fixture"
            self.assertTrue((fixture / "tls.crt").is_file())
            self.assertEqual((fixture / "tls.key").stat().st_mode & 0o777, 0o600)
            resources = json.loads((fixture / "resources.json").read_text(encoding="utf-8"))
            self.assertNotIn("Secret", [item["kind"] for item in resources["items"]])
            services = {item["metadata"]["name"] for item in resources["items"] if item["kind"] == "Service"}
            self.assertEqual(services, {"app", "api"})

    def test_failed_scenario_15_reset_preserves_existing_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"CKS_STATE_DIR": temporary}):
            self.assertEqual(simulator.create_scenario("15"), 0)
            artifact = Path(temporary) / "scenarios" / "15" / "artifacts" / "work.txt"
            artifact.write_text("keep me", encoding="utf-8")
            with patch.object(simulator, "generate_tls_fixture", side_effect=RuntimeError("openssl failed")):
                with self.assertRaisesRegex(RuntimeError, "openssl failed"):
                    simulator.create_scenario("15", reset=True)
            self.assertEqual(artifact.read_text(encoding="utf-8"), "keep me")

    def test_e2e_failure_exports_logs_and_deletes_owned_cluster(self):
        completed = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr="")
        fixture_results = [(False, "fixture failed")] + [(True, "ok")] * 4
        args = SimpleNamespace(name="cks-e2e-test", image="kindest/node:test", wait="1m", keep=False, as_json=True)
        output = StringIO()
        with (
            patch.object(simulator, "docker_command", return_value="docker"),
            patch.object(simulator, "kubectl_command", return_value="kubectl"),
            patch.object(simulator, "kind_command", return_value=["kind"]),
            patch.object(simulator, "command_output", return_value=completed),
            patch.object(simulator, "generate_tls_fixture", side_effect=seed_tls_fixture),
            patch.object(simulator, "provision", side_effect=[0, 0]),
            patch.object(
                simulator,
                "node_statuses",
                return_value=[
                    {"name": "cp", "ready": True},
                    {"name": "w1", "ready": True},
                    {"name": "w2", "ready": True},
                ],
            ),
            patch.object(simulator, "_validate_fixture", side_effect=fixture_results),
            patch.object(simulator, "state_is_owned", return_value=True),
            patch.object(simulator, "cluster_presence", side_effect=[False, True, False]),
            patch.object(simulator, "_export_e2e_logs", return_value=Path("/tmp/e2e-logs")),
            patch.object(simulator, "delete", return_value=0) as delete_mock,
            redirect_stdout(output),
        ):
            result = simulator.e2e(args)
        self.assertEqual(result, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "fail")
        self.assertTrue(payload["diagnostic_logs"])
        self.assertTrue(payload["checks"][-1]["passed"])
        delete_mock.assert_called_once()

    def test_e2e_refuses_and_preserves_preexisting_cluster(self):
        completed = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr="")
        args = SimpleNamespace(name="existing", image="kindest/node:test", wait="1m", keep=False, as_json=True)
        output = StringIO()
        with (
            patch.object(simulator, "docker_command", return_value="docker"),
            patch.object(simulator, "kubectl_command", return_value="kubectl"),
            patch.object(simulator, "kind_command", return_value=["kind"]),
            patch.object(simulator, "command_output", return_value=completed),
            patch.object(simulator, "generate_tls_fixture", side_effect=seed_tls_fixture),
            patch.object(simulator, "cluster_presence", return_value=True),
            patch.object(simulator, "metadata_path", return_value=Path("/nonexistent/e2e-metadata")),
            patch.object(simulator, "provision") as provision_mock,
            patch.object(simulator, "delete") as delete_mock,
            redirect_stdout(output),
        ):
            result = simulator.e2e(args)
        self.assertEqual(result, 1)
        payload = json.loads(output.getvalue())
        provision_check = next(check for check in payload["checks"] if check["name"] == "cluster provision")
        self.assertIn("refusing pre-existing", provision_check["detail"])
        self.assertEqual(payload["checks"][-1]["detail"], "pre-existing cluster or state left untouched")
        provision_mock.assert_not_called()
        delete_mock.assert_not_called()

    def test_diagnostic_logs_are_reported_only_after_successful_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def successful_export(*_args, **_kwargs):
                (root / "e2e-logs" / "test").mkdir(parents=True)
                return subprocess.CompletedProcess([], 0, stdout="", stderr="")

            with (
                patch.object(simulator, "state_dir", return_value=root),
                patch.object(simulator, "kind_command", return_value=["kind"]),
                patch.object(simulator, "command_output", side_effect=successful_export),
            ):
                self.assertEqual(simulator._export_e2e_logs("test", announce=False), root / "e2e-logs" / "test")

            with (
                patch.object(simulator, "state_dir", return_value=root),
                patch.object(simulator, "kind_command", return_value=["kind"]),
                patch.object(
                    simulator,
                    "command_output",
                    return_value=subprocess.CompletedProcess([], 1, stdout="", stderr="failed"),
                ),
            ):
                self.assertIsNone(simulator._export_e2e_logs("failed", announce=False))

    def test_e2e_claim_is_exclusive_and_token_scoped(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(simulator, "state_dir", return_value=Path(temporary)):
            first = simulator.acquire_e2e_claim("same-name")
            second = simulator.acquire_e2e_claim("same-name")
            self.assertTrue(first)
            self.assertIsNone(second)
            self.assertTrue(simulator.e2e_claim_is_owned("same-name", first))
            self.assertFalse(simulator.e2e_claim_is_owned("same-name", "wrong-token"))

    def test_json_mode_returns_structured_domain_errors(self):
        result = cli("grade", "99", "--json")
        self.assertEqual(result.returncode, 2)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error"]["type"], "ValueError")

    def test_unsupported_scenario_is_still_fixture_and_artifact_checkable(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            result = cli("scenario", "create", "10", "--apply", state=state)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("not applying unsupported fixture", result.stdout)
            self.assertTrue((state / "scenarios" / "10" / "TASK.md").is_file())

    def test_invalid_scenario_has_useful_error(self):
        result = cli("scenario", "create", "99")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown scenario", result.stderr)


if __name__ == "__main__":
    unittest.main()
