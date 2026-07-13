import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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


class CliTests(unittest.TestCase):
    def test_catalog_has_all_seventeen_scenarios(self):
        result = cli("list", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        catalog = json.loads(result.stdout)
        self.assertEqual(len(catalog), 17)
        self.assertEqual([item["id"] for item in catalog], [f"{n:02d}" for n in range(1, 18)])

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
