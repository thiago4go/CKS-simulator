from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cks_simulator import e2e
from cks_simulator.live_grading import GradeStatus
from cks_simulator.scenarios import EXPECTED_SCENARIO_IDS
from cks_simulator.state import LabPhase


class FullE2ETests(unittest.TestCase):
    @staticmethod
    def _build(name: str, passed: bool = True) -> dict[str, object]:
        return {
            "name": name,
            "passed": passed,
            "scenarios": [
                {"scenario_id": value, "attempted": True, "passed": passed}
                for value in EXPECTED_SCENARIO_IDS
            ],
            "cleanup": {"attempted": True, "passed": True, "phase": "destroyed"},
        }

    def test_destroy_rebuild_receipt_is_owner_only_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            builds = [self._build("release-a"), self._build("release-b")]
            with patch("cks_simulator.e2e._run_build", side_effect=builds) as run:
                payload = e2e.run_full_e2e(
                    "release",
                    state_root=state,
                    destroy_rebuild=True,
                )
            self.assertEqual(payload["status"], "PASS")
            self.assertEqual(payload["coverage"]["attempted_scenarios"], 17)
            self.assertEqual(payload["coverage"]["builds_passed"], 2)
            self.assertEqual(run.call_count, 2)
            receipt = Path(payload["receipt_path"])
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            self.assertEqual(json.loads(receipt.read_text()), payload)

    def test_failed_build_a_skips_build_b_and_still_writes_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch(
            "cks_simulator.e2e._run_build",
            return_value=self._build("release-a", passed=False),
        ):
            payload = e2e.run_full_e2e(
                "release", state_root=Path(temporary), destroy_rebuild=True
            )
        self.assertEqual(payload["status"], "FAIL")
        self.assertTrue(payload["builds"][1]["skipped"])
        self.assertEqual(payload["coverage"]["builds_passed"], 0)

    def test_low_profile_is_recorded_and_forwarded_to_every_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch(
            "cks_simulator.e2e._run_build",
            return_value=self._build("low-release-a"),
        ) as run:
            payload = e2e.run_full_e2e(
                "low-release",
                state_root=Path(temporary),
                memory_profile="low",
            )

        self.assertEqual(payload["memory_profile"], "low")
        self.assertEqual(run.call_args.kwargs["memory_profile"], "low")

    def test_keep_and_destroy_rebuild_are_mutually_exclusive(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            e2e.run_full_e2e("release", keep=True, destroy_rebuild=True)

    def test_unknown_memory_profile_fails_before_state_or_build_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch(
            "cks_simulator.e2e._run_build"
        ) as run, self.assertRaisesRegex(RuntimeError, "unsupported memory profile"):
            e2e.run_full_e2e(
                "release",
                state_root=Path(temporary),
                memory_profile="tiny",
            )
        run.assert_not_called()

    def test_receipt_writer_rejects_symlink_state_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir(mode=0o700)
            link = root / "state"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "must not be a symlink"):
                e2e._write_receipt(link, "run-id", {"status": "FAIL"})

    def test_matrix_attempts_exact_catalog_and_requires_repeatable_grades(self) -> None:
        solved = set()

        class Engine:
            current = None

            def prepare(self, _name, identifier):
                self.current = identifier
                return SimpleNamespace(identity=SimpleNamespace(lab_name="lab"))

            def grade(self, _name, identifier):
                if identifier in solved:
                    return SimpleNamespace(status=GradeStatus.PASS, score=100.0)
                return SimpleNamespace(status=GradeStatus.FAIL, score=0.0)

            def restore(self, _name, _identifier):
                return SimpleNamespace(
                    phase=LabPhase.VALIDATED, active_scenario=None
                )

        engine = Engine()

        class References:
            def execute(self, definition, _context, timeout_seconds):
                self.timeout_seconds = timeout_seconds
                solved.add(definition.scenario_id)

        with patch(
            "cks_simulator.e2e.build_scenario_runtime",
            return_value=(engine, References()),
        ):
            records = e2e._run_scenario_matrix(
                "lab",
                root=Path(__file__).resolve().parents[1],
                state_root=Path("/unused"),
            )
        self.assertEqual([item["scenario_id"] for item in records], list(EXPECTED_SCENARIO_IDS))
        self.assertTrue(all(item["passed"] for item in records))
        self.assertTrue(all(item["repeat_identical"] for item in records))
        self.assertTrue(all(item["restore_validated"] for item in records))

    def test_break_glass_cleanup_is_visible_even_when_exact_handles_are_removed(self) -> None:
        identity = SimpleNamespace(lab_id="00000000-0000-4000-8000-000000000001")
        machine = SimpleNamespace(handle=SimpleNamespace(value="cks-exact-candidate"))
        live = SimpleNamespace(identity=identity, inventory=(machine,), phase=LabPhase.DEGRADED)
        destroyed = SimpleNamespace(
            identity=identity, inventory=(machine,), phase=LabPhase.DESTROYED
        )
        with tempfile.TemporaryDirectory() as temporary:
            lab_directory = Path(temporary) / "full" / "lab"
            lab_directory.mkdir(parents=True)
            (lab_directory / "state.json").write_text("{}")
            store = MagicMock()
            store.load.side_effect = [live, live]
            store.state_path.return_value = lab_directory / "state.json"
            lifecycle = MagicMock()
            lifecycle.destroy.side_effect = [
                RuntimeError("ordinary ownership check failed"),
                destroyed,
                destroyed,
            ]
            with patch("cks_simulator.e2e.LabStateStore", return_value=store):
                result = e2e._cleanup_lab(
                    "lab",
                    lifecycle,
                    state_root=Path(temporary),
                    keep=False,
                    successful_before_cleanup=False,
                )
        self.assertFalse(result["passed"])
        self.assertTrue(result["break_glass_attempted"])
        self.assertEqual(result["phase"], "destroyed")
        self.assertIn("ordinary cleanup failed", result["error"])
        lifecycle.destroy.assert_any_call(
            "lab",
            break_glass=True,
            expected_lab_id=identity.lab_id,
        )


if __name__ == "__main__":
    unittest.main()
