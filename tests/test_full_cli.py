from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
import uuid
from argparse import Namespace
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from cks_simulator.full import FullHostCheck, FullTierError
from cks_simulator.full_cli import dispatch_full_command
from cks_simulator.live_grading import (
    CriterionEvidence,
    ExpectedCriterion,
    LabSignals,
    TrustSource,
    evaluate_live_grade,
)
from cks_simulator.providers.base import ProviderHandle, ProviderMachine
from cks_simulator.state import LabPhase, LabStateStore


class FullTierCliTests(unittest.TestCase):
    def test_doctor_renders_structured_host_checks(self) -> None:
        args = Namespace(command="doctor", as_json=True)
        checks = (
            FullHostCheck("host", True, "ok"),
            FullHostCheck("lima", False, "wrong version"),
        )
        with patch("cks_simulator.full_cli.host_preflight", return_value=checks):
            self.assertEqual(dispatch_full_command(args), 1)

    def test_provision_and_delete_use_only_full_lifecycle(self) -> None:
        identity = type("Identity", (), {"lab_id": str(uuid.uuid4())})()
        state = type("State", (), {"phase": LabPhase.CANDIDATE_READY, "identity": identity})()
        destroyed = type(
            "Destroyed",
            (),
            {"phase": LabPhase.DESTROYED, "identity": identity},
        )()
        provision_lifecycle = MagicMock()
        provision_lifecycle.provision.return_value = state
        delete_lifecycle = MagicMock()
        delete_lifecycle.destroy.return_value = destroyed
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("cks_simulator.full_cli.require_host_preflight") as preflight,
            patch(
                "cks_simulator.full_cli.build_lifecycle",
                side_effect=[provision_lifecycle, delete_lifecycle],
            ) as build,
        ):
            root = Path(__file__).resolve().parents[1]
            state_root = Path(temporary)
            self.assertEqual(
                dispatch_full_command(
                    Namespace(command="provision", name="full-lab", as_json=True),
                    root=root,
                    state_root=state_root,
                ),
                0,
            )
            self.assertEqual(
                dispatch_full_command(
                    Namespace(
                        command="delete",
                        name="full-lab",
                        as_json=True,
                        force=False,
                        break_glass=True,
                        expected_lab_id=identity.lab_id,
                    ),
                    root=root,
                    state_root=state_root,
                ),
                0,
            )
        preflight.assert_called_once_with(
            root=root, require_creation_capacity=True
        )
        self.assertEqual(
            build.call_args_list,
            [
                call(root=root, state_root=state_root),
                call(root=root, state_root=state_root, destroy_only=True),
            ],
        )
        provision_lifecycle.provision.assert_called_once_with("full-lab")
        delete_lifecycle.destroy.assert_called_once_with(
            "full-lab",
            break_glass=True,
            expected_lab_id=identity.lab_id,
        )

    def test_delete_rejects_incomplete_break_glass_before_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch(
            "cks_simulator.full_cli.build_lifecycle"
        ) as build:
            with self.assertRaisesRegex(ValueError, "requires --break-glass"):
                dispatch_full_command(
                    Namespace(
                        command="delete",
                        name="full-lab",
                        as_json=True,
                        force=False,
                        break_glass=False,
                        expected_lab_id=str(uuid.uuid4()),
                    ),
                    state_root=Path(temporary),
                )
        build.assert_not_called()

    def test_break_glass_authorization_is_complete_and_canonical_before_build(self) -> None:
        cases = (
            Namespace(
                command="delete", name="full-lab", as_json=True, force=False,
                break_glass=True, expected_lab_id=None,
            ),
            Namespace(
                command="delete", name="full-lab", as_json=True, force=False,
                break_glass=True, expected_lab_id="NOT-A-UUID",
            ),
            Namespace(
                command="delete", name="full-lab", as_json=True, force=False,
                break_glass=True,
                expected_lab_id="00000000-0000-4000-8000-00000000ABCD",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for args in cases:
                with self.subTest(expected=args.expected_lab_id), patch(
                    "cks_simulator.full_cli.build_lifecycle"
                ) as build, self.assertRaises(ValueError):
                    dispatch_full_command(args, state_root=Path(temporary))
                build.assert_not_called()

    def test_full_tier_rejects_quick_only_mutation_flags(self) -> None:
        cases = (
            Namespace(
                command="provision",
                name="full-lab",
                image="custom/image:v1",
                wait="5m",
                as_json=True,
            ),
            Namespace(
                command="provision",
                name="full-lab",
                image="kindest/node:v1.35.1",
                as_json=True,
            ),
            Namespace(command="provision", name="full-lab", wait="5m", as_json=True),
            Namespace(
                command="delete",
                name="full-lab",
                force=True,
                break_glass=False,
                expected_lab_id=None,
                as_json=True,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for args in cases:
                with self.subTest(command=args.command, args=args), patch(
                    "cks_simulator.full_cli.build_lifecycle"
                ) as build, self.assertRaisesRegex(ValueError, "quick tier"):
                    dispatch_full_command(args, state_root=Path(temporary))
                build.assert_not_called()

    def test_full_e2e_dispatches_machine_readable_destroy_rebuild_gate(self) -> None:
        payload = {
            "status": "PASS",
            "returncode": 0,
            "command": "e2e",
            "message": "full gate passed",
        }
        with tempfile.TemporaryDirectory() as temporary, patch(
            "cks_simulator.e2e.run_full_e2e", return_value=payload
        ) as run:
            state_root = Path(temporary)
            result = dispatch_full_command(
                Namespace(
                    command="e2e",
                    name="release",
                    destroy_rebuild=True,
                    keep=False,
                    as_json=True,
                ),
                state_root=state_root,
            )
        self.assertEqual(result, 0)
        run.assert_called_once_with(
            "release",
            root=Path(__file__).resolve().parents[1],
            state_root=state_root,
            destroy_rebuild=True,
            keep=False,
        )

    def test_lab_doctor_reconciles_existing_lab(self) -> None:
        identity = type("Identity", (), {"lab_id": str(uuid.uuid4())})()
        state = type("State", (), {"phase": LabPhase.CANDIDATE_READY, "identity": identity})()
        lifecycle = MagicMock()
        lifecycle.provision.return_value = state
        lifecycle.requires_creation_capacity.return_value = False
        checks = (FullHostCheck("host", True, "ok"),)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("cks_simulator.full_cli._lab_exists", return_value=True),
            patch("cks_simulator.full_cli.host_preflight", return_value=checks) as preflight,
            patch("cks_simulator.full_cli.build_lifecycle", return_value=lifecycle) as build,
        ):
            state_root = Path(temporary)
            result = dispatch_full_command(
                Namespace(command="doctor", lab=True, name="full-lab", as_json=True),
                state_root=state_root,
            )
        self.assertEqual(result, 0)
        preflight.assert_called_once_with(
            root=Path(__file__).resolve().parents[1],
            require_creation_capacity=False,
        )
        build.assert_called_once()
        lifecycle.provision.assert_called_once_with("full-lab")

    def test_lab_doctor_capacity_failure_prevents_reconciliation(self) -> None:
        lifecycle = MagicMock()
        lifecycle.requires_creation_capacity.return_value = True
        low = (FullHostCheck("host-disk", True, "minimum 20 GiB"),)
        high = (FullHostCheck("host-disk", False, "minimum 200 GiB"),)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("cks_simulator.full_cli._lab_exists", return_value=True),
            patch("cks_simulator.full_cli.host_preflight", side_effect=[low, high]) as preflight,
            patch("cks_simulator.full_cli.build_lifecycle", return_value=lifecycle),
        ):
            result = dispatch_full_command(
                Namespace(command="doctor", lab=True, name="partial-lab", as_json=True),
                state_root=Path(temporary),
            )
        self.assertEqual(result, 1)
        self.assertEqual(
            preflight.call_args_list,
            [
                call(root=Path(__file__).resolve().parents[1], require_creation_capacity=False),
                call(root=Path(__file__).resolve().parents[1], require_creation_capacity=True),
            ],
        )
        lifecycle.provision.assert_not_called()

    def test_existing_partial_lab_rechecks_the_creation_disk_reserve(self) -> None:
        identity = type("Identity", (), {"lab_id": str(uuid.uuid4())})()
        state = type("State", (), {"phase": LabPhase.CANDIDATE_READY, "identity": identity})()
        lifecycle = MagicMock()
        lifecycle.requires_creation_capacity.return_value = True
        lifecycle.provision.return_value = state
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("cks_simulator.full_cli._lab_exists", return_value=True),
            patch("cks_simulator.full_cli.require_host_preflight") as preflight,
            patch("cks_simulator.full_cli.build_lifecycle", return_value=lifecycle),
        ):
            result = dispatch_full_command(
                Namespace(command="provision", name="partial-lab", as_json=True),
                state_root=Path(temporary),
            )
        self.assertEqual(result, 0)
        self.assertEqual(
            preflight.call_args_list,
            [
                call(root=Path(__file__).resolve().parents[1], require_creation_capacity=False),
                call(root=Path(__file__).resolve().parents[1], require_creation_capacity=True),
            ],
        )
        lifecycle.provision.assert_called_once_with("partial-lab")

    def test_shell_uses_exact_candidate_handle_and_minimal_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary)
            name = "shell-lab"
            candidate = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
            lifecycle = MagicMock()
            lifecycle.provision.return_value = type(
                "State", (), {"phase": LabPhase.CANDIDATE_READY}
            )()
            lifecycle.verified_candidate_handle.return_value = candidate
            lifecycle.requires_creation_capacity.return_value = False
            calls = []

            def run(command, **kwargs):
                calls.append((command, kwargs))
                return subprocess.CompletedProcess(command, 0)

            with (
                patch("cks_simulator.full_cli.locate_lima", return_value="/trusted/limactl"),
                patch("cks_simulator.full_cli._lab_exists", return_value=True),
                patch("cks_simulator.full_cli.require_host_preflight") as preflight,
                patch("cks_simulator.full_cli.build_lifecycle", return_value=lifecycle) as build,
            ):
                result = dispatch_full_command(
                    Namespace(
                        command="shell",
                        name=name,
                        node=None,
                        shell=None,
                        as_json=False,
                    ),
                    state_root=state_root,
                    run_interactive=run,
                )

            self.assertEqual(result, 0)
            preflight.assert_called_once_with(
                root=Path(__file__).resolve().parents[1],
                require_creation_capacity=False,
            )
            build.assert_called_once_with(
                root=Path(__file__).resolve().parents[1],
                state_root=state_root,
            )
            lifecycle.provision.assert_called_once_with(name)
            lifecycle.verified_candidate_handle.assert_called_once_with(name)
            command, kwargs = calls[0]
            self.assertEqual(command[0:4], ("/trusted/limactl", "shell", "--tty=true", candidate.value))
            self.assertEqual(command[-7:], ("/usr/bin/sudo", "--login", "--user", "candidate", "--", "/bin/bash", "--login"))
            self.assertNotIn("SSH_AUTH_SOCK", kwargs["env"])
            self.assertFalse(kwargs["check"])

    def test_shell_capacity_failure_prevents_reconciliation_and_interaction(self) -> None:
        lifecycle = MagicMock()
        lifecycle.requires_creation_capacity.return_value = True
        interactive = MagicMock()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("cks_simulator.full_cli._lab_exists", return_value=True),
            patch(
                "cks_simulator.full_cli.require_host_preflight",
                side_effect=[None, FullTierError("creation capacity unavailable")],
            ) as preflight,
            patch("cks_simulator.full_cli.build_lifecycle", return_value=lifecycle),
            self.assertRaisesRegex(FullTierError, "creation capacity"),
        ):
            dispatch_full_command(
                Namespace(command="shell", name="partial-lab", node=None, shell=None),
                state_root=Path(temporary),
                run_interactive=interactive,
            )
        self.assertEqual(
            preflight.call_args_list,
            [
                call(root=Path(__file__).resolve().parents[1], require_creation_capacity=False),
                call(root=Path(__file__).resolve().parents[1], require_creation_capacity=True),
            ],
        )
        lifecycle.provision.assert_not_called()
        interactive.assert_not_called()

    def test_doctor_and_shell_rejections_happen_before_mutation(self) -> None:
        doctor_cases = (
            Namespace(command="doctor", lab=False, name="named", as_json=True),
            Namespace(command="doctor", lab=True, name="missing", as_json=True),
        )
        shell_cases = (
            Namespace(command="shell", name="lab", node="worker1", shell=None),
            Namespace(command="shell", name="lab", node=None, shell="/bin/zsh"),
            Namespace(command="shell", name="missing", node=None, shell=None),
        )
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary)
            for args in doctor_cases:
                with self.subTest(command="doctor", args=args), patch(
                    "cks_simulator.full_cli._lab_exists", return_value=False
                ), patch("cks_simulator.full_cli.host_preflight") as preflight, patch(
                    "cks_simulator.full_cli.build_lifecycle"
                ) as build, self.assertRaises(ValueError):
                    dispatch_full_command(args, state_root=state_root)
                preflight.assert_not_called()
                build.assert_not_called()
            for args in shell_cases:
                exists = args.name != "missing"
                interactive = MagicMock()
                with self.subTest(command="shell", args=args), patch(
                    "cks_simulator.full_cli._lab_exists", return_value=exists
                ), patch("cks_simulator.full_cli.require_host_preflight") as preflight, patch(
                    "cks_simulator.full_cli.build_lifecycle"
                ) as build, self.assertRaises(ValueError):
                    dispatch_full_command(
                        args, state_root=state_root, run_interactive=interactive
                    )
                preflight.assert_not_called()
                build.assert_not_called()
                interactive.assert_not_called()

    def test_shell_refuses_unavailable_lima_before_interaction(self) -> None:
        lifecycle = MagicMock()
        lifecycle.requires_creation_capacity.return_value = False
        lifecycle.verified_candidate_handle.return_value = ProviderHandle(
            "lima", "cks-0123456789abcdef-candidate"
        )
        interactive = MagicMock()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("cks_simulator.full_cli._lab_exists", return_value=True),
            patch("cks_simulator.full_cli.require_host_preflight"),
            patch("cks_simulator.full_cli.build_lifecycle", return_value=lifecycle),
            patch("cks_simulator.full_cli.locate_lima", return_value=None),
            self.assertRaisesRegex(RuntimeError, "limactl is unavailable"),
        ):
            dispatch_full_command(
                Namespace(command="shell", name="lab", node=None, shell=None),
                state_root=Path(temporary),
                run_interactive=interactive,
            )
        lifecycle.provision.assert_called_once_with("lab")
        interactive.assert_not_called()

    def test_full_scenario_prepare_and_restore_dispatch_to_reviewed_engine(self) -> None:
        attempt_id = str(uuid.uuid4())
        active = type("Active", (), {"attempt_id": attempt_id})()
        prepared = type(
            "Prepared",
            (),
            {"phase": LabPhase.SCENARIO_PREPARED, "active_scenario": active},
        )()
        restored = type(
            "Restored", (), {"phase": LabPhase.VALIDATED, "active_scenario": None}
        )()
        engine = MagicMock()
        engine.prepare.return_value = prepared
        engine.restore.return_value = restored
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary, patch(
            "cks_simulator.full_cli.build_scenario_engine", return_value=engine
        ) as build:
            state_root = Path(temporary)
            self.assertEqual(
                dispatch_full_command(
                    Namespace(
                        command="scenario",
                        scenario_command="prepare",
                        id="4",
                        name="full-lab",
                        as_json=True,
                    ),
                    state_root=state_root,
                ),
                0,
            )
            self.assertEqual(
                dispatch_full_command(
                    Namespace(
                        command="scenario",
                        scenario_command="restore",
                        id="04",
                        name="full-lab",
                        as_json=True,
                    ),
                    state_root=state_root,
                ),
                0,
            )
        self.assertEqual(
            build.call_args_list,
            [
                call(root=root, state_root=state_root),
                call(root=root, state_root=state_root),
            ],
        )
        engine.prepare.assert_called_once_with("full-lab", "4")
        engine.restore.assert_called_once_with("full-lab", "04")

    def test_full_grade_exit_status_and_payload_follow_live_evidence(self) -> None:
        expected = (ExpectedCriterion("fixed", "configuration fixed", 1),)
        passing = evaluate_live_grade(
            expected,
            (
                CriterionEvidence(
                    "fixed",
                    "configuration fixed",
                    1,
                    True,
                    TrustSource.OPERATOR,
                    "operator probe passed",
                ),
            ),
        )
        failing = evaluate_live_grade(expected, ())
        engine = MagicMock()
        engine.grade.side_effect = [passing, failing]
        with tempfile.TemporaryDirectory() as temporary, patch(
            "cks_simulator.full_cli.build_scenario_engine", return_value=engine
        ):
            args = Namespace(
                command="grade", id="04", name="full-lab", as_json=True
            )
            self.assertEqual(
                dispatch_full_command(args, state_root=Path(temporary)), 0
            )
            self.assertEqual(
                dispatch_full_command(args, state_root=Path(temporary)), 1
            )
        self.assertEqual(engine.grade.call_args_list, [call("full-lab", "04")] * 2)

    def test_full_grade_all_and_invalid_scenario_operation_fail_before_engine_action(self) -> None:
        engine = MagicMock()
        with tempfile.TemporaryDirectory() as temporary, patch(
            "cks_simulator.full_cli.build_scenario_engine", return_value=engine
        ):
            with self.assertRaisesRegex(ValueError, "one active scenario"):
                dispatch_full_command(
                    Namespace(command="grade", id="all", name="lab", as_json=True),
                    state_root=Path(temporary),
                )
            with self.assertRaisesRegex(ValueError, "prepare or restore"):
                dispatch_full_command(
                    Namespace(
                        command="scenario",
                        scenario_command="create",
                        id="01",
                        name="lab",
                        as_json=True,
                    ),
                    state_root=Path(temporary),
                )
        engine.grade.assert_not_called()
        engine.prepare.assert_not_called()
        engine.restore.assert_not_called()

    def test_full_scenario_and_grade_render_complete_json_contracts(self) -> None:
        attempt_id = str(uuid.uuid4())
        active = type("Active", (), {"attempt_id": attempt_id})()
        prepared = type(
            "Prepared",
            (),
            {"phase": LabPhase.SCENARIO_PREPARED, "active_scenario": active},
        )()
        expected = (
            ExpectedCriterion("a", "criterion a", 1),
            ExpectedCriterion("b", "criterion b", 1),
        )
        one_pass = (
            CriterionEvidence(
                "a", "criterion a", 1, True, TrustSource.OPERATOR, "passed"
            ),
        )
        grades = (
            evaluate_live_grade(expected, one_pass),
            evaluate_live_grade(expected, (), LabSignals(lab_broken=True)),
            evaluate_live_grade(expected, (), LabSignals(tampered=True)),
        )
        engine = MagicMock()
        engine.prepare.return_value = prepared
        engine.grade.side_effect = grades
        with tempfile.TemporaryDirectory() as temporary, patch(
            "cks_simulator.full_cli.build_scenario_engine", return_value=engine
        ):
            state_root = Path(temporary)
            output = StringIO()
            with redirect_stdout(output):
                code = dispatch_full_command(
                    Namespace(
                        command="scenario",
                        scenario_command="prepare",
                        id="4",
                        name="full-lab",
                        as_json=True,
                    ),
                    state_root=state_root,
                )
            self.assertEqual(code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(
                payload,
                {
                    "attempt_id": attempt_id,
                    "command": "scenario prepare",
                    "message": "full scenario 04 prepared on full-lab",
                    "name": "full-lab",
                    "phase": "scenario-prepared",
                    "returncode": 0,
                    "scenario_id": "04",
                    "status": "ok",
                    "tier": "full",
                },
            )

            for expected_status in ("PARTIAL", "LAB_BROKEN", "LAB_TAMPERED"):
                with self.subTest(status=expected_status):
                    output = StringIO()
                    with redirect_stdout(output):
                        code = dispatch_full_command(
                            Namespace(
                                command="grade",
                                id="04",
                                name="full-lab",
                                as_json=True,
                            ),
                            state_root=state_root,
                        )
                    self.assertEqual(code, 1)
                    payload = json.loads(output.getvalue())
                    self.assertEqual(payload["status"], expected_status)
                    self.assertEqual(payload["tier"], "full")
                    self.assertEqual(payload["scenario_id"], "04")
                    self.assertEqual(payload["name"], "full-lab")
                    self.assertEqual(payload["returncode"], 1)
                    self.assertEqual(len(payload["criteria"]), 2)

            human = StringIO()
            engine.grade.side_effect = [evaluate_live_grade(expected, one_pass)]
            with redirect_stdout(human):
                dispatch_full_command(
                    Namespace(
                        command="grade",
                        id="04",
                        name="full-lab",
                        as_json=False,
                    ),
                    state_root=state_root,
                )
            self.assertIn("full scenario 04 score: 50.00/100 (PARTIAL)", human.getvalue())


if __name__ == "__main__":
    unittest.main()
