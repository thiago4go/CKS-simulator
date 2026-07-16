from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cks_simulator.exam import (
    EXPECTED_TASK_IDS,
    ExamEndReason,
    ExamMode,
    ExamSessionStore,
    ExamStatus,
    build_exam_manifest,
)
from cks_simulator.exam_engine import ExamEngine
from cks_simulator.live_grading import CriterionEvidence, ExpectedCriterion, TrustSource
from cks_simulator.progress import ProgressEvent
from cks_simulator.scenarios import (
    GradeInputs,
    GradeSnapshot,
    HandlerRegistry,
    ReferenceSolutionRegistry,
    ScenarioContext,
    load_full_catalog,
    scenario_state_fingerprint,
)
from cks_simulator.state import LabPhase, LabStateStore
from tests.test_scenario_engine import FakeHealthAttestor, candidate_ready


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "scenarios" / "catalog.json"


def observed_sha(task_id: str, stage: str) -> str:
    return hashlib.sha256(f"{task_id}:{stage}".encode("ascii")).hexdigest()


def expected(stage: str):
    def build(context, definition, attempt_id):
        return scenario_state_fingerprint(
            context,
            definition,
            stage=stage,
            observed_state_sha256=observed_sha(definition.scenario_id, stage),
            attempt_id=attempt_id,
        )

    return build


class FakeCombinedMutator:
    def __init__(self) -> None:
        self.states = {task_id: "restored" for task_id in EXPECTED_TASK_IDS}
        self.events = []
        self.fail_prepare = None
        self.fail_restore = None

    def prepare(self, context, definition):
        task_id = definition.scenario_id
        self.events.append(("prepare", task_id))
        self.states[task_id] = "prepared"
        if self.fail_prepare == task_id:
            raise RuntimeError(f"prepare {task_id} failed")
        return scenario_state_fingerprint(
            context,
            definition,
            stage="prepared",
            observed_state_sha256=observed_sha(task_id, "prepared"),
        )

    def restore(self, context, definition):
        task_id = definition.scenario_id
        self.events.append(("restore", task_id))
        if self.fail_restore == task_id:
            raise RuntimeError(f"restore {task_id} failed")
        self.states[task_id] = "restored"
        return scenario_state_fingerprint(
            context,
            definition,
            stage="restored",
            observed_state_sha256=observed_sha(task_id, "restored"),
        )


class FakeCombinedCollector:
    def __init__(self, mutator: FakeCombinedMutator) -> None:
        self.mutator = mutator

    def collect(self, context, definition, state):
        self.assert_identity(context, definition, state)
        return GradeSnapshot.from_mapping(
            definition.scenario_id,
            {"solved": self.mutator.states[definition.scenario_id] == "solved"},
        )

    @staticmethod
    def assert_identity(context, definition, state):
        active = state.active_scenario
        if active is None or active.attempt_id != context.attempt_id:
            raise RuntimeError("attempt identity mismatch")
        if active.scenario_id != definition.scenario_id:
            raise RuntimeError("task identity mismatch")


class FakeCombinedEvaluator:
    __slots__ = ()

    def evaluate(self, snapshot, definition):
        payload = snapshot.payload()
        expected_criterion = ExpectedCriterion("solved", "task solved", 1)
        evidence = CriterionEvidence(
            "solved",
            "task solved",
            1,
            payload["solved"],
            TrustSource.OPERATOR,
            "fake trusted observation",
        )
        return GradeInputs((expected_criterion,), (evidence,))


class ExamEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.lab_name = "combined-exam"
        self.lab_store = LabStateStore(self.root / "state", namespace="full")
        candidate_ready(self.lab_store, self.lab_name)
        self.exam_store = ExamSessionStore(self.root / "exam-state")
        self.manifest = build_exam_manifest(CATALOG_PATH)
        self.catalog = load_full_catalog(CATALOG_PATH)
        self.mutator = FakeCombinedMutator()
        collector = FakeCombinedCollector(self.mutator)
        evaluator = FakeCombinedEvaluator()
        handlers = HandlerRegistry()
        references = ReferenceSolutionRegistry()
        for task_id in EXPECTED_TASK_IDS:
            handlers.register_snapshot(
                f"full.s{task_id}.v1",
                self.mutator,
                collector,
                evaluator,
                expected_prepared=expected("prepared"),
                expected_restored=expected("restored"),
            )
            references.register(
                f"full.s{task_id}.v1",
                lambda context, _timeout, identifier=task_id: self.mutator.states.__setitem__(identifier, "solved"),
                lambda _context, _timeout: None,
            )
        self.health = FakeHealthAttestor({"bytes": b"healthy"})
        self.composed = []
        self.progress_events: list[ProgressEvent] = []
        self.engine = ExamEngine(
            lab_store=self.lab_store,
            exam_store=self.exam_store,
            manifest=self.manifest,
            catalog=self.catalog,
            handlers=handlers,
            attest_health=self.health,
            references=references,
            compose_reference_apiserver=lambda state: self.composed.append(state.identity.lab_id),
            progress=self.progress_events.append,
        )

    def test_start_claims_prepares_and_activates_all_tasks(self) -> None:
        session = self.engine.start(self.lab_name, mode=ExamMode.PRACTICE)

        self.assertEqual(session.status, ExamStatus.ACTIVE)
        self.assertEqual(session.claimed_task_ids, EXPECTED_TASK_IDS)
        self.assertEqual(session.prepared_task_ids, EXPECTED_TASK_IDS)
        self.assertEqual(
            self.mutator.events,
            [("prepare", task_id) for task_id in EXPECTED_TASK_IDS],
        )
        self.assertEqual(self.lab_store.load(self.lab_name).phase, LabPhase.VALIDATED)

    def test_start_reports_each_exam_task_only_after_it_is_claimed(self) -> None:
        self.engine.start(self.lab_name, mode=ExamMode.PRACTICE)

        task_events = [
            item for item in self.progress_events if item.stage == 7 and not item.completed
        ]
        self.assertEqual(len(task_events), len(EXPECTED_TASK_IDS))
        self.assertEqual(task_events[0].current, 0)
        self.assertEqual(task_events[-1].current, len(EXPECTED_TASK_IDS) - 1)
        self.assertEqual(task_events[-1].total, len(EXPECTED_TASK_IDS))
        self.assertIn("01", task_events[0].detail)
        self.assertTrue(self.progress_events[-1].completed)
        self.assertEqual(self.progress_events[-1].current, len(EXPECTED_TASK_IDS))

    def test_practice_grade_and_final_fixed_denominator_receipt(self) -> None:
        active = self.engine.start(self.lab_name, mode=ExamMode.PRACTICE)
        self.mutator.states["01"] = "solved"

        self.assertEqual(self.engine.grade_task(self.lab_name, "01").score, 100)
        submitting = active.begin_submit(
            reason=ExamEndReason.MANUAL,
            now=datetime.now(timezone.utc),
        )
        self.exam_store.save(submitting, expected_revision=active.revision)
        receipt = self.engine.final_receipt(self.lab_name)

        self.assertEqual(receipt["score"], 4.0)
        self.assertEqual(len(receipt["tasks"]), 17)
        self.assertFalse(receipt["passed"])

    def test_prepare_failure_recovers_every_claimed_task_in_reverse(self) -> None:
        self.mutator.fail_prepare = "03"

        with self.assertRaisesRegex(RuntimeError, "prepare 03 failed"):
            self.engine.start(self.lab_name, mode=ExamMode.EXAM)

        session = self.exam_store.load(self.lab_name)
        self.assertEqual(session.status, ExamStatus.FAILED)
        self.assertEqual(session.claimed_task_ids, ("01", "02", "03"))
        self.assertEqual(
            self.mutator.events[-3:],
            [("restore", "03"), ("restore", "02"), ("restore", "01")],
        )

    def test_release_reference_solves_all_tasks_then_composes_shared_apiserver(self) -> None:
        self.engine.start(self.lab_name, mode=ExamMode.PRACTICE)

        grades = self.engine.apply_reference_all(self.lab_name)

        self.assertEqual(set(grades), set(EXPECTED_TASK_IDS))
        self.assertTrue(all(item.score == 100 for item in grades.values()))
        self.assertEqual(len(self.composed), 1)

    def test_submitted_teardown_restores_reverse_order_and_deletes_session(self) -> None:
        active = self.engine.start(self.lab_name, mode=ExamMode.EXAM)
        submitting = active.begin_submit(reason=ExamEndReason.MANUAL)
        self.exam_store.save(submitting, expected_revision=active.revision)
        receipt = self.engine.final_receipt(self.lab_name)
        submitted = submitting.complete_submit(receipt)
        self.exam_store.save(submitted, expected_revision=submitting.revision)

        self.engine.teardown(self.lab_name)

        self.assertFalse(self.exam_store.exists(self.lab_name))
        restores = [event for event in self.mutator.events if event[0] == "restore"]
        self.assertEqual(restores, [("restore", item) for item in reversed(EXPECTED_TASK_IDS)])

    def test_failed_submitted_teardown_preserves_receipt_for_retry(self) -> None:
        active = self.engine.start(self.lab_name, mode=ExamMode.EXAM)
        submitting = active.begin_submit(reason=ExamEndReason.MANUAL)
        self.exam_store.save(submitting, expected_revision=active.revision)
        receipt = self.engine.final_receipt(self.lab_name)
        submitted = submitting.complete_submit(receipt)
        self.exam_store.save(submitted, expected_revision=submitting.revision)
        self.mutator.fail_restore = "17"

        with self.assertRaisesRegex(Exception, "restore 17 failed"):
            self.engine.teardown(self.lab_name)

        preserved = self.exam_store.load(self.lab_name)
        self.assertEqual(preserved.status, ExamStatus.SUBMITTED)
        self.assertEqual(preserved.receipt, receipt)


if __name__ == "__main__":
    unittest.main()
