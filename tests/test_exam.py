from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cks_simulator.exam import (
    DEFAULT_EXAM_DURATION_SECONDS,
    EXPECTED_TASK_IDS,
    ExamConflictError,
    ExamEndReason,
    ExamManifest,
    ExamMode,
    ExamSession,
    ExamSessionStore,
    ExamStateError,
    ExamStatus,
    aggregate_exam_grades,
    build_exam_manifest,
)
from cks_simulator.live_grading import (
    CriterionEvidence,
    ExpectedCriterion,
    GradeStatus,
    LabSignals,
    TrustSource,
    evaluate_live_grade,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "scenarios" / "catalog.json"
NOW = datetime(2026, 7, 15, 10, 0, tzinfo=timezone.utc)


def grade(*, passed: bool, tampered: bool = False, broken: bool = False):
    expected = (ExpectedCriterion("answer", "answer is correct", 1),)
    evidence = (
        CriterionEvidence(
            "answer",
            "answer is correct",
            1,
            passed,
            TrustSource.OPERATOR,
            "operator observation",
        ),
    )
    return evaluate_live_grade(
        expected,
        evidence,
        LabSignals(tampered=tampered, lab_broken=broken),
    )


class ExamManifestTests(unittest.TestCase):
    def test_catalog_builds_complete_candidate_safe_manifest(self) -> None:
        manifest = build_exam_manifest(CATALOG_PATH)

        self.assertEqual(tuple(task.task_id for task in manifest.tasks), EXPECTED_TASK_IDS)
        self.assertEqual(sum(task.weight for task in manifest.tasks), 100)
        self.assertEqual(manifest.tasks[0].host, "cks3477-q01")
        self.assertEqual(manifest.tasks[0].workdir, "/opt/course/1")
        self.assertIn("/opt/course/1/contexts", manifest.tasks[0].prompt)
        self.assertNotIn("artifacts/", manifest.tasks[0].prompt)
        self.assertEqual(len(manifest.catalog_sha256), 64)
        self.assertEqual(len(manifest.manifest_sha256), 64)

    def test_manifest_rejects_catalog_reordering(self) -> None:
        value = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
        value[0], value[1] = value[1], value[0]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "catalog.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ExamStateError, "canonical and ordered"):
                build_exam_manifest(path)


class ExamSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = build_exam_manifest(CATALOG_PATH)
        self.session = ExamSession.create(
            lab_name="exam-lab",
            lab_id=str(uuid.uuid4()),
            mode=ExamMode.EXAM,
            manifest=self.manifest,
            now=NOW,
        )

    def test_timer_starts_after_preparation_and_is_server_authoritative(self) -> None:
        self.assertEqual(self.session.status, ExamStatus.PREPARING)
        self.assertIsNone(self.session.deadline_at)

        active = self.session.activate(now=NOW + timedelta(minutes=9))
        payload = active.to_candidate_dict(
            self.manifest,
            now=NOW + timedelta(minutes=10),
        )

        self.assertEqual(payload["remaining_seconds"], DEFAULT_EXAM_DURATION_SECONDS - 60)
        self.assertNotIn("lab_id", payload)
        self.assertNotIn("catalog_sha256", payload)
        self.assertNotIn("attempt_id", json.dumps(payload))
        self.assertFalse(payload["can_check"])

    def test_progress_navigation_does_not_change_task_identity(self) -> None:
        active = self.session.activate(now=NOW)
        changed = active.update_progress(
            "17",
            selected=True,
            visited=True,
            flagged=True,
            completed=True,
            now=NOW + timedelta(seconds=1),
        )

        self.assertEqual(changed.selected_task_id, "17")
        self.assertEqual(
            tuple(item.attempt_id for item in changed.tasks),
            tuple(item.attempt_id for item in active.tasks),
        )
        task = changed.tasks[-1]
        self.assertTrue(task.visited and task.flagged and task.completed)

    def test_preparation_claims_are_write_ahead_ordered_and_private(self) -> None:
        claimed = self.session.claim_preparation("01")
        self.assertEqual(claimed.claimed_task_ids, ("01",))
        self.assertEqual(claimed.prepared_task_ids, ())
        with self.assertRaisesRegex(ExamConflictError, "not confirmed"):
            claimed.claim_preparation("02")

        prepared = claimed.confirm_preparation("01")
        second = prepared.claim_preparation("02")
        self.assertEqual(second.claimed_task_ids, ("01", "02"))
        self.assertNotIn("claimed_task_ids", second.to_candidate_dict(self.manifest))
        self.assertNotIn("prepared_task_ids", second.to_candidate_dict(self.manifest))

    def test_expired_exam_rejects_progress_and_becomes_expired_submission(self) -> None:
        active = self.session.activate(now=NOW)
        deadline = NOW + timedelta(seconds=DEFAULT_EXAM_DURATION_SECONDS)

        with self.assertRaisesRegex(ExamConflictError, "deadline"):
            active.update_progress("02", visited=True, now=deadline)

        submitting = active.begin_submit(reason=ExamEndReason.MANUAL, now=deadline)
        self.assertEqual(submitting.status, ExamStatus.SUBMITTING)
        self.assertEqual(submitting.end_reason, ExamEndReason.EXPIRED)

    def test_submit_is_idempotent_at_the_state_machine_boundary(self) -> None:
        active = self.session.activate(now=NOW)
        submitting = active.begin_submit(reason=ExamEndReason.MANUAL, now=NOW)
        self.assertIs(submitting.begin_submit(reason=ExamEndReason.MANUAL), submitting)
        receipt = {"score": 42.0, "receipt_sha256": "a" * 64}
        submitted = submitting.complete_submit(receipt, now=NOW + timedelta(minutes=2))
        self.assertIs(submitted.begin_submit(reason=ExamEndReason.MANUAL), submitted)
        self.assertEqual(submitted.receipt, receipt)

    def test_mode_is_immutable_and_practice_only_exposes_check_capability(self) -> None:
        practice = ExamSession.create(
            lab_name="practice-lab",
            lab_id=str(uuid.uuid4()),
            mode=ExamMode.PRACTICE,
            manifest=self.manifest,
            now=NOW,
        ).activate(now=NOW)
        payload = practice.to_candidate_dict(self.manifest, now=NOW)
        self.assertTrue(payload["can_check"])
        self.assertEqual(payload["mode"], "practice")


class ExamSessionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "state"
        self.store = ExamSessionStore(self.root)
        self.manifest = build_exam_manifest(CATALOG_PATH)
        self.session = ExamSession.create(
            lab_name="persisted-lab",
            lab_id=str(uuid.uuid4()),
            mode=ExamMode.EXAM,
            manifest=self.manifest,
            now=NOW,
        )

    def test_atomic_owner_only_create_load_and_revision_save(self) -> None:
        self.store.create(self.session)
        path = self.root / "full-exams" / "persisted-lab" / "session.json"

        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(self.store.load("persisted-lab"), self.session)

        active = self.session.activate(now=NOW)
        self.store.save(active, expected_revision=0)
        self.assertEqual(self.store.load("persisted-lab"), active)
        with self.assertRaisesRegex(ExamConflictError, "revision"):
            self.store.save(active.update_progress("02", now=NOW), expected_revision=0)

    def test_existing_session_and_symlinked_state_fail_closed(self) -> None:
        self.store.create(self.session)
        with self.assertRaisesRegex(ExamConflictError, "already exists"):
            self.store.create(self.session)

        unsafe_root = Path(self.temporary.name) / "unsafe"
        unsafe_root.symlink_to(self.root, target_is_directory=True)
        unsafe = ExamSessionStore(unsafe_root)
        with self.assertRaisesRegex(ExamStateError, "unsafe"):
            unsafe.load("persisted-lab")

    def test_exact_session_delete_and_strict_integer_schema(self) -> None:
        self.store.create(self.session)
        with self.assertRaisesRegex(ExamConflictError, "identity"):
            self.store.delete("persisted-lab", expected_session_id=str(uuid.uuid4()))

        self.store.delete("persisted-lab", expected_session_id=self.session.session_id)
        self.assertFalse(self.store.exists("persisted-lab"))

        payload = self.session.to_dict()
        payload["duration_seconds"] = True
        with self.assertRaisesRegex(ExamStateError, "invalid or incomplete"):
            ExamSession.from_dict(payload)

    def test_exam_lock_serializes_mutations_and_is_owner_only(self) -> None:
        self.store.create(self.session)
        first_entered = threading.Event()
        release_first = threading.Event()
        second_entered = threading.Event()

        def first():
            with self.store.lock("persisted-lab"):
                first_entered.set()
                release_first.wait(2)

        def second():
            with self.store.lock("persisted-lab"):
                second_entered.set()

        first_thread = threading.Thread(target=first)
        second_thread = threading.Thread(target=second)
        first_thread.start()
        self.assertTrue(first_entered.wait(1))
        second_thread.start()
        time.sleep(0.05)
        self.assertFalse(second_entered.is_set())
        release_first.set()
        self.assertTrue(second_entered.wait(1))
        first_thread.join(1)
        second_thread.join(1)
        lock_path = self.root / "full-exams" / "persisted-lab" / ".lock"
        self.assertEqual(os.stat(lock_path).st_mode & 0o777, 0o600)


class ExamAggregateScoringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest: ExamManifest = build_exam_manifest(CATALOG_PATH)
        active = ExamSession.create(
            lab_name="score-lab",
            lab_id=str(uuid.uuid4()),
            mode=ExamMode.EXAM,
            manifest=self.manifest,
            now=NOW,
        ).activate(now=NOW)
        self.submitting = active.begin_submit(reason=ExamEndReason.MANUAL, now=NOW)

    def test_fixed_denominator_weighted_score_and_deterministic_receipt(self) -> None:
        grades = {task_id: grade(passed=task_id != "17") for task_id in EXPECTED_TASK_IDS}
        receipt = aggregate_exam_grades(self.submitting, self.manifest, grades)
        repeated = aggregate_exam_grades(self.submitting, self.manifest, grades)

        self.assertEqual(receipt, repeated)
        self.assertEqual(receipt["score"], 92.0)
        self.assertEqual(receipt["possible"], 100)
        self.assertEqual(len(receipt["tasks"]), 17)
        self.assertEqual(len(receipt["receipt_sha256"]), 64)

    def test_missing_task_and_candidate_forged_mapping_are_rejected(self) -> None:
        grades = {task_id: grade(passed=True) for task_id in EXPECTED_TASK_IDS[:-1]}
        with self.assertRaisesRegex(ExamStateError, "exactly one"):
            aggregate_exam_grades(self.submitting, self.manifest, grades)

        forged = {task_id: grade(passed=True) for task_id in EXPECTED_TASK_IDS}
        forged["17"] = {"status": "PASS", "score": 100}  # type: ignore[assignment]
        with self.assertRaisesRegex(ExamStateError, "invalid task grade"):
            aggregate_exam_grades(self.submitting, self.manifest, forged)  # type: ignore[arg-type]

    def test_tamper_and_broken_status_override_numeric_score(self) -> None:
        grades = {task_id: grade(passed=True) for task_id in EXPECTED_TASK_IDS}
        grades["03"] = grade(passed=True, broken=True)
        broken = aggregate_exam_grades(self.submitting, self.manifest, grades)
        self.assertEqual(broken["status"], GradeStatus.LAB_BROKEN.value)
        self.assertFalse(broken["passed"])

        grades["08"] = grade(passed=True, tampered=True)
        tampered = aggregate_exam_grades(self.submitting, self.manifest, grades)
        self.assertEqual(tampered["status"], GradeStatus.LAB_TAMPERED.value)
        self.assertFalse(tampered["passed"])


if __name__ == "__main__":
    unittest.main()
