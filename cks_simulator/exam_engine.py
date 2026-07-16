"""Trusted combined-exam orchestration over the existing full VM runtime."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable, Dict, Mapping, Optional

from .exam import (
    DEFAULT_EXAM_DURATION_SECONDS,
    EXPECTED_TASK_IDS,
    ExamConflictError,
    ExamManifest,
    ExamMode,
    ExamSession,
    ExamSessionStore,
    ExamStatus,
    aggregate_exam_grades,
)
from .live_grading import GradeStatus, LiveGrade, evaluate_live_grade
from .providers.base import bounded_redacted
from .progress import ProgressCallback, ProgressEvent
from .scenarios import (
    GradeContext,
    GradeInputs,
    GradeSnapshot,
    HandlerRegistry,
    HealthAttestor,
    ReferenceSolutionRegistry,
    ScenarioCatalog,
    ScenarioContext,
    ScenarioLifecycleError,
)
from .state import (
    ActiveScenario,
    JournalEntry,
    LabPhase,
    LabState,
    LabStateStore,
    state_write_prohibited,
)


class ExamEngine:
    """Prepare, grade, and recover one persistent 17-task lab session.

    Exam state is deliberately separate from ``LabState.active_scenario``.  A
    synthetic active-attempt view is supplied only to the reviewed scenario
    handler currently executing, preserving its identity contracts without
    weakening the existing serial scenario CLI.
    """

    def __init__(
        self,
        *,
        lab_store: LabStateStore,
        exam_store: ExamSessionStore,
        manifest: ExamManifest,
        catalog: ScenarioCatalog,
        handlers: HandlerRegistry,
        attest_health: HealthAttestor,
        references: Optional[ReferenceSolutionRegistry] = None,
        compose_reference_apiserver: Optional[Callable[[LabState], None]] = None,
        progress: Optional[ProgressCallback] = None,
    ) -> None:
        self._lab_store = lab_store
        self._exam_store = exam_store
        self._manifest = manifest
        self._catalog = catalog
        self._handlers = handlers
        self._attest_health = attest_health
        self._references = references
        self._compose_reference_apiserver = compose_reference_apiserver
        self._progress = progress

    def _report(self, event: ProgressEvent) -> None:
        if self._progress is not None:
            self._progress(event)

    @property
    def manifest(self) -> ExamManifest:
        return self._manifest

    @property
    def session_store(self) -> ExamSessionStore:
        return self._exam_store

    def _validated_lab(self, lab_name: str) -> LabState:
        state = self._lab_store.load(lab_name)
        if state.phase is LabPhase.CANDIDATE_READY or (
            state.phase is LabPhase.VALIDATED and state.health_fingerprint is None
        ):
            observed = self._attest_health(ScenarioContext(lab_name, state))
            state = self._lab_store.attest_validated(
                lab_name,
                state.identity.lab_id,
                observed,
                detail="host baseline health attested for combined exam",
            )
        if (
            state.phase is not LabPhase.VALIDATED
            or state.health_fingerprint is None
            or state.active_scenario is not None
        ):
            raise ScenarioLifecycleError(
                "combined exam requires a validated lab with no active serial scenario"
            )
        return state

    def _task_state(self, state: LabState, session: ExamSession, task_id: str) -> LabState:
        definition = self._catalog.require(task_id)
        if definition.support != "supported":
            raise ScenarioLifecycleError(f"exam task {task_id} is not supported")
        progress = next(item for item in session.tasks if item.task_id == task_id)
        registration = self._handlers.resolve(definition)
        context = ScenarioContext(state.identity.lab_name, state)
        prepared = registration.expected_prepared(context, definition, progress.attempt_id)
        restored = registration.expected_restored(context, definition, progress.attempt_id)
        active = ActiveScenario(
            scenario_id=task_id,
            attempt_id=progress.attempt_id,
            handler_identity=definition.handler_identity,
            recovery_class=definition.recovery_class,
            target_role=definition.target_role,
            baseline_fingerprint=state.health_fingerprint or "",
            prepared_fingerprint=prepared,
            restore_fingerprint=restored,
        )
        synthetic_journal = state.journal + (
            JournalEntry(
                sequence=len(state.journal),
                phase=LabPhase.SCENARIO_PREPARED,
                recorded_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                detail=f"synthetic combined-exam view for task {task_id}",
            ),
        )
        return replace(state, journal=synthetic_journal, active_scenario=active)

    def _collect_task(self, lab_name: str, state: LabState, session: ExamSession, task_id: str) -> LiveGrade:
        definition = self._catalog.require(task_id)
        registration = self._handlers.resolve(definition)
        synthetic = self._task_state(state, session, task_id)
        active = synthetic.active_scenario
        if active is None:
            raise ScenarioLifecycleError("exam task attempt is missing")
        with state_write_prohibited():
            context = GradeContext(
                lab_name=lab_name,
                lab_id=state.identity.lab_id,
                scenario_id=task_id,
                attempt_id=active.attempt_id,
                target_role=active.target_role,
            )
            if registration.snapshot_collector is not None:
                snapshot = registration.snapshot_collector.collect(context, definition, synthetic)
                if not isinstance(snapshot, GradeSnapshot) or registration.snapshot_evaluator is None:
                    raise ScenarioLifecycleError("exam task observation contract is invalid")
                inputs = registration.snapshot_evaluator.evaluate(snapshot, definition)
            elif registration.grader is not None:
                inputs = registration.grader.grade(context, definition)
            else:
                raise ScenarioLifecycleError("exam task has no trusted grader")
        if not isinstance(inputs, GradeInputs):
            raise ScenarioLifecycleError("exam task grader returned invalid inputs")
        return evaluate_live_grade(inputs.expected, inputs.evidence, inputs.signals)

    def start(
        self,
        lab_name: str,
        *,
        mode: ExamMode,
        duration_seconds: int = DEFAULT_EXAM_DURATION_SECONDS,
    ) -> ExamSession:
        with self._lab_store.lock(lab_name):
            state = self._validated_lab(lab_name)
            if self._exam_store.exists(lab_name):
                raise ExamConflictError(f"exam session already exists for {lab_name!r}")
            session = ExamSession.create(
                lab_name=lab_name,
                lab_id=state.identity.lab_id,
                mode=mode,
                manifest=self._manifest,
                duration_seconds=duration_seconds,
            )
            self._exam_store.create(session)
            try:
                for task_id in EXPECTED_TASK_IDS:
                    claimed = session.claim_preparation(task_id)
                    self._exam_store.save(claimed, expected_revision=session.revision)
                    session = claimed
                    definition = self._catalog.require(task_id)
                    self._report(
                        ProgressEvent(
                            7,
                            "Exam task baseline",
                            f"Preparing task {task_id}: {definition.title}",
                            len(session.prepared_task_ids),
                            len(EXPECTED_TASK_IDS),
                        )
                    )
                    registration = self._handlers.resolve(definition)
                    synthetic = self._task_state(state, session, task_id)
                    observed = registration.mutator.prepare(
                        ScenarioContext(lab_name, synthetic), definition
                    )
                    active = synthetic.active_scenario
                    if active is None or observed != active.prepared_fingerprint:
                        raise ScenarioLifecycleError(
                            f"exam task {task_id} differs from its write-ahead contract"
                        )
                    untouched = self._collect_task(lab_name, state, session, task_id)
                    if untouched.status is not GradeStatus.FAIL or untouched.score != 0:
                        raise ScenarioLifecycleError(
                            f"untouched exam task {task_id} must grade FAIL 0"
                        )
                    confirmed = session.confirm_preparation(task_id)
                    self._exam_store.save(confirmed, expected_revision=session.revision)
                    session = confirmed
                observed_health = self._attest_health(ScenarioContext(lab_name, state))
                if observed_health != state.health_fingerprint:
                    raise ScenarioLifecycleError("combined exam baseline changed trusted health identity")
                active_session = session.activate()
                self._exam_store.save(active_session, expected_revision=session.revision)
                self._report(
                    ProgressEvent(
                        7,
                        "Exam task baseline",
                        "All exam tasks are prepared and gradeable",
                        len(EXPECTED_TASK_IDS),
                        len(EXPECTED_TASK_IDS),
                        True,
                    )
                )
                return active_session
            except BaseException as error:
                recovery_error = self._restore_claimed(state, session)
                detail = bounded_redacted(str(error), limit=1536)
                if recovery_error is not None:
                    detail += "; recovery: " + bounded_redacted(str(recovery_error), limit=384)
                failed = session.fail(detail)
                self._exam_store.save(failed, expected_revision=session.revision)
                raise

    def load(self, lab_name: str) -> ExamSession:
        session = self._exam_store.load(lab_name)
        state = self._lab_store.load(lab_name)
        if session.lab_id != state.identity.lab_id:
            raise ExamConflictError("exam session no longer matches the owned lab")
        return session

    def grade_task(self, lab_name: str, task_id: str) -> LiveGrade:
        if task_id not in EXPECTED_TASK_IDS:
            raise ScenarioLifecycleError("exam task ID is invalid")
        with self._lab_store.lock(lab_name):
            session = self.load(lab_name)
            if session.status is not ExamStatus.ACTIVE:
                raise ExamConflictError("interim grading requires an active exam")
            state = self._validated_lab(lab_name)
            before = self._attest_health(ScenarioContext(lab_name, state))
            grade = self._collect_task(lab_name, state, session, task_id)
            after_state = self._lab_store.load(lab_name)
            after = self._attest_health(ScenarioContext(lab_name, after_state))
            if after_state != state or after != before:
                raise ScenarioLifecycleError("exam grading changed persistent or live lab state")
            return grade

    def grade_all(self, lab_name: str) -> Mapping[str, LiveGrade]:
        with self._lab_store.lock(lab_name):
            session = self.load(lab_name)
            if session.status is not ExamStatus.SUBMITTING:
                raise ExamConflictError("final grading requires a submitting exam")
            state = self._validated_lab(lab_name)
            before = self._attest_health(ScenarioContext(lab_name, state))
            results: Dict[str, LiveGrade] = {
                task_id: self._collect_task(lab_name, state, session, task_id)
                for task_id in EXPECTED_TASK_IDS
            }
            after_state = self._lab_store.load(lab_name)
            after = self._attest_health(ScenarioContext(lab_name, after_state))
            if after_state != state or after != before:
                raise ScenarioLifecycleError("final grading changed persistent or live lab state")
            return results

    def final_receipt(self, lab_name: str) -> Mapping[str, object]:
        session = self.load(lab_name)
        return aggregate_exam_grades(session, self._manifest, self.grade_all(lab_name))

    def apply_reference_all(self, lab_name: str) -> Mapping[str, LiveGrade]:
        """Release-gate-only reference path; never exposed through ExamUI."""

        if self._references is None or self._compose_reference_apiserver is None:
            raise ExamConflictError("combined exam reference actions are unavailable")
        with self._exam_store.lock(lab_name), self._lab_store.lock(lab_name):
            session = self.load(lab_name)
            if session.status is not ExamStatus.ACTIVE or session.mode is not ExamMode.PRACTICE:
                raise ExamConflictError("reference validation requires an active practice session")
            state = self._validated_lab(lab_name)
            for task_id in EXPECTED_TASK_IDS:
                definition = self._catalog.require(task_id)
                synthetic = self._task_state(state, session, task_id)
                self._references.execute(
                    definition,
                    ScenarioContext(lab_name, synthetic),
                    timeout_seconds=900,
                )
            self._compose_reference_apiserver(state)
            before = self._attest_health(ScenarioContext(lab_name, state))
            grades = {
                task_id: self._collect_task(lab_name, state, session, task_id)
                for task_id in EXPECTED_TASK_IDS
            }
            after = self._attest_health(ScenarioContext(lab_name, state))
            if after != before or any(
                grade.status is not GradeStatus.PASS or grade.score != 100
                for grade in grades.values()
            ):
                raise ScenarioLifecycleError("combined reference solution did not grade PASS 100")
            return grades

    def _restore_claimed(self, state: LabState, session: ExamSession) -> BaseException | None:
        errors = []
        for task_id in reversed(session.claimed_task_ids):
            try:
                definition = self._catalog.require(task_id)
                registration = self._handlers.resolve(definition)
                synthetic = self._task_state(state, session, task_id)
                observed = registration.mutator.restore(
                    ScenarioContext(state.identity.lab_name, synthetic), definition
                )
                active = synthetic.active_scenario
                if active is None or observed != active.restore_fingerprint:
                    raise ScenarioLifecycleError(
                        f"exam task {task_id} restore contract mismatch"
                    )
            except BaseException as error:
                errors.append(error)
        if not errors:
            return None
        return ScenarioLifecycleError(
            f"{len(errors)} exam task restore operation(s) failed: {errors[0]}"
        )

    def teardown(self, lab_name: str, *, force_active: bool = False) -> None:
        with self._exam_store.lock(lab_name), self._lab_store.lock(lab_name):
            session = self.load(lab_name)
            if session.status in {ExamStatus.ACTIVE, ExamStatus.SUBMITTING} and not force_active:
                raise ExamConflictError("active exam teardown requires explicit force")
            state = self._validated_lab(lab_name)
            error = self._restore_claimed(state, session)
            if error is not None:
                if session.status not in {ExamStatus.FAILED, ExamStatus.SUBMITTED}:
                    failed = session.fail(bounded_redacted(str(error), limit=2048))
                    self._exam_store.save(failed, expected_revision=session.revision)
                raise error
            observed = self._attest_health(ScenarioContext(lab_name, state))
            if observed != state.health_fingerprint:
                raise ScenarioLifecycleError("exam teardown did not restore trusted lab health")
            self._exam_store.delete(lab_name, expected_session_id=session.session_id)


__all__ = ["ExamEngine"]
