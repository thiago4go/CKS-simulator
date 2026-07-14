"""Catalog-driven full-tier scenario lifecycle and reviewed handler dispatch."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Iterable, Mapping, Protocol, Sequence, Tuple

from .live_grading import (
    CriterionEvidence,
    ExpectedCriterion,
    GradeStatus,
    LabSignals,
    LiveGrade,
    evaluate_live_grade,
)
from .providers.base import bounded_redacted, validate_identifier
from .state import LabPhase, LabState, LabStateStore, state_write_prohibited


EXPECTED_SCENARIO_IDS = tuple(f"{value:02d}" for value in range(1, 18))
FULL_SUPPORT = frozenset({"planned", "supported"})
TARGET_ROLES = frozenset({"candidate", "control-plane", "worker1", "worker2"})
RECOVERY_CLASSES = frozenset(
    {
        "candidate-files",
        "kubernetes-api",
        "control-plane",
        "node-cis",
        "docker",
        "apparmor",
        "gvisor",
        "falco",
    }
)
_SAFE_CONTRACT_ID = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_HANDLER_ID = re.compile(r"^full\.s(?:0[1-9]|1[0-7])\.v[1-9][0-9]*$")
_MAX_CATALOG_BYTES = 1024 * 1024
_MAX_SNAPSHOT_BYTES = 256 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


class ScenarioContractError(ValueError):
    """Catalog or static registry violates the reviewed U6 contract."""


class ScenarioLifecycleError(RuntimeError):
    """A full-tier scenario cannot safely complete its lifecycle operation."""


class RecoveryMode(str, Enum):
    TARGETED = "targeted"
    OPERATOR_TRANSPORT = "operator-transport"
    REBUILD_REQUIRED = "rebuild-required"


@dataclass(frozen=True)
class RecoverySignals:
    api_available: bool = True
    operator_transport_available: bool = True
    guest_identity_intact: bool = True

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, bool)
            for value in (
                self.api_available,
                self.operator_transport_available,
                self.guest_identity_intact,
            )
        ):
            raise TypeError("recovery signals must be booleans")


def select_recovery_mode(
    definition: "FullScenarioDefinition", signals: RecoverySignals
) -> RecoveryMode:
    """Choose the safe recovery rung without discovering or adopting resources."""

    if not isinstance(signals, RecoverySignals):
        raise TypeError("signals must be RecoverySignals")
    if not signals.guest_identity_intact or not signals.operator_transport_available:
        return RecoveryMode.REBUILD_REQUIRED
    if (
        not signals.api_available
        or definition.recovery_class in {"control-plane", "node-cis"}
    ):
        return RecoveryMode.OPERATOR_TRANSPORT
    return RecoveryMode.TARGETED


@dataclass(frozen=True)
class FullScenarioDefinition:
    scenario_id: str
    title: str
    support: str
    target_role: str
    prerequisites: Tuple[str, ...]
    recovery_class: str
    handler_identity: str
    untouched_baseline: str
    restore_fingerprint: str

    def __post_init__(self) -> None:
        if self.scenario_id not in EXPECTED_SCENARIO_IDS:
            raise ScenarioContractError("full scenario ID must be canonical from 01 through 17")
        if not isinstance(self.title, str) or not self.title.strip():
            raise ScenarioContractError("full scenario title is missing")
        if self.support not in FULL_SUPPORT:
            raise ScenarioContractError("full scenario support must be planned or supported")
        if self.target_role not in TARGET_ROLES:
            raise ScenarioContractError("full scenario target role is invalid")
        if self.recovery_class not in RECOVERY_CLASSES:
            raise ScenarioContractError("full scenario recovery class is invalid")
        if not self.prerequisites or len(self.prerequisites) != len(set(self.prerequisites)):
            raise ScenarioContractError("full scenario prerequisites must be non-empty and unique")
        for value in (
            *self.prerequisites,
            self.untouched_baseline,
            self.restore_fingerprint,
        ):
            if not isinstance(value, str) or _SAFE_CONTRACT_ID.fullmatch(value) is None:
                raise ScenarioContractError("full scenario contract identifier is unsafe")
        if (
            not isinstance(self.handler_identity, str)
            or _HANDLER_ID.fullmatch(self.handler_identity) is None
            or self.handler_identity[6:8] != self.scenario_id
        ):
            raise ScenarioContractError("full scenario handler identity is invalid")


class ScenarioCatalog:
    def __init__(self, definitions: Iterable[FullScenarioDefinition]) -> None:
        values = tuple(definitions)
        identifiers = tuple(item.scenario_id for item in values)
        if identifiers != EXPECTED_SCENARIO_IDS:
            raise ScenarioContractError(
                "full scenario catalog must contain ordered IDs 01 through 17 exactly once"
            )
        handlers = tuple(item.handler_identity for item in values)
        if len(handlers) != len(set(handlers)):
            raise ScenarioContractError("full scenario handler identities must be unique")
        self._definitions = values
        self._by_id = {item.scenario_id: item for item in values}

    @property
    def definitions(self) -> Tuple[FullScenarioDefinition, ...]:
        return self._definitions

    def require(self, scenario_id: str) -> FullScenarioDefinition:
        normalized = scenario_id.zfill(2) if isinstance(scenario_id, str) else scenario_id
        try:
            return self._by_id[normalized]
        except (KeyError, TypeError) as error:
            raise ScenarioContractError(f"unknown full scenario {scenario_id!r}") from error


def _require_mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ScenarioContractError(f"{name} must be an object")
    return value


def load_full_catalog(path: Path) -> ScenarioCatalog:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ScenarioContractError("scenario catalog must be a regular non-symlink file")
    encoded = source.read_bytes()
    if len(encoded) > _MAX_CATALOG_BYTES:
        raise ScenarioContractError("scenario catalog exceeds 1 MiB")
    try:
        payload = json.loads(encoded.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioContractError("scenario catalog is not valid UTF-8 JSON") from error
    if not isinstance(payload, list):
        raise ScenarioContractError("scenario catalog root must be an array")
    definitions = []
    for item_value in payload:
        item = _require_mapping(item_value, "scenario")
        full = _require_mapping(item.get("full"), "scenario.full")
        prerequisites = full.get("prerequisites")
        if (
            not isinstance(prerequisites, list)
            or any(not isinstance(value, str) for value in prerequisites)
        ):
            raise ScenarioContractError("full scenario prerequisites must be a string array")
        try:
            definitions.append(
                FullScenarioDefinition(
                    scenario_id=item["id"],
                    title=item["title"],
                    support=full["support"],
                    target_role=full["target_role"],
                    prerequisites=tuple(prerequisites),
                    recovery_class=full["recovery_class"],
                    handler_identity=full["handler_identity"],
                    untouched_baseline=full["untouched_baseline"],
                    restore_fingerprint=full["restore_fingerprint"],
                )
            )
        except KeyError as error:
            raise ScenarioContractError(
                f"scenario {item.get('id', '<unknown>')!r} has incomplete full metadata"
            ) from error
    return ScenarioCatalog(definitions)


@dataclass(frozen=True)
class ScenarioContext:
    lab_name: str
    state: LabState

    def __post_init__(self) -> None:
        validate_identifier(self.lab_name, field_name="full lab name")
        if self.state.identity.lab_name != self.lab_name:
            raise ScenarioLifecycleError("scenario context does not match lab identity")


@dataclass(frozen=True)
class GradeContext:
    """Minimal immutable capability exposed to read-only grading probes."""

    lab_name: str
    lab_id: str
    scenario_id: str
    attempt_id: str
    target_role: str

    def __post_init__(self) -> None:
        validate_identifier(self.lab_name, field_name="full lab name")
        try:
            uuid.UUID(self.lab_id)
            uuid.UUID(self.attempt_id)
        except (AttributeError, ValueError) as error:
            raise ScenarioLifecycleError("grade context identity is invalid") from error
        if self.scenario_id not in EXPECTED_SCENARIO_IDS:
            raise ScenarioLifecycleError("grade context scenario ID is invalid")
        if self.target_role not in TARGET_ROLES:
            raise ScenarioLifecycleError("grade context target role is invalid")


@dataclass(frozen=True)
class GradeInputs:
    expected: Tuple[ExpectedCriterion, ...]
    evidence: Tuple[CriterionEvidence, ...]
    signals: LabSignals = LabSignals()


@dataclass(frozen=True)
class GradeSnapshot:
    """Bounded immutable observations collected before pure evaluation.

    The canonical JSON string deliberately contains no transport, credential,
    path, runner, or callable object.  Concrete U7 evaluators receive only this
    value, which makes mutation impossible by construction.
    """

    scenario_id: str
    canonical_json: str

    def __post_init__(self) -> None:
        if self.scenario_id not in EXPECTED_SCENARIO_IDS:
            raise ScenarioContractError("grade snapshot scenario ID is invalid")
        if not isinstance(self.canonical_json, str):
            raise ScenarioContractError("grade snapshot must be canonical JSON text")
        encoded = self.canonical_json.encode("utf-8")
        if len(encoded) > _MAX_SNAPSHOT_BYTES:
            raise ScenarioContractError("grade snapshot exceeds 256 KiB")
        try:
            value = json.loads(
                self.canonical_json,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise ScenarioContractError("grade snapshot is not valid JSON") from error
        if not isinstance(value, Mapping):
            raise ScenarioContractError("grade snapshot root must be an object")
        canonical = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        if canonical != self.canonical_json:
            raise ScenarioContractError("grade snapshot is not canonical JSON")
        if value.get("schema") != 1 or value.get("scenario_id") != self.scenario_id:
            raise ScenarioContractError("grade snapshot identity is invalid")

    @classmethod
    def from_mapping(
        cls, scenario_id: str, value: Mapping[str, object]
    ) -> "GradeSnapshot":
        payload = dict(value)
        payload["schema"] = 1
        payload["scenario_id"] = scenario_id
        return cls(
            scenario_id,
            json.dumps(
                payload, sort_keys=True, separators=(",", ":"), allow_nan=False
            ),
        )

    def payload(self) -> Mapping[str, object]:
        return json.loads(self.canonical_json)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode("utf-8")).hexdigest()


class ScenarioMutator(Protocol):
    """Mutation-only contract; this object is never exposed to grade()."""

    def prepare(
        self,
        context: ScenarioContext,
        definition: FullScenarioDefinition,
    ) -> str:
        """Mutate to unsolved state and independently observe its fingerprint."""

    def restore(
        self, context: ScenarioContext, definition: FullScenarioDefinition
    ) -> str:
        """Restore owned mutations and independently fingerprint recovered state."""


class ScenarioGrader(Protocol):
    """Read-only probe object with no prepare/restore capability."""

    def grade(
        self, context: GradeContext, definition: FullScenarioDefinition
    ) -> GradeInputs:
        """Collect trusted evidence without mutation authority."""


class SnapshotCollector(Protocol):
    """Trusted observation boundary; never passed to an evaluator."""

    def collect(
        self,
        context: GradeContext,
        definition: FullScenarioDefinition,
        state: LabState,
    ) -> GradeSnapshot: ...


class SnapshotEvaluator(Protocol):
    """Pure evaluator holding no live-lab capability."""

    def evaluate(
        self, snapshot: GradeSnapshot, definition: FullScenarioDefinition
    ) -> GradeInputs: ...


ExpectedFingerprint = Callable[[ScenarioContext, FullScenarioDefinition, str], str]


@dataclass(frozen=True)
class RegisteredScenarioHandler:
    mutator: ScenarioMutator
    grader: ScenarioGrader | None
    snapshot_collector: SnapshotCollector | None
    snapshot_evaluator: SnapshotEvaluator | None
    expected_prepared: ExpectedFingerprint
    expected_restored: ExpectedFingerprint


class HandlerRegistry:
    """Static reviewed dispatch; catalog values never become commands/imports."""

    def __init__(self) -> None:
        self._handlers: Dict[str, RegisteredScenarioHandler] = {}

    def register(
        self,
        identity: str,
        mutator: ScenarioMutator,
        grader: ScenarioGrader,
        *,
        expected_prepared: ExpectedFingerprint,
        expected_restored: ExpectedFingerprint,
    ) -> None:
        if not isinstance(identity, str) or _HANDLER_ID.fullmatch(identity) is None:
            raise ScenarioContractError("registered handler identity is invalid")
        if identity in self._handlers:
            raise ScenarioContractError(f"handler {identity!r} is already registered")
        for method in ("prepare", "restore"):
            if not callable(getattr(mutator, method, None)):
                raise ScenarioContractError(f"handler {identity!r} is missing {method}()")
        if not callable(getattr(grader, "grade", None)):
            raise ScenarioContractError(f"handler {identity!r} is missing grade()")
        if mutator is grader or any(
            callable(getattr(grader, method, None)) for method in ("prepare", "restore")
        ):
            raise ScenarioContractError(
                f"handler {identity!r} grader must be structurally read-only"
            )
        if not callable(expected_prepared) or not callable(expected_restored):
            raise ScenarioContractError(
                f"handler {identity!r} requires separate expected state contracts"
            )
        self._handlers[identity] = RegisteredScenarioHandler(
            mutator, grader, None, None, expected_prepared, expected_restored
        )

    def register_snapshot(
        self,
        identity: str,
        mutator: ScenarioMutator,
        collector: SnapshotCollector,
        evaluator: SnapshotEvaluator,
        *,
        expected_prepared: ExpectedFingerprint,
        expected_restored: ExpectedFingerprint,
    ) -> None:
        """Register the U7 capability split without changing the U6 API."""

        if not isinstance(identity, str) or _HANDLER_ID.fullmatch(identity) is None:
            raise ScenarioContractError("registered handler identity is invalid")
        if identity in self._handlers:
            raise ScenarioContractError(f"handler {identity!r} is already registered")
        for method in ("prepare", "restore"):
            if not callable(getattr(mutator, method, None)):
                raise ScenarioContractError(f"handler {identity!r} is missing {method}()")
        if not callable(getattr(collector, "collect", None)):
            raise ScenarioContractError(f"handler {identity!r} is missing collect()")
        if not callable(getattr(evaluator, "evaluate", None)):
            raise ScenarioContractError(f"handler {identity!r} is missing evaluate()")
        forbidden = ("prepare", "restore", "collect", "execute", "run")
        if any(callable(getattr(evaluator, method, None)) for method in forbidden):
            raise ScenarioContractError(
                f"handler {identity!r} snapshot evaluator exposes a live capability"
            )
        if getattr(evaluator, "__dict__", None):
            raise ScenarioContractError(
                f"handler {identity!r} snapshot evaluator must be stateless"
            )
        if not callable(expected_prepared) or not callable(expected_restored):
            raise ScenarioContractError(
                f"handler {identity!r} requires separate expected state contracts"
            )
        self._handlers[identity] = RegisteredScenarioHandler(
            mutator,
            None,
            collector,
            evaluator,
            expected_prepared,
            expected_restored,
        )

    def resolve(self, definition: FullScenarioDefinition) -> RegisteredScenarioHandler:
        try:
            return self._handlers[definition.handler_identity]
        except KeyError as error:
            raise ScenarioLifecycleError(
                f"reviewed handler {definition.handler_identity!r} is not installed"
            ) from error


class ReferenceSolutionRegistry:
    """Operator-only static reference actions used by release validation."""

    def __init__(self) -> None:
        self._actions: Dict[
            str,
            Tuple[
                Callable[[ScenarioContext, float], None],
                Callable[[ScenarioContext, float], None],
            ],
        ] = {}

    def register(
        self,
        handler_identity: str,
        action: Callable[[ScenarioContext, float], None],
        cleanup: Callable[[ScenarioContext, float], None],
    ) -> None:
        if (
            _HANDLER_ID.fullmatch(handler_identity or "") is None
            or not callable(action)
            or not callable(cleanup)
        ):
            raise ScenarioContractError("reference solution registration is invalid")
        if handler_identity in self._actions:
            raise ScenarioContractError("reference solution is already registered")
        self._actions[handler_identity] = (action, cleanup)

    def resolve(
        self, definition: FullScenarioDefinition
    ) -> Tuple[
        Callable[[ScenarioContext, float], None],
        Callable[[ScenarioContext, float], None],
    ]:
        try:
            return self._actions[definition.handler_identity]
        except KeyError as error:
            raise ScenarioLifecycleError(
                f"reference solution for {definition.handler_identity!r} is unavailable"
            ) from error

    def execute(
        self,
        definition: FullScenarioDefinition,
        context: ScenarioContext,
        *,
        timeout_seconds: float,
    ) -> None:
        """Run one bounded reference action and always invoke its cleanup."""

        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < float(timeout_seconds) <= 900
        ):
            raise ScenarioContractError(
                "reference solution timeout must be in (0, 900] seconds"
            )
        action, cleanup = self.resolve(definition)
        primary_error: BaseException | None = None
        try:
            action(context, float(timeout_seconds))
        except BaseException as error:
            primary_error = error
        try:
            cleanup(context, float(timeout_seconds))
        except BaseException as cleanup_error:
            raise ScenarioLifecycleError("reference solution cleanup failed") from (
                primary_error or cleanup_error
            )
        if primary_error is not None:
            raise primary_error


HealthAttestor = Callable[[ScenarioContext], str]


def preparation_claim_fingerprint(
    context: ScenarioContext,
    definition: FullScenarioDefinition,
    *,
    attempt_id: str | None = None,
) -> str:
    active = context.state.active_scenario
    if context.state.health_fingerprint is None:
        raise ScenarioLifecycleError("lab has no trusted health baseline")
    if active is not None:
        if (
            active.scenario_id != definition.scenario_id
            or active.handler_identity != definition.handler_identity
        ):
            raise ScenarioLifecycleError("active attempt does not match scenario definition")
        resolved_attempt = active.attempt_id
        if attempt_id is not None and attempt_id != resolved_attempt:
            raise ScenarioLifecycleError("requested attempt does not match active attempt")
    else:
        if attempt_id is None:
            raise ScenarioLifecycleError("preparation fingerprint requires an attempt ID")
        try:
            resolved_attempt = str(uuid.UUID(attempt_id))
        except (AttributeError, ValueError) as error:
            raise ScenarioLifecycleError("preparation attempt ID is invalid") from error
    payload = {
        "attempt_contract": 2,
        "attempt_id": resolved_attempt,
        "baseline": context.state.health_fingerprint,
        "handler": definition.handler_identity,
        "lab_id": context.state.identity.lab_id,
        "prerequisites": definition.prerequisites,
        "recovery_class": definition.recovery_class,
        "restore_contract": definition.restore_fingerprint,
        "scenario_id": definition.scenario_id,
        "target_role": definition.target_role,
        "untouched_baseline": definition.untouched_baseline,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def scenario_state_fingerprint(
    context: ScenarioContext,
    definition: FullScenarioDefinition,
    *,
    stage: str,
    observed_state_sha256: str,
    attempt_id: str | None = None,
) -> str:
    """Bind a canonical scenario-owned observation to one active attempt."""

    if stage not in {"prepared", "restored"}:
        raise ScenarioContractError("scenario fingerprint stage is invalid")
    if _SHA256.fullmatch(observed_state_sha256 or "") is None:
        raise ScenarioContractError("observed scenario state must be canonical SHA-256")
    active = context.state.active_scenario
    resolved_attempt = attempt_id or (active.attempt_id if active is not None else None)
    if resolved_attempt is None:
        raise ScenarioLifecycleError("scenario state fingerprint requires an attempt ID")
    try:
        resolved_attempt = str(uuid.UUID(resolved_attempt))
    except (AttributeError, ValueError) as error:
        raise ScenarioLifecycleError("scenario state fingerprint attempt is invalid") from error
    if active is not None and (
        active.attempt_id != resolved_attempt
        or active.scenario_id != definition.scenario_id
        or active.handler_identity != definition.handler_identity
    ):
        raise ScenarioLifecycleError("scenario state fingerprint attempt mismatch")
    payload = {
        "contract": "cks-simulator/scenario-state/v1",
        "attempt_id": resolved_attempt,
        "baseline": context.state.health_fingerprint,
        "handler": definition.handler_identity,
        "lab_id": context.state.identity.lab_id,
        "observed_state_sha256": observed_state_sha256,
        "scenario_id": definition.scenario_id,
        "stage": stage,
        "state_contract": (
            definition.untouched_baseline
            if stage == "prepared"
            else definition.restore_fingerprint
        ),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class ScenarioEngine:
    """Serialize prepare/restore and keep live grade strictly read-only."""

    def __init__(
        self,
        *,
        store: LabStateStore,
        catalog: ScenarioCatalog,
        handlers: HandlerRegistry,
        attest_health: HealthAttestor,
    ) -> None:
        self._store = store
        self._catalog = catalog
        self._handlers = handlers
        self._attest_health = attest_health

    @staticmethod
    def _context(lab_name: str, state: LabState) -> ScenarioContext:
        return ScenarioContext(lab_name, state)

    def _degrade(self, lab_name: str, state: LabState, error: BaseException) -> None:
        try:
            if state.phase is not LabPhase.DEGRADED:
                self._store.advance(
                    lab_name,
                    state.identity.lab_id,
                    LabPhase.DEGRADED,
                    detail=bounded_redacted(str(error), limit=1024),
                )
        except Exception:
            pass

    @staticmethod
    def _require_fingerprint(value: object, name: str) -> str:
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise ScenarioContractError(f"{name} must be canonical SHA-256")
        return value

    @staticmethod
    def _grade_context(state: LabState) -> GradeContext:
        active = state.active_scenario
        if active is None:
            raise ScenarioLifecycleError("grade requires an active scenario attempt")
        return GradeContext(
            lab_name=state.identity.lab_name,
            lab_id=state.identity.lab_id,
            scenario_id=active.scenario_id,
            attempt_id=active.attempt_id,
            target_role=active.target_role,
        )

    def _collect_grade_read_only(
        self,
        lab_name: str,
        state: LabState,
        registration: RegisteredScenarioHandler,
        definition: FullScenarioDefinition,
    ) -> GradeInputs:
        """Detect persistent or live drift around a capability-minimal probe."""

        before = self._store.load(lab_name)
        if before != state:
            raise ScenarioLifecycleError("scenario state changed before grade collection")
        scenario_context = self._context(lab_name, before)
        health_before = self._attest_health(scenario_context)
        inputs: GradeInputs | None = None
        primary_error: BaseException | None = None
        try:
            with state_write_prohibited():
                grade_context = self._grade_context(before)
                if registration.snapshot_collector is not None:
                    snapshot = registration.snapshot_collector.collect(
                        grade_context, definition, before
                    )
                    if not isinstance(snapshot, GradeSnapshot):
                        raise ScenarioLifecycleError(
                            "snapshot collector returned an invalid observation"
                        )
                    evaluator = registration.snapshot_evaluator
                    if evaluator is None:
                        raise ScenarioLifecycleError("snapshot evaluator is unavailable")
                    inputs = evaluator.evaluate(snapshot, definition)
                else:
                    grader = registration.grader
                    if grader is None:
                        raise ScenarioLifecycleError("grade handler is unavailable")
                    inputs = grader.grade(grade_context, definition)
        except BaseException as error:
            primary_error = error
        try:
            health_after = self._attest_health(scenario_context)
            after = self._store.load(lab_name)
        except BaseException as integrity_error:
            raise ScenarioLifecycleError(
                "grade post-probe integrity attestation failed"
            ) from (primary_error or integrity_error)
        if after != before:
            raise ScenarioLifecycleError("grade changed persistent lab state") from primary_error
        if health_after != health_before:
            raise ScenarioLifecycleError("grade changed live lab state") from primary_error
        if primary_error is not None:
            raise primary_error
        if not isinstance(inputs, GradeInputs):
            raise ScenarioLifecycleError("grade handler returned an invalid evidence bundle")
        return inputs

    def prepare(self, lab_name: str, scenario_id: str) -> LabState:
        definition = self._catalog.require(scenario_id)
        if definition.support != "supported":
            raise ScenarioLifecycleError(
                f"full scenario {definition.scenario_id} is planned but not implemented"
            )
        with self._store.lock(lab_name):
            state = self._store.load(lab_name)
            if state.phase is LabPhase.CANDIDATE_READY or (
                state.phase is LabPhase.VALIDATED
                and state.health_fingerprint is None
            ):
                observed_health = self._attest_health(self._context(lab_name, state))
                state = self._store.attest_validated(
                    lab_name,
                    state.identity.lab_id,
                    observed_health,
                    detail="host baseline health attested",
                )
            if state.phase is not LabPhase.VALIDATED:
                raise ScenarioLifecycleError(
                    f"scenario prepare requires validated lab; current phase is {state.phase.value}"
                )
            registration = self._handlers.resolve(definition)
            attempt_id = str(uuid.uuid4())
            baseline_context = self._context(lab_name, state)
            prepared_fingerprint = self._require_fingerprint(
                registration.expected_prepared(
                    baseline_context, definition, attempt_id
                ),
                "expected prepared fingerprint",
            )
            restore_fingerprint = self._require_fingerprint(
                registration.expected_restored(
                    baseline_context, definition, attempt_id
                ),
                "expected restored fingerprint",
            )
            state = self._store.prepare_scenario(
                lab_name,
                state.identity.lab_id,
                scenario_id=definition.scenario_id,
                attempt_id=attempt_id,
                handler_identity=definition.handler_identity,
                recovery_class=definition.recovery_class,
                target_role=definition.target_role,
                prepared_fingerprint=prepared_fingerprint,
                restore_fingerprint=restore_fingerprint,
                detail=f"scenario {definition.scenario_id} write-ahead claim",
            )
            try:
                context = self._context(lab_name, state)
                observed = registration.mutator.prepare(context, definition)
                if observed != prepared_fingerprint:
                    raise ScenarioLifecycleError(
                        "prepared scenario fingerprint differs from the write-ahead claim"
                    )
                untouched = self._collect_grade_read_only(
                    lab_name, state, registration, definition
                )
                result = evaluate_live_grade(
                    untouched.expected, untouched.evidence, untouched.signals
                )
                if result.status is not GradeStatus.FAIL:
                    raise ScenarioLifecycleError(
                        "untouched prepared scenario must produce a zero-score FAIL grade"
                    )
                return state
            except BaseException as error:
                self._degrade(lab_name, state, error)
                raise

    def grade(self, lab_name: str, scenario_id: str) -> LiveGrade:
        definition = self._catalog.require(scenario_id)
        with self._store.lock(lab_name):
            before = self._store.load(lab_name)
            active = before.active_scenario
            if (
                before.phase is not LabPhase.SCENARIO_PREPARED
                or active is None
                or active.scenario_id != definition.scenario_id
                or active.handler_identity != definition.handler_identity
            ):
                raise ScenarioLifecycleError(
                    f"scenario {definition.scenario_id} is not the active prepared scenario"
                )
            try:
                inputs = self._collect_grade_read_only(
                    lab_name,
                    before,
                    self._handlers.resolve(definition),
                    definition,
                )
                return evaluate_live_grade(
                    inputs.expected, inputs.evidence, inputs.signals
                )
            except BaseException as error:
                self._degrade(lab_name, before, error)
                raise

    def restore(self, lab_name: str, scenario_id: str) -> LabState:
        definition = self._catalog.require(scenario_id)
        with self._store.lock(lab_name):
            state = self._store.load(lab_name)
            active = state.active_scenario
            if (
                state.phase not in {LabPhase.SCENARIO_PREPARED, LabPhase.DEGRADED}
                or active is None
                or active.scenario_id != definition.scenario_id
                or active.handler_identity != definition.handler_identity
            ):
                raise ScenarioLifecycleError(
                    f"scenario {definition.scenario_id} is not the active prepared scenario"
                )
            try:
                context = self._context(lab_name, state)
                registration = self._handlers.resolve(definition)
                observed_scenario = registration.mutator.restore(context, definition)
                if observed_scenario != active.restore_fingerprint:
                    raise ScenarioLifecycleError(
                        "restored scenario fingerprint differs from recovery contract"
                    )
                observed_health = self._attest_health(context)
                return self._store.restore_scenario(
                    lab_name,
                    state.identity.lab_id,
                    scenario_id=definition.scenario_id,
                    attempt_id=active.attempt_id,
                    health_fingerprint=observed_health,
                    scenario_fingerprint=observed_scenario,
                    detail=f"scenario {definition.scenario_id} restored and health attested",
                )
            except BaseException as error:
                self._degrade(lab_name, state, error)
                raise


__all__ = [
    "EXPECTED_SCENARIO_IDS",
    "FullScenarioDefinition",
    "GradeContext",
    "GradeInputs",
    "GradeSnapshot",
    "HandlerRegistry",
    "ReferenceSolutionRegistry",
    "RecoveryMode",
    "RecoverySignals",
    "RegisteredScenarioHandler",
    "ScenarioCatalog",
    "ScenarioContext",
    "ScenarioContractError",
    "ScenarioEngine",
    "ScenarioLifecycleError",
    "ScenarioGrader",
    "ScenarioMutator",
    "SnapshotCollector",
    "SnapshotEvaluator",
    "load_full_catalog",
    "preparation_claim_fingerprint",
    "scenario_state_fingerprint",
    "select_recovery_mode",
]
