"""Machine-readable full-tier release gate with exact cleanup ownership."""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

from .full import ROOT, build_lifecycle, build_scenario_runtime, require_host_preflight
from .live_grading import GradeStatus
from .providers.base import bounded_redacted, validate_identifier
from .recovery import recover_active_scenario
from .scenarios import (
    EXPECTED_SCENARIO_IDS,
    RecoverySignals,
    ScenarioContext,
    load_full_catalog,
)
from .state import LabPhase, LabStateStore, StateMissingError


_MAX_ERROR = 1536


def _safe_error(error: BaseException) -> str:
    return bounded_redacted(
        f"{type(error).__name__}: {error}", limit=_MAX_ERROR
    )


def _receipt_path(state_root: Path, run_id: str) -> Path:
    return state_root / "full-e2e" / run_id / "receipt.json"


def _secure_receipt_root(state_root: Path) -> Path:
    requested = Path(state_root).expanduser()
    if requested.is_symlink():
        raise RuntimeError("full E2E state root must not be a symlink")
    requested.mkdir(parents=True, mode=0o700, exist_ok=True)
    resolved = requested.resolve(strict=True)
    observed = resolved.lstat()
    if (
        resolved.is_symlink()
        or observed.st_uid != os.getuid()
        or (observed.st_mode & 0o777) != 0o700
    ):
        raise RuntimeError("full E2E state root must be an owner-only directory")
    receipt_root = resolved / "full-e2e"
    if receipt_root.is_symlink():
        raise RuntimeError("full E2E receipt root must not be a symlink")
    receipt_root.mkdir(mode=0o700, exist_ok=True)
    receipt_observed = receipt_root.lstat()
    if receipt_observed.st_uid != os.getuid() or (
        receipt_observed.st_mode & 0o777
    ) != 0o700:
        raise RuntimeError("full E2E receipt root must be owner-only")
    return receipt_root


def _write_receipt(state_root: Path, run_id: str, payload: dict[str, object]) -> Path:
    receipt_root = _secure_receipt_root(state_root)
    directory = receipt_root / run_id
    directory.mkdir(mode=0o700, exist_ok=False)
    if directory.is_symlink() or directory.lstat().st_uid != os.getuid():
        raise RuntimeError("full E2E receipt directory is not owner-controlled")
    os.chmod(directory, 0o700)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=".receipt-", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / "receipt.json")
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return directory / "receipt.json"


def _scenario_record(identifier: str) -> dict[str, object]:
    return {
        "scenario_id": identifier,
        "attempted": False,
        "passed": False,
        "untouched_status": None,
        "untouched_score": None,
        "reference_status": None,
        "reference_score": None,
        "repeat_identical": False,
        "restore_validated": False,
        "failed_criteria": [],
        "duration_seconds": 0.0,
        "error": None,
    }


def _run_scenario_matrix(
    lab_name: str,
    *,
    root: Path,
    state_root: Path,
) -> list[dict[str, object]]:
    engine, references = build_scenario_runtime(root=root, state_root=state_root)
    catalog = load_full_catalog(root / "scenarios" / "catalog.json")
    records: list[dict[str, object]] = []
    blocked = False
    for identifier in EXPECTED_SCENARIO_IDS:
        record = _scenario_record(identifier)
        records.append(record)
        if blocked:
            record["error"] = "not attempted because prior exact restore failed"
            continue
        started = time.monotonic()
        definition = catalog.require(identifier)
        try:
            state = engine.prepare(lab_name, identifier)
            record["attempted"] = True
            untouched = engine.grade(lab_name, identifier)
            record["untouched_status"] = untouched.status.value
            record["untouched_score"] = untouched.score
            if untouched.status is not GradeStatus.FAIL or untouched.score != 0.0:
                raise RuntimeError("untouched grade is not an exact zero-score FAIL")
            references.execute(
                definition,
                ScenarioContext(lab_name, state),
                timeout_seconds=900,
            )
            first = engine.grade(lab_name, identifier)
            second = engine.grade(lab_name, identifier)
            record["reference_status"] = first.status.value
            record["reference_score"] = first.score
            record["repeat_identical"] = first == second
            if (
                first.status is not GradeStatus.PASS
                or first.score != 100.0
                or first != second
            ):
                raise RuntimeError("reference grade is not a repeatable 100-score PASS")
            restored = engine.restore(lab_name, identifier)
            record["restore_validated"] = (
                restored.phase is LabPhase.VALIDATED
                and restored.active_scenario is None
            )
            if not record["restore_validated"]:
                raise RuntimeError("scenario restore did not return validated state")
            record["passed"] = True
        except BaseException as error:
            record["error"] = _safe_error(error)
            try:
                diagnostic_grade = engine.grade(lab_name, identifier)
                record["reference_status"] = diagnostic_grade.status.value
                record["reference_score"] = diagnostic_grade.score
                record["failed_criteria"] = [
                    criterion.criterion_id
                    for criterion in diagnostic_grade.criteria
                    if not criterion.passed
                ]
            except BaseException:
                pass
            try:
                state = LabStateStore(state_root, namespace="full").load(lab_name)
                if state.active_scenario is not None:
                    restored = engine.restore(lab_name, state.active_scenario.scenario_id)
                    record["restore_validated"] = restored.phase is LabPhase.VALIDATED
            except BaseException as restore_error:
                record["error"] = bounded_redacted(
                    f"{record['error']}; restore: {_safe_error(restore_error)}",
                    limit=_MAX_ERROR,
                )
                blocked = True
        finally:
            record["duration_seconds"] = round(time.monotonic() - started, 1)
    return records


def _rehearse_recovery(
    lab_name: str,
    *,
    root: Path,
    state_root: Path,
) -> dict[str, object]:
    engine, _references = build_scenario_runtime(root=root, state_root=state_root)
    definition = load_full_catalog(root / "scenarios" / "catalog.json").require("12")
    engine.prepare(lab_name, definition.scenario_id)
    untouched = engine.grade(lab_name, definition.scenario_id)
    if untouched.status is not GradeStatus.FAIL or untouched.score != 0.0:
        raise RuntimeError("recovery rehearsal did not start from untouched FAIL 0")
    result = recover_active_scenario(
        engine,
        lab_name,
        definition,
        RecoverySignals(
            api_available=False,
            operator_transport_available=True,
            guest_identity_intact=True,
        ),
    )
    payload = result.to_dict()
    payload["scenario_id"] = definition.scenario_id
    if not result.recovered or result.mode.value != "operator-transport":
        raise RuntimeError("operator-transport recovery rehearsal failed")
    return payload


def _cleanup_lab(
    lab_name: str,
    lifecycle: object,
    *,
    state_root: Path,
    keep: bool,
    successful_before_cleanup: bool,
) -> dict[str, object]:
    cleanup: dict[str, object] = {
        "attempted": False,
        "passed": False,
        "kept": False,
        "ordinary_error": None,
        "break_glass_attempted": False,
        "exact_handles": [],
        "phase": None,
        "residual_lab_paths": [],
        "error": None,
    }
    store = LabStateStore(state_root, namespace="full")
    try:
        state = store.load(lab_name)
    except StateMissingError:
        cleanup.update({"passed": True, "phase": "absent"})
        return cleanup
    cleanup["exact_handles"] = [machine.handle.value for machine in state.inventory]
    if keep and successful_before_cleanup:
        cleanup.update({"passed": True, "kept": True, "phase": state.phase.value})
        return cleanup
    cleanup["attempted"] = True
    ordinary_failed = False
    try:
        destroyed = lifecycle.destroy(lab_name)
    except BaseException as error:
        ordinary_failed = True
        cleanup["ordinary_error"] = _safe_error(error)
        cleanup["break_glass_attempted"] = True
        try:
            current = store.load(lab_name)
            destroyed = lifecycle.destroy(
                lab_name,
                break_glass=True,
                expected_lab_id=current.identity.lab_id,
            )
        except BaseException as break_glass_error:
            cleanup["error"] = _safe_error(break_glass_error)
            return cleanup
    try:
        verified = lifecycle.destroy(lab_name)
        lab_directory = store.state_path(lab_name).parent
        residual = (
            sorted(path.name for path in lab_directory.iterdir() if path.name != "state.json")
            if lab_directory.is_dir()
            else []
        )
        cleanup["phase"] = verified.phase.value
        cleanup["residual_lab_paths"] = residual
        cleanup["passed"] = (
            not ordinary_failed
            and destroyed.phase is LabPhase.DESTROYED
            and verified.phase is LabPhase.DESTROYED
            and not residual
        )
        if ordinary_failed:
            cleanup["error"] = "ordinary cleanup failed; exact UUID break-glass removed the lab"
        elif residual:
            cleanup["error"] = "unexpected residual paths remain in the lab state directory"
    except BaseException as error:
        cleanup["error"] = _safe_error(error)
    return cleanup


def _run_build(
    lab_name: str,
    *,
    root: Path,
    state_root: Path,
    run_matrix: bool,
    rehearse_recovery: bool,
    keep: bool,
) -> dict[str, object]:
    started = time.monotonic()
    record: dict[str, object] = {
        "name": lab_name,
        "lab_id": None,
        "provisioned": False,
        "idempotent": False,
        "recovery": None,
        "scenarios": [],
        "cleanup": None,
        "passed_before_cleanup": False,
        "passed": False,
        "duration_seconds": 0.0,
        "error": None,
    }
    lifecycle = None
    try:
        lifecycle = build_lifecycle(root=root, state_root=state_root)
        require_host_preflight(root=root, require_creation_capacity=True)
        first = lifecycle.provision(lab_name)
        record["lab_id"] = first.identity.lab_id
        record["provisioned"] = first.phase is LabPhase.CANDIDATE_READY
        second = lifecycle.provision(lab_name)
        record["idempotent"] = (
            second.phase is LabPhase.CANDIDATE_READY
            and second.identity.lab_id == first.identity.lab_id
            and second.inventory == first.inventory
        )
        if not record["provisioned"] or not record["idempotent"]:
            raise RuntimeError("full IaC provision did not converge idempotently")
        if rehearse_recovery:
            record["recovery"] = _rehearse_recovery(
                lab_name, root=root, state_root=state_root
            )
        if run_matrix:
            record["scenarios"] = _run_scenario_matrix(
                lab_name, root=root, state_root=state_root
            )
        scenarios = record["scenarios"]
        scenario_ok = not run_matrix or (
            isinstance(scenarios, list)
            and len(scenarios) == len(EXPECTED_SCENARIO_IDS)
            and all(item.get("passed") is True for item in scenarios)
        )
        recovery_ok = not rehearse_recovery or bool(
            isinstance(record["recovery"], dict)
            and record["recovery"].get("recovered") is True
        )
        record["passed_before_cleanup"] = bool(scenario_ok and recovery_ok)
    except BaseException as error:
        record["error"] = _safe_error(error)
    finally:
        if lifecycle is None:
            record["cleanup"] = {
                "attempted": False,
                "passed": True,
                "phase": "absent",
                "error": None,
            }
        else:
            record["cleanup"] = _cleanup_lab(
                lab_name,
                lifecycle,
                state_root=state_root,
                keep=keep,
                successful_before_cleanup=bool(record["passed_before_cleanup"]),
            )
        record["passed"] = bool(
            record["passed_before_cleanup"]
            and isinstance(record["cleanup"], dict)
            and record["cleanup"].get("passed") is True
        )
        record["duration_seconds"] = round(time.monotonic() - started, 1)
    return record


def run_full_e2e(
    base_name: Optional[str] = None,
    *,
    root: Path = ROOT,
    state_root: Optional[Path] = None,
    destroy_rebuild: bool = False,
    keep: bool = False,
) -> dict[str, object]:
    """Run the owned VM release gate and persist one bounded receipt."""

    if keep and destroy_rebuild:
        raise ValueError("--keep cannot be combined with --destroy-rebuild")
    root = Path(root).resolve(strict=True)
    state = Path(state_root) if state_root is not None else root / ".cks-state"
    run_id = str(uuid.uuid4())
    requested = base_name or f"cks-e2e-{os.getpid()}-{run_id[:8]}"
    validate_identifier(requested, field_name="full E2E name")
    names = [validate_identifier(f"{requested}-a", field_name="full E2E build name")]
    if destroy_rebuild:
        names.append(validate_identifier(f"{requested}-b", field_name="full E2E build name"))
    store = LabStateStore(state, namespace="full")
    for name in names:
        try:
            store.load(name)
        except StateMissingError:
            continue
        raise ValueError(f"refusing pre-existing full E2E lab state for {name!r}")

    started = time.monotonic()
    builds = [
        _run_build(
            names[0],
            root=root,
            state_root=state,
            run_matrix=True,
            rehearse_recovery=True,
            keep=keep,
        )
    ]
    if destroy_rebuild and builds[0]["passed"] is True:
        builds.append(
            _run_build(
                names[1],
                root=root,
                state_root=state,
                run_matrix=False,
                rehearse_recovery=False,
                keep=False,
            )
        )
    elif destroy_rebuild:
        builds.append(
            {
                "name": names[1],
                "passed": False,
                "skipped": True,
                "error": "build A failed; rebuild was not started",
                "scenarios": [],
                "cleanup": {"attempted": False, "passed": True, "phase": "absent"},
            }
        )

    scenario_records = builds[0].get("scenarios", [])
    attempted = sum(
        1 for item in scenario_records if isinstance(item, dict) and item.get("attempted")
    )
    passed = sum(
        1 for item in scenario_records if isinstance(item, dict) and item.get("passed")
    )
    successful = all(build.get("passed") is True for build in builds)
    payload: dict[str, object] = {
        "schema": 1,
        "run_id": run_id,
        "tier": "full",
        "command": "e2e",
        "name": requested,
        "destroy_rebuild": destroy_rebuild,
        "status": "PASS" if successful else "FAIL",
        "returncode": 0 if successful else 1,
        "coverage": {
            "expected_scenarios": len(EXPECTED_SCENARIO_IDS),
            "attempted_scenarios": attempted,
            "passed_scenarios": passed,
            "builds_expected": 2 if destroy_rebuild else 1,
            "builds_passed": sum(build.get("passed") is True for build in builds),
        },
        "builds": builds,
        "duration_seconds": round(time.monotonic() - started, 1),
        "receipt_path": str(_receipt_path(state, run_id)),
        "message": (
            f"full VM release gate: {passed}/{len(EXPECTED_SCENARIO_IDS)} scenarios, "
            f"{sum(build.get('passed') is True for build in builds)}/{len(builds)} builds"
        ),
    }
    _write_receipt(state, run_id, payload)
    return payload


__all__ = ["run_full_e2e"]
