"""Structured CLI adapter for the opt-in full VM tier."""

from __future__ import annotations

import json
import os
import subprocess
from argparse import Namespace
from pathlib import Path
from typing import Callable, Optional, Sequence

from .full import (
    ROOT,
    build_lifecycle,
    build_scenario_engine,
    host_preflight,
    locate_lima,
    require_host_preflight,
)
from .live_grading import GradeStatus
from .providers.base import canonical_uuid, validate_identifier
from .state import LabStateStore, StateMissingError


DEFAULT_FULL_LAB = "cks-simulator"
_SAFE_INTERACTIVE_ENV = {
    "HOME": str(Path.home()),
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "TERM": os.environ.get("TERM", "xterm-256color"),
}


def _lab_name(args: Namespace) -> str:
    return validate_identifier(
        getattr(args, "name", None) or DEFAULT_FULL_LAB,
        field_name="full lab name",
    )


def _emit(payload: dict[str, object], *, as_json: bool) -> int:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if payload.get("command") == "doctor":
            for item in payload.get("checks", []):
                if isinstance(item, dict):
                    print(
                        f"{'PASS' if item.get('passed') else 'FAIL'}  "
                        f"{item.get('name')}: {item.get('detail')}"
                    )
        print(str(payload["message"]))
    return int(payload["returncode"])


def _lab_exists(state_root: Path, name: str) -> bool:
    try:
        LabStateStore(state_root, namespace="full").load(name)
    except StateMissingError:
        return False
    return True


def _doctor(args: Namespace, *, root: Path, state_root: Path) -> int:
    lab_mode = bool(getattr(args, "lab", False))
    if not lab_mode and getattr(args, "name", None) is not None:
        raise ValueError("--name requires --lab for full-tier doctor")
    name = _lab_name(args) if lab_mode else None
    if lab_mode and not _lab_exists(state_root, name):
        raise ValueError(f"full lab {name!r} does not exist; provision it before lab doctor")
    checks = host_preflight(root=root, require_creation_capacity=not lab_mode)
    passed = sum(item.passed for item in checks)
    state = None
    if lab_mode and passed == len(checks):
        lifecycle = build_lifecycle(root=root, state_root=state_root)
        if lifecycle.requires_creation_capacity(name):
            checks = host_preflight(root=root, require_creation_capacity=True)
            passed = sum(item.passed for item in checks)
        if passed == len(checks):
            state = lifecycle.provision(name)
    payload: dict[str, object] = {
        "status": "pass" if passed == len(checks) else "fail",
        "tier": "full",
        "command": "doctor",
        "returncode": 0 if passed == len(checks) else 1,
        "message": (
            f"full-tier lab {name} reached {state.phase.value}"
            if state is not None
            else f"full-tier host preflight: {passed}/{len(checks)} checks passed"
        ),
        "checks": [item.to_dict() for item in checks],
    }
    if state is not None:
        payload.update(
            {
                "name": name,
                "phase": state.phase.value,
                "lab_id": state.identity.lab_id,
            }
        )
    return _emit(payload, as_json=bool(getattr(args, "as_json", False)))


def _provision(args: Namespace, *, root: Path, state_root: Path) -> int:
    if hasattr(args, "image"):
        raise ValueError("--image is supported only by the quick tier")
    if hasattr(args, "wait"):
        raise ValueError("--wait is supported only by the quick tier")
    name = _lab_name(args)
    exists = _lab_exists(state_root, name)
    require_host_preflight(root=root, require_creation_capacity=not exists)
    lifecycle = build_lifecycle(root=root, state_root=state_root)
    if exists and lifecycle.requires_creation_capacity(name):
        require_host_preflight(root=root, require_creation_capacity=True)
    state = lifecycle.provision(name)
    return _emit(
        {
            "status": "ok",
            "tier": "full",
            "command": "provision",
            "name": name,
            "phase": state.phase.value,
            "lab_id": state.identity.lab_id,
            "returncode": 0,
            "message": f"full VM lab {name} reached {state.phase.value}",
        },
        as_json=bool(getattr(args, "as_json", False)),
    )


def _delete(args: Namespace, *, root: Path, state_root: Path) -> int:
    if bool(getattr(args, "force", False)):
        raise ValueError("--force is supported only by the quick tier; use full-tier break-glass authorization")
    name = _lab_name(args)
    break_glass = bool(getattr(args, "break_glass", False))
    expected_lab_id = getattr(args, "expected_lab_id", None)
    if break_glass and expected_lab_id is None:
        raise ValueError("--break-glass requires --expected-lab-id")
    if expected_lab_id is not None and not break_glass:
        raise ValueError("--expected-lab-id requires --break-glass")
    if expected_lab_id is not None:
        canonical_uuid(expected_lab_id, field_name="expected lab ID")
    state = build_lifecycle(
        root=root, state_root=state_root, destroy_only=True
    ).destroy(
        name,
        break_glass=break_glass,
        expected_lab_id=expected_lab_id,
    )
    return _emit(
        {
            "status": "ok",
            "tier": "full",
            "command": "delete",
            "name": name,
            "phase": state.phase.value,
            "lab_id": state.identity.lab_id,
            "returncode": 0,
            "message": f"full VM lab {name} is {state.phase.value}",
        },
        as_json=bool(getattr(args, "as_json", False)),
    )


def _shell(
    args: Namespace,
    *,
    root: Path,
    state_root: Path,
    run_interactive: Callable[..., subprocess.CompletedProcess],
) -> int:
    name = _lab_name(args)
    requested_node = getattr(args, "node", None)
    if requested_node not in (None, "candidate"):
        raise ValueError("full-tier shell opens only the candidate workstation")
    requested_shell = getattr(args, "shell", None)
    if requested_shell not in (None, "/bin/bash"):
        raise ValueError("full-tier shell executable must be /bin/bash")
    if not _lab_exists(state_root, name):
        raise ValueError(f"full lab {name!r} does not exist")
    require_host_preflight(root=root, require_creation_capacity=False)
    lifecycle = build_lifecycle(root=root, state_root=state_root)
    if lifecycle.requires_creation_capacity(name):
        require_host_preflight(root=root, require_creation_capacity=True)
    lifecycle.provision(name)
    candidate = lifecycle.verified_candidate_handle(name)
    lima = locate_lima()
    if lima is None:
        raise RuntimeError("limactl is unavailable")
    command = (
        lima,
        "shell",
        "--tty=true",
        candidate.value,
        "--",
        "/usr/bin/sudo",
        "--login",
        "--user",
        "candidate",
        "--",
        "/bin/bash",
        "--login",
    )
    value = run_interactive(command, env=dict(_SAFE_INTERACTIVE_ENV), check=False)
    return int(value.returncode)


def _scenario(args: Namespace, *, root: Path, state_root: Path) -> int:
    name = _lab_name(args)
    engine = build_scenario_engine(root=root, state_root=state_root)
    operation = getattr(args, "scenario_command", None)
    if operation == "prepare":
        state = engine.prepare(name, args.id)
        message = f"full scenario {args.id.zfill(2)} prepared on {name}"
    elif operation == "restore":
        state = engine.restore(name, args.id)
        message = f"full scenario {args.id.zfill(2)} restored on {name}"
    else:
        raise ValueError("full-tier scenario operation must be prepare or restore")
    active = state.active_scenario
    return _emit(
        {
            "status": "ok",
            "tier": "full",
            "command": f"scenario {operation}",
            "scenario_id": args.id.zfill(2),
            "name": name,
            "phase": state.phase.value,
            "attempt_id": active.attempt_id if active is not None else None,
            "returncode": 0,
            "message": message,
        },
        as_json=bool(getattr(args, "as_json", False)),
    )


def _grade(args: Namespace, *, root: Path, state_root: Path) -> int:
    if args.id.lower() == "all":
        raise ValueError("full-tier grade requires one active scenario ID")
    name = _lab_name(args)
    result = build_scenario_engine(root=root, state_root=state_root).grade(name, args.id)
    payload = result.to_payload()
    payload.update(
        {
            "tier": "full",
            "command": "grade",
            "scenario_id": args.id.zfill(2),
            "name": name,
            "returncode": 0 if result.status is GradeStatus.PASS else 1,
            "message": (
                f"full scenario {args.id.zfill(2)} score: "
                f"{result.score:.2f}/100 ({result.status.value})"
            ),
        }
    )
    return _emit(payload, as_json=bool(getattr(args, "as_json", False)))


def dispatch_full_command(
    args: Namespace,
    *,
    root: Path = ROOT,
    state_root: Optional[Path] = None,
    run_interactive: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> int:
    """Dispatch implemented full-tier lifecycle and scenario commands."""

    root = Path(root).resolve(strict=True)
    state = Path(state_root) if state_root is not None else root / ".cks-state"
    if args.command == "doctor":
        return _doctor(args, root=root, state_root=state)
    if args.command == "provision":
        return _provision(args, root=root, state_root=state)
    if args.command == "delete":
        return _delete(args, root=root, state_root=state)
    if args.command == "shell":
        return _shell(
            args,
            root=root,
            state_root=state,
            run_interactive=run_interactive,
        )
    if args.command == "scenario":
        return _scenario(args, root=root, state_root=state)
    if args.command == "grade":
        return _grade(args, root=root, state_root=state)
    raise RuntimeError(
        f"full tier for {args.command!r} is reserved for a later implementation unit"
    )


__all__ = ["DEFAULT_FULL_LAB", "dispatch_full_command"]
