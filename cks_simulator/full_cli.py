"""Structured CLI adapter for the opt-in full VM tier."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from typing import Callable, Optional, Sequence

from .full import (
    DEFAULT_MEMORY_PROFILE,
    ROOT,
    build_exam_engine,
    build_lifecycle,
    build_scenario_engine,
    host_preflight,
    locate_lima,
    require_host_preflight,
    resolve_memory_profile,
)
from .desktop import LimaDesktopTunnel
from .exam import ExamMode, ExamStatus
from .exam_server import ExamUIServer, StoredExamController
from .live_grading import GradeStatus
from .prerequisites import install_full_prerequisites
from .providers.base import canonical_uuid, validate_identifier
from .scenarios import ScenarioLifecycleError, load_full_catalog
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


def _memory_profile(args: Namespace, state_root: Path, name: Optional[str] = None) -> str:
    requested = getattr(args, "memory_profile", None)
    if requested is not None:
        return resolve_memory_profile(requested).name
    if name is not None:
        try:
            state = LabStateStore(state_root, namespace="full").load(name)
        except StateMissingError:
            pass
        else:
            return resolve_memory_profile(
                state.provisioning_profile or DEFAULT_MEMORY_PROFILE
            ).name
    return DEFAULT_MEMORY_PROFILE


def _profile_kwargs(profile: str) -> dict[str, str]:
    """Keep the established standard-profile call contract unchanged."""

    return {} if profile == DEFAULT_MEMORY_PROFILE else {"memory_profile": profile}


def _doctor(args: Namespace, *, root: Path, state_root: Path) -> int:
    lab_mode = bool(getattr(args, "lab", False))
    if not lab_mode and getattr(args, "name", None) is not None:
        raise ValueError("--name requires --lab for full-tier doctor")
    name = _lab_name(args) if lab_mode else None
    if lab_mode and not _lab_exists(state_root, name):
        raise ValueError(f"full lab {name!r} does not exist; provision it before lab doctor")
    profile = _memory_profile(args, state_root, name)
    checks = host_preflight(
        root=root,
        require_creation_capacity=not lab_mode,
        **_profile_kwargs(profile),
    )
    passed = sum(item.passed for item in checks)
    state = None
    if lab_mode and passed == len(checks):
        lifecycle = build_lifecycle(
            root=root, state_root=state_root, **_profile_kwargs(profile)
        )
        if lifecycle.requires_creation_capacity(name):
            checks = host_preflight(
                root=root,
                require_creation_capacity=True,
                **_profile_kwargs(profile),
            )
            passed = sum(item.passed for item in checks)
        if passed == len(checks):
            state = lifecycle.provision(name)
    payload: dict[str, object] = {
        "status": "pass" if passed == len(checks) else "fail",
        "tier": "full",
        "command": "doctor",
        "memory_profile": profile,
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


def _setup(args: Namespace, *, root: Path, state_root: Path) -> int:
    profile = _memory_profile(args, state_root)
    installed = install_full_prerequisites(root=root)
    checks = host_preflight(root=root, **_profile_kwargs(profile))
    passed = sum(item.passed for item in checks)
    payload: dict[str, object] = {
        "status": "pass" if passed == len(checks) else "fail",
        "tier": "full",
        "command": "setup",
        "memory_profile": profile,
        "returncode": 0 if passed == len(checks) else 1,
        "message": (
            "full-tier prerequisites ready; host preflight: "
            f"{passed}/{len(checks)} checks passed"
        ),
        "installation": installed.to_dict(),
        "checks": [item.to_dict() for item in checks],
    }
    if not bool(getattr(args, "as_json", False)):
        action = "installed" if installed.changed else "already present"
        print(
            f"{'INSTALLED' if installed.changed else 'PASS'}  "
            f"{installed.name}: {installed.version} ({action}; {installed.command})"
        )
    return _emit(payload, as_json=bool(getattr(args, "as_json", False)))


def _provision(args: Namespace, *, root: Path, state_root: Path) -> int:
    if hasattr(args, "image"):
        raise ValueError("--image is supported only by the quick tier")
    if hasattr(args, "wait"):
        raise ValueError("--wait is supported only by the quick tier")
    name = _lab_name(args)
    exists = _lab_exists(state_root, name)
    profile = _memory_profile(args, state_root, name if exists else None)
    require_host_preflight(
        root=root,
        require_creation_capacity=not exists,
        **_profile_kwargs(profile),
    )
    lifecycle = build_lifecycle(
        root=root, state_root=state_root, **_profile_kwargs(profile)
    )
    if exists and lifecycle.requires_creation_capacity(name):
        require_host_preflight(
            root=root, require_creation_capacity=True, **_profile_kwargs(profile)
        )
    state = lifecycle.provision(name)
    return _emit(
        {
            "status": "ok",
            "tier": "full",
            "command": "provision",
            "name": name,
            "phase": state.phase.value,
            "lab_id": state.identity.lab_id,
            "memory_profile": profile,
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
    profile = _memory_profile(args, state_root, name)
    require_host_preflight(
        root=root, require_creation_capacity=False, **_profile_kwargs(profile)
    )
    lifecycle = build_lifecycle(
        root=root, state_root=state_root, **_profile_kwargs(profile)
    )
    if lifecycle.requires_creation_capacity(name):
        require_host_preflight(
            root=root, require_creation_capacity=True, **_profile_kwargs(profile)
        )
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
    definition = load_full_catalog(root / "scenarios" / "catalog.json").require(args.id)
    if definition.support != "supported":
        raise ScenarioLifecycleError(
            f"full scenario {definition.scenario_id} is planned but not implemented"
        )
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


def _serve_exam_ui(
    args: Namespace,
    *,
    name: str,
    lifecycle,
    engine,
) -> int:
    session = engine.load(name)
    tunnel = None
    if session.status is ExamStatus.ACTIVE:
        lima = locate_lima()
        if lima is None:
            raise RuntimeError("limactl is unavailable")
        tunnel = LimaDesktopTunnel(
            lifecycle.verified_candidate_handle(name),
            limactl_command=(lima,),
        ).start()
    controller = StoredExamController(
        lab_name=name,
        store=engine.session_store,
        manifest=engine.manifest,
        grade_one=lambda task_id: engine.grade_task(name, task_id),
        grade_all=lambda: engine.grade_all(name),
        desktop_url=tunnel.url if tunnel is not None else None,
        on_submission_start=tunnel.close if tunnel is not None else None,
    )
    server = ExamUIServer(controller)
    thread = server.start_background()
    print(f"CKS ExamUI: {server.address.url}")
    print("Ctrl-C closes the local UI bridge; the VM lab and exam session remain resumable.")
    if not bool(getattr(args, "no_open", False)):
        try:
            subprocess.run(
                ("/usr/bin/open", server.address.url),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError as error:
            print(f"warning: browser could not be opened: {error}", file=sys.stderr)
    try:
        while thread.is_alive():
            thread.join(timeout=1.0)
    except KeyboardInterrupt:
        return 0
    finally:
        server.close()
        if tunnel is not None:
            tunnel.close()
    return 0


def _exam(args: Namespace, *, root: Path, state_root: Path) -> int:
    name = _lab_name(args)
    operation = getattr(args, "exam_command", None)
    engine = build_exam_engine(root=root, state_root=state_root)
    if operation == "status":
        session = engine.load(name)
        return _emit(
            {
                "status": "ok",
                "tier": "full",
                "command": "exam status",
                "name": name,
                "exam_status": session.status.value,
                "mode": session.mode.value,
                "session_id": session.session_id,
                "started_at": session.started_at,
                "deadline_at": session.deadline_at,
                "submitted_at": session.submitted_at,
                "score": (session.receipt or {}).get("score"),
                "returncode": 0,
                "message": f"exam session on {name} is {session.status.value}",
            },
            as_json=bool(getattr(args, "as_json", False)),
        )
    if operation == "teardown":
        session = engine.load(name)
        engine.teardown(name, force_active=bool(getattr(args, "force", False)))
        return _emit(
            {
                "status": "ok",
                "tier": "full",
                "command": "exam teardown",
                "name": name,
                "session_id": session.session_id,
                "returncode": 0,
                "message": f"exam session on {name} restored and removed",
            },
            as_json=bool(getattr(args, "as_json", False)),
        )
    if operation not in {"start", "resume"}:
        raise ValueError("full-tier exam operation is invalid")

    exists = _lab_exists(state_root, name)
    profile = _memory_profile(args, state_root, name if exists else None)
    require_host_preflight(
        root=root,
        require_creation_capacity=not exists,
        **_profile_kwargs(profile),
    )
    lifecycle = build_lifecycle(
        root=root,
        state_root=state_root,
        **_profile_kwargs(profile),
    )
    if exists and lifecycle.requires_creation_capacity(name):
        require_host_preflight(
            root=root,
            require_creation_capacity=True,
            **_profile_kwargs(profile),
        )
    lifecycle.provision(name)
    if operation == "start":
        engine.start(
            name,
            mode=ExamMode(getattr(args, "mode", "practice")),
            duration_seconds=int(getattr(args, "duration", 2 * 60 * 60)),
        )
    else:
        engine.load(name)
    return _serve_exam_ui(args, name=name, lifecycle=lifecycle, engine=engine)


def _e2e(args: Namespace, *, root: Path, state_root: Path) -> int:
    from .e2e import run_full_e2e

    payload = run_full_e2e(
        getattr(args, "name", None),
        root=root,
        state_root=state_root,
        destroy_rebuild=bool(getattr(args, "destroy_rebuild", False)),
        keep=bool(getattr(args, "keep", False)),
        **_profile_kwargs(_memory_profile(args, state_root)),
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
    if args.command == "setup":
        return _setup(args, root=root, state_root=state)
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
    if args.command == "exam":
        return _exam(args, root=root, state_root=state)
    if args.command == "e2e":
        return _e2e(args, root=root, state_root=state)
    raise RuntimeError(
        f"full tier for {args.command!r} is reserved for a later implementation unit"
    )


__all__ = ["DEFAULT_FULL_LAB", "dispatch_full_command"]
