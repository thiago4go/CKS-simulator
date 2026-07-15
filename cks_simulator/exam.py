"""Host-owned exam sessions and deterministic aggregate scoring.

The candidate browser is an untrusted view over this state.  It may request
navigation/progress changes, but it never supplies time, score, evidence, lab
identity, task membership, or lifecycle authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
import fcntl
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence, Tuple

from .live_grading import GradeStatus, LiveGrade
from .providers.base import canonical_uuid, validate_identifier


EXAM_SCHEMA_VERSION = 1
DEFAULT_EXAM_DURATION_SECONDS = 2 * 60 * 60
MIN_EXAM_DURATION_SECONDS = 60
MAX_EXAM_DURATION_SECONDS = 6 * 60 * 60
PASS_SCORE = 67.0
MAX_EXAM_STATE_BYTES = 2 * 1024 * 1024
EXPECTED_TASK_IDS = tuple(f"{value:02d}" for value in range(1, 18))
TASK_WEIGHTS = (4, 4, 5, 5, 5, 5, 5, 5, 6, 6, 7, 7, 7, 7, 7, 7, 8)


class ExamError(RuntimeError):
    """Base error for candidate exam sessions."""


class ExamStateError(ExamError):
    pass


class ExamConflictError(ExamError):
    pass


class ExamMode(str, Enum):
    PRACTICE = "practice"
    EXAM = "exam"


class ExamStatus(str, Enum):
    PREPARING = "preparing"
    ACTIVE = "active"
    SUBMITTING = "submitting"
    SUBMITTED = "submitted"
    FAILED = "failed"


class ExamEndReason(str, Enum):
    MANUAL = "manual"
    EXPIRED = "expired"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ExamStateError("exam timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise ExamStateError(f"{field} must be a bounded UTC timestamp")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ExamStateError(f"{field} is invalid") from error
    if result.tzinfo is None:
        raise ExamStateError(f"{field} must be timezone-aware")
    return result.astimezone(timezone.utc)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


@dataclass(frozen=True)
class ExamTask:
    task_id: str
    title: str
    domain: str
    host: str
    target_role: str
    workdir: str
    prompt: str
    weight: int

    def __post_init__(self) -> None:
        if self.task_id not in EXPECTED_TASK_IDS:
            raise ExamStateError("exam task ID is invalid")
        for field, value, limit in (
            ("title", self.title, 200),
            ("domain", self.domain, 100),
            ("prompt", self.prompt, 8000),
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > limit:
                raise ExamStateError(f"exam task {field} is invalid")
        validate_identifier(self.host, field_name="exam task host")
        validate_identifier(self.target_role, field_name="exam task target role")
        path = Path(self.workdir)
        if not path.is_absolute() or ".." in path.parts or not str(path).startswith("/opt/course/"):
            raise ExamStateError("exam task workdir is unsafe")
        if isinstance(self.weight, bool) or not isinstance(self.weight, int) or self.weight < 1:
            raise ExamStateError("exam task weight must be a positive integer")

    def to_candidate_dict(self) -> dict[str, object]:
        return {
            "id": self.task_id,
            "title": self.title,
            "domain": self.domain,
            "host": self.host,
            "target_role": self.target_role,
            "workdir": self.workdir,
            "prompt": self.prompt,
            "weight": self.weight,
        }


@dataclass(frozen=True)
class ExamManifest:
    tasks: Tuple[ExamTask, ...]
    catalog_sha256: str
    manifest_sha256: str

    def __post_init__(self) -> None:
        if tuple(task.task_id for task in self.tasks) != EXPECTED_TASK_IDS:
            raise ExamStateError("exam manifest must contain tasks 01 through 17 in order")
        if sum(task.weight for task in self.tasks) != 100:
            raise ExamStateError("exam task weights must total 100")
        for name, value in (
            ("catalog", self.catalog_sha256),
            ("manifest", self.manifest_sha256),
        ):
            if not isinstance(value, str) or len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise ExamStateError(f"{name} digest is invalid")

    def candidate_tasks(self) -> list[dict[str, object]]:
        return [task.to_candidate_dict() for task in self.tasks]


def build_exam_manifest(catalog_path: Path) -> ExamManifest:
    """Freeze the reviewed full-tier catalog into candidate-safe task text."""

    path = Path(catalog_path).resolve(strict=True)
    raw = path.read_bytes()
    try:
        catalog = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ExamStateError("scenario catalog is invalid JSON") from error
    if not isinstance(catalog, list) or len(catalog) != len(EXPECTED_TASK_IDS):
        raise ExamStateError("exam catalog must contain exactly 17 tasks")
    tasks = []
    for index, (item, task_id, weight) in enumerate(
        zip(catalog, EXPECTED_TASK_IDS, TASK_WEIGHTS), start=1
    ):
        if not isinstance(item, Mapping) or item.get("id") != task_id:
            raise ExamStateError("exam catalog IDs must be canonical and ordered")
        full = item.get("full")
        if not isinstance(full, Mapping) or full.get("support") != "supported":
            raise ExamStateError(f"exam task {task_id} is not supported by the full tier")
        target = item.get("target")
        if not isinstance(target, str):
            raise ExamStateError(f"exam task {task_id} has no target host")
        workdir = f"/opt/course/{index}"
        prompt = item.get("prompt")
        if not isinstance(prompt, str):
            raise ExamStateError(f"exam task {task_id} has no prompt")
        # The quick tier calls its answer directory ``artifacts``.  Full-tier
        # candidate files live at the original Killer Shell /opt/course path.
        prompt = prompt.replace("artifacts/", f"{workdir}/")
        tasks.append(
            ExamTask(
                task_id=task_id,
                title=str(item.get("title", "")),
                domain=str(item.get("domain", "")),
                host=f"{target}-q{task_id}",
                target_role=str(full.get("target_role", "")),
                workdir=workdir,
                prompt=prompt,
                weight=weight,
            )
        )
    candidate_payload = [task.to_candidate_dict() for task in tasks]
    return ExamManifest(
        tasks=tuple(tasks),
        catalog_sha256=_sha256(raw),
        manifest_sha256=_sha256(_canonical_json(candidate_payload)),
    )


@dataclass(frozen=True)
class ExamTaskProgress:
    task_id: str
    attempt_id: str
    visited: bool = False
    flagged: bool = False
    completed: bool = False

    def __post_init__(self) -> None:
        if self.task_id not in EXPECTED_TASK_IDS:
            raise ExamStateError("exam progress task ID is invalid")
        canonical_uuid(self.attempt_id, field_name="exam task attempt ID")
        if any(not isinstance(value, bool) for value in (self.visited, self.flagged, self.completed)):
            raise ExamStateError("exam progress flags must be boolean")

    def to_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "attempt_id": self.attempt_id,
            "visited": self.visited,
            "flagged": self.flagged,
            "completed": self.completed,
        }


@dataclass(frozen=True)
class ExamSession:
    lab_name: str
    lab_id: str
    session_id: str
    mode: ExamMode
    status: ExamStatus
    catalog_sha256: str
    manifest_sha256: str
    duration_seconds: int
    created_at: str
    started_at: str | None
    deadline_at: str | None
    submitted_at: str | None
    end_reason: ExamEndReason | None
    selected_task_id: str
    tasks: Tuple[ExamTaskProgress, ...]
    claimed_task_ids: Tuple[str, ...] = ()
    prepared_task_ids: Tuple[str, ...] = ()
    receipt: Mapping[str, object] | None = None
    failure: str | None = None
    revision: int = 0
    schema_version: int = EXAM_SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.lab_name, field_name="exam lab name")
        canonical_uuid(self.lab_id, field_name="exam lab ID")
        canonical_uuid(self.session_id, field_name="exam session ID")
        if not isinstance(self.mode, ExamMode) or not isinstance(self.status, ExamStatus):
            raise ExamStateError("exam mode or status is invalid")
        if self.schema_version != EXAM_SCHEMA_VERSION:
            raise ExamStateError("unsupported exam state schema")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or self.revision < 0:
            raise ExamStateError("exam revision is invalid")
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, int)
            or not MIN_EXAM_DURATION_SECONDS <= self.duration_seconds <= MAX_EXAM_DURATION_SECONDS
        ):
            raise ExamStateError("exam duration is outside the supported range")
        _parse_timestamp(self.created_at, "created_at")
        if tuple(task.task_id for task in self.tasks) != EXPECTED_TASK_IDS:
            raise ExamStateError("exam progress must contain tasks 01 through 17")
        for name, values in (
            ("claimed", self.claimed_task_ids),
            ("prepared", self.prepared_task_ids),
        ):
            if not isinstance(values, tuple) or values != EXPECTED_TASK_IDS[: len(values)]:
                raise ExamStateError(f"exam {name} task IDs must be a canonical prefix")
        if len(self.prepared_task_ids) > len(self.claimed_task_ids):
            raise ExamStateError("prepared exam tasks must have write-ahead claims")
        if self.prepared_task_ids != self.claimed_task_ids[: len(self.prepared_task_ids)]:
            raise ExamStateError("prepared exam tasks do not match their claims")
        if self.selected_task_id not in EXPECTED_TASK_IDS:
            raise ExamStateError("selected exam task is invalid")
        for value in (self.catalog_sha256, self.manifest_sha256):
            if not isinstance(value, str) or len(value) != 64:
                raise ExamStateError("exam manifest digest is invalid")
        if self.status is ExamStatus.PREPARING or (
            self.status is ExamStatus.FAILED
            and self.started_at is None
            and self.deadline_at is None
        ):
            if any(value is not None for value in (self.started_at, self.deadline_at, self.submitted_at, self.end_reason, self.receipt)):
                raise ExamStateError("unstarted exam contains terminal or timer state")
        else:
            if self.started_at is None or self.deadline_at is None:
                raise ExamStateError("started exam is missing its authoritative timer")
            start = _parse_timestamp(self.started_at, "started_at")
            deadline = _parse_timestamp(self.deadline_at, "deadline_at")
            if deadline != start + timedelta(seconds=self.duration_seconds):
                raise ExamStateError("exam deadline does not match its immutable duration")
        if self.status is ExamStatus.SUBMITTED:
            if self.submitted_at is None or self.end_reason is None or self.receipt is None:
                raise ExamStateError("submitted exam is missing its final receipt")
            _parse_timestamp(self.submitted_at, "submitted_at")
        elif self.receipt is not None:
            raise ExamStateError("only a submitted exam may contain a receipt")
        if self.failure is not None and (not isinstance(self.failure, str) or len(self.failure) > 2048):
            raise ExamStateError("exam failure detail is invalid")

    @classmethod
    def create(
        cls,
        *,
        lab_name: str,
        lab_id: str,
        mode: ExamMode,
        manifest: ExamManifest,
        duration_seconds: int = DEFAULT_EXAM_DURATION_SECONDS,
        now: datetime | None = None,
    ) -> "ExamSession":
        created = now or utc_now()
        return cls(
            lab_name=lab_name,
            lab_id=lab_id,
            session_id=str(uuid.uuid4()),
            mode=mode,
            status=ExamStatus.PREPARING,
            catalog_sha256=manifest.catalog_sha256,
            manifest_sha256=manifest.manifest_sha256,
            duration_seconds=duration_seconds,
            created_at=_timestamp(created),
            started_at=None,
            deadline_at=None,
            submitted_at=None,
            end_reason=None,
            selected_task_id=EXPECTED_TASK_IDS[0],
            tasks=tuple(
                ExamTaskProgress(task_id=task_id, attempt_id=str(uuid.uuid4()))
                for task_id in EXPECTED_TASK_IDS
            ),
        )

    def claim_preparation(self, task_id: str) -> "ExamSession":
        """Persist one write-ahead task claim before any guest mutation."""

        if self.status is not ExamStatus.PREPARING:
            raise ExamConflictError("task preparation can be claimed only while preparing")
        next_index = len(self.claimed_task_ids)
        if next_index >= len(EXPECTED_TASK_IDS) or task_id != EXPECTED_TASK_IDS[next_index]:
            raise ExamConflictError("exam task preparation claims must be ordered and unique")
        if len(self.claimed_task_ids) != len(self.prepared_task_ids):
            raise ExamConflictError("the previous exam task claim is not confirmed")
        return replace(
            self,
            claimed_task_ids=self.claimed_task_ids + (task_id,),
            revision=self.revision + 1,
        )

    def confirm_preparation(self, task_id: str) -> "ExamSession":
        if self.status is not ExamStatus.PREPARING:
            raise ExamConflictError("task preparation can be confirmed only while preparing")
        if not self.claimed_task_ids or self.claimed_task_ids[-1] != task_id:
            raise ExamConflictError("exam task has no matching write-ahead claim")
        if len(self.claimed_task_ids) != len(self.prepared_task_ids) + 1:
            raise ExamConflictError("exam task preparation is already confirmed")
        return replace(
            self,
            prepared_task_ids=self.prepared_task_ids + (task_id,),
            revision=self.revision + 1,
        )

    def activate(self, *, now: datetime | None = None) -> "ExamSession":
        if self.status is not ExamStatus.PREPARING:
            raise ExamConflictError("only a preparing exam can be activated")
        started = now or utc_now()
        return replace(
            self,
            status=ExamStatus.ACTIVE,
            started_at=_timestamp(started),
            deadline_at=_timestamp(started + timedelta(seconds=self.duration_seconds)),
            revision=self.revision + 1,
        )

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if self.deadline_at is None:
            return False
        return (now or utc_now()).astimezone(timezone.utc) >= _parse_timestamp(
            self.deadline_at, "deadline_at"
        )

    def update_progress(
        self,
        task_id: str,
        *,
        selected: bool = False,
        visited: bool | None = None,
        flagged: bool | None = None,
        completed: bool | None = None,
        now: datetime | None = None,
    ) -> "ExamSession":
        if self.status is not ExamStatus.ACTIVE:
            raise ExamConflictError("exam progress can change only while active")
        if self.is_expired(now=now):
            raise ExamConflictError("exam deadline has elapsed")
        if task_id not in EXPECTED_TASK_IDS:
            raise ExamStateError("exam task ID is invalid")
        updates = {"visited": visited, "flagged": flagged, "completed": completed}
        if any(value is not None and not isinstance(value, bool) for value in updates.values()):
            raise ExamStateError("exam progress values must be boolean")
        changed = []
        for item in self.tasks:
            if item.task_id != task_id:
                changed.append(item)
                continue
            changed.append(
                replace(
                    item,
                    visited=item.visited if visited is None else visited,
                    flagged=item.flagged if flagged is None else flagged,
                    completed=item.completed if completed is None else completed,
                )
            )
        return replace(
            self,
            selected_task_id=task_id if selected else self.selected_task_id,
            tasks=tuple(changed),
            revision=self.revision + 1,
        )

    def begin_submit(
        self,
        *,
        reason: ExamEndReason,
        now: datetime | None = None,
    ) -> "ExamSession":
        if self.status is ExamStatus.SUBMITTING:
            return self
        if self.status is ExamStatus.SUBMITTED:
            return self
        if self.status is not ExamStatus.ACTIVE:
            raise ExamConflictError("only an active exam can be submitted")
        observed = now or utc_now()
        if reason is ExamEndReason.MANUAL and self.is_expired(now=observed):
            reason = ExamEndReason.EXPIRED
        return replace(
            self,
            status=ExamStatus.SUBMITTING,
            end_reason=reason,
            revision=self.revision + 1,
        )

    def complete_submit(
        self,
        receipt: Mapping[str, object],
        *,
        now: datetime | None = None,
    ) -> "ExamSession":
        if self.status is not ExamStatus.SUBMITTING or self.end_reason is None:
            raise ExamConflictError("exam is not awaiting a final receipt")
        if not isinstance(receipt, Mapping) or not receipt:
            raise ExamStateError("final exam receipt is invalid")
        return replace(
            self,
            status=ExamStatus.SUBMITTED,
            submitted_at=_timestamp(now or utc_now()),
            receipt=dict(receipt),
            revision=self.revision + 1,
        )

    def fail(self, detail: str) -> "ExamSession":
        if not isinstance(detail, str) or not detail.strip():
            raise ExamStateError("exam failure detail is required")
        return replace(
            self,
            status=ExamStatus.FAILED,
            failure=detail[:2048],
            revision=self.revision + 1,
        )

    def progress_payload(self) -> list[dict[str, object]]:
        return [
            {
                "id": item.task_id,
                "visited": item.visited,
                "flagged": item.flagged,
                "completed": item.completed,
            }
            for item in self.tasks
        ]

    def to_candidate_dict(self, manifest: ExamManifest, *, now: datetime | None = None) -> dict[str, object]:
        if manifest.catalog_sha256 != self.catalog_sha256 or manifest.manifest_sha256 != self.manifest_sha256:
            raise ExamStateError("exam manifest no longer matches the frozen session")
        observed = now or utc_now()
        remaining = 0
        if self.deadline_at is not None and self.status is ExamStatus.ACTIVE:
            remaining = max(
                0,
                int(
                    (_parse_timestamp(self.deadline_at, "deadline_at") - observed.astimezone(timezone.utc)).total_seconds()
                ),
            )
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "mode": self.mode.value,
            "status": self.status.value,
            "duration_seconds": self.duration_seconds,
            "started_at": self.started_at,
            "deadline_at": self.deadline_at,
            "server_now": _timestamp(observed),
            "remaining_seconds": remaining,
            "selected_task_id": self.selected_task_id,
            "tasks": manifest.candidate_tasks(),
            "progress": self.progress_payload(),
            "can_check": self.mode is ExamMode.PRACTICE and self.status is ExamStatus.ACTIVE,
            "can_submit": self.status is ExamStatus.ACTIVE,
        }
        if self.status is ExamStatus.SUBMITTED:
            payload["result"] = dict(self.receipt or {})
            payload["end_reason"] = self.end_reason.value if self.end_reason else None
        if self.status is ExamStatus.FAILED:
            payload["failure"] = self.failure
        return payload

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "lab_name": self.lab_name,
            "lab_id": self.lab_id,
            "session_id": self.session_id,
            "mode": self.mode.value,
            "status": self.status.value,
            "catalog_sha256": self.catalog_sha256,
            "manifest_sha256": self.manifest_sha256,
            "duration_seconds": self.duration_seconds,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "deadline_at": self.deadline_at,
            "submitted_at": self.submitted_at,
            "end_reason": self.end_reason.value if self.end_reason else None,
            "selected_task_id": self.selected_task_id,
            "tasks": [item.to_dict() for item in self.tasks],
            "claimed_task_ids": list(self.claimed_task_ids),
            "prepared_task_ids": list(self.prepared_task_ids),
            "receipt": dict(self.receipt) if self.receipt is not None else None,
            "failure": self.failure,
            "revision": self.revision,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ExamSession":
        try:
            tasks_value = payload["tasks"]
            if not isinstance(tasks_value, Sequence) or isinstance(tasks_value, (str, bytes)):
                raise TypeError("tasks")
            receipt = payload.get("receipt")
            if receipt is not None and not isinstance(receipt, Mapping):
                raise TypeError("receipt")
            claimed = payload.get("claimed_task_ids", ())
            prepared = payload.get("prepared_task_ids", ())
            if (
                not isinstance(claimed, Sequence)
                or isinstance(claimed, (str, bytes))
                or not isinstance(prepared, Sequence)
                or isinstance(prepared, (str, bytes))
            ):
                raise TypeError("preparation task IDs")
            schema_version = payload["schema_version"]
            duration_seconds = payload["duration_seconds"]
            revision = payload.get("revision", 0)
            if any(isinstance(value, bool) or not isinstance(value, int) for value in (schema_version, duration_seconds, revision)):
                raise TypeError("integer fields")
            return cls(
                schema_version=schema_version,
                lab_name=str(payload["lab_name"]),
                lab_id=str(payload["lab_id"]),
                session_id=str(payload["session_id"]),
                mode=ExamMode(str(payload["mode"])),
                status=ExamStatus(str(payload["status"])),
                catalog_sha256=str(payload["catalog_sha256"]),
                manifest_sha256=str(payload["manifest_sha256"]),
                duration_seconds=duration_seconds,
                created_at=str(payload["created_at"]),
                started_at=payload.get("started_at") if isinstance(payload.get("started_at"), str) else None,
                deadline_at=payload.get("deadline_at") if isinstance(payload.get("deadline_at"), str) else None,
                submitted_at=payload.get("submitted_at") if isinstance(payload.get("submitted_at"), str) else None,
                end_reason=(ExamEndReason(str(payload["end_reason"])) if payload.get("end_reason") is not None else None),
                selected_task_id=str(payload["selected_task_id"]),
                tasks=tuple(
                    ExamTaskProgress(
                        task_id=str(item["task_id"]),
                        attempt_id=str(item["attempt_id"]),
                        visited=item.get("visited", False),
                        flagged=item.get("flagged", False),
                        completed=item.get("completed", False),
                    )
                    for item in tasks_value
                    if isinstance(item, Mapping)
                ),
                claimed_task_ids=tuple(str(item) for item in claimed),
                prepared_task_ids=tuple(str(item) for item in prepared),
                receipt=dict(receipt) if receipt is not None else None,
                failure=payload.get("failure") if isinstance(payload.get("failure"), str) else None,
                revision=revision,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ExamStateError("exam state has an invalid or incomplete schema") from error


class ExamSessionStore:
    """Owner-only atomic persistence outside the candidate VM boundary."""

    def __init__(self, root: Path) -> None:
        value = Path(root)
        if not value.is_absolute():
            raise ExamStateError("exam state root must be absolute")
        self.root = value

    def _directory(self, lab_name: str, *, create: bool) -> Path:
        validate_identifier(lab_name, field_name="exam lab name")
        root = self.root / "full-exams"
        for path in (self.root, root, root / lab_name):
            if path.exists() and (path.is_symlink() or not path.is_dir()):
                raise ExamStateError("exam state directory is unsafe")
            if create:
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(path, 0o700)
        directory = root / lab_name
        if not directory.exists():
            raise ExamStateError(f"exam session is missing for {lab_name!r}")
        observed = os.stat(directory, follow_symlinks=False)
        if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) & 0o077:
            raise ExamStateError("exam state directory must be owner-only")
        return directory

    def _path(self, lab_name: str, *, create: bool) -> Path:
        return self._directory(lab_name, create=create) / "session.json"

    def exists(self, lab_name: str) -> bool:
        try:
            path = self._path(lab_name, create=False)
        except ExamStateError:
            return False
        return path.is_file() and not path.is_symlink()

    @contextmanager
    def lock(self, lab_name: str):
        """Serialize exam mutations across UI, status, and teardown processes."""

        directory = self._directory(lab_name, create=True)
        path = directory / ".lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            observed = os.fstat(descriptor)
            if not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid():
                raise ExamStateError("exam lock file is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def load(self, lab_name: str) -> ExamSession:
        path = self._path(lab_name, create=False)
        if not path.is_file() or path.is_symlink():
            raise ExamStateError(f"exam session is missing for {lab_name!r}")
        observed = os.stat(path, follow_symlinks=False)
        if (
            observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) & 0o077
            or observed.st_size > MAX_EXAM_STATE_BYTES
        ):
            raise ExamStateError("exam state file is unsafe")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ExamStateError("exam state file is unreadable") from error
        if not isinstance(payload, Mapping):
            raise ExamStateError("exam state root must be an object")
        return ExamSession.from_dict(payload)

    def create(self, session: ExamSession) -> ExamSession:
        path = self._path(session.lab_name, create=True)
        if path.exists() or path.is_symlink():
            raise ExamConflictError(f"exam session already exists for {session.lab_name!r}")
        self._write(path, session)
        return session

    def save(self, session: ExamSession, *, expected_revision: int) -> ExamSession:
        current = self.load(session.lab_name)
        if current.session_id != session.session_id:
            raise ExamConflictError("exam session identity changed")
        if current.revision != expected_revision:
            raise ExamConflictError("exam session revision changed")
        if session.revision <= current.revision:
            raise ExamConflictError("exam session revision did not advance")
        self._write(self._path(session.lab_name, create=False), session)
        return session

    def delete(self, lab_name: str, *, expected_session_id: str) -> None:
        canonical_uuid(expected_session_id, field_name="exam session ID")
        session = self.load(lab_name)
        if session.session_id != expected_session_id:
            raise ExamConflictError("exam session identity changed")
        path = self._path(lab_name, create=False)
        observed = os.stat(path, follow_symlinks=False)
        if observed.st_uid != os.getuid() or not stat.S_ISREG(observed.st_mode):
            raise ExamStateError("exam state file is unsafe")
        path.unlink()
        directory = path.parent
        try:
            directory.rmdir()
        except OSError:
            pass

    @staticmethod
    def _write(path: Path, session: ExamSession) -> None:
        encoded = json.dumps(session.to_dict(), indent=2, sort_keys=True).encode("utf-8") + b"\n"
        if len(encoded) > MAX_EXAM_STATE_BYTES:
            raise ExamStateError("exam state exceeds its maximum size")
        temporary = path.with_name(f".session.{uuid.uuid4().hex}.json")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            if path.exists() and path.is_symlink():
                raise ExamStateError("refusing symlinked exam state file")
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def aggregate_exam_grades(
    session: ExamSession,
    manifest: ExamManifest,
    grades: Mapping[str, LiveGrade],
) -> dict[str, object]:
    """Build one fixed-denominator receipt from trusted per-task grades."""

    if session.status is not ExamStatus.SUBMITTING:
        raise ExamConflictError("aggregate scoring requires a submitting exam")
    if manifest.catalog_sha256 != session.catalog_sha256 or manifest.manifest_sha256 != session.manifest_sha256:
        raise ExamStateError("aggregate scoring manifest mismatch")
    if set(grades) != set(EXPECTED_TASK_IDS):
        raise ExamStateError("aggregate scoring requires exactly one result for every task")
    task_results = []
    score = 0.0
    statuses = []
    for task in manifest.tasks:
        grade = grades[task.task_id]
        if not isinstance(grade, LiveGrade):
            raise ExamStateError("aggregate scoring received an invalid task grade")
        statuses.append(grade.status)
        weighted = grade.score * task.weight / 100.0
        score += weighted
        task_results.append(
            {
                "id": task.task_id,
                "title": task.title,
                "weight": task.weight,
                "score": round(grade.score, 2),
                "weighted_score": round(weighted, 2),
                "status": grade.status.value,
                "criteria": [
                    {
                        "criterion_id": criterion.criterion_id,
                        "label": criterion.label,
                        "weight": criterion.weight,
                        "passed": criterion.passed,
                        "trust_source": (
                            criterion.trust_source.value
                            if criterion.trust_source
                            else None
                        ),
                        "detail": criterion.detail,
                        "evidence_present": criterion.evidence_present,
                    }
                    for criterion in grade.criteria
                ],
            }
        )
    rounded = round(score, 2)
    if GradeStatus.LAB_TAMPERED in statuses:
        status = GradeStatus.LAB_TAMPERED.value
        passed = False
    elif GradeStatus.LAB_BROKEN in statuses:
        status = GradeStatus.LAB_BROKEN.value
        passed = False
    else:
        passed = rounded >= PASS_SCORE
        status = "PASS" if passed else "FAIL"
    receipt: dict[str, object] = {
        "schema_version": 1,
        "session_id": session.session_id,
        "lab_id": session.lab_id,
        "mode": session.mode.value,
        "catalog_sha256": session.catalog_sha256,
        "manifest_sha256": session.manifest_sha256,
        "started_at": session.started_at,
        "deadline_at": session.deadline_at,
        "end_reason": session.end_reason.value if session.end_reason else None,
        "score": rounded,
        "possible": 100,
        "pass_score": PASS_SCORE,
        "passed": passed,
        "status": status,
        "tasks": task_results,
    }
    receipt["receipt_sha256"] = _sha256(_canonical_json(receipt))
    return receipt
