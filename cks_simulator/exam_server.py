"""Loopback-only candidate ExamUI service.

The server intentionally uses the Python standard library.  A random
capability path authenticates the local browser, mutating requests additionally
require the exact Origin, and all lifecycle/grading calls are delegated to a
host-owned controller.
"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Mapping, Optional, Protocol, Tuple
from urllib.parse import urlsplit

from .exam import (
    EXPECTED_TASK_IDS,
    ExamConflictError,
    ExamEndReason,
    ExamManifest,
    ExamMode,
    ExamSessionStore,
    ExamStateError,
    ExamStatus,
    aggregate_exam_grades,
    utc_now,
)
from .live_grading import LiveGrade


MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
UI_ROOT = Path(__file__).resolve().parent / "exam_ui"


class ExamController(Protocol):
    def snapshot(self) -> Mapping[str, object]: ...

    def update_progress(self, task_id: str, value: Mapping[str, object]) -> Mapping[str, object]: ...

    def check(self, task_id: str) -> Mapping[str, object]: ...

    def submit(self, reason: ExamEndReason = ExamEndReason.MANUAL) -> Mapping[str, object]: ...


class StoredExamController:
    """Serialize browser requests around the owner-only session and graders."""

    def __init__(
        self,
        *,
        lab_name: str,
        store: ExamSessionStore,
        manifest: ExamManifest,
        grade_one: Callable[[str], LiveGrade],
        desktop_url: Optional[str],
        grade_all: Optional[Callable[[], Mapping[str, LiveGrade]]] = None,
        on_submission_start: Optional[Callable[[], None]] = None,
    ) -> None:
        self._lab_name = lab_name
        self._store = store
        self._manifest = manifest
        self._grade_one = grade_one
        self._grade_all = grade_all
        self._desktop_url = desktop_url
        self._on_submission_start = on_submission_start or (lambda: None)
        self._lock = threading.RLock()

    def _candidate_payload(self, session) -> dict[str, object]:
        payload = session.to_candidate_dict(self._manifest, now=utc_now())
        payload["desktop_url"] = (
            self._desktop_url if session.status is ExamStatus.ACTIVE else None
        )
        return payload

    def snapshot(self) -> Mapping[str, object]:
        with self._lock:
            with self._store.lock(self._lab_name):
                session = self._store.load(self._lab_name)
            if session.status is ExamStatus.ACTIVE and session.is_expired(now=utc_now()):
                return self.submit(ExamEndReason.EXPIRED)
            return self._candidate_payload(session)

    def update_progress(
        self, task_id: str, value: Mapping[str, object]
    ) -> Mapping[str, object]:
        if task_id not in EXPECTED_TASK_IDS:
            raise ExamStateError("exam task ID is invalid")
        allowed = {"selected", "visited", "flagged", "completed"}
        if not isinstance(value, Mapping) or not set(value).issubset(allowed):
            raise ExamStateError("exam progress request has unsupported fields")
        if any(not isinstance(item, bool) for item in value.values()):
            raise ExamStateError("exam progress request values must be boolean")
        with self._lock, self._store.lock(self._lab_name):
            session = self._store.load(self._lab_name)
            changed = session.update_progress(
                task_id,
                selected=bool(value.get("selected", False)),
                visited=value.get("visited"),
                flagged=value.get("flagged"),
                completed=value.get("completed"),
                now=utc_now(),
            )
            self._store.save(changed, expected_revision=session.revision)
            return self._candidate_payload(changed)

    def check(self, task_id: str) -> Mapping[str, object]:
        if task_id not in EXPECTED_TASK_IDS:
            raise ExamStateError("exam task ID is invalid")
        with self._lock, self._store.lock(self._lab_name):
            session = self._store.load(self._lab_name)
            if session.status is not ExamStatus.ACTIVE:
                raise ExamConflictError("practice check requires an active session")
            if session.mode is not ExamMode.PRACTICE:
                raise ExamConflictError("interim grading is disabled in exam mode")
            if session.is_expired(now=utc_now()):
                raise ExamConflictError("exam deadline has elapsed")
            grade = self._grade_one(task_id)
            return {
                "id": task_id,
                "status": grade.status.value,
                "score": grade.score,
                "earned_weight": grade.earned_weight,
                "possible_weight": grade.possible_weight,
                "criteria": [criterion.to_payload() for criterion in grade.criteria],
            }

    def submit(
        self, reason: ExamEndReason = ExamEndReason.MANUAL
    ) -> Mapping[str, object]:
        if not isinstance(reason, ExamEndReason):
            raise ExamStateError("exam end reason is invalid")
        with self._lock, self._store.lock(self._lab_name):
            session = self._store.load(self._lab_name)
            if session.status is ExamStatus.SUBMITTED:
                return self._candidate_payload(session)
            if session.status is ExamStatus.ACTIVE:
                submitting = session.begin_submit(reason=reason, now=utc_now())
                self._store.save(submitting, expected_revision=session.revision)
                session = submitting
                self._on_submission_start()
            elif session.status is not ExamStatus.SUBMITTING:
                raise ExamConflictError("exam cannot be submitted from its current state")
            try:
                grades = (
                    self._grade_all()
                    if self._grade_all is not None
                    else {task_id: self._grade_one(task_id) for task_id in EXPECTED_TASK_IDS}
                )
                receipt = aggregate_exam_grades(session, self._manifest, grades)
                submitted = session.complete_submit(receipt, now=utc_now())
                self._store.save(submitted, expected_revision=session.revision)
                return self._candidate_payload(submitted)
            except BaseException as error:
                current = self._store.load(self._lab_name)
                if current.status is ExamStatus.SUBMITTING:
                    failed = current.fail(str(error))
                    self._store.save(failed, expected_revision=current.revision)
                raise


@dataclass(frozen=True)
class ExamUIAddress:
    host: str
    port: int
    token: str

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.origin}/s/{self.token}/"


class _ExamHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: Tuple[str, int],
        controller: ExamController,
        token: str,
    ) -> None:
        self.controller = controller
        self.token = token
        super().__init__(address, _ExamRequestHandler)

    @property
    def origin(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"


class _ExamRequestHandler(BaseHTTPRequestHandler):
    server: _ExamHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        # Capability-bearing paths must never enter routine logs.
        return

    def _base(self) -> str:
        return f"/s/{self.server.token}/"

    def _route(self) -> Optional[str]:
        value = urlsplit(self.path)
        if value.query or value.fragment or not value.path.startswith(self._base()):
            return None
        return value.path[len(self._base()) :]

    def _headers(self, status: HTTPStatus, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; font-src 'self'; "
            "frame-src http://127.0.0.1:*; connect-src 'self' ws://127.0.0.1:*",
        )
        self.end_headers()

    def _send_bytes(self, status: HTTPStatus, content_type: str, value: bytes) -> None:
        if len(value) > MAX_RESPONSE_BYTES:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "response_too_large"})
            return
        self._headers(status, content_type, len(value))
        self.wfile.write(value)

    def _send_json(self, status: HTTPStatus, value: Mapping[str, object]) -> None:
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", encoded)

    def _error(self, status: HTTPStatus, code: str, detail: str) -> None:
        self._send_json(status, {"error": code, "detail": detail[:512]})

    def _require_origin(self) -> bool:
        if self.headers.get("Origin") != self.server.origin:
            self._error(HTTPStatus.FORBIDDEN, "invalid_origin", "request origin is not authorized")
            return False
        return True

    def _read_json(self) -> Optional[Mapping[str, object]]:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json":
            self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "invalid_content_type", "application/json is required")
            return None
        length_value = self.headers.get("Content-Length")
        try:
            length = int(length_value or "")
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_REQUEST_BYTES:
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "invalid_length", "request body is too large")
            return None
        try:
            value = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json", "request body is not valid JSON")
            return None
        if not isinstance(value, Mapping):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json", "request body must be an object")
            return None
        return value

    def _dispatch(self, action: Callable[[], Mapping[str, object]]) -> None:
        try:
            self._send_json(HTTPStatus.OK, action())
        except ExamConflictError as error:
            self._error(HTTPStatus.CONFLICT, "exam_conflict", str(error))
        except ExamStateError as error:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_exam_request", str(error))
        except Exception:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "exam_operation_failed", "trusted exam operation failed")

    def do_GET(self) -> None:
        route = self._route()
        if route is None:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "resource not found")
            return
        if route == "api/session":
            self._dispatch(self.server.controller.snapshot)
            return
        asset = {
            "": ("index.html", "text/html; charset=utf-8"),
            "assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
        }.get(route)
        if asset is None:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "resource not found")
            return
        filename, content_type = asset
        path = UI_ROOT / filename
        try:
            value = path.read_bytes()
        except OSError:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "asset_missing", "ExamUI asset is unavailable")
            return
        self._send_bytes(HTTPStatus.OK, content_type, value)

    def do_POST(self) -> None:
        route = self._route()
        if route is None:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "resource not found")
            return
        if not self._require_origin():
            return
        value = self._read_json()
        if value is None:
            return
        if route == "api/submit":
            if value:
                self._error(HTTPStatus.BAD_REQUEST, "invalid_submit", "submit accepts no candidate fields")
                return
            self._dispatch(self.server.controller.submit)
            return
        parts = route.split("/")
        if len(parts) == 4 and parts[:2] == ["api", "tasks"]:
            task_id, operation = parts[2], parts[3]
            if operation == "progress":
                self._dispatch(lambda: self.server.controller.update_progress(task_id, value))
                return
            if operation == "check":
                if value:
                    self._error(HTTPStatus.BAD_REQUEST, "invalid_check", "check accepts no candidate evidence")
                    return
                self._dispatch(lambda: self.server.controller.check(task_id))
                return
        self._error(HTTPStatus.NOT_FOUND, "not_found", "resource not found")


class ExamUIServer:
    def __init__(
        self,
        controller: ExamController,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        token: Optional[str] = None,
    ) -> None:
        if host != "127.0.0.1":
            raise ValueError("ExamUI must bind only to IPv4 loopback")
        resolved_token = token or secrets.token_urlsafe(32)
        if not isinstance(resolved_token, str) or len(resolved_token) < 32:
            raise ValueError("ExamUI token is too short")
        self._server = _ExamHTTPServer((host, port), controller, resolved_token)
        actual_host, actual_port = self._server.server_address[:2]
        self.address = ExamUIAddress(str(actual_host), int(actual_port), resolved_token)

    def serve_forever(self) -> None:
        self._server.serve_forever(poll_interval=0.25)

    def start_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="cks-examui", daemon=True)
        thread.start()
        return thread

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
