from __future__ import annotations

import http.client
import json
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cks_simulator.exam import (
    EXPECTED_TASK_IDS,
    ExamEndReason,
    ExamManifest,
    ExamMode,
    ExamSession,
    ExamSessionStore,
    build_exam_manifest,
)
from cks_simulator.exam_server import ExamUIServer, StoredExamController
from cks_simulator.live_grading import (
    CriterionEvidence,
    ExpectedCriterion,
    TrustSource,
    evaluate_live_grade,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "scenarios" / "catalog.json"
NOW = datetime(2026, 7, 15, 10, 0, tzinfo=timezone.utc)


def passing_grade():
    expected = (ExpectedCriterion("answer", "answer", 1),)
    evidence = (
        CriterionEvidence(
            "answer", "answer", 1, True, TrustSource.OPERATOR, "trusted"
        ),
    )
    return evaluate_live_grade(expected, evidence)


class FakeController:
    def __init__(self) -> None:
        self.progress = []
        self.checks = []
        self.submits = 0

    def snapshot(self):
        return {"status": "active", "tasks": []}

    def update_progress(self, task_id, value):
        self.progress.append((task_id, dict(value)))
        return {"status": "active", "updated": task_id}

    def check(self, task_id):
        self.checks.append(task_id)
        return {"id": task_id, "score": 0}

    def submit(self, reason=ExamEndReason.MANUAL):
        self.submits += 1
        return {"status": "submitted", "reason": reason.value}


class ExamUIServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = FakeController()
        self.server = ExamUIServer(
            self.controller,
            token="t" * 43,
        )
        self.server.start_background()
        self.addCleanup(self.server.close)

    def request(self, method, route, body=None, headers=None):
        connection = http.client.HTTPConnection(
            self.server.address.host, self.server.address.port, timeout=5
        )
        try:
            connection.request(method, route, body=body, headers=headers or {})
            response = connection.getresponse()
            value = response.read()
            return response.status, dict(response.getheaders()), value
        finally:
            connection.close()

    def session_path(self, suffix=""):
        return f"/s/{self.server.address.token}/{suffix}"

    def test_static_ui_and_session_api_are_capability_scoped_and_hardened(self) -> None:
        status, headers, value = self.request("GET", self.session_path())
        self.assertEqual(status, 200)
        self.assertIn(b"CKS Simulator Exam", value)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")

        status, _headers, value = self.request(
            "GET", self.session_path("api/session")
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(value), {"status": "active", "tasks": []})

        status, _headers, _value = self.request(
            "GET", "/s/not-the-capability/api/session"
        )
        self.assertEqual(status, 404)

    def test_mutations_require_exact_origin_json_and_allowlisted_fields(self) -> None:
        route = self.session_path("api/tasks/01/progress")
        body = json.dumps({"selected": True})
        base_headers = {"Content-Type": "application/json"}

        status, _headers, _value = self.request(
            "POST", route, body, base_headers
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.controller.progress, [])

        status, _headers, _value = self.request(
            "POST",
            route,
            body,
            {**base_headers, "Origin": "http://attacker.invalid"},
        )
        self.assertEqual(status, 403)

        status, _headers, value = self.request(
            "POST",
            route,
            body,
            {**base_headers, "Origin": self.server.address.origin},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(value)["updated"], "01")
        self.assertEqual(self.controller.progress, [("01", {"selected": True})])

    def test_submit_accepts_no_candidate_score_or_evidence(self) -> None:
        route = self.session_path("api/submit")
        headers = {
            "Content-Type": "application/json",
            "Origin": self.server.address.origin,
        }
        status, _headers, _value = self.request(
            "POST", route, json.dumps({"score": 100}), headers
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.controller.submits, 0)

        status, _headers, value = self.request("POST", route, "{}", headers)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(value)["status"], "submitted")
        self.assertEqual(self.controller.submits, 1)

    def test_non_loopback_bind_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            ExamUIServer(self.controller, host="0.0.0.0")


class StoredExamControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = ExamSessionStore(Path(self.temporary.name) / "state")
        self.manifest: ExamManifest = build_exam_manifest(CATALOG_PATH)
        self.lab_id = str(uuid.uuid4())

    def create_controller(self, mode: ExamMode):
        session = ExamSession.create(
            lab_name="controller-lab",
            lab_id=self.lab_id,
            mode=mode,
            manifest=self.manifest,
            now=NOW,
        ).activate()
        self.store.create(session)
        disconnects = []
        grades = []

        def grade_one(task_id):
            grades.append(task_id)
            return passing_grade()

        controller = StoredExamController(
            lab_name="controller-lab",
            store=self.store,
            manifest=self.manifest,
            grade_one=grade_one,
            desktop_url="http://127.0.0.1:6080/vnc.html",
            on_submission_start=lambda: disconnects.append(True),
        )
        return controller, disconnects, grades

    def test_exam_mode_blocks_interim_grade_and_final_submit_grades_all_once(self) -> None:
        controller, disconnects, grades = self.create_controller(ExamMode.EXAM)
        with self.assertRaisesRegex(Exception, "disabled"):
            controller.check("01")

        result = controller.submit()
        self.assertEqual(result["status"], "submitted")
        self.assertEqual(result["result"]["score"], 100.0)
        self.assertIsNone(result["desktop_url"])
        self.assertEqual(disconnects, [True])
        self.assertEqual(tuple(grades), EXPECTED_TASK_IDS)

        repeated = controller.submit()
        self.assertEqual(repeated["result"], result["result"])
        self.assertEqual(disconnects, [True])
        self.assertEqual(tuple(grades), EXPECTED_TASK_IDS)

    def test_practice_mode_check_returns_only_grade_result(self) -> None:
        controller, disconnects, grades = self.create_controller(ExamMode.PRACTICE)
        result = controller.check("03")
        self.assertEqual(result["id"], "03")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["score"], 100.0)
        self.assertEqual(grades, ["03"])
        self.assertEqual(disconnects, [])


if __name__ == "__main__":
    unittest.main()
