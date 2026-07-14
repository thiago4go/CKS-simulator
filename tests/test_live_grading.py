from __future__ import annotations

import json
import unittest
from dataclasses import FrozenInstanceError

from cks_simulator.live_grading import (
    CriterionEvidence,
    ExpectedCriterion,
    GradeStatus,
    LabSignals,
    TrustSource,
    evaluate_live_grade,
)


def expected(criterion_id: str, weight: float = 1.0) -> ExpectedCriterion:
    return ExpectedCriterion(criterion_id, f"criterion {criterion_id}", weight)


def observed(
    criterion_id: str,
    *,
    weight: float = 1.0,
    passed: bool = True,
    source: TrustSource = TrustSource.OPERATOR,
    detail: str = "probe complete",
) -> CriterionEvidence:
    return CriterionEvidence(
        criterion_id=criterion_id,
        label=f"criterion {criterion_id}",
        weight=weight,
        passed=passed,
        trust_source=source,
        detail=detail,
    )


class LiveGradingTests(unittest.TestCase):
    def test_all_trusted_criteria_pass(self) -> None:
        grade = evaluate_live_grade(
            [expected("operator", 2), expected("cross", 3)],
            [
                observed("operator", weight=2),
                observed("cross", weight=3, source=TrustSource.CROSS_SOURCE),
            ],
        )

        self.assertIs(grade.status, GradeStatus.PASS)
        self.assertEqual(grade.score, 100.0)
        self.assertEqual(grade.earned_weight, 5.0)
        self.assertEqual(grade.possible_weight, 5.0)
        self.assertTrue(all(item.passed for item in grade.criteria))

    def test_weighted_partial_grade(self) -> None:
        grade = evaluate_live_grade(
            [expected("heavy", 3), expected("light", 1)],
            [
                observed("heavy", weight=3, passed=False),
                observed("light", weight=1),
            ],
        )

        self.assertIs(grade.status, GradeStatus.PARTIAL)
        self.assertEqual(grade.score, 25.0)
        self.assertEqual(grade.earned_weight, 1.0)
        self.assertEqual(grade.possible_weight, 4.0)

    def test_no_criterion_passes_is_fail(self) -> None:
        grade = evaluate_live_grade(
            [expected("a"), expected("b")],
            [observed("a", passed=False), observed("b", passed=False)],
        )

        self.assertIs(grade.status, GradeStatus.FAIL)
        self.assertEqual(grade.score, 0.0)

    def test_missing_criteria_fail_and_remain_in_declared_denominator(self) -> None:
        grade = evaluate_live_grade(
            [expected("present", 1), expected("missing", 3)],
            [observed("present", weight=1)],
        )

        self.assertIs(grade.status, GradeStatus.PARTIAL)
        self.assertEqual(grade.criterion_denominator, 2)
        self.assertEqual(grade.evidence_count, 1)
        self.assertEqual(grade.possible_weight, 4.0)
        self.assertEqual(grade.earned_weight, 1.0)
        self.assertEqual(grade.score, 25.0)
        missing = next(item for item in grade.criteria if item.criterion_id == "missing")
        self.assertFalse(missing.passed)
        self.assertFalse(missing.evidence_present)
        self.assertIsNone(missing.trust_source)
        self.assertEqual(missing.detail, "missing evidence")

    def test_guest_only_success_never_passes_a_criterion(self) -> None:
        grade = evaluate_live_grade(
            [expected("guest-claim", 4)],
            [observed("guest-claim", weight=4, source=TrustSource.GUEST)],
        )

        self.assertIs(grade.status, GradeStatus.FAIL)
        self.assertEqual(grade.score, 0.0)
        self.assertFalse(grade.criteria[0].passed)
        self.assertIs(grade.criteria[0].trust_source, TrustSource.GUEST)
        self.assertTrue(grade.criteria[0].evidence_present)

    def test_lab_broken_precedes_a_passing_score(self) -> None:
        grade = evaluate_live_grade(
            [expected("a")],
            [observed("a")],
            LabSignals(lab_broken=True, detail="API unavailable"),
        )

        self.assertIs(grade.status, GradeStatus.LAB_BROKEN)
        self.assertEqual(grade.score, 0.0)
        self.assertFalse(grade.criteria[0].passed)
        self.assertEqual(grade.signal_detail, "API unavailable")

    def test_tampering_precedes_broken_lab_and_score(self) -> None:
        grade = evaluate_live_grade(
            [expected("a")],
            [observed("a")],
            LabSignals(lab_broken=True, tampered=True, detail="identity drift"),
        )

        self.assertIs(grade.status, GradeStatus.LAB_TAMPERED)
        self.assertEqual(grade.score, 0.0)
        self.assertFalse(grade.criteria[0].passed)
        self.assertTrue(grade.lab_broken)
        self.assertTrue(grade.tampered)

    def test_tampering_precedes_a_failed_score(self) -> None:
        grade = evaluate_live_grade(
            [expected("a")],
            [observed("a", passed=False)],
            LabSignals(tampered=True),
        )

        self.assertIs(grade.status, GradeStatus.LAB_TAMPERED)
        self.assertEqual(grade.score, 0.0)

    def test_duplicate_expected_criteria_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate expected criterion: a"):
            evaluate_live_grade([expected("a"), expected("a")], [])

    def test_duplicate_evidence_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate evidence: a"):
            evaluate_live_grade([expected("a")], [observed("a"), observed("a")])

    def test_undeclared_evidence_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "undeclared evidence: extra"):
            evaluate_live_grade([expected("a")], [observed("extra")])

    def test_evidence_metadata_must_match_declaration(self) -> None:
        wrong_label = CriterionEvidence(
            criterion_id="a",
            label="different",
            weight=1,
            passed=True,
            trust_source=TrustSource.OPERATOR,
            detail="probe complete",
        )
        with self.assertRaisesRegex(ValueError, "metadata disagrees"):
            evaluate_live_grade([expected("a")], [wrong_label])
        with self.assertRaisesRegex(ValueError, "metadata disagrees"):
            evaluate_live_grade([expected("a", 2)], [observed("a", weight=1)])

    def test_empty_denominator_is_invalid(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one"):
            evaluate_live_grade([], [])

    def test_invalid_model_fields_are_rejected(self) -> None:
        invalid_weights = (0, -1, float("inf"), float("nan"))
        for weight in invalid_weights:
            with self.subTest(weight=weight):
                with self.assertRaises(ValueError):
                    expected("a", weight)
        with self.assertRaises(TypeError):
            expected("a", True)
        with self.assertRaises(ValueError):
            ExpectedCriterion(" ", "label", 1)
        with self.assertRaises(ValueError):
            ExpectedCriterion("a", " ", 1)
        with self.assertRaises(TypeError):
            CriterionEvidence("a", "criterion a", 1, 1, TrustSource.OPERATOR, "")
        with self.assertRaises(TypeError):
            CriterionEvidence("a", "criterion a", 1, True, "operator", "")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            LabSignals(lab_broken=1)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            LabSignals(tampered=1)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ExpectedCriterion("UPPER", "label", 1)
        with self.assertRaises(ValueError):
            ExpectedCriterion("a" * 65, "label", 1)
        with self.assertRaises(ValueError):
            CriterionEvidence(
                "a",
                "criterion a",
                1,
                True,
                TrustSource.OPERATOR,
                "x" * 2049,
            )

    def test_evidence_and_signal_details_are_bounded_and_redacted(self) -> None:
        evidence = CriterionEvidence(
            "safe",
            "safe evidence",
            1,
            False,
            TrustSource.OPERATOR,
            "password: hunter2\nprobe failed",
        )
        signals = LabSignals(detail="token: abcdef.abcdefghijklmnop")

        self.assertNotIn("hunter2", evidence.detail)
        self.assertNotIn("abcdef.abcdefghijklmnop", signals.detail)
        self.assertLessEqual(len(evidence.detail.encode("utf-8")), 2048)
        self.assertLessEqual(len(signals.detail.encode("utf-8")), 2048)

    def test_invalid_collection_and_signal_types_are_rejected(self) -> None:
        with self.assertRaisesRegex(TypeError, "expected_criteria must be iterable"):
            evaluate_live_grade(None, [])  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "evidence must be iterable"):
            evaluate_live_grade([expected("a")], None)  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "ExpectedCriterion"):
            evaluate_live_grade(["a"], [])  # type: ignore[list-item]
        with self.assertRaisesRegex(TypeError, "CriterionEvidence"):
            evaluate_live_grade([expected("a")], ["a"])  # type: ignore[list-item]
        with self.assertRaisesRegex(TypeError, "signals must be LabSignals"):
            evaluate_live_grade([expected("a")], [], None)  # type: ignore[arg-type]

    def test_models_and_result_are_immutable(self) -> None:
        criterion = expected("a")
        evidence = observed("a")
        signals = LabSignals()
        grade = evaluate_live_grade([criterion], [evidence], signals)

        with self.assertRaises(FrozenInstanceError):
            criterion.weight = 9  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            evidence.passed = False  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            signals.tampered = True  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            grade.score = 0  # type: ignore[misc]
        self.assertIsInstance(grade.criteria, tuple)

    def test_payload_is_json_safe_complete_and_deterministic(self) -> None:
        declarations = [expected("z", 0.1), expected("a", 0.2), expected("m", 0.3)]
        evidence = [
            observed("m", weight=0.3, passed=False, detail="m failed"),
            observed("z", weight=0.1, detail="z passed"),
            observed("a", weight=0.2, source=TrustSource.CROSS_SOURCE),
        ]

        first = evaluate_live_grade(declarations, evidence).to_payload()
        second = evaluate_live_grade(reversed(declarations), reversed(evidence)).to_payload()

        self.assertEqual(first, second)
        self.assertEqual([item["criterion_id"] for item in first["criteria"]], ["a", "m", "z"])
        self.assertEqual(first["status"], "PARTIAL")
        self.assertEqual(first["score"], 50.0)
        self.assertEqual(first["criterion_denominator"], 3)
        self.assertEqual(first["evidence_count"], 3)
        encoded = json.dumps(first, sort_keys=True, allow_nan=False)
        self.assertEqual(encoded, json.dumps(second, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    unittest.main()
