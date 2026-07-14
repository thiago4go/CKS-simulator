"""Pure trusted-evidence grading for full-tier CKS scenarios.

This module deliberately performs no I/O. Callers collect evidence elsewhere,
declare the complete expected criterion set, and pass both into the evaluator.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, Optional, Tuple, Union

from .providers.base import bounded_redacted


Weight = Union[int, float]
_CRITERION_ID = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$")


class GradeStatus(str, Enum):
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"
    LAB_TAMPERED = "LAB_TAMPERED"
    LAB_BROKEN = "LAB_BROKEN"


class TrustSource(str, Enum):
    OPERATOR = "operator"
    CROSS_SOURCE = "cross-source"
    GUEST = "guest"


def _require_text(name: str, value: object, *, allow_empty: bool = False) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not allow_empty and not value.strip():
        raise ValueError(f"{name} must not be empty")
    limit = 64 if name == "criterion_id" else (2048 if name == "detail" else 256)
    if len(value.encode("utf-8")) > limit:
        raise ValueError(f"{name} exceeds {limit} UTF-8 bytes")
    if name == "criterion_id" and _CRITERION_ID.fullmatch(value) is None:
        raise ValueError("criterion_id must be a safe lowercase identifier")


def _normalise_weight(weight: object) -> float:
    if isinstance(weight, bool) or not isinstance(weight, (int, float)):
        raise TypeError("weight must be a finite positive number")
    value = float(weight)
    if not math.isfinite(value) or value <= 0:
        raise ValueError("weight must be a finite positive number")
    return value


@dataclass(frozen=True)
class ExpectedCriterion:
    """One criterion in the declared grading denominator."""

    criterion_id: str
    label: str
    weight: Weight

    def __post_init__(self) -> None:
        _require_text("criterion_id", self.criterion_id)
        _require_text("label", self.label)
        object.__setattr__(self, "weight", _normalise_weight(self.weight))


@dataclass(frozen=True)
class CriterionEvidence:
    """Immutable evidence produced by a reviewed live probe."""

    criterion_id: str
    label: str
    weight: Weight
    passed: bool
    trust_source: TrustSource
    detail: str

    def __post_init__(self) -> None:
        _require_text("criterion_id", self.criterion_id)
        _require_text("label", self.label)
        _require_text("detail", self.detail, allow_empty=True)
        object.__setattr__(self, "detail", bounded_redacted(self.detail, limit=2048))
        object.__setattr__(self, "weight", _normalise_weight(self.weight))
        if not isinstance(self.passed, bool):
            raise TypeError("passed must be a bool")
        if not isinstance(self.trust_source, TrustSource):
            raise TypeError("trust_source must be a TrustSource")


@dataclass(frozen=True)
class LabSignals:
    """Out-of-band lab-integrity signals supplied by the operator."""

    lab_broken: bool = False
    tampered: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.lab_broken, bool):
            raise TypeError("lab_broken must be a bool")
        if not isinstance(self.tampered, bool):
            raise TypeError("tampered must be a bool")
        _require_text("detail", self.detail, allow_empty=True)
        object.__setattr__(self, "detail", bounded_redacted(self.detail, limit=2048))


@dataclass(frozen=True)
class CriterionResult:
    criterion_id: str
    label: str
    weight: float
    passed: bool
    trust_source: Optional[TrustSource]
    detail: str
    evidence_present: bool

    def to_payload(self) -> Dict[str, Any]:
        return {
            "criterion_id": self.criterion_id,
            "label": self.label,
            "weight": self.weight,
            "passed": self.passed,
            "trust_source": self.trust_source.value if self.trust_source else None,
            "detail": self.detail,
            "evidence_present": self.evidence_present,
        }


@dataclass(frozen=True)
class LiveGrade:
    status: GradeStatus
    score: float
    earned_weight: float
    possible_weight: float
    criterion_denominator: int
    evidence_count: int
    criteria: Tuple[CriterionResult, ...]
    lab_broken: bool
    tampered: bool
    signal_detail: str

    def to_payload(self) -> Dict[str, Any]:
        """Return a deterministic structure accepted by ``json.dumps``."""
        return {
            "status": self.status.value,
            "score": self.score,
            "earned_weight": self.earned_weight,
            "possible_weight": self.possible_weight,
            "criterion_denominator": self.criterion_denominator,
            "evidence_count": self.evidence_count,
            "lab_broken": self.lab_broken,
            "tampered": self.tampered,
            "signal_detail": self.signal_detail,
            "criteria": [criterion.to_payload() for criterion in self.criteria],
        }


def _items(name: str, values: Iterable[object]) -> Tuple[object, ...]:
    try:
        return tuple(values)
    except TypeError as exc:
        raise TypeError(f"{name} must be iterable") from exc


def evaluate_live_grade(
    expected_criteria: Iterable[ExpectedCriterion],
    evidence: Iterable[CriterionEvidence],
    signals: LabSignals = LabSignals(),
) -> LiveGrade:
    """Evaluate trusted evidence against an explicit, fixed denominator.

    Missing evidence fails its declared criterion. Duplicate or undeclared
    evidence and metadata disagreement are rejected, rather than guessed at.
    Guest-only evidence is diagnostic and never earns weight. Integrity status
    precedence is ``LAB_TAMPERED``, then ``LAB_BROKEN``, then the weighted grade.
    """
    if not isinstance(signals, LabSignals):
        raise TypeError("signals must be LabSignals")

    expected_items = _items("expected_criteria", expected_criteria)
    evidence_items = _items("evidence", evidence)
    expected_by_id: Dict[str, ExpectedCriterion] = {}
    evidence_by_id: Dict[str, CriterionEvidence] = {}

    for item in expected_items:
        if not isinstance(item, ExpectedCriterion):
            raise TypeError("expected_criteria must contain ExpectedCriterion values")
        if item.criterion_id in expected_by_id:
            raise ValueError(f"duplicate expected criterion: {item.criterion_id}")
        expected_by_id[item.criterion_id] = item
    if not expected_by_id:
        raise ValueError("expected_criteria must declare at least one criterion")

    for item in evidence_items:
        if not isinstance(item, CriterionEvidence):
            raise TypeError("evidence must contain CriterionEvidence values")
        if item.criterion_id in evidence_by_id:
            raise ValueError(f"duplicate evidence: {item.criterion_id}")
        expected = expected_by_id.get(item.criterion_id)
        if expected is None:
            raise ValueError(f"undeclared evidence: {item.criterion_id}")
        if item.label != expected.label or item.weight != expected.weight:
            raise ValueError(f"evidence metadata disagrees for criterion: {item.criterion_id}")
        evidence_by_id[item.criterion_id] = item

    results = []
    lab_evidence_valid = not signals.tampered and not signals.lab_broken
    for criterion_id in sorted(expected_by_id):
        expected = expected_by_id[criterion_id]
        observed = evidence_by_id.get(criterion_id)
        if observed is None:
            results.append(
                CriterionResult(
                    criterion_id=expected.criterion_id,
                    label=expected.label,
                    weight=float(expected.weight),
                    passed=False,
                    trust_source=None,
                    detail="missing evidence",
                    evidence_present=False,
                )
            )
            continue
        trusted = observed.trust_source in (
            TrustSource.OPERATOR,
            TrustSource.CROSS_SOURCE,
        )
        results.append(
            CriterionResult(
                criterion_id=expected.criterion_id,
                label=expected.label,
                weight=float(expected.weight),
                passed=observed.passed and trusted and lab_evidence_valid,
                trust_source=observed.trust_source,
                detail=observed.detail,
                evidence_present=True,
            )
        )

    criteria = tuple(results)
    possible_weight = math.fsum(item.weight for item in criteria)
    earned_weight = math.fsum(item.weight for item in criteria if item.passed)
    score = round((earned_weight / possible_weight) * 100.0, 2)

    if signals.tampered:
        status = GradeStatus.LAB_TAMPERED
    elif signals.lab_broken:
        status = GradeStatus.LAB_BROKEN
    elif earned_weight == possible_weight:
        status = GradeStatus.PASS
    elif earned_weight > 0:
        status = GradeStatus.PARTIAL
    else:
        status = GradeStatus.FAIL

    return LiveGrade(
        status=status,
        score=score,
        earned_weight=earned_weight,
        possible_weight=possible_weight,
        criterion_denominator=len(criteria),
        evidence_count=len(evidence_by_id),
        criteria=criteria,
        lab_broken=signals.lab_broken,
        tampered=signals.tampered,
        signal_detail=signals.detail,
    )
