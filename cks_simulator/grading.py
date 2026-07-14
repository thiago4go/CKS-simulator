"""Deterministic, cluster-free grading for learner artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


SUPPORTED_RULE_KINDS = {
    "file_exists",
    "json_pointer",
    "text_contains",
    "text_exact_lines",
    "text_not_contains",
}


def json_pointer(value: Any, pointer: str) -> Any:
    current = value
    if pointer == "":
        return current
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must be empty or start with '/'")
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current[part]
    return current


def _criterion(label: str, passed: bool) -> Dict[str, Any]:
    return {"label": label, "passed": passed}


def evaluate_rule(artifact_root: Path, rule: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate one catalog rule and expose its independently scored criteria."""
    relative_path = rule["path"]
    path = artifact_root / relative_path
    kind = rule["kind"]
    criteria: List[Dict[str, Any]] = []

    if kind not in SUPPORTED_RULE_KINDS:
        criteria.append(_criterion(f"supported rule kind: {kind}", False))
    elif kind == "file_exists":
        criteria.append(_criterion(f"{relative_path} exists", path.is_file()))
    else:
        text: Any = None
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                text = None
        if kind == "text_contains":
            criteria.extend(
                _criterion(f"{relative_path} contains {value!r}", text is not None and value in text)
                for value in rule["values"]
            )
        elif kind == "text_not_contains":
            criteria.extend(
                _criterion(f"{relative_path} excludes {value!r}", text is not None and value not in text)
                for value in rule["values"]
            )
        elif kind == "text_exact_lines":
            actual = [line for line in text.splitlines() if line.strip()] if text is not None else []
            expected = rule["values"]
            criteria.extend(
                _criterion(f"{relative_path} line {index + 1} is {value!r}", index < len(actual) and actual[index] == value)
                for index, value in enumerate(expected)
            )
            criteria.append(_criterion(f"{relative_path} has exactly {len(expected)} non-empty lines", text is not None and len(actual) == len(expected)))
        elif kind == "json_pointer":
            try:
                actual = json_pointer(json.loads(text), rule["pointer"])
                criteria.append(_criterion(f"{relative_path}{rule['pointer']} equals {rule['expected']!r}", actual == rule["expected"]))
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                criteria.append(_criterion(f"{relative_path} JSON lookup succeeds: {exc}", False))

    if not criteria:
        criteria.append(_criterion(f"{relative_path} rule defines at least one criterion", False))
    passed = all(item["passed"] for item in criteria)
    return {
        "path": relative_path,
        "kind": kind,
        "passed": passed,
        "earned": sum(1 for item in criteria if item["passed"]),
        "possible": len(criteria),
        "criteria": criteria,
    }


def grade_scenario(item: Dict[str, Any], artifact_root: Path) -> Dict[str, Any]:
    rules = [evaluate_rule(artifact_root, rule) for rule in item["checks"]]
    earned = sum(rule["earned"] for rule in rules)
    possible = sum(rule["possible"] for rule in rules)
    score = round((earned / possible) * 100, 1) if possible else 0.0
    return {
        "id": item["id"],
        "title": item["title"],
        "kind_support": item["kind_support"],
        "artifact_root": str(artifact_root),
        "validation_scope": "artifact evidence; live support is graded separately by e2e",
        "earned": earned,
        "possible": possible,
        "score": score,
        "status": "complete" if earned == possible else "incomplete",
        "rules": rules,
    }


def summarize_grades(grades: List[Dict[str, Any]]) -> Dict[str, Any]:
    score = round(sum(grade["score"] for grade in grades) / len(grades), 1) if grades else 0.0
    return {
        "validation_scope": "artifact evidence; not an official CKS exam score",
        "scenario_count": len(grades),
        "complete": sum(1 for grade in grades if grade["status"] == "complete"),
        "score": score,
        "status": "complete" if grades and all(grade["status"] == "complete" for grade in grades) else "incomplete",
        "scenarios": grades,
    }
