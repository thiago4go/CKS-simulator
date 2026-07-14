"""Reviewed recovery ladder for full-tier scenario rehearsals."""

from __future__ import annotations

from dataclasses import dataclass

from .scenarios import (
    FullScenarioDefinition,
    RecoveryMode,
    RecoverySignals,
    ScenarioEngine,
    select_recovery_mode,
)
from .state import LabPhase


@dataclass(frozen=True)
class RecoveryResult:
    """Bounded result of one recovery decision and action."""

    mode: RecoveryMode
    recovered: bool
    phase: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "recovered": self.recovered,
            "phase": self.phase,
            "detail": self.detail,
        }


def recover_active_scenario(
    engine: ScenarioEngine,
    lab_name: str,
    definition: FullScenarioDefinition,
    signals: RecoverySignals,
) -> RecoveryResult:
    """Execute only the recovery rung justified by trusted signals.

    Targeted and operator-transport recovery both use the scenario's reviewed,
    exact restore handler.  A missing identity or transport never triggers
    discovery or adoption; it returns a rebuild-required decision instead.
    """

    mode = select_recovery_mode(definition, signals)
    if mode is RecoveryMode.REBUILD_REQUIRED:
        return RecoveryResult(
            mode=mode,
            recovered=False,
            phase=LabPhase.DEGRADED.value,
            detail="identity or operator transport is unavailable; exact rebuild required",
        )
    state = engine.restore(lab_name, definition.scenario_id)
    recovered = state.phase is LabPhase.VALIDATED and state.active_scenario is None
    return RecoveryResult(
        mode=mode,
        recovered=recovered,
        phase=state.phase.value,
        detail=(
            "reviewed restore and health attestation passed"
            if recovered
            else "reviewed restore did not return the lab to validated"
        ),
    )


__all__ = ["RecoveryResult", "recover_active_scenario"]
