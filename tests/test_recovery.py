from __future__ import annotations

import unittest
from types import SimpleNamespace
from pathlib import Path

from cks_simulator.recovery import recover_active_scenario
from cks_simulator.scenarios import (
    RecoveryMode,
    RecoverySignals,
    load_full_catalog,
)
from cks_simulator.state import LabPhase


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.definition = load_full_catalog(
            Path(__file__).resolve().parents[1] / "scenarios" / "catalog.json"
        ).require("12")

    def test_api_down_uses_reviewed_operator_transport_restore(self) -> None:
        state = SimpleNamespace(phase=LabPhase.VALIDATED, active_scenario=None)

        class Engine:
            calls = []

            def restore(self, name, scenario_id):
                self.calls.append((name, scenario_id))
                return state

        engine = Engine()
        result = recover_active_scenario(
            engine,
            "lab",
            self.definition,
            RecoverySignals(api_available=False),
        )
        self.assertEqual(result.mode, RecoveryMode.OPERATOR_TRANSPORT)
        self.assertTrue(result.recovered)
        self.assertEqual(engine.calls, [("lab", "12")])

    def test_lost_identity_requires_rebuild_without_mutation(self) -> None:
        class Engine:
            def restore(self, *_args):
                raise AssertionError("restore must not run")

        result = recover_active_scenario(
            Engine(),
            "lab",
            self.definition,
            RecoverySignals(guest_identity_intact=False),
        )
        self.assertEqual(result.mode, RecoveryMode.REBUILD_REQUIRED)
        self.assertFalse(result.recovered)


if __name__ == "__main__":
    unittest.main()
