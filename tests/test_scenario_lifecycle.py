from __future__ import annotations

import json
import tempfile
import unittest
import uuid
from pathlib import Path

from cks_simulator.providers.base import ProviderMachine, derive_provider_handle
from cks_simulator.state import (
    ActiveScenario,
    InvalidTransitionError,
    LabPhase,
    LabState,
    LabStateStore,
    MachineObservation,
    OwnershipError,
    StateValidationError,
)


class ScenarioStateLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = LabStateStore(self.root, namespace="full")
        self.name = "scenario-lab"

    def candidate_ready(self):
        state = self.store.claim(self.name, provider="lima")
        state = self.store.bind_provisioning_spec(
            self.name, state.identity.lab_id, "a" * 64
        )
        machines = tuple(
            ProviderMachine(
                role=role,
                machine_id=str(uuid.uuid4()),
                handle=derive_provider_handle("lima", state.identity.lab_id, role),
            )
            for role in ("candidate", "control-plane", "worker1", "worker2")
        )
        state = self.store.declare_inventory(
            self.name, state.identity.lab_id, machines
        )
        observations = tuple(
            MachineObservation(
                role=machine.role,
                machine_id=machine.machine_id,
                handle=machine.handle,
                ipv4=f"192.0.2.{20 + index}",
                mac_address=f"02:00:00:00:00:{index + 1:02x}",
                product_uuid=str(uuid.uuid4()),
                provisioning_bundle_sha256="b" * 64,
                provisioning_spec_sha256="a" * 64,
            )
            for index, machine in enumerate(machines)
        )
        state = self.store.record_machine_observations(
            self.name, state.identity.lab_id, observations
        )
        for phase in (
            LabPhase.VMS_CREATED,
            LabPhase.OS_READY,
            LabPhase.CLUSTER_READY,
            LabPhase.ADDONS_READY,
            LabPhase.CANDIDATE_READY,
        ):
            state = self.store.advance(self.name, state.identity.lab_id, phase)
        return state

    def test_legacy_candidate_ready_state_loads_without_u6_fields(self) -> None:
        state = self.candidate_ready()
        payload = state.to_dict()
        payload.pop("health_fingerprint")
        payload.pop("active_scenario")
        loaded = LabState.from_dict(payload)
        self.assertIs(loaded.phase, LabPhase.CANDIDATE_READY)
        self.assertIsNone(loaded.health_fingerprint)
        self.assertIsNone(loaded.active_scenario)

    def test_attest_prepare_and_exact_restore_are_atomic_state_transitions(self) -> None:
        state = self.candidate_ready()
        baseline = "c" * 64
        state = self.store.attest_validated(
            self.name, state.identity.lab_id, baseline, detail="host health passed"
        )
        self.assertIs(state.phase, LabPhase.VALIDATED)
        self.assertEqual(state.health_fingerprint, baseline)
        self.assertIsNone(state.active_scenario)

        state = self.store.prepare_scenario(
            self.name,
            state.identity.lab_id,
            scenario_id="04",
            attempt_id=str(uuid.uuid4()),
            handler_identity="full.s04.v1",
            recovery_class="kubernetes-api",
            target_role="worker1",
            prepared_fingerprint="d" * 64,
            restore_fingerprint="e" * 64,
            detail="scenario 04 prepared",
        )
        self.assertIs(state.phase, LabPhase.SCENARIO_PREPARED)
        self.assertEqual(state.active_scenario.scenario_id, "04")
        self.assertEqual(state.active_scenario.baseline_fingerprint, baseline)
        persisted = self.store.load(self.name)
        self.assertEqual(persisted.active_scenario, state.active_scenario)

        restored = self.store.restore_scenario(
            self.name,
            state.identity.lab_id,
            scenario_id="04",
            attempt_id=state.active_scenario.attempt_id,
            health_fingerprint=baseline,
            scenario_fingerprint="e" * 64,
            detail="scenario 04 restored",
        )
        self.assertIs(restored.phase, LabPhase.VALIDATED)
        self.assertIsNone(restored.active_scenario)
        self.assertEqual(
            [entry.phase for entry in restored.journal[-3:]],
            [LabPhase.VALIDATED, LabPhase.SCENARIO_PREPARED, LabPhase.VALIDATED],
        )

    def test_one_active_scenario_and_restore_identity_fail_closed(self) -> None:
        state = self.candidate_ready()
        state = self.store.attest_validated(
            self.name, state.identity.lab_id, "c" * 64
        )
        state = self.store.prepare_scenario(
            self.name,
            state.identity.lab_id,
            scenario_id="01",
            attempt_id=str(uuid.uuid4()),
            handler_identity="full.s01.v1",
            recovery_class="candidate-files",
            target_role="candidate",
            prepared_fingerprint="d" * 64,
            restore_fingerprint="f" * 64,
        )
        with self.assertRaises(InvalidTransitionError):
            self.store.prepare_scenario(
                self.name,
                state.identity.lab_id,
                scenario_id="02",
                attempt_id=str(uuid.uuid4()),
                handler_identity="full.s02.v1",
                recovery_class="candidate-files",
                target_role="candidate",
                prepared_fingerprint="e" * 64,
                restore_fingerprint="f" * 64,
            )
        with self.assertRaises(OwnershipError):
            self.store.restore_scenario(
                self.name,
                state.identity.lab_id,
                scenario_id="01",
                attempt_id=str(uuid.uuid4()),
                health_fingerprint="c" * 64,
                scenario_fingerprint="f" * 64,
            )
        with self.assertRaises(StateValidationError):
            self.store.restore_scenario(
                self.name,
                state.identity.lab_id,
                scenario_id="01",
                attempt_id=state.active_scenario.attempt_id,
                health_fingerprint="f" * 64,
                scenario_fingerprint="f" * 64,
            )
        unchanged = self.store.load(self.name)
        self.assertIs(unchanged.phase, LabPhase.SCENARIO_PREPARED)
        self.assertEqual(unchanged.active_scenario, state.active_scenario)

    def test_grade_has_no_generic_state_transition_surface(self) -> None:
        state = self.candidate_ready()
        with self.assertRaises(InvalidTransitionError):
            self.store.advance(
                self.name, state.identity.lab_id, LabPhase.VALIDATED
            )
        state = self.store.attest_validated(
            self.name, state.identity.lab_id, "c" * 64
        )
        for phase in (LabPhase.SCENARIO_PREPARED, LabPhase.GRADED):
            with self.subTest(phase=phase), self.assertRaises(InvalidTransitionError):
                self.store.advance(self.name, state.identity.lab_id, phase)

    def test_active_scenario_rejects_cross_id_handler_and_unsafe_values(self) -> None:
        base = dict(
            scenario_id="04",
            attempt_id=str(uuid.uuid4()),
            handler_identity="full.s04.v1",
            recovery_class="kubernetes-api",
            target_role="worker1",
            baseline_fingerprint="a" * 64,
            prepared_fingerprint="b" * 64,
            restore_fingerprint="c" * 64,
        )
        ActiveScenario(**base)
        for field, value in (
            ("scenario_id", "4"),
            ("attempt_id", "not-a-uuid"),
            ("handler_identity", "full.s05.v1"),
            ("handler_identity", "../../handler"),
            ("recovery_class", "control plane"),
            ("target_role", "--worker"),
            ("baseline_fingerprint", "short"),
        ):
            hostile = dict(base)
            hostile[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(
                StateValidationError
            ):
                ActiveScenario(**hostile)

    def test_legacy_scenario_phases_remain_readable_for_attestation_and_cleanup(self) -> None:
        state = self.candidate_ready()
        payload = state.to_dict()
        payload.pop("health_fingerprint")
        payload.pop("active_scenario")
        payload["journal"].append(
            {
                "sequence": len(payload["journal"]),
                "phase": LabPhase.VALIDATED.value,
                "recorded_at": "2026-07-14T00:00:00Z",
                "detail": "legacy validated",
            }
        )
        self.store.state_path(self.name).write_text(
            json.dumps(payload), encoding="utf-8"
        )

        legacy = self.store.load(self.name)
        self.assertIs(legacy.phase, LabPhase.VALIDATED)
        self.assertIsNone(legacy.health_fingerprint)
        rebound = self.store.attest_validated(
            self.name, legacy.identity.lab_id, "c" * 64
        )
        self.assertEqual(rebound.health_fingerprint, "c" * 64)
        self.assertEqual(rebound.journal, legacy.journal)

        graded = payload
        graded["journal"].extend(
            (
                {
                    "sequence": len(graded["journal"]),
                    "phase": LabPhase.SCENARIO_PREPARED.value,
                    "recorded_at": "2026-07-14T00:01:00Z",
                    "detail": "legacy prepared",
                },
                {
                    "sequence": len(graded["journal"]) + 1,
                    "phase": LabPhase.GRADED.value,
                    "recorded_at": "2026-07-14T00:02:00Z",
                    "detail": "legacy graded",
                },
            )
        )
        self.store.state_path(self.name).write_text(
            json.dumps(graded), encoding="utf-8"
        )
        loaded_graded = self.store.load(self.name)
        self.assertIs(loaded_graded.phase, LabPhase.GRADED)
        cleanup = self.store.advance(
            self.name, loaded_graded.identity.lab_id, LabPhase.CLEANUP_PENDING
        )
        self.assertIs(cleanup.phase, LabPhase.CLEANUP_PENDING)


if __name__ == "__main__":
    unittest.main()
