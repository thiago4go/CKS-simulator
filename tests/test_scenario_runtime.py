from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from cks_simulator.providers.base import (
    GuestIdentity,
    ProcessResult,
    ProviderMachine,
    derive_provider_handle,
)
from cks_simulator.scenario_runtime import (
    build_health_attestor,
    build_u7_registries,
)
from cks_simulator.scenarios import ScenarioContext, ScenarioEngine, load_full_catalog
from cks_simulator.state import LabPhase, LabStateStore, MachineObservation


ROOT = Path(__file__).resolve().parents[1]


class FakeScenarioProvider:
    name = "lima"

    def __init__(self, state) -> None:
        self.state = state
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.lifecycle = "restored"
        self.solved = False

    def observe_machine(self, handle):
        observed = next(item for item in self.state.observations if item.handle == handle)
        return SimpleNamespace(
            ipv4=observed.ipv4,
            mac=observed.mac_address,
            product_uuid=observed.product_uuid,
        )

    def execute_verified(
        self,
        expected: GuestIdentity,
        argv,
        *,
        stdin=None,
        as_root=False,
        timeout_seconds=120.0,
        output_limit=4096,
        secrets=(),
    ) -> ProcessResult:
        machine = next(item for item in self.state.inventory if item.role == expected.role)
        self.assert_identity(expected, machine)
        command = tuple(argv)
        self.calls.append((expected.role, command))
        stdout = ""
        if command[0] == "/usr/bin/sha256sum":
            local = ROOT / command[1].removeprefix("/opt/cks-simulator/provision/")
            if not local.is_file():
                local = ROOT / "infra/provision" / command[1].removeprefix(
                    "/opt/cks-simulator/provision/"
                )
            stdout = f"{hashlib.sha256(local.read_bytes()).hexdigest()}  {command[1]}\n"
        elif command[0].endswith("/mutate.sh"):
            action = command[2]
            self.lifecycle = {
                "prepare": "prepared",
                "reference": "reference",
                "restore": "restored",
            }[action]
            self.solved = action == "reference"
        elif command[0].endswith("/observe.sh"):
            checks = {
                "contexts-exact": self.solved,
                "certificate-pem": self.solved,
                "certificate-match": self.solved,
            }
            payload = {
                "checks": checks,
                "lifecycle": self.lifecycle,
                "role": expected.role,
                "scenario_id": "01",
                "schema": 1,
                "state_sha256": "a" * 64,
            }
            stdout = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        return ProcessResult(
            command=command,
            returncode=0,
            stdout=stdout,
            stderr="",
            output_limit=output_limit,
        )

    @staticmethod
    def assert_identity(expected: GuestIdentity, machine: ProviderMachine) -> None:
        assert expected.machine_id == machine.machine_id
        assert expected.handle == machine.handle
        assert expected.role == machine.role


def candidate_ready(store: LabStateStore, name: str):
    state = store.claim(name, provider="lima")
    state = store.bind_provisioning_spec(name, state.identity.lab_id, "a" * 64)
    machines = tuple(
        ProviderMachine(
            role=role,
            machine_id=str(uuid.uuid4()),
            handle=derive_provider_handle("lima", state.identity.lab_id, role),
        )
        for role in ("candidate", "control-plane", "worker1", "worker2")
    )
    state = store.declare_inventory(name, state.identity.lab_id, machines)
    observations = tuple(
        MachineObservation(
            role=machine.role,
            machine_id=machine.machine_id,
            handle=machine.handle,
            ipv4=f"192.0.2.{index + 10}",
            mac_address=f"02:00:00:00:00:{index + 1:02x}",
            product_uuid=str(uuid.uuid4()),
            provisioning_bundle_sha256="b" * 64,
            provisioning_spec_sha256="a" * 64,
        )
        for index, machine in enumerate(machines)
    )
    state = store.record_machine_observations(name, state.identity.lab_id, observations)
    for phase in (
        LabPhase.VMS_CREATED,
        LabPhase.OS_READY,
        LabPhase.CLUSTER_READY,
        LabPhase.ADDONS_READY,
        LabPhase.CANDIDATE_READY,
    ):
        state = store.advance(name, state.identity.lab_id, phase)
    return state


class U7ScenarioRuntimeTests(unittest.TestCase):
    def test_fake_live_matrix_is_fail_pass_repeat_restore_with_verified_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = LabStateStore(Path(temporary), namespace="full")
            state = candidate_ready(store, "u7-contract")
            provider = FakeScenarioProvider(state)
            handlers, references, _broker = build_u7_registries(provider, ROOT)
            engine = ScenarioEngine(
                store=store,
                catalog=load_full_catalog(ROOT / "scenarios/catalog.json"),
                handlers=handlers,
                attest_health=build_health_attestor(provider),
            )

            prepared = engine.prepare("u7-contract", "01")
            self.assertEqual(engine.grade("u7-contract", "01").score, 0)
            references.execute(
                load_full_catalog(ROOT / "scenarios/catalog.json").require("01"),
                ScenarioContext("u7-contract", prepared),
                timeout_seconds=30,
            )
            self.assertEqual(engine.grade("u7-contract", "01").score, 100)
            self.assertEqual(engine.grade("u7-contract", "01").score, 100)
            restored = engine.restore("u7-contract", "01")

            self.assertIs(restored.phase, LabPhase.VALIDATED)
            self.assertIsNone(restored.active_scenario)
            self.assertGreaterEqual(
                sum(command[0] == "/usr/bin/sha256sum" for _, command in provider.calls),
                6,
            )
            self.assertTrue(
                all(role in {"candidate", "control-plane", "worker1", "worker2"} for role, _ in provider.calls)
            )

    def test_observer_has_no_admin_kubeconfig_or_mutation_dispatch(self) -> None:
        source = (ROOT / "infra/provision/scenarios/observe.sh").read_text()
        self.assertNotIn("admin.conf", source)
        self.assertNotIn("docker --host \"$DOCKER_SOCKET\" exec", source)
        self.assertNotIn("kubectl apply", source)
        self.assertNotIn("kubectl patch", source)
        self.assertNotIn("kubectl delete", source)
        self.assertIn("cks-grader.kubeconfig", source)


if __name__ == "__main__":
    unittest.main()
