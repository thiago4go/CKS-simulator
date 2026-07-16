from __future__ import annotations

import tempfile
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Iterable, Optional, Sequence

from cks_simulator.lab import FullLabReconcileError
from cks_simulator.providers.base import (
    Discovery,
    GuestIdentity,
    OwnershipProofMode,
    Presence,
    ProcessResult,
    ProviderHandle,
)
from cks_simulator.providers.lima import MachineObservation as LimaMachineObservation
from cks_simulator.progress import ProgressEvent
from cks_simulator.state import LabPhase, LabStateStore, StateMissingError


ROLES = ("candidate", "control-plane", "worker1", "worker2")


def result(*, ok: bool = True, stdout: str = "", stderr: str = "") -> ProcessResult:
    return ProcessResult(
        command=("fake",),
        returncode=0 if ok else 1,
        stdout=stdout,
        stderr=stderr,
    )


class FakeProvider:
    name = "lima"

    def __init__(self, store: LabStateStore, lab_name: str) -> None:
        self.store = store
        self.lab_name = lab_name
        self.identities: dict[ProviderHandle, Optional[GuestIdentity]] = {}
        self.observations: dict[ProviderHandle, LimaMachineObservation] = {}
        self.calls: list[tuple[object, ...]] = []
        self.fail_scripts: set[str] = set()
        self.fail_ensure_roles: set[str] = set()
        self.fail_deletes: set[ProviderHandle] = set()
        self.discovery_unknown = False
        self.join_material_override: Optional[str] = None
        self._next_address = 10

    def discover(self, expected_handles: Sequence[ProviderHandle]) -> Discovery:
        self.calls.append(("discover", tuple(expected_handles)))
        if self.discovery_unknown:
            return Discovery(Presence.UNKNOWN, detail="inventory unavailable")
        present = tuple(handle for handle in expected_handles if handle in self.identities)
        if present:
            return Discovery(Presence.PRESENT, handles=present)
        return Discovery(Presence.ABSENT)

    def read_guest_identity(self, handle: ProviderHandle) -> Optional[GuestIdentity]:
        self.calls.append(("identity", handle))
        return self.identities[handle]

    def prove_ownership(
        self,
        expected: GuestIdentity,
        *,
        mode: OwnershipProofMode,
    ) -> bool:
        self.calls.append(("prove", expected.handle, mode))
        if expected.handle not in self.identities:
            return False
        observed = self.identities[expected.handle]
        return observed == expected or (
            observed is None and mode is OwnershipProofMode.BREAK_GLASS
        )

    def ensure(self, identity: GuestIdentity) -> ProcessResult:
        state = self.store.load(self.lab_name)
        if len(state.inventory) != 4:
            raise AssertionError("immutable inventory was not declared before provider mutation")
        self.calls.append(("ensure", identity.role, identity.handle))
        if identity.role in self.fail_ensure_roles:
            return result(ok=False, stderr="injected ensure failure")
        self.identities.setdefault(identity.handle, identity)
        self.observations.setdefault(
            identity.handle,
            LimaMachineObservation(
                f"192.0.2.{self._next_address}",
                f"02:00:00:00:00:{self._next_address:02x}",
                str(uuid.UUID(int=self._next_address)),
            ),
        )
        self._next_address += 1
        return result()

    create = ensure

    def install_root_file(
        self,
        handle: ProviderHandle,
        destination: str,
        content: bytes,
        *,
        mode: int = 0o600,
        timeout_seconds: float = 120.0,
    ) -> ProcessResult:
        self.calls.append(("install", handle, destination, content, mode))
        return result()

    def observe_machine(self, handle: ProviderHandle) -> LimaMachineObservation:
        self.calls.append(("observe", handle))
        return self.observations[handle]

    def execute(
        self,
        handle: ProviderHandle,
        argv: Sequence[str],
        *,
        stdin: Optional[bytes] = None,
        as_root: bool = False,
        timeout_seconds: float = 120.0,
        output_limit: int = 4096,
        secrets: Sequence[str] = (),
    ) -> ProcessResult:
        command = tuple(argv)
        self.calls.append(("execute", handle, command, stdin, as_root, tuple(secrets), timeout_seconds))
        script = command[-1] if command else ""
        if any(script.endswith(name) for name in self.fail_scripts):
            return result(ok=False, stderr="injected script failure")
        if script.endswith("join-material.sh"):
            if self.join_material_override is not None:
                return result(stdout=self.join_material_override)
            control_plane = next(
                machine
                for machine in self.store.load(self.lab_name).inventory
                if machine.role == "control-plane"
            )
            return result(
                stdout=(
                    f"CONTROL_PLANE_ENDPOINT={control_plane.handle.value}:6443\n"
                    "BOOTSTRAP_TOKEN=abcdef.0123456789abcdef\n"
                    f"DISCOVERY_TOKEN_CA_CERT_HASH=sha256:{'a' * 64}\n"
                    "CRI_SOCKET=unix:///run/containerd/containerd.sock\n"
                )
            )
        return result()

    def _delete_exact(self, handle: ProviderHandle) -> ProcessResult:
        self.calls.append(("delete", handle))
        if handle in self.fail_deletes:
            return result(ok=False, stderr="injected delete failure")
        self.identities.pop(handle, None)
        self.observations.pop(handle, None)
        return result()


class LabLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        for relative in (
            "common/lib.sh",
            "common/install.sh",
            "common/check.sh",
            "common/versions.env",
            "control-plane/lib.sh",
            "control-plane/bootstrap.sh",
            "control-plane/join-material.sh",
            "control-plane/revoke-token.sh",
            "control-plane/health.sh",
            "worker/join.sh",
        ):
            path = self.bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            content = f"#!/bin/sh\n# {relative}\n"
            if relative == "common/versions.env":
                content += "KUBERNETES_VERSION=v1.35.6\n"
            path.write_text(content, encoding="utf-8")
        self.store = LabStateStore(self.root / "state", namespace="full")
        self.lab_name = "u4-lab"
        self.provider = FakeProvider(self.store, self.lab_name)

    def lifecycle(self, config=None, **kwargs):
        from cks_simulator.lab import FullLabConfig, FullLabLifecycle

        return FullLabLifecycle(
            self.store,
            self.provider,
            provisioning_root=self.bundle,
            config=config or FullLabConfig(),
            **kwargs,
        )

    def provision(self):
        return self.lifecycle().provision(self.lab_name)

    def test_fresh_provision_claims_four_machines_before_mutation_and_reaches_addons_ready(self) -> None:
        state = self.provision()

        self.assertIs(state.phase, LabPhase.ADDONS_READY)
        self.assertEqual({machine.role for machine in state.inventory}, set(ROLES))
        self.assertEqual(len(state.observations), 4)
        self.assertEqual(len({item.ipv4 for item in state.observations}), 4)
        self.assertEqual(len({item.mac_address for item in state.observations}), 4)
        self.assertEqual(len({item.product_uuid for item in state.observations}), 4)
        self.assertEqual(len({item.provisioning_bundle_sha256 for item in state.observations}), 1)
        self.assertEqual(len({item.provisioning_spec_sha256 for item in state.observations}), 1)
        host_maps = [
            call for call in self.provider.calls
            if call[0] == "install" and call[2] == "/etc/hosts"
        ]
        self.assertEqual(len(host_maps), 4)
        for call in host_maps:
            rendered = call[3].decode("ascii")
            for machine in state.inventory:
                self.assertIn(machine.handle.value, rendered)
        phases = [entry.phase for entry in state.journal]
        self.assertEqual(
            phases,
            [
                LabPhase.DECLARED,
                LabPhase.VMS_CREATED,
                LabPhase.OS_READY,
                LabPhase.CLUSTER_READY,
                LabPhase.ADDONS_READY,
            ],
        )

        ensure_roles = [call[1] for call in self.provider.calls if call[0] == "ensure"]
        self.assertEqual(ensure_roles, list(ROLES))
        execute_scripts = [
            next(argument for argument in call[2] if argument.startswith("/opt/cks-simulator/provision/") and argument.endswith(".sh"))
            for call in self.provider.calls
            if call[0] == "execute"
        ]
        self.assertLess(execute_scripts.index("/opt/cks-simulator/provision/common/check.sh"), execute_scripts.index("/opt/cks-simulator/provision/control-plane/bootstrap.sh"))
        self.assertLess(execute_scripts.index("/opt/cks-simulator/provision/control-plane/bootstrap.sh"), execute_scripts.index("/opt/cks-simulator/provision/worker/join.sh"))
        self.assertEqual(execute_scripts[-1], "/opt/cks-simulator/provision/control-plane/health.sh")
        installed = [call[2] for call in self.provider.calls if call[0] == "install"]
        self.assertNotIn("/opt/cks-simulator/provision/worker/run-join.sh", installed)

    def test_provision_reports_only_real_verified_lifecycle_stages(self) -> None:
        events: list[ProgressEvent] = []

        state = self.lifecycle(progress=events.append).provision(self.lab_name)

        completed = [item.stage for item in events if item.completed]
        self.assertEqual(state.phase, LabPhase.ADDONS_READY)
        self.assertEqual(completed, [2, 3, 4])
        vm_updates = [item for item in events if item.stage == 2 and not item.completed]
        self.assertEqual(vm_updates[-1].current, len(ROLES))
        self.assertEqual(vm_updates[-1].total, len(ROLES))
        self.assertTrue(any("worker1" in item.detail for item in events))

    def test_repeat_provision_reverifies_reality_without_duplicate_phases(self) -> None:
        first = self.provision()
        journal = first.journal
        calls_before = len(self.provider.calls)

        second = self.provision()

        self.assertEqual(second.journal, journal)
        replay = self.provider.calls[calls_before:]
        self.assertEqual([call[1] for call in replay if call[0] == "ensure"], list(ROLES))
        self.assertEqual(len([call for call in replay if call[0] == "observe"]), 4)
        self.assertTrue(any(call[0] == "execute" and call[2][-1].endswith("health.sh") for call in replay))

    def test_memory_profile_is_persisted_and_profile_drift_fails_before_provider_mutation(self) -> None:
        low = self.lifecycle(
            provisioning_profile="low",
            provisioning_spec_extension={
                "memory_profile": "low",
                "memory_gib_by_role": {
                    "candidate": 1,
                    "control-plane": 2,
                    "worker1": 1,
                    "worker2": 1,
                },
            },
        )
        state = low.provision(self.lab_name)
        self.assertEqual(state.provisioning_profile, "low")
        calls_before = tuple(self.provider.calls)

        with self.assertRaisesRegex(FullLabReconcileError, "profile drift"):
            self.lifecycle().provision(self.lab_name)

        self.assertEqual(tuple(self.provider.calls), calls_before)

    def test_creation_capacity_requires_verified_phase_and_all_exact_machines(self) -> None:
        lifecycle = self.lifecycle()
        state = lifecycle.provision(self.lab_name)
        self.assertFalse(lifecycle.requires_creation_capacity(self.lab_name))

        missing = state.inventory[0].handle
        self.provider.identities.pop(missing)
        self.assertTrue(lifecycle.requires_creation_capacity(self.lab_name))

        self.provider.discovery_unknown = True
        with self.assertRaisesRegex(FullLabReconcileError, "inventory is unknown"):
            lifecycle.requires_creation_capacity(self.lab_name)

    def test_interrupted_creation_keeps_creation_capacity_gate(self) -> None:
        lifecycle = self.lifecycle()
        self.provider.fail_ensure_roles.add("candidate")
        with self.assertRaises(FullLabReconcileError):
            lifecycle.provision(self.lab_name)
        self.assertIs(self.store.load(self.lab_name).phase, LabPhase.DEGRADED)
        self.assertTrue(lifecycle.requires_creation_capacity(self.lab_name))

    def test_join_material_stays_on_bounded_stdin_and_token_is_revoked(self) -> None:
        self.provision()

        joins = [call for call in self.provider.calls if call[0] == "execute" and call[2][-1].endswith("worker/join.sh")]
        self.assertEqual(len(joins), 2)
        for call in joins:
            argv = call[2]
            stdin = call[3]
            self.assertNotIn("abcdef.0123456789abcdef", " ".join(argv))
            self.assertNotIn(f"sha256:{'a' * 64}", " ".join(argv))
            self.assertFalse(any(item.startswith("BOOTSTRAP_TOKEN=") for item in argv))
            self.assertFalse(any(item.startswith("DISCOVERY_TOKEN_CA_CERT_HASH=") for item in argv))
            self.assertIsNotNone(stdin)
            self.assertLessEqual(len(stdin or b""), 512)
            self.assertIn(b"BOOTSTRAP_TOKEN=", stdin or b"")
            self.assertIn("abcdef.0123456789abcdef", call[5])
            self.assertIn(f"sha256:{'a' * 64}", call[5])
            self.assertIn((stdin or b"").decode("ascii"), call[5])
        revocations = [call for call in self.provider.calls if call[0] == "execute" and call[2][-1].endswith("revoke-token.sh")]
        self.assertEqual(len(revocations), 1)
        self.assertEqual(revocations[0][3], b"abcdef.0123456789abcdef\n")
        self.assertNotIn("abcdef.0123456789abcdef", " ".join(revocations[0][2]))
        self.assertEqual(revocations[0][5], ("abcdef.0123456789abcdef",))

    def test_worker_failure_revokes_token_marks_degraded_and_never_auto_deletes(self) -> None:
        self.provider.fail_scripts.add("worker/join.sh")

        with self.assertRaisesRegex(RuntimeError, "worker join"):
            self.provision()

        state = self.store.load(self.lab_name)
        self.assertIs(state.phase, LabPhase.DEGRADED)
        self.assertTrue(any(call[0] == "execute" and call[2][-1].endswith("revoke-token.sh") for call in self.provider.calls))
        self.assertFalse(any(call[0] == "delete" for call in self.provider.calls))

    def test_worker_failure_is_replayable_after_fault_is_cleared(self) -> None:
        self.provider.fail_scripts.add("worker/join.sh")
        with self.assertRaisesRegex(RuntimeError, "worker join"):
            self.provision()

        self.provider.fail_scripts.clear()
        recovered = self.provision()

        self.assertIs(recovered.phase, LabPhase.ADDONS_READY)
        self.assertEqual(len(recovered.inventory), 4)
        self.assertEqual(len(recovered.observations), 4)
        self.assertEqual(
            [entry.phase for entry in recovered.journal].count(LabPhase.DEGRADED),
            1,
        )

    def test_worker_failure_diagnostic_redacts_token_and_ca_hash(self) -> None:
        token = "abcdef.0123456789abcdef"
        ca_hash = f"sha256:{'a' * 64}"

        original_execute = self.provider.execute

        def leaking_execute(handle, argv, **kwargs):
            if argv and argv[-1].endswith("worker/join.sh"):
                self.provider.calls.append(
                    (
                        "execute",
                        handle,
                        tuple(argv),
                        kwargs.get("stdin"),
                        kwargs.get("as_root", False),
                        tuple(kwargs.get("secrets", ())),
                    )
                )
                return result(ok=False, stderr=f"failed with {token} and {ca_hash}")
            return original_execute(handle, argv, **kwargs)

        self.provider.execute = leaking_execute  # type: ignore[method-assign]

        with self.assertRaises(RuntimeError) as raised:
            self.provision()

        diagnostic = str(raised.exception)
        self.assertNotIn(token, diagnostic)
        self.assertNotIn(ca_hash, diagnostic)
        self.assertIn("[REDACTED]", diagnostic)

    def test_bootstrap_failure_redacts_discovered_token_from_error_and_journal(self) -> None:
        token = "abcdef.0123456789abcdef"
        original_execute = self.provider.execute

        def leaking_execute(handle, argv, **kwargs):
            if argv and argv[-1].endswith("control-plane/bootstrap.sh"):
                return result(ok=False, stderr=f"kubeadm failed; join token {token}")
            return original_execute(handle, argv, **kwargs)

        self.provider.execute = leaking_execute  # type: ignore[method-assign]

        with self.assertRaises(RuntimeError) as raised:
            self.provision()

        self.assertNotIn(token, str(raised.exception))
        persisted = self.store.load(self.lab_name).journal[-1].detail
        self.assertNotIn(token, persisted)
        self.assertIn("[REDACTED]", persisted)

    def test_malformed_join_material_still_revokes_any_valid_emitted_token(self) -> None:
        self.provider.join_material_override = (
            "CONTROL_PLANE_ENDPOINT=wrong-control-plane:6443\n"
            "BOOTSTRAP_TOKEN=abcdef.0123456789abcdef\n"
            f"DISCOVERY_TOKEN_CA_CERT_HASH=sha256:{'a' * 64}\n"
            "CRI_SOCKET=unix:///run/containerd/containerd.sock\n"
        )

        with self.assertRaisesRegex(RuntimeError, "endpoint"):
            self.provision()

        revocations = [
            call
            for call in self.provider.calls
            if call[0] == "execute" and call[2][-1].endswith("revoke-token.sh")
        ]
        self.assertEqual(len(revocations), 1)
        self.assertEqual(revocations[0][3], b"abcdef.0123456789abcdef\n")
        self.assertIs(self.store.load(self.lab_name).phase, LabPhase.DEGRADED)

    def test_observation_drift_fails_closed_and_marks_degraded(self) -> None:
        self.provision()
        candidate = next(machine for machine in self.store.load(self.lab_name).inventory if machine.role == "candidate")
        previous = self.provider.observations[candidate.handle]
        self.provider.observations[candidate.handle] = LimaMachineObservation(
            "192.0.2.99", previous.mac, previous.product_uuid
        )
        calls_before = len(self.provider.calls)

        with self.assertRaisesRegex(RuntimeError, "drift|immutable"):
            self.provision()

        self.assertIs(self.store.load(self.lab_name).phase, LabPhase.DEGRADED)
        replay = self.provider.calls[calls_before:]
        self.assertFalse(any(call[0] in {"install", "execute"} for call in replay))

    def test_bundle_drift_fails_before_any_guest_mutation(self) -> None:
        self.provision()
        changed = self.bundle / "common" / "check.sh"
        changed.write_text(changed.read_text(encoding="utf-8") + "# changed IaC\n", encoding="utf-8")
        calls_before = len(self.provider.calls)

        with self.assertRaisesRegex(RuntimeError, "bundle drift"):
            self.provision()

        self.assertEqual(self.provider.calls[calls_before:], [])
        self.assertIs(self.store.load(self.lab_name).phase, LabPhase.DEGRADED)

    def test_cidr_specification_drift_fails_before_any_guest_mutation(self) -> None:
        from cks_simulator.lab import FullLabConfig

        self.provision()
        calls_before = len(self.provider.calls)
        for changed in (
            replace(FullLabConfig(), pod_cidr="10.245.0.0/16"),
            replace(FullLabConfig(), service_cidr="10.97.0.0/16"),
        ):
            with self.subTest(config=changed), self.assertRaisesRegex(
                RuntimeError, "specification drift"
            ):
                self.lifecycle(changed).provision(self.lab_name)
        self.assertEqual(self.provider.calls[calls_before:], [])

    def test_spec_is_bound_before_first_vm_and_blocks_changed_retry(self) -> None:
        from cks_simulator.lab import FullLabConfig

        self.provider.fail_ensure_roles.add("candidate")
        with self.assertRaisesRegex(RuntimeError, "Lima ensure"):
            self.provision()
        failed = self.store.load(self.lab_name)
        self.assertIsNotNone(failed.provisioning_spec_sha256)
        self.assertEqual(failed.observations, ())

        self.provider.fail_ensure_roles.clear()
        calls_before = len(self.provider.calls)
        with self.assertRaisesRegex(RuntimeError, "specification drift"):
            self.lifecycle(
                replace(FullLabConfig(), pod_cidr="10.245.0.0/16")
            ).provision(self.lab_name)
        self.assertEqual(self.provider.calls[calls_before:], [])

    def test_destroy_is_worker_first_exact_preserves_unmanaged_and_second_call_is_noop(self) -> None:
        state = self.provision()
        unmanaged = ProviderHandle("lima", "unmanaged-instance")
        self.provider.identities[unmanaged] = None
        calls_before = len(self.provider.calls)

        destroyed = self.lifecycle().destroy(self.lab_name)

        self.assertIs(destroyed.phase, LabPhase.DESTROYED)
        deleted = [call[1] for call in self.provider.calls[calls_before:] if call[0] == "delete"]
        self.assertEqual(
            [handle.value.rsplit("-", 1)[-1] for handle in deleted[:2]],
            ["worker2", "worker1"],
        )
        self.assertEqual(deleted[-1].value.rsplit("-", 1)[-1], "candidate")
        self.assertIn(unmanaged, self.provider.identities)

        deletes_before = len([call for call in self.provider.calls if call[0] == "delete"])
        again = self.lifecycle().destroy(self.lab_name)
        self.assertIs(again.phase, LabPhase.DESTROYED)
        self.assertEqual(len([call for call in self.provider.calls if call[0] == "delete"]), deletes_before)
        self.assertEqual(state.identity.lab_id, again.identity.lab_id)

    def test_partial_cleanup_uses_only_recorded_break_glass_handles(self) -> None:
        state = self.provision()
        externally_absent = next(machine.handle for machine in state.inventory if machine.role == "candidate")
        self.provider.identities.pop(externally_absent)
        markerless = next(machine.handle for machine in state.inventory if machine.role == "control-plane")
        self.provider.identities[markerless] = None

        with self.assertRaisesRegex(RuntimeError, "explicit break-glass"):
            self.lifecycle().destroy(self.lab_name)
        destroyed = self.lifecycle().destroy(
            self.lab_name,
            break_glass=True,
            expected_lab_id=state.identity.lab_id,
        )

        self.assertIs(destroyed.phase, LabPhase.DESTROYED)
        deleted = {call[1] for call in self.provider.calls if call[0] == "delete"}
        self.assertEqual(deleted, set(machine.handle for machine in state.inventory) - {externally_absent})

    def test_full_set_marker_loss_uses_exact_recorded_break_glass_handles(self) -> None:
        state = self.provision()
        for machine in state.inventory:
            self.provider.identities[machine.handle] = None

        with self.assertRaisesRegex(RuntimeError, "explicit break-glass"):
            self.lifecycle().destroy(self.lab_name)
        with self.assertRaisesRegex(RuntimeError, "exact expected lab UUID"):
            self.lifecycle().destroy(
                self.lab_name,
                break_glass=True,
                expected_lab_id=str(uuid.uuid4()),
            )
        destroyed = self.lifecycle().destroy(
            self.lab_name,
            break_glass=True,
            expected_lab_id=state.identity.lab_id,
        )

        self.assertIs(destroyed.phase, LabPhase.DESTROYED)
        deleted = {call[1] for call in self.provider.calls if call[0] == "delete"}
        self.assertEqual(deleted, {machine.handle for machine in state.inventory})

    def test_invalid_break_glass_uuid_does_not_change_ready_state(self) -> None:
        ready = self.provision()
        calls_before = len(self.provider.calls)

        with self.assertRaisesRegex(RuntimeError, "exact expected lab UUID"):
            self.lifecycle().destroy(
                self.lab_name,
                break_glass=True,
                expected_lab_id=str(uuid.uuid4()),
            )

        observed = self.store.load(self.lab_name)
        self.assertEqual(observed.journal, ready.journal)
        self.assertIs(observed.phase, LabPhase.ADDONS_READY)
        self.assertEqual(self.provider.calls[calls_before:], [])

    def test_destroy_aggregates_delete_failures_and_leaves_cleanup_pending(self) -> None:
        state = self.provision()
        failed = {state.inventory[0].handle, state.inventory[2].handle}
        self.provider.fail_deletes.update(failed)

        with self.assertRaisesRegex(RuntimeError, "2 provider cleanup operations failed"):
            self.lifecycle().destroy(self.lab_name)

        self.assertIs(self.store.load(self.lab_name).phase, LabPhase.CLEANUP_PENDING)
        attempted = {call[1] for call in self.provider.calls if call[0] == "delete"}
        self.assertTrue(set(machine.handle for machine in state.inventory).issubset(attempted))

    def test_destroy_refuses_unknown_discovery_and_never_claims_absence(self) -> None:
        self.provision()
        self.provider.discovery_unknown = True

        with self.assertRaisesRegex(RuntimeError, "unknown|unavailable"):
            self.lifecycle().destroy(self.lab_name)

        self.assertIs(self.store.load(self.lab_name).phase, LabPhase.CLEANUP_PENDING)

    def test_destroy_missing_lab_refuses_without_claim_or_provider_mutation(self) -> None:
        missing = "missing-lab"

        with self.assertRaises(StateMissingError):
            self.lifecycle().destroy(missing)

        self.assertFalse(self.store.state_path(missing).exists())
        self.assertEqual(self.provider.calls, [])


if __name__ == "__main__":
    unittest.main()
