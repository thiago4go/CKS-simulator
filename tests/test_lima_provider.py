from __future__ import annotations

import json
import hashlib
import os
import re
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Iterable, Optional

from cks_simulator.providers.base import (
    GuestIdentity,
    OwnershipProofMode,
    Presence,
    ProcessRequest,
    ProcessResult,
    ProviderHandle,
    ProviderMachine,
)
from cks_simulator.providers import kind as kind_module
from cks_simulator.providers import lima as lima_module
from cks_simulator.providers.kind import KindProvider
from cks_simulator.providers.lima import LimaProvider


MARKER_PATH = "/etc/cks-simulator/identity.json"
LAB_ID = "01234567-89ab-cdef-8000-000000000001"


def completed(
    argv: Iterable[str],
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
) -> ProcessResult:
    return ProcessResult(
        command=tuple(argv),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )


class FakeRunner:
    def __init__(self, responses: Iterable[ProcessResult]) -> None:
        self.responses = list(responses)
        self.requests: list[ProcessRequest] = []

    def run(self, request: ProcessRequest) -> ProcessResult:
        self.requests.append(request)
        if not self.responses:
            raise AssertionError(f"unexpected command: {request.argv!r}")
        response = self.responses.pop(0)
        if response.command and response.command != request.argv:
            raise AssertionError(
                f"expected command {response.command!r}, observed {request.argv!r}"
            )
        return response

    def assert_consumed(self) -> None:
        if self.responses:
            raise AssertionError(f"unused fake responses: {self.responses!r}")


def marker(
    *,
    provider: str,
    handle: str,
    lab_id: Optional[str] = None,
    machine_id: Optional[str] = None,
    role: str = "candidate",
) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "managed_by": "cks-simulator",
            "lab_id": lab_id or str(uuid.uuid4()),
            "machine_id": machine_id or str(uuid.uuid4()),
            "role": role,
            "provider": provider,
            "handle": handle,
        }
    )


def lima_inventory(
    identity: GuestIdentity,
    status: str,
    *,
    digest: Optional[str],
    generation: str = "owned",
) -> str:
    """Render stable Lima inventory fields for replacement-sensitive tests."""

    parameters = {} if digest is None else {"cksIdentity": digest}
    return json.dumps(
        {
            "name": identity.handle.value,
            "hostname": identity.handle.value,
            "status": status,
            "dir": f"/private/var/tmp/lima/{identity.handle.value}-{generation}",
            "vmType": "vz",
            "arch": "aarch64",
            "cpus": 2,
            "memory": 4 * 1024 * 1024 * 1024,
            "disk": 100 * 1024 * 1024 * 1024,
            "config": {"param": parameters},
            "limaVersion": "2.1.4",
            "param": parameters,
        }
    )


class LimaProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        limactl = self.root / "limactl"
        limactl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        limactl.chmod(0o700)
        self.limactl = str(limactl.resolve())
        self.templates = {}
        for role in ("candidate", "control-plane", "worker1", "worker2"):
            path = self.root / f"{role}.yaml"
            path.write_text(f"role: {role}\n", encoding="utf-8")
            self.templates[role] = str(path)

    def provider(self, runner: FakeRunner) -> LimaProvider:
        return LimaProvider(
            runner,
            templates=self.templates,
            state_dir=self.root,
            command=(self.limactl,),
        )

    def test_discovery_returns_only_exact_present_handles_and_preserves_lookalikes(self) -> None:
        argv = (self.limactl, "list", "--all-fields", "--json")
        expected = (
            ProviderHandle("lima", "cks-0123456789abcdef-candidate"),
            ProviderHandle("lima", "cks-0123456789abcdef-control-plane"),
            ProviderHandle("lima", "cks-0123456789abcdef-worker1"),
            ProviderHandle("lima", "cks-0123456789abcdef-worker2"),
        )
        inventory = "\n".join(
            json.dumps({"name": name, "status": "Running"})
            for name in (
                "cks-0123456789abcdef-worker10",
                "cks-0123456789abcdef-control-plane",
                "unmanaged",
                "cks-0123456789abcdef-worker1",
            )
        )
        runner = FakeRunner([completed(argv, stdout=inventory)])

        discovery = self.provider(runner).discover(expected)

        self.assertIs(discovery.presence, Presence.PRESENT)
        self.assertEqual(
            discovery.handles,
            (
                expected[1],
                expected[2],
            ),
        )
        self.assertNotIn(ProviderHandle("lima", "cks-0123456789abcdef-worker10"), discovery.handles)
        self.assertEqual(
            [instance.status for instance in discovery.instances],
            [lima_module.LimaInstanceStatus.RUNNING, lima_module.LimaInstanceStatus.RUNNING],
        )
        self.assertEqual(runner.requests[0].output_limit, 1024 * 1024)
        runner.assert_consumed()

    def test_discovery_distinguishes_running_stopped_and_unknown_statuses(self) -> None:
        argv = (self.limactl, "list", "--all-fields", "--json")
        expected = tuple(
            ProviderHandle("lima", f"cks-0123456789abcdef-{role}")
            for role in ("candidate", "control-plane", "worker1")
        )
        inventory = "\n".join(
            (
                json.dumps({"name": expected[0].value, "status": "Running", "param": {}}),
                json.dumps({"name": expected[1].value, "status": "Stopped", "param": {}}),
                json.dumps({"name": expected[2].value, "status": "Broken", "param": {}}),
            )
        )
        runner = FakeRunner([completed(argv, stdout=inventory)])

        discovery = self.provider(runner).discover(expected)

        self.assertEqual(
            [instance.status for instance in discovery.instances],
            [
                lima_module.LimaInstanceStatus.RUNNING,
                lima_module.LimaInstanceStatus.STOPPED,
                lima_module.LimaInstanceStatus.UNKNOWN,
            ],
        )
        self.assertEqual(discovery.status_for(expected[1]), lima_module.LimaInstanceStatus.STOPPED)
        runner.assert_consumed()

    def test_discovery_distinguishes_absent_unknown_and_malformed_output(self) -> None:
        argv = (self.limactl, "list", "--all-fields", "--json")
        expected_handles = (ProviderHandle("lima", "cks-0123456789abcdef-candidate"),)
        cases = (
            (completed(argv, stdout='{"name":"other-lab-worker1","status":"Running"}\n'), Presence.ABSENT),
            (completed(argv, returncode=1, stderr="provider unavailable"), Presence.UNKNOWN),
            (completed(argv, stdout="not-json\n"), Presence.UNKNOWN),
            (completed(argv, stdout='{"status":"Running"}\n'), Presence.UNKNOWN),
            (completed(argv, stdout='{"name":"bad name"}\n'), Presence.UNKNOWN),
            (completed(argv, stdout='{"name":"other-lab-worker1"}\n'), Presence.UNKNOWN),
            (completed(argv, stdout='{"name":"other-lab-worker1","status":7}\n'), Presence.UNKNOWN),
        )
        for response, expected in cases:
            with self.subTest(expected=expected, output=response.stdout or response.stderr):
                runner = FakeRunner([response])
                discovery = self.provider(runner).discover(expected_handles)
                self.assertIs(discovery.presence, expected)
                runner.assert_consumed()

    def test_discovery_requires_unique_exact_lima_handles_without_running_a_command(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        for values in ((), (handle, handle), (ProviderHandle("kind", "quick-lab"),)):
            with self.subTest(values=values):
                runner = FakeRunner([])
                with self.assertRaises(ValueError):
                    self.provider(runner).discover(values)
                self.assertEqual(runner.requests, [])

    def test_create_absent_machine_from_pinned_template_is_rediscovered_and_exact(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        runner = FakeRunner([])
        provider = self.provider(runner)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        digest = lima_module.guest_identity_sha256(identity)
        create_argv = (
            self.limactl,
            "start",
            "--yes",
            "--name",
            handle.value,
            "--param",
            f"cksIdentity={digest}",
            provider._templates["candidate"],
        )
        write_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_WRITE_SCRIPT,
        )
        absent_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_ABSENT_SCRIPT,
        )
        read_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_READ_SCRIPT,
        )
        marker_text = marker(
            provider="lima", handle=handle.value, lab_id=identity.lab_id,
            machine_id=identity.machine_id, role=identity.role,
        )
        runner.responses = [
            completed(inventory_argv, stdout='{"name":"lookalike","status":"Running"}\n'),
            completed(create_argv), completed(write_argv),
            completed(
                inventory_argv,
                stdout=lima_inventory(identity, "Running", digest=digest),
            ),
            completed(absent_argv, returncode=1), completed(read_argv, stdout=marker_text),
        ]

        self.assertTrue(provider.create(identity).ok)

        self.assertEqual(
            [request.argv for request in runner.requests],
            [inventory_argv, create_argv, write_argv, inventory_argv, absent_argv, read_argv],
        )
        self.assertEqual(runner.requests[2].stdin, lima_module.guest_identity_payload(identity))
        self.assertEqual(
            runner.requests[1].pass_fds,
            (provider._template_inputs["candidate"].descriptor,),
        )
        self.assertEqual(provider._templates["candidate"], f"/dev/fd/{provider._template_inputs['candidate'].descriptor}")
        runner.assert_consumed()

    def test_ensure_reuses_running_owned_machine_without_starting_it(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        absent_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_ABSENT_SCRIPT,
        )
        read_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_READ_SCRIPT,
        )
        marker_text = marker(
            provider="lima", handle=handle.value, lab_id=identity.lab_id,
            machine_id=identity.machine_id, role=identity.role,
        )
        runner = FakeRunner(
            [
                completed(
                    inventory_argv,
                    stdout=json.dumps(
                        {
                            "name": handle.value,
                            "status": "Running",
                            "param": {
                                "cksIdentity": lima_module.guest_identity_sha256(identity)
                            },
                        }
                    ),
                ),
                completed(absent_argv, returncode=1),
                completed(read_argv, stdout=marker_text),
            ]
        )

        result = self.provider(runner).ensure(identity)

        self.assertTrue(result.ok)
        self.assertEqual([request.argv for request in runner.requests], [inventory_argv, absent_argv, read_argv])
        runner.assert_consumed()

    def test_running_reuse_refuses_exact_marker_with_wrong_or_missing_digest(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        absent_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_ABSENT_SCRIPT,
        )
        read_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_READ_SCRIPT,
        )
        marker_text = marker(
            provider="lima", handle=handle.value, lab_id=identity.lab_id,
            machine_id=identity.machine_id, role=identity.role,
        )

        for digest in (None, "f" * 64):
            with self.subTest(digest=digest):
                runner = FakeRunner(
                    [
                        completed(
                            inventory_argv,
                            stdout=lima_inventory(identity, "Running", digest=digest),
                        ),
                        completed(absent_argv, returncode=1),
                        completed(read_argv, stdout=marker_text),
                    ]
                )

                with self.assertRaisesRegex(RuntimeError, "identity digest"):
                    self.provider(runner).ensure(identity)

    def test_create_rediscovery_refuses_exact_marker_with_wrong_digest(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        runner = FakeRunner([])
        provider = self.provider(runner)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        digest = lima_module.guest_identity_sha256(identity)
        create_argv = (
            self.limactl, "start", "--yes", "--name", handle.value,
            "--param", f"cksIdentity={digest}", provider._templates["candidate"],
        )
        write_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_WRITE_SCRIPT,
        )
        runner.responses = [
            completed(inventory_argv),
            completed(create_argv),
            completed(write_argv),
            completed(
                inventory_argv,
                stdout=lima_inventory(identity, "Running", digest="f" * 64),
            ),
        ]

        with self.assertRaisesRegex(RuntimeError, "identity digest"):
            provider.create(identity)

        self.assertEqual(
            [request.argv for request in runner.requests],
            [inventory_argv, create_argv, write_argv, inventory_argv],
        )
        runner.assert_consumed()

    def test_ensure_restarts_stopped_machine_only_with_matching_identity_digest(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        restart_argv = (
            self.limactl, "shell", "--start", "--yes", handle.value, "--",
            "/usr/bin/sudo", "/bin/sh", "-c", lima_module._MARKER_READ_SCRIPT,
        )
        marker_text = marker(
            provider="lima", handle=handle.value, lab_id=identity.lab_id,
            machine_id=identity.machine_id, role=identity.role,
        )
        inventory = json.dumps(
            {
                "name": handle.value,
                "status": "Stopped",
                "param": {"cksIdentity": lima_module.guest_identity_sha256(identity)},
            }
        )
        runner = FakeRunner(
            [
                completed(inventory_argv, stdout=inventory),
                completed(restart_argv, stdout=marker_text),
                completed(
                    inventory_argv,
                    stdout=json.dumps(
                        {
                            "name": handle.value,
                            "status": "Running",
                            "param": {
                                "cksIdentity": lima_module.guest_identity_sha256(identity)
                            },
                        }
                    ),
                ),
            ]
        )

        result = self.provider(runner).ensure(identity)

        self.assertTrue(result.ok)
        self.assertEqual(
            [request.argv for request in runner.requests],
            [inventory_argv, restart_argv, inventory_argv],
        )
        runner.assert_consumed()

        forged = json.dumps(
            {"name": handle.value, "status": "Stopped", "param": {"cksIdentity": "0" * 64}}
        )
        refused = FakeRunner([completed(inventory_argv, stdout=forged)])
        with self.assertRaisesRegex(RuntimeError, "identity digest"):
            self.provider(refused).ensure(identity)
        self.assertEqual([request.argv for request in refused.requests], [inventory_argv])

    def test_cleanup_ownership_proof_requires_digest_and_status_appropriate_marker(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        digest = lima_module.guest_identity_sha256(identity)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        absent_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_ABSENT_SCRIPT,
        )
        read_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_READ_SCRIPT,
        )
        marker_text = marker(
            provider="lima", handle=handle.value, lab_id=identity.lab_id,
            machine_id=identity.machine_id, role=identity.role,
        )

        running = json.dumps(
            {"name": handle.value, "status": "Running", "param": {"cksIdentity": digest}}
        )
        runner = FakeRunner(
            [completed(inventory_argv, stdout=running), completed(absent_argv, returncode=1),
             completed(read_argv, stdout=marker_text)]
        )
        self.assertTrue(
            self.provider(runner).prove_ownership(
                identity, mode=OwnershipProofMode.ORDINARY
            )
        )
        runner.assert_consumed()

        markerless = FakeRunner(
            [completed(inventory_argv, stdout=running), completed(absent_argv)]
        )
        self.assertFalse(
            self.provider(markerless).prove_ownership(
                identity, mode=OwnershipProofMode.ORDINARY
            )
        )
        markerless.assert_consumed()

        break_glass = FakeRunner(
            [completed(inventory_argv, stdout=running), completed(absent_argv)]
        )
        self.assertTrue(
            self.provider(break_glass).prove_ownership(
                identity, mode=OwnershipProofMode.BREAK_GLASS
            )
        )
        break_glass.assert_consumed()

        stopped = json.dumps(
            {"name": handle.value, "status": "Stopped", "param": {"cksIdentity": digest}}
        )
        stopped_runner = FakeRunner([completed(inventory_argv, stdout=stopped)])
        self.assertTrue(
            self.provider(stopped_runner).prove_ownership(
                identity, mode=OwnershipProofMode.ORDINARY
            )
        )
        stopped_runner.assert_consumed()

        collision = json.dumps(
            {"name": handle.value, "status": "Stopped", "param": {"cksIdentity": "0" * 64}}
        )
        collision_runner = FakeRunner([completed(inventory_argv, stdout=collision)])
        self.assertFalse(
            self.provider(collision_runner).prove_ownership(
                identity, mode=OwnershipProofMode.BREAK_GLASS
            )
        )
        collision_runner.assert_consumed()

    def test_marker_write_failure_is_cleanup_eligible_only_through_break_glass(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        provider = self.provider(FakeRunner([]))
        digest = lima_module.guest_identity_sha256(identity)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        create_argv = (
            self.limactl, "start", "--yes", "--name", handle.value,
            "--param", f"cksIdentity={digest}", provider._templates["candidate"],
        )
        write_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_WRITE_SCRIPT,
        )
        provider._runner.responses = [
            completed(inventory_argv), completed(create_argv),
            completed(write_argv, returncode=1, stderr="marker write failed"),
        ]
        self.assertFalse(provider.create(identity).ok)
        provider._runner.assert_consumed()

        present = json.dumps(
            {"name": handle.value, "status": "Running", "param": {"cksIdentity": digest}}
        )
        absent_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_ABSENT_SCRIPT,
        )
        ordinary = FakeRunner([completed(inventory_argv, stdout=present), completed(absent_argv)])
        self.assertFalse(
            self.provider(ordinary).prove_ownership(
                identity, mode=OwnershipProofMode.ORDINARY
            )
        )
        break_glass = FakeRunner([completed(inventory_argv, stdout=present), completed(absent_argv)])
        self.assertTrue(
            self.provider(break_glass).prove_ownership(
                identity, mode=OwnershipProofMode.BREAK_GLASS
            )
        )

    def test_running_cleanup_collision_or_present_marker_mismatch_is_never_owned(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        absent_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_ABSENT_SCRIPT,
        )
        read_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_READ_SCRIPT,
        )
        matching_digest = json.dumps(
            {"name": handle.value, "status": "Running", "param": {
                "cksIdentity": lima_module.guest_identity_sha256(identity)}}
        )
        mismatch = FakeRunner(
            [completed(inventory_argv, stdout=matching_digest),
             completed(absent_argv, returncode=1),
             completed(read_argv, stdout=marker(provider="lima", handle=handle.value))]
        )
        self.assertFalse(
            self.provider(mismatch).prove_ownership(
                identity, mode=OwnershipProofMode.BREAK_GLASS
            )
        )
        mismatch.assert_consumed()

        wrong_digest = json.dumps(
            {"name": handle.value, "status": "Running", "param": {"cksIdentity": "f" * 64}}
        )
        collision = FakeRunner([completed(inventory_argv, stdout=wrong_digest)])
        self.assertFalse(
            self.provider(collision).prove_ownership(
                identity, mode=OwnershipProofMode.BREAK_GLASS
            )
        )
        collision.assert_consumed()

    def test_stopped_restart_failure_or_guest_mismatch_restores_stopped_state(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        restart_argv = (
            self.limactl, "shell", "--start", "--yes", handle.value, "--",
            "/usr/bin/sudo", "/bin/sh", "-c", lima_module._MARKER_READ_SCRIPT,
        )
        stop_argv = (self.limactl, "stop", "--force", handle.value)
        inventory = json.dumps(
            {
                "name": handle.value,
                "status": "Stopped",
                "param": {"cksIdentity": lima_module.guest_identity_sha256(identity)},
            }
        )
        running_inventory = json.dumps(
            {
                "name": handle.value,
                "status": "Running",
                "param": {"cksIdentity": lima_module.guest_identity_sha256(identity)},
            }
        )
        transport_failure = FakeRunner(
            [
                completed(inventory_argv, stdout=inventory),
                completed(restart_argv, returncode=1, stderr="boot transport failed"),
                completed(inventory_argv, stdout=running_inventory),
                completed(stop_argv),
                completed(inventory_argv, stdout=inventory),
            ]
        )

        result = self.provider(transport_failure).ensure(identity)

        self.assertFalse(result.ok)
        self.assertIn("restart rollback", result.stderr)
        self.assertEqual(
            [request.argv for request in transport_failure.requests],
            [inventory_argv, restart_argv, inventory_argv, stop_argv, inventory_argv],
        )

        mismatch = FakeRunner(
            [
                completed(inventory_argv, stdout=inventory),
                completed(restart_argv, stdout=marker(provider="lima", handle=handle.value)),
                completed(inventory_argv, stdout=running_inventory),
                completed(stop_argv),
                completed(inventory_argv, stdout=inventory),
            ]
        )
        with self.assertRaisesRegex(RuntimeError, "identity does not match"):
            self.provider(mismatch).ensure(identity)
        self.assertEqual(
            [request.argv for request in mismatch.requests],
            [inventory_argv, restart_argv, inventory_argv, stop_argv, inventory_argv],
        )

    def test_stopped_restart_rollback_never_stops_a_same_name_replacement(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        digest = lima_module.guest_identity_sha256(identity)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        restart_argv = (
            self.limactl, "shell", "--start", "--yes", handle.value, "--",
            "/usr/bin/sudo", "/bin/sh", "-c", lima_module._MARKER_READ_SCRIPT,
        )
        owned = lima_inventory(identity, "Stopped", digest=digest)
        replacement = lima_inventory(
            identity, "Running", digest=digest, generation="replacement"
        )
        runner = FakeRunner(
            [
                completed(inventory_argv, stdout=owned),
                completed(restart_argv, returncode=1, stderr="boot transport failed"),
                completed(inventory_argv, stdout=replacement),
            ]
        )

        result = self.provider(runner).ensure(identity)

        self.assertFalse(result.ok)
        self.assertIn("identity changed", result.stderr)
        self.assertEqual(
            [request.argv for request in runner.requests],
            [inventory_argv, restart_argv, inventory_argv],
        )
        runner.assert_consumed()

    def test_ensure_refuses_unknown_status_and_marker_mismatch(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        unknown = FakeRunner(
            [completed(inventory_argv, stdout=json.dumps({"name": handle.value, "status": "Broken"}))]
        )
        with self.assertRaisesRegex(RuntimeError, "unknown state"):
            self.provider(unknown).ensure(identity)
        self.assertEqual(len(unknown.requests), 1)

        absent_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_ABSENT_SCRIPT,
        )
        read_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_READ_SCRIPT,
        )
        mismatch = FakeRunner(
            [
                completed(
                    inventory_argv,
                    stdout=json.dumps(
                        {
                            "name": handle.value,
                            "status": "Running",
                            "param": {
                                "cksIdentity": lima_module.guest_identity_sha256(identity)
                            },
                        }
                    ),
                ),
                completed(absent_argv, returncode=1),
                completed(read_argv, stdout=marker(provider="lima", handle=handle.value)),
            ]
        )
        with self.assertRaisesRegex(RuntimeError, "identity does not match"):
            self.provider(mismatch).ensure(identity)
        self.assertEqual([request.argv for request in mismatch.requests], [inventory_argv, absent_argv, read_argv])

    def test_exact_guest_transport_uses_argv_and_bounded_stdin(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-control-plane")
        argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "--",
            "/usr/bin/env", "STATIC=value", "/bin/true",
        )
        runner = FakeRunner([completed(argv)])
        provider = self.provider(runner)

        result = provider.execute(
            handle,
            ("/usr/bin/env", "STATIC=value", "/bin/true"),
            stdin=b"trusted payload\n",
            as_root=True,
            timeout_seconds=17,
            output_limit=2048,
            secrets=("ephemeral-join-token",),
        )

        self.assertTrue(result.ok)
        request = runner.requests[0]
        self.assertEqual(request.argv, argv)
        self.assertEqual(request.stdin, b"trusted payload\n")
        self.assertEqual(request.timeout_seconds, 17)
        self.assertEqual(request.output_limit, 2048)
        self.assertEqual(request.secrets, ("ephemeral-join-token",))
        self.assertNotIn("-c", request.argv)
        runner.assert_consumed()

    def test_guest_transport_rejects_shell_source_and_unsafe_inputs_without_execution(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-control-plane")
        provider = self.provider(FakeRunner([]))
        for argv in (
            ("relative-command",),
            ("/bin/sh", "-c", "learner supplied"),
            ("/bin/bash", "--command", "learner supplied"),
            ("/usr/bin/env", "bad\0value"),
        ):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                provider.execute(handle, argv)
        with self.assertRaises(ValueError):
            provider.execute(handle, ("/bin/true",), stdin=b"x" * (8 * 1024 * 1024 + 1))
        self.assertEqual(provider._runner.requests, [])

    def test_root_file_install_streams_content_to_static_script(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-worker1")
        argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._ROOT_FILE_INSTALL_SCRIPT, "cks-install", "/var/lib/cks-simulator/provision/common.sh", "0700",
        )
        runner = FakeRunner([completed(argv)])
        payload = b"#!/bin/sh\nset -eu\n"

        result = self.provider(runner).install_root_file(
            handle, "/var/lib/cks-simulator/provision/common.sh", payload, mode=0o700
        )

        self.assertTrue(result.ok)
        self.assertEqual(runner.requests[0].stdin, payload)
        self.assertNotIn("/var/lib/cks-simulator/provision/common.sh", lima_module._ROOT_FILE_INSTALL_SCRIPT)
        runner.assert_consumed()

    def test_root_file_install_rejects_unsafe_path_mode_and_content(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-worker1")
        provider = self.provider(FakeRunner([]))
        cases = (
            ("relative.sh", b"ok", 0o700),
            ("/var/lib/../etc/unsafe", b"ok", 0o600),
            ("/", b"ok", 0o600),
            ("/var/lib/cks/file", b"ok", 0o777),
            ("/var/lib/cks/file", b"ok", 0o622),
        )
        for destination, content, mode in cases:
            with self.subTest(destination=destination, mode=mode), self.assertRaises(ValueError):
                provider.install_root_file(handle, destination, content, mode=mode)
        with self.assertRaises(ValueError):
            provider.install_root_file(handle, "/var/lib/cks/file", "not-bytes")  # type: ignore[arg-type]
        self.assertEqual(provider._runner.requests, [])

    def test_machine_observation_is_validated_and_normalized(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-worker2")
        argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._OBSERVATION_SCRIPT,
        )
        runner = FakeRunner(
            [completed(argv, stdout="192.168.5.23\t52:54:00:AA:bb:0C\t01234567-89AB-CDEF-8000-000000000099\n")]
        )

        observation = self.provider(runner).observe_machine(handle)

        self.assertEqual(observation.ipv4, "192.168.5.23")
        self.assertEqual(observation.mac, "52:54:00:aa:bb:0c")
        self.assertEqual(observation.product_uuid, "01234567-89ab-cdef-8000-000000000099")
        runner.assert_consumed()

    def test_machine_observation_fails_closed_on_transport_or_malformed_output(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-worker2")
        argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._OBSERVATION_SCRIPT,
        )
        for response in (
            completed(argv, returncode=1, stderr="ssh failed"),
            completed(argv, stdout="127.0.0.1\t52:54:00:aa:bb:cc\t01234567-89ab-cdef-8000-000000000099\n"),
            completed(argv, stdout="192.168.5.23\tinvalid\t01234567-89ab-cdef-8000-000000000099\n"),
            completed(argv, stdout="too\tfew\n"),
        ):
            with self.subTest(response=response):
                runner = FakeRunner([response])
                with self.assertRaises(RuntimeError):
                    self.provider(runner).observe_machine(handle)
                runner.assert_consumed()

    def test_production_templates_preserve_the_hardened_arm64_topology(self) -> None:
        expected_resources = {
            "candidate": (2, "2GiB", "30GiB"),
            "control-plane": (4, "4GiB", "50GiB"),
            "worker1": (3, "2GiB", "40GiB"),
            "worker2": (3, "2GiB", "40GiB"),
        }
        production = Path(__file__).resolve().parents[1] / "infra" / "lima"
        digest = "sha256:cafa1a965b591b7c4184b484ffd8e625981a79d48f9b4ae8a4adf7b4c5ade927"
        for role, (cpus, memory, disk) in expected_resources.items():
            with self.subTest(role=role):
                text = (production / f"{role}.yaml").read_text(encoding="utf-8")
                self.assertIn('minimumLimaVersion: "2.1.4"', text)
                self.assertIn("vmType: vz", text)
                self.assertIn("arch: aarch64", text)
                self.assertIn(digest, text)
                self.assertRegex(text, rf"(?m)^cpus: {cpus}$")
                self.assertIn(f'memory: "{memory}"', text)
                self.assertIn(f'disk: "{disk}"', text)
                self.assertRegex(text, r"(?m)^mounts: \[\]$")
                self.assertRegex(text, r"(?m)^portForwards: \[\]$")
                self.assertIn("  - lima: user-v2", text)
                self.assertIn("  system: false", text)
                self.assertIn("  user: false", text)
                self.assertNotIn("{{.Home}}", text)
                self.assertNotIn("location: /", text)
                self.assertEqual(len(re.findall(r"(?m)^mounts:", text)), 1)

    def test_guest_marker_absence_is_positive_and_uses_exact_handle(self) -> None:
        handle = ProviderHandle("lima", "lab-one-candidate")
        absent_argv = (
            self.limactl,
            "shell",
            "lab-one-candidate",
            "--",
            "/usr/bin/sudo",
            "/bin/sh",
            "-c",
            lima_module._MARKER_ABSENT_SCRIPT,
        )
        runner = FakeRunner([completed(absent_argv)])

        self.assertIsNone(self.provider(runner).read_guest_identity(handle))
        runner.assert_consumed()

    def test_guest_marker_parses_exact_identity_and_mismatch_or_error_fails_closed(self) -> None:
        handle = ProviderHandle("lima", "lab-one-candidate")
        absent_argv = (
            self.limactl,
            "shell",
            "lab-one-candidate",
            "--",
            "/usr/bin/sudo",
            "/bin/sh",
            "-c",
            lima_module._MARKER_ABSENT_SCRIPT,
        )
        read_argv = (
            self.limactl,
            "shell",
            "lab-one-candidate",
            "--",
            "/usr/bin/sudo",
            "/bin/sh",
            "-c",
            lima_module._MARKER_READ_SCRIPT,
        )
        lab_id = str(uuid.uuid4())
        machine_id = str(uuid.uuid4())
        good_runner = FakeRunner(
            [
                completed(absent_argv, returncode=1),
                completed(
                    read_argv,
                    stdout=marker(
                        provider="lima",
                        handle=handle.value,
                        lab_id=lab_id,
                        machine_id=machine_id,
                    ),
                ),
            ]
        )

        observed = self.provider(good_runner).read_guest_identity(handle)

        self.assertEqual(
            observed,
            GuestIdentity(lab_id, machine_id, "candidate", handle),
        )
        good_runner.assert_consumed()

        failures = (
            [completed(absent_argv, returncode=2, stderr="permission denied")],
            [
                completed(absent_argv, returncode=1),
                completed(read_argv, returncode=1, stderr="transport failed"),
            ],
            [
                completed(absent_argv, returncode=1),
                completed(read_argv, stdout="not-json"),
            ],
            [
                completed(absent_argv, returncode=1),
                completed(
                    read_argv,
                    stdout=marker(provider="lima", handle="lab-one-worker1"),
                ),
            ],
        )
        for responses in failures:
            with self.subTest(responses=responses):
                runner = FakeRunner(responses)
                with self.assertRaises(RuntimeError):
                    self.provider(runner).read_guest_identity(handle)
                runner.assert_consumed()

    def test_template_option_injection_and_non_regular_paths_are_rejected(self) -> None:
        target = self.root / "target.yaml"
        target.write_text("role: target\n", encoding="utf-8")
        symlink = self.root / "linked.yaml"
        symlink.symlink_to(target)
        for path in ("--list-drivers", str(self.root / "missing.yaml"), str(symlink)):
            with self.subTest(path=path), self.assertRaises(ValueError):
                LimaProvider(
                    FakeRunner([]), templates={"candidate": path}, state_dir=self.root,
                    command=(self.limactl,)
                )

    def test_lima_templates_are_pinned_to_anonymous_verified_descriptors(self) -> None:
        provider = self.provider(FakeRunner([]))
        source = Path(self.templates["candidate"])
        pinned = provider._template_inputs["candidate"]
        original = source.read_bytes()
        original_digest = hashlib.sha256(original).hexdigest()

        source.write_text("attacker: replaced\n", encoding="utf-8")

        self.assertEqual(pinned.sha256, original_digest)
        self.assertEqual(os.pread(pinned.descriptor, pinned.size, 0), original)
        self.assertEqual(os.fstat(pinned.descriptor).st_mode & 0o777, 0o400)
        self.assertEqual(list((self.root / "provider-inputs").iterdir()), [])

    def test_lima_command_must_be_a_trusted_absolute_executable(self) -> None:
        with self.assertRaises(ValueError):
            LimaProvider(
                FakeRunner([]), templates=self.templates, state_dir=self.root,
                command=("limactl",)
            )

        non_executable = self.root / "not-executable"
        non_executable.write_text("placeholder\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            LimaProvider(
                FakeRunner([]),
                templates=self.templates,
                state_dir=self.root,
                command=(str(non_executable),),
            )

    def test_lima_exposes_no_public_delete_and_internal_transport_is_exact(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        digest = lima_module.guest_identity_sha256(identity)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        stop_argv = (self.limactl, "stop", "--force", handle.value)
        delete_argv = (self.limactl, "delete", "--force", handle.value)
        stopped = lima_inventory(identity, "Stopped", digest=digest)
        runner = FakeRunner(
            [
                completed(inventory_argv, stdout=stopped),
                completed(inventory_argv, stdout=stopped),
                completed(stop_argv),
                completed(inventory_argv, stdout=stopped),
                completed(inventory_argv, stdout=stopped),
                completed(delete_argv),
            ]
        )
        provider = self.provider(runner)

        self.assertFalse(hasattr(provider, "destroy"))
        self.assertFalse(hasattr(provider, "break_glass_destroy"))
        self.assertTrue(
            provider.prove_ownership(identity, mode=OwnershipProofMode.ORDINARY)
        )
        self.assertTrue(provider._delete_exact(handle).ok)
        self.assertEqual(
            [request.argv for request in runner.requests],
            [
                inventory_argv,
                inventory_argv,
                stop_argv,
                inventory_argv,
                inventory_argv,
                delete_argv,
            ],
        )
        self.assertNotIn(f"{handle.value}*", delete_argv)
        runner.assert_consumed()

    def test_failed_stop_never_deletes_the_exact_name(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        digest = lima_module.guest_identity_sha256(identity)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        stop_argv = (self.limactl, "stop", "--force", handle.value)
        stopped = lima_inventory(identity, "Stopped", digest=digest)
        runner = FakeRunner(
            [
                completed(inventory_argv, stdout=stopped),
                completed(inventory_argv, stdout=stopped),
                completed(stop_argv, returncode=1, stderr="stop failed"),
            ]
        )
        provider = self.provider(runner)

        self.assertTrue(
            provider.prove_ownership(identity, mode=OwnershipProofMode.ORDINARY)
        )
        result = provider._delete_exact(handle)

        self.assertFalse(result.ok)
        self.assertIn("stop failed", result.stderr)
        self.assertEqual(
            [request.argv for request in runner.requests],
            [inventory_argv, inventory_argv, stop_argv],
        )
        runner.assert_consumed()

    def test_replacement_between_stop_and_delete_is_never_deleted(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        digest = lima_module.guest_identity_sha256(identity)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        stop_argv = (self.limactl, "stop", "--force", handle.value)
        owned = lima_inventory(identity, "Stopped", digest=digest)
        replacement = lima_inventory(
            identity, "Stopped", digest=digest, generation="replacement"
        )
        runner = FakeRunner(
            [
                completed(inventory_argv, stdout=owned),
                completed(inventory_argv, stdout=owned),
                completed(stop_argv),
                completed(inventory_argv, stdout=owned),
                completed(inventory_argv, stdout=replacement),
            ]
        )
        provider = self.provider(runner)

        self.assertTrue(
            provider.prove_ownership(identity, mode=OwnershipProofMode.ORDINARY)
        )
        with self.assertRaisesRegex(RuntimeError, "identity changed"):
            provider._delete_exact(handle)

        self.assertEqual(
            [request.argv for request in runner.requests],
            [inventory_argv, inventory_argv, stop_argv, inventory_argv, inventory_argv],
        )
        runner.assert_consumed()


    def test_execute_verified_holds_exact_identity_proof_through_dispatch(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        digest = lima_module.guest_identity_sha256(identity)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        absent_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_ABSENT_SCRIPT,
        )
        read_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "/bin/sh", "-c",
            lima_module._MARKER_READ_SCRIPT,
        )
        command_argv = (
            self.limactl, "shell", handle.value, "--", "/usr/bin/sudo", "--",
            "/usr/bin/true",
        )
        marker_text = marker(
            provider="lima", handle=handle.value, lab_id=identity.lab_id,
            machine_id=identity.machine_id, role=identity.role,
        )
        runner = FakeRunner(
            [
                completed(
                    inventory_argv,
                    stdout=lima_inventory(identity, "Running", digest=digest),
                ),
                completed(absent_argv, returncode=1),
                completed(read_argv, stdout=marker_text),
                completed(command_argv),
            ]
        )

        result = self.provider(runner).execute_verified(
            identity, ("/usr/bin/true",), as_root=True
        )

        self.assertTrue(result.ok)
        self.assertEqual(
            [request.argv for request in runner.requests],
            [inventory_argv, absent_argv, read_argv, command_argv],
        )
        runner.assert_consumed()

    def test_execute_verified_refuses_replaced_identity_before_command(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        inventory_argv = (self.limactl, "list", "--all-fields", "--json")
        runner = FakeRunner(
            [
                completed(
                    inventory_argv,
                    stdout=lima_inventory(identity, "Running", digest="f" * 64),
                )
            ]
        )

        with self.assertRaisesRegex(RuntimeError, "identity digest changed"):
            self.provider(runner).execute_verified(identity, ("/usr/bin/true",))

        self.assertEqual([request.argv for request in runner.requests], [inventory_argv])
        runner.assert_consumed()


class KindProviderTests(unittest.TestCase):
    def provider(self, runner: FakeRunner, state_dir: Path) -> KindProvider:
        config = state_dir / "cluster.yaml"
        config.write_text("kind: Cluster\n", encoding="utf-8")
        kind = state_dir / "kind"
        docker = state_dir / "docker"
        for executable in (kind, docker):
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
        return KindProvider(
            runner,
            config_path=str(config),
            state_dir=state_dir,
            image="kindest/node:v1.35.1",
            command=(str(kind.resolve()),),
            docker_command=(str(docker.resolve()),),
        )

    def test_discovery_uses_the_exact_cluster_name_and_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kind_bin = str((root / "kind").resolve())
            handle_name = "cks-0123456789abcdef-cluster"
            argv = (kind_bin, "get", "clusters")
            cases = (
                (completed(argv, stdout=f"{handle_name}-old\n{handle_name}\n"), Presence.PRESENT),
                (completed(argv, stdout=f"{handle_name}-old\n"), Presence.ABSENT),
                (completed(argv, returncode=1, stderr="docker unavailable"), Presence.UNKNOWN),
                (completed(argv, stdout="quick lab\n"), Presence.UNKNOWN),
            )
            for response, expected in cases:
                with self.subTest(expected=expected):
                    runner = FakeRunner([response])
                    expected_handle = ProviderHandle("kind", handle_name)
                    discovery = self.provider(runner, root).discover((expected_handle,))
                    self.assertIs(discovery.presence, expected)
                    if expected is Presence.PRESENT:
                        self.assertEqual(
                            discovery.handles,
                            (expected_handle,),
                        )
                    runner.assert_consumed()

    def test_kind_commands_must_be_trusted_absolute_executables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "cluster.yaml"
            config.write_text("kind: Cluster\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                KindProvider(
                    FakeRunner([]),
                    config_path=str(config),
                    state_dir=root,
                    command=("kind",),
                    docker_command=("docker",),
                )

    def test_kind_config_is_pinned_to_an_anonymous_verified_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = FakeRunner([])
            provider = self.provider(runner, root)
            source = root / "cluster.yaml"
            original = source.read_bytes()

            source.write_text("attacker: host-mount\n", encoding="utf-8")

            pinned = provider._config_input
            self.assertEqual(os.pread(pinned.descriptor, pinned.size, 0), original)
            self.assertEqual(os.fstat(pinned.descriptor).st_mode & 0o777, 0o400)
            self.assertEqual(list((root / "provider-inputs").iterdir()), [])

    def test_owned_create_and_internal_cleanup_keep_the_kind_argv_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            handle_name = "cks-0123456789abcdef-cluster"
            kind_bin = str((root / "kind").resolve())
            docker_bin = str((root / "docker").resolve())
            kubeconfig = root / f"kubeconfig-{handle_name}"
            kubeconfig.write_text("placeholder", encoding="utf-8")
            handle = ProviderHandle("kind", handle_name)
            identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "cluster", handle)
            config = root / "cluster.yaml"
            config.write_text("kind: Cluster\n", encoding="utf-8")
            runner = FakeRunner([])
            provider = self.provider(runner, root)
            create_argv = (
                kind_bin,
                "create",
                "cluster",
                "--name",
                handle_name,
                "--image",
                "kindest/node:v1.35.1",
                "--config",
                provider._config_path,
                "--kubeconfig",
                str(kubeconfig),
                "--wait",
                "5m",
            )
            write_argv = (
                docker_bin, "exec", "-i", f"{handle_name}-control-plane", "/bin/sh", "-c",
                kind_module._MARKER_WRITE_SCRIPT,
            )
            absent_argv = (
                docker_bin, "exec", f"{handle_name}-control-plane", "/bin/sh", "-c",
                kind_module._MARKER_ABSENT_SCRIPT,
            )
            read_argv = (
                docker_bin, "exec", f"{handle_name}-control-plane", "/bin/sh", "-c",
                kind_module._MARKER_READ_SCRIPT,
            )
            destroy_argv = (
                kind_bin,
                "delete",
                "cluster",
                "--name",
                handle_name,
                "--kubeconfig",
                str(kubeconfig),
            )
            marker_text = marker(
                provider="kind", handle=handle.value, lab_id=identity.lab_id,
                machine_id=identity.machine_id, role=identity.role,
            )
            runner.responses = [
                completed(create_argv), completed(write_argv),
                completed(absent_argv, returncode=1), completed(read_argv, stdout=marker_text),
                completed(destroy_argv),
            ]

            self.assertTrue(provider.create(identity).ok)
            self.assertTrue(provider._delete_exact(identity.handle).ok)

            self.assertEqual(
                [request.argv for request in runner.requests],
                [create_argv, write_argv, absent_argv, read_argv, destroy_argv],
            )
            self.assertEqual(runner.requests[1].stdin, kind_module.guest_identity_payload(identity))
            self.assertEqual(
                runner.requests[0].pass_fds,
                (provider._config_input.descriptor,),
            )
            runner.assert_consumed()

    def test_inexact_kind_inventory_and_raw_destroy_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = FakeRunner([])
            provider = self.provider(runner, Path(temporary))
            handle = ProviderHandle("kind", "cks-0123456789abcdef-cluster")
            for value in ((), (handle, handle), (ProviderHandle("lima", handle.value),)):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    provider.discover(value)
            self.assertFalse(hasattr(provider, "destroy"))
            self.assertFalse(hasattr(provider, "break_glass_destroy"))
            self.assertEqual(runner.requests, [])

    def test_kind_guest_marker_absence_is_positive_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            handle = ProviderHandle("kind", "cks-0123456789abcdef-cluster")
            absent_argv = (
                str((root / "docker").resolve()),
                "exec",
                f"{handle.value}-control-plane",
                "/bin/sh",
                "-c",
                kind_module._MARKER_ABSENT_SCRIPT,
            )
            runner = FakeRunner([completed(absent_argv)])
            observed = self.provider(runner, root).read_guest_identity(handle)

        self.assertIsNone(observed)
        runner.assert_consumed()

    def test_kind_cleanup_proof_requires_the_exact_root_marker_in_every_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            handle = ProviderHandle("kind", "cks-0123456789abcdef-cluster")
            identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "cluster", handle)
            kind_bin = str((root / "kind").resolve())
            docker_bin = str((root / "docker").resolve())
            inventory_argv = (kind_bin, "get", "clusters")
            absent_argv = (
                docker_bin, "exec", f"{handle.value}-control-plane", "/bin/sh", "-c",
                kind_module._MARKER_ABSENT_SCRIPT,
            )
            read_argv = (
                docker_bin, "exec", f"{handle.value}-control-plane", "/bin/sh", "-c",
                kind_module._MARKER_READ_SCRIPT,
            )
            marker_text = marker(
                provider="kind", handle=handle.value, lab_id=identity.lab_id,
                machine_id=identity.machine_id, role=identity.role,
            )
            ordinary = FakeRunner(
                [completed(inventory_argv, stdout=f"{handle.value}\n"),
                 completed(absent_argv, returncode=1), completed(read_argv, stdout=marker_text)]
            )
            self.assertTrue(
                self.provider(ordinary, root).prove_ownership(
                    identity, mode=OwnershipProofMode.ORDINARY
                )
            )
            ordinary.assert_consumed()

            markerless = FakeRunner(
                [completed(inventory_argv, stdout=f"{handle.value}\n"), completed(absent_argv)]
            )
            self.assertFalse(
                self.provider(markerless, root).prove_ownership(
                    identity, mode=OwnershipProofMode.BREAK_GLASS
                )
            )
            markerless.assert_consumed()

    def test_kind_guest_marker_mismatch_and_transport_error_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            handle = ProviderHandle("kind", "cks-0123456789abcdef-cluster")
            docker_bin = str((root / "docker").resolve())
            absent_argv = (
                docker_bin, "exec", f"{handle.value}-control-plane", "/bin/sh", "-c",
                kind_module._MARKER_ABSENT_SCRIPT,
            )
            read_argv = (
                docker_bin, "exec", f"{handle.value}-control-plane", "/bin/sh", "-c",
                kind_module._MARKER_READ_SCRIPT,
            )
            failures = (
                [completed(absent_argv, returncode=2, stderr="container missing")],
                [
                    completed(absent_argv, returncode=1),
                    completed(read_argv, returncode=1, stderr="transport failed"),
                ],
                [
                    completed(absent_argv, returncode=1),
                    completed(
                        read_argv,
                        stdout=marker(provider="kind", handle=f"{handle.value}-old"),
                    ),
                ],
            )
            for responses in failures:
                with self.subTest(responses=responses):
                    runner = FakeRunner(responses)
                    with self.assertRaises(RuntimeError):
                        self.provider(runner, root).read_guest_identity(handle)
                    runner.assert_consumed()


if __name__ == "__main__":
    unittest.main()
