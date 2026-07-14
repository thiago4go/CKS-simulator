from __future__ import annotations

import json
import hashlib
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Iterable, Optional

from cks_simulator.providers.base import (
    GuestIdentity,
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
        argv = (self.limactl, "list", "--json")
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
        self.assertEqual(runner.requests[0].output_limit, 1024 * 1024)
        runner.assert_consumed()

    def test_discovery_distinguishes_absent_unknown_and_malformed_output(self) -> None:
        argv = (self.limactl, "list", "--json")
        expected_handles = (ProviderHandle("lima", "cks-0123456789abcdef-candidate"),)
        cases = (
            (completed(argv, stdout='{"name":"other-lab-worker1"}\n'), Presence.ABSENT),
            (completed(argv, returncode=1, stderr="provider unavailable"), Presence.UNKNOWN),
            (completed(argv, stdout="not-json\n"), Presence.UNKNOWN),
            (completed(argv, stdout='{"status":"Running"}\n'), Presence.UNKNOWN),
            (completed(argv, stdout='{"name":"bad name"}\n'), Presence.UNKNOWN),
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

    def test_create_and_internal_cleanup_use_only_the_exact_recorded_handle(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        identity = GuestIdentity(LAB_ID, str(uuid.uuid4()), "candidate", handle)
        runner = FakeRunner([])
        provider = self.provider(runner)
        create_argv = (
            self.limactl,
            "start",
            "--yes",
            "--name",
            handle.value,
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
        stop_argv = (self.limactl, "stop", "--force", handle.value)
        destroy_argv = (self.limactl, "delete", "--force", handle.value)
        marker_text = marker(
            provider="lima", handle=handle.value, lab_id=identity.lab_id,
            machine_id=identity.machine_id, role=identity.role,
        )
        runner.responses = [
            completed(create_argv), completed(write_argv),
            completed(absent_argv, returncode=1), completed(read_argv, stdout=marker_text),
            completed(stop_argv), completed(destroy_argv),
        ]

        self.assertTrue(provider.create(identity).ok)
        self.assertTrue(provider._delete_exact(identity.handle).ok)

        self.assertEqual(
            [request.argv for request in runner.requests],
            [create_argv, write_argv, absent_argv, read_argv, stop_argv, destroy_argv],
        )
        self.assertEqual(runner.requests[1].stdin, lima_module.guest_identity_payload(identity))
        self.assertEqual(
            runner.requests[0].pass_fds,
            (provider._template_inputs["candidate"].descriptor,),
        )
        self.assertNotIn(f"{handle.value}*", destroy_argv)
        runner.assert_consumed()

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
        machine = ProviderMachine("candidate", str(uuid.uuid4()), handle)
        stop_argv = (self.limactl, "stop", "--force", handle.value)
        delete_argv = (self.limactl, "delete", "--force", handle.value)
        runner = FakeRunner([completed(stop_argv), completed(delete_argv)])
        provider = self.provider(runner)

        self.assertFalse(hasattr(provider, "destroy"))
        self.assertFalse(hasattr(provider, "break_glass_destroy"))
        self.assertTrue(provider._delete_exact(machine.handle).ok)
        self.assertEqual([request.argv for request in runner.requests], [stop_argv, delete_argv])

    def test_successful_delete_preserves_a_failed_stop_as_a_warning(self) -> None:
        handle = ProviderHandle("lima", "cks-0123456789abcdef-candidate")
        machine = ProviderMachine("candidate", str(uuid.uuid4()), handle)
        stop_argv = (self.limactl, "stop", "--force", handle.value)
        delete_argv = (self.limactl, "delete", "--force", handle.value)
        runner = FakeRunner(
            [
                completed(stop_argv, returncode=1, stderr="already stopped"),
                completed(delete_argv),
            ]
        )

        result = self.provider(runner)._delete_exact(machine.handle)

        self.assertTrue(result.ok)
        self.assertIn("already stopped", result.stderr)
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
