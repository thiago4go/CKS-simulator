from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cks_simulator.full import (
    FullTierError,
    build_lifecycle,
    ensure_provider_runtime,
    host_preflight,
    require_host_preflight,
)
from cks_simulator.lab import FullLabLifecycle
from cks_simulator.providers.base import ProcessRequest, ProcessResult
from cks_simulator.state import LabPhase, LabStateStore
from tests.test_lab import FakeProvider


ROOT = Path(__file__).resolve().parents[1]


class FakeRunner:
    def __init__(self, responses: list[ProcessResult]) -> None:
        self.responses = list(responses)
        self.requests: list[ProcessRequest] = []

    def run(self, request: ProcessRequest) -> ProcessResult:
        self.requests.append(request)
        if not self.responses:
            raise AssertionError(f"unexpected command: {request.argv!r}")
        value = self.responses.pop(0)
        if value.command != request.argv:
            raise AssertionError(f"expected {value.command!r}, observed {request.argv!r}")
        return value


def completed(command: tuple[str, ...], *, ok: bool = True, output: str = "") -> ProcessResult:
    return ProcessResult(
        command=command,
        returncode=0 if ok else 1,
        stdout=output if ok else "",
        stderr="" if ok else output,
    )


class FullTierCompositionTests(unittest.TestCase):
    def test_host_preflight_is_bounded_exact_and_non_mutating(self) -> None:
        root = Path(__file__).resolve().parents[1]
        lima = "/trusted/limactl"
        responses = [
            completed((lima, "--version"), output="limactl version 2.1.4\n"),
            *[
                completed((lima, "validate", str(root / "infra" / "lima" / f"{role}.yaml")))
                for role in ("candidate", "control-plane", "worker1", "worker2")
            ],
        ]
        runner = FakeRunner(responses)

        checks = host_preflight(
            root=root,
            runner=runner,
            lima_command=lima,
            system="Darwin",
            machine="arm64",
            cpu_count=18,
            memory_bytes=48 * 1024**3,
            disk_free_bytes=400 * 1024**3,
        )

        self.assertTrue(all(item.passed for item in checks))
        self.assertEqual(len(checks), 11)
        self.assertFalse((root / ".cks-state" / "full" / "preflight").exists())
        self.assertEqual(runner.responses, [])

    def test_host_preflight_reports_all_resource_and_version_failures(self) -> None:
        root = Path(__file__).resolve().parents[1]
        lima = "/trusted/limactl"
        responses = [
            completed((lima, "--version"), output="limactl version 2.0.0\n"),
            *[
                completed(
                    (lima, "validate", str(root / "infra" / "lima" / f"{role}.yaml")),
                    ok=role != "worker2",
                    output="invalid template",
                )
                for role in ("candidate", "control-plane", "worker1", "worker2")
            ],
        ]
        runner = FakeRunner(responses)

        with self.assertRaisesRegex(FullTierError, "host-os.*host-arch.*host-cpus"):
            require_host_preflight(
                root=root,
                runner=runner,
                lima_command=lima,
                system="Linux",
                machine="x86_64",
                cpu_count=4,
                memory_bytes=8 * 1024**3,
                disk_free_bytes=20 * 1024**3,
            )

    def test_replay_preflight_uses_recovery_disk_reserve(self) -> None:
        root = ROOT
        lima = "/trusted/limactl"
        runner = FakeRunner(
            [
                completed((lima, "--version"), output="limactl version 2.1.4\n"),
                *[
                    completed(
                        (lima, "validate", str(root / "infra" / "lima" / f"{role}.yaml"))
                    )
                    for role in ("candidate", "control-plane", "worker1", "worker2")
                ],
            ]
        )
        checks = host_preflight(
            root=root,
            runner=runner,
            lima_command=lima,
            system="Darwin",
            machine="arm64",
            cpu_count=18,
            memory_bytes=48 * 1024**3,
            disk_free_bytes=25 * 1024**3,
            require_creation_capacity=False,
        )
        disk = next(item for item in checks if item.name == "host-disk")
        self.assertTrue(disk.passed)
        self.assertIn("minimum 20 GiB", disk.detail)

    def test_provider_runtime_is_created_owner_only_and_refuses_wrong_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            runtime = ensure_provider_runtime(root)
            self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)
            self.assertEqual(runtime.stat().st_uid, os.getuid())

            runtime.chmod(0o755)
            with self.assertRaisesRegex(FullTierError, "owner-only"):
                ensure_provider_runtime(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            root.mkdir(mode=0o755)
            with self.assertRaisesRegex(FullTierError, "state root"):
                ensure_provider_runtime(root)

    def test_destroy_only_lifecycle_works_without_any_iac_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            state_root = temporary_root / "state"
            state_root.mkdir(mode=0o700)
            name = "destroy-only-lab"
            store = LabStateStore(state_root, namespace="full")
            provider = FakeProvider(store, name)
            FullLabLifecycle(
                store,
                provider,
                provisioning_root=ROOT / "infra" / "provision",
            ).provision(name)
            empty_checkout = temporary_root / "empty-checkout"
            empty_checkout.mkdir()
            self.assertEqual(list(empty_checkout.iterdir()), [])

            with patch("cks_simulator.full.LimaProvider", return_value=provider):
                lifecycle = build_lifecycle(
                    root=empty_checkout,
                    state_root=state_root,
                    runner=FakeRunner([]),
                    lima_command="/trusted/limactl",
                    destroy_only=True,
                )
                destroyed = lifecycle.destroy(name)
                repeated = lifecycle.destroy(name)

            self.assertIs(destroyed.phase, LabPhase.DESTROYED)
            self.assertEqual(repeated.journal, destroyed.journal)
            self.assertFalse(provider.identities)


if __name__ == "__main__":
    unittest.main()
