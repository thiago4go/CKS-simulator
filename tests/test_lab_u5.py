from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Optional, Sequence

from cks_simulator.lab import FullLabLifecycle, FullLabReconcileError
from cks_simulator.providers.base import GuestIdentity, ProcessResult, ProviderHandle
from cks_simulator.state import LabPhase, LabStateStore
from tests.test_lab import FakeProvider, result


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZha2VLZXlGb3JUZXN0c09ubHkxMjM0NTY candidate@cks-simulator\n"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZha2VIb3N0S2V5Rm9yVGVzdHMxMjM0NTY root@node\n"
CSR = "-----BEGIN CERTIFICATE REQUEST-----\nVEVTVA==\n-----END CERTIFICATE REQUEST-----\n"
CREDENTIALS = json.dumps(
    {
        "schema": 1,
        "cluster_name": "cks-simulator",
        "server": "https://control-plane:6443",
        "certificate_authority_data": "VEVTVA==",
        "client_certificate_data": "VEVTVA==",
    },
    separators=(",", ":"),
) + "\n"


class U5FakeProvider(FakeProvider):
    def __init__(self, store: LabStateStore, lab_name: str) -> None:
        super().__init__(store, lab_name)
        self.stopped: set[ProviderHandle] = set()

    def ensure(self, identity: GuestIdentity) -> ProcessResult:
        if identity.handle in self.stopped:
            self.calls.append(("restart", identity.role, identity.handle))
            self.stopped.remove(identity.handle)
        return super().ensure(identity)

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
        script = next((arg for arg in command if isinstance(arg, str) and arg.endswith(".sh")), "")
        if script.endswith("export-public-key.sh"):
            self.calls.append(("execute", handle, command, stdin, as_root, tuple(secrets), timeout_seconds))
            return result(stdout=PUBLIC_KEY)
        if script.endswith("export-csr.sh"):
            self.calls.append(("execute", handle, command, stdin, as_root, tuple(secrets), timeout_seconds))
            return result(stdout=CSR)
        if script.endswith("sign-csr.sh"):
            self.calls.append(("execute", handle, command, stdin, as_root, tuple(secrets), timeout_seconds))
            return result(stdout=CREDENTIALS)
        if command == ("/usr/bin/cat", "/etc/ssh/ssh_host_ed25519_key.pub"):
            self.calls.append(("execute", handle, command, stdin, as_root, tuple(secrets), timeout_seconds))
            return result(stdout=HOST_KEY)
        if "kubectl" in command and "can-i" in command:
            self.calls.append(("execute", handle, command, stdin, as_root, tuple(secrets), timeout_seconds))
            return result(stdout="yes\n")
        return super().execute(
            handle,
            argv,
            stdin=stdin,
            as_root=as_root,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
            secrets=secrets,
        )


class U5LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = LabStateStore(Path(self.temporary.name), namespace="full")
        self.name = "u5-lab"
        self.provider = U5FakeProvider(self.store, self.name)
        self.lifecycle = FullLabLifecycle(
            self.store,
            self.provider,
            provisioning_root=ROOT / "infra" / "provision",
            version_source_path=ROOT / "infra" / "versions.json",
            inventory_path=ROOT / "infra" / "inventory.json",
        )

    def test_full_u5_converges_tools_and_candidate_without_private_key_transit(self) -> None:
        state = self.lifecycle.provision(self.name)
        self.assertIs(state.phase, LabPhase.CANDIDATE_READY)
        self.assertEqual(state.journal[-1].phase, LabPhase.CANDIDATE_READY)
        calls = [call for call in self.provider.calls if call[0] == "execute"]
        scripts = [
            next((arg for arg in call[2] if isinstance(arg, str) and arg.endswith(".sh")), "")
            for call in calls
        ]
        for required in (
            "tools/install.sh",
            "tools/addons.sh",
            "tools/check.sh",
            "candidate/configure-workstation.sh",
            "candidate/configure-self-ssh.sh",
            "candidate/install-tools.sh",
            "candidate/install-desktop.sh",
            "candidate/install-ssh-access.sh",
            "candidate/sign-csr.sh",
            "candidate/install-kubeconfig.sh",
            "candidate/doctor.sh",
        ):
            self.assertTrue(any(value.endswith(required) for value in scripts), required)
        transit = b"\n".join(call[3] or b"" for call in calls)
        self.assertNotIn(b"PRIVATE KEY", transit)
        self.assertEqual(scripts[-1].endswith("candidate/doctor.sh"), True)
        stage_targets = {"health", "network", "apparmor-pod", "gvisor-pod", "falco", "ingress"}
        stage_checks = [
            (call[2][-1], call[6])
            for call in calls
            if "/opt/cks-simulator/provision/tools/check.sh" in call[2]
            and call[2][-1] in stage_targets
        ]
        self.assertEqual(
            stage_checks,
            [
                ("network", 1800),
                ("health", 3600),
                ("network", 1800),
                ("apparmor-pod", 1200),
                ("gvisor-pod", 1200),
                ("falco", 1200),
                ("ingress", 2700),
                ("health", 3600),
            ],
        )

    def test_replay_preserves_candidate_ready_journal(self) -> None:
        first = self.lifecycle.provision(self.name)
        machines = {item.role: item for item in first.inventory}
        self.provider.stopped.update(
            {machines["candidate"].handle, machines["control-plane"].handle}
        )
        self.provider.calls.clear()

        second = self.lifecycle.provision(self.name)

        self.assertEqual(second.journal, first.journal)
        self.assertEqual(self.provider.stopped, set())
        self.assertEqual(
            [call[1] for call in self.provider.calls if call[0] == "ensure"],
            ["candidate", "control-plane", "worker1", "worker2"],
        )
        self.assertEqual(
            [call[1] for call in self.provider.calls if call[0] == "restart"],
            ["candidate", "control-plane"],
        )
        replay_scripts = [
            next(
                (
                    arg
                    for arg in call[2]
                    if isinstance(arg, str) and arg.endswith(".sh")
                ),
                "",
            )
            for call in self.provider.calls
            if call[0] == "execute"
        ]
        for required in (
            "tools/check.sh",
            "candidate/configure-node.sh",
            "candidate/install-ssh-access.sh",
            "candidate/check-node.sh",
            "candidate/doctor.sh",
        ):
            self.assertTrue(any(item.endswith(required) for item in replay_scripts), required)

    def test_u5_failure_is_recoverable_and_reruns_candidate_doctor(self) -> None:
        self.provider.fail_scripts.add("candidate/doctor.sh")
        with self.assertRaisesRegex(FullLabReconcileError, "candidate workstation"):
            self.lifecycle.provision(self.name)
        self.assertIs(self.store.load(self.name).phase, LabPhase.DEGRADED)

        self.provider.fail_scripts.clear()
        self.provider.calls.clear()
        recovered = self.lifecycle.provision(self.name)

        self.assertIs(recovered.phase, LabPhase.CANDIDATE_READY)
        self.assertEqual(
            [entry.phase for entry in recovered.journal].count(LabPhase.DEGRADED),
            1,
        )
        self.assertTrue(
            any(
                call[0] == "execute"
                and any(
                    isinstance(arg, str) and arg.endswith("candidate/doctor.sh")
                    for arg in call[2]
                )
                for call in self.provider.calls
            )
        )

    def test_candidate_shell_requires_ready_phase_and_exact_guest_identity(self) -> None:
        with self.store.lock(self.name):
            self.store.claim(self.name, provider="lima")
        with self.assertRaises(FullLabReconcileError):
            self.lifecycle.verified_candidate_handle(self.name)
        state = self.lifecycle.provision(self.name)
        candidate = next(item for item in state.inventory if item.role == "candidate")
        self.assertEqual(
            self.lifecycle.verified_candidate_handle(self.name), candidate.handle
        )
        self.provider.identities[candidate.handle] = None
        with self.assertRaisesRegex(FullLabReconcileError, "guest identity"):
            self.lifecycle.verified_candidate_handle(self.name)


if __name__ == "__main__":
    unittest.main()
