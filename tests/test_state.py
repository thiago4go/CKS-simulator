from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys
import tempfile
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cks_simulator.providers.base import (
    Discovery,
    GuestIdentity,
    OwnershipProofMode,
    Presence,
    ProcessRequest,
    ProcessResult,
    ProviderHandle,
    ProviderMachine,
    SubprocessRunner,
    bounded_redacted,
    derive_provider_handle,
)
from cks_simulator.state import (
    InvalidTransitionError,
    LabLockedError,
    LabPhase,
    LabState,
    LabStateStore,
    MachineObservation,
    OwnershipError,
    StateExistsError,
    StateMissingError,
    StateValidationError,
    validate_identifier,
)


class IdentifierTests(unittest.TestCase):
    def test_accepts_canonical_identifiers(self) -> None:
        for value in ("lab", "cks-simulator", "worker-2", "a1"):
            with self.subTest(value=value):
                self.assertEqual(validate_identifier(value), value)

    def test_rejects_hostile_or_ambiguous_identifiers(self) -> None:
        hostile = (
            "",
            "-lab",
            "Lab",
            "../lab",
            "lab/name",
            "lab\\name",
            "lab\nname",
            "lab name",
            "lab;touch-pwned",
            ".",
            "a" * 64,
        )
        for value in hostile:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_identifier(value)

    def test_store_paths_cannot_escape_the_state_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = LabStateStore(Path(temporary), namespace="full")
            for hostile in ("../outside", "/tmp/outside", "--help", "a/b"):
                with self.subTest(value=hostile), self.assertRaises(ValueError):
                    store.state_path(hostile)


class RunnerTests(unittest.TestCase):
    def test_runner_uses_argv_without_a_shell(self) -> None:
        script = "import json,sys; print(json.dumps(sys.argv[1:])); print(sys.stdin.read())"
        arguments = ("; touch /tmp/pwned", "$(id)", "line\nbreak", "-leading")
        request = ProcessRequest(
            argv=(sys.executable, "-c", script, *arguments), stdin=b"input"
        )
        result = SubprocessRunner().run(request)

        self.assertTrue(result.ok)
        self.assertEqual(json.loads(result.stdout.splitlines()[0]), list(arguments))
        self.assertEqual(result.stdout.splitlines()[1], "input")

    def test_runner_passes_only_explicit_open_regular_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input"
            source.write_bytes(b"pinned-provider-input")
            descriptor = os.open(source, os.O_RDONLY)
            source.unlink()
            try:
                request = ProcessRequest.build(
                    (
                        sys.executable,
                        "-c",
                        "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())",
                        f"/dev/fd/{descriptor}",
                    ),
                    pass_fds=(descriptor,),
                )
                result = SubprocessRunner().run(request)
            finally:
                os.close(descriptor)

        self.assertTrue(result.ok, result.diagnostic())
        self.assertEqual(result.stdout.strip(), "pinned-provider-input")
        with self.assertRaises(ValueError):
            ProcessRequest.build((sys.executable, "-c", "pass"), pass_fds=(descriptor,))

    def test_runner_uses_minimal_environment_and_validated_overlay(self) -> None:
        script = "import json,os; print(json.dumps(dict(os.environ), sort_keys=True))"
        request = ProcessRequest.build(
            (sys.executable, "-c", script),
            environment={"HOME": "/safe/home", "LANG": "C.UTF-8"},
        )
        inherited = {
            "PATH": "/hostile/bin",
            "HOME": "/inherited/home",
            "DOCKER_HOST": "tcp://attacker:2375",
            "LIMA_HOME": "/attacker/lima",
            "PYTHONPATH": "/attacker/python",
        }
        with patch.dict(os.environ, inherited, clear=True):
            result = SubprocessRunner().run(request)

        environment = json.loads(result.stdout)
        self.assertEqual(environment["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertEqual(environment["HOME"], "/safe/home")
        self.assertEqual(environment["LANG"], "C.UTF-8")
        self.assertNotIn("DOCKER_HOST", environment)
        self.assertNotIn("LIMA_HOME", environment)
        self.assertNotIn("PYTHONPATH", environment)

    def test_runner_does_not_inherit_ambient_home_locale_or_tmpdir(self) -> None:
        script = "import json,os; print(json.dumps(dict(os.environ), sort_keys=True))"
        inherited = {
            "HOME": "/attacker/home",
            "TMPDIR": "/attacker/tmp",
            "LANG": "attacker_LOCALE",
            "LC_ALL": "attacker_LOCALE",
        }
        with patch.dict(os.environ, inherited, clear=True):
            result = SubprocessRunner().run(
                ProcessRequest.build((sys.executable, "-c", script))
            )

        environment = json.loads(result.stdout)
        self.assertEqual(environment["HOME"], pwd.getpwuid(os.getuid()).pw_dir)
        self.assertEqual(environment["TMPDIR"], "/tmp")
        self.assertEqual(environment["LANG"], "C")
        self.assertEqual(environment["LC_ALL"], "C")

    def test_runner_rejects_unallowlisted_or_unsafe_environment_overlays(self) -> None:
        for environment in (
            {"PATH": "/attacker"},
            {"PYTHONPATH": "/attacker"},
            {"HOME": "relative/home"},
            {"DOCKER_HOST": "tcp://attacker:2375"},
            {"LANG": "C\nEVIL=yes"},
        ):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                SubprocessRunner().run(
                    ProcessRequest.build((sys.executable, "-c", "pass"), environment=environment)
                )

    def test_runner_bounds_and_redacts_output_and_timeout_diagnostics(self) -> None:
        secret = "super-secret-token"
        script = (
            "import sys; "
            "sys.stdout.write(sys.argv[1] + '\\n' + 'x' * 1000000); "
            "sys.stderr.write('password: hunter2\\n-----BEGIN PRIVATE KEY-----\\nsecret\\n'"
            "+ '-----END PRIVATE KEY-----\\n\\x1b[31m'); sys.exit(2)"
        )
        request = ProcessRequest(
            argv=(sys.executable, "-c", script, secret),
            secrets=(secret,),
            output_limit=96,
        )
        result = SubprocessRunner().run(request)

        diagnostic = result.diagnostic()
        self.assertNotIn(secret, diagnostic)
        self.assertNotIn("hunter2", diagnostic)
        self.assertNotIn("BEGIN PRIVATE KEY", diagnostic)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 96)
        self.assertLessEqual(len(result.stderr.encode("utf-8")), 96)
        self.assertTrue(all(secret not in argument for argument in result.command))
        self.assertNotIn("\x1b", result.stderr)

    def test_bounded_redaction_is_utf8_byte_bounded(self) -> None:
        value = "token: secret\n" + "🛡️" * 100
        rendered = bounded_redacted(value, secrets=("secret",), limit=31)
        self.assertLessEqual(len(rendered.encode("utf-8")), 31)
        self.assertNotIn("secret", rendered)

    def test_timeout_is_a_typed_bounded_failure(self) -> None:
        request = ProcessRequest(
            argv=(
                sys.executable,
                "-c",
                "import sys,time; print('x'*1000, flush=True); "
                "print('token: secret', file=sys.stderr, flush=True); time.sleep(10)",
            ),
            output_limit=64,
            timeout_seconds=0.1,
        )
        result = SubprocessRunner().run(request)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)
        self.assertEqual(result.returncode, 124)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 64)
        self.assertNotIn("secret", result.stderr)


class StateKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = LabStateStore(self.root, namespace="full")

    def claim_with_inventory(self, lab_name: str = "lab-one"):
        state = self.store.claim(lab_name, provider="lima")
        machines = tuple(
            ProviderMachine(
                role=role,
                machine_id=str(uuid.uuid4()),
                handle=derive_provider_handle("lima", state.identity.lab_id, role),
            )
            for role in ("candidate", "control-plane", "worker1", "worker2")
        )
        return self.store.declare_inventory(lab_name, state.identity.lab_id, machines)

    @staticmethod
    def observations_for(state, *, bundle_sha256: str = "a" * 64):
        return tuple(
            MachineObservation(
                role=machine.role,
                machine_id=machine.machine_id,
                handle=machine.handle,
                ipv4=f"192.0.2.{10 + index}",
                mac_address=f"AA-BB-CC-DD-EE-{index + 1:02X}",
                product_uuid=str(uuid.UUID(int=index + 1)).upper(),
                provisioning_bundle_sha256=bundle_sha256,
                provisioning_spec_sha256="b" * 64,
            )
            for index, machine in enumerate(state.inventory)
        )

    @staticmethod
    def discovery_and_guests(state):
        handles = tuple(machine.handle for machine in state.inventory)
        guests = tuple(
            GuestIdentity(
                lab_id=state.identity.lab_id,
                machine_id=machine.machine_id,
                role=machine.role,
                handle=machine.handle,
            )
            for machine in state.inventory
        )
        return Discovery(Presence.PRESENT, handles), guests

    def test_claim_writes_immutable_identity_before_inventory(self) -> None:
        state = self.store.claim("lab-one", provider="lima")
        payload = json.loads(self.store.state_path("lab-one").read_text(encoding="utf-8"))

        self.assertEqual(payload["identity"]["lab_id"], state.identity.lab_id)
        self.assertEqual(payload["identity"]["lab_name"], "lab-one")
        self.assertEqual(payload["inventory"], [])
        self.assertEqual(payload["journal"][0]["phase"], "declared")
        self.assertEqual(self.store.state_path("lab-one").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(StateExistsError):
            self.store.claim("lab-one", provider="lima")

    def test_atomic_replace_keeps_previous_state_when_replace_fails(self) -> None:
        state = self.store.claim("lab-one", provider="lima")
        before = self.store.state_path("lab-one").read_bytes()
        machine = ProviderMachine(
            role="candidate",
            machine_id=str(uuid.uuid4()),
            handle=derive_provider_handle("lima", state.identity.lab_id, "candidate"),
        )
        with patch("cks_simulator.state.os.replace", side_effect=OSError("disk fault")):
            with self.assertRaises(OSError):
                self.store.declare_inventory("lab-one", state.identity.lab_id, (machine,))

        self.assertEqual(self.store.state_path("lab-one").read_bytes(), before)
        self.assertEqual(list(self.store.state_path("lab-one").parent.glob(".state.json.*")), [])

    def test_create_commit_stays_on_open_descriptor_when_lab_path_is_swapped(self) -> None:
        self.store.claim("lab-two", provider="lima")
        other_directory = self.store.state_path("lab-two").parent
        other_before = self.store.state_path("lab-two").read_bytes()
        lab_directory = self.store.state_path("lab-one").parent
        detached_directory = self.store.namespace_path / "lab-one-detached"
        real_link = os.link
        raced = False

        def racing_link(source, destination, **kwargs):
            nonlocal raced
            if destination == "state.json" and not raced:
                raced = True
                lab_directory.rename(detached_directory)
                lab_directory.symlink_to(other_directory, target_is_directory=True)
            return real_link(source, destination, **kwargs)

        with patch("cks_simulator.state.os.link", side_effect=racing_link):
            with self.assertRaises(StateValidationError):
                self.store.claim("lab-one", provider="lima")

        self.assertTrue(raced)
        self.assertEqual(self.store.state_path("lab-two").read_bytes(), other_before)
        self.assertTrue((detached_directory / "state.json").is_file())
        self.assertEqual(list(detached_directory.glob(".state.json.*")), [])

    def test_replace_commit_cannot_write_to_swapped_other_lab(self) -> None:
        state = self.claim_with_inventory("lab-one")
        state = self.store.record_machine_observations(
            "lab-one", state.identity.lab_id, self.observations_for(state)
        )
        self.store.claim("lab-two", provider="lima")
        other_directory = self.store.state_path("lab-two").parent
        other_before = self.store.state_path("lab-two").read_bytes()
        lab_directory = self.store.state_path("lab-one").parent
        detached_directory = self.store.namespace_path / "lab-one-detached"
        real_replace = os.replace
        raced = False

        def racing_replace(source, destination, **kwargs):
            nonlocal raced
            if destination == "state.json" and not raced:
                raced = True
                lab_directory.rename(detached_directory)
                lab_directory.symlink_to(other_directory, target_is_directory=True)
            return real_replace(source, destination, **kwargs)

        with patch("cks_simulator.state.os.replace", side_effect=racing_replace):
            with self.assertRaises(StateValidationError):
                self.store.advance(
                    "lab-one", state.identity.lab_id, LabPhase.VMS_CREATED
                )

        self.assertTrue(raced)
        self.assertEqual(self.store.state_path("lab-two").read_bytes(), other_before)
        detached = json.loads(
            (detached_directory / "state.json").read_text(encoding="utf-8")
        )
        self.assertEqual(detached["journal"][-1]["phase"], "vms-created")
        self.assertEqual(list(detached_directory.glob(".state.json.*")), [])

    def test_inventory_uses_exact_unique_handles_and_is_immutable(self) -> None:
        state = self.claim_with_inventory()
        self.assertEqual(len(state.inventory), 4)
        with self.assertRaises(StateValidationError):
            self.store.declare_inventory("lab-one", state.identity.lab_id, state.inventory)

        duplicate = ProviderMachine(
            role="extra",
            machine_id=str(uuid.uuid4()),
            handle=state.inventory[0].handle,
        )
        with self.assertRaises(StateValidationError):
            LabState(
                identity=state.identity,
                inventory=state.inventory + (duplicate,),
                journal=state.journal,
            )

    def test_complete_machine_observations_are_normalized_persisted_and_replayable(self) -> None:
        state = self.claim_with_inventory()
        observations = self.observations_for(state)

        recorded = self.store.record_machine_observations(
            "lab-one", state.identity.lab_id, observations
        )

        self.assertEqual(
            tuple(observation.role for observation in recorded.observations),
            ("candidate", "control-plane", "worker1", "worker2"),
        )
        self.assertEqual(recorded.observations[0].mac_address, "aa:bb:cc:dd:ee:01")
        self.assertEqual(
            recorded.observations[0].product_uuid,
            "00000000-0000-0000-0000-000000000001",
        )
        persisted = json.loads(self.store.state_path("lab-one").read_text(encoding="utf-8"))
        self.assertEqual(len(persisted["observations"]), 4)
        before = self.store.state_path("lab-one").read_bytes()

        replayed = self.store.record_machine_observations(
            "lab-one", state.identity.lab_id, tuple(reversed(observations))
        )

        self.assertEqual(replayed, recorded)
        self.assertEqual(self.store.state_path("lab-one").read_bytes(), before)

    def test_machine_observations_are_complete_unique_and_match_inventory(self) -> None:
        state = self.claim_with_inventory()
        observations = list(self.observations_for(state))

        for incomplete in ((), tuple(observations[:-1]), tuple(observations + observations[:1])):
            with self.subTest(incomplete=len(incomplete)), self.assertRaises(
                StateValidationError
            ):
                self.store.record_machine_observations(
                    "lab-one", state.identity.lab_id, incomplete
                )

        duplicate_fields = ("ipv4", "mac_address", "product_uuid")
        for field_name in duplicate_fields:
            duplicate = list(observations)
            duplicate[1] = replace(
                duplicate[1], **{field_name: getattr(duplicate[0], field_name)}
            )
            with self.subTest(duplicate=field_name), self.assertRaises(
                StateValidationError
            ):
                self.store.record_machine_observations(
                    "lab-one", state.identity.lab_id, duplicate
                )

        forged = list(observations)
        forged[0] = replace(forged[0], machine_id=str(uuid.uuid4()))
        with self.assertRaises(StateValidationError):
            self.store.record_machine_observations(
                "lab-one", state.identity.lab_id, forged
            )

    def test_machine_observation_values_are_bounded_and_valid(self) -> None:
        state = self.claim_with_inventory()
        machine = state.inventory[0]
        valid = {
            "role": machine.role,
            "machine_id": machine.machine_id,
            "handle": machine.handle,
            "ipv4": "192.0.2.10",
            "mac_address": "aa:bb:cc:dd:ee:01",
            "product_uuid": "00000000-0000-0000-0000-000000000001",
            "provisioning_bundle_sha256": "a" * 64,
            "provisioning_spec_sha256": "b" * 64,
        }
        invalid = {
            "ipv4": (
                "192.0.2.001",
                "2001:db8::1",
                "0.0.0.0",
                "127.0.0.1",
                "169.254.1.1",
                "224.0.0.1",
                "x" * 10000,
            ),
            "mac_address": (
                "aa:bb:cc:dd:ee",
                "gg:bb:cc:dd:ee:01",
                "aa:bb-cc:dd:ee:01",
                "01:bb:cc:dd:ee:01",
                "a" * 10000,
            ),
            "product_uuid": ("not-a-uuid", "a" * 10000),
            "provisioning_bundle_sha256": ("a" * 63, "A" * 64, "z" * 64),
            "provisioning_spec_sha256": ("b" * 63, "B" * 64, "z" * 64),
        }
        for field_name, values in invalid.items():
            for value in values:
                with self.subTest(field=field_name, value=value[:80]), self.assertRaises(
                    StateValidationError
                ):
                    MachineObservation(**{**valid, field_name: value})

    def test_provisioning_spec_binds_only_before_inventory_and_is_immutable(self) -> None:
        state = self.store.claim("spec-lab", provider="lima")
        bound = self.store.bind_provisioning_spec(
            "spec-lab", state.identity.lab_id, "a" * 64
        )
        self.assertEqual(bound.provisioning_spec_sha256, "a" * 64)
        replay = self.store.bind_provisioning_spec(
            "spec-lab", state.identity.lab_id, "a" * 64
        )
        self.assertEqual(replay, bound)
        with self.assertRaisesRegex(StateValidationError, "drift"):
            self.store.bind_provisioning_spec(
                "spec-lab", state.identity.lab_id, "b" * 64
            )

        legacy = self.claim_with_inventory("legacy-lab")
        with self.assertRaisesRegex(StateValidationError, "explicit rebuild"):
            self.store.bind_provisioning_spec(
                "legacy-lab", legacy.identity.lab_id, "a" * 64
            )

    def test_machine_observations_are_immutable_and_drift_fails_closed(self) -> None:
        state = self.claim_with_inventory()
        observations = self.observations_for(state)
        self.store.record_machine_observations(
            "lab-one", state.identity.lab_id, observations
        )
        before = self.store.state_path("lab-one").read_bytes()

        drift = {
            "ipv4": "192.0.2.99",
            "mac_address": "aa:bb:cc:dd:ee:99",
            "product_uuid": "00000000-0000-0000-0000-000000000099",
            "provisioning_bundle_sha256": "b" * 64,
            "provisioning_spec_sha256": "c" * 64,
        }
        for field_name, value in drift.items():
            changed = list(observations)
            changed[0] = replace(changed[0], **{field_name: value})
            with self.subTest(drift=field_name), self.assertRaises(
                StateValidationError
            ):
                self.store.record_machine_observations(
                    "lab-one", state.identity.lab_id, changed
                )

        self.assertEqual(self.store.state_path("lab-one").read_bytes(), before)

    def test_machine_observation_write_is_atomic_on_replace_failure(self) -> None:
        state = self.claim_with_inventory()
        before = self.store.state_path("lab-one").read_bytes()

        with patch("cks_simulator.state.os.replace", side_effect=OSError("disk fault")):
            with self.assertRaises(OSError):
                self.store.record_machine_observations(
                    "lab-one", state.identity.lab_id, self.observations_for(state)
                )

        self.assertEqual(self.store.state_path("lab-one").read_bytes(), before)
        self.assertEqual(list(self.store.state_path("lab-one").parent.glob(".state.json.*")), [])

    def test_copied_observations_cannot_be_adopted_by_another_inventory(self) -> None:
        first = self.claim_with_inventory("lab-one")
        copied = self.observations_for(first)
        second = self.claim_with_inventory("lab-two")

        with self.assertRaises(StateValidationError):
            self.store.record_machine_observations(
                "lab-two", second.identity.lab_id, copied
            )

    def test_forged_persisted_observation_is_rejected_on_load(self) -> None:
        state = self.claim_with_inventory()
        self.store.record_machine_observations(
            "lab-one", state.identity.lab_id, self.observations_for(state)
        )
        payload = json.loads(self.store.state_path("lab-one").read_text(encoding="utf-8"))
        payload["observations"][0]["machine_id"] = str(uuid.uuid4())
        self.store.state_path("lab-one").write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaises(StateValidationError):
            self.store.load("lab-one")

    def test_legacy_u3_state_without_observations_still_parses(self) -> None:
        state = self.claim_with_inventory()
        payload = state.to_dict()
        payload.pop("observations")

        loaded = LabState.from_dict(payload)

        self.assertEqual(loaded.observations, ())

    def test_legacy_progress_without_observations_parses_but_cannot_advance(self) -> None:
        state = self.claim_with_inventory()
        payload = state.to_dict()
        payload.pop("observations")
        payload["journal"].append(
            {
                "sequence": 1,
                "phase": "vms-created",
                "recorded_at": "2026-07-14T00:00:00Z",
                "detail": "legacy U3 state",
            }
        )
        self.store.state_path("lab-one").write_text(json.dumps(payload), encoding="utf-8")

        loaded = self.store.load("lab-one")
        self.assertEqual(loaded.phase, LabPhase.VMS_CREATED)
        with self.assertRaises(StateValidationError):
            self.store.advance("lab-one", state.identity.lab_id, LabPhase.OS_READY)

    def test_valid_exact_ownership_authorizes_mutation(self) -> None:
        state = self.claim_with_inventory()
        discovery, guests = self.discovery_and_guests(state)
        authorized = self.store.require_mutation_authority("lab-one", discovery, guests)
        self.assertEqual(authorized.identity, state.identity)

    def test_state_coordinator_is_the_only_public_destructive_boundary(self) -> None:
        state = self.claim_with_inventory()
        discovery, guests = self.discovery_and_guests(state)

        class FakeProvider:
            name = "lima"

            def __init__(self, observed: Discovery, identities: tuple[GuestIdentity, ...]) -> None:
                self.observed = observed
                self.identities = {identity.handle: identity for identity in identities}
                self.deleted: list[ProviderHandle] = []

            def discover(self, expected: tuple[ProviderHandle, ...]) -> Discovery:
                self.expected = expected
                return self.observed

            def read_guest_identity(self, handle: ProviderHandle) -> GuestIdentity | None:
                return self.identities.get(handle)

            def prove_ownership(
                self,
                expected: GuestIdentity,
                *,
                mode: OwnershipProofMode,
            ) -> bool:
                self.proofs.append((expected, mode))
                observed = self.identities.get(expected.handle)
                return observed == expected

            def create(self, identity: GuestIdentity) -> ProcessResult:
                raise AssertionError("create is outside this test")

            def _delete_exact(self, handle: ProviderHandle) -> ProcessResult:
                self.deleted.append(handle)
                return ProcessResult(("delete", handle.value), 0, "", "")

        provider = FakeProvider(discovery, guests)
        provider.proofs = []
        results = self.store.destroy_owned("lab-one", provider)
        self.assertTrue(all(result.ok for result in results))
        self.assertEqual(
            tuple(provider.deleted),
            tuple(
                next(machine.handle for machine in state.inventory if machine.role == role)
                for role in ("worker2", "worker1", "control-plane", "candidate")
            ),
        )
        self.assertEqual(
            {proof.handle for proof, mode in provider.proofs if mode is OwnershipProofMode.ORDINARY},
            set(discovery.handles),
        )

        with self.assertRaises(OwnershipError):
            self.store.break_glass_destroy_owned(
                "lab-one", state.identity.lab_id, provider
            )
        degraded = self.store.advance(
            "lab-one", state.identity.lab_id, LabPhase.DEGRADED
        )
        partial = Discovery(Presence.PRESENT, (state.inventory[1].handle,))
        break_glass_identity = next(
            identity for identity in guests if identity.handle == state.inventory[1].handle
        )
        break_glass_provider = FakeProvider(partial, (break_glass_identity,))
        break_glass_provider.proofs = []
        break_glass = self.store.break_glass_destroy_owned(
            "lab-one", degraded.identity.lab_id, break_glass_provider
        )
        self.assertTrue(all(result.ok for result in break_glass))
        self.assertEqual(
            break_glass_provider.deleted,
            [state.inventory[1].handle],
        )
        self.assertEqual(
            break_glass_provider.proofs,
            [(break_glass_identity, OwnershipProofMode.BREAK_GLASS)],
        )

    def test_break_glass_refuses_an_exact_name_collision_without_ownership_proof(self) -> None:
        state = self.claim_with_inventory()
        state = self.store.advance(
            "lab-one", state.identity.lab_id, LabPhase.DEGRADED
        )
        collision = state.inventory[1]

        class CollisionProvider:
            name = "lima"

            def __init__(self) -> None:
                self.deleted: list[ProviderHandle] = []

            def discover(self, expected: tuple[ProviderHandle, ...]) -> Discovery:
                return Discovery(Presence.PRESENT, (collision.handle,))

            def read_guest_identity(self, handle: ProviderHandle) -> None:
                return None

            def prove_ownership(
                self,
                expected: GuestIdentity,
                *,
                mode: OwnershipProofMode,
            ) -> bool:
                self.proof = (expected, mode)
                return False

            def create(self, identity: GuestIdentity) -> ProcessResult:
                raise AssertionError("create is outside this test")

            def _delete_exact(self, handle: ProviderHandle) -> ProcessResult:
                self.deleted.append(handle)
                return ProcessResult(("delete", handle.value), 0, "", "")

        provider = CollisionProvider()
        with self.assertRaisesRegex(OwnershipError, "ownership proof"):
            self.store.break_glass_destroy_owned(
                "lab-one", state.identity.lab_id, provider
            )

        self.assertEqual(provider.deleted, [])
        self.assertEqual(provider.proof[0].handle, collision.handle)
        self.assertIs(provider.proof[1], OwnershipProofMode.BREAK_GLASS)

    def test_destroy_coordinator_refuses_missing_guest_identity(self) -> None:
        state = self.claim_with_inventory()
        discovery, guests = self.discovery_and_guests(state)

        class MissingMarkerProvider:
            name = "lima"

            def discover(self, expected: tuple[ProviderHandle, ...]) -> Discovery:
                return discovery

            def read_guest_identity(self, handle: ProviderHandle) -> None:
                return None

            def prove_ownership(
                self,
                expected: GuestIdentity,
                *,
                mode: OwnershipProofMode,
            ) -> bool:
                return False

            def create(self, identity: GuestIdentity) -> ProcessResult:
                raise AssertionError("create is outside this test")

            def _delete_exact(self, handle: ProviderHandle) -> ProcessResult:
                raise AssertionError("delete must not run")

        with self.assertRaises(OwnershipError):
            self.store.destroy_owned("lab-one", MissingMarkerProvider())

    def test_inventory_handles_are_deterministic_for_lima_and_kind(self) -> None:
        lab_id = str(uuid.uuid4())
        prefix = uuid.UUID(lab_id).hex[:16]
        self.assertEqual(
            derive_provider_handle("lima", lab_id, "worker1"),
            ProviderHandle("lima", f"cks-{prefix}-worker1"),
        )
        self.assertEqual(
            derive_provider_handle("kind", lab_id, "cluster"),
            ProviderHandle("kind", f"cks-{prefix}-cluster"),
        )
        with self.assertRaises(ValueError):
            derive_provider_handle("kind", lab_id, "worker1")

    def test_forged_inventory_handle_is_rejected_before_mutation_authority(self) -> None:
        state = self.store.claim("lab-one", provider="lima")
        forged = ProviderMachine(
            role="candidate",
            machine_id=str(uuid.uuid4()),
            handle=ProviderHandle("lima", "unrelated-candidate"),
        )
        with self.assertRaises(StateValidationError):
            self.store.declare_inventory(
                "lab-one", state.identity.lab_id, (forged,)
            )

    def test_missing_state_refuses_mutation(self) -> None:
        with self.assertRaises(StateMissingError):
            self.store.require_mutation_authority(
                "missing", Discovery(Presence.ABSENT), ()
            )

    def test_copied_state_refuses_mutation(self) -> None:
        state = self.claim_with_inventory("lab-one")
        copied_dir = self.store.state_path("lab-two").parent
        copied_dir.mkdir(parents=True, mode=0o700)
        self.store.state_path("lab-two").write_bytes(self.store.state_path("lab-one").read_bytes())
        discovery, guests = self.discovery_and_guests(state)

        with self.assertRaises(OwnershipError):
            self.store.require_mutation_authority("lab-two", discovery, guests)

    def test_state_copied_between_namespaces_is_not_adopted(self) -> None:
        self.claim_with_inventory("lab-one")
        quick = LabStateStore(self.root, namespace="quick")
        destination = quick.state_path("lab-one")
        destination.parent.mkdir(parents=True, mode=0o700)
        destination.write_bytes(self.store.state_path("lab-one").read_bytes())
        with self.assertRaises(OwnershipError):
            quick.load("lab-one")

    def test_forged_identity_or_guest_marker_refuses_mutation(self) -> None:
        state = self.claim_with_inventory()
        discovery, guests = self.discovery_and_guests(state)
        forged = json.loads(self.store.state_path("lab-one").read_text(encoding="utf-8"))
        forged["identity"]["lab_id"] = str(uuid.uuid4())
        self.store.state_path("lab-one").write_text(json.dumps(forged), encoding="utf-8")

        with self.assertRaises(StateValidationError):
            self.store.require_mutation_authority("lab-one", discovery, guests)

    def test_missing_or_mismatched_guest_identity_refuses_mutation(self) -> None:
        state = self.claim_with_inventory()
        discovery, guests = self.discovery_and_guests(state)
        with self.assertRaises(OwnershipError):
            self.store.require_mutation_authority("lab-one", discovery, guests[:-1])

        wrong = list(guests)
        wrong[0] = GuestIdentity(
            lab_id=state.identity.lab_id,
            machine_id=str(uuid.uuid4()),
            role=wrong[0].role,
            handle=wrong[0].handle,
        )
        with self.assertRaises(OwnershipError):
            self.store.require_mutation_authority("lab-one", discovery, wrong)

    def test_unknown_or_inexact_discovery_refuses_mutation(self) -> None:
        state = self.claim_with_inventory()
        discovery, guests = self.discovery_and_guests(state)
        with self.assertRaises(OwnershipError):
            self.store.require_mutation_authority(
                "lab-one", Discovery(Presence.UNKNOWN, detail="provider failed"), ()
            )

        for handles in (
            discovery.handles[:-1],
            discovery.handles + (ProviderHandle("lima", "lab-one-lookalike"),),
        ):
            with self.subTest(handles=handles), self.assertRaises(OwnershipError):
                self.store.require_mutation_authority(
                    "lab-one", Discovery(Presence.PRESENT, handles), guests
                )

    def test_absent_discovery_is_safe_only_when_no_provider_mutation_exists(self) -> None:
        state = self.claim_with_inventory()
        authorized = self.store.require_mutation_authority(
            "lab-one", Discovery(Presence.ABSENT), ()
        )
        self.assertEqual(authorized.identity, state.identity)
        with self.assertRaises(ValueError):
            Discovery(Presence.ABSENT, (state.inventory[0].handle,))

    def test_phase_journal_enforces_transitions_identity_and_bounded_detail(self) -> None:
        state = self.claim_with_inventory()
        observations = self.observations_for(state)
        state = self.store.record_machine_observations(
            "lab-one", state.identity.lab_id, observations
        )
        state = self.store.advance(
            "lab-one", state.identity.lab_id, LabPhase.VMS_CREATED, detail="token: secret"
        )
        self.assertEqual(state.phase, LabPhase.VMS_CREATED)
        self.assertNotIn("secret", state.journal[-1].detail)
        state = self.store.advance("lab-one", state.identity.lab_id, LabPhase.OS_READY)
        self.assertEqual([entry.sequence for entry in state.journal], [0, 1, 2])
        self.assertEqual(self.store.load("lab-one").phase, LabPhase.OS_READY)

        with self.assertRaises(InvalidTransitionError):
            self.store.advance("lab-one", state.identity.lab_id, LabPhase.VALIDATED)
        with self.assertRaises(OwnershipError):
            self.store.advance("lab-one", str(uuid.uuid4()), LabPhase.CLUSTER_READY)

    def test_phase_journal_allows_degraded_cleanup_and_destroy(self) -> None:
        state = self.claim_with_inventory()
        state = self.store.advance("lab-one", state.identity.lab_id, LabPhase.DEGRADED)
        state = self.store.advance("lab-one", state.identity.lab_id, LabPhase.CLEANUP_PENDING)
        state = self.store.advance("lab-one", state.identity.lab_id, LabPhase.DESTROYED)
        self.assertEqual(state.phase, LabPhase.DESTROYED)

    def test_ordinary_advance_cannot_blindly_resume_a_degraded_lab(self) -> None:
        state = self.claim_with_inventory()
        observations = self.observations_for(state)
        self.store.record_machine_observations(
            "lab-one", state.identity.lab_id, observations
        )
        degraded = self.store.advance(
            "lab-one", state.identity.lab_id, LabPhase.DEGRADED
        )

        for target in (
            LabPhase.VMS_CREATED,
            LabPhase.OS_READY,
            LabPhase.CLUSTER_READY,
            LabPhase.ADDONS_READY,
        ):
            with self.subTest(target=target), self.assertRaises(
                InvalidTransitionError
            ):
                self.store.advance("lab-one", degraded.identity.lab_id, target)

    def test_verified_recovery_records_observations_and_preserves_history(self) -> None:
        state = self.claim_with_inventory()
        observations = self.observations_for(state)
        degraded = self.store.advance(
            "lab-one", state.identity.lab_id, LabPhase.DEGRADED,
            detail="creation interrupted",
        )

        recovered = self.store.recover_verified_phase(
            "lab-one",
            state.identity.lab_id,
            LabPhase.ADDONS_READY,
            observations,
            detail="freshly verified",
        )

        self.assertEqual(recovered.phase, LabPhase.ADDONS_READY)
        self.assertEqual(recovered.observations[0].mac_address, "aa:bb:cc:dd:ee:01")
        self.assertEqual(
            [entry.phase for entry in recovered.journal],
            [LabPhase.DECLARED, LabPhase.DEGRADED, LabPhase.ADDONS_READY],
        )
        self.assertEqual([entry.sequence for entry in recovered.journal], [0, 1, 2])
        self.assertEqual(recovered.journal[-1].detail, "freshly verified")

    def test_verified_recovery_rejects_non_u4_target_non_degraded_state_and_drift(self) -> None:
        state = self.claim_with_inventory()
        observations = self.observations_for(state)
        self.store.record_machine_observations(
            "lab-one", state.identity.lab_id, observations
        )
        with self.assertRaises(InvalidTransitionError):
            self.store.recover_verified_phase(
                "lab-one",
                state.identity.lab_id,
                LabPhase.VMS_CREATED,
                observations,
            )

        degraded = self.store.advance(
            "lab-one", state.identity.lab_id, LabPhase.DEGRADED
        )
        with self.assertRaises(InvalidTransitionError):
            self.store.recover_verified_phase(
                "lab-one",
                degraded.identity.lab_id,
                LabPhase.CANDIDATE_READY,
                observations,
            )

        changed = list(observations)
        changed[0] = replace(changed[0], mac_address="aa:bb:cc:dd:ee:99")
        before = self.store.state_path("lab-one").read_bytes()
        with self.assertRaises(StateValidationError):
            self.store.recover_verified_phase(
                "lab-one",
                degraded.identity.lab_id,
                LabPhase.OS_READY,
                changed,
            )
        self.assertEqual(self.store.state_path("lab-one").read_bytes(), before)

    def test_observation_recording_requires_canonical_full_lima_roles(self) -> None:
        state = self.store.claim("lab-one", provider="lima")
        legacy_inventory = tuple(
            ProviderMachine(
                role=role,
                machine_id=str(uuid.uuid4()),
                handle=derive_provider_handle("lima", state.identity.lab_id, role),
            )
            for role in ("candidate", "control-plane", "worker-1", "worker-2")
        )
        state = self.store.declare_inventory(
            "lab-one", state.identity.lab_id, legacy_inventory
        )
        observations = tuple(
            MachineObservation(
                role=machine.role,
                machine_id=machine.machine_id,
                handle=machine.handle,
                ipv4=f"192.0.2.{index + 1}",
                mac_address=f"aa:bb:cc:dd:ee:{index + 1:02x}",
                product_uuid=str(uuid.UUID(int=index + 1)),
                provisioning_bundle_sha256="a" * 64,
                provisioning_spec_sha256="b" * 64,
            )
            for index, machine in enumerate(state.inventory)
        )

        with self.assertRaises(StateValidationError):
            self.store.record_machine_observations(
                "lab-one", state.identity.lab_id, observations
            )

    def test_nonblocking_lock_refuses_a_concurrent_mutator(self) -> None:
        with self.store.lock("lab-one"):
            with self.assertRaises(LabLockedError):
                with self.store.lock("lab-one", blocking=False):
                    self.fail("second mutator entered the critical section")

    def test_symlinked_lock_file_is_rejected_without_touching_target(self) -> None:
        outside = self.root / "outside.lock"
        outside.write_text("unchanged", encoding="utf-8")
        lock_path = self.root / ".locks" / "full" / "lab-one.lock"
        lock_path.parent.mkdir(parents=True, mode=0o700)
        lock_path.symlink_to(outside)

        with self.assertRaises(StateValidationError):
            with self.store.lock("lab-one"):
                self.fail("symlinked lock entered the critical section")

        self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")

    def test_symlinked_lock_ancestors_are_rejected_without_redirection(self) -> None:
        outside = self.root / "outside-locks"
        outside.mkdir(mode=0o700)
        locks = self.root / ".locks"
        locks.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(StateValidationError):
            with self.store.lock("lab-one"):
                self.fail("symlinked lock root entered the critical section")
        self.assertEqual(list(outside.iterdir()), [])

        locks.unlink()
        locks.mkdir(mode=0o700)
        namespace = locks / "full"
        namespace.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(StateValidationError):
            with self.store.lock("lab-one"):
                self.fail("symlinked lock namespace entered the critical section")
        self.assertEqual(list(outside.iterdir()), [])

    def test_swapped_lock_namespace_cannot_admit_a_concurrent_mutator(self) -> None:
        namespace = self.root / ".locks" / "full"
        detached = self.root / ".locks" / "full-detached"

        with self.assertRaises(StateValidationError):
            with self.store.lock("lab-one"):
                namespace.rename(detached)
                namespace.mkdir(mode=0o700)
                with self.assertRaises(LabLockedError):
                    with self.store.lock("lab-one", blocking=False):
                        self.fail("swapped namespace admitted a concurrent mutator")

    def test_fifo_lock_file_is_rejected_without_blocking(self) -> None:
        lock_path = self.root / ".locks" / "full" / "lab-one.lock"
        lock_path.parent.mkdir(parents=True, mode=0o700)
        os.mkfifo(lock_path, mode=0o600)

        with self.assertRaises(StateValidationError):
            with self.store.lock("lab-one"):
                self.fail("FIFO lock entered the critical section")

    def test_lock_serializes_across_processes(self) -> None:
        ready = self.root / "ready"
        release = self.root / "release"
        script = """
import sys, time
from pathlib import Path
from cks_simulator.state import LabStateStore
root, ready, release = map(Path, sys.argv[1:])
with LabStateStore(root, namespace='full').lock('lab-one'):
    ready.write_text('ready')
    while not release.exists():
        time.sleep(0.01)
"""
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(self.root), str(ready), str(release)],
            cwd=Path(__file__).resolve().parents[1],
        )
        self.addCleanup(lambda: process.poll() is None and process.kill())
        for _ in range(200):
            if ready.exists():
                break
            if process.poll() is not None:
                self.fail(f"lock holder exited early with {process.returncode}")
            import time

            time.sleep(0.01)
        self.assertTrue(ready.exists(), "lock holder did not become ready")
        with self.assertRaises(LabLockedError):
            with self.store.lock("lab-one", blocking=False):
                pass
        release.write_text("release", encoding="utf-8")
        self.assertEqual(process.wait(timeout=5), 0)

    def test_symlinked_state_file_is_never_trusted(self) -> None:
        outside = self.root / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        state_path = self.store.state_path("lab-one")
        state_path.parent.mkdir(parents=True, mode=0o700)
        state_path.symlink_to(outside)
        with self.assertRaises(StateValidationError):
            self.store.load("lab-one")

    def test_fifo_and_oversized_state_files_are_rejected_without_blocking(self) -> None:
        state_path = self.store.state_path("lab-one")
        state_path.parent.mkdir(parents=True, mode=0o700)
        os.mkfifo(state_path, mode=0o600)
        with self.assertRaises(StateValidationError):
            self.store.load("lab-one")
        state_path.unlink()
        state_path.write_bytes(b"{" + b"x" * (1024 * 1024))
        with self.assertRaises(StateValidationError):
            self.store.load("lab-one")

    def test_symlinked_lab_directory_cannot_redirect_state_reads(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "state.json").write_text("{}", encoding="utf-8")
        self.store.namespace_path.mkdir(parents=True)
        (self.store.namespace_path / "lab-one").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(StateValidationError):
            self.store.load("lab-one")

    def test_broken_symlinked_lab_directory_refuses_state_creation(self) -> None:
        self.store.namespace_path.mkdir(parents=True)
        lab_directory = self.store.state_path("lab-one").parent
        lab_directory.symlink_to(self.root / "missing-target", target_is_directory=True)

        with self.assertRaises(StateValidationError):
            self.store.claim("lab-one", provider="lima")


if __name__ == "__main__":
    unittest.main()
