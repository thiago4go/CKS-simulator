"""Host-side reconciler for the owned four-machine Lima lab.

This module deliberately owns orchestration only.  Provider identity and exact
deletion remain in :mod:`cks_simulator.providers` and :mod:`cks_simulator.state`;
guest convergence remains in the reviewed scripts under ``infra/provision``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Protocol, Sequence, Tuple

from .providers.base import (
    Discovery,
    GuestIdentity,
    Presence,
    ProcessResult,
    ProviderHandle,
    ProviderMachine,
    bounded_redacted,
    derive_provider_handle,
    validate_identifier,
)
from .providers.lima import MachineObservation as LimaMachineObservation
from .state import (
    LabPhase,
    LabState,
    LabStateStore,
    MachineObservation,
    OwnershipError,
    StateMissingError,
    StateValidationError,
)


MACHINE_ROLES = ("candidate", "control-plane", "worker1", "worker2")
_CLUSTER_ROLES = ("control-plane", "worker1", "worker2")
_BUNDLE_FILES = (
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
)
_GUEST_ROOT = "/opt/cks-simulator/provision"
_MAX_BUNDLE_BYTES = 8 * 1024 * 1024
_MAX_JOIN_MATERIAL_BYTES = 512
_TOKEN = re.compile(r"^[a-z0-9]{6}\.[a-z0-9]{16}$")
_CA_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN_ANYWHERE = re.compile(r"(?<![a-z0-9])[a-z0-9]{6}\.[a-z0-9]{16}(?![a-z0-9])")
_CA_HASH_ANYWHERE = re.compile(r"sha256:[0-9a-f]{64}")
_KUBERNETES_VERSION = re.compile(r"^KUBERNETES_VERSION=(v[0-9]+\.[0-9]+\.[0-9]+)$", re.M)
_PORTS = {
    "control-plane": "6443,2379,2380,10250,10257,10259",
    "worker1": "10250,10256",
    "worker2": "10250,10256",
}
_VERIFIED_RANK = {
    LabPhase.DECLARED: 0,
    LabPhase.VMS_CREATED: 1,
    LabPhase.OS_READY: 2,
    LabPhase.CLUSTER_READY: 3,
    LabPhase.ADDONS_READY: 4,
    LabPhase.CANDIDATE_READY: 5,
    LabPhase.VALIDATED: 6,
}

class FullLabError(RuntimeError):
    """Base class for bounded, user-safe full-lab lifecycle failures."""


class FullLabReconcileError(FullLabError):
    """The lab could not be converged and was journaled as degraded."""


class FullLabDestroyError(FullLabError):
    """Exact cleanup did not produce a provably absent provider inventory."""


class _FullProvider(Protocol):
    name: str

    def discover(self, expected_handles: Sequence[ProviderHandle]) -> Discovery: ...

    def read_guest_identity(self, handle: ProviderHandle) -> Optional[GuestIdentity]: ...

    def ensure(self, identity: GuestIdentity) -> ProcessResult: ...

    def install_root_file(
        self,
        handle: ProviderHandle,
        destination: str,
        content: bytes,
        *,
        mode: int = 0o600,
        timeout_seconds: float = 120.0,
    ) -> ProcessResult: ...

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
    ) -> ProcessResult: ...

    def observe_machine(self, handle: ProviderHandle) -> LimaMachineObservation: ...

    def _delete_exact(self, handle: ProviderHandle) -> ProcessResult: ...


@dataclass(frozen=True)
class FullLabConfig:
    pod_cidr: str = "10.244.0.0/16"
    service_cidr: str = "10.96.0.0/12"
    cilium_version: str = "1.19.5"
    cilium_cli_version: str = "v0.19.5"
    cilium_cli_url: str = "https://github.com/cilium/cilium-cli/releases/download/v0.19.5/cilium-linux-arm64.tar.gz"
    cilium_cli_sha256: str = "5498defafc248160ca44a38be39f5ba090769ef112f9ec34a19e72dfa7e7eb25"
    cilium_chart_url: str = "https://helm.cilium.io/cilium-1.19.5.tgz"
    cilium_chart_sha256: str = "56b60445a2c650b387ce2edb13cfd8d83219a9da693b0523915dba8be451a29e"


@dataclass(frozen=True)
class _Bundle:
    files: Tuple[Tuple[str, bytes, int], ...]
    sha256: str
    kubernetes_version: str

    @classmethod
    def load(cls, root: Path) -> "_Bundle":
        root = Path(root).expanduser().resolve(strict=True)
        collected = []
        total = 0
        digest = hashlib.sha256()
        for relative in _BUNDLE_FILES:
            path = root / relative
            try:
                descriptor = os.open(
                    path,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                )
            except OSError as error:
                raise ValueError(f"provisioning bundle file is unavailable: {relative}") from error
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_BUNDLE_BYTES:
                    raise ValueError(
                        f"provisioning bundle entry must be a bounded regular file: {relative}"
                    )
                chunks = bytearray()
                while len(chunks) <= _MAX_BUNDLE_BYTES:
                    chunk = os.read(
                        descriptor,
                        min(65536, _MAX_BUNDLE_BYTES + 1 - len(chunks)),
                    )
                    if not chunk:
                        break
                    chunks.extend(chunk)
                after = os.fstat(descriptor)
                if (
                    len(chunks) > _MAX_BUNDLE_BYTES
                    or len(chunks) != after.st_size
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                ):
                    raise ValueError(
                        f"provisioning bundle entry changed while being pinned: {relative}"
                    )
                content = bytes(chunks)
            finally:
                os.close(descriptor)
            total += len(content)
            if total > _MAX_BUNDLE_BYTES:
                raise ValueError("provisioning bundle exceeds the maximum size")
            mode = 0o600 if relative.endswith(".env") else 0o755
            collected.append((relative, content, mode))
            encoded = relative.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)

        manifest = dict((name, content) for name, content, _ in collected)["common/versions.env"]
        try:
            manifest_text = manifest.decode("utf-8")
        except UnicodeError as error:
            raise ValueError("versions.env must be UTF-8") from error
        match = _KUBERNETES_VERSION.search(manifest_text)
        if match is None:
            raise ValueError("versions.env has no pinned KUBERNETES_VERSION")
        return cls(tuple(collected), digest.hexdigest(), match.group(1))


@dataclass(frozen=True)
class _JoinMaterial:
    payload: bytes
    token: str
    ca_hash: str

    @property
    def secrets(self) -> Tuple[str, ...]:
        return (self.token, self.ca_hash, self.payload.decode("ascii"))


class FullLabLifecycle:
    """Dependency-injected, replay-safe U4 provision and destroy coordinator."""

    def __init__(
        self,
        store: LabStateStore,
        provider: _FullProvider,
        *,
        provisioning_root: Path,
        config: FullLabConfig = FullLabConfig(),
    ) -> None:
        if provider.name != "lima":
            raise ValueError("the full VM lifecycle requires the Lima provider")
        self._store = store
        self._provider = provider
        self._bundle = _Bundle.load(provisioning_root)
        self._config = config
        specification = {
            "schema": "cks-simulator/full-lab-spec/v1",
            "provisioning_bundle_sha256": self._bundle.sha256,
            "config": {
                "pod_cidr": config.pod_cidr,
                "service_cidr": config.service_cidr,
                "cilium_version": config.cilium_version,
                "cilium_cli_version": config.cilium_cli_version,
                "cilium_cli_url": config.cilium_cli_url,
                "cilium_cli_sha256": config.cilium_cli_sha256,
                "cilium_chart_url": config.cilium_chart_url,
                "cilium_chart_sha256": config.cilium_chart_sha256,
            },
        }
        canonical = json.dumps(
            specification,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        self._provisioning_spec_sha256 = hashlib.sha256(canonical).hexdigest()

    def _load_or_declare_inventory(self, lab_name: str) -> LabState:
        try:
            state = self._store.load(lab_name)
        except StateMissingError:
            state = self._store.claim(lab_name, provider=self._provider.name)
        if state.provisioning_spec_sha256 is None:
            state = self._store.bind_provisioning_spec(
                lab_name,
                state.identity.lab_id,
                self._provisioning_spec_sha256,
            )
        if not state.inventory:
            inventory = tuple(
                ProviderMachine(
                    role=role,
                    machine_id=str(uuid.uuid4()),
                    handle=derive_provider_handle(self._provider.name, state.identity.lab_id, role),
                )
                for role in MACHINE_ROLES
            )
            state = self._store.declare_inventory(
                lab_name, state.identity.lab_id, inventory
            )
        if (
            len(state.inventory) != len(MACHINE_ROLES)
            or {machine.role for machine in state.inventory} != set(MACHINE_ROLES)
        ):
            raise StateValidationError("full lab inventory must contain the canonical four roles")
        return state

    @staticmethod
    def _by_role(state: LabState) -> Mapping[str, ProviderMachine]:
        return {machine.role: machine for machine in state.inventory}

    def _require_compatible_bundle(self, state: LabState) -> None:
        if state.observations:
            if any(
                observation.provisioning_bundle_sha256 != self._bundle.sha256
                for observation in state.observations
            ):
                raise FullLabReconcileError(
                    "provisioning bundle drift detected before guest mutation; "
                    "destroy and rebuild this immutable lab"
                )
        if state.provisioning_spec_sha256 != self._provisioning_spec_sha256:
            raise FullLabReconcileError(
                "immutable provisioning specification drift detected before guest "
                "mutation; destroy and rebuild this lab"
            )
        if state.observations:
            if any(
                observation.provisioning_spec_sha256 != state.provisioning_spec_sha256
                for observation in state.observations
            ):
                raise FullLabReconcileError(
                    "durable machine observations conflict with the bound provisioning "
                    "specification; destroy and rebuild this lab"
                )

    @staticmethod
    def _guest_identity(state: LabState, machine: ProviderMachine) -> GuestIdentity:
        return GuestIdentity(
            lab_id=state.identity.lab_id,
            machine_id=machine.machine_id,
            role=machine.role,
            handle=machine.handle,
        )

    @staticmethod
    def _safe_diagnostic(
        value: object, *, secrets: Sequence[str] = (), limit: int = 1024
    ) -> str:
        rendered = str(value)
        discovered = tuple(
            dict.fromkeys(
                (*_TOKEN_ANYWHERE.findall(rendered), *_CA_HASH_ANYWHERE.findall(rendered))
            )
        )
        return bounded_redacted(
            rendered,
            secrets=tuple(secrets) + discovered,
            limit=limit,
        )

    @classmethod
    def _require_ok(
        cls,
        value: ProcessResult, context: str, *, secrets: Sequence[str] = ()
    ) -> None:
        if not value.ok:
            raise FullLabReconcileError(
                f"{context} failed: "
                f"{cls._safe_diagnostic(value.diagnostic(limit=1024), secrets=secrets, limit=1024)}"
            )

    def _install_bundle(self, handle: ProviderHandle) -> None:
        for relative, content, mode in self._bundle.files:
            installed = self._provider.install_root_file(
                handle,
                f"{_GUEST_ROOT}/{relative}",
                content,
                mode=mode,
                timeout_seconds=120,
            )
            self._require_ok(installed, f"provisioning bundle install for {handle.value}")

    def _install_host_map(
        self,
        machines: Mapping[str, ProviderMachine],
        observations: Sequence[MachineObservation],
    ) -> None:
        by_role = {item.role: item for item in observations}
        lines = [
            "127.0.0.1 localhost",
            "::1 localhost ip6-localhost ip6-loopback",
            "fe00::0 ip6-localnet",
            "ff00::0 ip6-mcastprefix",
            "ff02::1 ip6-allnodes",
            "ff02::2 ip6-allrouters",
            "ff02::3 ip6-allhosts",
            "",
            "# Managed by cks-simulator from immutable lab observations.",
        ]
        for role in MACHINE_ROLES:
            handle = machines[role].handle.value
            lines.append(f"{by_role[role].ipv4} {handle} lima-{handle}")
        content = ("\n".join(lines) + "\n").encode("ascii")
        for role in MACHINE_ROLES:
            installed = self._provider.install_root_file(
                machines[role].handle,
                "/etc/hosts",
                content,
                mode=0o644,
                timeout_seconds=120,
            )
            self._require_ok(installed, f"stable host map install for {role}")

    def _execute(
        self,
        handle: ProviderHandle,
        argv: Sequence[str],
        context: str,
        *,
        stdin: Optional[bytes] = None,
        timeout_seconds: float = 120.0,
        output_limit: int = 4096,
        secrets: Sequence[str] = (),
    ) -> ProcessResult:
        value = self._provider.execute(
            handle,
            argv,
            stdin=stdin,
            as_root=True,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
            secrets=secrets,
        )
        self._require_ok(value, context, secrets=secrets)
        return value

    def _observations(self, state: LabState) -> Tuple[MachineObservation, ...]:
        observations = []
        for machine in state.inventory:
            observed = self._provider.observe_machine(machine.handle)
            observations.append(
                MachineObservation(
                    role=machine.role,
                    machine_id=machine.machine_id,
                    handle=machine.handle,
                    ipv4=observed.ipv4,
                    mac_address=observed.mac,
                    product_uuid=observed.product_uuid,
                    provisioning_bundle_sha256=self._bundle.sha256,
                    provisioning_spec_sha256=self._provisioning_spec_sha256,
                )
            )
        return tuple(observations)

    def _record_verified_phase(
        self,
        lab_name: str,
        state: LabState,
        phase: LabPhase,
        observations: Sequence[MachineObservation],
    ) -> LabState:
        current = self._store.load(lab_name)
        if current.phase is LabPhase.DEGRADED:
            return self._store.recover_verified_phase(
                lab_name,
                state.identity.lab_id,
                phase,
                observations,
                detail=f"fresh U4 verification recovered {phase.value}",
            )
        current_rank = _VERIFIED_RANK.get(current.phase)
        target_rank = _VERIFIED_RANK[phase]
        if current_rank is None:
            raise StateValidationError(
                f"cannot reconcile U4 while lab is in {current.phase.value}"
            )
        if current_rank >= target_rank:
            return current
        return self._store.advance(
            lab_name,
            state.identity.lab_id,
            phase,
            detail="fresh U4 verification passed",
        )

    def _common_arguments(
        self,
        state: LabState,
        machine: ProviderMachine,
        observation: MachineObservation,
        script: str,
    ) -> Tuple[str, ...]:
        if machine.role == "candidate":
            pod_cidr = service_cidr = ports = "-"
        else:
            pod_cidr = self._config.pod_cidr
            service_cidr = self._config.service_cidr
            ports = _PORTS[machine.role]
        return (
            f"{_GUEST_ROOT}/common/{script}",
            f"{_GUEST_ROOT}/common/versions.env",
            machine.role,
            state.identity.lab_id,
            machine.handle.value,
            machine.handle.value,
            observation.ipv4,
            pod_cidr,
            service_cidr,
            ports,
        )

    def _converge_common(
        self, state: LabState, observations: Sequence[MachineObservation]
    ) -> None:
        observations_by_role = {item.role: item for item in observations}
        for machine in state.inventory:
            self._execute(
                machine.handle,
                self._common_arguments(
                    state, machine, observations_by_role[machine.role], "install.sh"
                ),
                f"common OS convergence for {machine.role}",
                timeout_seconds=1800,
            )
        for machine in state.inventory:
            self._execute(
                machine.handle,
                self._common_arguments(
                    state, machine, observations_by_role[machine.role], "check.sh"
                ),
                f"common OS verification for {machine.role}",
                timeout_seconds=300,
            )

    def _bootstrap_control_plane(
        self,
        state: LabState,
        machine: ProviderMachine,
        observation: MachineObservation,
    ) -> None:
        endpoint = f"{machine.handle.value}:6443"
        environment = (
            "/usr/bin/env",
            f"KUBERNETES_VERSION={self._bundle.kubernetes_version}",
            f"NODE_IP={observation.ipv4}",
            f"NODE_NAME={machine.handle.value}",
            f"POD_CIDR={self._config.pod_cidr}",
            f"SERVICE_CIDR={self._config.service_cidr}",
            f"CONTROL_PLANE_ENDPOINT={endpoint}",
            f"CILIUM_VERSION={self._config.cilium_version}",
            f"CILIUM_CLI_VERSION={self._config.cilium_cli_version}",
            f"CILIUM_CLI_URL={self._config.cilium_cli_url}",
            f"CILIUM_CLI_SHA256={self._config.cilium_cli_sha256}",
            f"CILIUM_CHART_URL={self._config.cilium_chart_url}",
            f"CILIUM_CHART_SHA256={self._config.cilium_chart_sha256}",
            f"{_GUEST_ROOT}/control-plane/bootstrap.sh",
        )
        self._execute(
            machine.handle,
            environment,
            "control-plane kubeadm and Cilium convergence",
            timeout_seconds=1800,
        )

    def _generate_join_material(self, control_plane: ProviderMachine) -> ProcessResult:
        endpoint = f"{control_plane.handle.value}:6443"
        value = self._provider.execute(
            control_plane.handle,
            (
                "/usr/bin/env",
                f"NODE_NAME={control_plane.handle.value}",
                f"CONTROL_PLANE_ENDPOINT={endpoint}",
                f"{_GUEST_ROOT}/control-plane/join-material.sh",
            ),
            as_root=True,
            timeout_seconds=60,
            output_limit=1024,
        )
        if not value.ok:
            rendered = f"{value.stdout}\n{value.stderr}"
            discovered_secrets = tuple(
                dict.fromkeys(
                    (*_TOKEN_ANYWHERE.findall(rendered), *_CA_HASH_ANYWHERE.findall(rendered))
                )
            )
            self._require_ok(
                value,
                "bounded kubeadm join material generation",
                secrets=discovered_secrets,
            )
        return value

    @staticmethod
    def _revocable_token(stdout: str) -> Optional[str]:
        for line in stdout.splitlines():
            prefix = "BOOTSTRAP_TOKEN="
            if line.startswith(prefix):
                value = line[len(prefix) :]
                if _TOKEN.fullmatch(value) is not None:
                    return value
        return None

    def _parse_join_material(
        self, control_plane: ProviderMachine, value: ProcessResult
    ) -> _JoinMaterial:
        endpoint = f"{control_plane.handle.value}:6443"
        try:
            payload = value.stdout.encode("ascii")
        except UnicodeError as error:
            raise FullLabReconcileError("join material was not ASCII") from error
        if not payload or len(payload) > _MAX_JOIN_MATERIAL_BYTES:
            raise FullLabReconcileError("join material exceeded its bounded contract")
        if not payload.endswith(b"\n") or b"\r" in payload or b"\x00" in payload:
            raise FullLabReconcileError("join material was not an exact newline-terminated record")
        lines_with_terminator = value.stdout.split("\n")
        if not lines_with_terminator or lines_with_terminator[-1] != "":
            raise FullLabReconcileError("join material was not newline terminated")
        lines = lines_with_terminator[:-1]
        expected_keys = (
            "CONTROL_PLANE_ENDPOINT",
            "BOOTSTRAP_TOKEN",
            "DISCOVERY_TOKEN_CA_CERT_HASH",
            "CRI_SOCKET",
        )
        if len(lines) != len(expected_keys):
            raise FullLabReconcileError("join material had an invalid record count")
        values = {}
        for key, line in zip(expected_keys, lines):
            prefix = f"{key}="
            if not line.startswith(prefix):
                raise FullLabReconcileError("join material had an invalid schema")
            values[key] = line[len(prefix) :]
        if values["CONTROL_PLANE_ENDPOINT"] != endpoint:
            raise FullLabReconcileError("join material endpoint did not match immutable state")
        if _TOKEN.fullmatch(values["BOOTSTRAP_TOKEN"]) is None:
            raise FullLabReconcileError("join material token was invalid")
        if _CA_HASH.fullmatch(values["DISCOVERY_TOKEN_CA_CERT_HASH"]) is None:
            raise FullLabReconcileError("join material CA hash was invalid")
        if values["CRI_SOCKET"] != "unix:///run/containerd/containerd.sock":
            raise FullLabReconcileError("join material CRI socket was invalid")
        canonical_payload = ("\n".join(lines) + "\n").encode("ascii")
        return _JoinMaterial(
            canonical_payload,
            values["BOOTSTRAP_TOKEN"],
            values["DISCOVERY_TOKEN_CA_CERT_HASH"],
        )

    def _join_workers(
        self,
        state: LabState,
        machines: Mapping[str, ProviderMachine],
        observations: Mapping[str, MachineObservation],
    ) -> None:
        control_plane = machines["control-plane"]
        generated = self._generate_join_material(control_plane)
        token_to_revoke = self._revocable_token(generated.stdout)
        material: Optional[_JoinMaterial] = None
        join_failure: Optional[Exception] = None
        revoke_failure: Optional[Exception] = None
        try:
            material = self._parse_join_material(control_plane, generated)
            token_to_revoke = material.token
            for role in ("worker1", "worker2"):
                worker = machines[role]
                self._execute(
                    worker.handle,
                    (
                        "/usr/bin/env",
                        f"NODE_NAME={worker.handle.value}",
                        f"NODE_IP={observations[role].ipv4}",
                        f"{_GUEST_ROOT}/worker/join.sh",
                    ),
                    f"worker join for {role}",
                    stdin=material.payload,
                    timeout_seconds=600,
                    secrets=material.secrets,
                )
        except Exception as error:  # revocation must still run before surfacing it
            join_failure = error
        finally:
            if token_to_revoke is not None:
                try:
                    self._execute(
                        control_plane.handle,
                        (f"{_GUEST_ROOT}/control-plane/revoke-token.sh",),
                        "bootstrap token revocation",
                        stdin=(token_to_revoke + "\n").encode("ascii"),
                        timeout_seconds=60,
                        secrets=(token_to_revoke,),
                    )
                except Exception as error:
                    revoke_failure = error
        if join_failure is not None and revoke_failure is not None:
            raise FullLabReconcileError(
                f"{self._safe_diagnostic(join_failure, limit=768)}; "
                f"token revocation also failed: {self._safe_diagnostic(revoke_failure, limit=768)}"
            ) from join_failure
        if join_failure is not None:
            raise join_failure
        if revoke_failure is not None:
            raise revoke_failure

    def _health(
        self,
        machines: Mapping[str, ProviderMachine],
        observations: Mapping[str, MachineObservation],
    ) -> None:
        control_plane = machines["control-plane"]
        argv = ["/usr/bin/env"]
        for role, prefix in (
            ("control-plane", "CONTROL_PLANE"),
            ("worker1", "WORKER1"),
            ("worker2", "WORKER2"),
        ):
            argv.extend(
                (
                    f"{prefix}_NAME={machines[role].handle.value}",
                    f"{prefix}_IP={observations[role].ipv4}",
                )
            )
        argv.append(f"{_GUEST_ROOT}/control-plane/health.sh")
        self._execute(
            control_plane.handle,
            tuple(argv),
            "exact three-node and addon health verification",
            timeout_seconds=900,
        )

    def _mark_degraded(self, lab_name: str, lab_id: str, error: Exception) -> None:
        try:
            state = self._store.load(lab_name)
            if state.phase not in {
                LabPhase.DEGRADED,
                LabPhase.CLEANUP_PENDING,
                LabPhase.DESTROYED,
            }:
                self._store.advance(
                    lab_name,
                    lab_id,
                    LabPhase.DEGRADED,
                    detail=self._safe_diagnostic(error, limit=1024),
                )
        except Exception:
            # Preserve the original failure. State-layer diagnostics remain
            # available through an explicit load/doctor operation.
            pass

    def provision(self, lab_name: str) -> LabState:
        validate_identifier(lab_name, field_name="lab name")
        with self._store.lock(lab_name):
            state = self._load_or_declare_inventory(lab_name)
            if state.phase in {LabPhase.CLEANUP_PENDING, LabPhase.DESTROYED}:
                raise FullLabReconcileError(
                    f"cannot provision a lab in {state.phase.value}; use a new lab name after cleanup"
                )
            if state.phase in {LabPhase.SCENARIO_PREPARED, LabPhase.GRADED}:
                raise FullLabReconcileError(
                    f"cannot reconcile base infrastructure during {state.phase.value}"
                )
            try:
                self._require_compatible_bundle(state)
                machines = self._by_role(state)
                for role in MACHINE_ROLES:
                    machine = machines[role]
                    ensured = self._provider.ensure(self._guest_identity(state, machine))
                    self._require_ok(ensured, f"Lima ensure for {role}")

                observations = self._observations(state)
                state = self._store.record_machine_observations(
                    lab_name, state.identity.lab_id, observations
                )
                for role in MACHINE_ROLES:
                    self._install_bundle(machines[role].handle)
                self._install_host_map(machines, observations)
                state = self._record_verified_phase(
                    lab_name, state, LabPhase.VMS_CREATED, observations
                )

                self._converge_common(state, observations)
                state = self._record_verified_phase(
                    lab_name, state, LabPhase.OS_READY, observations
                )

                observations_by_role = {item.role: item for item in observations}
                self._bootstrap_control_plane(
                    state,
                    machines["control-plane"],
                    observations_by_role["control-plane"],
                )
                self._join_workers(state, machines, observations_by_role)
                state = self._record_verified_phase(
                    lab_name, state, LabPhase.CLUSTER_READY, observations
                )

                self._health(machines, observations_by_role)
                return self._record_verified_phase(
                    lab_name, state, LabPhase.ADDONS_READY, observations
                )
            except Exception as error:
                self._mark_degraded(lab_name, state.identity.lab_id, error)
                if isinstance(error, FullLabReconcileError):
                    raise
                raise FullLabReconcileError(
                    f"full lab reconciliation failed: {self._safe_diagnostic(error, limit=1536)}"
                ) from error

    def _break_glass_allowed(
        self, expected: Sequence[ProviderHandle]
    ) -> bool:
        discovery = self._provider.discover(expected)
        if discovery.presence is Presence.UNKNOWN:
            raise FullLabDestroyError(
                "provider discovery is unknown; refusing cleanup"
                + (f": {discovery.detail}" if discovery.detail else "")
            )
        return (
            discovery.presence is Presence.PRESENT
            and 0 < len(discovery.handles) <= len(expected)
            and set(discovery.handles).issubset(set(expected))
        )

    @staticmethod
    def _cleanup_failures(results: Sequence[ProcessResult]) -> Tuple[ProcessResult, ...]:
        return tuple(value for value in results if not value.ok)

    def destroy(
        self,
        lab_name: str,
        *,
        break_glass: bool = False,
        expected_lab_id: Optional[str] = None,
    ) -> LabState:
        validate_identifier(lab_name, field_name="lab name")
        with self._store.lock(lab_name):
            state = self._store.load(lab_name)
            if not state.inventory:
                raise FullLabDestroyError(
                    "refusing destroy because immutable provider inventory is missing"
                )
            expected = tuple(machine.handle for machine in state.inventory)
            if state.phase is LabPhase.DESTROYED:
                discovery = self._provider.discover(expected)
                if discovery.presence is Presence.UNKNOWN:
                    raise FullLabDestroyError(
                        "destroyed tombstone could not be reverified: " + discovery.detail
                    )
                if discovery.presence is not Presence.ABSENT:
                    raise FullLabDestroyError(
                        "destroyed tombstone conflicts with present exact provider handles"
                    )
                return state

            if state.phase is not LabPhase.CLEANUP_PENDING:
                state = self._store.advance(
                    lab_name,
                    state.identity.lab_id,
                    LabPhase.CLEANUP_PENDING,
                    detail="write-ahead exact provider cleanup",
                )

            if break_glass:
                if expected_lab_id is None or expected_lab_id != state.identity.lab_id:
                    raise FullLabDestroyError(
                        "break-glass cleanup requires the exact expected lab UUID"
                    )
                if not self._break_glass_allowed(expected):
                    raise FullLabDestroyError(
                        "break-glass discovery did not prove a bounded subset of exact handles"
                    )
                results = self._store.break_glass_destroy_owned(
                    lab_name, expected_lab_id, self._provider
                )
            else:
                try:
                    results = self._store.destroy_owned(lab_name, self._provider)
                except OwnershipError as error:
                    raise FullLabDestroyError(
                        "ordinary cleanup ownership proof failed: "
                        f"{self._safe_diagnostic(error, limit=768)}; explicit break-glass "
                        "authorization with the exact lab UUID is required"
                    ) from error

            failures = self._cleanup_failures(results)
            discovery = self._provider.discover(expected)
            if discovery.presence is Presence.UNKNOWN:
                raise FullLabDestroyError(
                    "provider discovery is unknown after cleanup; refusing destroyed state"
                    + (f": {discovery.detail}" if discovery.detail else "")
                )
            if failures:
                details = "; ".join(
                    value.diagnostic(limit=512) for value in failures
                )
                raise FullLabDestroyError(
                    f"{len(failures)} provider cleanup operations failed: "
                    f"{self._safe_diagnostic(details, limit=1536)}"
                )
            if discovery.presence is not Presence.ABSENT:
                remaining = ", ".join(handle.value for handle in discovery.handles)
                raise FullLabDestroyError(
                    "exact provider handles remain after cleanup: " + remaining
                )
            return self._store.advance(
                lab_name,
                state.identity.lab_id,
                LabPhase.DESTROYED,
                detail="provider discovery proved every exact handle absent",
            )


__all__ = [
    "FullLabConfig",
    "FullLabDestroyError",
    "FullLabError",
    "FullLabLifecycle",
    "FullLabReconcileError",
    "MACHINE_ROLES",
]
