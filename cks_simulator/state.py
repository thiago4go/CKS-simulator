"""Owned lab identity, inventory, journal, and mutation-lock kernel.

State mutators are deliberately low-level: they do not acquire a hidden lock.
Lifecycle callers must hold :meth:`LabStateStore.lock` across the complete
read/check/provider-mutation/state-update transaction for a lab.
"""

from __future__ import annotations

import errno
import fcntl
import ipaddress
import json
import os
import re
import stat
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .providers.base import (
    Discovery,
    GuestIdentity,
    OwnershipProofMode,
    Presence,
    ProcessResult,
    Provider,
    ProviderHandle,
    ProviderMachine,
    bounded_redacted,
    canonical_uuid,
    derive_provider_handle,
    validate_identifier,
)


MANAGED_BY = "cks-simulator"
SCHEMA_VERSION = 1
MAX_STATE_BYTES = 1024 * 1024
_FULL_LIMA_ROLES = ("candidate", "control-plane", "worker1", "worker2")
_DESTROY_ROLE_ORDER = {"worker2": 0, "worker1": 1, "control-plane": 2, "candidate": 3}
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAC_PATTERN = re.compile(
    r"^(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|"
    r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})$"
)
_SCENARIO_ID_PATTERN = re.compile(r"^(?:0[1-9]|1[0-7])$")
_HANDLER_ID_PATTERN = re.compile(r"^full\.s(?:0[1-9]|1[0-7])\.v[1-9][0-9]*$")
_STATE_WRITES_PROHIBITED: ContextVar[bool] = ContextVar(
    "cks_state_writes_prohibited", default=False
)


class StateError(RuntimeError):
    """Base class for state-kernel failures."""


class StateMissingError(StateError):
    pass


class StateExistsError(StateError):
    pass


class StateValidationError(StateError):
    pass


class OwnershipError(StateError):
    pass


class InvalidTransitionError(StateError):
    pass


class LabLockedError(StateError):
    pass


class LabPhase(str, Enum):
    DECLARED = "declared"
    VMS_CREATED = "vms-created"
    OS_READY = "os-ready"
    CLUSTER_READY = "cluster-ready"
    ADDONS_READY = "addons-ready"
    CANDIDATE_READY = "candidate-ready"
    VALIDATED = "validated"
    SCENARIO_PREPARED = "scenario-prepared"
    GRADED = "graded"
    DEGRADED = "degraded"
    CLEANUP_PENDING = "cleanup-pending"
    DESTROYED = "destroyed"


_ALLOWED_TRANSITIONS = {
    LabPhase.DECLARED: {
        LabPhase.VMS_CREATED,
        LabPhase.DEGRADED,
        LabPhase.CLEANUP_PENDING,
        LabPhase.DESTROYED,
    },
    LabPhase.VMS_CREATED: {LabPhase.OS_READY, LabPhase.DEGRADED, LabPhase.CLEANUP_PENDING},
    LabPhase.OS_READY: {LabPhase.CLUSTER_READY, LabPhase.DEGRADED, LabPhase.CLEANUP_PENDING},
    LabPhase.CLUSTER_READY: {LabPhase.ADDONS_READY, LabPhase.DEGRADED, LabPhase.CLEANUP_PENDING},
    LabPhase.ADDONS_READY: {LabPhase.CANDIDATE_READY, LabPhase.DEGRADED, LabPhase.CLEANUP_PENDING},
    LabPhase.CANDIDATE_READY: {LabPhase.VALIDATED, LabPhase.DEGRADED, LabPhase.CLEANUP_PENDING},
    LabPhase.VALIDATED: {
        LabPhase.SCENARIO_PREPARED,
        LabPhase.DEGRADED,
        LabPhase.CLEANUP_PENDING,
        LabPhase.DESTROYED,
    },
    LabPhase.SCENARIO_PREPARED: {
        LabPhase.VALIDATED,
        # Retained only so pre-U6 journals remain readable for recovery and
        # cleanup. New code cannot append GRADED through ``advance``.
        LabPhase.GRADED,
        LabPhase.DEGRADED,
        LabPhase.CLEANUP_PENDING,
    },
    LabPhase.GRADED: {LabPhase.VALIDATED, LabPhase.DEGRADED, LabPhase.CLEANUP_PENDING},
    # These recovery edges are valid in persisted history, but ordinary
    # ``advance`` rejects them. Only ``recover_verified_phase`` may append one.
    LabPhase.DEGRADED: {
        LabPhase.VMS_CREATED,
        LabPhase.OS_READY,
        LabPhase.CLUSTER_READY,
        LabPhase.ADDONS_READY,
        # Only ``restore_scenario`` may use this edge for an authenticated
        # active attempt after exact baseline re-attestation.
        LabPhase.VALIDATED,
        LabPhase.CLEANUP_PENDING,
    },
    LabPhase.CLEANUP_PENDING: {LabPhase.DESTROYED},
    LabPhase.DESTROYED: set(),
}
_U4_VERIFIED_PHASES = frozenset(
    {
        LabPhase.VMS_CREATED,
        LabPhase.OS_READY,
        LabPhase.CLUSTER_READY,
        LabPhase.ADDONS_READY,
    }
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@contextmanager
def state_write_prohibited():
    """Process-context capability guard used by read-only grading probes."""

    token = _STATE_WRITES_PROHIBITED.set(True)
    try:
        yield
    finally:
        _STATE_WRITES_PROHIBITED.reset(token)


def _require_state_writes_allowed() -> None:
    if _STATE_WRITES_PROHIBITED.get():
        raise StateValidationError("persistent state mutation is prohibited during grading")


@dataclass(frozen=True)
class LabIdentity:
    lab_name: str
    lab_id: str
    provider: str
    namespace: str
    managed_by: str = MANAGED_BY
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.lab_name, field_name="lab name")
        canonical_uuid(self.lab_id, field_name="lab_id")
        validate_identifier(self.provider, field_name="provider")
        validate_identifier(self.namespace, field_name="state namespace")
        if self.managed_by != MANAGED_BY:
            raise OwnershipError("state is not managed by cks-simulator")
        if self.schema_version != SCHEMA_VERSION:
            raise StateValidationError(f"unsupported state schema {self.schema_version!r}")


@dataclass(frozen=True)
class JournalEntry:
    sequence: int
    phase: LabPhase
    recorded_at: str
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or self.sequence < 0:
            raise StateValidationError("journal sequence must be a non-negative integer")
        if not isinstance(self.phase, LabPhase):
            raise StateValidationError("journal phase is invalid")
        if not isinstance(self.recorded_at, str) or not self.recorded_at:
            raise StateValidationError("journal timestamp is missing")
        object.__setattr__(self, "detail", bounded_redacted(self.detail, limit=2048))


def _canonical_product_uuid(value: object) -> str:
    if not isinstance(value, str) or len(value) > 36:
        raise StateValidationError("product UUID must be a bounded UUID string")
    try:
        canonical = str(uuid.UUID(value))
    except (AttributeError, ValueError) as error:
        raise StateValidationError("product UUID is invalid") from error
    if uuid.UUID(canonical).int == 0:
        raise StateValidationError("product UUID must not be nil")
    return canonical


def _canonical_ipv4(value: object) -> str:
    if not isinstance(value, str) or len(value) > 15:
        raise StateValidationError("machine IPv4 must be a bounded IPv4 string")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise StateValidationError("machine IPv4 is invalid") from error
    canonical = str(address)
    if value != canonical:
        raise StateValidationError("machine IPv4 must use canonical dotted-decimal form")
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or canonical == "255.255.255.255"
    ):
        raise StateValidationError("machine IPv4 must be a usable unicast address")
    return canonical


def _normalized_mac(value: object) -> str:
    if not isinstance(value, str) or len(value) > 17:
        raise StateValidationError("machine MAC must be a bounded MAC string")
    if _MAC_PATTERN.fullmatch(value) is None:
        raise StateValidationError("machine MAC is invalid")
    compact = value.replace(":", "").replace("-", "")
    octets = tuple(int(compact[index : index + 2], 16) for index in range(0, 12, 2))
    if not any(octets) or all(octet == 0xFF for octet in octets) or octets[0] & 1:
        raise StateValidationError("machine MAC must be a non-zero unicast address")
    return ":".join(f"{octet:02x}" for octet in octets)


@dataclass(frozen=True)
class MachineObservation:
    """Bounded durable facts observed from one exact full-lab VM."""

    role: str
    machine_id: str
    handle: ProviderHandle
    ipv4: str
    mac_address: str
    product_uuid: str
    provisioning_bundle_sha256: str
    provisioning_spec_sha256: str

    def __post_init__(self) -> None:
        try:
            validate_identifier(self.role, field_name="machine observation role")
            canonical_uuid(self.machine_id, field_name="machine observation machine_id")
        except ValueError as error:
            raise StateValidationError("machine observation identity is invalid") from error
        if not isinstance(self.handle, ProviderHandle):
            raise StateValidationError("machine observation handle is invalid")
        object.__setattr__(self, "ipv4", _canonical_ipv4(self.ipv4))
        object.__setattr__(self, "mac_address", _normalized_mac(self.mac_address))
        object.__setattr__(self, "product_uuid", _canonical_product_uuid(self.product_uuid))
        if (
            not isinstance(self.provisioning_bundle_sha256, str)
            or _SHA256_PATTERN.fullmatch(self.provisioning_bundle_sha256) is None
        ):
            raise StateValidationError(
                "provisioning bundle SHA-256 must be 64 lowercase hexadecimal characters"
            )
        if (
            not isinstance(self.provisioning_spec_sha256, str)
            or _SHA256_PATTERN.fullmatch(self.provisioning_spec_sha256) is None
        ):
            raise StateValidationError(
                "provisioning spec SHA-256 must be 64 lowercase hexadecimal characters"
            )


@dataclass(frozen=True)
class ActiveScenario:
    """Host-owned identity for the one prepared full-tier scenario."""

    scenario_id: str
    attempt_id: str
    handler_identity: str
    recovery_class: str
    target_role: str
    baseline_fingerprint: str
    prepared_fingerprint: str
    restore_fingerprint: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.scenario_id, str)
            or _SCENARIO_ID_PATTERN.fullmatch(self.scenario_id) is None
        ):
            raise StateValidationError("active scenario ID must be canonical from 01 through 17")
        try:
            canonical_uuid(self.attempt_id, field_name="scenario attempt ID")
            validate_identifier(self.recovery_class, field_name="scenario recovery class")
            validate_identifier(self.target_role, field_name="scenario target role")
        except ValueError as error:
            raise StateValidationError("active scenario identity is invalid") from error
        if (
            not isinstance(self.handler_identity, str)
            or _HANDLER_ID_PATTERN.fullmatch(self.handler_identity) is None
            or self.handler_identity[6:8] != self.scenario_id
        ):
            raise StateValidationError("active scenario handler identity is invalid")
        for name, value in (
            ("baseline", self.baseline_fingerprint),
            ("prepared", self.prepared_fingerprint),
            ("restore", self.restore_fingerprint),
        ):
            if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
                raise StateValidationError(
                    f"active scenario {name} fingerprint must be canonical SHA-256"
                )


@dataclass(frozen=True)
class LabState:
    identity: LabIdentity
    inventory: Tuple[ProviderMachine, ...]
    journal: Tuple[JournalEntry, ...]
    observations: Tuple[MachineObservation, ...] = ()
    provisioning_profile: Optional[str] = None
    provisioning_spec_sha256: Optional[str] = None
    health_fingerprint: Optional[str] = None
    active_scenario: Optional[ActiveScenario] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "inventory", tuple(self.inventory))
        object.__setattr__(self, "journal", tuple(self.journal))
        object.__setattr__(self, "observations", tuple(self.observations))
        if self.provisioning_profile is not None:
            validate_identifier(
                self.provisioning_profile, field_name="provisioning profile"
            )
        if self.provisioning_spec_sha256 is not None and (
            not isinstance(self.provisioning_spec_sha256, str)
            or _SHA256_PATTERN.fullmatch(self.provisioning_spec_sha256) is None
        ):
            raise StateValidationError(
                "lab provisioning spec SHA-256 must be canonical when present"
            )
        if self.health_fingerprint is not None and (
            not isinstance(self.health_fingerprint, str)
            or _SHA256_PATTERN.fullmatch(self.health_fingerprint) is None
        ):
            raise StateValidationError("lab health fingerprint must be canonical when present")
        if self.active_scenario is not None and not isinstance(
            self.active_scenario, ActiveScenario
        ):
            raise StateValidationError("active scenario record is invalid")
        if not self.journal or self.journal[0].phase is not LabPhase.DECLARED:
            raise StateValidationError("journal must begin in declared phase")
        if [entry.sequence for entry in self.journal] != list(range(len(self.journal))):
            raise StateValidationError("journal sequences must be contiguous from zero")
        for previous, current in zip(self.journal, self.journal[1:]):
            if current.phase not in _ALLOWED_TRANSITIONS[previous.phase]:
                raise StateValidationError(
                    f"invalid persisted phase transition {previous.phase.value} -> {current.phase.value}"
                )
        roles = [machine.role for machine in self.inventory]
        machine_ids = [machine.machine_id for machine in self.inventory]
        handles = [machine.handle for machine in self.inventory]
        if len(roles) != len(set(roles)):
            raise StateValidationError("inventory roles must be unique")
        if len(machine_ids) != len(set(machine_ids)):
            raise StateValidationError("inventory machine identities must be unique")
        if len(handles) != len(set(handles)):
            raise StateValidationError("inventory provider handles must be unique")
        if any(machine.handle.provider != self.identity.provider for machine in self.inventory):
            raise StateValidationError("inventory handle provider does not match lab identity")
        _validate_derived_inventory(self)
        if self.observations:
            object.__setattr__(
                self,
                "observations",
                _validated_observation_tuple(
                    self.identity.provider, self.inventory, self.observations
                ),
            )
        if self.phase is LabPhase.VALIDATED and self.active_scenario is not None:
            raise StateValidationError(
                "validated state cannot retain an active scenario"
            )
        # Before U6 these phases existed without durable health/attempt fields.
        # Such state remains readable only for fresh attestation or cleanup;
        # scenario operations still fail closed when the fields are absent.
        if (
            self.phase is LabPhase.SCENARIO_PREPARED
            and self.active_scenario is None
            and self.health_fingerprint is not None
        ):
            raise StateValidationError(
                "scenario-prepared state with a health baseline requires an active scenario"
            )
        if self.active_scenario is not None and self.health_fingerprint is None:
            raise StateValidationError("active scenario requires a lab health fingerprint")
        if (
            self.active_scenario is not None
            and self.active_scenario.baseline_fingerprint != self.health_fingerprint
        ):
            raise StateValidationError("active scenario baseline does not match lab health")

    @property
    def phase(self) -> LabPhase:
        return self.journal[-1].phase

    def with_inventory(self, inventory: Sequence[ProviderMachine]) -> "LabState":
        return replace(self, inventory=tuple(inventory))

    def with_observations(
        self, observations: Sequence[MachineObservation]
    ) -> "LabState":
        return replace(self, observations=tuple(observations))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity": {
                "lab_name": self.identity.lab_name,
                "lab_id": self.identity.lab_id,
                "provider": self.identity.provider,
                "namespace": self.identity.namespace,
                "managed_by": self.identity.managed_by,
                "schema_version": self.identity.schema_version,
            },
            "provisioning_profile": self.provisioning_profile,
            "provisioning_spec_sha256": self.provisioning_spec_sha256,
            "health_fingerprint": self.health_fingerprint,
            "active_scenario": (
                {
                    "scenario_id": self.active_scenario.scenario_id,
                    "attempt_id": self.active_scenario.attempt_id,
                    "handler_identity": self.active_scenario.handler_identity,
                    "recovery_class": self.active_scenario.recovery_class,
                    "target_role": self.active_scenario.target_role,
                    "baseline_fingerprint": self.active_scenario.baseline_fingerprint,
                    "prepared_fingerprint": self.active_scenario.prepared_fingerprint,
                    "restore_fingerprint": self.active_scenario.restore_fingerprint,
                }
                if self.active_scenario is not None
                else None
            ),
            "inventory": [
                {
                    "role": machine.role,
                    "machine_id": machine.machine_id,
                    "handle": {
                        "provider": machine.handle.provider,
                        "value": machine.handle.value,
                    },
                }
                for machine in self.inventory
            ],
            "observations": [
                {
                    "role": observation.role,
                    "machine_id": observation.machine_id,
                    "handle": {
                        "provider": observation.handle.provider,
                        "value": observation.handle.value,
                    },
                    "ipv4": observation.ipv4,
                    "mac_address": observation.mac_address,
                    "product_uuid": observation.product_uuid,
                    "provisioning_bundle_sha256": observation.provisioning_bundle_sha256,
                    "provisioning_spec_sha256": observation.provisioning_spec_sha256,
                }
                for observation in self.observations
            ],
            "journal": [
                {
                    "sequence": entry.sequence,
                    "phase": entry.phase.value,
                    "recorded_at": entry.recorded_at,
                    "detail": entry.detail,
                }
                for entry in self.journal
            ],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "LabState":
        try:
            identity_value = payload["identity"]
            inventory_value = payload["inventory"]
            observations_value = payload.get("observations", ())
            journal_value = payload["journal"]
            if not isinstance(identity_value, Mapping):
                raise TypeError("identity")
            identity = LabIdentity(
                lab_name=identity_value["lab_name"],
                lab_id=identity_value["lab_id"],
                provider=identity_value["provider"],
                namespace=identity_value["namespace"],
                managed_by=identity_value["managed_by"],
                schema_version=identity_value["schema_version"],
            )
            inventory = tuple(
                ProviderMachine(
                    role=item["role"],
                    machine_id=item["machine_id"],
                    handle=ProviderHandle(
                        provider=item["handle"]["provider"], value=item["handle"]["value"]
                    ),
                )
                for item in inventory_value
            )
            journal = tuple(
                JournalEntry(
                    sequence=item["sequence"],
                    phase=LabPhase(item["phase"]),
                    recorded_at=item["recorded_at"],
                    detail=item.get("detail", ""),
                )
                for item in journal_value
            )
            observations = tuple(
                MachineObservation(
                    role=item["role"],
                    machine_id=item["machine_id"],
                    handle=ProviderHandle(
                        provider=item["handle"]["provider"],
                        value=item["handle"]["value"],
                    ),
                    ipv4=item["ipv4"],
                    mac_address=item["mac_address"],
                    product_uuid=item["product_uuid"],
                    provisioning_bundle_sha256=item["provisioning_bundle_sha256"],
                    provisioning_spec_sha256=item.get(
                        "provisioning_spec_sha256",
                        item["provisioning_bundle_sha256"],
                    ),
                )
                for item in observations_value
            )
            active_value = payload.get("active_scenario")
            if active_value is not None and not isinstance(active_value, Mapping):
                raise TypeError("active_scenario")
            active_scenario = (
                ActiveScenario(
                    scenario_id=active_value["scenario_id"],
                    attempt_id=active_value["attempt_id"],
                    handler_identity=active_value["handler_identity"],
                    recovery_class=active_value["recovery_class"],
                    target_role=active_value["target_role"],
                    baseline_fingerprint=active_value["baseline_fingerprint"],
                    prepared_fingerprint=active_value["prepared_fingerprint"],
                    restore_fingerprint=active_value["restore_fingerprint"],
                )
                if active_value is not None
                else None
            )
            return cls(
                identity=identity,
                inventory=inventory,
                journal=journal,
                observations=observations,
                provisioning_profile=payload.get("provisioning_profile"),
                provisioning_spec_sha256=payload.get("provisioning_spec_sha256"),
                health_fingerprint=payload.get("health_fingerprint"),
                active_scenario=active_scenario,
            )
        except OwnershipError:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise StateValidationError("state has an invalid or incomplete schema") from error


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise StateValidationError(f"refusing symlinked state directory: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _validate_derived_inventory(state: LabState) -> None:
    """Reject mutable inventory that is not derived from immutable lab identity."""

    for machine in state.inventory:
        try:
            expected = derive_provider_handle(
                state.identity.provider, state.identity.lab_id, machine.role
            )
        except ValueError as error:
            raise StateValidationError("inventory uses an unsupported provider policy") from error
        if machine.handle != expected:
            raise StateValidationError(
                f"inventory handle for role {machine.role!r} is not derived from lab identity"
            )


def _validated_observation_tuple(
    provider: str,
    inventory: Sequence[ProviderMachine],
    observations: Sequence[MachineObservation],
) -> Tuple[MachineObservation, ...]:
    """Validate and order one complete, exact full-Lima observation set."""

    inventory_value = tuple(inventory)
    if provider != "lima":
        raise StateValidationError("machine observations are supported only for the full Lima lab")
    if tuple(sorted(machine.role for machine in inventory_value)) != tuple(
        sorted(_FULL_LIMA_ROLES)
    ):
        raise StateValidationError(
            "full Lima inventory must use candidate, control-plane, worker1, and worker2"
        )
    try:
        observation_count = len(observations)
    except TypeError as error:
        raise StateValidationError("machine observations must be a bounded sequence") from error
    if observation_count != len(_FULL_LIMA_ROLES):
        raise StateValidationError("machine observations must contain all four full-Lima machines")
    observation_value = tuple(observations)
    if any(not isinstance(observation, MachineObservation) for observation in observation_value):
        raise StateValidationError("machine observations contain an invalid entry")

    for field_name, values in (
        ("roles", [observation.role for observation in observation_value]),
        ("machine identities", [observation.machine_id for observation in observation_value]),
        ("provider handles", [observation.handle for observation in observation_value]),
        ("IPv4 addresses", [observation.ipv4 for observation in observation_value]),
        ("MAC addresses", [observation.mac_address for observation in observation_value]),
        ("product UUIDs", [observation.product_uuid for observation in observation_value]),
    ):
        if len(values) != len(set(values)):
            raise StateValidationError(f"machine observation {field_name} must be unique")

    inventory_by_role = {machine.role: machine for machine in inventory_value}
    observations_by_role = {observation.role: observation for observation in observation_value}
    if set(observations_by_role) != set(inventory_by_role):
        raise StateValidationError("machine observation roles do not match immutable inventory")
    ordered = []
    for role in _FULL_LIMA_ROLES:
        machine = inventory_by_role[role]
        observation = observations_by_role[role]
        if (
            observation.role != machine.role
            or observation.machine_id != machine.machine_id
            or observation.handle != machine.handle
        ):
            raise StateValidationError(
                f"machine observation identity does not match immutable inventory for {role!r}"
            )
        ordered.append(observation)
    return tuple(ordered)


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_directory(path_or_name: str, *, dir_fd: Optional[int] = None) -> int:
    try:
        descriptor = os.open(path_or_name, _directory_open_flags(), dir_fd=dir_fd)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise StateValidationError("refusing unsafe state directory") from error
        raise
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise StateValidationError("refusing non-directory state ancestor")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_or_create_directory(parent_descriptor: int, name: str, *, create: bool) -> int:
    try:
        descriptor = _open_directory(name, dir_fd=parent_descriptor)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
        descriptor = _open_directory(name, dir_fd=parent_descriptor)
    if create:
        os.fchmod(descriptor, 0o700)
    return descriptor


def _directory_identity(descriptor: int) -> Tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise StateValidationError("refusing non-directory state ancestor")
    return metadata.st_dev, metadata.st_ino


@dataclass(frozen=True)
class _DirectoryEntry:
    parent_descriptor: int
    name: str
    descriptor: int
    identity: Tuple[int, int]


class _StateDirectoryChain:
    def __init__(self, descriptors: Sequence[int], entries: Sequence[_DirectoryEntry]) -> None:
        self.descriptors = tuple(descriptors)
        self.entries = tuple(entries)

    @property
    def lab_descriptor(self) -> int:
        return self.entries[-1].descriptor

    def verify(self) -> None:
        """Prove every pathname still names the directory opened initially."""

        for entry in self.entries:
            try:
                observed = os.stat(
                    entry.name,
                    dir_fd=entry.parent_descriptor,
                    follow_symlinks=False,
                )
            except (FileNotFoundError, OSError) as error:
                raise StateValidationError(
                    "state directory identity changed during persistence"
                ) from error
            if (
                not stat.S_ISDIR(observed.st_mode)
                or (observed.st_dev, observed.st_ino) != entry.identity
                or _directory_identity(entry.descriptor) != entry.identity
            ):
                raise StateValidationError(
                    "state directory identity changed during persistence"
                )


@contextmanager
def _state_directory_chain(
    root: Path,
    namespace: str,
    lab_name: str,
    *,
    create: bool,
):
    descriptors = []
    entries = []
    try:
        parent_descriptor = _open_directory(str(root.parent))
        descriptors.append(parent_descriptor)
        root_descriptor = _open_or_create_directory(
            parent_descriptor, root.name, create=create
        )
        descriptors.append(root_descriptor)
        entries.append(
            _DirectoryEntry(
                parent_descriptor,
                root.name,
                root_descriptor,
                _directory_identity(root_descriptor),
            )
        )
        namespace_descriptor = _open_or_create_directory(
            root_descriptor, namespace, create=create
        )
        descriptors.append(namespace_descriptor)
        entries.append(
            _DirectoryEntry(
                root_descriptor,
                namespace,
                namespace_descriptor,
                _directory_identity(namespace_descriptor),
            )
        )
        lab_descriptor = _open_or_create_directory(
            namespace_descriptor, lab_name, create=create
        )
        descriptors.append(lab_descriptor)
        entries.append(
            _DirectoryEntry(
                namespace_descriptor,
                lab_name,
                lab_descriptor,
                _directory_identity(lab_descriptor),
            )
        )
        chain = _StateDirectoryChain(descriptors, entries)
        chain.verify()
        yield chain
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_state_at(lab_descriptor: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open("state.json", flags, dir_fd=lab_descriptor)
    except FileNotFoundError:
        raise
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EISDIR, errno.ENXIO):
            raise StateValidationError("refusing unsafe state file") from error
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise StateValidationError("refusing non-regular state file")
        if metadata.st_size > MAX_STATE_BYTES:
            raise StateValidationError("state file exceeds the maximum size")
        chunks = bytearray()
        while len(chunks) <= MAX_STATE_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_STATE_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > MAX_STATE_BYTES:
            raise StateValidationError("state file exceeds the maximum size")
        return bytes(chunks)
    finally:
        os.close(descriptor)


def _write_temporary_json_at(lab_descriptor: int, payload: Mapping[str, Any]) -> str:
    _require_state_writes_allowed()
    temporary_name = f".state.json.{uuid.uuid4().hex}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(temporary_name, flags, 0o600, dir_fd=lab_descriptor)
    try:
        os.fchmod(descriptor, 0o600)
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
        return temporary_name
    except BaseException:
        try:
            os.unlink(temporary_name, dir_fd=lab_descriptor)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)


def _unlink_at(lab_descriptor: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=lab_descriptor)
    except FileNotFoundError:
        pass


def _atomic_replace_json_at(
    chain: _StateDirectoryChain, payload: Mapping[str, Any]
) -> None:
    _require_state_writes_allowed()
    temporary = _write_temporary_json_at(chain.lab_descriptor, payload)
    try:
        chain.verify()
        os.replace(
            temporary,
            "state.json",
            src_dir_fd=chain.lab_descriptor,
            dst_dir_fd=chain.lab_descriptor,
        )
        os.fsync(chain.lab_descriptor)
        chain.verify()
    finally:
        _unlink_at(chain.lab_descriptor, temporary)
        os.fsync(chain.lab_descriptor)


def _atomic_create_json_at(
    chain: _StateDirectoryChain, payload: Mapping[str, Any], lab_name: str
) -> None:
    _require_state_writes_allowed()
    temporary = _write_temporary_json_at(chain.lab_descriptor, payload)
    try:
        chain.verify()
        try:
            os.link(
                temporary,
                "state.json",
                src_dir_fd=chain.lab_descriptor,
                dst_dir_fd=chain.lab_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise StateExistsError(f"state already exists for {lab_name!r}") from error
        os.fsync(chain.lab_descriptor)
        chain.verify()
    finally:
        _unlink_at(chain.lab_descriptor, temporary)
        os.fsync(chain.lab_descriptor)


class _LockDirectoryChain(_StateDirectoryChain):
    @property
    def root_descriptor(self) -> int:
        return self.entries[0].descriptor

    @property
    def namespace_descriptor(self) -> int:
        return self.entries[-1].descriptor

    def verify(self) -> None:
        try:
            super().verify()
        except StateValidationError as error:
            raise StateValidationError(
                "lock directory identity changed while mutation lock was held"
            ) from error


def _require_private_owned_directory(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise StateValidationError(
            "lock directories must be owner-controlled with mode 0700"
        )


class LabMutatorLock:
    def __init__(
        self,
        root: Path,
        namespace: str,
        lab_name: str,
        *,
        blocking: bool,
    ) -> None:
        self.root = root
        self.namespace = validate_identifier(namespace, field_name="state namespace")
        self.lab_name = validate_identifier(lab_name, field_name="lab name")
        self.path = root / ".locks" / namespace / f"{lab_name}.lock"
        self.blocking = blocking
        self._descriptor: Optional[int] = None
        self._chain: Optional[_LockDirectoryChain] = None
        self._lock_identity: Optional[Tuple[int, int]] = None

    def _operation(self) -> int:
        return fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB)

    def _locked_error(self, error: OSError) -> LabLockedError:
        return LabLockedError(f"lab {self.lab_name!r} is being mutated")

    def _verify_lock_file(self) -> None:
        if self._descriptor is None or self._chain is None or self._lock_identity is None:
            raise StateValidationError("mutation lock is not fully initialized")
        self._chain.verify()
        try:
            observed = os.stat(
                self.path.name,
                dir_fd=self._chain.namespace_descriptor,
                follow_symlinks=False,
            )
        except (FileNotFoundError, OSError) as error:
            raise StateValidationError(
                f"lock file identity changed for lab {self.lab_name!r}"
            ) from error
        opened = os.fstat(self._descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or (observed.st_dev, observed.st_ino) != self._lock_identity
            or (opened.st_dev, opened.st_ino) != self._lock_identity
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
        ):
            raise StateValidationError(
                f"lock file identity changed for lab {self.lab_name!r}"
            )

    @staticmethod
    def _close_chain(chain: Optional[_LockDirectoryChain]) -> None:
        if chain is None:
            return
        for descriptor in reversed(chain.descriptors):
            os.close(descriptor)

    def __enter__(self) -> "LabMutatorLock":
        descriptors = []
        entries = []
        chain: Optional[_LockDirectoryChain] = None
        root_locked = False
        descriptor: Optional[int] = None
        descriptor_locked = False
        try:
            parent_descriptor = _open_directory(str(self.root.parent))
            descriptors.append(parent_descriptor)
            root_descriptor = _open_or_create_directory(
                parent_descriptor, self.root.name, create=True
            )
            descriptors.append(root_descriptor)
            entries.append(
                _DirectoryEntry(
                    parent_descriptor,
                    self.root.name,
                    root_descriptor,
                    _directory_identity(root_descriptor),
                )
            )
            _require_private_owned_directory(root_descriptor)
            try:
                fcntl.flock(root_descriptor, self._operation())
            except OSError as error:
                if error.errno in (errno.EACCES, errno.EAGAIN):
                    raise self._locked_error(error) from error
                raise
            root_locked = True
            locks_descriptor = _open_or_create_directory(
                root_descriptor, ".locks", create=True
            )
            descriptors.append(locks_descriptor)
            entries.append(
                _DirectoryEntry(
                    root_descriptor,
                    ".locks",
                    locks_descriptor,
                    _directory_identity(locks_descriptor),
                )
            )
            namespace_descriptor = _open_or_create_directory(
                locks_descriptor, self.namespace, create=True
            )
            descriptors.append(namespace_descriptor)
            entries.append(
                _DirectoryEntry(
                    locks_descriptor,
                    self.namespace,
                    namespace_descriptor,
                    _directory_identity(namespace_descriptor),
                )
            )
            for directory_descriptor in (
                locks_descriptor,
                namespace_descriptor,
            ):
                _require_private_owned_directory(directory_descriptor)
            chain = _LockDirectoryChain(descriptors, entries)
            chain.verify()

            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_NONBLOCK"):
                flags |= os.O_NONBLOCK
            descriptor = os.open(
                self.path.name,
                flags,
                0o600,
                dir_fd=namespace_descriptor,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise StateValidationError(
                    f"refusing unsafe lock file for lab {self.lab_name!r}"
                )
            os.fchmod(descriptor, 0o600)
            self._descriptor = descriptor
            self._chain = chain
            self._lock_identity = (metadata.st_dev, metadata.st_ino)
            try:
                fcntl.flock(descriptor, self._operation())
            except OSError as error:
                if error.errno in (errno.EACCES, errno.EAGAIN):
                    raise self._locked_error(error) from error
                raise
            descriptor_locked = True
            self._verify_lock_file()
            return self
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.EISDIR, errno.ENXIO):
                failure: BaseException = StateValidationError(
                    f"refusing unsafe lock path for lab {self.lab_name!r}"
                )
                failure.__cause__ = error
            else:
                failure = error
            if descriptor is not None:
                os.close(descriptor)
            if root_locked and descriptors:
                fcntl.flock(descriptors[1], fcntl.LOCK_UN)
            for opened in reversed(descriptors):
                os.close(opened)
            self._descriptor = None
            self._chain = None
            self._lock_identity = None
            raise failure
        except BaseException:
            if descriptor is not None:
                try:
                    if descriptor_locked:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)
            if root_locked and len(descriptors) > 1:
                fcntl.flock(descriptors[1], fcntl.LOCK_UN)
            for opened in reversed(descriptors):
                os.close(opened)
            self._descriptor = None
            self._chain = None
            self._lock_identity = None
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        verification_error: Optional[BaseException] = None
        if self._descriptor is not None:
            try:
                self._verify_lock_file()
            except BaseException as error:
                verification_error = error
            finally:
                try:
                    fcntl.flock(self._descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(self._descriptor)
                self._descriptor = None
        if self._chain is not None:
            try:
                fcntl.flock(self._chain.root_descriptor, fcntl.LOCK_UN)
            finally:
                self._close_chain(self._chain)
                self._chain = None
                self._lock_identity = None
        if verification_error is not None and exc_type is None:
            raise verification_error


class LabStateStore:
    """Namespace-scoped state store; quick and full state can never be adopted.

    State mutators intentionally do not lock themselves. A lifecycle caller
    must hold ``with store.lock(lab_name):`` around the whole operation,
    including provider discovery, ownership checks, provider mutations, and the
    final state write. Keeping the lock at that boundary avoids hidden
    re-entrant locking and prevents check/use gaps.
    """

    def __init__(self, root: Path, *, namespace: str) -> None:
        validate_identifier(namespace, field_name="state namespace")
        self.root = Path(root).expanduser().resolve()
        self.namespace = namespace

    @property
    def namespace_path(self) -> Path:
        return self.root / self.namespace

    def state_path(self, lab_name: str) -> Path:
        validate_identifier(lab_name, field_name="lab name")
        path = self.namespace_path / lab_name / "state.json"
        try:
            path.relative_to(self.root)
        except ValueError as error:
            raise ValueError("state path escapes configured root") from error
        return path

    def lock(self, lab_name: str, *, blocking: bool = True) -> LabMutatorLock:
        validate_identifier(lab_name, field_name="lab name")
        return LabMutatorLock(
            self.root,
            self.namespace,
            lab_name,
            blocking=blocking,
        )

    def claim(self, lab_name: str, *, provider: str) -> LabState:
        """Create the write-ahead identity; the caller must hold the lab lock."""

        _require_state_writes_allowed()
        validate_identifier(lab_name, field_name="lab name")
        validate_identifier(provider, field_name="provider")
        state = LabState(
            identity=LabIdentity(
                lab_name=lab_name,
                lab_id=str(uuid.uuid4()),
                provider=provider,
                namespace=self.namespace,
            ),
            inventory=(),
            journal=(JournalEntry(0, LabPhase.DECLARED, _now()),),
        )
        with _state_directory_chain(
            self.root, self.namespace, lab_name, create=True
        ) as chain:
            _atomic_create_json_at(chain, state.to_dict(), lab_name)
        return state

    def _load_from_chain(
        self, lab_name: str, chain: _StateDirectoryChain
    ) -> LabState:
        try:
            chain.verify()
            encoded = _read_state_at(chain.lab_descriptor)
            chain.verify()
            payload = json.loads(encoded.decode("utf-8"))
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise StateValidationError(f"state is unreadable for {lab_name!r}") from error
        if not isinstance(payload, Mapping):
            raise StateValidationError("state root must be a JSON object")
        state = LabState.from_dict(payload)
        if state.identity.lab_name != lab_name:
            raise OwnershipError(
                f"state identity {state.identity.lab_name!r} does not match requested lab {lab_name!r}"
            )
        if state.identity.namespace != self.namespace:
            raise OwnershipError("state namespace does not match this store")
        return state

    def load(self, lab_name: str) -> LabState:
        validate_identifier(lab_name, field_name="lab name")
        try:
            with _state_directory_chain(
                self.root, self.namespace, lab_name, create=False
            ) as chain:
                return self._load_from_chain(lab_name, chain)
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error

    @staticmethod
    def _require_identity(state: LabState, expected_lab_id: str) -> None:
        try:
            canonical_uuid(expected_lab_id, field_name="expected_lab_id")
        except ValueError as error:
            raise OwnershipError("expected lab identity is invalid") from error
        if state.identity.lab_id != expected_lab_id:
            raise OwnershipError("state lab identity does not match the caller's immutable claim")

    def declare_inventory(
        self,
        lab_name: str,
        expected_lab_id: str,
        inventory: Sequence[ProviderMachine],
    ) -> LabState:
        """Persist immutable inventory; the caller must hold the lab lock."""

        validate_identifier(lab_name, field_name="lab name")
        try:
            with _state_directory_chain(
                self.root, self.namespace, lab_name, create=False
            ) as chain:
                state = self._load_from_chain(lab_name, chain)
                _validate_derived_inventory(state)
                self._require_identity(state, expected_lab_id)
                if state.phase is not LabPhase.DECLARED:
                    raise StateValidationError(
                        "inventory can only be declared in the declared phase"
                    )
                if state.inventory:
                    raise StateValidationError("inventory is immutable once declared")
                inventory_value = tuple(inventory)
                if not inventory_value:
                    raise StateValidationError(
                        "inventory must declare at least one machine before creation"
                    )
                updated = state.with_inventory(inventory_value)
                _atomic_replace_json_at(chain, updated.to_dict())
                return updated
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error

    def bind_provisioning_spec(
        self,
        lab_name: str,
        expected_lab_id: str,
        provisioning_spec_sha256: str,
    ) -> LabState:
        """Bind immutable full-lab inputs before any provider mutation."""

        validate_identifier(lab_name, field_name="lab name")
        if (
            not isinstance(provisioning_spec_sha256, str)
            or _SHA256_PATTERN.fullmatch(provisioning_spec_sha256) is None
        ):
            raise StateValidationError("provisioning spec SHA-256 must be canonical")
        try:
            with _state_directory_chain(
                self.root, self.namespace, lab_name, create=False
            ) as chain:
                state = self._load_from_chain(lab_name, chain)
                self._require_identity(state, expected_lab_id)
                if state.provisioning_spec_sha256 is not None:
                    if state.provisioning_spec_sha256 != provisioning_spec_sha256:
                        raise StateValidationError(
                            "immutable provisioning specification drift detected"
                        )
                    return state
                if state.inventory or state.observations:
                    raise StateValidationError(
                        "legacy state has provider inventory without a bound provisioning "
                        "specification; explicit rebuild is required"
                    )
                updated = replace(
                    state, provisioning_spec_sha256=provisioning_spec_sha256
                )
                _atomic_replace_json_at(chain, updated.to_dict())
                return updated
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error

    def bind_provisioning_profile(
        self,
        lab_name: str,
        expected_lab_id: str,
        provisioning_profile: str,
    ) -> LabState:
        """Bind the selected resource profile before spec or inventory mutation."""

        validate_identifier(lab_name, field_name="lab name")
        validate_identifier(provisioning_profile, field_name="provisioning profile")
        try:
            with _state_directory_chain(
                self.root, self.namespace, lab_name, create=False
            ) as chain:
                state = self._load_from_chain(lab_name, chain)
                self._require_identity(state, expected_lab_id)
                if state.provisioning_profile is not None:
                    if state.provisioning_profile != provisioning_profile:
                        raise StateValidationError(
                            "immutable provisioning profile drift detected"
                        )
                    return state
                if state.provisioning_spec_sha256 is not None or state.inventory:
                    raise StateValidationError(
                        "provisioning profile must be bound before specification and inventory"
                    )
                updated = replace(
                    state, provisioning_profile=provisioning_profile
                )
                _atomic_replace_json_at(chain, updated.to_dict())
                return updated
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error

    def record_machine_observations(
        self,
        lab_name: str,
        expected_lab_id: str,
        observations: Sequence[MachineObservation],
    ) -> LabState:
        """Atomically persist one complete immutable set of verified VM facts.

        The caller must hold the lab lock while collecting all four observations
        and through this write. A normalized exact replay is a no-op; any IP,
        hardware identity, inventory identity, or bundle drift fails closed.
        """

        validate_identifier(lab_name, field_name="lab name")
        try:
            with _state_directory_chain(
                self.root, self.namespace, lab_name, create=False
            ) as chain:
                state = self._load_from_chain(lab_name, chain)
                self._require_identity(state, expected_lab_id)
                normalized = _validated_observation_tuple(
                    state.identity.provider, state.inventory, observations
                )
                if state.observations:
                    if state.observations != normalized:
                        raise StateValidationError(
                            "machine observations are immutable; identity or IP drift detected"
                        )
                    return state
                if state.phase in {LabPhase.CLEANUP_PENDING, LabPhase.DESTROYED}:
                    raise StateValidationError(
                        "machine observations cannot be introduced during or after cleanup"
                    )
                updated = state.with_observations(normalized)
                _atomic_replace_json_at(chain, updated.to_dict())
                return updated
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error

    def attest_validated(
        self,
        lab_name: str,
        expected_lab_id: str,
        health_fingerprint: str,
        *,
        detail: str = "",
    ) -> LabState:
        """Bind a host-observed healthy baseline before scenario mutation."""

        validate_identifier(lab_name, field_name="lab name")
        if (
            not isinstance(health_fingerprint, str)
            or _SHA256_PATTERN.fullmatch(health_fingerprint) is None
        ):
            raise StateValidationError("health fingerprint must be canonical SHA-256")
        try:
            with _state_directory_chain(
                self.root, self.namespace, lab_name, create=False
            ) as chain:
                state = self._load_from_chain(lab_name, chain)
                self._require_identity(state, expected_lab_id)
                if state.phase is LabPhase.VALIDATED:
                    if state.health_fingerprint is None:
                        updated = replace(state, health_fingerprint=health_fingerprint)
                        _atomic_replace_json_at(chain, updated.to_dict())
                        return updated
                    if state.health_fingerprint != health_fingerprint:
                        raise StateValidationError("validated health fingerprint drift detected")
                    return state
                if state.phase is not LabPhase.CANDIDATE_READY:
                    raise InvalidTransitionError(
                        "baseline attestation requires candidate-ready state"
                    )
                if state.active_scenario is not None:
                    raise StateValidationError("cannot attest baseline with an active scenario")
                updated = replace(
                    state,
                    health_fingerprint=health_fingerprint,
                    journal=state.journal
                    + (
                        JournalEntry(
                            len(state.journal),
                            LabPhase.VALIDATED,
                            _now(),
                            detail=detail,
                        ),
                    ),
                )
                _atomic_replace_json_at(chain, updated.to_dict())
                return updated
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error

    def prepare_scenario(
        self,
        lab_name: str,
        expected_lab_id: str,
        *,
        scenario_id: str,
        attempt_id: str,
        handler_identity: str,
        recovery_class: str,
        target_role: str,
        prepared_fingerprint: str,
        restore_fingerprint: str,
        detail: str = "",
    ) -> LabState:
        """Atomically write the one active attempt before guest mutation."""

        validate_identifier(lab_name, field_name="lab name")
        try:
            with _state_directory_chain(
                self.root, self.namespace, lab_name, create=False
            ) as chain:
                state = self._load_from_chain(lab_name, chain)
                self._require_identity(state, expected_lab_id)
                if state.phase is not LabPhase.VALIDATED:
                    raise InvalidTransitionError(
                        "scenario preparation requires validated state"
                    )
                if state.health_fingerprint is None:
                    raise StateValidationError("validated lab is missing its health baseline")
                if state.active_scenario is not None:
                    raise StateValidationError(
                        f"scenario {state.active_scenario.scenario_id} is already active"
                    )
                active = ActiveScenario(
                    scenario_id=scenario_id,
                    attempt_id=attempt_id,
                    handler_identity=handler_identity,
                    recovery_class=recovery_class,
                    target_role=target_role,
                    baseline_fingerprint=state.health_fingerprint,
                    prepared_fingerprint=prepared_fingerprint,
                    restore_fingerprint=restore_fingerprint,
                )
                updated = replace(
                    state,
                    active_scenario=active,
                    journal=state.journal
                    + (
                        JournalEntry(
                            len(state.journal),
                            LabPhase.SCENARIO_PREPARED,
                            _now(),
                            detail=detail,
                        ),
                    ),
                )
                _atomic_replace_json_at(chain, updated.to_dict())
                return updated
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error

    def restore_scenario(
        self,
        lab_name: str,
        expected_lab_id: str,
        *,
        scenario_id: str,
        attempt_id: str,
        health_fingerprint: str,
        scenario_fingerprint: str,
        detail: str = "",
    ) -> LabState:
        """Clear the active scenario only after exact baseline re-attestation."""

        validate_identifier(lab_name, field_name="lab name")
        try:
            with _state_directory_chain(
                self.root, self.namespace, lab_name, create=False
            ) as chain:
                state = self._load_from_chain(lab_name, chain)
                self._require_identity(state, expected_lab_id)
                if state.phase not in {
                    LabPhase.SCENARIO_PREPARED,
                    LabPhase.DEGRADED,
                }:
                    raise InvalidTransitionError(
                        "scenario restore requires prepared or degraded active state"
                    )
                active = state.active_scenario
                if active is None:
                    raise StateValidationError("scenario-prepared state has no active scenario")
                if active.scenario_id != scenario_id or active.attempt_id != attempt_id:
                    raise OwnershipError("active scenario identity does not match restore request")
                if health_fingerprint != active.baseline_fingerprint:
                    raise StateValidationError(
                        "restored health fingerprint does not match the trusted baseline"
                    )
                if scenario_fingerprint != active.restore_fingerprint:
                    raise StateValidationError(
                        "restored scenario fingerprint does not match recovery contract"
                    )
                updated = replace(
                    state,
                    active_scenario=None,
                    health_fingerprint=health_fingerprint,
                    journal=state.journal
                    + (
                        JournalEntry(
                            len(state.journal),
                            LabPhase.VALIDATED,
                            _now(),
                            detail=detail,
                        ),
                    ),
                )
                _atomic_replace_json_at(chain, updated.to_dict())
                return updated
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error

    def advance(
        self,
        lab_name: str,
        expected_lab_id: str,
        phase: LabPhase,
        *,
        detail: str = "",
    ) -> LabState:
        """Append one phase transition; the caller must hold the lab lock."""

        validate_identifier(lab_name, field_name="lab name")
        try:
            with _state_directory_chain(
                self.root, self.namespace, lab_name, create=False
            ) as chain:
                state = self._load_from_chain(lab_name, chain)
                self._require_identity(state, expected_lab_id)
                if not isinstance(phase, LabPhase):
                    raise StateValidationError("target phase is invalid")
                if phase in {
                    LabPhase.VALIDATED,
                    LabPhase.SCENARIO_PREPARED,
                    LabPhase.GRADED,
                }:
                    raise InvalidTransitionError(
                        "scenario phases require the dedicated attestation/lifecycle methods"
                    )
                if state.phase is LabPhase.DEGRADED and phase in _U4_VERIFIED_PHASES:
                    raise InvalidTransitionError(
                        "degraded labs require recover_verified_phase with fresh observations"
                    )
                if phase not in _ALLOWED_TRANSITIONS[state.phase]:
                    raise InvalidTransitionError(
                        f"invalid phase transition {state.phase.value} -> {phase.value}"
                    )
                if phase in _U4_VERIFIED_PHASES and not state.observations:
                    raise StateValidationError(
                        "complete machine observations are required before a verified U4 phase"
                    )
                updated = replace(
                    state,
                    journal=state.journal
                    + (JournalEntry(len(state.journal), phase, _now(), detail=detail),),
                )
                _atomic_replace_json_at(chain, updated.to_dict())
                return updated
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error

    def recover_verified_phase(
        self,
        lab_name: str,
        expected_lab_id: str,
        phase: LabPhase,
        observations: Sequence[MachineObservation],
        *,
        detail: str = "",
    ) -> LabState:
        """Resume a degraded lab only after fresh exact U4 verification.

        The supplied complete observation set is the recovery proof at this
        trust boundary. It is persisted on first recovery or compared against
        the immutable prior set, so IP or hardware identity drift cannot be
        journaled as a successful resume. The caller must hold the lab lock.
        """

        validate_identifier(lab_name, field_name="lab name")
        try:
            with _state_directory_chain(
                self.root, self.namespace, lab_name, create=False
            ) as chain:
                state = self._load_from_chain(lab_name, chain)
                self._require_identity(state, expected_lab_id)
                if not isinstance(phase, LabPhase) or phase not in _U4_VERIFIED_PHASES:
                    raise InvalidTransitionError(
                        "verified recovery target must be vms-created, os-ready, "
                        "cluster-ready, or addons-ready"
                    )
                if state.phase is not LabPhase.DEGRADED:
                    raise InvalidTransitionError(
                        "verified recovery requires the current degraded phase"
                    )
                normalized = _validated_observation_tuple(
                    state.identity.provider, state.inventory, observations
                )
                if state.observations and state.observations != normalized:
                    raise StateValidationError(
                        "machine observations are immutable; identity or IP drift detected"
                    )
                updated = replace(
                    state,
                    observations=state.observations or normalized,
                    journal=state.journal
                    + (JournalEntry(len(state.journal), phase, _now(), detail=detail),),
                )
                _atomic_replace_json_at(chain, updated.to_dict())
                return updated
        except FileNotFoundError as error:
            raise StateMissingError(f"state is missing for {lab_name!r}") from error

    def require_mutation_authority(
        self,
        lab_name: str,
        discovery: Discovery,
        guest_identities: Iterable[GuestIdentity],
    ) -> LabState:
        """Authorize exact mutation only after state/provider/guest agreement.

        The caller must hold the lab lock from discovery through the resulting
        provider mutation and state update.

        ``ABSENT`` authorizes only the no-provider-resource case, enabling an
        idempotent cleanup path.  It never turns a discovery failure into
        absence; ``UNKNOWN`` always refuses.
        """

        state = self.load(lab_name)
        if discovery.presence is Presence.UNKNOWN:
            raise OwnershipError(
                "provider discovery is unknown; refusing mutation"
                + (f": {discovery.detail}" if discovery.detail else "")
            )
        guests = tuple(guest_identities)
        if discovery.presence is Presence.ABSENT:
            if guests:
                raise OwnershipError("provider reports absence but guest identities were supplied")
            return state

        expected_handles = tuple(machine.handle for machine in state.inventory)
        if not expected_handles:
            raise OwnershipError("state has no immutable provider inventory")
        if set(discovery.handles) != set(expected_handles) or len(discovery.handles) != len(
            expected_handles
        ):
            raise OwnershipError("discovered provider handles do not exactly match owned inventory")

        if len(guests) != len(state.inventory):
            raise OwnershipError("every owned provider handle requires one guest identity")
        guest_by_handle: Dict[ProviderHandle, GuestIdentity] = {}
        for guest in guests:
            if guest.handle in guest_by_handle:
                raise OwnershipError("guest identities contain a duplicate provider handle")
            guest_by_handle[guest.handle] = guest
        for machine in state.inventory:
            guest = guest_by_handle.get(machine.handle)
            if guest is None:
                raise OwnershipError(f"guest identity is missing for {machine.handle.value!r}")
            if (
                guest.lab_id != state.identity.lab_id
                or guest.machine_id != machine.machine_id
                or guest.role != machine.role
                or guest.handle != machine.handle
            ):
                raise OwnershipError(f"guest identity mismatch for {machine.handle.value!r}")
        return state

    def destroy_owned(
        self, lab_name: str, provider: Provider
    ) -> Tuple[ProcessResult, ...]:
        """Reconcile all three ownership sources and delete exact owned handles.

        This coordinator is the only public destructive API. The caller must
        hold the lab lock across this operation and the resulting state update.
        Concrete providers expose only a protected exact-delete transport.
        """

        state = self.load(lab_name)
        _validate_derived_inventory(state)
        if provider.name != state.identity.provider:
            raise OwnershipError("provider does not match the immutable lab identity")
        expected = tuple(machine.handle for machine in state.inventory)
        discovery = provider.discover(expected)
        guests: Tuple[GuestIdentity, ...] = ()
        if discovery.presence is Presence.PRESENT:
            observed = []
            machine_by_handle = {machine.handle: machine for machine in state.inventory}
            for handle in discovery.handles:
                machine = machine_by_handle.get(handle)
                if machine is None:
                    raise OwnershipError(
                        f"provider discovery contains an unrecorded handle {handle.value!r}"
                    )
                identity = GuestIdentity(
                    state.identity.lab_id,
                    machine.machine_id,
                    machine.role,
                    machine.handle,
                )
                if not provider.prove_ownership(
                    identity, mode=OwnershipProofMode.ORDINARY
                ):
                    raise OwnershipError(
                        f"provider ownership proof failed for {handle.value!r}"
                    )
                observed.append(identity)
            guests = tuple(observed)
        authorized = self.require_mutation_authority(lab_name, discovery, guests)
        if discovery.presence is not Presence.PRESENT:
            return ()
        deletion_order = sorted(
            authorized.inventory,
            key=lambda machine: _DESTROY_ROLE_ORDER.get(machine.role, -1),
        )
        return tuple(provider._delete_exact(machine.handle) for machine in deletion_order)

    def break_glass_destroy_owned(
        self,
        lab_name: str,
        expected_lab_id: str,
        provider: Provider,
    ) -> Tuple[ProcessResult, ...]:
        """Delete only discovered recorded handles after a degraded transition."""

        state = self.load(lab_name)
        self._require_identity(state, expected_lab_id)
        if state.phase not in {LabPhase.DEGRADED, LabPhase.CLEANUP_PENDING}:
            raise OwnershipError("break-glass cleanup requires a degraded or cleanup-pending lab")
        if not state.inventory:
            raise OwnershipError("break-glass cleanup requires immutable provider inventory")
        _validate_derived_inventory(state)
        if provider.name != state.identity.provider:
            raise OwnershipError("provider does not match the immutable lab identity")
        expected = tuple(machine.handle for machine in state.inventory)
        discovery = provider.discover(expected)
        if discovery.presence is Presence.UNKNOWN:
            raise OwnershipError(
                "provider discovery is unknown; refusing break-glass cleanup"
                + (f": {discovery.detail}" if discovery.detail else "")
            )
        if discovery.presence is Presence.ABSENT:
            return ()
        discovered = set(discovery.handles)
        if not discovered.issubset(set(expected)) or len(discovered) != len(
            discovery.handles
        ):
            raise OwnershipError("break-glass discovery contains an unrecorded handle")
        machine_by_handle = {machine.handle: machine for machine in state.inventory}
        for handle in discovery.handles:
            machine = machine_by_handle[handle]
            identity = GuestIdentity(
                state.identity.lab_id,
                machine.machine_id,
                machine.role,
                machine.handle,
            )
            if not provider.prove_ownership(
                identity, mode=OwnershipProofMode.BREAK_GLASS
            ):
                raise OwnershipError(
                    f"provider ownership proof failed for {handle.value!r}"
                )
        deletion_order = sorted(
            (machine for machine in state.inventory if machine.handle in discovered),
            key=lambda machine: _DESTROY_ROLE_ORDER.get(machine.role, -1),
        )
        return tuple(provider._delete_exact(machine.handle) for machine in deletion_order)


__all__ = [
    "ActiveScenario",
    "InvalidTransitionError",
    "JournalEntry",
    "LabIdentity",
    "LabLockedError",
    "LabMutatorLock",
    "LabPhase",
    "LabState",
    "LabStateStore",
    "MachineObservation",
    "OwnershipError",
    "StateError",
    "StateExistsError",
    "StateMissingError",
    "StateValidationError",
    "state_write_prohibited",
    "validate_identifier",
]
