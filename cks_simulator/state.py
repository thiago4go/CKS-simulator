"""Owned lab identity, inventory, journal, and mutation-lock kernel.

State mutators are deliberately low-level: they do not acquire a hidden lock.
Lifecycle callers must hold :meth:`LabStateStore.lock` across the complete
read/check/provider-mutation/state-update transaction for a lab.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .providers.base import (
    Discovery,
    GuestIdentity,
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
        LabPhase.GRADED,
        LabPhase.DEGRADED,
        LabPhase.CLEANUP_PENDING,
    },
    LabPhase.GRADED: {LabPhase.VALIDATED, LabPhase.DEGRADED, LabPhase.CLEANUP_PENDING},
    LabPhase.DEGRADED: {LabPhase.OS_READY, LabPhase.CLEANUP_PENDING},
    LabPhase.CLEANUP_PENDING: {LabPhase.DESTROYED},
    LabPhase.DESTROYED: set(),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


@dataclass(frozen=True)
class LabState:
    identity: LabIdentity
    inventory: Tuple[ProviderMachine, ...]
    journal: Tuple[JournalEntry, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "inventory", tuple(self.inventory))
        object.__setattr__(self, "journal", tuple(self.journal))
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

    @property
    def phase(self) -> LabPhase:
        return self.journal[-1].phase

    def with_inventory(self, inventory: Sequence[ProviderMachine]) -> "LabState":
        return replace(self, inventory=tuple(inventory))

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
            return cls(identity=identity, inventory=inventory, journal=journal)
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


class LabMutatorLock:
    def __init__(self, path: Path, *, blocking: bool) -> None:
        self.path = path
        self.blocking = blocking
        self._descriptor: Optional[int] = None

    def __enter__(self) -> "LabMutatorLock":
        _private_directory(self.path.parent)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        try:
            descriptor = os.open(str(self.path), flags, 0o600)
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.EISDIR):
                raise StateValidationError(
                    f"refusing unsafe lock file for lab {self.path.stem!r}"
                ) from error
            raise
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise StateValidationError(
                    f"refusing non-regular lock file for lab {self.path.stem!r}"
                )
            os.fchmod(descriptor, 0o600)
        except BaseException:
            os.close(descriptor)
            raise
        operation = fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(descriptor, operation)
        except OSError as error:
            os.close(descriptor)
            if error.errno in (errno.EACCES, errno.EAGAIN):
                raise LabLockedError(f"lab {self.path.stem!r} is being mutated") from error
            raise
        self._descriptor = descriptor
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._descriptor is not None:
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._descriptor)
                self._descriptor = None


class LabStateStore:
    """Namespace-scoped state store; quick and full state can never be adopted.

    ``claim``, ``declare_inventory``, and ``advance`` intentionally do not lock
    themselves.  A lifecycle caller must hold ``with store.lock(lab_name):``
    around the whole operation, including provider discovery, ownership checks,
    provider mutations, and the final state write.  Keeping the lock at that
    boundary avoids hidden re-entrant locking and prevents check/use gaps.
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
            self.root / ".locks" / self.namespace / f"{lab_name}.lock", blocking=blocking
        )

    def claim(self, lab_name: str, *, provider: str) -> LabState:
        """Create the write-ahead identity; the caller must hold the lab lock."""

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
                if phase not in _ALLOWED_TRANSITIONS[state.phase]:
                    raise InvalidTransitionError(
                        f"invalid phase transition {state.phase.value} -> {phase.value}"
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
            for handle in discovery.handles:
                identity = provider.read_guest_identity(handle)
                if identity is None:
                    raise OwnershipError(
                        f"guest identity is missing for {handle.value!r}"
                    )
                observed.append(identity)
            guests = tuple(observed)
        authorized = self.require_mutation_authority(lab_name, discovery, guests)
        if discovery.presence is not Presence.PRESENT:
            return ()
        return tuple(
            provider._delete_exact(machine.handle)
            for machine in authorized.inventory
        )

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
        return tuple(
            provider._delete_exact(machine.handle)
            for machine in state.inventory
            if machine.handle in discovered
        )


__all__ = [
    "InvalidTransitionError",
    "JournalEntry",
    "LabIdentity",
    "LabLockedError",
    "LabMutatorLock",
    "LabPhase",
    "LabState",
    "LabStateStore",
    "OwnershipError",
    "StateError",
    "StateExistsError",
    "StateMissingError",
    "StateValidationError",
    "validate_identifier",
]
