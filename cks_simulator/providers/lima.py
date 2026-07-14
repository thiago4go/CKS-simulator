"""Fail-closed Lima adapter using exact instance handles."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence, Tuple

from ..state import LabMutatorLock

from .base import (
    Discovery,
    GuestIdentity,
    OwnershipProofMode,
    Presence,
    PinnedProviderInput,
    ProcessRequest,
    ProcessResult,
    ProviderHandle,
    Runner,
    bounded_redacted,
    derive_provider_handle,
    guest_identity_payload,
    pin_provider_input,
    validate_identifier,
)


GUEST_IDENTITY_PATH = "/etc/cks-simulator/identity.json"
LIMA_ROLES = ("candidate", "control-plane", "worker1", "worker2")
_MARKER_KEYS = {
    "schema_version",
    "managed_by",
    "lab_id",
    "machine_id",
    "role",
    "provider",
    "handle",
}
_MARKER_ABSENT_SCRIPT = (
    'p=/etc/cks-simulator/identity.json; [ ! -e "$p" ] && [ ! -L "$p" ]'
)
_MARKER_READ_SCRIPT = (
    'set -eu; p=/etc/cks-simulator/identity.json; '
    '[ -f "$p" ] && [ ! -L "$p" ]; '
    '[ "$(/usr/bin/stat -c %u:%g:%a "$p")" = "0:0:600" ]; '
    '/bin/cat "$p"'
)
_MARKER_WRITE_SCRIPT = (
    'set -eu; umask 077; '
    '/usr/bin/install -d -m 0700 -o root -g root /etc/cks-simulator; '
    't=/etc/cks-simulator/.identity.json.tmp; '
    '[ ! -e "$t" ] && [ ! -L "$t" ]; '
    '/bin/cat > "$t"; /bin/chown root:root "$t"; /bin/chmod 0600 "$t"; '
    '/bin/mv -fT "$t" /etc/cks-simulator/identity.json'
)
_ROOT_FILE_INSTALL_SCRIPT = (
    'set -eu; case "$1" in /*) ;; *) exit 64;; esac; '
    '[ ! -L "$1" ]; '
    '/usr/bin/install -D -o root -g root -m "$2" /dev/stdin "$1"'
)
_OBSERVATION_SCRIPT = (
    'set -eu; '
    'iface=$(/usr/sbin/ip -4 route show default | /usr/bin/awk "NR == 1 {print \\$5}"); '
    '[ -n "$iface" ]; '
    'ipv4=$(/usr/sbin/ip -o -4 addr show dev "$iface" scope global | '
    '/usr/bin/awk "NR == 1 {split(\\$4, a, \\"/\\"); print a[1]}"); '
    '[ -n "$ipv4" ]; '
    'mac=$(/bin/cat "/sys/class/net/$iface/address"); '
    'product_uuid=$(/bin/cat /sys/class/dmi/id/product_uuid); '
    'printf "%s\\t%s\\t%s\\n" "$ipv4" "$mac" "$product_uuid"'
)
_MAC_ADDRESS = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
_IDENTITY_PARAM = "cksIdentity"
_MAX_GUEST_STDIN = 8 * 1024 * 1024
_PROVIDER_LOCK_NAMESPACE = "lima"
_PROVIDER_LOCK_NAME = "host"
_IMMUTABLE_INVENTORY_FIELDS = (
    ("hostname", ("hostname", "Hostname")),
    ("dir", ("dir", "Dir")),
    ("vmType", ("vmType", "VMType")),
    ("arch", ("arch", "Arch")),
    ("cpus", ("cpus", "CPUs")),
    ("memory", ("memory", "Memory")),
    ("disk", ("disk", "Disk")),
    ("additionalDisks", ("additionalDisks", "AdditionalDisks")),
    ("network", ("network", "Networks")),
    ("config", ("config", "Config")),
    ("limaVersion", ("limaVersion", "LimaVersion")),
)


class LimaProviderError(RuntimeError):
    """Raised when Lima cannot positively prove the requested observation."""


class LimaInstanceStatus(str, Enum):
    """Lifecycle states understood well enough for safe reconciliation."""

    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LimaInstanceFingerprint:
    """Provider-native identity carried from proof through name-only mutation."""

    identity_sha256: str
    provider_data_sha256: str

    def __post_init__(self) -> None:
        for value in (self.identity_sha256, self.provider_data_sha256):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("Lima instance fingerprint must contain canonical SHA-256 values")


@dataclass(frozen=True)
class LimaInstance:
    handle: ProviderHandle
    status: LimaInstanceStatus
    identity_sha256: Optional[str] = None
    provider_data_sha256: str = hashlib.sha256(b"{}").hexdigest()

    def __post_init__(self) -> None:
        _require_lima_handle(self.handle)
        if not isinstance(self.status, LimaInstanceStatus):
            raise ValueError("Lima instance status must be canonical")
        if self.identity_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", self.identity_sha256
        ):
            raise ValueError("Lima identity digest must be canonical SHA-256")
        if not re.fullmatch(r"[0-9a-f]{64}", self.provider_data_sha256):
            raise ValueError("Lima provider fingerprint must be canonical SHA-256")

    @property
    def fingerprint(self) -> Optional[LimaInstanceFingerprint]:
        if self.identity_sha256 is None:
            return None
        return LimaInstanceFingerprint(
            identity_sha256=self.identity_sha256,
            provider_data_sha256=self.provider_data_sha256,
        )


@dataclass(frozen=True)
class LimaDiscovery(Discovery):
    """Exact discovery plus status and immutable provider identity evidence."""

    instances: Tuple[LimaInstance, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        object.__setattr__(self, "instances", tuple(self.instances))
        instance_handles = tuple(instance.handle for instance in self.instances)
        if instance_handles != self.handles:
            raise ValueError("Lima discovery instances must match exact discovery handles")

    def status_for(self, handle: ProviderHandle) -> LimaInstanceStatus:
        return self.instance_for(handle).status

    def instance_for(self, handle: ProviderHandle) -> LimaInstance:
        exact = _require_lima_handle(handle)
        for instance in self.instances:
            if instance.handle == exact:
                return instance
        raise KeyError(exact)


@dataclass(frozen=True)
class MachineObservation:
    ipv4: str
    mac: str
    product_uuid: str

    def __post_init__(self) -> None:
        address = ipaddress.IPv4Address(self.ipv4)
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError("machine IPv4 address is not usable")
        if not _MAC_ADDRESS.fullmatch(self.mac):
            raise ValueError("machine MAC address is invalid")
        canonical_product_uuid = str(uuid.UUID(self.product_uuid))
        object.__setattr__(self, "ipv4", str(address))
        object.__setattr__(self, "mac", self.mac.lower())
        object.__setattr__(self, "product_uuid", canonical_product_uuid)


def _command_prefix(value: Sequence[str], *, field_name: str) -> Tuple[str, ...]:
    prefix = tuple(value)
    if not prefix or any(
        not isinstance(argument, str) or not argument or "\0" in argument
        for argument in prefix
    ):
        raise ValueError(f"{field_name} must contain static non-empty argv entries")
    executable = Path(prefix[0])
    if not executable.is_absolute():
        raise ValueError(f"{field_name} executable must be an absolute path")
    if executable.is_symlink():
        executable = executable.resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError(f"{field_name} executable must be a regular executable file")
    return (str(executable.resolve(strict=True)), *prefix[1:])


def _default_lima_command() -> Tuple[str, ...]:
    for candidate in (
        Path("/opt/homebrew/bin/limactl"),
        Path("/usr/local/bin/limactl"),
        Path("/usr/bin/limactl"),
    ):
        try:
            return _command_prefix((str(candidate),), field_name="Lima command")
        except (OSError, ValueError):
            continue
    raise ValueError("no trusted absolute limactl executable was found")


def _require_lima_handle(handle: ProviderHandle) -> ProviderHandle:
    if handle.provider != "lima":
        raise ValueError("Lima operations require an exact lima provider handle")
    return handle


def _parse_guest_marker(text: str, expected: ProviderHandle) -> GuestIdentity:
    try:
        payload = json.loads(text)
    except (TypeError, ValueError) as error:
        raise LimaProviderError("Lima guest identity marker is not valid JSON") from error
    if not isinstance(payload, dict) or set(payload) != _MARKER_KEYS:
        raise LimaProviderError("Lima guest identity marker has an invalid schema")
    if payload["schema_version"] != 1 or payload["managed_by"] != "cks-simulator":
        raise LimaProviderError("Lima guest identity marker is not owned by cks-simulator")
    if payload["provider"] != expected.provider or payload["handle"] != expected.value:
        raise LimaProviderError("Lima guest identity marker does not match the exact handle")
    try:
        return GuestIdentity(
            lab_id=payload["lab_id"],
            machine_id=payload["machine_id"],
            role=payload["role"],
            handle=expected,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise LimaProviderError("Lima guest identity marker contains invalid identity data") from error


def guest_identity_sha256(identity: GuestIdentity) -> str:
    """Digest mirrored into immutable Lima config for stopped-VM authorization."""

    return hashlib.sha256(guest_identity_payload(identity)).hexdigest()


def _inventory_field(item: Mapping[str, object], name: str, *, required: bool) -> object:
    keys = (name, name[:1].upper() + name[1:])
    values = [item[key] for key in keys if key in item]
    if not values:
        if required:
            raise ValueError(f"inventory item has no {name!r} field")
        return None
    if len(values) > 1 and values[0] != values[1]:
        raise ValueError(f"inventory item has conflicting {name!r} fields")
    return values[0]


def _parse_lima_status(value: object) -> LimaInstanceStatus:
    if not isinstance(value, str) or not value or len(value) > 64 or any(
        ord(character) < 32 for character in value
    ):
        raise ValueError("inventory item has an invalid status")
    normalized = value.casefold()
    if normalized == "running":
        return LimaInstanceStatus.RUNNING
    if normalized == "stopped":
        return LimaInstanceStatus.STOPPED
    return LimaInstanceStatus.UNKNOWN


def _parse_identity_param(value: object) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise ValueError("inventory item has invalid Lima parameters")
    digest = value.get(_IDENTITY_PARAM)
    if digest in (None, ""):
        return None
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("inventory item has an invalid identity digest")
    return digest


def _provider_data_sha256(item: Mapping[str, object]) -> str:
    """Hash stable all-fields inventory data while excluding runtime status/PIDs."""

    immutable = {}
    for canonical, aliases in _IMMUTABLE_INVENTORY_FIELDS:
        values = [item[alias] for alias in aliases if alias in item]
        if len(values) > 1 and any(value != values[0] for value in values[1:]):
            raise ValueError(f"inventory item has conflicting {canonical!r} fields")
        if values:
            immutable[canonical] = values[0]
    try:
        payload = json.dumps(
            immutable,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise ValueError("inventory item has invalid immutable provider data") from error
    return hashlib.sha256(payload).hexdigest()


def _validate_guest_argv(argv: Sequence[str]) -> Tuple[str, ...]:
    command = tuple(argv)
    if not command or any(
        not isinstance(argument, str) or "\0" in argument for argument in command
    ):
        raise ValueError("guest command requires static argv without NUL bytes")
    executable = Path(command[0])
    if not executable.is_absolute() or ".." in executable.parts:
        raise ValueError("guest executable must be an absolute normalized path")
    if executable.name in {"sh", "bash", "dash", "zsh"} and any(
        argument in {"-c", "--command"} for argument in command[1:]
    ):
        raise ValueError("guest shell source is reserved for provider-owned static scripts")
    return command


def _validate_guest_destination(value: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value or len(value) > 4096:
        raise ValueError("guest destination must be a bounded path without NUL bytes")
    destination = Path(value)
    if not destination.is_absolute() or ".." in destination.parts or value == "/":
        raise ValueError("guest destination must be an absolute normalized file path")
    return value


class LimaProvider:
    """Minimal provider implementation for the four-machine full tier."""

    name = "lima"

    def __init__(
        self,
        runner: Runner,
        *,
        templates: Mapping[str, str],
        state_dir: Path,
        command: Optional[Sequence[str]] = None,
    ) -> None:
        self._runner = runner
        runtime_root = Path(state_dir)
        if (
            not runtime_root.is_absolute()
            or runtime_root.is_symlink()
            or not runtime_root.is_dir()
        ):
            raise ValueError("Lima provider runtime root must be an absolute non-symlink directory")
        self._state_dir = runtime_root.resolve(strict=True)
        self._provider_runtime_root = self._state_dir / ".provider-runtime"
        self._ownership_fingerprints: Dict[
            ProviderHandle, LimaInstanceFingerprint
        ] = {}
        self._command = (
            _default_lima_command()
            if command is None
            else _command_prefix(command, field_name="Lima command")
        )
        normalized = {}
        pinned_inputs = {}
        for role, path in templates.items():
            role = validate_identifier(role, field_name="machine role")
            if not isinstance(path, str) or not path or "\0" in path or path.startswith("-"):
                raise ValueError("Lima template paths must be non-empty strings without NUL bytes")
            candidate = Path(path)
            if not candidate.is_absolute():
                raise ValueError("Lima templates must be absolute paths")
            pinned = pin_provider_input(
                str(candidate),
                self._state_dir,
                label=f"lima-{role}",
            )
            normalized[role] = pinned.path
            pinned_inputs[role] = pinned
        self._templates = normalized
        self._template_inputs = pinned_inputs

    def _mutation_lock(self) -> LabMutatorLock:
        return LabMutatorLock(
            self._provider_runtime_root,
            _PROVIDER_LOCK_NAMESPACE,
            _PROVIDER_LOCK_NAME,
            blocking=True,
        )

    def _run(
        self,
        argv: Sequence[str],
        *,
        stdin: Optional[bytes] = None,
        timeout_seconds: float = 120.0,
        output_limit: int = 4096,
        pass_fds: Sequence[int] = (),
        secrets: Sequence[str] = (),
    ) -> ProcessResult:
        return self._runner.run(
            ProcessRequest.build(
                (*self._command, *argv),
                stdin=stdin,
                timeout_seconds=timeout_seconds,
                output_limit=output_limit,
                pass_fds=pass_fds,
                secrets=secrets,
            )
        )

    def discover(self, expected_handles: Sequence[ProviderHandle]) -> LimaDiscovery:
        expected = tuple(_require_lima_handle(handle) for handle in expected_handles)
        if not expected or len(set(expected)) != len(expected):
            raise ValueError("Lima discovery requires unique exact expected handles")
        result = self._run(
            ("list", "--all-fields", "--json"),
            timeout_seconds=30,
            output_limit=1024 * 1024,
        )
        if not result.ok:
            return LimaDiscovery(
                presence=Presence.UNKNOWN,
                detail=result.diagnostic(limit=1024),
            )

        expected_by_name = {handle.value: handle for handle in expected}
        names = set()
        observed = {}
        try:
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError("inventory item is not an object")
                raw_name = _inventory_field(item, "name", required=True)
                if not isinstance(raw_name, str):
                    raise ValueError("inventory item has no string name")
                name = validate_identifier(raw_name, field_name="Lima instance name")
                if name in names:
                    raise ValueError("inventory contains a duplicate instance name")
                names.add(name)
                status = _parse_lima_status(_inventory_field(item, "status", required=True))
                if name in expected_by_name:
                    identity_digest = _parse_identity_param(
                        _inventory_field(item, "param", required=False)
                    )
                    observed[name] = LimaInstance(
                        handle=expected_by_name[name],
                        status=status,
                        identity_sha256=identity_digest,
                        provider_data_sha256=_provider_data_sha256(item),
                    )
        except (TypeError, ValueError) as error:
            return LimaDiscovery(
                presence=Presence.UNKNOWN,
                detail=f"invalid Lima inventory: {error}",
            )

        instances = tuple(observed[handle.value] for handle in expected if handle.value in observed)
        handles = tuple(instance.handle for instance in instances)
        if handles:
            return LimaDiscovery(
                presence=Presence.PRESENT,
                handles=handles,
                instances=instances,
            )
        return LimaDiscovery(presence=Presence.ABSENT)

    def read_guest_identity(self, handle: ProviderHandle) -> Optional[GuestIdentity]:
        exact = _require_lima_handle(handle)
        absent = self._run(
            (
                "shell",
                exact.value,
                "--",
                "/usr/bin/sudo",
                "/bin/sh",
                "-c",
                _MARKER_ABSENT_SCRIPT,
            ),
            timeout_seconds=30,
        )
        if absent.ok:
            if absent.stdout or absent.stderr:
                raise LimaProviderError(
                    "Lima guest marker absence probe returned unexpected output"
                )
            return None
        if absent.timed_out or absent.returncode != 1:
            raise LimaProviderError(
                "unable to prove Lima guest marker presence: "
                + absent.diagnostic(limit=1024)
            )

        observed = self._run(
            (
                "shell",
                exact.value,
                "--",
                "/usr/bin/sudo",
                "/bin/sh",
                "-c",
                _MARKER_READ_SCRIPT,
            ),
            timeout_seconds=30,
        )
        if not observed.ok:
            raise LimaProviderError(
                "unable to read Lima guest identity marker: "
                + observed.diagnostic(limit=1024)
            )
        return _parse_guest_marker(observed.stdout, exact)

    def prove_ownership(
        self,
        expected: GuestIdentity,
        *,
        mode: OwnershipProofMode,
    ) -> bool:
        """Authorize cleanup from immutable Lima config and guest evidence.

        Stopped guests cannot expose their root marker without mutation, so the
        exact config digest is sufficient. Running guests require that digest
        plus the exact root-owned marker. Break-glass may accept a positively
        absent marker only when the immutable digest still matches.
        """

        if not isinstance(mode, OwnershipProofMode):
            raise ValueError("cleanup ownership proof mode is invalid")
        exact = self._validate_identity_handle(expected)
        with self._mutation_lock():
            self._ownership_fingerprints.pop(exact, None)
            discovery = self.discover((exact,))
            if discovery.presence is Presence.UNKNOWN:
                raise LimaProviderError(
                    "unable to prove Lima cleanup ownership: " + discovery.detail
                )
            if discovery.presence is Presence.ABSENT:
                return False
            instance = discovery.instance_for(exact)
            fingerprint = instance.fingerprint
            if (
                fingerprint is None
                or fingerprint.identity_sha256 != guest_identity_sha256(expected)
            ):
                return False
            if instance.status is LimaInstanceStatus.STOPPED:
                self._ownership_fingerprints[exact] = fingerprint
                return True
            if instance.status is LimaInstanceStatus.UNKNOWN:
                raise LimaProviderError(
                    f"Lima instance {exact.value!r} has an unknown state"
                )
            observed = self.read_guest_identity(exact)
            owned = (
                mode is OwnershipProofMode.BREAK_GLASS
                if observed is None
                else observed == expected
            )
            if owned:
                self._ownership_fingerprints[exact] = fingerprint
            return owned

    @staticmethod
    def _validate_identity_handle(identity: GuestIdentity) -> ProviderHandle:
        exact = _require_lima_handle(identity.handle)
        if exact != derive_provider_handle("lima", identity.lab_id, identity.role):
            raise ValueError("Lima handle is not derived from the immutable lab identity")
        if not exact.value.endswith(f"-{identity.role}"):
            raise ValueError("Lima machine role does not match its exact provider handle")
        return exact

    def _validate_identity(
        self, identity: GuestIdentity
    ) -> Tuple[ProviderHandle, str, PinnedProviderInput]:
        exact = self._validate_identity_handle(identity)
        template = self._templates.get(identity.role)
        pinned = self._template_inputs.get(identity.role)
        if template is None or pinned is None:
            raise ValueError(f"no Lima template is configured for role {identity.role!r}")
        return exact, template, pinned

    def _success(self, handle: ProviderHandle, detail: str) -> ProcessResult:
        return ProcessResult(
            command=(*self._command, "ensure", handle.value),
            returncode=0,
            stdout=bounded_redacted(detail, limit=1024),
            stderr="",
            output_limit=1024,
        )

    def _rediscover_exact(
        self,
        handle: ProviderHandle,
        *,
        context: str,
    ) -> LimaInstance:
        discovery = self.discover((handle,))
        if discovery.presence is Presence.UNKNOWN:
            raise LimaProviderError(f"{context}: {discovery.detail}")
        if discovery.presence is Presence.ABSENT:
            raise LimaProviderError(f"{context}: exact Lima instance is absent")
        return discovery.instance_for(handle)

    @staticmethod
    def _require_status(
        instance: LimaInstance,
        expected: LimaInstanceStatus,
        *,
        context: str,
    ) -> None:
        if instance.status is not expected:
            raise LimaProviderError(
                f"{context}: expected {expected.value}, observed {instance.status.value}"
            )

    @staticmethod
    def _require_digest(
        instance: LimaInstance,
        expected_digest: str,
        *,
        context: str,
    ) -> LimaInstanceFingerprint:
        fingerprint = instance.fingerprint
        if fingerprint is None or fingerprint.identity_sha256 != expected_digest:
            raise LimaProviderError(f"{context}: Lima identity digest changed or is missing")
        return fingerprint

    @staticmethod
    def _require_fingerprint(
        instance: LimaInstance,
        expected: LimaInstanceFingerprint,
        *,
        context: str,
    ) -> None:
        if instance.fingerprint != expected:
            raise LimaProviderError(f"{context}: Lima instance identity changed")

    def _rollback_restart(
        self,
        instance: LimaInstance,
        fingerprint: LimaInstanceFingerprint,
    ) -> str:
        """Stop only the exact instance generation that was started for reconciliation."""

        try:
            current = self._rediscover_exact(
                instance.handle,
                context="restart rollback pre-stop verification failed",
            )
            self._require_fingerprint(
                current,
                fingerprint,
                context="restart rollback pre-stop verification failed",
            )
            if current.status is LimaInstanceStatus.UNKNOWN:
                raise LimaProviderError(
                    "restart rollback pre-stop verification failed: unknown Lima state"
                )
        except LimaProviderError as error:
            return str(error)

        stopped = self._run(
            ("stop", "--force", instance.handle.value), timeout_seconds=300
        )
        if not stopped.ok:
            return "restart rollback stop failed: " + stopped.diagnostic(limit=1024)
        try:
            restored = self._rediscover_exact(
                instance.handle,
                context="restart rollback post-stop verification failed",
            )
            self._require_fingerprint(
                restored,
                fingerprint,
                context="restart rollback post-stop verification failed",
            )
            self._require_status(
                restored,
                LimaInstanceStatus.STOPPED,
                context="restart rollback post-stop verification failed",
            )
        except LimaProviderError as error:
            return str(error)
        return "stopped instance generation restored and verified"

    def _create_absent(
        self,
        identity: GuestIdentity,
        exact: ProviderHandle,
        template: str,
        pinned: PinnedProviderInput,
    ) -> ProcessResult:
        descriptor = pinned.descriptor
        os.lseek(descriptor, 0, os.SEEK_SET)
        started = self._run(
            (
                "start",
                "--yes",
                "--name",
                exact.value,
                "--param",
                f"{_IDENTITY_PARAM}={guest_identity_sha256(identity)}",
                template,
            ),
            timeout_seconds=1800,
            pass_fds=(descriptor,),
        )
        if not started.ok:
            return started
        written = self._run(
            (
                "shell",
                exact.value,
                "--",
                "/usr/bin/sudo",
                "/bin/sh",
                "-c",
                _MARKER_WRITE_SCRIPT,
            ),
            stdin=guest_identity_payload(identity),
            timeout_seconds=30,
        )
        if not written.ok:
            return written
        created = self._rediscover_exact(
            exact,
            context="new Lima instance rediscovery failed",
        )
        self._require_digest(
            created,
            guest_identity_sha256(identity),
            context="new Lima instance verification failed",
        )
        self._require_status(
            created,
            LimaInstanceStatus.RUNNING,
            context="new Lima instance verification failed",
        )
        if self.read_guest_identity(exact) != identity:
            raise LimaProviderError("new Lima guest identity did not verify")
        return started

    def _restart_stopped(
        self, identity: GuestIdentity, instance: LimaInstance
    ) -> ProcessResult:
        expected_digest = guest_identity_sha256(identity)
        fingerprint = self._require_digest(
            instance,
            expected_digest,
            context="stopped Lima instance verification failed",
        )
        restarted = self._run(
            (
                "shell",
                "--start",
                "--yes",
                instance.handle.value,
                "--",
                "/usr/bin/sudo",
                "/bin/sh",
                "-c",
                _MARKER_READ_SCRIPT,
            ),
            timeout_seconds=300,
        )
        if not restarted.ok:
            rollback = self._rollback_restart(instance, fingerprint)
            return ProcessResult(
                command=restarted.command,
                returncode=restarted.returncode,
                stdout=restarted.stdout,
                stderr=bounded_redacted(
                    restarted.stderr
                    + "\nrestart rollback: "
                    + rollback,
                    limit=restarted.output_limit,
                ),
                timed_out=restarted.timed_out,
                output_limit=restarted.output_limit,
            )
        try:
            observed = _parse_guest_marker(restarted.stdout, instance.handle)
        except LimaProviderError as error:
            rollback = self._rollback_restart(instance, fingerprint)
            raise LimaProviderError(
                "restarted Lima guest marker could not be verified; rollback: "
                + rollback
            ) from error
        if observed != identity:
            rollback = self._rollback_restart(instance, fingerprint)
            raise LimaProviderError(
                "restarted Lima guest identity does not match immutable state; rollback: "
                + rollback
            )
        try:
            verified = self._rediscover_exact(
                instance.handle,
                context="restarted Lima instance rediscovery failed",
            )
            self._require_fingerprint(
                verified,
                fingerprint,
                context="restarted Lima instance verification failed",
            )
            self._require_status(
                verified,
                LimaInstanceStatus.RUNNING,
                context="restarted Lima instance verification failed",
            )
        except LimaProviderError as error:
            rollback = self._rollback_restart(instance, fingerprint)
            raise LimaProviderError(f"{error}; rollback: {rollback}") from error
        return self._success(instance.handle, "stopped owned Lima instance restarted and verified")

    def ensure(self, identity: GuestIdentity) -> ProcessResult:
        """Create, reuse, or restart one exact machine without adopting collisions."""

        exact, template, pinned = self._validate_identity(identity)
        with self._mutation_lock():
            self._ownership_fingerprints.pop(exact, None)
            discovery = self.discover((exact,))
            if discovery.presence is Presence.UNKNOWN:
                raise LimaProviderError("unable to reconcile Lima inventory: " + discovery.detail)
            if discovery.presence is Presence.ABSENT:
                return self._create_absent(identity, exact, template, pinned)

            instance = discovery.instance_for(exact)
            if instance.status is LimaInstanceStatus.RUNNING:
                self._require_digest(
                    instance,
                    guest_identity_sha256(identity),
                    context="running Lima instance verification failed",
                )
                observed = self.read_guest_identity(exact)
                if observed != identity:
                    raise LimaProviderError(
                        "running Lima guest identity does not match immutable state"
                    )
                return self._success(exact, "running owned Lima instance reused")
            if instance.status is LimaInstanceStatus.STOPPED:
                return self._restart_stopped(identity, instance)
            raise LimaProviderError("exact Lima instance is in an unknown state")

    def create(self, identity: GuestIdentity) -> ProcessResult:
        """Provider protocol alias for idempotent exact reconciliation."""

        return self.ensure(identity)

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
        """Execute fixed argv in an exact running guest without shell interpolation."""

        exact = _require_lima_handle(handle)
        command = _validate_guest_argv(argv)
        if stdin is not None and len(stdin) > _MAX_GUEST_STDIN:
            raise ValueError("guest stdin exceeds the maximum size")
        guest_argv = (
            ("/usr/bin/sudo", "--", *command) if as_root else command
        )
        return self._run(
            ("shell", exact.value, "--", *guest_argv),
            stdin=stdin,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
            secrets=secrets,
        )

    def execute_verified(
        self,
        expected: GuestIdentity,
        argv: Sequence[str],
        *,
        stdin: Optional[bytes] = None,
        as_root: bool = False,
        timeout_seconds: float = 120.0,
        output_limit: int = 4096,
        secrets: Sequence[str] = (),
    ) -> ProcessResult:
        """Verify exact provider and guest identity atomically before dispatch.

        The provider mutation lock prevents a competing lifecycle operation
        from replacing or restarting the instance between ownership proof and
        execution.  Scenario code should use this surface instead of retaining
        a raw generic execution capability.
        """

        exact = self._validate_identity_handle(expected)
        command = _validate_guest_argv(argv)
        if stdin is not None and len(stdin) > _MAX_GUEST_STDIN:
            raise ValueError("guest stdin exceeds the maximum size")
        guest_argv = ("/usr/bin/sudo", "--", *command) if as_root else command
        with self._mutation_lock():
            instance = self._rediscover_exact(
                exact, context="verified guest execution failed"
            )
            self._require_status(
                instance,
                LimaInstanceStatus.RUNNING,
                context="verified guest execution failed",
            )
            self._require_digest(
                instance,
                guest_identity_sha256(expected),
                context="verified guest execution failed",
            )
            if self.read_guest_identity(exact) != expected:
                raise LimaProviderError(
                    "verified guest execution identity marker does not match state"
                )
            return self._run(
                ("shell", exact.value, "--", *guest_argv),
                stdin=stdin,
                timeout_seconds=timeout_seconds,
                output_limit=output_limit,
                secrets=secrets,
            )

    def install_root_file(
        self,
        handle: ProviderHandle,
        destination: str,
        content: bytes,
        *,
        mode: int = 0o600,
        timeout_seconds: float = 120.0,
    ) -> ProcessResult:
        """Install trusted bytes through stdin using provider-owned static shell text."""

        exact = _require_lima_handle(handle)
        target = _validate_guest_destination(destination)
        if not isinstance(content, bytes) or len(content) > _MAX_GUEST_STDIN:
            raise ValueError("root file content must be bounded bytes")
        if (
            not isinstance(mode, int)
            or isinstance(mode, bool)
            or mode < 0o400
            or mode > 0o755
            or mode & 0o022
        ):
            raise ValueError("root file mode must be owner-writable at most and no broader than 0755")
        return self._run(
            (
                "shell",
                exact.value,
                "--",
                "/usr/bin/sudo",
                "/bin/sh",
                "-c",
                _ROOT_FILE_INSTALL_SCRIPT,
                "cks-install",
                target,
                f"{mode:04o}",
            ),
            stdin=content,
            timeout_seconds=timeout_seconds,
        )

    def observe_machine(self, handle: ProviderHandle) -> MachineObservation:
        """Read and validate the default-interface IP, MAC, and product UUID."""

        exact = _require_lima_handle(handle)
        result = self._run(
            (
                "shell",
                exact.value,
                "--",
                "/usr/bin/sudo",
                "/bin/sh",
                "-c",
                _OBSERVATION_SCRIPT,
            ),
            timeout_seconds=30,
            output_limit=1024,
        )
        if not result.ok:
            raise LimaProviderError(
                "unable to observe exact Lima machine: " + result.diagnostic(limit=1024)
            )
        lines = result.stdout.splitlines()
        if len(lines) != 1:
            raise LimaProviderError("Lima machine observation returned an invalid record count")
        fields = lines[0].split("\t")
        if len(fields) != 3:
            raise LimaProviderError("Lima machine observation returned an invalid schema")
        try:
            return MachineObservation(*fields)
        except (TypeError, ValueError) as error:
            raise LimaProviderError("Lima machine observation contains invalid values") from error

    def _delete_exact(self, handle: ProviderHandle) -> ProcessResult:
        exact = _require_lima_handle(handle)
        with self._mutation_lock():
            fingerprint = self._ownership_fingerprints.pop(exact, None)
            if fingerprint is None:
                raise LimaProviderError(
                    "Lima exact deletion requires a fresh bound ownership proof"
                )

            before_stop = self._rediscover_exact(
                exact,
                context="pre-stop Lima identity verification failed",
            )
            self._require_fingerprint(
                before_stop,
                fingerprint,
                context="pre-stop Lima identity verification failed",
            )
            if before_stop.status is LimaInstanceStatus.UNKNOWN:
                raise LimaProviderError("pre-stop Lima instance state is unknown")

            stopped = self._run(("stop", "--force", exact.value), timeout_seconds=300)
            if not stopped.ok:
                return stopped

            after_stop = self._rediscover_exact(
                exact,
                context="post-stop Lima identity verification failed",
            )
            self._require_fingerprint(
                after_stop,
                fingerprint,
                context="post-stop Lima identity verification failed",
            )
            self._require_status(
                after_stop,
                LimaInstanceStatus.STOPPED,
                context="post-stop Lima identity verification failed",
            )

            before_delete = self._rediscover_exact(
                exact,
                context="pre-delete Lima identity verification failed",
            )
            self._require_fingerprint(
                before_delete,
                fingerprint,
                context="pre-delete Lima identity verification failed",
            )
            self._require_status(
                before_delete,
                LimaInstanceStatus.STOPPED,
                context="pre-delete Lima identity verification failed",
            )
            return self._run(("delete", "--force", exact.value), timeout_seconds=300)

    def close(self) -> None:
        for pinned in self._template_inputs.values():
            pinned.close()
        self._template_inputs = {}

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

__all__ = [
    "GUEST_IDENTITY_PATH",
    "LIMA_ROLES",
    "LimaDiscovery",
    "LimaInstance",
    "LimaInstanceFingerprint",
    "LimaInstanceStatus",
    "LimaProvider",
    "LimaProviderError",
    "MachineObservation",
    "guest_identity_sha256",
]
