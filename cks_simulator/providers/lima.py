"""Fail-closed Lima adapter using exact instance handles."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping, Optional, Sequence, Tuple

from .base import (
    Discovery,
    GuestIdentity,
    Presence,
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


class LimaProviderError(RuntimeError):
    """Raised when Lima cannot positively prove the requested observation."""


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
                Path(state_dir),
                label=f"lima-{role}",
            )
            normalized[role] = pinned.path
            pinned_inputs[role] = pinned
        self._templates = normalized
        self._template_inputs = pinned_inputs

    def _run(
        self,
        argv: Sequence[str],
        *,
        stdin: Optional[bytes] = None,
        timeout_seconds: float = 120.0,
        output_limit: int = 4096,
        pass_fds: Sequence[int] = (),
    ) -> ProcessResult:
        return self._runner.run(
            ProcessRequest.build(
                (*self._command, *argv),
                stdin=stdin,
                timeout_seconds=timeout_seconds,
                output_limit=output_limit,
                pass_fds=pass_fds,
            )
        )

    def discover(self, expected_handles: Sequence[ProviderHandle]) -> Discovery:
        expected = tuple(_require_lima_handle(handle) for handle in expected_handles)
        if not expected or len(set(expected)) != len(expected):
            raise ValueError("Lima discovery requires unique exact expected handles")
        result = self._run(
            ("list", "--json"),
            timeout_seconds=30,
            output_limit=1024 * 1024,
        )
        if not result.ok:
            return Discovery(Presence.UNKNOWN, detail=result.diagnostic(limit=1024))

        names = set()
        try:
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                    raise ValueError("inventory item has no string name")
                name = validate_identifier(item["name"], field_name="Lima instance name")
                if name in names:
                    raise ValueError("inventory contains a duplicate instance name")
                names.add(name)
        except (TypeError, ValueError) as error:
            return Discovery(Presence.UNKNOWN, detail=f"invalid Lima inventory: {error}")

        handles = tuple(handle for handle in expected if handle.value in names)
        if handles:
            return Discovery(Presence.PRESENT, handles)
        return Discovery(Presence.ABSENT)

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

    def create(self, identity: GuestIdentity) -> ProcessResult:
        exact = _require_lima_handle(identity.handle)
        if exact != derive_provider_handle("lima", identity.lab_id, identity.role):
            raise ValueError("Lima handle is not derived from the immutable lab identity")
        template = self._templates.get(identity.role)
        pinned = self._template_inputs.get(identity.role)
        if template is None or pinned is None:
            raise ValueError(f"no Lima template is configured for role {identity.role!r}")
        if not exact.value.endswith(f"-{identity.role}"):
            raise ValueError("Lima machine role does not match its exact provider handle")
        started = self._run(
            ("start", "--yes", "--name", exact.value, template),
            timeout_seconds=1800,
            pass_fds=(pinned.descriptor,),
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
        if self.read_guest_identity(exact) != identity:
            raise LimaProviderError("new Lima guest identity did not verify")
        return started

    def _delete_exact(self, handle: ProviderHandle) -> ProcessResult:
        exact = _require_lima_handle(handle)
        stopped = self._run(("stop", "--force", exact.value), timeout_seconds=300)
        deleted = self._run(("delete", "--force", exact.value), timeout_seconds=300)
        if deleted.ok and not stopped.ok:
            return ProcessResult(
                command=deleted.command,
                returncode=0,
                stdout=deleted.stdout,
                stderr=bounded_redacted(
                    "stop warning: " + stopped.diagnostic(limit=1024) + "\n" + deleted.stderr,
                    limit=deleted.output_limit,
                ),
                output_limit=deleted.output_limit,
            )
        return deleted

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
    "LimaProvider",
    "LimaProviderError",
]
