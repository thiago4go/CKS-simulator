"""Quick-tier Kind adapter preserving the existing CLI command contract."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional, Sequence, Tuple

from .base import (
    Discovery,
    GuestIdentity,
    OwnershipProofMode,
    Presence,
    ProcessRequest,
    ProcessResult,
    ProviderHandle,
    Runner,
    derive_provider_handle,
    guest_identity_payload,
    pin_provider_input,
    validate_identifier,
)


DEFAULT_IMAGE = "kindest/node:v1.35.1"
GUEST_IDENTITY_PATH = "/etc/cks-simulator/identity.json"
_MARKER_KEYS = {
    "schema_version",
    "managed_by",
    "lab_id",
    "machine_id",
    "role",
    "provider",
    "handle",
}
_WAIT_DURATION = re.compile(r"^[1-9][0-9]*(?:s|m|h)$")
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


class KindProviderError(RuntimeError):
    """Raised when Kind cannot positively prove the requested observation."""


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


def _default_command(name: str, candidates: Sequence[Path]) -> Tuple[str, ...]:
    for candidate in candidates:
        try:
            return _command_prefix((str(candidate),), field_name=f"{name} command")
        except (OSError, ValueError):
            continue
    raise ValueError(f"no trusted absolute {name} executable was found")


def _require_kind_handle(handle: ProviderHandle) -> ProviderHandle:
    if handle.provider != "kind":
        raise ValueError("Kind operations require an exact kind provider handle")
    return handle


def _parse_guest_marker(text: str, expected: ProviderHandle) -> GuestIdentity:
    try:
        payload = json.loads(text)
    except (TypeError, ValueError) as error:
        raise KindProviderError("Kind guest identity marker is not valid JSON") from error
    if not isinstance(payload, dict) or set(payload) != _MARKER_KEYS:
        raise KindProviderError("Kind guest identity marker has an invalid schema")
    if payload["schema_version"] != 1 or payload["managed_by"] != "cks-simulator":
        raise KindProviderError("Kind guest identity marker is not owned by cks-simulator")
    if payload["provider"] != expected.provider or payload["handle"] != expected.value:
        raise KindProviderError("Kind guest identity marker does not match the exact handle")
    try:
        return GuestIdentity(
            lab_id=payload["lab_id"],
            machine_id=payload["machine_id"],
            role=payload["role"],
            handle=expected,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise KindProviderError("Kind guest identity marker contains invalid identity data") from error


class KindProvider:
    """Provider implementation for the existing single-cluster quick tier."""

    name = "kind"

    def __init__(
        self,
        runner: Runner,
        *,
        config_path: str,
        state_dir: Path,
        image: str = DEFAULT_IMAGE,
        wait: str = "5m",
        command: Optional[Sequence[str]] = None,
        docker_command: Optional[Sequence[str]] = None,
    ) -> None:
        self._runner = runner
        project_kind = Path(__file__).resolve().parents[2] / "tools" / "kind"
        self._command = (
            _default_command(
                "Kind",
                (project_kind, Path("/opt/homebrew/bin/kind"), Path("/usr/local/bin/kind")),
            )
            if command is None
            else _command_prefix(command, field_name="Kind command")
        )
        self._docker_command = (
            _default_command(
                "Docker",
                (Path("/usr/local/bin/docker"), Path("/opt/homebrew/bin/docker"), Path("/usr/bin/docker")),
            )
            if docker_command is None
            else _command_prefix(docker_command, field_name="Docker command")
        )
        if not isinstance(config_path, str) or not config_path or "\0" in config_path:
            raise ValueError("Kind config path must be a non-empty string without NUL bytes")
        if not isinstance(image, str) or not image or "\0" in image:
            raise ValueError("Kind image must be a non-empty string without NUL bytes")
        config = Path(config_path)
        if (
            config_path.startswith("-")
            or not config.is_absolute()
        ):
            raise ValueError("Kind config must be an absolute path")
        if not isinstance(wait, str) or not _WAIT_DURATION.fullmatch(wait):
            raise ValueError("Kind wait must be a positive duration such as 5m")
        self._state_dir = Path(state_dir)
        self._config_input = pin_provider_input(
            str(config), self._state_dir, label="kind-config"
        )
        self._config_path = self._config_input.path
        self._image = image
        self._wait = wait

    def _run(
        self,
        prefix: Sequence[str],
        argv: Sequence[str],
        *,
        stdin: Optional[bytes] = None,
        timeout_seconds: float = 120.0,
        pass_fds: Sequence[int] = (),
    ) -> ProcessResult:
        return self._runner.run(
            ProcessRequest.build(
                (*prefix, *argv),
                stdin=stdin,
                timeout_seconds=timeout_seconds,
                pass_fds=pass_fds,
            )
        )

    def _kubeconfig(self, cluster_name: str) -> Path:
        validate_identifier(cluster_name, field_name="Kind cluster name")
        return self._state_dir / f"kubeconfig-{cluster_name}"

    def discover(self, expected_handles: Sequence[ProviderHandle]) -> Discovery:
        expected = tuple(_require_kind_handle(handle) for handle in expected_handles)
        if len(expected) != 1:
            raise ValueError("Kind discovery requires exactly one expected cluster handle")
        result = self._run(self._command, ("get", "clusters"), timeout_seconds=30)
        if not result.ok:
            return Discovery(Presence.UNKNOWN, detail=result.diagnostic(limit=1024))
        try:
            names = set()
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                name = validate_identifier(line, field_name="Kind cluster name")
                if name in names:
                    raise ValueError("Kind inventory contains a duplicate cluster name")
                names.add(name)
        except ValueError as error:
            return Discovery(Presence.UNKNOWN, detail=f"invalid Kind inventory: {error}")
        if expected[0].value in names:
            return Discovery(
                Presence.PRESENT,
                expected,
            )
        return Discovery(Presence.ABSENT)

    def read_guest_identity(self, handle: ProviderHandle) -> Optional[GuestIdentity]:
        exact = _require_kind_handle(handle)
        node = f"{exact.value}-control-plane"
        absent = self._run(
            self._docker_command,
            (
                "exec",
                node,
                "/bin/sh",
                "-c",
                _MARKER_ABSENT_SCRIPT,
            ),
            timeout_seconds=30,
        )
        if absent.ok:
            if absent.stdout or absent.stderr:
                raise KindProviderError(
                    "Kind guest marker absence probe returned unexpected output"
                )
            return None
        if absent.timed_out or absent.returncode != 1:
            raise KindProviderError(
                "unable to prove Kind guest marker presence: "
                + absent.diagnostic(limit=1024)
            )
        observed = self._run(
            self._docker_command,
            ("exec", node, "/bin/sh", "-c", _MARKER_READ_SCRIPT),
            timeout_seconds=30,
        )
        if not observed.ok:
            raise KindProviderError(
                "unable to read Kind guest identity marker: "
                + observed.diagnostic(limit=1024)
            )
        return _parse_guest_marker(observed.stdout, exact)

    def prove_ownership(
        self,
        expected: GuestIdentity,
        *,
        mode: OwnershipProofMode,
    ) -> bool:
        """Authorize exact Kind cleanup only from its root-owned node marker."""

        if not isinstance(mode, OwnershipProofMode):
            raise ValueError("cleanup ownership proof mode is invalid")
        exact = _require_kind_handle(expected.handle)
        if expected.role != "cluster":
            raise ValueError("Kind machine role must be 'cluster'")
        if exact != derive_provider_handle("kind", expected.lab_id, expected.role):
            raise ValueError("Kind handle is not derived from the immutable lab identity")
        discovery = self.discover((exact,))
        if discovery.presence is Presence.UNKNOWN:
            raise KindProviderError(
                "unable to prove Kind cleanup ownership: " + discovery.detail
            )
        if discovery.presence is Presence.ABSENT:
            return False
        return self.read_guest_identity(exact) == expected

    def create(self, identity: GuestIdentity) -> ProcessResult:
        exact = _require_kind_handle(identity.handle)
        if identity.role != "cluster":
            raise ValueError("Kind machine role must be 'cluster'")
        if exact != derive_provider_handle("kind", identity.lab_id, identity.role):
            raise ValueError("Kind handle is not derived from the immutable lab identity")
        started = self._run(
            self._command,
            (
                "create",
                "cluster",
                "--name",
                exact.value,
                "--image",
                self._image,
                "--config",
                self._config_path,
                "--kubeconfig",
                str(self._kubeconfig(exact.value)),
                "--wait",
                self._wait,
            ),
            timeout_seconds=900,
            pass_fds=(self._config_input.descriptor,),
        )
        if not started.ok:
            return started
        node = f"{exact.value}-control-plane"
        written = self._run(
            self._docker_command,
            ("exec", "-i", node, "/bin/sh", "-c", _MARKER_WRITE_SCRIPT),
            stdin=guest_identity_payload(identity),
            timeout_seconds=30,
        )
        if not written.ok:
            return written
        if self.read_guest_identity(exact) != identity:
            raise KindProviderError("new Kind guest identity did not verify")
        return started

    def _delete_exact(self, handle: ProviderHandle) -> ProcessResult:
        exact = _require_kind_handle(handle)
        argv = ["delete", "cluster", "--name", exact.value]
        kubeconfig = self._kubeconfig(exact.value)
        if kubeconfig.exists():
            argv.extend(("--kubeconfig", str(kubeconfig)))
        return self._run(self._command, argv, timeout_seconds=300)

    def close(self) -> None:
        self._config_input.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

__all__ = [
    "DEFAULT_IMAGE",
    "GUEST_IDENTITY_PATH",
    "KindProvider",
    "KindProviderError",
]
