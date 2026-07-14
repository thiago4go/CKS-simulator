"""Small, provider-neutral data and process-execution contracts.

Provider inventory describes infrastructure machines.  Kubernetes nodes are a
separate observation because a candidate VM is not a node and a broken cluster
must not make owned provider machines disappear from inventory.
"""

from __future__ import annotations

import hashlib
import os
import pwd
import re
import selectors
import signal
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Protocol, Sequence, Tuple


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----",
    re.DOTALL,
)
_NAMED_SECRET = re.compile(
    r"(?im)^(\s*(?:token|password|client-key-data|client-certificate-data|"
    r"certificate-authority-data)\s*[:=]\s*).*$"
)
_LOCALE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
_SAFE_BASE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_EXPLICIT_ENVIRONMENT = frozenset(
    ("HOME", "TMPDIR", "LANG", "LC_ALL", "LIMA_HOME", "DOCKER_HOST")
)
_MAX_PROVIDER_INPUT_BYTES = 4 * 1024 * 1024


def validate_identifier(value: str, *, field_name: str = "identifier", max_length: int = 63) -> str:
    """Return a canonical safe identifier or raise ``ValueError``.

    Identifiers are intentionally narrower than provider CLI arguments.  This
    prevents path traversal, option injection, shell metacharacters and visual
    ambiguity at every provider/state boundary.
    """

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if len(value) > max_length or not _IDENTIFIER.fullmatch(value):
        raise ValueError(
            f"{field_name} must be 1-{max_length} lowercase letters, digits, or single hyphens, "
            "starting with a letter"
        )
    return value


def canonical_uuid(value: str, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as error:
        raise ValueError(f"{field_name} must be a canonical UUID") from error
    canonical = str(parsed)
    if value != canonical:
        raise ValueError(f"{field_name} must be a canonical UUID")
    return canonical


def derive_provider_handle(provider: str, lab_id: str, role: str) -> "ProviderHandle":
    """Derive the only provider handle owned by a lab identity and role."""

    provider = validate_identifier(provider, field_name="provider")
    canonical = canonical_uuid(lab_id, field_name="lab_id")
    role = validate_identifier(role, field_name="machine role")
    prefix = uuid.UUID(canonical).hex[:16]
    if provider == "lima":
        return ProviderHandle(provider, f"cks-{prefix}-{role}")
    if provider == "kind":
        if role != "cluster":
            raise ValueError("Kind provider identity requires the 'cluster' role")
        return ProviderHandle(provider, f"cks-{prefix}-cluster")
    raise ValueError(f"unsupported provider {provider!r}")


def _utf8_bounded(value: str, limit: int) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value
    marker = b"...[truncated]"
    if limit <= len(marker):
        return encoded[:limit].decode("utf-8", errors="ignore")
    prefix = encoded[: limit - len(marker)].decode("utf-8", errors="ignore")
    return prefix + marker.decode("ascii")


def bounded_redacted(
    value: object,
    *,
    secrets: Sequence[str] = (),
    limit: int = 4096,
) -> str:
    """Render diagnostic text with known/common secrets removed and a byte cap."""

    if not isinstance(limit, int) or limit < 1:
        raise ValueError("diagnostic limit must be a positive integer")
    if isinstance(value, bytes):
        rendered = value.decode("utf-8", errors="replace")
    else:
        rendered = str(value)
    for secret in secrets:
        if secret:
            rendered = rendered.replace(secret, "[REDACTED]")
    rendered = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", rendered)
    rendered = _NAMED_SECRET.sub(r"\1[REDACTED]", rendered)
    rendered = "".join(
        character
        if character in "\n\t" or (ord(character) >= 32 and not 127 <= ord(character) <= 159)
        else f"\\x{ord(character):02x}"
        for character in rendered
    )
    return _utf8_bounded(rendered, limit)


@dataclass
class PinnedProviderInput:
    """Verified provider input held by an unlinked read-only descriptor."""

    descriptor: int
    sha256: str
    size: int
    _closed: bool = field(default=False, init=False, repr=False)

    @property
    def path(self) -> str:
        if self._closed:
            raise ValueError("provider input descriptor is closed")
        return f"/dev/fd/{self.descriptor}"

    def close(self) -> None:
        if self._closed:
            return
        try:
            os.close(self.descriptor)
        finally:
            self._closed = True


def pin_provider_input(
    source: str, destination_root: Path, *, label: str
) -> PinnedProviderInput:
    """Pin a source to an anonymous descriptor for exact child consumption.

    The source is read once through a no-follow descriptor, copied into an
    owner-only directory, verified, opened read-only, and unlinked before this
    function returns. A later pathname replacement therefore cannot change the
    bytes exposed to a provider through ``/dev/fd``.
    """

    validate_identifier(label, field_name="provider input label")
    source_path = Path(source)
    if not source_path.is_absolute():
        raise ValueError("provider input source must be an absolute path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(str(source_path), flags)
    except OSError as error:
        raise ValueError("provider input must be an existing non-symlink file") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_PROVIDER_INPUT_BYTES:
            raise ValueError("provider input must be a bounded regular file")
        chunks = bytearray()
        while len(chunks) <= _MAX_PROVIDER_INPUT_BYTES:
            chunk = os.read(descriptor, min(65536, _MAX_PROVIDER_INPUT_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        if len(chunks) > _MAX_PROVIDER_INPUT_BYTES:
            raise ValueError("provider input exceeds the maximum size")
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(chunks) != after.st_size
        ):
            raise ValueError("provider input changed while it was being pinned")
    finally:
        os.close(descriptor)

    root = Path(destination_root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("provider input destination must be an absolute non-symlink directory")
    root = root.resolve(strict=True)
    root_descriptor = os.open(
        str(root),
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        root_stat = os.fstat(root_descriptor)
        if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) & 0o077:
            raise ValueError("provider input destination must be owner-only")
        try:
            os.mkdir("provider-inputs", 0o700, dir_fd=root_descriptor)
        except FileExistsError:
            pass
        input_descriptor = os.open(
            "provider-inputs",
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        try:
            input_stat = os.fstat(input_descriptor)
            if input_stat.st_uid != os.getuid() or stat.S_IMODE(input_stat.st_mode) & 0o077:
                raise ValueError("provider input snapshot directory must be owner-only")
            digest = hashlib.sha256(chunks).hexdigest()
            filename = f".{label}-{digest}-{uuid.uuid4().hex}.input"
            create_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            output = os.open(filename, create_flags, 0o600, dir_fd=input_descriptor)
            try:
                offset = 0
                while offset < len(chunks):
                    written = os.write(output, chunks[offset:])
                    if written < 1:
                        raise OSError("short provider input snapshot write")
                    offset += written
                os.fsync(output)
                os.fchmod(output, 0o400)
            finally:
                os.close(output)
            verify = -1
            try:
                verify = os.open(
                    filename,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=input_descriptor,
                )
                observed = os.fstat(verify)
                if (
                    not stat.S_ISREG(observed.st_mode)
                    or observed.st_uid != os.getuid()
                    or stat.S_IMODE(observed.st_mode) != 0o400
                    or observed.st_size != len(chunks)
                ):
                    raise ValueError("provider input snapshot is unsafe")
                materialized = bytearray()
                while True:
                    chunk = os.read(verify, 65536)
                    if not chunk:
                        break
                    materialized.extend(chunk)
                if hashlib.sha256(materialized).hexdigest() != digest:
                    raise ValueError("provider input snapshot digest mismatch")
                os.lseek(verify, 0, os.SEEK_SET)
                os.unlink(filename, dir_fd=input_descriptor)
                os.fsync(input_descriptor)
                pinned = PinnedProviderInput(verify, digest, len(chunks))
                verify = -1
            finally:
                if verify >= 0:
                    os.close(verify)
                try:
                    os.unlink(filename, dir_fd=input_descriptor)
                except FileNotFoundError:
                    pass
        finally:
            os.close(input_descriptor)
    finally:
        os.close(root_descriptor)
    return pinned


class Presence(str, Enum):
    """Fail-closed result of provider discovery."""

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


@dataclass(frozen=True, order=True)
class ProviderHandle:
    """An exact provider-native resource handle, never a prefix or glob."""

    provider: str
    value: str

    def __post_init__(self) -> None:
        validate_identifier(self.provider, field_name="provider")
        validate_identifier(self.value, field_name="provider handle")


@dataclass(frozen=True)
class ProviderMachine:
    """Write-ahead machine identity and its exact provider handle."""

    role: str
    machine_id: str
    handle: ProviderHandle

    def __post_init__(self) -> None:
        validate_identifier(self.role, field_name="machine role")
        canonical_uuid(self.machine_id, field_name="machine_id")


@dataclass(frozen=True)
class GuestIdentity:
    """Identity marker read from inside a provider machine."""

    lab_id: str
    machine_id: str
    role: str
    handle: ProviderHandle

    def __post_init__(self) -> None:
        canonical_uuid(self.lab_id, field_name="lab_id")
        canonical_uuid(self.machine_id, field_name="machine_id")
        validate_identifier(self.role, field_name="machine role")


def guest_identity_payload(identity: GuestIdentity) -> bytes:
    """Return the canonical root-owned guest marker payload."""

    import json

    return (
        json.dumps(
            {
                "schema_version": 1,
                "managed_by": "cks-simulator",
                "lab_id": identity.lab_id,
                "machine_id": identity.machine_id,
                "role": identity.role,
                "provider": identity.handle.provider,
                "handle": identity.handle.value,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


@dataclass(frozen=True)
class KubernetesNode:
    """Cluster observation kept deliberately separate from provider inventory."""

    name: str
    ready: bool
    machine_id: Optional[str] = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str)
            or len(self.name) > 253
            or any(not _DNS_LABEL.fullmatch(label) for label in self.name.split("."))
        ):
            raise ValueError("Kubernetes node name must be a lowercase DNS subdomain")
        if not isinstance(self.ready, bool):
            raise ValueError("ready must be a boolean")
        if self.machine_id is not None:
            canonical_uuid(self.machine_id, field_name="machine_id")


@dataclass(frozen=True)
class Discovery:
    presence: Presence
    handles: Tuple[ProviderHandle, ...] = ()
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "handles", tuple(self.handles))
        if not isinstance(self.presence, Presence):
            raise ValueError("presence must be a Presence value")
        if self.presence is Presence.PRESENT and not self.handles:
            raise ValueError("present discovery requires at least one exact handle")
        if self.presence is not Presence.PRESENT and self.handles:
            raise ValueError("absent or unknown discovery cannot report handles")
        if len(set(self.handles)) != len(self.handles):
            raise ValueError("discovery handles must be unique")
        object.__setattr__(self, "detail", bounded_redacted(self.detail, limit=1024))


@dataclass(frozen=True)
class ProcessRequest:
    """A subprocess invocation whose arguments can never become shell source."""

    argv: Tuple[str, ...]
    stdin: Optional[bytes] = None
    timeout_seconds: float = 120.0
    output_limit: int = 4096
    secrets: Tuple[str, ...] = ()
    cwd: Optional[str] = None
    environment: Tuple[Tuple[str, str], ...] = ()
    pass_fds: Tuple[int, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "argv", tuple(self.argv))
        object.__setattr__(self, "secrets", tuple(self.secrets))
        object.__setattr__(self, "pass_fds", tuple(self.pass_fds))
        if not self.argv or not self.argv[0]:
            raise ValueError("argv requires a non-empty executable")
        if any(not isinstance(argument, str) or "\0" in argument for argument in self.argv):
            raise ValueError("argv entries must be strings without NUL bytes")
        if self.stdin is not None and not isinstance(self.stdin, bytes):
            raise ValueError("stdin must be bytes or None")
        if any(not isinstance(secret, str) for secret in self.secrets):
            raise ValueError("secrets must contain strings")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not isinstance(self.output_limit, int) or not 1 <= self.output_limit <= 1024 * 1024:
            raise ValueError("output_limit must be between 1 and 1048576 bytes")
        environment = tuple(self.environment)
        for item in environment:
            if not isinstance(item, tuple) or len(item) != 2:
                raise ValueError("environment entries must be key/value pairs")
            key, value = item
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or not key
                or "\0" in key
                or "=" in key
                or "\0" in value
            ):
                raise ValueError("environment entries contain an invalid key or NUL byte")
        if self.cwd is not None and (not isinstance(self.cwd, str) or "\0" in self.cwd):
            raise ValueError("cwd must be a string without NUL bytes")
        if any(
            not isinstance(descriptor, int) or isinstance(descriptor, bool) or descriptor < 0
            for descriptor in self.pass_fds
        ) or len(set(self.pass_fds)) != len(self.pass_fds):
            raise ValueError("pass_fds must contain unique non-negative descriptors")
        for descriptor in self.pass_fds:
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError("pass_fds may contain only open regular files")
            except OSError as error:
                raise ValueError("pass_fds contains a closed descriptor") from error
        object.__setattr__(self, "environment", environment)

    @classmethod
    def build(
        cls,
        argv: Sequence[str],
        *,
        stdin: Optional[bytes] = None,
        timeout_seconds: float = 120.0,
        output_limit: int = 4096,
        secrets: Sequence[str] = (),
        cwd: Optional[str] = None,
        environment: Optional[Mapping[str, str]] = None,
        pass_fds: Sequence[int] = (),
    ) -> "ProcessRequest":
        return cls(
            argv=tuple(argv),
            stdin=stdin,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
            secrets=tuple(secrets),
            cwd=cwd,
            environment=tuple((environment or {}).items()),
            pass_fds=tuple(pass_fds),
        )


@dataclass(frozen=True)
class ProcessResult:
    command: Tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limit: int = field(default=4096, repr=False)

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.returncode == 0

    def diagnostic(self, *, limit: Optional[int] = None) -> str:
        cap = self.output_limit if limit is None else limit
        rendered = "command={} returncode={} timed_out={}\nstdout:\n{}\nstderr:\n{}".format(
            " ".join(self.command),
            self.returncode,
            str(self.timed_out).lower(),
            self.stdout,
            self.stderr,
        )
        return bounded_redacted(rendered, limit=cap)


class Runner(Protocol):
    def run(self, request: ProcessRequest) -> ProcessResult:
        ...


class SubprocessRunner:
    """Execute requests with bounded pipes and a minimal explicit environment."""

    @staticmethod
    def _safe_path(value: str, *, field_name: str) -> str:
        candidate = Path(value)
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"{field_name} must be an absolute normalized path")
        return str(candidate)

    @classmethod
    def _environment(cls, request: ProcessRequest) -> dict[str, str]:
        environment = {
            "PATH": _SAFE_BASE_PATH,
            "HOME": cls._safe_path(
                pwd.getpwuid(os.getuid()).pw_dir, field_name="account HOME"
            ),
            "TMPDIR": "/tmp",
            "LANG": "C",
            "LC_ALL": "C",
        }
        for key, value in request.environment:
            if key not in _EXPLICIT_ENVIRONMENT:
                raise ValueError(f"environment variable {key!r} is not allowlisted")
            environment[key] = cls._validated_environment_value(key, value)
        return environment

    @classmethod
    def _validated_environment_value(cls, key: str, value: str) -> str:
        if key in {"HOME", "TMPDIR", "LIMA_HOME"}:
            return cls._safe_path(value, field_name=key)
        if key in {"LANG", "LC_ALL"}:
            if not _LOCALE.fullmatch(value):
                raise ValueError(f"{key} contains unsafe characters")
            return value
        if key == "DOCKER_HOST":
            if not value.startswith("unix://"):
                raise ValueError("DOCKER_HOST must name an absolute Unix socket")
            socket_path = cls._safe_path(value[7:], field_name="DOCKER_HOST socket")
            return f"unix://{socket_path}"
        raise ValueError(f"environment variable {key!r} is not allowlisted")

    @staticmethod
    def _bounded_append(target: bytearray, chunk: bytes, limit: int) -> None:
        remaining = limit - len(target)
        if remaining > 0:
            target.extend(chunk[:remaining])

    @staticmethod
    def _close_registered(selector: selectors.BaseSelector, stream: object) -> None:
        try:
            selector.unregister(stream)
        except (KeyError, ValueError):
            pass
        try:
            stream.close()  # type: ignore[attr-defined]
        except OSError:
            pass

    def run(self, request: ProcessRequest) -> ProcessResult:
        environment = self._environment(request)
        source_limit = min(
            2 * 1024 * 1024,
            request.output_limit
            + 65536
            + max((len(secret.encode("utf-8")) for secret in request.secrets), default=0),
        )
        stdout = bytearray()
        stderr = bytearray()
        process = subprocess.Popen(
            list(request.argv),
            stdin=subprocess.PIPE if request.stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            cwd=request.cwd,
            env=environment,
            bufsize=0,
            start_new_session=True,
            pass_fds=request.pass_fds,
        )
        selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout))
        selector.register(process.stderr, selectors.EVENT_READ, ("stderr", stderr))
        stdin_offset = 0
        if request.stdin is not None:
            assert process.stdin is not None
            if request.stdin:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, ("stdin", None))
            else:
                process.stdin.close()
        timed_out = False
        deadline = time.monotonic() + request.timeout_seconds
        drain_deadline: Optional[float] = None
        try:
            while process.poll() is None or selector.get_map():
                now = time.monotonic()
                if process.poll() is None and now >= deadline and not timed_out:
                    timed_out = True
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        process.kill()
                if process.poll() is not None and drain_deadline is None:
                    drain_deadline = now + 1.0
                if drain_deadline is not None and now >= drain_deadline:
                    for key in tuple(selector.get_map().values()):
                        self._close_registered(selector, key.fileobj)
                    break
                events = selector.select(timeout=0.05)
                for key, _ in events:
                    stream = key.fileobj
                    channel, target = key.data
                    if channel == "stdin":
                        assert request.stdin is not None
                        try:
                            written = os.write(
                                stream.fileno(),  # type: ignore[attr-defined]
                                request.stdin[stdin_offset : stdin_offset + 65536],
                            )
                            stdin_offset += written
                            if stdin_offset >= len(request.stdin):
                                self._close_registered(selector, stream)
                        except (BrokenPipeError, OSError):
                            self._close_registered(selector, stream)
                        continue
                    try:
                        chunk = os.read(stream.fileno(), 65536)  # type: ignore[attr-defined]
                    except BlockingIOError:
                        continue
                    if not chunk:
                        self._close_registered(selector, stream)
                    else:
                        self._bounded_append(target, chunk, source_limit)
        finally:
            for key in tuple(selector.get_map().values()):
                self._close_registered(selector, key.fileobj)
            selector.close()
            if process.poll() is None:
                process.kill()
            process.wait()
        stderr_value: object = bytes(stderr)
        if timed_out and not stderr:
            stderr_value = b"timeout expired"
        return ProcessResult(
            command=tuple(
                bounded_redacted(argument, secrets=request.secrets, limit=512)
                for argument in request.argv
            ),
            returncode=124 if timed_out else process.returncode,
            stdout=bounded_redacted(
                bytes(stdout), secrets=request.secrets, limit=request.output_limit
            ),
            stderr=bounded_redacted(
                stderr_value, secrets=request.secrets, limit=request.output_limit
            ),
            timed_out=timed_out,
            output_limit=request.output_limit,
        )


class Provider(Protocol):
    """Minimal lifecycle surface implemented by concrete providers."""

    name: str

    def discover(self, expected_handles: Sequence[ProviderHandle]) -> Discovery:
        ...

    def read_guest_identity(self, handle: ProviderHandle) -> Optional[GuestIdentity]:
        ...

    def create(self, identity: GuestIdentity) -> ProcessResult:
        ...

    def _delete_exact(self, handle: ProviderHandle) -> ProcessResult:
        ...
