"""Command line implementation for the local CKS simulator."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional

from .grading import grade_scenario, summarize_grades
from .providers.base import (
    ProcessRequest,
    SubprocessRunner,
    bounded_redacted,
    validate_identifier,
)


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "scenarios" / "catalog.json"
DEFAULT_CLUSTER = "cks-simulator"
DEFAULT_IMAGE = "kindest/node:v1.35.1"
EXPECTED_NODE_COUNT = 3
LIVE_FIXTURE_IDS = {"04", "06", "07", "11", "15"}
SUPPORTED_TIERS = {"quick", "full"}
PROCESS_OUTPUT_LIMIT = 64 * 1024
PROCESS_TIMEOUT_SECONDS = 900.0
_SAFE_CHILD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_PROCESS_RUNNER = SubprocessRunner()
_TOOL_CANDIDATES = {
    "kind": (
        "/opt/homebrew/bin/kind",
        "/usr/local/bin/kind",
        "/usr/bin/kind",
    ),
    "docker": (
        "/Applications/Docker.app/Contents/Resources/bin/docker",
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        "/usr/bin/docker",
    ),
    "kubectl": (
        "/Applications/Docker.app/Contents/Resources/bin/kubectl",
        "/usr/local/bin/kubectl",
        "/opt/homebrew/bin/kubectl",
        "/usr/bin/kubectl",
    ),
    "openssl": ("/usr/bin/openssl", "/opt/homebrew/bin/openssl"),
    "curl": ("/usr/bin/curl", "/opt/homebrew/bin/curl"),
    "checksum": (
        "/usr/bin/shasum",
        "/usr/bin/sha256sum",
        "/opt/homebrew/bin/sha256sum",
    ),
    "awk": ("/usr/bin/awk", "/bin/awk"),
    "env": ("/usr/bin/env",),
}
QUICK_MARKER_PATH = "/etc/cks-simulator/quick-identity.json"
_QUICK_MARKER_KEYS = {
    "schema_version",
    "managed_by",
    "cluster_name",
    "claim_id",
    "container_id",
}
_CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
_MARKER_WRITE_SCRIPT = (
    "set -eu; umask 077; "
    "/usr/bin/install -d -m 0700 -o root -g root /etc/cks-simulator; "
    "p=/etc/cks-simulator/quick-identity.json; "
    "[ ! -e \"$p\" ] && [ ! -L \"$p\" ]; "
    "t=/etc/cks-simulator/.quick-identity.json.tmp; "
    "[ ! -e \"$t\" ] && [ ! -L \"$t\" ]; "
    "/bin/cat > \"$t\"; /bin/chown root:root \"$t\"; /bin/chmod 0600 \"$t\"; "
    "/bin/mv -fT \"$t\" \"$p\""
)
_MARKER_READ_SCRIPT = (
    "set -eu; p=/etc/cks-simulator/quick-identity.json; "
    "[ -f \"$p\" ] && [ ! -L \"$p\" ]; "
    "[ \"$(/usr/bin/stat -c %u:%g:%a \"$p\")\" = \"0:0:600\" ]; "
    "/bin/cat \"$p\""
)


@dataclass(frozen=True)
class QuickLifecycleResult:
    """One quick-tier lifecycle outcome, rendered once by the public wrapper."""

    command: str
    name: str
    returncode: int
    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    def payload(self) -> Dict[str, Any]:
        return {
            "status": "ok" if self.returncode == 0 else "error",
            "command": self.command,
            "tier": "quick",
            "name": self.name,
            "returncode": self.returncode,
            "message": self.message,
            "details": self.details,
        }


class TierDispatchError(RuntimeError):
    """Structured routing failure raised before any tier implementation runs."""

    def __init__(self, code: str, message: str, *, command: str, tier: str) -> None:
        super().__init__(message)
        self.code = code
        self.command = command
        self.tier = tier


def load_catalog() -> List[Dict[str, Any]]:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def state_dir() -> Path:
    value = os.environ.get("CKS_STATE_DIR")
    if not value:
        return ROOT / ".cks-state"
    return Path(os.path.abspath(os.path.expanduser(value)))


def validate_cluster_name(name: str) -> str:
    return validate_identifier(name, field_name="cluster name")


def cluster_name(args: argparse.Namespace) -> str:
    return validate_cluster_name(args.name or os.environ.get("CKS_CLUSTER_NAME", DEFAULT_CLUSTER))


def kubeconfig_path(name: str) -> Path:
    return state_dir() / _kubeconfig_filename(name)


def metadata_path(name: str) -> Path:
    return state_dir() / _metadata_filename(name)


def e2e_claim_path(name: str) -> Path:
    return state_dir() / _claim_filename(name)


def _kubeconfig_filename(name: str) -> str:
    return f"kubeconfig-{validate_cluster_name(name)}"


def _metadata_filename(name: str) -> str:
    return f"cluster-{validate_cluster_name(name)}.json"


def _claim_filename(name: str) -> str:
    return f"e2e-claim-{validate_cluster_name(name)}"


def _validate_state_filename(filename: str) -> str:
    if (
        not isinstance(filename, str)
        or not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\0" in filename
    ):
        raise ValueError("state filename must be one safe path component")
    return filename


@contextmanager
def _state_root_fd(*, create: bool) -> Iterator[int]:
    """Open the trusted state directory without following its final component."""

    root = state_dir()
    if create:
        try:
            root.mkdir(parents=True, mode=0o700)
        except FileExistsError:
            pass
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(root, flags)
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        raise RuntimeError(f"state root {root} is missing, symlinked, or inaccessible") from exc
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) & 0o077
        ):
            raise RuntimeError(
                f"state root {root} must be an owner-only directory owned by uid {os.getuid()}"
            )
        yield descriptor
    finally:
        os.close(descriptor)


def _entry_stat(root_fd: int, filename: str) -> Optional[os.stat_result]:
    try:
        return os.stat(
            _validate_state_filename(filename),
            dir_fd=root_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None


def _require_regular_state_entry(
    root_fd: int, filename: str, *, allow_missing: bool
) -> Optional[os.stat_result]:
    observed = _entry_stat(root_fd, filename)
    if observed is None and allow_missing:
        return None
    if observed is None:
        raise RuntimeError(f"state entry {filename!r} does not exist")
    if not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid():
        raise RuntimeError(f"state entry {filename!r} must be an owned regular file")
    if stat.S_IMODE(observed.st_mode) & 0o077:
        raise RuntimeError(f"state entry {filename!r} must not be accessible by group or other")
    return observed


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written < 1:
            raise OSError("short write while storing quick-tier state")
        offset += written


def _write_state_bytes(filename: str, value: bytes) -> None:
    filename = _validate_state_filename(filename)
    if not isinstance(value, bytes):
        raise TypeError("state content must be bytes")
    temporary = f".tmp-{uuid.uuid4().hex}"
    with _state_root_fd(create=True) as root_fd:
        _require_regular_state_entry(root_fd, filename, allow_missing=True)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(temporary, flags, 0o600, dir_fd=root_fd)
        try:
            _write_all(descriptor, value)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(
                temporary,
                filename,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
            )
            os.fsync(root_fd)
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=root_fd)
            except FileNotFoundError:
                pass
            raise


def _write_state_json(filename: str, value: Dict[str, Any]) -> None:
    rendered = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_state_bytes(filename, rendered)


def _read_state_bytes(filename: str, *, limit: int = 65536) -> Optional[bytes]:
    filename = _validate_state_filename(filename)
    try:
        root_context = _state_root_fd(create=False)
        with root_context as root_fd:
            if _require_regular_state_entry(root_fd, filename, allow_missing=True) is None:
                return None
            flags = (
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            descriptor = os.open(filename, flags, dir_fd=root_fd)
            try:
                observed = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(observed.st_mode)
                    or observed.st_uid != os.getuid()
                    or stat.S_IMODE(observed.st_mode) & 0o077
                ):
                    return None
                value = bytearray()
                while len(value) <= limit:
                    chunk = os.read(descriptor, min(8192, limit + 1 - len(value)))
                    if not chunk:
                        break
                    value.extend(chunk)
                return bytes(value) if len(value) <= limit else None
            finally:
                os.close(descriptor)
    except (FileNotFoundError, NotADirectoryError, OSError, RuntimeError):
        return None


def _read_state_json(filename: str) -> Optional[Dict[str, Any]]:
    raw = _read_state_bytes(filename)
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _remove_state_file(filename: str) -> bool:
    filename = _validate_state_filename(filename)
    try:
        with _state_root_fd(create=False) as root_fd:
            if _require_regular_state_entry(root_fd, filename, allow_missing=True) is None:
                return False
            os.unlink(filename, dir_fd=root_fd)
            os.fsync(root_fd)
            return True
    except FileNotFoundError:
        return False
    except RuntimeError:
        if not os.path.lexists(state_dir()):
            return False
        raise


def _state_entry_exists(filename: str) -> bool:
    try:
        with _state_root_fd(create=False) as root_fd:
            return _entry_stat(root_fd, filename) is not None
    except (OSError, RuntimeError):
        return False


def _assert_state_destination_safe(filename: str) -> None:
    with _state_root_fd(create=True) as root_fd:
        _require_regular_state_entry(root_fd, filename, allow_missing=True)


def _adopt_kubeconfig(source: str, destination: str) -> None:
    with _state_root_fd(create=False) as root_fd:
        _require_regular_state_entry(root_fd, source, allow_missing=False)
        _require_regular_state_entry(root_fd, destination, allow_missing=True)
        descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        try:
            os.fchmod(descriptor, 0o600)
            observed = os.fstat(descriptor)
            if not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid():
                raise RuntimeError("Kind kubeconfig is not an owned regular file")
        finally:
            os.close(descriptor)
        os.replace(source, destination, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)


def _parse_quick_identity(value: object, name: str) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict) or not _QUICK_MARKER_KEYS.issubset(value):
        return None
    if (
        value.get("schema_version") != 1
        or value.get("managed_by") != "cks-simulator"
        or value.get("cluster_name") != name
    ):
        return None
    claim_id = value.get("claim_id")
    container_id = value.get("container_id")
    try:
        if not isinstance(claim_id, str) or str(uuid.UUID(claim_id)) != claim_id:
            return None
    except ValueError:
        return None
    if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
        return None
    return {key: value[key] for key in _QUICK_MARKER_KEYS}


def _inspect_kind_control_plane(name: str) -> Optional[Dict[str, str]]:
    docker = docker_command()
    if not docker:
        return None
    node = f"{validate_cluster_name(name)}-control-plane"
    result = command_output(
        [docker, "inspect", "--type", "container", node], announce=False
    )
    if result.returncode != 0:
        return None
    try:
        values = json.loads(result.stdout)
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            return None
        observed = values[0]
        labels = observed["Config"]["Labels"]
        container_id = observed["Id"]
        if (
            observed.get("Name") != f"/{node}"
            or not isinstance(labels, dict)
            or labels.get("io.x-k8s.kind.cluster") != name
            or labels.get("io.x-k8s.kind.role") != "control-plane"
            or not isinstance(container_id, str)
            or not _CONTAINER_ID.fullmatch(container_id)
        ):
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return {"node": node, "container_id": container_id}


def _marker_payload(identity: Dict[str, Any]) -> str:
    return json.dumps(
        {key: identity[key] for key in sorted(_QUICK_MARKER_KEYS)},
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def _write_quick_marker(identity: Dict[str, Any]) -> bool:
    parsed = _parse_quick_identity(identity, str(identity.get("cluster_name", "")))
    if parsed is None:
        return False
    observed = _inspect_kind_control_plane(parsed["cluster_name"])
    if not observed or observed["container_id"] != parsed["container_id"]:
        return False
    docker = docker_command()
    if not docker:
        return False
    result = command_output(
        [docker, "exec", "-i", observed["node"], "/bin/sh", "-c", _MARKER_WRITE_SCRIPT],
        announce=False,
        input_text=_marker_payload(parsed),
    )
    return result.returncode == 0 and _read_quick_marker(parsed["cluster_name"]) == parsed


def _read_quick_marker(name: str) -> Optional[Dict[str, Any]]:
    observed = _inspect_kind_control_plane(name)
    docker = docker_command()
    if not observed or not docker:
        return None
    result = command_output(
        [docker, "exec", observed["node"], "/bin/sh", "-c", _MARKER_READ_SCRIPT],
        announce=False,
    )
    if result.returncode != 0:
        return None
    try:
        parsed = _parse_quick_identity(json.loads(result.stdout), name)
    except ValueError:
        return None
    if parsed is None or parsed["container_id"] != observed["container_id"]:
        return None
    return parsed


def state_is_owned(name: str) -> bool:
    name = validate_cluster_name(name)
    metadata = _read_state_json(_metadata_filename(name))
    if metadata is None or metadata.get("status") not in {"ready", "nodes-not-ready"}:
        return False
    identity = _parse_quick_identity(metadata, name)
    return identity is not None and _read_quick_marker(name) == identity


def _validated_executable(
    value: str, *, field_name: str, explicit_override: bool
) -> str:
    """Return a normalized trusted executable or reject the path fail-closed."""

    message = f"{field_name} must be an absolute regular executable path"
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError(message)
    candidate = Path(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(message)
    try:
        if explicit_override and candidate.is_symlink():
            raise ValueError(message)
        normalized = candidate if explicit_override else candidate.resolve(strict=True)
        descriptor = os.open(
            normalized,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(message) from exc
    try:
        observed = os.fstat(descriptor)
        mode = stat.S_IMODE(observed.st_mode)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid not in {0, os.getuid()}
            or mode & 0o022
            or not mode & 0o111
        ):
            raise ValueError(message)
    finally:
        os.close(descriptor)
    return str(normalized)


def _resolve_tool(
    tool: str, *, override: Optional[str] = None, field_name: Optional[str] = None
) -> Optional[str]:
    if override:
        return _validated_executable(
            override,
            field_name=field_name or f"{tool} override",
            explicit_override=True,
        )
    for candidate in _TOOL_CANDIDATES[tool]:
        try:
            return _validated_executable(
                candidate,
                field_name=field_name or tool,
                explicit_override=False,
            )
        except ValueError:
            continue
    return None


def global_kind() -> Optional[str]:
    return _resolve_tool("kind")


def kind_command() -> List[str]:
    explicit = os.environ.get("CKS_KIND_BIN")
    if explicit:
        return [
            _validated_executable(
                explicit,
                field_name="CKS_KIND_BIN",
                explicit_override=True,
            )
        ]
    discovered = global_kind()
    if os.environ.get("CKS_KIND_USE_GLOBAL", "1") != "0" and discovered:
        return [discovered]
    fallback = _validated_executable(
        str(ROOT / "tools" / "kind"),
        field_name="pinned Kind fallback",
        explicit_override=False,
    )
    return [fallback]


def kubectl_command() -> Optional[str]:
    return _resolve_tool(
        "kubectl", override=os.environ.get("KUBECTL_BIN"), field_name="KUBECTL_BIN"
    )


def docker_command() -> Optional[str]:
    return _resolve_tool(
        "docker", override=os.environ.get("DOCKER_BIN"), field_name="DOCKER_BIN"
    )


def curl_command() -> Optional[str]:
    return _resolve_tool(
        "curl", override=os.environ.get("CURL_BIN"), field_name="CURL_BIN"
    )


def checksum_command() -> Optional[str]:
    return _resolve_tool(
        "checksum",
        override=os.environ.get("CHECKSUM_BIN"),
        field_name="CHECKSUM_BIN",
    )


def openssl_command() -> Optional[str]:
    return _resolve_tool(
        "openssl",
        override=os.environ.get("OPENSSL_BIN"),
        field_name="OPENSSL_BIN",
    )


def awk_command() -> Optional[str]:
    return _resolve_tool("awk", override=os.environ.get("AWK_BIN"), field_name="AWK_BIN")


def generate_tls_fixture(destination: Path) -> None:
    openssl = openssl_command()
    if not openssl:
        raise RuntimeError("openssl is required to generate the scenario 15 TLS fixture; run 'doctor'")
    destination.mkdir(parents=True, exist_ok=True)
    result = command_output(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(destination / "tls.key"),
            "-out", str(destination / "tls.crt"),
            "-subj", "/CN=secure-ingress.test", "-days", "3650",
        ],
        announce=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"openssl failed while generating scenario 15 TLS fixture: {result.stderr.strip()}")
    os.chmod(destination / "tls.key", 0o600)


def acquire_e2e_claim(name: str) -> Optional[str]:
    token = uuid.uuid4().hex
    filename = _claim_filename(name)
    with _state_root_fd(create=True) as root_fd:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(filename, flags, 0o600, dir_fd=root_fd)
        except FileExistsError:
            return None
        try:
            _write_all(descriptor, (token + "\n").encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(root_fd)
    return token


def e2e_claim_is_owned(name: str, token: Optional[str]) -> bool:
    if not token:
        return False
    try:
        raw = _read_state_bytes(_claim_filename(name), limit=128)
        return raw is not None and raw.decode("ascii").strip() == token
    except (OSError, UnicodeDecodeError):
        return False


def _safe_command_display(command: List[str]) -> str:
    return bounded_redacted(shlex.join(command), limit=4096)


def _emit_process_output(value: str, *, stream: Any) -> None:
    if not value:
        return
    rendered = bounded_redacted(value, limit=PROCESS_OUTPUT_LIMIT)
    stream.write(rendered)
    if not rendered.endswith("\n"):
        stream.write("\n")


def _bounded_process(
    command: List[str],
    *,
    input_text: Optional[str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    """Execute one noninteractive command with bounded output and a scrubbed env."""

    if not command:
        raise ValueError("command must contain a trusted absolute executable")
    normalized = list(command)
    normalized[0] = _validated_executable(
        normalized[0], field_name="command executable", explicit_override=False
    )
    execution = list(normalized)
    trusted_path: Optional[tempfile.TemporaryDirectory[str]] = None
    try:
        # Kind locates its container provider by name. Supply only a private
        # `docker` entry plus the fixed system path, never the caller's PATH.
        if Path(normalized[0]).name == "kind":
            trusted_path = tempfile.TemporaryDirectory(
                prefix="cks-simulator-exec-", dir="/tmp"
            )
            directory = Path(trusted_path.name)
            docker = docker_command()
            if docker:
                (directory / "docker").symlink_to(docker)
            env_binary = _resolve_tool("env")
            if not env_binary:
                raise RuntimeError("trusted /usr/bin/env is unavailable")
            execution = [
                env_binary,
                f"PATH={directory}:{_SAFE_CHILD_PATH}",
                f"CKS_STATE_DIR={state_dir()}",
                *normalized,
            ]
        result = _PROCESS_RUNNER.run(
            ProcessRequest.build(
                execution,
                stdin=input_text.encode("utf-8") if input_text is not None else None,
                timeout_seconds=timeout_seconds,
                output_limit=PROCESS_OUTPUT_LIMIT,
            )
        )
    finally:
        if trusted_path is not None:
            trusted_path.cleanup()
    return subprocess.CompletedProcess(
        args=normalized,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def run_command(
    command: List[str],
    *,
    check: bool = True,
    announce: bool = True,
    timeout_seconds: float = PROCESS_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    if announce:
        print("$ " + _safe_command_display(command))
    result = _bounded_process(
        command, input_text=None, timeout_seconds=timeout_seconds
    )
    if announce:
        _emit_process_output(result.stdout, stream=sys.stdout)
        _emit_process_output(result.stderr, stream=sys.stderr)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            result.args,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


def command_output(
    command: List[str],
    *,
    announce: bool = True,
    input_text: Optional[str] = None,
    timeout_seconds: float = PROCESS_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    if announce:
        print("$ " + _safe_command_display(command))
    result = _bounded_process(
        command, input_text=input_text, timeout_seconds=timeout_seconds
    )
    if announce:
        _emit_process_output(result.stdout, stream=sys.stdout)
        _emit_process_output(result.stderr, stream=sys.stderr)
    return result


def cluster_presence(name: str, *, announce: bool = True) -> Optional[bool]:
    result = command_output(kind_command() + ["get", "clusters"], announce=announce)
    return None if result.returncode != 0 else name in result.stdout.splitlines()


def cluster_exists(name: str, *, announce: bool = True) -> bool:
    return cluster_presence(name, announce=announce) is True


def node_statuses(name: str, *, announce: bool = True) -> List[Dict[str, Any]]:
    kube = kubeconfig_path(name)
    binary = kubectl_command()
    if _read_state_bytes(_kubeconfig_filename(name), limit=4 * 1024 * 1024) is None or not binary:
        return []
    result = command_output(
        [binary, "--kubeconfig", str(kube), "--context", f"kind-{name}", "get", "nodes", "-o", "json"],
        announce=announce,
    )
    if result.returncode != 0:
        return []
    try:
        items = json.loads(result.stdout)["items"]
        return [
            {
                "name": item["metadata"]["name"],
                "ready": any(
                    condition.get("type") == "Ready" and condition.get("status") == "True"
                    for condition in item.get("status", {}).get("conditions", [])
                ),
            }
            for item in items
        ]
    except (KeyError, TypeError, ValueError):
        return []


def cluster_healthy(name: str, *, announce: bool = True) -> bool:
    return nodes_healthy(node_statuses(name, announce=announce))


def nodes_healthy(nodes: List[Dict[str, Any]]) -> bool:
    return len(nodes) == EXPECTED_NODE_COUNT and all(node["ready"] for node in nodes)


def scenario_by_id(identifier: str) -> Dict[str, Any]:
    normalized = identifier.zfill(2)
    for item in load_catalog():
        if item["id"] == normalized:
            return item
    raise ValueError(f"unknown scenario {identifier!r}; use 'list' to see the catalog")


def print_catalog(as_json: bool = False) -> int:
    catalog = load_catalog()
    if as_json:
        # The additive full-tier contract is internal. Keep the established
        # quick-tier JSON projection byte-for-structure compatible.
        print(
            json.dumps(
                [{key: value for key, value in item.items() if key != "full"} for item in catalog],
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    for item in catalog:
        print(f"{item['id']}  {item['title']}  [{item['kind_support']}]  {item['compatibility']}")
    return 0


def doctor(as_json: bool = False) -> int:
    kind_fallback = ROOT / "tools" / "kind"
    fallback_selected = os.environ.get("CKS_KIND_USE_GLOBAL", "1") == "0" or global_kind() is None
    docker = docker_command()
    docker_detail = "not found"
    docker_ok = False
    if docker:
        docker_result = command_output([docker, "info", "--format", "{{.ServerVersion}}"], announce=not as_json)
        docker_ok = docker_result.returncode == 0
        docker_detail = docker_result.stdout.strip() if docker_ok else (docker_result.stderr.strip() or "daemon unavailable")
    checks = [
        {"name": "python3", "ok": sys.version_info >= (3, 9), "detail": sys.version.split()[0]},
        {"name": "docker daemon", "ok": docker_ok, "detail": docker_detail},
        {"name": "kubectl", "ok": kubectl_command() is not None, "detail": kubectl_command() or "not found"},
        {"name": "curl", "ok": (not fallback_selected) or curl_command() is not None, "detail": curl_command() or "not found"},
        {"name": "awk", "ok": (not fallback_selected) or awk_command() is not None, "detail": awk_command() or "not found"},
        {"name": "checksum tool", "ok": (not fallback_selected) or checksum_command() is not None, "detail": checksum_command() or "not found"},
        {"name": "openssl", "ok": openssl_command() is not None, "detail": openssl_command() or "not found"},
        {"name": "kind (global)", "ok": global_kind() is not None, "detail": global_kind() or "not found"},
        {"name": "kind (pinned fallback)", "ok": (not fallback_selected) or (kind_fallback.is_file() and os.access(kind_fallback, os.X_OK)), "detail": str(kind_fallback)},
    ]
    result = {"project": str(ROOT), "state_dir": str(state_dir()), "cluster_name": os.environ.get("CKS_CLUSTER_NAME", DEFAULT_CLUSTER), "checks": checks}
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"project: {ROOT}")
        print(f"state:   {state_dir()}")
        for check in checks:
            print(f"{'OK' if check['ok'] else 'MISSING':7} {check['name']}: {check['detail']}")
        print("note: Docker Desktop is required for a live kind cluster; unsupported scenarios remain artifact-checkable.")
    return 0 if all(check["ok"] for check in checks if check["name"] != "kind (global)") else 1


def _lifecycle_quiet(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "quiet", False) or getattr(args, "as_json", False))


def _emit_quick_lifecycle(result: QuickLifecycleResult, args: argparse.Namespace) -> int:
    if getattr(args, "quiet", False):
        return result.returncode
    if getattr(args, "as_json", False):
        print(json.dumps(result.payload(), indent=2, sort_keys=True))
    elif result.returncode == 0:
        print(result.message)
        if result.details.get("kubeconfig"):
            print(f"kubeconfig: {result.details['kubeconfig']}")
    else:
        print(result.message, file=sys.stderr)
    return result.returncode


def _provision_quick(args: argparse.Namespace) -> QuickLifecycleResult:
    name = cluster_name(args)
    quiet = _lifecycle_quiet(args)
    config = ROOT / "kind" / "cluster.yaml"
    kube_filename = _kubeconfig_filename(name)
    metadata_filename = _metadata_filename(name)
    kube = kubeconfig_path(name)
    try:
        _assert_state_destination_safe(metadata_filename)
        _assert_state_destination_safe(kube_filename)
        if cluster_exists(name, announce=not quiet):
            if not state_is_owned(name):
                return QuickLifecycleResult(
                    "provision",
                    name,
                    1,
                    f"refusing to manage unowned cluster {name!r}; choose another --name or delete it explicitly",
                )
            if cluster_healthy(name, announce=not quiet):
                return QuickLifecycleResult(
                    "provision",
                    name,
                    0,
                    f"cluster already ready: {name}",
                    {"kubeconfig": str(kube), "reused": True},
                )
            return QuickLifecycleResult(
                "provision",
                name,
                1,
                f"cluster {name!r} exists but is not healthy with project state; use 'reset' to recreate it",
            )

        pending_kube = f".kubeconfig-{name}-{uuid.uuid4().hex}"
        claim_id = str(uuid.uuid4())
        _write_state_json(
            metadata_filename,
            {
                "schema_version": 1,
                "managed_by": "cks-simulator",
                "cluster_name": name,
                "claim_id": claim_id,
                "container_id": None,
                "image": args.image,
                "status": "creating",
            },
        )
        command = kind_command() + [
            "create",
            "cluster",
            "--name",
            name,
            "--config",
            str(config),
            "--image",
            args.image,
            "--kubeconfig",
            str(state_dir() / pending_kube),
            "--wait",
            args.wait,
        ]
        try:
            run_command(command, announce=not quiet)
        except FileNotFoundError as exc:
            _remove_state_file(metadata_filename)
            return QuickLifecycleResult("provision", name, 1, f"unable to run kind: {exc}")
        except subprocess.CalledProcessError as exc:
            try:
                _remove_state_file(pending_kube)
                _remove_state_file(metadata_filename)
            except RuntimeError:
                pass
            return QuickLifecycleResult(
                "provision",
                name,
                exc.returncode or 1,
                f"kind failed while provisioning {name!r} (exit {exc.returncode}); partial state removed",
            )

        observed = _inspect_kind_control_plane(name)
        if not observed:
            return QuickLifecycleResult(
                "provision",
                name,
                1,
                "Kind created the cluster but its exact control-plane identity could not be verified; use 'delete --force' to remove it",
            )
        identity: Dict[str, Any] = {
            "schema_version": 1,
            "managed_by": "cks-simulator",
            "cluster_name": name,
            "claim_id": claim_id,
            "container_id": observed["container_id"],
        }
        if not _write_quick_marker(identity):
            return QuickLifecycleResult(
                "provision",
                name,
                1,
                "Kind created the cluster but its immutable ownership marker did not verify; use 'delete --force' to remove it",
            )
        _adopt_kubeconfig(pending_kube, kube_filename)
        metadata = {
            **identity,
            "image": args.image,
            "status": "nodes-not-ready",
        }
        _write_state_json(metadata_filename, metadata)
        try:
            ready_result = command_output(
                cluster_kubectl(
                    name,
                    [
                        "wait",
                        "--for=condition=Ready",
                        "nodes",
                        "--all",
                        f"--timeout={args.wait}",
                    ],
                ),
                announce=not quiet,
            )
        except RuntimeError as exc:
            ready_result = subprocess.CompletedProcess(command, 1, "", str(exc))
        if ready_result.returncode != 0:
            return QuickLifecycleResult(
                "provision",
                name,
                1,
                f"cluster {name!r} was created but all nodes did not become Ready; use 'reset' to retry",
                {"kubeconfig": str(kube)},
            )
        metadata["status"] = "ready"
        _write_state_json(metadata_filename, metadata)
        return QuickLifecycleResult(
            "provision",
            name,
            0,
            f"cluster ready: {name}",
            {"kubeconfig": str(kube), "reused": False},
        )
    except (OSError, RuntimeError) as exc:
        return QuickLifecycleResult(
            "provision", name, 1, f"unable to manage trusted quick-tier state: {exc}"
        )


def provision(args: argparse.Namespace) -> int:
    return _emit_quick_lifecycle(_provision_quick(args), args)


def _delete_quick(args: argparse.Namespace) -> QuickLifecycleResult:
    name = cluster_name(args)
    quiet = _lifecycle_quiet(args)
    try:
        exists = cluster_exists(name, announce=not quiet)
        if exists and not getattr(args, "force", False) and not state_is_owned(name):
            return QuickLifecycleResult(
                "delete",
                name,
                1,
                f"refusing to delete unowned cluster {name!r}; pass --force only if you explicitly intend to remove it",
            )
        command = kind_command() + ["delete", "cluster", "--name", name]
        try:
            result = run_command(command, check=False, announce=not quiet)
        except FileNotFoundError as exc:
            return QuickLifecycleResult("delete", name, 1, f"unable to run kind: {exc}")
        if result.returncode != 0:
            return QuickLifecycleResult(
                "delete",
                name,
                result.returncode,
                f"kind failed while deleting {name!r} (exit {result.returncode})",
            )
        for filename in (
            _kubeconfig_filename(name),
            _metadata_filename(name),
            _claim_filename(name),
        ):
            _remove_state_file(filename)
        return QuickLifecycleResult(
            "delete",
            name,
            0,
            f"cluster deleted: {name}" if exists else f"cluster already absent: {name}",
            {"existed": exists},
        )
    except (OSError, RuntimeError) as exc:
        return QuickLifecycleResult(
            "delete", name, 1, f"unable to manage trusted quick-tier state: {exc}"
        )


def delete(args: argparse.Namespace) -> int:
    return _emit_quick_lifecycle(_delete_quick(args), args)


def reset_cluster(args: argparse.Namespace) -> int:
    name = cluster_name(args)
    deleted = _delete_quick(args)
    if deleted.returncode != 0:
        result = QuickLifecycleResult(
            "reset",
            name,
            deleted.returncode,
            f"reset stopped because deletion failed: {deleted.message}",
            {"delete": deleted.payload()},
        )
        return _emit_quick_lifecycle(result, args)
    provisioned = _provision_quick(args)
    result = QuickLifecycleResult(
        "reset",
        name,
        provisioned.returncode,
        (
            f"cluster reset complete: {name}"
            if provisioned.returncode == 0
            else f"reset deletion succeeded but provisioning failed: {provisioned.message}"
        ),
        {"delete": deleted.payload(), "provision": provisioned.payload()},
    )
    return _emit_quick_lifecycle(result, args)


def cluster_kubectl(name: str, args: Iterable[str]) -> List[str]:
    binary = kubectl_command()
    if not binary:
        raise RuntimeError("kubectl is required; run 'doctor'")
    return [binary, "--kubeconfig", str(kubeconfig_path(name)), "--context", f"kind-{name}", *args]


def open_shell(args: argparse.Namespace) -> int:
    """Attach an interactive TTY; output is intentionally owned by the user shell."""

    name = cluster_name(args)
    node = args.node or f"{name}-control-plane"
    docker = docker_command()
    if not docker:
        print("docker is required; run 'doctor'", file=sys.stderr)
        return 1
    shell = args.shell or "/bin/bash"
    command = [docker, "exec", "-it", node, shell]
    print("$ " + _safe_command_display(command))
    environment = SubprocessRunner._environment(ProcessRequest.build([docker]))
    return subprocess.run(command, check=False, env=environment).returncode


def scenario_root(item: Dict[str, Any]) -> Path:
    return state_dir() / "scenarios" / item["id"]


def create_scenario(identifier: str, apply: bool = False, cluster: Optional[str] = None, reset: bool = False) -> int:
    item = scenario_by_id(identifier)
    destination = scenario_root(item)
    fixture_source = ROOT / "scenarios" / "fixtures" / item["id"]
    tls_temporary: Optional[tempfile.TemporaryDirectory[str]] = None
    try:
        if item["id"] == "15":
            tls_temporary = tempfile.TemporaryDirectory(prefix="cks-simulator-scenario-15-")
            generate_tls_fixture(Path(tls_temporary.name))
        if destination.exists():
            if not reset:
                print(f"scenario {item['id']} already exists; use 'scenario reset {item['id']}' to replace it", file=sys.stderr)
                return 1
            shutil.rmtree(destination)
        (destination / "artifacts").mkdir(parents=True)
        fixture_destination = destination / "fixture"
        if fixture_source.exists():
            shutil.copytree(fixture_source, fixture_destination)
        else:
            fixture_destination.mkdir()
        if tls_temporary:
            shutil.copy2(Path(tls_temporary.name) / "tls.crt", fixture_destination / "tls.crt")
            shutil.copy2(Path(tls_temporary.name) / "tls.key", fixture_destination / "tls.key")
            os.chmod(fixture_destination / "tls.key", 0o600)
    finally:
        if tls_temporary:
            tls_temporary.cleanup()
    (destination / "TASK.md").write_text(
        f"# Scenario {item['id']}: {item['title']}\n\n"
        f"Compatibility: **{item['kind_support']}** — {item['compatibility']}\n\n"
        f"{item['prompt']}\n\n"
        "Put your answer artifacts under `artifacts/`, then run `cks-simulator check "
        f"{item['id']}`.\n",
        encoding="utf-8",
    )
    print(f"created scenario {item['id']} at {destination}")
    if item["kind_support"] == "unsupported":
        print("compatibility: unsupported on stock kind; use the fixture as a command/configuration exercise")
    if apply:
        if item["kind_support"] == "unsupported":
            print("not applying unsupported fixture")
            return 0
        resources = fixture_destination / "resources.json"
        if not resources.exists():
            print("no resources.json fixture; nothing to apply")
            return 0
        target_cluster = cluster or os.environ.get("CKS_CLUSTER_NAME", DEFAULT_CLUSTER)
        if not state_is_owned(target_cluster) or not cluster_healthy(target_cluster):
            print(f"cluster {target_cluster!r} is not a healthy CKS-simulator cluster; run provision first", file=sys.stderr)
            return 1
        try:
            return run_command(cluster_kubectl(target_cluster, ["apply", "-f", str(resources)]), check=False).returncode
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    return 0


def check_scenario(identifier: str, root: Optional[str] = None) -> int:
    item = scenario_by_id(identifier)
    artifact_root = artifact_root_for_grade(item, root, all_scenarios=False)
    grade = grade_scenario(item, artifact_root)
    print(f"scenario {item['id']} [{item['kind_support']}] artifacts: {artifact_root}")
    for rule in grade["rules"]:
        print(f"{'PASS' if rule['passed'] else 'FAIL'}  {rule['path']} ({rule['earned']}/{rule['possible']} criteria)")
    print(f"artifact score: {grade['score']:.1f}/100 ({grade['status']})")
    print("scope: artifact evidence only; use 'e2e' for live kind validation")
    return 0 if grade["status"] == "complete" else 1


def artifact_root_for_grade(item: Dict[str, Any], root: Optional[str], *, all_scenarios: bool) -> Path:
    if not root:
        return scenario_root(item) / "artifacts"
    base = Path(root).expanduser().resolve()
    if not all_scenarios:
        return base
    candidate = base / item["id"] / "artifacts"
    return candidate if candidate.is_dir() else base / item["id"]


def grade_artifacts(identifier: str, root: Optional[str] = None, as_json: bool = False) -> int:
    all_scenarios = identifier.lower() == "all"
    items = load_catalog() if all_scenarios else [scenario_by_id(identifier)]
    grades = [
        grade_scenario(item, artifact_root_for_grade(item, root, all_scenarios=all_scenarios))
        for item in items
    ]
    payload: Dict[str, Any] = summarize_grades(grades) if all_scenarios else grades[0]
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif all_scenarios:
        for grade in grades:
            print(f"{grade['id']}  {grade['score']:5.1f}/100  {grade['status']:10}  [{grade['kind_support']}] {grade['title']}")
        print(f"overall artifact score: {payload['score']:.1f}/100; {payload['complete']}/{payload['scenario_count']} complete")
        print("scope: artifact evidence only; not an official CKS exam score")
    else:
        grade = grades[0]
        print(f"scenario {grade['id']} [{grade['kind_support']}] artifact score: {grade['score']:.1f}/100")
        for rule in grade["rules"]:
            for criterion in rule["criteria"]:
                print(f"{'PASS' if criterion['passed'] else 'FAIL'}  {criterion['label']}")
        print(f"status: {grade['status']}")
        print(f"scope: {grade['validation_scope']}")
    return 0 if payload["status"] == "complete" else 1


def _e2e_check(checks: List[Dict[str, Any]], name: str, passed: bool, detail: str) -> None:
    checks.append({"name": name, "passed": passed, "detail": detail})


def _validate_fixture(
    name: str, item: Dict[str, Any], *, announce: bool, tls_dir: Optional[Path] = None
) -> tuple[bool, str]:
    resources = ROOT / "scenarios" / "fixtures" / item["id"] / "resources.json"
    expected = json.loads(resources.read_text(encoding="utf-8"))
    expected_items = expected.get("items", [expected]) if isinstance(expected, dict) else []
    if item["id"] == "07":
        namespace_result = run_command(
            cluster_kubectl(name, ["create", "namespace", "team-sepia"]),
            check=False,
            announce=announce,
        )
        if namespace_result.returncode != 0:
            return False, namespace_result.stderr.strip() if namespace_result.stderr else "namespace creation failed"
        dry_run = command_output(
            cluster_kubectl(name, ["apply", "--dry-run=server", "-f", str(resources)]),
            announce=announce,
        )
        if dry_run.returncode != 0:
            return False, dry_run.stderr.strip() or "server-side dry-run failed"
        return True, f"server-side validated {len(expected_items)} objects without scheduling the privileged Pod"
    apply_result = run_command(
        cluster_kubectl(name, ["apply", "-f", str(resources)]),
        check=False,
        announce=announce,
    )
    if apply_result.returncode != 0:
        detail = apply_result.stderr.strip() if apply_result.stderr else f"kubectl apply exited {apply_result.returncode}"
        return False, detail

    get_result = command_output(
        cluster_kubectl(name, ["get", "-f", str(resources), "-o", "json"]),
        announce=announce,
    )
    if get_result.returncode != 0:
        return False, get_result.stderr.strip() or f"kubectl get exited {get_result.returncode}"
    try:
        actual = json.loads(get_result.stdout)
        actual_items = actual.get("items", [actual]) if isinstance(actual, dict) else []
    except ValueError as exc:
        return False, f"kubectl returned invalid JSON: {exc}"
    if len(actual_items) != len(expected_items):
        return False, f"expected {len(expected_items)} objects, found {len(actual_items)}"

    for resource in expected_items:
        kind = resource.get("kind")
        metadata = resource.get("metadata", {})
        resource_name = metadata.get("name")
        namespace = metadata.get("namespace")
        if kind not in {"Deployment", "Pod"} or not resource_name:
            continue
        condition = "Available" if kind == "Deployment" else "Ready"
        target = f"{kind.lower()}/{resource_name}"
        wait_args = ["wait", f"--for=condition={condition}", "--timeout=120s"]
        if namespace:
            wait_args += ["-n", namespace]
        wait_args.append(target)
        wait_result = command_output(cluster_kubectl(name, wait_args), announce=announce)
        if wait_result.returncode != 0:
            return False, wait_result.stderr.strip() or f"{target} did not reach {condition}"
    if item["id"] == "15":
        if not tls_dir:
            return False, "generated TLS fixture is missing"
        secret_result = command_output(
            cluster_kubectl(
                name,
                [
                    "create", "secret", "tls", "secure-tls", "-n", "team-pink",
                    f"--cert={tls_dir / 'tls.crt'}", f"--key={tls_dir / 'tls.key'}",
                ],
            ),
            announce=announce,
        )
        if secret_result.returncode != 0:
            return False, secret_result.stderr.strip() or "TLS Secret creation failed"
        patch_value = json.dumps({"spec": {"tls": [{"hosts": ["secure-ingress.test"], "secretName": "secure-tls"}]}})
        patch_result = command_output(
            cluster_kubectl(name, ["patch", "ingress", "secure", "-n", "team-pink", "--type=merge", "-p", patch_value]),
            announce=announce,
        )
        if patch_result.returncode != 0:
            return False, patch_result.stderr.strip() or "Ingress TLS patch failed"
        verify_result = command_output(
            cluster_kubectl(name, ["get", "ingress", "secure", "-n", "team-pink", "-o", "json"]),
            announce=announce,
        )
        try:
            secret_name = json.loads(verify_result.stdout)["spec"]["tls"][0]["secretName"]
        except (ValueError, KeyError, IndexError, TypeError):
            return False, "Ingress does not reference the generated TLS Secret"
        if verify_result.returncode != 0 or secret_name != "secure-tls":
            return False, "Ingress does not reference the generated TLS Secret"
        return True, f"applied {len(actual_items)} baseline objects and verified generated TLS Secret termination"
    return True, f"applied and observed {len(actual_items)} objects"


def _export_e2e_logs(name: str, *, announce: bool) -> Optional[Path]:
    destination = state_dir() / "e2e-logs" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = command_output(kind_command() + ["export", "logs", "--name", name, str(destination)], announce=announce)
    return destination if result.returncode == 0 and destination.is_dir() else None


def e2e(args: argparse.Namespace) -> int:
    """Run an isolated release gate against a disposable kind cluster."""
    name = validate_cluster_name(args.name or f"cks-simulator-e2e-{os.getpid()}")
    announce = not args.as_json
    checks: List[Dict[str, Any]] = []
    started = time.monotonic()
    provisioned = False
    creation_attempted = False
    preexisting_run_state = False
    claim_token: Optional[str] = None
    logs_path: Optional[Path] = None
    tls_temporary: Optional[tempfile.TemporaryDirectory[str]] = None
    tls_fixture_dir: Optional[Path] = None
    catalog = load_catalog()
    catalog_by_id = {item["id"]: item for item in catalog}
    missing_live_fixtures = [
        identifier
        for identifier in sorted(LIVE_FIXTURE_IDS)
        if identifier not in catalog_by_id
        or not (ROOT / "scenarios" / "fixtures" / identifier / "resources.json").is_file()
    ]
    live_fixtures = [catalog_by_id[identifier] for identifier in sorted(LIVE_FIXTURE_IDS) if identifier in catalog_by_id]

    docker = docker_command()
    docker_result = command_output([docker, "info"], announce=announce) if docker else None
    _e2e_check(checks, "docker daemon", bool(docker_result and docker_result.returncode == 0), "available" if docker_result and docker_result.returncode == 0 else "unavailable")
    kubectl = kubectl_command()
    kubectl_result = command_output([kubectl, "version", "--client", "-o", "json"], announce=announce) if kubectl else None
    _e2e_check(checks, "kubectl client", bool(kubectl_result and kubectl_result.returncode == 0), "available" if kubectl_result and kubectl_result.returncode == 0 else "unavailable")
    kind_result = command_output(kind_command() + ["version"], announce=announce)
    _e2e_check(checks, "kind client", kind_result.returncode == 0, kind_result.stdout.strip() or kind_result.stderr.strip())
    _e2e_check(checks, "openssl client", openssl_command() is not None, openssl_command() or "unavailable")
    _e2e_check(
        checks,
        "live fixture declaration",
        not missing_live_fixtures,
        "04, 06, 07, 11, 15 present" if not missing_live_fixtures else f"missing: {', '.join(missing_live_fixtures)}",
    )
    try:
        tls_temporary = tempfile.TemporaryDirectory(prefix="cks-simulator-e2e-tls-")
        tls_fixture_dir = Path(tls_temporary.name)
        generate_tls_fixture(tls_fixture_dir)
        tls_ok = (tls_fixture_dir / "tls.crt").is_file() and (tls_fixture_dir / "tls.key").stat().st_mode & 0o777 == 0o600
        _e2e_check(checks, "scenario 15 TLS generation", tls_ok, "certificate and mode-0600 key generated" if tls_ok else "generated files invalid")
    except (OSError, RuntimeError) as exc:
        _e2e_check(checks, "scenario 15 TLS generation", False, str(exc))

    prerequisites_ok = all(check["passed"] for check in checks)
    try:
        if prerequisites_ok:
            presence = cluster_presence(name, announce=announce)
            preexisting_run_state = presence is True or _state_entry_exists(
                _metadata_filename(name)
            )
            if presence is None:
                _e2e_check(checks, "cluster provision", False, "unable to query existing kind clusters")
            elif preexisting_run_state:
                _e2e_check(checks, "cluster provision", False, f"refusing pre-existing cluster or state for {name}")
            else:
                claim_token = acquire_e2e_claim(name)
                if not claim_token:
                    _e2e_check(checks, "cluster provision", False, f"another E2E run claimed {name}")
                else:
                    creation_attempted = True
                    provision_args = argparse.Namespace(name=name, image=args.image, wait=args.wait, quiet=args.as_json)
                    provision_code = provision(provision_args)
                    provisioned = provision_code == 0
                    _e2e_check(checks, "cluster provision", provisioned, f"cluster {name}" if provisioned else f"exit {provision_code}")

            idempotent_code = provision(provision_args) if provisioned else 1
            _e2e_check(checks, "idempotent provision", idempotent_code == 0, "second provision reused the healthy owned cluster" if idempotent_code == 0 else "second provision failed")

            nodes = node_statuses(name, announce=announce) if provisioned else []
            nodes_ok = nodes_healthy(nodes)
            _e2e_check(checks, "three Ready nodes", nodes_ok, ", ".join(f"{node['name']}={'Ready' if node['ready'] else 'NotReady'}" for node in nodes) or "no nodes")

            for item in live_fixtures:
                if provisioned and nodes_ok:
                    ok, detail = _validate_fixture(name, item, announce=announce, tls_dir=tls_fixture_dir)
                else:
                    ok, detail = False, "skipped because the cluster was not Ready"
                _e2e_check(checks, f"scenario {item['id']} fixture", ok, detail)
        else:
            _e2e_check(checks, "cluster provision", False, "skipped because prerequisites failed")
            _e2e_check(checks, "idempotent provision", False, "skipped because prerequisites failed")
            _e2e_check(checks, "three Ready nodes", False, "skipped because prerequisites failed")
            for item in live_fixtures:
                _e2e_check(checks, f"scenario {item['id']} fixture", False, "skipped because prerequisites failed")
    finally:
        failed_before_cleanup = any(not check["passed"] for check in checks)
        owns_claim = e2e_claim_is_owned(name, claim_token)
        if creation_attempted and owns_claim and failed_before_cleanup and cluster_presence(name, announce=False) is True and state_is_owned(name):
            logs_path = _export_e2e_logs(name, announce=announce)
        if preexisting_run_state:
            _e2e_check(checks, "cluster cleanup", True, "pre-existing cluster or state left untouched")
        elif args.keep and provisioned:
            _e2e_check(checks, "cluster cleanup", True, f"retained by request: {name}")
        elif creation_attempted and owns_claim:
            owned_state = state_is_owned(name)
            presence_before_delete = cluster_presence(name, announce=False)
            if presence_before_delete is True:
                force_cleanup = not owned_state and not preexisting_run_state
                delete_code = delete(
                    argparse.Namespace(
                        name=name,
                        force=force_cleanup,
                        quiet=args.as_json,
                    )
                )
            elif presence_before_delete is False:
                delete_code = 0
            else:
                delete_code = 1
            presence_after_delete = cluster_presence(name, announce=False)
            cleaned = delete_code == 0 and presence_after_delete is False
            _e2e_check(checks, "cluster cleanup", cleaned, "deleted" if cleaned else f"delete exited {delete_code}")
            if not cleaned and logs_path is None and presence_after_delete is True and state_is_owned(name):
                logs_path = _export_e2e_logs(name, announce=announce)
        else:
            _e2e_check(checks, "cluster cleanup", True, "nothing created")
        if e2e_claim_is_owned(name, claim_token):
            _remove_state_file(_claim_filename(name))
        if tls_temporary:
            tls_temporary.cleanup()

    passed = sum(1 for check in checks if check["passed"])
    score = round((passed / len(checks)) * 100, 1) if checks else 0.0
    support_counts = {
        support: sum(1 for item in catalog if item["kind_support"] == support)
        for support in ("native", "partial", "unsupported")
    }
    payload = {
        "name": name,
        "image": args.image,
        "score": score,
        "status": "pass" if passed == len(checks) else "fail",
        "passed": passed,
        "possible": len(checks),
        "duration_seconds": round(time.monotonic() - started, 1),
        "checks": checks,
        "coverage": {
            "catalog_scenarios": len(catalog),
            "support": support_counts,
            "live_fixture_scenarios": [item["id"] for item in live_fixtures],
            "artifact_grading_scenarios": len(catalog),
        },
        "diagnostic_logs": str(logs_path) if logs_path else None,
    }
    if args.as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for check in checks:
            print(f"{'PASS' if check['passed'] else 'FAIL'}  {check['name']}: {check['detail']}")
        print(f"e2e score: {score:.1f}/100 ({payload['status']}); {passed}/{len(checks)} gates passed")
        print(f"live fixtures: {', '.join(payload['coverage']['live_fixture_scenarios'])}")
        if logs_path:
            print(f"diagnostic logs: {logs_path}")
    return 0 if payload["status"] == "pass" else 1


def dispatch_full_tier(args: argparse.Namespace) -> int:
    """Lazy full-tier dispatch keeps Kind dependencies outside the VM path."""

    from .full_cli import dispatch_full_command

    try:
        return dispatch_full_command(args, state_root=state_dir())
    except RuntimeError as error:
        if "reserved for a later implementation unit" not in str(error):
            raise
        raise TierDispatchError(
            "full_command_not_available",
            str(error),
            command=args.command,
            tier="full",
        ) from error


def dispatch_tier(args: argparse.Namespace, quick_handler: Callable[[], int]) -> int:
    tier = getattr(args, "tier", "quick")
    if tier not in SUPPORTED_TIERS:
        raise TierDispatchError(
            "invalid_tier",
            f"invalid tier {tier!r}; expected 'quick' or 'full'",
            command=args.command,
            tier=tier,
        )
    if args.command == "grade":
        if tier == "quick" and getattr(args, "name", None) is not None:
            raise TierDispatchError(
                "unsupported_tier_option",
                "--name is supported only by full-tier grade",
                command=args.command,
                tier=tier,
            )
        if tier == "full" and getattr(args, "root", None) is not None:
            raise TierDispatchError(
                "unsupported_tier_option",
                "--root is supported only by quick-tier grade",
                command=args.command,
                tier=tier,
            )
    if args.command in {"provision", "delete", "reset"}:
        cluster_name(args)
    elif args.command == "e2e":
        validate_cluster_name(args.name or f"cks-simulator-e2e-{os.getpid()}")
    if tier == "quick":
        if getattr(args, "memory_profile", None) is not None:
            raise TierDispatchError(
                "unsupported_tier_option",
                "--memory-profile is supported only by the full tier",
                command=args.command,
                tier=tier,
            )
        if args.command == "e2e" and bool(
            getattr(args, "destroy_rebuild", False)
        ):
            raise TierDispatchError(
                "unsupported_tier_option",
                "--destroy-rebuild is supported only by the full tier",
                command=args.command,
                tier=tier,
            )
        if args.command in {"provision", "reset", "e2e"}:
            if not hasattr(args, "image"):
                args.image = DEFAULT_IMAGE
            if not hasattr(args, "wait"):
                args.wait = "5m"
        if args.command == "doctor" and (
            bool(getattr(args, "lab", False)) or getattr(args, "name", None) is not None
        ):
            raise TierDispatchError(
                "unsupported_tier_option",
                "--lab and --name are supported only by full-tier doctor",
                command=args.command,
                tier=tier,
            )
        if args.command == "delete" and (
            bool(getattr(args, "break_glass", False))
            or getattr(args, "expected_lab_id", None) is not None
        ):
            raise TierDispatchError(
                "unsupported_tier_option",
                "--break-glass and --expected-lab-id are supported only by the full tier",
                command=args.command,
                tier=tier,
            )
        return quick_handler()
    return dispatch_full_tier(args)


def add_tier_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tier",
        default="quick",
        metavar="{quick,full}",
        help="execution tier (default: quick)",
    )


def add_memory_profile_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--memory-profile",
        choices=("standard", "low"),
        default=None,
        help=(
            "full tier guest-resource profile "
            "(default: standard; low uses 8 vCPUs and 5 GiB RAM total)"
        ),
    )


def parse_exam_duration(value: str) -> int:
    """Parse bounded candidate-friendly durations such as 120m or 2h."""

    match = re.fullmatch(r"([1-9][0-9]*)([smh]?)", value or "")
    if match is None:
        raise argparse.ArgumentTypeError("duration must be seconds or use s, m, or h")
    amount = int(match.group(1))
    multiplier = {"": 1, "s": 1, "m": 60, "h": 3600}[match.group(2)]
    seconds = amount * multiplier
    if not 60 <= seconds <= 6 * 60 * 60:
        raise argparse.ArgumentTypeError("duration must be between 60 seconds and 6 hours")
    return seconds


def reject_quick_scenario_lifecycle(args: argparse.Namespace) -> int:
    raise TierDispatchError(
        "quick_command_not_available",
        f"quick tier does not support scenario {args.scenario_command!r}",
        command=f"scenario {args.scenario_command}",
        tier="quick",
    )


def reject_quick_setup(args: argparse.Namespace) -> int:
    raise TierDispatchError(
        "quick_command_not_available",
        "prerequisite setup is currently supported only by the full tier",
        command="setup",
        tier="quick",
    )


def reject_quick_exam(args: argparse.Namespace) -> int:
    raise TierDispatchError(
        "quick_command_not_available",
        "the candidate ExamUI requires the full VM tier",
        command=f"exam {args.exam_command}",
        tier="quick",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cks-simulator", description="Local CKS practice environment")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor_parser = sub.add_parser("doctor")
    add_tier_argument(doctor_parser)
    doctor_parser.add_argument("--lab", action="store_true", help="full tier: reconcile and behaviorally validate an existing lab")
    doctor_parser.add_argument("--name", default=None, help="full tier lab name used with --lab")
    doctor_parser.add_argument("--json", action="store_true", dest="as_json")
    add_memory_profile_argument(doctor_parser)

    setup_parser = sub.add_parser(
        "setup", help="install and verify host prerequisites"
    )
    add_tier_argument(setup_parser)
    setup_parser.add_argument("--json", action="store_true", dest="as_json")
    add_memory_profile_argument(setup_parser)

    for name in ("provision", "reset"):
        command = sub.add_parser(name)
        command.add_argument("--name", default=None)
        command.add_argument("--image", default=argparse.SUPPRESS)
        command.add_argument("--wait", default=argparse.SUPPRESS)
        add_tier_argument(command)
        command.add_argument("--json", action="store_true", dest="as_json")
        if name == "provision":
            add_memory_profile_argument(command)
        if name == "reset":
            command.add_argument("--force", action="store_true", help="allow deleting an unowned same-named kind cluster")

    delete_parser = sub.add_parser("delete")
    delete_parser.add_argument("--name", default=None)
    add_tier_argument(delete_parser)
    delete_parser.add_argument("--json", action="store_true", dest="as_json")
    delete_parser.add_argument("--force", action="store_true", help="allow deleting an unowned same-named kind cluster")
    delete_parser.add_argument(
        "--break-glass",
        action="store_true",
        help="full tier only: permit exact-handle cleanup after ordinary guest proof fails",
    )
    delete_parser.add_argument(
        "--expected-lab-id",
        default=None,
        help="full tier only: exact immutable lab UUID required with --break-glass",
    )

    list_parser = sub.add_parser("list")
    list_parser.add_argument("--json", action="store_true", dest="as_json")

    shell_parser = sub.add_parser("shell")
    shell_parser.add_argument("--name", default=None)
    shell_parser.add_argument("--node", default=None)
    shell_parser.add_argument("--shell", default=None)
    add_tier_argument(shell_parser)
    add_memory_profile_argument(shell_parser)

    check_parser = sub.add_parser("check")
    check_parser.add_argument("id")
    check_parser.add_argument("--root", default=None)

    grade_parser = sub.add_parser("grade", help="score one scenario or the complete artifact set")
    grade_parser.add_argument("id", help="scenario ID or 'all'")
    grade_parser.add_argument("--root", default=None)
    grade_parser.add_argument("--name", default=None, help="full tier lab name")
    add_tier_argument(grade_parser)
    grade_parser.add_argument("--json", action="store_true", dest="as_json")

    e2e_parser = sub.add_parser("e2e", help="run the disposable live kind release gate")
    e2e_parser.add_argument("--name", default=None, help="unique disposable kind cluster name")
    e2e_parser.add_argument("--image", default=argparse.SUPPRESS)
    e2e_parser.add_argument("--wait", default=argparse.SUPPRESS)
    e2e_parser.add_argument("--keep", action="store_true", help="retain a successfully provisioned E2E cluster")
    e2e_parser.add_argument(
        "--destroy-rebuild",
        action="store_true",
        help="full tier: destroy build A, provision and validate build B, then destroy it",
    )
    add_tier_argument(e2e_parser)
    add_memory_profile_argument(e2e_parser)
    e2e_parser.add_argument("--json", action="store_true", dest="as_json")

    scenario_parser = sub.add_parser("scenario")
    scenario_sub = scenario_parser.add_subparsers(dest="scenario_command", required=True)
    for name in ("create", "reset"):
        command = scenario_sub.add_parser(name)
        command.add_argument("id")
        command.add_argument("--apply", action="store_true")
        command.add_argument("--name", default=None, help="kind cluster name used with --apply")

    for name in ("prepare", "restore"):
        command = scenario_sub.add_parser(name)
        command.add_argument("id")
        command.add_argument("--name", default=None, help="full tier lab name")
        add_tier_argument(command)
        command.add_argument("--json", action="store_true", dest="as_json")

    exam_parser = sub.add_parser(
        "exam",
        help="start or resume the exam-like candidate interface on the full VM lab",
    )
    exam_sub = exam_parser.add_subparsers(dest="exam_command", required=True)
    for name in ("start", "resume", "status", "teardown"):
        command = exam_sub.add_parser(name)
        command.add_argument("--name", default=None, help="full tier lab name")
        command.add_argument("--tier", default="full", choices=("quick", "full"))
        if name in {"start", "resume"}:
            add_memory_profile_argument(command)
            command.add_argument(
                "--no-open",
                action="store_true",
                help="serve the loopback ExamUI without opening the host browser",
            )
        if name == "start":
            command.add_argument("--mode", choices=("practice", "exam"), default="practice")
            command.add_argument("--duration", type=parse_exam_duration, default=2 * 60 * 60)
        if name == "teardown":
            command.add_argument(
                "--force",
                action="store_true",
                help="end and recover an active candidate session",
            )
        if name in {"status", "teardown"}:
            command.add_argument("--json", action="store_true", dest="as_json")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            return dispatch_tier(args, lambda: doctor(args.as_json))
        if args.command == "setup":
            return dispatch_tier(args, lambda: reject_quick_setup(args))
        if args.command == "provision":
            return dispatch_tier(args, lambda: provision(args))
        if args.command == "delete":
            return dispatch_tier(args, lambda: delete(args))
        if args.command == "reset":
            return dispatch_tier(args, lambda: reset_cluster(args))
        if args.command == "list":
            return print_catalog(args.as_json)
        if args.command == "shell":
            return dispatch_tier(args, lambda: open_shell(args))
        if args.command == "check":
            return check_scenario(args.id, args.root)
        if args.command == "grade":
            return dispatch_tier(
                args,
                lambda: grade_artifacts(args.id, args.root, args.as_json),
            )
        if args.command == "e2e":
            return dispatch_tier(args, lambda: e2e(args))
        if args.command == "scenario":
            if args.scenario_command == "create":
                return create_scenario(args.id, args.apply, args.name, reset=False)
            if args.scenario_command == "reset":
                return create_scenario(args.id, args.apply, args.name, reset=True)
            if args.scenario_command in {"prepare", "restore"}:
                return dispatch_tier(
                    args,
                    lambda: reject_quick_scenario_lifecycle(args),
                )
        if args.command == "exam":
            return dispatch_tier(args, lambda: reject_quick_exam(args))
    except (OSError, ValueError, RuntimeError) as exc:
        error = {"type": type(exc).__name__, "message": str(exc)}
        if isinstance(exc, TierDispatchError):
            error.update({"code": exc.code, "command": exc.command, "tier": exc.tier})
        if getattr(args, "as_json", False):
            print(json.dumps({"status": "error", "error": error}))
        elif isinstance(exc, TierDispatchError):
            print(f"error [{exc.code}]: {exc}", file=sys.stderr)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2
