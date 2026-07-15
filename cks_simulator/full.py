"""Composition and host preflight for the opt-in full VM tier."""

from __future__ import annotations

import os
import platform
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence, Tuple

from .exam import ExamSessionStore, build_exam_manifest
from .exam_engine import ExamEngine
from .lab import FullLabLifecycle
from .providers.base import ProcessRequest, Runner, SubprocessRunner
from .providers.lima import LimaProvider
from .scenario_runtime import (
    build_exam_apiserver_composer,
    build_full_registries,
    build_health_attestor,
)
from .scenarios import ReferenceSolutionRegistry, ScenarioEngine, load_full_catalog
from .state import LabStateStore


ROOT = Path(__file__).resolve().parents[1]
FULL_ROLES = ("candidate", "control-plane", "worker1", "worker2")
MINIMUM_CPUS = 16
LOW_MINIMUM_CPUS = 8
MINIMUM_MEMORY_BYTES = 16 * 1024**3
LOW_MEMORY_BYTES = 12 * 1024**3
MINIMUM_DISK_BYTES = 80 * 1024**3
MINIMUM_REPLAY_DISK_BYTES = 20 * 1024**3
REQUIRED_LIMA_VERSION = "2.1.4"
_LIMA_CANDIDATES = (
    str(ROOT / ".cks-tools" / "lima" / REQUIRED_LIMA_VERSION / "bin" / "limactl"),
    "/opt/homebrew/bin/limactl",
    "/usr/local/bin/limactl",
    "/usr/bin/limactl",
)


class FullTierError(RuntimeError):
    """A full-tier host or composition invariant failed."""


@dataclass(frozen=True)
class MemoryProfile:
    """Immutable guest-resource and host-capacity contract for the full tier."""

    name: str
    role_cpus: Tuple[Tuple[str, int], ...]
    role_memory_gib: Tuple[Tuple[str, int], ...]
    minimum_host_cpus: int
    minimum_host_memory_bytes: int

    def __post_init__(self) -> None:
        if self.name not in {"standard", "low"}:
            raise ValueError("unsupported full-tier memory profile")
        cpu_values = dict(self.role_cpus)
        memory_values = dict(self.role_memory_gib)
        if tuple(cpu_values) != FULL_ROLES or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in cpu_values.values()
        ):
            raise ValueError("memory profile must define positive CPUs for every role")
        if tuple(memory_values) != FULL_ROLES or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in memory_values.values()
        ):
            raise ValueError("memory profile must define positive GiB for every role")
        if self.minimum_host_cpus < max(cpu_values.values()):
            raise ValueError("host CPU floor must cover the largest guest")
        if self.minimum_host_memory_bytes < sum(memory_values.values()) * 1024**3:
            raise ValueError("host memory floor must cover all guest memory")

    @property
    def cpus_by_role(self) -> Mapping[str, int]:
        return dict(self.role_cpus)

    @property
    def memory_gib_by_role(self) -> Mapping[str, int]:
        return dict(self.role_memory_gib)

    @property
    def total_guest_memory_gib(self) -> int:
        return sum(value for _role, value in self.role_memory_gib)

    @property
    def total_guest_cpus(self) -> int:
        return sum(value for _role, value in self.role_cpus)


MEMORY_PROFILES = {
    "standard": MemoryProfile(
        "standard",
        (("candidate", 2), ("control-plane", 4), ("worker1", 3), ("worker2", 3)),
        (("candidate", 2), ("control-plane", 4), ("worker1", 2), ("worker2", 2)),
        MINIMUM_CPUS,
        MINIMUM_MEMORY_BYTES,
    ),
    "low": MemoryProfile(
        "low",
        (("candidate", 1), ("control-plane", 3), ("worker1", 2), ("worker2", 2)),
        (("candidate", 1), ("control-plane", 2), ("worker1", 1), ("worker2", 1)),
        LOW_MINIMUM_CPUS,
        LOW_MEMORY_BYTES,
    ),
}
DEFAULT_MEMORY_PROFILE = "standard"


def resolve_memory_profile(value: Optional[str]) -> MemoryProfile:
    name = value or DEFAULT_MEMORY_PROFILE
    try:
        return MEMORY_PROFILES[name]
    except (KeyError, TypeError) as error:
        raise FullTierError(
            f"unsupported memory profile {name!r}; expected standard or low"
        ) from error


@dataclass(frozen=True)
class FullHostCheck:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


def _default_memory_bytes() -> int:
    runner = SubprocessRunner()
    value = runner.run(
        ProcessRequest.build(
            ("/usr/sbin/sysctl", "-n", "hw.memsize"),
            timeout_seconds=10,
            output_limit=128,
        )
    )
    if not value.ok:
        return 0
    try:
        return int(value.stdout.strip())
    except ValueError:
        return 0


def locate_lima(candidates: Sequence[str] = _LIMA_CANDIDATES) -> Optional[str]:
    for value in candidates:
        candidate = Path(value)
        try:
            resolved = candidate.resolve(strict=True)
            observed = resolved.stat()
        except OSError:
            continue
        if (
            candidate.is_absolute()
            and stat.S_ISREG(observed.st_mode)
            and os.access(resolved, os.X_OK)
        ):
            return str(resolved)
    return None


def host_preflight(
    *,
    root: Path = ROOT,
    runner: Optional[Runner] = None,
    lima_command: Optional[str] = None,
    system: Optional[str] = None,
    machine: Optional[str] = None,
    cpu_count: Optional[int] = None,
    memory_bytes: Optional[int] = None,
    disk_free_bytes: Optional[int] = None,
    require_creation_capacity: bool = True,
    memory_profile: Optional[str] = None,
) -> Tuple[FullHostCheck, ...]:
    """Return every bounded full-tier host check without creating a lab."""

    root = Path(root).resolve(strict=True)
    profile = resolve_memory_profile(memory_profile)
    command = lima_command or locate_lima()
    process_runner = runner or SubprocessRunner()
    observed_system = system if system is not None else platform.system()
    observed_machine = machine if machine is not None else platform.machine()
    observed_cpus = cpu_count if cpu_count is not None else (os.cpu_count() or 0)
    observed_memory = memory_bytes if memory_bytes is not None else _default_memory_bytes()
    observed_disk = (
        disk_free_bytes
        if disk_free_bytes is not None
        else shutil.disk_usage(root).free
    )
    required_disk = (
        MINIMUM_DISK_BYTES if require_creation_capacity else MINIMUM_REPLAY_DISK_BYTES
    )
    checks = [
        FullHostCheck("host-os", observed_system == "Darwin", observed_system),
        FullHostCheck("host-arch", observed_machine == "arm64", observed_machine),
        FullHostCheck(
            "host-cpus",
            observed_cpus >= profile.minimum_host_cpus,
            f"{observed_cpus} logical CPUs (minimum {profile.minimum_host_cpus}; "
            f"profile {profile.name})",
        ),
        FullHostCheck(
            "host-memory",
            observed_memory >= profile.minimum_host_memory_bytes,
            f"{observed_memory // 1024**3} GiB "
            f"(minimum {profile.minimum_host_memory_bytes // 1024**3} GiB; "
            f"profile {profile.name})",
        ),
        FullHostCheck(
            "host-disk",
            observed_disk >= required_disk,
            f"{observed_disk // 1024**3} GiB free (minimum {required_disk // 1024**3} GiB)",
        ),
        FullHostCheck("lima-command", command is not None, command or "not found"),
    ]
    if command is None:
        checks.append(FullHostCheck("lima-version", False, "limactl is unavailable"))
        return tuple(checks)

    version = process_runner.run(
        ProcessRequest.build(
            (command, "--version"), timeout_seconds=10, output_limit=256
        )
    )
    rendered_version = (version.stdout or version.stderr).strip()
    checks.append(
        FullHostCheck(
            "lima-version",
            version.ok and rendered_version == f"limactl version {REQUIRED_LIMA_VERSION}",
            rendered_version or "no version output",
        )
    )
    for role in FULL_ROLES:
        template = root / "infra" / "lima" / f"{role}.yaml"
        result = process_runner.run(
            ProcessRequest.build(
                (command, "validate", str(template)),
                timeout_seconds=30,
                output_limit=1024,
            )
        )
        checks.append(
            FullHostCheck(
                f"lima-template-{role}",
                result.ok,
                "valid" if result.ok else result.diagnostic(limit=512),
            )
        )
    return tuple(checks)


def require_host_preflight(**kwargs: object) -> Tuple[FullHostCheck, ...]:
    checks = host_preflight(**kwargs)
    failed = tuple(item for item in checks if not item.passed)
    if failed:
        raise FullTierError(
            "full-tier host preflight failed: "
            + "; ".join(f"{item.name}={item.detail}" for item in failed)
        )
    return checks


def ensure_provider_runtime(state_root: Path) -> Path:
    """Create the provider runtime root once and verify owner-only semantics."""

    requested_root = Path(state_root).expanduser()
    if requested_root.is_symlink():
        raise FullTierError(
            "full-tier state root must be an owner-only non-symlink directory"
        )
    requested_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    state_root = requested_root.resolve(strict=True)
    state_observed = state_root.lstat()
    if (
        state_root.is_symlink()
        or not stat.S_ISDIR(state_observed.st_mode)
        or state_observed.st_uid != os.getuid()
        or stat.S_IMODE(state_observed.st_mode) != 0o700
    ):
        raise FullTierError(
            "full-tier state root must be an owner-only non-symlink directory"
        )
    runtime = state_root / "provider-runtime"
    runtime.mkdir(mode=0o700, exist_ok=True)
    observed = runtime.lstat()
    if (
        runtime.is_symlink()
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        raise FullTierError(
            "full-tier provider runtime must be an owner-only non-symlink directory"
        )
    return runtime


def build_lifecycle(
    *,
    root: Path = ROOT,
    state_root: Optional[Path] = None,
    runner: Optional[Runner] = None,
    lima_command: Optional[str] = None,
    destroy_only: bool = False,
    memory_profile: Optional[str] = None,
) -> FullLabLifecycle:
    """Build one dependency-injected full lifecycle from version-controlled IaC."""

    root = Path(root).resolve(strict=True)
    profile = resolve_memory_profile(memory_profile)
    state = Path(state_root) if state_root is not None else root / ".cks-state"
    runtime = ensure_provider_runtime(state)
    command = lima_command or locate_lima()
    if command is None:
        raise FullTierError("limactl is unavailable")
    templates = (
        {}
        if destroy_only
        else {
            role: str((root / "infra" / "lima" / f"{role}.yaml").resolve(strict=True))
            for role in FULL_ROLES
        }
    )
    provider = LimaProvider(
        runner or SubprocessRunner(),
        templates=templates,
        state_dir=runtime,
        command=(command,),
        cpus_by_role={} if destroy_only else profile.cpus_by_role,
        memory_gib_by_role={} if destroy_only else profile.memory_gib_by_role,
    )
    return FullLabLifecycle(
        LabStateStore(state, namespace="full"),
        provider,
        provisioning_root=None if destroy_only else root / "infra" / "provision",
        version_source_path=None if destroy_only else root / "infra" / "versions.json",
        inventory_path=None if destroy_only else root / "infra" / "inventory.json",
        scenario_fixture_root=None if destroy_only else root / "scenarios" / "fixtures",
        provisioning_profile=profile.name,
        provisioning_spec_extension=(
            None
            if destroy_only or profile.name == DEFAULT_MEMORY_PROFILE
            else {
                "memory_profile": profile.name,
                "cpus_by_role": profile.cpus_by_role,
                "memory_gib_by_role": profile.memory_gib_by_role,
            }
        ),
    )


def build_scenario_runtime(
    *,
    root: Path = ROOT,
    state_root: Optional[Path] = None,
    runner: Optional[Runner] = None,
    lima_command: Optional[str] = None,
) -> tuple[ScenarioEngine, ReferenceSolutionRegistry]:
    """Build U7 scenario lifecycle, trusted observation, and references."""

    root = Path(root).resolve(strict=True)
    state = Path(state_root) if state_root is not None else root / ".cks-state"
    runtime = ensure_provider_runtime(state)
    command = lima_command or locate_lima()
    if command is None:
        raise FullTierError("limactl is unavailable")
    provider = LimaProvider(
        runner or SubprocessRunner(),
        templates={},
        state_dir=runtime,
        command=(command,),
    )
    handlers, references, _broker = build_full_registries(provider, root)
    engine = ScenarioEngine(
        store=LabStateStore(state, namespace="full"),
        catalog=load_full_catalog(root / "scenarios" / "catalog.json"),
        handlers=handlers,
        attest_health=build_health_attestor(provider),
    )
    return engine, references


def build_scenario_engine(
    *,
    root: Path = ROOT,
    state_root: Optional[Path] = None,
) -> ScenarioEngine:
    """Build the reviewed full-tier scenario engine."""

    return build_scenario_runtime(root=root, state_root=state_root)[0]


def build_exam_engine(
    *,
    root: Path = ROOT,
    state_root: Optional[Path] = None,
) -> ExamEngine:
    """Build the host-owned combined exam runtime over the full VM lab."""

    root = Path(root).resolve(strict=True)
    state = (
        Path(state_root).expanduser().resolve()
        if state_root is not None
        else (root / ".cks-state").resolve()
    )
    runtime = ensure_provider_runtime(state)
    command = locate_lima()
    if command is None:
        raise FullTierError("limactl is unavailable")
    provider = LimaProvider(
        SubprocessRunner(),
        templates={},
        state_dir=runtime,
        command=(command,),
    )
    handlers, references, _broker = build_full_registries(provider, root)
    composer = build_exam_apiserver_composer(provider, root)
    return ExamEngine(
        lab_store=LabStateStore(state, namespace="full"),
        exam_store=ExamSessionStore(state),
        manifest=build_exam_manifest(root / "scenarios" / "catalog.json"),
        catalog=load_full_catalog(root / "scenarios" / "catalog.json"),
        handlers=handlers,
        attest_health=build_health_attestor(provider),
        references=references,
        compose_reference_apiserver=composer.apply_reference,
    )


__all__ = [
    "DEFAULT_MEMORY_PROFILE",
    "FULL_ROLES",
    "FullHostCheck",
    "FullTierError",
    "MEMORY_PROFILES",
    "MemoryProfile",
    "build_scenario_engine",
    "build_exam_engine",
    "build_scenario_runtime",
    "build_lifecycle",
    "ensure_provider_runtime",
    "host_preflight",
    "locate_lima",
    "require_host_preflight",
    "resolve_memory_profile",
]
