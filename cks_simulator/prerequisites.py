"""Pinned, project-local host prerequisite installation."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import posixpath
import shutil
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable, Optional, Sequence
from urllib.request import Request, urlopen

from .full import REQUIRED_LIMA_VERSION, ROOT, locate_lima
from .providers.base import ProcessRequest, Runner, SubprocessRunner


MAX_ARCHIVE_BYTES = 256 * 1024**2
MAX_EXTRACTED_BYTES = 512 * 1024**2
MAX_ARCHIVE_ENTRIES = 10_000


class PrerequisiteError(RuntimeError):
    """A prerequisite could not be installed or trusted."""


@dataclass(frozen=True)
class PrerequisiteInstallResult:
    name: str
    version: str
    command: str
    changed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "command": self.command,
            "changed": self.changed,
        }


def _exact_lima_version(command: str, runner: Runner) -> bool:
    result = runner.run(
        ProcessRequest.build(
            (command, "--version"), timeout_seconds=10, output_limit=256
        )
    )
    return result.ok and result.stdout.strip() == (
        f"limactl version {REQUIRED_LIMA_VERSION}"
    )


def _load_lima_artifact(root: Path) -> tuple[str, str]:
    manifest_path = root / "infra" / "versions.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        lima = manifest["lima"]
        version = lima["version"]
        url = lima["darwin_arm64_url"]
        digest = lima["darwin_arm64_sha256"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise PrerequisiteError(
            f"invalid Lima artifact metadata in {manifest_path}"
        ) from error
    if version != REQUIRED_LIMA_VERSION:
        raise PrerequisiteError(
            "Lima manifest version differs from the runtime contract"
        )
    expected_suffix = f"/v{version}/lima-{version}-Darwin-arm64.tar.gz"
    if (
        not isinstance(url, str)
        or not url.startswith("https://github.com/lima-vm/lima/releases/download/")
        or not url.endswith(expected_suffix)
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(value not in "0123456789abcdef" for value in digest)
    ):
        raise PrerequisiteError("Lima artifact URL or SHA-256 is invalid")
    return url, digest


def _download(
    url: str,
    destination: Path,
    expected_digest: str,
    *,
    opener: Callable[..., BinaryIO],
) -> None:
    request = Request(url, headers={"User-Agent": "CKS-simulator-prerequisites"})
    digest = hashlib.sha256()
    observed_size = 0
    try:
        with opener(request, timeout=60) as response, destination.open("xb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                observed_size += len(chunk)
                if observed_size > MAX_ARCHIVE_BYTES:
                    raise PrerequisiteError("Lima release archive exceeds the size limit")
                digest.update(chunk)
                output.write(chunk)
    except PrerequisiteError:
        raise
    except OSError as error:
        raise PrerequisiteError(
            f"failed to download pinned Lima release: {error}"
        ) from error
    if digest.hexdigest() != expected_digest:
        raise PrerequisiteError("pinned Lima release SHA-256 mismatch")


def _safe_extract(archive_path: Path, destination: Path) -> None:
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if (
                len(members) > MAX_ARCHIVE_ENTRIES
                or sum(member.size for member in members) > MAX_EXTRACTED_BYTES
            ):
                raise PrerequisiteError("Lima release archive exceeds extraction limits")
            for member in members:
                relative = PurePosixPath(member.name)
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or not (member.isdir() or member.isfile() or member.issym())
                ):
                    raise PrerequisiteError("Lima release archive contains an unsafe entry")
                if member.issym():
                    link = PurePosixPath(member.linkname)
                    resolved_link = PurePosixPath(
                        posixpath.normpath(str(relative.parent / link))
                    )
                    if link.is_absolute() or ".." in resolved_link.parts:
                        raise PrerequisiteError(
                            "Lima release archive contains an unsafe symlink"
                        )
            for member in members:
                relative = PurePosixPath(member.name)
                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if member.issym():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(member.linkname)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise PrerequisiteError(
                        "Lima release archive contains an unreadable file"
                    )
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(member.mode & 0o755)
    except PrerequisiteError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise PrerequisiteError(
            f"failed to extract pinned Lima release: {error}"
        ) from error


def _prepare_tools_root(root: Path) -> Path:
    tools_root = root / ".cks-tools"
    try:
        observed = tools_root.lstat()
    except FileNotFoundError:
        tools_root.mkdir(mode=0o700)
    else:
        if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
            raise PrerequisiteError(f"{tools_root} must be a real directory")
        if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) & 0o077:
            raise PrerequisiteError(
                f"{tools_root} must be owner-only and owned by this user"
            )
    return tools_root


def install_full_prerequisites(
    *,
    root: Path = ROOT,
    runner: Optional[Runner] = None,
    opener: Callable[..., BinaryIO] = urlopen,
    existing_candidates: Optional[Sequence[str]] = None,
    system: Optional[str] = None,
    machine: Optional[str] = None,
) -> PrerequisiteInstallResult:
    """Install the exact tested Lima release without mutating global packages."""

    project_root = Path(root).resolve(strict=True)
    observed_system = system if system is not None else platform.system()
    observed_machine = machine if machine is not None else platform.machine()
    if observed_system != "Darwin" or observed_machine != "arm64":
        raise PrerequisiteError(
            "full-tier setup supports only Apple Silicon macOS (Darwin arm64)"
        )
    process_runner = runner or SubprocessRunner()
    command = (
        locate_lima(existing_candidates)
        if existing_candidates is not None
        else locate_lima()
    )
    if command is not None and _exact_lima_version(command, process_runner):
        return PrerequisiteInstallResult(
            "lima", REQUIRED_LIMA_VERSION, command, False
        )

    url, expected_digest = _load_lima_artifact(project_root)
    tools_root = _prepare_tools_root(project_root)
    install_parent = tools_root / "lima"
    try:
        observed_parent = install_parent.lstat()
    except FileNotFoundError:
        install_parent.mkdir(mode=0o700)
    else:
        if (
            not stat.S_ISDIR(observed_parent.st_mode)
            or stat.S_ISLNK(observed_parent.st_mode)
            or observed_parent.st_uid != os.getuid()
            or stat.S_IMODE(observed_parent.st_mode) & 0o077
        ):
            raise PrerequisiteError(
                f"{install_parent} must be an owned real directory"
            )
    target = install_parent / REQUIRED_LIMA_VERSION
    target_command = target / "bin" / "limactl"
    try:
        observed_target = target.lstat()
    except FileNotFoundError:
        observed_target = None
    if observed_target is not None:
        if (
            not stat.S_ISDIR(observed_target.st_mode)
            or stat.S_ISLNK(observed_target.st_mode)
            or observed_target.st_uid != os.getuid()
        ):
            raise PrerequisiteError(f"unsafe existing Lima install target: {target}")
        if target_command.is_file() and not target_command.is_symlink():
            resolved = str(target_command.resolve(strict=True))
            if _exact_lima_version(resolved, process_runner):
                return PrerequisiteInstallResult(
                    "lima", REQUIRED_LIMA_VERSION, resolved, False
                )

    temporary = Path(tempfile.mkdtemp(prefix="lima-install-", dir=tools_root))
    try:
        archive_path = temporary / "lima.tar.gz"
        extracted = temporary / "extracted"
        extracted.mkdir(mode=0o700)
        _download(url, archive_path, expected_digest, opener=opener)
        _safe_extract(archive_path, extracted)
        staged_command = extracted / "bin" / "limactl"
        if (
            not staged_command.is_file()
            or staged_command.is_symlink()
            or not os.access(staged_command, os.X_OK)
        ):
            raise PrerequisiteError(
                "pinned Lima release does not contain executable limactl"
            )
        if not _exact_lima_version(str(staged_command.resolve()), process_runner):
            raise PrerequisiteError("extracted limactl failed exact version validation")
        if observed_target is not None:
            shutil.rmtree(target)
        extracted.rename(target)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)

    resolved = str(target_command.resolve(strict=True))
    return PrerequisiteInstallResult("lima", REQUIRED_LIMA_VERSION, resolved, True)


__all__ = [
    "PrerequisiteError",
    "PrerequisiteInstallResult",
    "install_full_prerequisites",
]
