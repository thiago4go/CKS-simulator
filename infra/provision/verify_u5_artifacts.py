#!/usr/bin/env python3
"""Verify every U5 installed fingerprint from its transport-pinned release."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import gzip
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Iterator
from urllib.parse import urlparse


CHUNK = 1024 * 1024
MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_PATH_BYTES = 768
MAX_ARCHIVE_COMPONENT_BYTES = 255
MAX_ARCHIVE_DEPTH = 64
# tarfile consumes normal headers in 512-byte reads. PAX/GNU extension payloads
# are requested as a single, rounded read before they become visible as members;
# limiting metadata-phase reads prevents those records from becoming an
# allocation bypass. Canonical release archives do not require larger records.
MAX_TAR_METADATA_READ_BYTES = 1024
# Derive structural allowance from the accepted combined maximum: every member
# may need its own header, maximum payload padding, and one bounded extension
# record (header plus rounded payload). Include one global extension and the two
# terminating blocks. This keeps independent limits internally consistent.
MAX_TAR_STRUCTURAL_BYTES = (
    MAX_ARCHIVE_MEMBERS * (512 + 511)
    + (MAX_ARCHIVE_MEMBERS + 1) * (512 + MAX_TAR_METADATA_READ_BYTES)
    + 1024
)
MAX_TAR_STREAM_BYTES = MAX_DOWNLOAD_BYTES + MAX_TAR_STRUCTURAL_BYTES
RELEASE_HOSTS = {
    "download.docker.com",
    "get.helm.sh",
    "github.com",
    "storage.googleapis.com",
}
SAFE_ENV = {
    "HOME": str(Path.home()),
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
}


def _digest_bounded_regular(path: Path, algorithm: str) -> str:
    value = hashlib.new(algorithm)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        observed = os.fstat(stream.fileno())
        if not stat.S_ISREG(observed.st_mode):
            raise ValueError(f"cached artifact is not a regular file: {path.name}")
        if observed.st_size > MAX_DOWNLOAD_BYTES:
            raise ValueError(f"cached artifact exceeds 1 GiB: {path.name}")
        total = 0
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"cached artifact exceeds 1 GiB: {path.name}")
            value.update(chunk)
    return value.hexdigest()


def _validate_cache_dir(cache: Path) -> None:
    observed = cache.lstat()
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_mode & 0o077
    ):
        raise ValueError("artifact cache must be an owner-only directory owned by the current user")


@contextmanager
def _cache_lock(cache: Path) -> Iterator[None]:
    """Serialize the complete cache hash-to-consumption transaction."""

    _validate_cache_dir(cache)
    lock_path = cache / ".verify.lock"
    descriptor = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or observed.st_mode & 0o077
        ):
            raise ValueError("artifact cache lock must be an owner-only regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _validate_release_url(url: str) -> None:
    value = urlparse(url)
    hostname = (value.hostname or "").lower()
    allowed = hostname in RELEASE_HOSTS or hostname.endswith(".githubusercontent.com")
    if (
        value.scheme != "https"
        or not allowed
        or value.username is not None
        or value.password is not None
        or value.port not in (None, 443)
    ):
        raise ValueError(f"artifact URL is not an approved HTTPS release destination: {url}")


class _ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        _validate_release_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(
    cache: Path,
    label: str,
    url: str,
    expected: str,
    algorithm: str = "sha256",
) -> Path:
    _validate_cache_dir(cache)
    _validate_release_url(url)
    destination = cache / label
    if destination.exists() or destination.is_symlink():
        observed = destination.lstat()
        if stat.S_ISREG(observed.st_mode) and not stat.S_ISLNK(observed.st_mode):
            if _digest_bounded_regular(destination, algorithm) == expected:
                return destination
            destination.unlink()
        else:
            raise ValueError(f"unsafe artifact cache path: {destination}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{label}.", dir=cache)
    temporary = Path(temporary_name)
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "CKS-simulator-release-integrity/1"},
        )
        total = 0
        observed_digest = hashlib.new(algorithm)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            opener = urllib.request.build_opener(_ValidatingRedirectHandler())
            with opener.open(request, timeout=300) as response:
                _validate_release_url(response.geturl())
                for chunk in iter(lambda: response.read(CHUNK), b""):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ValueError(f"download exceeds 1 GiB: {label}")
                    output.write(chunk)
                    observed_digest.update(chunk)
        if observed_digest.hexdigest() != expected:
            raise ValueError(f"transport digest mismatch: {label}")
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        return destination
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _safe_relative(name: str) -> PurePosixPath:
    value = PurePosixPath(name)
    if value.is_absolute() or not value.parts or ".." in value.parts:
        raise ValueError(f"unsafe archive member: {name}")
    return value


class _BoundedTarStream:
    """Seekable decompressed tar stream with pre-parse allocation bounds."""

    def __init__(self, stream) -> None:  # noqa: ANN001
        self._stream = stream
        self._metadata_phase = True

    def allow_payload_reads(self) -> None:
        self._metadata_phase = False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            raise ValueError("unbounded tar stream read is not allowed")
        if self._metadata_phase and size > MAX_TAR_METADATA_READ_BYTES:
            raise ValueError("tar extension metadata exceeds 1 KiB")
        position = self.tell()
        if size > MAX_TAR_STREAM_BYTES - position:
            raise ValueError("decompressed tar stream exceeds its safe bound")
        return self._stream.read(size)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self.tell() + offset
        else:
            raise ValueError("end-relative tar seeks are not allowed")
        if target < 0 or target > MAX_TAR_STREAM_BYTES:
            raise ValueError("decompressed tar stream exceeds its safe bound")
        observed = self._stream.seek(offset, whence)
        if observed != target:
            raise ValueError("tar stream seek did not reach the requested offset")
        return observed

    def tell(self) -> int:
        return self._stream.tell()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True


@contextmanager
def _validated_tar(archive_path: Path) -> Iterator[tarfile.TarFile]:
    """Open a gzip tar only after bounded parsing validates every member."""

    with gzip.open(archive_path, "rb") as decompressed:
        bounded = _BoundedTarStream(decompressed)
        with tarfile.open(fileobj=bounded, mode="r:") as archive:
            _validate_archive(archive)
            bounded.allow_payload_reads()
            yield archive


def _validate_archive(archive: tarfile.TarFile) -> None:
    members = []
    total_size = 0
    for member in archive:
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive has too many members")
        if member.size < 0 or member.size > MAX_DOWNLOAD_BYTES:
            raise ValueError(f"archive member is too large: {member.name}")
        total_size += member.size
        if total_size > MAX_DOWNLOAD_BYTES:
            raise ValueError("archive expands beyond 1 GiB")
        members.append(member)
    if not members:
        raise ValueError("archive is empty")
    kinds: dict[str, str] = {}
    prefix_aliases: dict[str, str] = {}
    for member in members:
        path = _safe_relative(member.name)
        if (
            len(path.as_posix().encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES
            or any(len(part.encode("utf-8")) > MAX_ARCHIVE_COMPONENT_BYTES for part in path.parts)
            or len(path.parts) > MAX_ARCHIVE_DEPTH
        ):
            raise ValueError(f"archive path exceeds safe bounds: {member.name}")
        if not (member.isfile() or member.isdir()):
            raise ValueError(f"archive has a non-regular member: {member.name}")
        normalized = path.as_posix()
        allowed = {normalized, normalized + "/"} if member.isdir() else {normalized}
        if (
            member.name not in allowed
            or unicodedata.normalize("NFC", normalized) != normalized
            or normalized in kinds
        ):
            raise ValueError(f"archive has a non-canonical or duplicate path: {member.name}")
        prefixes = [path, *(parent for parent in path.parents if parent.parts)]
        for prefix in prefixes:
            canonical_prefix = prefix.as_posix()
            alias = unicodedata.normalize("NFC", canonical_prefix).casefold()
            if alias in prefix_aliases and prefix_aliases[alias] != canonical_prefix:
                raise ValueError(f"archive has a casefold path-prefix collision: {member.name}")
            prefix_aliases[alias] = canonical_prefix
        kinds[normalized] = "directory" if member.isdir() else "file"
    for name in kinds:
        for parent in PurePosixPath(name).parents:
            if not parent.parts:
                break
            if kinds.get(parent.as_posix()) == "file":
                raise ValueError(f"archive has a regular-file ancestor: {parent}")


def _regular_member(archive: tarfile.TarFile, name: str) -> bytes:
    matches = [item for item in archive.getmembers() if item.name == name]
    if len(matches) != 1 or not matches[0].isfile():
        raise ValueError(f"archive does not contain one regular {name!r}")
    stream = archive.extractfile(matches[0])
    if stream is None:
        raise ValueError(f"cannot read archive member {name!r}")
    return stream.read(MAX_DOWNLOAD_BYTES + 1)


def _write_file(path: Path, content: bytes, mode: int) -> Path:
    if len(content) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"extracted artifact is too large: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return path


def _tar_binary(archive_path: Path, member: str, output: Path) -> Path:
    with _validated_tar(archive_path) as archive:
        return _write_file(output, _regular_member(archive, member), 0o755)


def _kube_bench(archive_path: Path, root: Path) -> tuple[Path, Path]:
    binary = root / "kube-bench"
    config = root / "kube-bench-config"
    config.mkdir(mode=0o755)
    seen: set[PurePosixPath] = set()
    with _validated_tar(archive_path) as archive:
        _write_file(binary, _regular_member(archive, "kube-bench"), 0o755)
        for member in archive.getmembers():
            path = _safe_relative(member.name)
            if path.parts[0] != "cfg" or len(path.parts) == 1:
                continue
            relative = PurePosixPath(*path.parts[1:])
            if relative in seen:
                raise ValueError(f"duplicate kube-bench config member: {relative}")
            seen.add(relative)
            target = config.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o755)
            elif member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"cannot read kube-bench member: {relative}")
                _write_file(target, stream.read(MAX_DOWNLOAD_BYTES + 1), 0o644)
            else:
                raise ValueError(f"unsafe kube-bench member: {relative}")
    for directory in [config, *(path for path in config.rglob("*") if path.is_dir())]:
        directory.chmod(0o755)
    return binary, config


def _docker(archive_path: Path, root: Path) -> Path:
    output = root / "docker"
    output.mkdir(mode=0o755)
    seen: set[str] = set()
    with _validated_tar(archive_path) as archive:
        for member in archive.getmembers():
            path = _safe_relative(member.name)
            if path.parts[0] != "docker" or len(path.parts) == 1:
                continue
            if len(path.parts) != 2 or not member.isfile() or path.name in seen:
                raise ValueError(f"unsafe Docker archive member: {member.name}")
            seen.add(path.name)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read Docker member: {member.name}")
            _write_file(output / path.name, stream.read(MAX_DOWNLOAD_BYTES + 1), 0o755)
    if not {"docker", "dockerd", "containerd"}.issubset(seen):
        raise ValueError("Docker archive is incomplete")
    output.chmod(0o755)
    return output


def _fingerprint(tools_lib: Path, artifact: Path) -> str:
    command = 'source "$1"; artifact_content_sha256 "$2"'
    result = subprocess.run(
        ("/bin/bash", "-c", command, "verify-u5", str(tools_lib), str(artifact)),
        text=True,
        capture_output=True,
        env=SAFE_ENV,
        timeout=300,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or len(value) != 64:
        raise ValueError(f"cannot fingerprint {artifact.name}: {result.stderr.strip()}")
    return value


def _verify_locked(source_path: Path, tools_lib: Path, cache: Path) -> dict[str, str]:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    if not isinstance(source, dict) or source.get("schema") != 1:
        raise ValueError("unsupported version source schema")
    work = cache / "installed"
    _validate_cache_dir(cache)
    if work.is_symlink():
        raise ValueError("installed-artifact workspace must not be a symlink")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700)

    artifacts: dict[str, tuple[Path, str]] = {}
    helm = source["helm"]
    artifacts["HELM_INSTALLED_SHA256"] = (
        _tar_binary(
            _download(cache, "helm.tgz", helm["url"], helm["sha256"]),
            "linux-arm64/helm",
            work / "helm",
        ),
        helm["installed_sha256"],
    )
    cilium = source["cilium"]
    artifacts["CILIUM_CLI_INSTALLED_SHA256"] = (
        _tar_binary(
            _download(cache, "cilium.tgz", cilium["cli_url"], cilium["cli_sha256"]),
            "cilium",
            work / "cilium",
        ),
        cilium["cli_installed_sha256"],
    )
    etcdctl = source["etcdctl"]
    artifacts["ETCDCTL_INSTALLED_SHA256"] = (
        _tar_binary(
            _download(cache, "etcdctl.tgz", etcdctl["url"], etcdctl["sha256"]),
            f"etcd-v{etcdctl['version']}-linux-arm64/etcdctl",
            work / "etcdctl",
        ),
        etcdctl["installed_sha256"],
    )
    kube_bench = source["kube_bench"]
    kb_binary, kb_config = _kube_bench(
        _download(cache, "kube-bench.tgz", kube_bench["url"], kube_bench["sha256"]),
        work,
    )
    artifacts["KUBE_BENCH_BINARY_INSTALLED_SHA256"] = (
        kb_binary,
        kube_bench["binary_installed_sha256"],
    )
    artifacts["KUBE_BENCH_CONFIG_INSTALLED_SHA256"] = (
        kb_config,
        kube_bench["config_installed_sha256"],
    )
    gvisor = source["gvisor"]
    for label, url_key, transport_key, installed_key, manifest_key in (
        ("runsc", "runsc_url", "runsc_sha512", "runsc_installed_sha256", "GVISOR_RUNSC_INSTALLED_SHA256"),
        ("gvisor_shim", "shim_url", "shim_sha512", "shim_installed_sha256", "GVISOR_SHIM_INSTALLED_SHA256"),
    ):
        cached = _download(cache, label, gvisor[url_key], gvisor[transport_key], "sha512")
        target = work / label
        shutil.copyfile(cached, target)
        target.chmod(0o755)
        artifacts[manifest_key] = (target, gvisor[installed_key])
    docker = source["docker"]
    artifacts["DOCKER_INSTALLED_SHA256"] = (
        _docker(_download(cache, "docker.tgz", docker["url"], docker["sha256"]), work),
        docker["installed_sha256"],
    )
    for label, section_name, manifest_key in (
        ("falco_chart", "falco", "FALCO_CHART_INSTALLED_SHA256"),
        ("ingress_chart", "ingress_nginx", "INGRESS_NGINX_CHART_INSTALLED_SHA256"),
    ):
        section = source[section_name]
        cached = _download(cache, label, section["chart_url"], section["chart_sha256"])
        target = work / label
        shutil.copyfile(cached, target)
        target.chmod(0o600)
        artifacts[manifest_key] = (target, section["chart_installed_sha256"])

    observed: dict[str, str] = {}
    for name, (path, expected) in artifacts.items():
        value = _fingerprint(tools_lib, path)
        if value != expected:
            raise ValueError(f"installed fingerprint mismatch for {name}: {value} != {expected}")
        observed[name] = value
    return observed


def verify(source_path: Path, tools_lib: Path, cache: Path) -> dict[str, str]:
    with _cache_lock(cache):
        return _verify_locked(source_path, tools_lib, cache)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--tools-lib", required=True, type=Path)
    parser.add_argument("--cache-dir", type=Path)
    args = parser.parse_args()
    if args.source.is_symlink() or args.tools_lib.is_symlink():
        raise ValueError("release gate inputs must not be symlinks")
    if args.cache_dir is None:
        with tempfile.TemporaryDirectory(prefix="cks-u5-release-gate-") as temporary:
            observed = verify(args.source.resolve(strict=True), args.tools_lib.resolve(strict=True), Path(temporary))
    else:
        cache = args.cache_dir.expanduser()
        cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        _validate_cache_dir(cache)
        observed = verify(args.source.resolve(strict=True), args.tools_lib.resolve(strict=True), cache.resolve(strict=True))
    print(json.dumps({"status": "pass", "verified": observed}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError, tarfile.TarError) as error:
        print(f"ERROR: {error}", file=os.sys.stderr)
        raise SystemExit(1)
