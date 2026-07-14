from __future__ import annotations

import io
import gzip
import hashlib
import os
import stat
import subprocess
import tarfile
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

from infra.provision.verify_u5_artifacts import (
    MAX_DOWNLOAD_BYTES,
    _ValidatingRedirectHandler,
    _download,
    _digest_bounded_regular,
    _docker,
    _kube_bench,
    _safe_relative,
    _tar_binary,
    _validated_tar,
    _validate_cache_dir,
    _validate_archive,
    _validate_release_url,
    verify,
)


TOOLS_LIB = Path(__file__).resolve().parents[1] / "infra" / "provision" / "tools" / "lib.sh"


class U5ArtifactReleaseGateTests(unittest.TestCase):
    def test_release_urls_and_cache_directory_are_fail_closed(self) -> None:
        for accepted in (
            "https://github.com/org/project/releases/download/v1/tool",
            "https://release-assets.githubusercontent.com/github-production-release-asset/tool",
            "https://storage.googleapis.com/gvisor/releases/tool",
        ):
            _validate_release_url(accepted)
        for rejected in (
            "file:///etc/passwd",
            "http://github.com/tool",
            "https://127.0.0.1/tool",
            "https://169.254.169.254/latest/meta-data",
            "https://example.com/tool",
            "https://user:password@github.com/tool",
        ):
            with self.subTest(url=rejected), self.assertRaises(ValueError):
                _validate_release_url(rejected)
        handler = _ValidatingRedirectHandler()
        request = urllib.request.Request("https://github.com/org/project")
        with patch.object(
            urllib.request.HTTPRedirectHandler, "redirect_request"
        ) as parent, self.assertRaises(ValueError):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "http://127.0.0.1/internal",
            )
        parent.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            _validate_cache_dir(cache)
            cache.chmod(0o755)
            with self.assertRaises(ValueError):
                _validate_cache_dir(cache)

    def test_download_rejects_every_unsafe_cache_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir(mode=0o700)
            linked = root / "linked"
            linked.symlink_to(real)
            regular = root / "regular"
            regular.write_text("not a directory", encoding="utf-8")
            broad = root / "broad"
            broad.mkdir(mode=0o755)
            for label, cache in (("symlink", linked), ("file", regular), ("mode", broad)):
                with self.subTest(label=label), patch(
                    "urllib.request.build_opener"
                ) as build, self.assertRaises(ValueError):
                    _download(
                        cache,
                        "tool",
                        "https://github.com/org/project/releases/download/v1/tool",
                        "0" * 64,
                    )
                build.assert_not_called()

            wrong_owner = SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700,
                st_uid=os.getuid() + 1,
            )
            with patch.object(Path, "lstat", return_value=wrong_owner), patch(
                "urllib.request.build_opener"
            ) as build, self.assertRaises(ValueError):
                _download(
                    real,
                    "tool",
                    "https://github.com/org/project/releases/download/v1/tool",
                    "0" * 64,
                )
            build.assert_not_called()

    def test_download_success_redirect_and_post_open_failures_are_atomic(self) -> None:
        class FakeResponse:
            def __init__(self, chunks: list[bytes], url: str) -> None:
                self.chunks = iter(chunks)
                self.url = url

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def read(self, _size: int) -> bytes:
                return next(self.chunks, b"")

            def geturl(self) -> str:
                return self.url

        class FakeOpener:
            def __init__(self, callback) -> None:  # noqa: ANN001
                self.callback = callback

            def open(self, request, timeout):  # noqa: ANN001
                self.request = request
                self.timeout = timeout
                return self.callback(request)

        url = "https://github.com/org/project/releases/download/v1/tool"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            success = root / "success"
            success.mkdir(mode=0o700)
            content = b"verified artifact"
            opener = FakeOpener(lambda _request: FakeResponse([content], url))
            with patch("urllib.request.build_opener", return_value=opener) as build:
                installed = _download(success, "tool", url, hashlib.sha256(content).hexdigest())
            self.assertEqual(installed.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o600)
            self.assertEqual(list(success.iterdir()), [installed])
            handler = build.call_args.args[0]
            self.assertIsInstance(handler, _ValidatingRedirectHandler)

            stale = root / "stale"
            stale.mkdir(mode=0o700)
            stale_destination = stale / "tool"
            stale_destination.write_bytes(b"stale content")
            replacement = b"replacement content"
            with patch(
                "urllib.request.build_opener",
                return_value=FakeOpener(lambda _request: FakeResponse([replacement], url)),
            ):
                replaced = _download(
                    stale, "tool", url, hashlib.sha256(replacement).hexdigest()
                )
            self.assertEqual(replaced.read_bytes(), replacement)
            self.assertEqual(stat.S_IMODE(replaced.stat().st_mode), 0o600)
            self.assertEqual(list(stale.iterdir()), [replaced])

            forbidden = root / "forbidden"
            forbidden.mkdir(mode=0o700)

            def follow_forbidden(request):  # noqa: ANN001
                return handler.redirect_request(
                    request, None, 302, "Found", {}, "http://127.0.0.1/internal"
                )
            with patch(
                "urllib.request.build_opener", return_value=FakeOpener(follow_forbidden)
            ), self.assertRaises(ValueError):
                _download(forbidden, "tool", url, "0" * 64)
            self.assertEqual(list(forbidden.iterdir()), [])

            mismatch = root / "mismatch"
            mismatch.mkdir(mode=0o700)
            with patch(
                "urllib.request.build_opener",
                return_value=FakeOpener(lambda _request: FakeResponse([content], url)),
            ), self.assertRaisesRegex(ValueError, "digest mismatch"):
                _download(mismatch, "tool", url, "0" * 64)
            self.assertEqual(list(mismatch.iterdir()), [])

            oversized = root / "oversized"
            oversized.mkdir(mode=0o700)
            with patch("infra.provision.verify_u5_artifacts.MAX_DOWNLOAD_BYTES", 4), patch(
                "urllib.request.build_opener",
                return_value=FakeOpener(lambda _request: FakeResponse([b"12345"], url)),
            ), self.assertRaisesRegex(ValueError, "download exceeds"):
                _download(oversized, "tool", url, "0" * 64)
            self.assertEqual(list(oversized.iterdir()), [])

    def test_cached_download_enforces_exact_size_bound_before_network(self) -> None:
        url = "https://github.com/org/project/releases/download/v1/tool"
        with tempfile.TemporaryDirectory() as temporary, patch(
            "infra.provision.verify_u5_artifacts.MAX_DOWNLOAD_BYTES", 8
        ):
            root = Path(temporary)
            exact_cache = root / "exact"
            exact_cache.mkdir(mode=0o700)
            exact = exact_cache / "tool"
            exact.write_bytes(b"12345678")
            expected = hashlib.sha256(exact.read_bytes()).hexdigest()
            with patch("urllib.request.build_opener") as build:
                self.assertEqual(_download(exact_cache, "tool", url, expected), exact)
            build.assert_not_called()

    def test_cached_download_rejects_destination_substitution_and_growth(self) -> None:
        url = "https://github.com/org/project/releases/download/v1/tool"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.write_bytes(b"content")
            for label, create in (
                ("symlink", lambda path: path.symlink_to(real)),
                ("directory", lambda path: path.mkdir()),
                ("fifo", lambda path: os.mkfifo(path)),
            ):
                cache = root / f"cache-{label}"
                cache.mkdir(mode=0o700)
                create(cache / "tool")
                with self.subTest(label=label), patch(
                    "urllib.request.build_opener"
                ) as build, self.assertRaisesRegex(ValueError, "unsafe artifact cache path"):
                    _download(cache, "tool", url, "0" * 64)
                build.assert_not_called()

            growing = root / "growing"
            growing.write_bytes(b"123456789")
            underreported = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600,
                st_size=8,
            )
            with patch("infra.provision.verify_u5_artifacts.MAX_DOWNLOAD_BYTES", 8), patch(
                "infra.provision.verify_u5_artifacts.os.fstat", return_value=underreported
            ), self.assertRaisesRegex(ValueError, "cached artifact exceeds"):
                _digest_bounded_regular(growing, "sha256")

            oversized_cache = root / "oversized"
            oversized_cache.mkdir(mode=0o700)
            (oversized_cache / "tool").write_bytes(b"123456789")
            with patch("infra.provision.verify_u5_artifacts.MAX_DOWNLOAD_BYTES", 8), patch(
                "urllib.request.build_opener"
            ) as build, self.assertRaisesRegex(ValueError, "cached artifact exceeds"):
                _download(oversized_cache, "tool", url, "0" * 64)
            build.assert_not_called()

    def test_verify_lock_pins_cache_from_hash_through_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            artifact = cache / "tool"
            original = b"verified artifact"
            artifact.write_bytes(original)
            expected = hashlib.sha256(original).hexdigest()
            hashed = threading.Event()
            release = threading.Event()
            replacement_started = threading.Event()
            consumed: list[bytes] = []
            failures: list[BaseException] = []

            def locked_operation(_source, _tools, current_cache):  # noqa: ANN001
                if threading.current_thread().name == "first-verifier":
                    cached = _download(current_cache, "tool", "https://github.com/x", expected)
                    hashed.set()
                    if not release.wait(timeout=5):
                        raise AssertionError("test did not release first verifier")
                    consumed.append(cached.read_bytes())
                else:
                    replacement_started.set()
                    artifact.write_bytes(b"replacement")
                return {}

            def run() -> None:
                try:
                    verify(Path("source"), Path("tools"), cache)
                except BaseException as error:  # pragma: no cover - asserted below
                    failures.append(error)

            with patch(
                "infra.provision.verify_u5_artifacts._verify_locked",
                side_effect=locked_operation,
            ):
                first = threading.Thread(target=run, name="first-verifier")
                second = threading.Thread(target=run, name="second-verifier")
                first.start()
                self.assertTrue(hashed.wait(timeout=5))
                second.start()
                self.assertFalse(replacement_started.wait(timeout=0.2))
                release.set()
                first.join(timeout=5)
                second.join(timeout=5)

            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(consumed, [original])
            self.assertTrue(replacement_started.is_set())

    @staticmethod
    def write_archive(path: Path, members: list[tarfile.TarInfo]) -> None:
        with tarfile.open(path, "w:gz") as archive:
            for member in members:
                content = b"fixture" if member.isfile() else b""
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content) if content else None)

    @staticmethod
    def write_sparse_metadata_archive(
        path: Path, sizes: tuple[int, ...], *, complete_members: int
    ) -> None:
        zero = b"\0" * (8 * 1024 * 1024)
        with gzip.open(path, "wb", compresslevel=1) as stream:
            for index, size in enumerate(sizes):
                member = tarfile.TarInfo(f"member-{index}")
                member.type = tarfile.REGTYPE
                member.size = size
                stream.write(member.tobuf(format=tarfile.GNU_FORMAT))
                if index >= complete_members:
                    return
                remaining = (size + 511) // 512 * 512
                while remaining:
                    chunk = zero[: min(len(zero), remaining)]
                    stream.write(chunk)
                    remaining -= len(chunk)
            stream.write(b"\0" * 1024)

    @staticmethod
    def write_pax_metadata_bomb(path: Path) -> None:
        member = tarfile.TarInfo("tool")
        member.type = tarfile.REGTYPE
        member.pax_headers = {"comment": "A" * (16 * 1024 * 1024)}
        content = b"fixture"
        member.size = len(content)
        with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            archive.addfile(member, io.BytesIO(content))

    @staticmethod
    def write_negative_size_archive(path: Path) -> None:
        member = tarfile.TarInfo("negative")
        member.type = tarfile.REGTYPE
        member.size = -1
        with gzip.open(path, "wb") as stream:
            stream.write(member.tobuf(format=tarfile.GNU_FORMAT))
            stream.write(b"\0" * 1024)

    @staticmethod
    def write_combined_maximum_archive(path: Path) -> None:
        value = "A" * 900
        body = f"comment={value}\n"
        length = len(body) + 3
        while True:
            record = f"{length} {body}".encode("ascii")
            if len(record) == length:
                break
            length = len(record)
        if not (512 < len(record) <= 1024):
            raise AssertionError("fixture PAX record must exercise the 1 KiB bound")
        padded_record = record + b"\0" * (-len(record) % 512)
        content_size = MAX_DOWNLOAD_BYTES // 4096
        zero = b"\0" * (8 * 1024 * 1024)
        with gzip.open(path, "wb", compresslevel=1) as stream:
            for index in range(4096):
                extension = tarfile.TarInfo(f"pax-{index}")
                extension.type = tarfile.XHDTYPE
                extension.size = len(record)
                stream.write(extension.tobuf(format=tarfile.PAX_FORMAT))
                stream.write(padded_record)
                member = tarfile.TarInfo(f"member-{index:04d}")
                member.type = tarfile.REGTYPE
                member.size = content_size
                stream.write(member.tobuf(format=tarfile.PAX_FORMAT))
                remaining = content_size
                while remaining:
                    chunk = zero[: min(len(zero), remaining)]
                    stream.write(chunk)
                    remaining -= len(chunk)
            stream.write(b"\0" * 1024)

    def validate_members(self, members: list[tarfile.TarInfo]) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.tar.gz"
            self.write_archive(path, members)
            with tarfile.open(path, "r:gz") as archive:
                _validate_archive(archive)

    @staticmethod
    def guest_validate(path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                'source "$1"; assert_safe_tar_archive "$2"',
                "guest-archive-test",
                str(TOOLS_LIB),
                str(path),
            ],
            text=True,
            capture_output=True,
        )

    @staticmethod
    def guest_extract(path: Path, destination: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                'source "$1"; extract_safe_tar "$2" "$3"',
                "guest-extract-test",
                str(TOOLS_LIB),
                str(path),
                str(destination),
            ],
            text=True,
            capture_output=True,
        )

    def test_archive_wide_validator_accepts_only_safe_directories_and_files(self) -> None:
        directory = tarfile.TarInfo("safe")
        directory.type = tarfile.DIRTYPE
        regular = tarfile.TarInfo("safe/tool")
        regular.type = tarfile.REGTYPE
        self.validate_members([directory, regular])

    def test_archive_wide_validator_rejects_unsafe_members_anywhere(self) -> None:
        cases = (
            ("traversal", "../escape", tarfile.REGTYPE),
            ("symlink", "safe/link", tarfile.SYMTYPE),
            ("hardlink", "safe/hardlink", tarfile.LNKTYPE),
            ("fifo", "safe/fifo", tarfile.FIFOTYPE),
            ("character-device", "safe/device", tarfile.CHRTYPE),
        )
        for label, name, kind in cases:
            regular = tarfile.TarInfo("safe/tool")
            regular.type = tarfile.REGTYPE
            hostile = tarfile.TarInfo(name)
            hostile.type = kind
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                hostile.linkname = "safe/tool"
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.validate_members([regular, hostile])

    def test_archive_metadata_bounds_cover_both_sides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            accepted_path = root / "accepted.tar.gz"
            accepted_members = []
            for index in range(4096):
                member = tarfile.TarInfo(f"member-{index:04d}")
                member.type = tarfile.REGTYPE
                accepted_members.append(member)
            self.write_archive(accepted_path, accepted_members)
            with tarfile.open(accepted_path, "r:gz") as archive:
                _validate_archive(archive)
            self.assertEqual(self.guest_validate(accepted_path).returncode, 0)

            rejected_path = root / "rejected.tar.gz"
            extra = tarfile.TarInfo("member-4096")
            extra.type = tarfile.REGTYPE
            self.write_archive(rejected_path, [*accepted_members, extra])
            with tarfile.open(rejected_path, "r:gz") as archive, self.assertRaises(ValueError):
                _validate_archive(archive)
            self.assertNotEqual(self.guest_validate(rejected_path).returncode, 0)

        oversized = tarfile.TarInfo("oversized")
        oversized.type = tarfile.REGTYPE
        oversized.size = MAX_DOWNLOAD_BYTES + 1
        with self.assertRaises(ValueError):
            _validate_archive(iter([oversized]))  # type: ignore[arg-type]

        exact = tarfile.TarInfo("exact")
        exact.type = tarfile.REGTYPE
        exact.size = MAX_DOWNLOAD_BYTES
        _validate_archive(iter([exact]))  # type: ignore[arg-type]
        negative = tarfile.TarInfo("negative")
        negative.type = tarfile.REGTYPE
        negative.size = -1
        with self.assertRaises(ValueError):
            _validate_archive(iter([negative]))  # type: ignore[arg-type]
        first = tarfile.TarInfo("first")
        first.type = tarfile.REGTYPE
        first.size = MAX_DOWNLOAD_BYTES // 2 + 1
        second = tarfile.TarInfo("second")
        second.type = tarfile.REGTYPE
        second.size = MAX_DOWNLOAD_BYTES // 2 + 1
        with self.assertRaises(ValueError):
            _validate_archive(iter([first, second]))  # type: ignore[arg-type]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exact_path = root / "exact.tar.gz"
            self.write_sparse_metadata_archive(
                exact_path, (MAX_DOWNLOAD_BYTES,), complete_members=1
            )
            self.assertEqual(self.guest_validate(exact_path).returncode, 0)
            oversized_path = root / "oversized.tar.gz"
            self.write_sparse_metadata_archive(
                oversized_path, (MAX_DOWNLOAD_BYTES + 1,), complete_members=0
            )
            self.assertNotEqual(self.guest_validate(oversized_path).returncode, 0)
            aggregate_path = root / "aggregate.tar.gz"
            half = MAX_DOWNLOAD_BYTES // 2 + 1
            self.write_sparse_metadata_archive(
                aggregate_path, (half, half), complete_members=1
            )
            self.assertNotEqual(self.guest_validate(aggregate_path).returncode, 0)
            negative_path = root / "negative.tar.gz"
            self.write_negative_size_archive(negative_path)
            negative_guest = self.guest_validate(negative_path)
            self.assertNotEqual(negative_guest.returncode, 0)
            self.assertIn("member is too large", negative_guest.stderr)

    def test_compressed_pax_metadata_bomb_is_rejected_before_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "pax-bomb.tar.gz"
            self.write_pax_metadata_bomb(archive_path)
            self.assertLess(archive_path.stat().st_size, 128 * 1024)
            with self.assertRaisesRegex(ValueError, "extension metadata"):
                with _validated_tar(archive_path):
                    pass
            guest = self.guest_validate(archive_path)
            self.assertNotEqual(guest.returncode, 0)
            self.assertIn("extension metadata", guest.stderr)
            destination = root / "rejected-pax-extract"
            extracted = self.guest_extract(archive_path, destination)
            self.assertNotEqual(extracted.returncode, 0)
            self.assertFalse(destination.exists())

    def test_combined_maximum_payload_members_and_pax_metadata_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "combined-maximum.tar.gz"
            self.write_combined_maximum_archive(archive_path)
            with _validated_tar(archive_path):
                pass
            guest = self.guest_validate(archive_path)
            self.assertEqual(guest.returncode, 0, guest.stderr)

    def test_archive_path_length_and_depth_bounds_cover_both_sides(self) -> None:
        total_768 = "/".join(("a" * 190, "b" * 190, "c" * 190, "d" * 195))
        total_769 = "/".join(("a" * 190, "b" * 190, "c" * 190, "d" * 196))
        cases = (
            ("component-accepted", "a" * 255, True),
            ("component-rejected", "a" * 256, False),
            ("length-accepted", total_768, True),
            ("length-rejected", total_769, False),
            ("depth-accepted", "/".join("a" for _ in range(64)), True),
            ("depth-rejected", "/".join("a" for _ in range(65)), False),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, name, accepted in cases:
                member = tarfile.TarInfo(name)
                member.type = tarfile.REGTYPE
                archive_path = root / f"{label}.tar.gz"
                self.write_archive(archive_path, [member])
                if accepted:
                    with tarfile.open(archive_path, "r:gz") as archive:
                        _validate_archive(archive)
                    self.assertEqual(self.guest_validate(archive_path).returncode, 0)
                    destination = root / f"{label}-extract"
                    extracted = self.guest_extract(archive_path, destination)
                    self.assertEqual(extracted.returncode, 0, extracted.stderr)
                    self.assertTrue(destination.joinpath(*PurePosixPath(name).parts).is_file())
                else:
                    with tarfile.open(archive_path, "r:gz") as archive, self.assertRaises(ValueError):
                        _validate_archive(archive)
                    self.assertNotEqual(self.guest_validate(archive_path).returncode, 0)
                    destination = root / f"{label}-rejected-extract"
                    extracted = self.guest_extract(archive_path, destination)
                    self.assertNotEqual(extracted.returncode, 0)
                    self.assertFalse(destination.exists())

    def test_archive_validator_rejects_aliases_and_regular_file_ancestors(self) -> None:
        tool = tarfile.TarInfo("tool")
        tool.type = tarfile.REGTYPE
        alias = tarfile.TarInfo("./tool")
        alias.type = tarfile.REGTYPE
        with self.assertRaises(ValueError):
            self.validate_members([tool, alias])
        duplicate = tarfile.TarInfo("tool")
        duplicate.type = tarfile.REGTYPE
        with self.assertRaises(ValueError):
            self.validate_members([tool, duplicate])

        ancestor = tarfile.TarInfo("cfg")
        ancestor.type = tarfile.REGTYPE
        child = tarfile.TarInfo("cfg/config.yaml")
        child.type = tarfile.REGTYPE
        with self.assertRaises(ValueError):
            self.validate_members([ancestor, child])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            alias_archive = root / "alias.tar.gz"
            self.write_archive(alias_archive, [tool, alias])
            self.assertNotEqual(self.guest_validate(alias_archive).returncode, 0)
            duplicate_archive = root / "duplicate.tar.gz"
            self.write_archive(duplicate_archive, [tool, duplicate])
            self.assertNotEqual(self.guest_validate(duplicate_archive).returncode, 0)
            with self.assertRaises(ValueError):
                _tar_binary(duplicate_archive, "tool", root / "duplicate-tool")
            ancestor_archive = root / "ancestor.tar.gz"
            self.write_archive(ancestor_archive, [ancestor, child])
            self.assertNotEqual(self.guest_validate(ancestor_archive).returncode, 0)

    def test_archive_validator_rejects_casefold_and_unicode_normalization_collisions(self) -> None:
        binary = tarfile.TarInfo("kube-bench")
        binary.type = tarfile.REGTYPE
        upper = tarfile.TarInfo("cfg/A")
        upper.type = tarfile.REGTYPE
        lower = tarfile.TarInfo("cfg/a")
        lower.type = tarfile.REGTYPE
        composed = tarfile.TarInfo("cfg/é")
        composed.type = tarfile.REGTYPE
        decomposed = tarfile.TarInfo("cfg/e\u0301")
        decomposed.type = tarfile.REGTYPE
        nested_upper = tarfile.TarInfo("cfg/A/x")
        nested_upper.type = tarfile.REGTYPE
        nested_lower = tarfile.TarInfo("cfg/a/y")
        nested_lower.type = tarfile.REGTYPE
        for label, members in (
            ("casefold", [binary, upper, lower]),
            ("unicode", [binary, composed, decomposed]),
            ("implicit-prefix", [binary, nested_upper, nested_lower]),
        ):
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.validate_members(members)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, members in (
                ("casefold", [binary, upper, lower]),
                ("unicode", [binary, composed, decomposed]),
                ("implicit-prefix", [binary, nested_upper, nested_lower]),
            ):
                archive = root / f"{label}.tar.gz"
                self.write_archive(archive, members)
                self.assertNotEqual(self.guest_validate(archive).returncode, 0)
                output = root / f"{label}-output"
                output.mkdir()
                with self.assertRaises(ValueError):
                    _kube_bench(archive, output)

            docker_archive = root / "docker-casefold.tar.gz"
            docker_members = []
            for name in (
                "docker/docker",
                "docker/dockerd",
                "docker/containerd",
                "docker/Tool",
                "docker/tool",
            ):
                member = tarfile.TarInfo(name)
                member.type = tarfile.REGTYPE
                docker_members.append(member)
            self.write_archive(docker_archive, docker_members)
            docker_output = root / "docker-case-output"
            docker_output.mkdir()
            with self.assertRaises(ValueError):
                _docker(docker_archive, docker_output)

    def test_safe_relative_rejects_absolute_and_empty_names(self) -> None:
        for name in ("/absolute", "", "."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                _safe_relative(name)

    def test_every_extractor_wires_archive_wide_validation(self) -> None:
        hostile = tarfile.TarInfo("unrelated-link")
        hostile.type = tarfile.SYMTYPE
        hostile.linkname = "tool"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            binary_archive = root / "binary.tar.gz"
            tool = tarfile.TarInfo("tool")
            tool.type = tarfile.REGTYPE
            self.write_archive(binary_archive, [tool, hostile])
            with self.assertRaises(ValueError):
                _tar_binary(binary_archive, "tool", root / "installed-tool")

            alias = tarfile.TarInfo("./tool")
            alias.type = tarfile.REGTYPE
            self.write_archive(binary_archive, [tool, alias])
            with self.assertRaises(ValueError):
                _tar_binary(binary_archive, "tool", root / "installed-tool")

            kube_bench_archive = root / "kube-bench.tar.gz"
            kube_bench = tarfile.TarInfo("kube-bench")
            kube_bench.type = tarfile.REGTYPE
            config = tarfile.TarInfo("cfg/config.yaml")
            config.type = tarfile.REGTYPE
            self.write_archive(kube_bench_archive, [kube_bench, config, hostile])
            kube_output = root / "kube-output"
            kube_output.mkdir()
            with self.assertRaises(ValueError):
                _kube_bench(kube_bench_archive, kube_output)

            cfg_file = tarfile.TarInfo("cfg")
            cfg_file.type = tarfile.REGTYPE
            self.write_archive(kube_bench_archive, [kube_bench, cfg_file, config])
            kube_output_alias = root / "kube-output-alias"
            kube_output_alias.mkdir()
            with self.assertRaises(ValueError):
                _kube_bench(kube_bench_archive, kube_output_alias)

            docker_archive = root / "docker.tar.gz"
            docker_members = []
            for name in ("docker/docker", "docker/dockerd", "docker/containerd"):
                member = tarfile.TarInfo(name)
                member.type = tarfile.REGTYPE
                docker_members.append(member)
            self.write_archive(docker_archive, [*docker_members, hostile])
            docker_output = root / "docker-output"
            docker_output.mkdir()
            with self.assertRaises(ValueError):
                _docker(docker_archive, docker_output)


if __name__ == "__main__":
    unittest.main()
