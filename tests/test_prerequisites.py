from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from cks_simulator.prerequisites import (
    PrerequisiteError,
    install_full_prerequisites,
)


def lima_archive(
    *, unsafe_name: str | None = None, linkname: str = "../../lima"
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        entries = {
            unsafe_name or "./bin/limactl": (
                b"#!/bin/sh\nprintf 'limactl version 2.1.4\\n'\n",
                0o755,
            ),
            "./share/lima/lima-guestagent.Linux-aarch64.gz": (b"guest-agent", 0o644),
        }
        for name, (contents, mode) in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(contents)
            member.mode = mode
            archive.addfile(member, io.BytesIO(contents))
        link = tarfile.TarInfo("./share/doc/lima/templates")
        link.type = tarfile.SYMTYPE
        link.linkname = linkname
        archive.addfile(link)
    return output.getvalue()


def project_root(parent: Path, archive: bytes) -> Path:
    root = parent / "project"
    (root / "infra").mkdir(parents=True)
    (root / "infra" / "versions.json").write_text(
        json.dumps(
            {
                "lima": {
                    "version": "2.1.4",
                    "darwin_arm64_url": (
                        "https://github.com/lima-vm/lima/releases/download/"
                        "v2.1.4/lima-2.1.4-Darwin-arm64.tar.gz"
                    ),
                    "darwin_arm64_sha256": hashlib.sha256(archive).hexdigest(),
                }
            }
        ),
        encoding="utf-8",
    )
    return root


class PrerequisiteInstallerTests(unittest.TestCase):
    def test_installs_pinned_lima_locally_and_replays_without_network(self) -> None:
        archive = lima_archive()
        calls = []

        def opener(request, *, timeout):
            calls.append((request.full_url, timeout))
            return io.BytesIO(archive)

        with tempfile.TemporaryDirectory() as temporary:
            root = project_root(Path(temporary), archive)
            installed = install_full_prerequisites(
                root=root,
                opener=opener,
                existing_candidates=(),
                system="Darwin",
                machine="arm64",
            )
            replayed = install_full_prerequisites(
                root=root,
                opener=lambda *_args, **_kwargs: self.fail("unexpected download"),
                existing_candidates=(),
                system="Darwin",
                machine="arm64",
            )

            command = root / ".cks-tools" / "lima" / "2.1.4" / "bin" / "limactl"
            self.assertTrue(command.is_file())
            self.assertEqual(installed.command, str(command.resolve()))
            self.assertTrue(installed.changed)
            self.assertFalse(replayed.changed)
            self.assertEqual(len(calls), 1)
            self.assertEqual(list((root / ".cks-tools").glob("lima-install-*")), [])

    def test_digest_mismatch_leaves_no_install(self) -> None:
        archive = lima_archive()
        with tempfile.TemporaryDirectory() as temporary:
            root = project_root(Path(temporary), archive)
            manifest_path = root / "infra" / "versions.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["lima"]["darwin_arm64_sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(PrerequisiteError, "SHA-256 mismatch"):
                install_full_prerequisites(
                    root=root,
                    opener=lambda *_args, **_kwargs: io.BytesIO(archive),
                    existing_candidates=(),
                    system="Darwin",
                    machine="arm64",
                )

            self.assertFalse((root / ".cks-tools" / "lima" / "2.1.4").exists())

    def test_rejects_unsafe_archive_and_unsupported_host(self) -> None:
        archive = lima_archive(unsafe_name="../outside")
        with tempfile.TemporaryDirectory() as temporary:
            root = project_root(Path(temporary), archive)
            with self.assertRaisesRegex(PrerequisiteError, "unsafe entry"):
                install_full_prerequisites(
                    root=root,
                    opener=lambda *_args, **_kwargs: io.BytesIO(archive),
                    existing_candidates=(),
                    system="Darwin",
                    machine="arm64",
                )

            unsafe_link_archive = lima_archive(linkname="../../../../outside")
            unsafe_link_root = project_root(
                Path(temporary) / "unsafe-link", unsafe_link_archive
            )
            with self.assertRaisesRegex(PrerequisiteError, "unsafe symlink"):
                install_full_prerequisites(
                    root=unsafe_link_root,
                    opener=lambda *_args, **_kwargs: io.BytesIO(unsafe_link_archive),
                    existing_candidates=(),
                    system="Darwin",
                    machine="arm64",
                )
            with self.assertRaisesRegex(PrerequisiteError, "Apple Silicon"):
                install_full_prerequisites(
                    root=root,
                    existing_candidates=(),
                    system="Linux",
                    machine="x86_64",
                )


if __name__ == "__main__":
    unittest.main()
