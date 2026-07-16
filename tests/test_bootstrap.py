from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "bootstrap-python"
LAUNCHER = ROOT / "bin" / "cks-simulator"
SETUP = ROOT / "setup.sh"


class HostBootstrapTests(unittest.TestCase):
    def test_entrypoints_are_executable_strict_shell(self) -> None:
        for path in (BOOTSTRAP, LAUNCHER, SETUP):
            with self.subTest(path=path):
                mode = path.stat().st_mode
                self.assertTrue(mode & stat.S_IXUSR)
                result = subprocess.run(
                    ("/bin/sh", "-n", str(path)),
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scripts/bootstrap-python", LAUNCHER.read_text(encoding="utf-8"))
        self.assertIn("setup --tier full", SETUP.read_text(encoding="utf-8"))

    def test_uses_explicit_compatible_python_without_installing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tools = Path(temporary) / "tools"
            result = subprocess.run(
                (str(BOOTSTRAP),),
                env={
                    **os.environ,
                    "PYTHON": os.environ.get("PYTHON", "python3"),
                    "CKS_TOOLS_ROOT": str(tools),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(Path(result.stdout.strip()).is_file())
            self.assertFalse(tools.exists())

    def test_pinned_python_contract_matches_version_manifest(self) -> None:
        manifest = json.loads(
            (ROOT / "infra" / "bootstrap-versions.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["schema"], 1)
        python = manifest["python"]
        script = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn(f"PYTHON_VERSION={python['version']}", script)
        self.assertIn(f"PYTHON_BUILD={python['build']}", script)
        self.assertIn(f"PYTHON_URL='{python['darwin_arm64_url']}'", script)
        self.assertIn(f"PYTHON_SHA256={python['darwin_arm64_sha256']}", script)
        self.assertIn("pinned Python archive SHA-256 mismatch", script)
        self.assertIn("automatic Python installation supports Apple Silicon macOS only", script)

    def test_rejects_symlinked_tools_root_before_download(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            result = subprocess.run(
                (str(BOOTSTRAP),),
                env={
                    **os.environ,
                    "CKS_BOOTSTRAP_PREFER_PINNED": "1",
                    "CKS_TOOLS_ROOT": str(linked),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be a real directory", result.stderr)


if __name__ == "__main__":
    unittest.main()
