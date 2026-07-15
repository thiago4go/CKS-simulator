from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "infra" / "provision" / "candidate" / "install-desktop.sh"
LIBRARY = ROOT / "infra" / "provision" / "candidate" / "lib.sh"


class CandidateDesktopProvisionContractTests(unittest.TestCase):
    @staticmethod
    def embedded_file(source: str, name: str) -> str:
        marker = f'cat >"$temporary/{name}" <<\'EOF\'\n'
        _, found, remainder = source.partition(marker)
        if not found:
            raise AssertionError(f"embedded file is missing: {name}")
        body, found, _ = remainder.partition("\nEOF\n")
        if not found:
            raise AssertionError(f"embedded file is unterminated: {name}")
        return body + "\n"

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8")
        cls.library_source = LIBRARY.read_text(encoding="utf-8")
        cls.vnc_unit = cls.embedded_file(cls.source, "cks-candidate-vnc.service")
        cls.novnc_unit = cls.embedded_file(cls.source, "cks-candidate-novnc.service")
        cls.xstartup = cls.embedded_file(cls.source, "xstartup")
        cls.openbox_menu = cls.embedded_file(cls.source, "openbox-menu.xml")

    def test_installer_is_executable_strict_bash(self) -> None:
        self.assertTrue(os.access(INSTALLER, os.X_OK))
        self.assertTrue(self.source.startswith("#!/usr/bin/env bash\n"))
        self.assertIn("set -Eeuo pipefail", self.source)
        self.assertIn("IFS=$'\\n\\t'", self.source)
        self.assertIn(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            self.source,
        )
        syntax = subprocess.run(
            ["/bin/bash", "-n", str(INSTALLER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_apt_contract_is_noninteractive_minimal_and_exact(self) -> None:
        self.assertIn("export DEBIAN_FRONTEND=noninteractive", self.source)
        expected = """timeout 600 apt-get install --yes --no-install-recommends \\
  tigervnc-standalone-server \\
  novnc \\
  websockify \\
  openbox \\
  xterm \\
  dbus-x11 \\
  xauth \\
  fonts-dejavu-core \\
  netsurf-gtk"""
        self.assertIn(expected, self.source)
        self.assertIn('[[ "$os_id" == ubuntu ]]', self.source)
        for display_manager in ("gdm3", "lightdm", "sddm"):
            self.assertNotRegex(
                self.source,
                rf"apt-get install[^\n]*(?:\\\n[^\n]*)*\b{display_manager}\b",
            )

    def test_identity_and_paths_are_exact_and_fail_closed(self) -> None:
        for contract in (
            "readonly VNC_PORT=5901",
            "readonly NOVNC_PORT=6080",
            '[[ "$name" == "$CANDIDATE_USER"',
            '[[ "$home" == "$CANDIDATE_HOME" && "$shell" == /bin/bash ]]',
            '[[ "$group_name" == "$CANDIDATE_USER" ]]',
            '[[ -d "$CANDIDATE_HOME" && ! -L "$CANDIDATE_HOME" ]]',
            "assert_candidate_password_locked",
            "assert_candidate_has_no_sudo",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, self.source)
        self.assertIn("readonly CANDIDATE_USER=candidate", self.library_source)
        self.assertIn("readonly CANDIDATE_HOME=/home/candidate", self.library_source)
        self.assertIn('source "${SCRIPT_DIR}/lib.sh"', self.source)
        self.assertIn("candidate path is unsafe", self.source)
        self.assertIn("destination path is unsafe", self.source)

    def test_tigervnc_is_candidate_only_and_not_externally_reachable(self) -> None:
        for contract in (
            "User=candidate",
            "Group=candidate",
            "tigervncserver :1 -fg",
            "-geometry 1280x800",
            "-rfbport 5901",
            "-localhost yes",
            "-interface 127.0.0.1",
            "-SecurityTypes None",
            "-AcceptCutText=0",
            "-SendCutText=0",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, self.vnc_unit)
        self.assertNotIn("vncpasswd", self.vnc_unit)
        self.assertNotIn("-NoClipboard", self.vnc_unit)
        self.assertNotIn("0.0.0.0:5901", self.vnc_unit)
        self.assertNotIn("IPAddressDeny=any", self.vnc_unit)
        self.assertNotIn("IPAddressAllow=localhost", self.vnc_unit)

    def test_novnc_websockify_is_loopback_only(self) -> None:
        self.assertIn(
            "websockify --web=/usr/share/novnc 127.0.0.1:6080 127.0.0.1:5901",
            self.novnc_unit,
        )
        self.assertNotIn("0.0.0.0:6080", self.novnc_unit)
        self.assertIn('readonly NOVNC_PACKAGE=/usr/share/novnc/package.json', self.source)
        self.assertIn('{"name":"@novnc/novnc","version":"1.3.0"}', self.source)
        self.assertIn('"$NOVNC_PACKAGE" root root 0644', self.source)
        self.assertIn('wait_for_exact_listener "$VNC_PORT"', self.source)
        self.assertIn('wait_for_exact_listener "$NOVNC_PORT"', self.source)
        self.assertIn('expected="127.0.0.1:${port}"', self.source)
        self.assertNotIn('local port=$1 expected=', self.source)
        self.assertIn("systemctl stop cks-candidate-novnc.service", self.source)

    def test_units_are_root_owned_and_session_files_candidate_owned(self) -> None:
        root_files = (
            '"$VNC_UNIT" root root 0644',
            '"$NOVNC_UNIT" root root 0644',
        )
        candidate_files = (
            '"$VNC_XSTARTUP" "$CANDIDATE_USER" "$CANDIDATE_USER" 0755',
            '"$OPENBOX_MENU" "$CANDIDATE_USER" "$CANDIDATE_USER" 0644',
            '"$OPENBOX_AUTOSTART" "$CANDIDATE_USER" "$CANDIDATE_USER" 0755',
        )
        for ownership in (*root_files, *candidate_files):
            with self.subTest(ownership=ownership):
                self.assertIn(ownership, self.source)
        for unit in (self.vnc_unit, self.novnc_unit):
            with self.subTest(unit=unit.splitlines()[1]):
                self.assertIn("ProtectSystem=strict", unit)
                self.assertIn("NoNewPrivileges=true", unit)
                self.assertNotIn("WantedBy=graphical.target", unit)
        self.assertIn("IPAddressDeny=any", self.novnc_unit)
        self.assertIn("IPAddressAllow=localhost", self.novnc_unit)

    def test_openbox_exposes_only_the_requested_candidate_apps(self) -> None:
        for contract in (
            "exec dbus-run-session -- openbox-session",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, self.xstartup)
        for contract in (
            '<item label="Terminal">',
            "<command>/usr/bin/xterm</command>",
            '<item label="Vim">',
            "<command>/usr/bin/xterm -title Vim -e /usr/bin/vim.basic</command>",
            '<item label="NetSurf">',
            "<command>/usr/bin/netsurf-gtk</command>",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, self.openbox_menu)

    def test_replay_converges_files_and_avoids_unneeded_restart(self) -> None:
        self.assertIn("cmp -s --", self.source)
        self.assertIn("mv -fT --", self.source)
        self.assertIn("file_changed=0", self.source)
        restart_guard = re.compile(
            r"if \(\( file_changed == 1 \)\).*?systemctl restart "
            r"cks-candidate-vnc\.service.*?systemctl restart "
            r"cks-candidate-novnc\.service.*?\nfi",
            re.DOTALL,
        )
        self.assertRegex(self.source, restart_guard)
        self.assertNotIn("systemctl start cks-candidate-vnc.service", self.source)
        self.assertIn(
            "systemctl enable cks-candidate-vnc.service cks-candidate-novnc.service",
            self.source,
        )
        self.assertNotIn(">>", self.source)

    def test_failure_stops_both_services_and_display_manager_is_rejected(self) -> None:
        self.assertIn("fail_closed", self.source)
        self.assertIn("trap cleanup EXIT", self.source)
        self.assertIn("systemctl stop cks-candidate-novnc.service", self.source)
        self.assertIn("cks-candidate-vnc.service", self.source)
        self.assertIn("systemctl is-active --quiet display-manager.service", self.source)
        self.assertIn("systemctl is-enabled --quiet display-manager.service", self.source)
        self.assertIn("display manager must not be active or enabled", self.source)


if __name__ == "__main__":
    unittest.main()
