import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "infra" / "provision" / "candidate"
INVENTORY = ROOT / "infra" / "inventory.json"
ALIASES = {"cks3477", "cks8930", "cks5608", "cks2546", "cks7262", "cks4024"}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class CandidateProvisionContractTests(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def run_cmd(argv, *, input_bytes=None, env=None, cwd=None, check=False):
        return subprocess.run(
            argv,
            input=input_bytes,
            capture_output=True,
            env=env,
            cwd=cwd,
            check=check,
        )

    @staticmethod
    def candidate_env(home: Path):
        return {
            **os.environ,
            "HOME": str(home),
            "CKS_CANDIDATE_TEST_USER": os.environ.get("USER", "test-user"),
        }

    def test_all_candidate_operations_are_strict_static_shell(self):
        expected = {
            "configure-workstation.sh",
            "configure-home.sh",
            "configure-node.sh",
            "export-public-key.sh",
            "install-ssh-access.sh",
            "export-csr.sh",
            "install-kubeconfig.sh",
            "install-tools.sh",
            "doctor.sh",
            "check-node.sh",
        }
        self.assertTrue(CANDIDATE.is_dir())
        self.assertTrue(expected.issubset({path.name for path in CANDIDATE.glob("*.sh")}))
        for path in CANDIDATE.glob("*.sh"):
            with self.subTest(path=path.name):
                contents = read(path)
                self.assertTrue(contents.startswith("#!/usr/bin/env bash\n"))
                self.assertIn("set -Eeuo pipefail", contents)
                self.assertIn("IFS=$'\\n\\t'", contents)
                self.assertIn(
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    contents,
                )
                self.assertNotIn("eval ", contents)
                self.run_cmd(["/bin/bash", "-n", str(path)], check=True)

    def test_candidate_tool_manifest_is_exact_and_digest_pinned(self):
        values = {}
        for line in read(CANDIDATE / "tools.env").splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                values[key] = value
        self.assertEqual(values["KUBECTL_VERSION"], "1.35.6")
        self.assertEqual(values["TRIVY_VERSION"], "0.72.0")
        self.assertEqual(values["YQ_VERSION"], "4.53.2")
        for name in ("KUBECTL", "TRIVY", "YQ"):
            self.assertRegex(values[f"{name}_URL"], r"^https://")
            self.assertRegex(values[f"{name}_SHA256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            values["KUBECTL_SHA256"],
            "c0f97f31c9ddc22d4951d543a1a7125a9af4b31e895ad4aa99899c4ba2a6ff0b",
        )
        self.assertEqual(
            values["TRIVY_SHA256"],
            "2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467",
        )
        self.assertEqual(
            values["YQ_SHA256"],
            "03061b2a50c7a498de2bbb92d7cb078ce433011f085a4994117c2726be4106ea",
        )

        installer = read(CANDIDATE / "install-tools.sh")
        for tool in (
            "kubectl",
            "trivy",
            "yq",
            "jq",
            "curl",
            "wget",
            "openssl",
            "ssh",
            "vim",
            "less",
            "bash-completion",
        ):
            self.assertIn(tool, installer)
        self.assertIn("sha256sum --check --status", installer)
        self.assertIn("mktemp -d", installer)
        self.assertNotIn("infra/versions.json", installer)

    def test_inventory_maps_every_original_alias_to_semantic_roles(self):
        inventory = json.loads(read(INVENTORY))
        self.assertEqual(inventory["schema"], 1)
        self.assertEqual(
            set(inventory["roles"]),
            {"candidate", "control-plane", "worker1", "worker2"},
        )
        self.assertEqual(set(inventory["aliases"]), ALIASES)
        expected = {
            "cks3477": {"01": "candidate", "17": "control-plane"},
            "cks8930": {"02": "candidate", "03": "control-plane", "13": "control-plane"},
            "cks5608": {"04": "worker1", "07": "worker1", "16": "worker1"},
            "cks2546": {"06": "worker2", "11": "worker2", "15": "worker2"},
            "cks7262": {
                "05": "control-plane",
                "09": "worker1",
                "10": "worker1",
                "14": "control-plane",
            },
            "cks4024": {"08": "worker2", "12": "control-plane"},
        }
        for alias, scenario_roles in expected.items():
            entry = inventory["aliases"][alias]
            self.assertIn(entry["default_role"], set(scenario_roles.values()))
            self.assertEqual(entry["scenario_roles"], scenario_roles)

    def test_workstation_and_node_account_modes_are_explicit(self):
        workstation = read(CANDIDATE / "configure-workstation.sh")
        self.assertIn("useradd", workstation)
        self.assertIn("passwd --lock", workstation)
        self.assertIn("assert_candidate_has_no_sudo", workstation)
        self.assertIn("configure-home.sh", workstation)
        self.assertIn('runuser -u "$CANDIDATE_USER"', workstation)
        self.assertNotIn("chown ", workstation)
        self.assertNotIn("NOPASSWD", workstation)

        home = read(CANDIDATE / "configure-home.sh")
        self.assertIn("ssh-keygen -q -t ed25519", home)
        self.assertIn("LEARNER_KEY_NAME", home)
        self.assertIn('[[ ! -L "$ssh_dir" ]]', home)
        self.assertIn("require_candidate_user", home)

        node = read(CANDIDATE / "configure-node.sh")
        self.assertIn("read_exact_public_key", node)
        self.assertIn('runuser -u "$CANDIDATE_USER"', node)
        self.assertIn('[[ ! -L "$ssh_dir" ]]', node)
        self.assertIn("NOPASSWD: ALL", node)
        self.assertIn("passwd --lock", node)
        self.assertIn("AuthenticationMethods publickey", node)
        self.assertIn("PasswordAuthentication no", node)
        self.assertIn("KbdInteractiveAuthentication no", node)
        self.assertIn("AllowTcpForwarding no", node)
        self.assertIn("AllowAgentForwarding no", node)
        self.assertIn("X11Forwarding no", node)
        self.assertIn("PermitTunnel no", node)
        self.assertIn("PermitUserRC no", node)
        self.assertIn("cks-simulator-host-ed25519_key", node)
        self.assertIn("ssh-keygen -q -t ed25519", node)
        self.assertIn("restore_persistent_host_key", node)
        self.assertIn("sshd -t", node)
        self.assertIn("systemctl reload ssh", node)
        self.assertIn("systemctl is-active --quiet ssh", node)
        self.assertNotIn("if (( sshd_changed", node)

    def test_persistent_host_key_restoration_is_behavioral_and_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            persistent = root / "persistent"
            active = root / "active"
            for path, comment in ((persistent, "persistent"), (active, "rotated")):
                self.run_cmd(
                    [
                        "ssh-keygen",
                        "-q",
                        "-t",
                        "ed25519",
                        "-N",
                        "",
                        "-C",
                        comment,
                        "-f",
                        str(path),
                    ],
                    check=True,
                )
            os.chmod(persistent.with_suffix(".pub"), 0o600)
            original_private = persistent.read_bytes()
            original_public = persistent.with_suffix(".pub").read_bytes()
            command = (
                f'source "{CANDIDATE / "lib.sh"}"; '
                f'if ! restore_persistent_host_key "{persistent}" "{active}"; then exit 10; fi; '
                f'cmp -s -- "{persistent}" "{active}"; '
                f'cmp -s -- "{persistent}.pub" "{active}.pub"; '
                f'if restore_persistent_host_key "{persistent}" "{active}"; then exit 11; fi'
            )
            completed = self.run_cmd(["/bin/bash", "-c", command])
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(active.read_bytes(), original_private)
            self.assertEqual(active.with_suffix(".pub").read_bytes(), original_public)
            self.assertEqual(active.stat().st_mode & 0o777, 0o600)
            self.assertEqual(active.with_suffix(".pub").stat().st_mode & 0o777, 0o644)

    def test_persistent_host_key_restoration_fails_closed(self):
        cases = ("unsafe-mode", "private-symlink", "public-symlink", "keypair-mismatch")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                persistent = root / "persistent"
                active = root / "active"
                self.run_cmd(
                    ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(persistent)],
                    check=True,
                )
                os.chmod(persistent.with_suffix(".pub"), 0o600)
                active.write_bytes(b"active-private-sentinel\n")
                active.with_suffix(".pub").write_bytes(b"active-public-sentinel\n")
                protected = root / "protected"
                protected.write_bytes(b"protected-sentinel\n")

                if case == "unsafe-mode":
                    os.chmod(persistent, 0o644)
                elif case == "private-symlink":
                    active.unlink()
                    active.symlink_to(protected)
                elif case == "public-symlink":
                    active.with_suffix(".pub").unlink()
                    active.with_suffix(".pub").symlink_to(protected)
                else:
                    replacement = root / "replacement"
                    self.run_cmd(
                        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(replacement)],
                        check=True,
                    )
                    persistent.with_suffix(".pub").write_bytes(replacement.with_suffix(".pub").read_bytes())
                    os.chmod(persistent.with_suffix(".pub"), 0o600)

                command = (
                    f'source "{CANDIDATE / "lib.sh"}"; '
                    f'if restore_persistent_host_key "{persistent}" "{active}"; then '
                    "status=0; else status=$?; fi; (( status == 2 ))"
                )
                completed = self.run_cmd(["/bin/bash", "-c", command])
                self.assertEqual(completed.returncode, 0, completed.stderr.decode())
                self.assertEqual(protected.read_bytes(), b"protected-sentinel\n")
                if not active.is_symlink():
                    self.assertEqual(active.read_bytes(), b"active-private-sentinel\n")
                if not active.with_suffix(".pub").is_symlink():
                    self.assertEqual(active.with_suffix(".pub").read_bytes(), b"active-public-sentinel\n")

    def test_node_configuration_exits_before_ssh_reload_when_key_restore_errors(self):
        node = read(CANDIDATE / "configure-node.sh")
        guard = '(( restore_status == 1 )) || exit "$restore_status"'
        self.assertIn(guard, node)
        self.assertLess(node.index(guard), node.index("systemctl reload ssh"))

    def test_public_key_export_is_one_bounded_line_and_never_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            private = ssh_dir / "cks-learner-ed25519"
            self.run_cmd(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "candidate@cks-simulator",
                    "-f",
                    str(private),
                ],
                check=True,
            )
            completed = self.run_cmd(
                ["/bin/bash", str(CANDIDATE / "export-public-key.sh")],
                env=self.candidate_env(home),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertRegex(
                completed.stdout.decode(),
                r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2} candidate@cks-simulator\n$",
            )
            self.assertLessEqual(len(completed.stdout), 512)
            self.assertNotIn(b"PRIVATE", completed.stdout)
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)

    def test_candidate_home_rejects_ssh_symlink_without_mutating_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            target = root / "protected"
            home.mkdir(mode=0o700)
            target.mkdir(mode=0o755)
            marker = target / "marker"
            marker.write_text("unchanged", encoding="utf-8")
            (home / ".ssh").symlink_to(target, target_is_directory=True)
            before_mode = target.stat().st_mode & 0o777

            completed = self.run_cmd(
                ["/bin/bash", str(CANDIDATE / "configure-home.sh")],
                env=self.candidate_env(home),
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("unsafe candidate SSH directory", completed.stderr.decode())
            self.assertEqual(target.stat().st_mode & 0o777, before_mode)
            self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged")

    def test_node_public_key_parser_rejects_trailing_and_non_ed25519_input(self):
        valid = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIApkXqgu90BofvkPU5lhX7CoA4m8gWwxiBJm0vX2uWBR candidate@cks-simulator\n"
        command = (
            f'source "{CANDIDATE / "lib.sh"}"; '
            "read_exact_public_key >/dev/null"
        )
        accepted = self.run_cmd(["/bin/bash", "-c", command], input_bytes=valid)
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
        invalid = (
            valid.rstrip(b"\n"),
            valid + b"extra\n",
            valid.replace(b"ssh-ed25519", b"ssh-rsa"),
            valid.replace(b"candidate@cks-simulator", b"other"),
            b"x" * 513,
        )
        for payload in invalid:
            with self.subTest(payload=payload[:30]):
                rejected = self.run_cmd(["/bin/bash", "-c", command], input_bytes=payload)
                self.assertNotEqual(rejected.returncode, 0)

    def test_ssh_access_install_is_exact_strict_and_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            key = "AAAAC3NzaC1lZDI1NTE5AAAAIApkXqgu90BofvkPU5lhX7CoA4m8gWwxiBJm0vX2uWBR"
            inventory = json.loads(read(INVENTORY))
            aliases = {}
            for index, alias in enumerate(sorted(ALIASES), start=10):
                aliases[alias] = {
                    "role": inventory["aliases"][alias]["default_role"],
                    "host": f"192.0.2.{index}",
                    "host_key": f"ssh-ed25519 {key}",
                }
            payload = (json.dumps({"schema": 1, "aliases": aliases}) + "\n").encode()
            env = self.candidate_env(home)
            command = ["/bin/bash", str(CANDIDATE / "install-ssh-access.sh")]
            first = self.run_cmd(command, input_bytes=payload, env=env)
            self.assertEqual(first.returncode, 0, first.stderr.decode())
            config = read(home / ".ssh" / "config")
            known_hosts = read(home / ".ssh" / "known_hosts")
            first_hashes = (hashlib.sha256(config.encode()).digest(), hashlib.sha256(known_hosts.encode()).digest())
            second = self.run_cmd(command, input_bytes=payload, env=env)
            self.assertEqual(second.returncode, 0, second.stderr.decode())
            self.assertEqual(
                first_hashes,
                (
                    hashlib.sha256((home / ".ssh" / "config").read_bytes()).digest(),
                    hashlib.sha256((home / ".ssh" / "known_hosts").read_bytes()).digest(),
                ),
            )
            self.assertEqual({line.split()[0] for line in known_hosts.splitlines()}, ALIASES)
            for directive in (
                "StrictHostKeyChecking yes",
                "UpdateHostKeys no",
                "IdentitiesOnly yes",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "PubkeyAuthentication yes",
                "ForwardAgent no",
                "ForwardX11 no",
                "ClearAllForwardings yes",
            ):
                self.assertEqual(config.count(directive), len(ALIASES))
            self.assertNotIn("Host *", config)
            self.assertNotIn("ssh-keyscan", config)

    def test_ssh_access_rejects_missing_extra_invalid_or_oversized_manifests(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            env = self.candidate_env(home)
            command = ["/bin/bash", str(CANDIDATE / "install-ssh-access.sh")]
            key = "AAAAC3NzaC1lZDI1NTE5AAAAIApkXqgu90BofvkPU5lhX7CoA4m8gWwxiBJm0vX2uWBR"
            valid_alias = {
                "role": "control-plane",
                "host": "192.0.2.10",
                "host_key": f"ssh-ed25519 {key}",
            }
            payloads = (
                b"{}\n",
                (json.dumps({"schema": 1, "aliases": {"extra": valid_alias}}) + "\n").encode(),
                b"{" + b"x" * 32768,
                b'{"schema":1}\ntrailing',
            )
            for payload in payloads:
                with self.subTest(size=len(payload)):
                    rejected = self.run_cmd(command, input_bytes=payload, env=env)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertFalse((home / ".ssh" / "config").exists())

    @unittest.skipUnless(shutil.which("openssl") and shutil.which("kubectl"), "openssl and kubectl required")
    def test_candidate_csr_and_signed_kubeconfig_stay_candidate_side(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "candidate"
            home.mkdir()
            env = self.candidate_env(home)
            export = ["/bin/bash", str(CANDIDATE / "export-csr.sh")]
            first_csr = self.run_cmd(export, env=env)
            self.assertEqual(first_csr.returncode, 0, first_csr.stderr.decode())
            self.assertTrue(first_csr.stdout.startswith(b"-----BEGIN CERTIFICATE REQUEST-----\n"))
            self.assertTrue(first_csr.stdout.endswith(b"-----END CERTIFICATE REQUEST-----\n"))
            self.assertNotIn(b"PRIVATE", first_csr.stdout)
            private_key = home / ".kube" / "candidate.key"
            self.assertTrue(private_key.is_file())
            self.assertEqual(private_key.stat().st_mode & 0o777, 0o600)
            second_csr = self.run_cmd(export, env=env)
            self.assertEqual(second_csr.stdout, first_csr.stdout)

            ca_key = root / "ca.key"
            ca_cert = root / "ca.crt"
            signed_cert = root / "candidate.crt"
            csr = home / ".kube" / "candidate.csr"
            self.run_cmd(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(ca_key)],
                check=True,
            )
            self.run_cmd(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    str(ca_key),
                    "-subj",
                    "/CN=cks-test-ca",
                    "-days",
                    "2",
                    "-out",
                    str(ca_cert),
                ],
                check=True,
            )
            self.run_cmd(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(csr),
                    "-CA",
                    str(ca_cert),
                    "-CAkey",
                    str(ca_key),
                    "-CAcreateserial",
                    "-days",
                    "1",
                    "-out",
                    str(signed_cert),
                ],
                check=True,
            )
            payload = {
                "schema": 1,
                "cluster_name": "cks-simulator",
                "server": "https://192.0.2.10:6443",
                "certificate_authority_data": base64.b64encode(ca_cert.read_bytes()).decode(),
                "client_certificate_data": base64.b64encode(signed_cert.read_bytes()).decode(),
            }
            encoded = (json.dumps(payload) + "\n").encode()
            install = ["/bin/bash", str(CANDIDATE / "install-kubeconfig.sh")]
            completed = self.run_cmd(install, input_bytes=encoded, env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(completed.stdout, b"candidate kubeconfig installed\n")
            kubeconfig = home / ".kube" / "config"
            contents = read(kubeconfig)
            self.assertIn(str(home / ".kube" / "candidate.key"), contents)
            self.assertIn(str(home / ".kube" / "candidate.crt"), contents)
            self.assertIn(str(home / ".kube" / "ca.crt"), contents)
            self.assertNotIn("client-key-data", contents)
            self.assertNotIn("client-certificate-data", contents)
            self.assertNotIn("certificate-authority-data", contents)
            self.assertNotIn("PRIVATE", contents)
            digest = hashlib.sha256(kubeconfig.read_bytes()).digest()
            replay = self.run_cmd(install, input_bytes=encoded, env=env)
            self.assertEqual(replay.returncode, 0, replay.stderr.decode())
            self.assertEqual(hashlib.sha256(kubeconfig.read_bytes()).digest(), digest)

    def test_kubeconfig_input_is_bounded_public_only_and_fail_closed(self):
        contents = read(CANDIDATE / "install-kubeconfig.sh")
        self.assertIn("65537", contents)
        self.assertIn("PRIVATE KEY", contents)
        self.assertIn("openssl verify", contents)
        self.assertIn("candidate.key", contents)
        self.assertIn("candidate.crt", contents)
        self.assertIn("ca.crt", contents)
        self.assertNotIn("client-key-data", contents)
        self.assertNotIn("--client-key-data", contents)

    def test_exact_doctor_and_node_checks_cover_modes_access_credentials_and_tools(self):
        doctor = read(CANDIDATE / "doctor.sh")
        self.assertIn("assert_candidate_has_no_sudo", doctor)
        self.assertIn("ssh -G", doctor)
        self.assertIn("StrictHostKeyChecking", doctor)
        self.assertIn("candidate.key", doctor)
        self.assertIn("candidate.crt", doctor)
        self.assertIn("kubectl version", doctor)
        for version in ("1.35.6", "0.72.0", "4.53.2"):
            self.assertIn(version, doctor)
        for command in ("jq", "curl", "wget", "openssl", "ssh", "vim", "less"):
            self.assertIn(command, doctor)
        self.assertNotIn("config view --raw", doctor)

        node = read(CANDIDATE / "check-node.sh")
        self.assertIn("read_exact_public_key", node)
        self.assertIn("assert_candidate_password_locked", node)
        self.assertIn("sudo -n true", node)
        self.assertIn("sshd -T", node)
        self.assertIn("cks-simulator-host-ed25519_key", node)
        self.assertIn('cmp -s -- "$persistent_host_key" "$active_host_key"', node)
        for setting in (
            "authenticationmethods publickey",
            "passwordauthentication no",
            "kbdinteractiveauthentication no",
            "allowtcpforwarding no",
            "allowagentforwarding no",
            "x11forwarding no",
        ):
            self.assertIn(setting, node)

    def test_candidate_scripts_never_emit_or_import_forbidden_trust_material(self):
        combined = "\n".join(read(path) for path in CANDIDATE.glob("*"))
        for forbidden in (
            "BEGIN OPENSSH PRIVATE KEY",
            "host project mount",
            "operator state",
            "reference solution",
            "grader implementation",
        ):
            self.assertNotIn(forbidden, combined)
        for script_name in ("export-public-key.sh", "export-csr.sh"):
            script = read(CANDIDATE / script_name)
            self.assertNotRegex(script, r"cat .*candidate\.key")
            self.assertNotRegex(script, r"cat .*cks-learner-ed25519(?:[\"']|$)")


if __name__ == "__main__":
    unittest.main()
