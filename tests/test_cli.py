import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cks_simulator import cli as simulator
from cks_simulator.grading import evaluate_rule


ROOT = Path(__file__).resolve().parents[1]


def cli(*args, state=None):
    env = os.environ.copy()
    if state:
        env["CKS_STATE_DIR"] = str(state)
    return subprocess.run(
        [sys.executable, "-m", "cks_simulator", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )


def seed_tls_fixture(destination):
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "tls.crt").write_text("test certificate", encoding="utf-8")
    (destination / "tls.key").write_text("test key", encoding="utf-8")
    os.chmod(destination / "tls.key", 0o600)


def invoke_main(*args):
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        returncode = simulator.main(list(args))
    return returncode, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def test_catalog_has_all_seventeen_scenarios(self):
        result = cli("list", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        catalog = json.loads(result.stdout)
        self.assertEqual(len(catalog), 17)
        self.assertEqual([item["id"] for item in catalog], [f"{n:02d}" for n in range(1, 18)])
        self.assertTrue(all("full" not in item for item in catalog))
        self.assertTrue(simulator.LIVE_FIXTURE_IDS.issubset({item["id"] for item in catalog}))
        for identifier in simulator.LIVE_FIXTURE_IDS:
            self.assertTrue((ROOT / "scenarios" / "fixtures" / identifier / "resources.json").is_file())

    def test_help_is_available(self):
        result = cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("scenario", result.stdout)

    def test_doctor_json_is_machine_readable(self):
        result = cli("doctor", "--json")
        self.assertIn(result.returncode, (0, 1))
        payload = json.loads(result.stdout)
        self.assertIn("checks", payload)
        self.assertTrue(any(check["name"] == "kind (pinned fallback)" for check in payload["checks"]))

    def test_quick_tool_resolution_ignores_hostile_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            hostile = Path(temporary)
            for name in ("kind", "docker", "kubectl", "openssl", "curl", "shasum", "awk"):
                candidate = hostile / name
                candidate.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
                os.chmod(candidate, 0o700)
            overrides = {
                "PATH": str(hostile),
                "HOME": str(hostile),
                "DOCKER_HOST": "tcp://attacker.invalid:2375",
                "PYTHONPATH": str(hostile),
                "CKS_KIND_BIN": "",
                "DOCKER_BIN": "",
                "KUBECTL_BIN": "",
                "OPENSSL_BIN": "",
                "CURL_BIN": "",
                "CHECKSUM_BIN": "",
                "AWK_BIN": "",
            }
            with patch.dict(os.environ, overrides, clear=False):
                resolved = [
                    simulator.global_kind(),
                    simulator.docker_command(),
                    simulator.kubectl_command(),
                    simulator.openssl_command(),
                    simulator.curl_command(),
                    simulator.checksum_command(),
                    simulator.awk_command(),
                ]
            for value in resolved:
                if value is not None:
                    self.assertTrue(Path(value).is_absolute())
                    self.assertNotEqual(Path(value).parent, hostile)

    def test_relative_and_symlinked_tool_overrides_are_rejected(self):
        resolvers = (
            ("CKS_KIND_BIN", simulator.kind_command),
            ("DOCKER_BIN", simulator.docker_command),
            ("KUBECTL_BIN", simulator.kubectl_command),
            ("OPENSSL_BIN", simulator.openssl_command),
            ("CURL_BIN", simulator.curl_command),
            ("CHECKSUM_BIN", simulator.checksum_command),
            ("AWK_BIN", simulator.awk_command),
        )
        for variable, resolver in resolvers:
            with self.subTest(variable=variable), patch.dict(
                os.environ, {variable: "relative-tool"}, clear=False
            ):
                with self.assertRaisesRegex(ValueError, "absolute regular executable"):
                    resolver()

        with tempfile.TemporaryDirectory() as temporary:
            linked = Path(temporary) / "docker"
            linked.symlink_to(Path(sys.executable).resolve())
            with patch.dict(os.environ, {"DOCKER_BIN": str(linked)}, clear=False):
                with self.assertRaisesRegex(ValueError, "absolute regular executable"):
                    simulator.docker_command()

    def test_bounded_runner_does_not_inherit_hostile_provider_environment(self):
        python = str(Path(sys.executable).resolve())
        script = (
            "import json,os; "
            "print(json.dumps({k:os.environ.get(k) for k in "
            "['PATH','HOME','DOCKER_HOST','PYTHONPATH']}))"
        )
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ,
            {
                "PATH": temporary,
                "HOME": temporary,
                "DOCKER_HOST": "tcp://attacker.invalid:2375",
                "PYTHONPATH": temporary,
            },
            clear=False,
        ):
            result = simulator.command_output([python, "-c", script], announce=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertNotEqual(observed["HOME"], temporary)
        self.assertIsNone(observed["DOCKER_HOST"])
        self.assertIsNone(observed["PYTHONPATH"])

    def test_bounded_runner_caps_floods_and_escapes_control_output(self):
        python = str(Path(sys.executable).resolve())
        script = (
            "import sys; "
            "sys.stdout.write('\\x1b[31m' + 'x' * 2000000); "
            "sys.stderr.write('\\x00bad\\x1b[0m' + 'y' * 2000000)"
        )
        result = simulator.command_output([python, "-c", script], announce=False)
        self.assertEqual(result.returncode, 0)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), simulator.PROCESS_OUTPUT_LIMIT)
        self.assertLessEqual(len(result.stderr.encode("utf-8")), simulator.PROCESS_OUTPUT_LIMIT)
        self.assertNotIn("\x1b", result.stdout + result.stderr)
        self.assertNotIn("\x00", result.stdout + result.stderr)
        self.assertIn("\\x1b", result.stdout + result.stderr)
        self.assertIn("\\x00", result.stdout + result.stderr)

    def test_announced_commands_and_output_escape_controls(self):
        python = str(Path(sys.executable).resolve())
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = simulator.run_command(
                [python, "-c", "import sys; print('\\x1b[31mout'); sys.stderr.write('\\x00err')", "\x1bargument"],
                check=False,
                announce=True,
            )
        self.assertEqual(result.returncode, 0)
        rendered = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x00", rendered)
        self.assertIn("\\x1b", rendered)
        self.assertIn("\\x00", rendered)

    def test_shell_preserves_interactive_tty_with_trusted_minimal_environment(self):
        docker = "/Applications/Docker.app/Contents/Resources/bin/docker"
        completed = subprocess.CompletedProcess([], 0, stdout=None, stderr=None)
        args = SimpleNamespace(name="shell-lab", node=None, shell=None)
        with (
            patch.dict(
                os.environ,
                {
                    "PATH": "/tmp/hostile",
                    "HOME": "/tmp/hostile-home",
                    "DOCKER_HOST": "tcp://attacker.invalid:2375",
                    "PYTHONPATH": "/tmp/hostile-python",
                },
                clear=False,
            ),
            patch.object(simulator, "docker_command", return_value=docker),
            patch.object(simulator, "run_command") as bounded_mock,
            patch.object(simulator.subprocess, "run", return_value=completed) as direct,
            redirect_stdout(StringIO()),
        ):
            self.assertEqual(simulator.open_shell(args), 0)
        bounded_mock.assert_not_called()
        direct.assert_called_once()
        command = direct.call_args.args[0]
        options = direct.call_args.kwargs
        self.assertEqual(
            command,
            [docker, "exec", "-it", "shell-lab-control-plane", "/bin/bash"],
        )
        self.assertTrue(Path(command[0]).is_absolute())
        self.assertFalse(options["check"])
        self.assertNotIn("capture_output", options)
        self.assertNotIn("stdin", options)
        self.assertEqual(options["env"]["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertNotEqual(options["env"]["HOME"], "/tmp/hostile-home")
        self.assertNotIn("DOCKER_HOST", options["env"])
        self.assertNotIn("PYTHONPATH", options["env"])

    def test_omitted_tier_and_explicit_quick_have_identical_dispatch_contract(self):
        cases = [
            ("doctor", ("doctor",), ("doctor", "--tier", "quick")),
            ("provision", ("provision", "--name", "parity-lab"), ("provision", "--name", "parity-lab", "--tier", "quick")),
            ("delete", ("delete", "--name", "parity-lab"), ("delete", "--name", "parity-lab", "--tier", "quick")),
            ("reset_cluster", ("reset", "--name", "parity-lab"), ("reset", "--name", "parity-lab", "--tier", "quick")),
            ("e2e", ("e2e", "--name", "parity-lab"), ("e2e", "--name", "parity-lab", "--tier", "quick")),
        ]

        def quick_handler(*handler_args):
            namespace = next((value for value in handler_args if isinstance(value, argparse.Namespace)), None)
            if namespace is not None and getattr(namespace, "name", None):
                name = simulator.cluster_name(namespace)
                print(f"state={simulator.metadata_path(name)}")
            else:
                print("quick output")
            print("quick warning", file=sys.stderr)
            return 7

        for handler, omitted_args, explicit_args in cases:
            with self.subTest(command=omitted_args[0]), patch.object(simulator, handler, side_effect=quick_handler):
                self.assertEqual(invoke_main(*omitted_args), invoke_main(*explicit_args))

    def test_full_tier_routes_only_through_the_integration_seam(self):
        with (
            patch.object(simulator, "dispatch_full_tier", return_value=9) as full_dispatch,
            patch.object(simulator, "provision") as quick_provision,
        ):
            result = invoke_main("provision", "--name", "full-lab", "--tier", "full")
        self.assertEqual(result, (9, "", ""))
        full_dispatch.assert_called_once()
        quick_provision.assert_not_called()

    def test_grade_keeps_quick_default_and_full_routes_through_integration_seam(self):
        with patch.object(simulator, "grade_artifacts", return_value=7) as quick_grade:
            omitted = invoke_main("grade", "04", "--root", "/tmp/artifacts")
            explicit = invoke_main(
                "grade", "04", "--root", "/tmp/artifacts", "--tier", "quick"
            )
        self.assertEqual(omitted, explicit)
        self.assertEqual(quick_grade.call_count, 2)

        with (
            patch.object(simulator, "dispatch_full_tier", return_value=9) as full_dispatch,
            patch.object(simulator, "grade_artifacts") as quick_grade,
        ):
            result = invoke_main(
                "grade", "04", "--name", "full-lab", "--tier", "full"
            )
        self.assertEqual(result, (9, "", ""))
        full_dispatch.assert_called_once()
        quick_grade.assert_not_called()

    def test_scenario_prepare_restore_require_explicit_full_tier(self):
        for operation in ("prepare", "restore"):
            with self.subTest(operation=operation):
                quick = invoke_main("scenario", operation, "04", "--json")
                self.assertEqual(quick[0], 2)
                payload = json.loads(quick[1])
                self.assertEqual(payload["error"]["code"], "quick_command_not_available")

                with patch.object(
                    simulator, "dispatch_full_tier", return_value=8
                ) as full_dispatch:
                    full = invoke_main(
                        "scenario",
                        operation,
                        "04",
                        "--name",
                        "full-lab",
                        "--tier",
                        "full",
                    )
                self.assertEqual(full, (8, "", ""))
                full_dispatch.assert_called_once()

    def test_unknown_full_scenario_refuses_with_structured_error_without_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            result = cli(
                "scenario",
                "prepare",
                "18",
                "--tier",
                "full",
                "--json",
                state=state,
            )
            self.assertEqual(result.returncode, 2)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "error")
            self.assertIn("unknown full scenario", payload["error"]["message"])
            self.assertEqual(list(state.iterdir()), [])

    def test_tier_specific_safety_options_are_not_silently_ignored(self):
        cases = (
            ("doctor", "--tier", "quick", "--lab"),
            ("doctor", "--tier", "quick", "--memory-profile", "low"),
            ("grade", "04", "--tier", "quick", "--name", "full-lab"),
            ("grade", "04", "--tier", "full", "--root", "/tmp/artifacts"),
            ("e2e", "--tier", "quick", "--destroy-rebuild"),
            (
                "delete",
                "--tier",
                "quick",
                "--name",
                "quick-lab",
                "--break-glass",
                "--expected-lab-id",
                "00000000-0000-4000-8000-000000000000",
            ),
        )
        for args in cases:
            with self.subTest(args=args):
                returncode, _stdout, stderr = invoke_main(*args)
                self.assertEqual(returncode, 2)
                self.assertIn("unsupported_tier_option", stderr)

    def test_unimplemented_full_tier_commands_fail_closed_without_mutating_quick_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            commands = ("reset",)
            for command in commands:
                with self.subTest(command=command):
                    human = cli(command, "--tier", "full", state=state)
                    machine = cli(command, "--tier", "full", "--json", state=state)
                    self.assertEqual(human.returncode, 2)
                    self.assertEqual(machine.returncode, 2)
                    payload = json.loads(machine.stdout)
                    self.assertEqual(payload["status"], "error")
                    self.assertEqual(payload["error"]["code"], "full_command_not_available")
                    self.assertEqual(payload["error"]["tier"], "full")
                    self.assertEqual(payload["error"]["command"], command)
                    self.assertIn(payload["error"]["code"], human.stderr)
                    self.assertIn(payload["error"]["message"], human.stderr)
                    self.assertEqual(list(state.iterdir()), [])

    def test_hostile_tier_values_are_structured_and_do_not_dispatch(self):
        hostile_values = ("FULL", "../full", "full;quick", "full\nquick", "-full", "f" * 256)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            for value in hostile_values:
                with self.subTest(value=value):
                    result = cli("e2e", f"--tier={value}", "--json", state=state)
                    self.assertEqual(result.returncode, 2)
                    payload = json.loads(result.stdout)
                    self.assertEqual(payload["error"]["code"], "invalid_tier")
                    self.assertEqual(payload["error"]["tier"], value)
                    self.assertEqual(list(state.iterdir()), [])

    def test_hostile_names_are_rejected_before_quick_state_or_commands(self):
        hostile_names = ("../owned", "-other", "bad;touch-pwned", "bad\nname", "UPPER", "x" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            for command in ("provision", "delete", "reset", "e2e"):
                for name in hostile_names:
                    with self.subTest(command=command, name=name):
                        result = cli(command, f"--name={name}", "--tier", "quick", "--json", state=state)
                        self.assertEqual(result.returncode, 2)
                        payload = json.loads(result.stdout)
                        self.assertEqual(payload["status"], "error")
                        self.assertEqual(payload["error"]["type"], "ValueError")
                        self.assertIn("cluster name", payload["error"]["message"])
                        self.assertEqual(list(state.iterdir()), [])

    def test_quick_provision_json_is_one_document_on_success_and_failure(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"CKS_STATE_DIR": temporary}
        ):
            with (
                patch.object(simulator, "cluster_exists", return_value=True),
                patch.object(simulator, "state_is_owned", return_value=True),
                patch.object(simulator, "cluster_healthy", return_value=True),
            ):
                code, stdout, stderr = invoke_main(
                    "provision", "--name", "json-lab", "--json"
                )
            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            payload = json.loads(stdout)
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["command"], "provision")
            self.assertEqual(payload["name"], "json-lab")
            self.assertEqual(stdout.count("\n}"), 1)

            with (
                patch.object(simulator, "cluster_exists", return_value=True),
                patch.object(simulator, "state_is_owned", return_value=False),
            ):
                code, stdout, stderr = invoke_main(
                    "provision", "--name", "json-lab", "--json"
                )
            self.assertEqual(code, 1)
            self.assertEqual(stderr, "")
            payload = json.loads(stdout)
            self.assertEqual(payload["status"], "error")
            self.assertEqual(payload["command"], "provision")
            self.assertIn("unowned", payload["message"])
            self.assertEqual(stdout.count("\n}"), 1)

    def test_quick_delete_and_reset_json_emit_only_their_own_result(self):
        deleted = simulator.QuickLifecycleResult(
            command="delete",
            name="json-lab",
            returncode=0,
            message="cluster deleted",
        )
        provisioned = simulator.QuickLifecycleResult(
            command="provision",
            name="json-lab",
            returncode=0,
            message="cluster ready",
        )
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"CKS_STATE_DIR": temporary}
        ):
            with patch.object(simulator, "_delete_quick", return_value=deleted):
                code, stdout, stderr = invoke_main(
                    "delete", "--name", "json-lab", "--json"
                )
            self.assertEqual((code, stderr), (0, ""))
            payload = json.loads(stdout)
            self.assertEqual((payload["command"], payload["status"]), ("delete", "ok"))
            self.assertEqual(stdout.count("\n}"), 1)

            with (
                patch.object(simulator, "_delete_quick", return_value=deleted),
                patch.object(simulator, "_provision_quick", return_value=provisioned),
            ):
                code, stdout, stderr = invoke_main(
                    "reset", "--name", "json-lab", "--json"
                )
            self.assertEqual((code, stderr), (0, ""))
            payload = json.loads(stdout)
            self.assertEqual((payload["command"], payload["status"]), ("reset", "ok"))
            self.assertEqual(stdout.count("\n}"), 1)

    def test_quick_state_rejects_symlinked_root_and_state_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            real_root = base / "real-state"
            real_root.mkdir(mode=0o700)
            linked_root = base / "linked-state"
            linked_root.symlink_to(real_root, target_is_directory=True)
            with patch.object(simulator, "state_dir", return_value=linked_root):
                with self.assertRaisesRegex(RuntimeError, "state root"):
                    simulator._write_state_json("cluster-safe.json", {"safe": True})
            self.assertEqual(list(real_root.iterdir()), [])

            victim = base / "victim"
            victim.write_text("do not replace", encoding="utf-8")
            state = base / "state"
            state.mkdir(mode=0o700)
            (state / "cluster-linked.json").symlink_to(victim)
            (state / "kubeconfig-linked").symlink_to(victim)
            with patch.object(simulator, "state_dir", return_value=state):
                with self.assertRaisesRegex(RuntimeError, "regular file"):
                    simulator._write_state_json("cluster-linked.json", {"safe": True})
                with self.assertRaisesRegex(RuntimeError, "regular file"):
                    simulator._remove_state_file("kubeconfig-linked")
            self.assertEqual(victim.read_text(encoding="utf-8"), "do not replace")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_quick_state_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            fifo = state / "cluster-fifo.json"
            os.mkfifo(fifo, 0o600)
            with patch.object(simulator, "state_dir", return_value=state):
                with self.assertRaisesRegex(RuntimeError, "regular file"):
                    simulator._write_state_json(fifo.name, {"safe": True})
                self.assertIsNone(simulator._read_state_json(fifo.name))

    def test_forged_metadata_cannot_authorize_quick_delete(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"CKS_STATE_DIR": temporary}
        ):
            state = Path(temporary)
            (state / "cluster-forged.json").write_text(
                json.dumps(
                    {
                        "cluster_name": "forged",
                        "managed_by": "cks-simulator",
                        "status": "ready",
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(state / "cluster-forged.json", 0o600)
            with (
                patch.object(simulator, "cluster_exists", return_value=True),
                patch.object(simulator, "run_command") as run_mock,
            ):
                code, stdout, stderr = invoke_main(
                    "delete", "--name", "forged", "--json"
                )
            self.assertEqual((code, stderr), (1, ""))
            payload = json.loads(stdout)
            self.assertEqual(payload["status"], "error")
            self.assertIn("unowned", payload["message"])
            run_mock.assert_not_called()

    def test_quick_ownership_requires_matching_provider_marker(self):
        container_id = "a" * 64
        identity = {
            "schema_version": 1,
            "managed_by": "cks-simulator",
            "cluster_name": "owned",
            "claim_id": "2bb5fb18-fc97-4d89-915b-55b12380fb2f",
            "container_id": container_id,
        }
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            simulator, "state_dir", return_value=Path(temporary)
        ):
            simulator._write_state_json(
                "cluster-owned.json", {**identity, "status": "ready", "image": "test"}
            )
            with patch.object(simulator, "_read_quick_marker", return_value=identity):
                self.assertTrue(simulator.state_is_owned("owned"))
            with patch.object(
                simulator,
                "_read_quick_marker",
                return_value={**identity, "container_id": "b" * 64},
            ):
                self.assertFalse(simulator.state_is_owned("owned"))

    def test_kind_control_plane_inspection_requires_exact_name_labels_and_id(self):
        valid = {
            "Id": "c" * 64,
            "Name": "/exact-control-plane",
            "Config": {
                "Labels": {
                    "io.x-k8s.kind.cluster": "exact",
                    "io.x-k8s.kind.role": "control-plane",
                }
            },
        }
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps([valid]), stderr="")
        with (
            patch.object(simulator, "docker_command", return_value="docker"),
            patch.object(simulator, "command_output", return_value=completed),
        ):
            self.assertEqual(
                simulator._inspect_kind_control_plane("exact"),
                {"node": "exact-control-plane", "container_id": "c" * 64},
            )
        for mutation in (
            {**valid, "Name": "/other-control-plane"},
            {**valid, "Id": "short"},
            {
                **valid,
                "Config": {
                    "Labels": {
                        "io.x-k8s.kind.cluster": "other",
                        "io.x-k8s.kind.role": "control-plane",
                    }
                },
            },
        ):
            with (
                self.subTest(mutation=mutation),
                patch.object(simulator, "docker_command", return_value="docker"),
                patch.object(
                    simulator,
                    "command_output",
                    return_value=subprocess.CompletedProcess(
                        [], 0, stdout=json.dumps([mutation]), stderr=""
                    ),
                ),
            ):
                self.assertIsNone(simulator._inspect_kind_control_plane("exact"))

    def test_quick_provision_uses_private_pending_kubeconfig_and_atomic_publish(self):
        container_id = "d" * 64
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"CKS_STATE_DIR": temporary}
        ):
            state = Path(temporary)

            def create_cluster(command, **_kwargs):
                pending = Path(command[command.index("--kubeconfig") + 1])
                self.assertNotEqual(pending, state / "kubeconfig-atomic")
                self.assertEqual(pending.parent, state)
                pending.write_text("apiVersion: v1\n", encoding="utf-8")
                os.chmod(pending, 0o600)
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with (
                patch.object(simulator, "cluster_exists", return_value=False),
                patch.object(simulator, "run_command", side_effect=create_cluster),
                patch.object(
                    simulator,
                    "_inspect_kind_control_plane",
                    return_value={
                        "node": "atomic-control-plane",
                        "container_id": container_id,
                    },
                ),
                patch.object(simulator, "_write_quick_marker", return_value=True) as marker,
                patch.object(simulator, "kubectl_command", return_value="kubectl"),
                patch.object(
                    simulator,
                    "command_output",
                    return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
                ),
            ):
                code, stdout, stderr = invoke_main(
                    "provision", "--name", "atomic", "--json"
                )
            self.assertEqual((code, stderr), (0, ""))
            self.assertEqual(json.loads(stdout)["status"], "ok")
            kubeconfig = state / "kubeconfig-atomic"
            self.assertEqual(kubeconfig.read_text(encoding="utf-8"), "apiVersion: v1\n")
            self.assertEqual(kubeconfig.stat().st_mode & 0o777, 0o600)
            metadata = json.loads((state / "cluster-atomic.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["container_id"], container_id)
            self.assertEqual(metadata["status"], "ready")
            marker.assert_called_once()
            self.assertFalse(any(path.name.startswith(".kubeconfig-") for path in state.iterdir()))

    def test_quick_provision_does_not_follow_preplaced_kubeconfig_symlink(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"CKS_STATE_DIR": temporary}
        ):
            state = Path(temporary)
            victim = state / "victim"
            victim.write_text("keep", encoding="utf-8")
            os.chmod(victim, 0o600)
            (state / "kubeconfig-linked").symlink_to(victim)
            with patch.object(simulator, "run_command") as run_mock:
                code, stdout, stderr = invoke_main(
                    "provision", "--name", "linked", "--json"
                )
            self.assertEqual((code, stderr), (1, ""))
            self.assertEqual(json.loads(stdout)["status"], "error")
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep")
            run_mock.assert_not_called()

    def test_quick_json_subprocess_failure_does_not_leak_command_output(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"CKS_STATE_DIR": temporary}
        ):
            failure = subprocess.CalledProcessError(
                17, ["kind"], output="SHOULD-NOT-LEAK", stderr="SECRET-STDERR"
            )
            with (
                patch.object(simulator, "cluster_exists", return_value=False),
                patch.object(simulator, "run_command", side_effect=failure),
            ):
                code, stdout, stderr = invoke_main(
                    "provision", "--name", "failed", "--json"
                )
            self.assertEqual((code, stderr), (17, ""))
            payload = json.loads(stdout)
            self.assertEqual(payload["status"], "error")
            self.assertNotIn("SHOULD-NOT-LEAK", stdout)
            self.assertNotIn("SECRET-STDERR", stdout)

    def test_create_and_reset_seed_task_and_fixture_without_cluster(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            created = cli("scenario", "create", "04", state=state)
            self.assertEqual(created.returncode, 0, created.stderr)
            scenario = state / "scenarios" / "04"
            self.assertTrue((scenario / "TASK.md").is_file())
            self.assertTrue((scenario / "fixture" / "resources.json").is_file())
            refused = cli("scenario", "create", "04", state=state)
            self.assertEqual(refused.returncode, 1)
            self.assertIn("scenario reset", refused.stderr)
            reset = cli("scenario", "reset", "04", state=state)
            self.assertEqual(reset.returncode, 0, reset.stderr)
            self.assertTrue((scenario / "artifacts").is_dir())

    def test_artifact_check_is_deterministic_and_cluster_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            self.assertEqual(cli("scenario", "create", "06", state=state).returncode, 0)
            failed = cli("check", "06", state=state)
            self.assertEqual(failed.returncode, 1)
            artifact = state / "scenarios" / "06" / "artifacts" / "immutable-deployment-new.yaml"
            artifact.write_text(
                "securityContext:\n  readOnlyRootFilesystem: true\n"
                "volumeMounts:\n- mountPath: /tmp\n  name: tmp\n"
                "volumes:\n- name: tmp\n  emptyDir: {}\n",
                encoding="utf-8",
            )
            passed = cli("check", "06", state=state)
            self.assertEqual(passed.returncode, 0, passed.stdout + passed.stderr)
            self.assertIn("PASS", passed.stdout)

    def test_grade_awards_partial_credit_but_check_remains_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "immutable-deployment-new.yaml").write_text(
                "readOnlyRootFilesystem: true\nmountPath: /tmp\n",
                encoding="utf-8",
            )
            result = cli("grade", "06", "--root", str(root), "--json")
            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["score"], 66.7)
            self.assertEqual(payload["status"], "incomplete")
            self.assertEqual(payload["earned"], 2)
            self.assertEqual(payload["possible"], 3)

    def test_grade_all_is_machine_readable_and_covers_every_scenario(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = cli("grade", "all", "--root", temporary, "--json")
            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["scenario_count"], 17)
            self.assertEqual(len(payload["scenarios"]), 17)
            self.assertEqual(payload["validation_scope"], "artifact evidence; not an official CKS exam score")

    def test_cluster_health_requires_every_reported_node_to_be_ready(self):
        with patch.object(
            simulator,
            "node_statuses",
            return_value=[{"name": "cp", "ready": True}, {"name": "worker", "ready": False}],
        ):
            self.assertFalse(simulator.cluster_healthy("test", announce=False))
        with patch.object(
            simulator,
            "node_statuses",
            return_value=[
                {"name": "cp", "ready": True},
                {"name": "worker", "ready": True},
                {"name": "worker2", "ready": True},
            ],
        ):
            self.assertTrue(simulator.cluster_healthy("test", announce=False))
        for nodes in ([], [{"name": "cp", "ready": True}], [{"name": str(index), "ready": True} for index in range(4)]):
            with self.subTest(nodes=len(nodes)), patch.object(simulator, "node_statuses", return_value=nodes):
                self.assertFalse(simulator.cluster_healthy("test", announce=False))

    def test_every_grading_rule_family_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "value.txt").write_text("alpha\nbeta\n", encoding="utf-8")
            (root / "value.json").write_text('{"outer":{"enabled":true}}', encoding="utf-8")
            cases = [
                ({"path": "value.txt", "kind": "file_exists"}, True),
                ({"path": "value.txt", "kind": "text_contains", "values": ["alpha", "beta"]}, True),
                ({"path": "value.txt", "kind": "text_not_contains", "values": ["gamma"]}, True),
                ({"path": "value.txt", "kind": "text_exact_lines", "values": ["alpha", "beta"]}, True),
                ({"path": "value.json", "kind": "json_pointer", "pointer": "/outer/enabled", "expected": True}, True),
                ({"path": "missing", "kind": "text_not_contains", "values": ["gamma"]}, False),
                ({"path": "value.txt", "kind": "unknown"}, False),
            ]
            for rule, expected in cases:
                with self.subTest(kind=rule["kind"], path=rule["path"]):
                    self.assertEqual(evaluate_rule(root, rule)["passed"], expected)
            (root / "invalid.txt").write_bytes(b"\xff\xfe")
            invalid = evaluate_rule(root, {"path": "invalid.txt", "kind": "text_contains", "values": ["alpha"]})
            self.assertFalse(invalid["passed"])

    def test_fixture_validator_exercises_real_apply_get_and_wait_contract(self):
        item = simulator.scenario_by_id("04")
        expected = json.loads((ROOT / "scenarios" / "fixtures" / "04" / "resources.json").read_text(encoding="utf-8"))
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        observed = subprocess.CompletedProcess([], 0, stdout=json.dumps(expected), stderr="")
        with (
            patch.object(simulator, "run_command", return_value=completed) as run_mock,
            patch.object(simulator, "command_output", side_effect=[observed, completed]) as output_mock,
            patch.object(simulator, "cluster_kubectl", side_effect=lambda _name, args: ["kubectl", *args]),
        ):
            ok, detail = simulator._validate_fixture("test", item, announce=False)
        self.assertTrue(ok, detail)
        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(output_mock.call_count, 2)

    def test_scenario_07_e2e_uses_server_dry_run(self):
        item = simulator.scenario_by_id("07")
        completed = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        with (
            patch.object(simulator, "run_command", return_value=completed) as run_mock,
            patch.object(simulator, "command_output", return_value=completed) as output_mock,
            patch.object(simulator, "cluster_kubectl", side_effect=lambda _name, args: ["kubectl", *args]),
        ):
            ok, detail = simulator._validate_fixture("test", item, announce=False)
        self.assertTrue(ok, detail)
        self.assertIn("without scheduling", detail)
        self.assertIn("create", run_mock.call_args.args[0])
        self.assertIn("--dry-run=server", output_mock.call_args.args[0])

    def test_scenario_15_live_validator_exercises_generated_tls(self):
        item = simulator.scenario_by_id("15")
        expected = json.loads((ROOT / "scenarios" / "fixtures" / "15" / "resources.json").read_text(encoding="utf-8"))
        completed = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        observed = subprocess.CompletedProcess([], 0, stdout=json.dumps(expected), stderr="")
        ingress = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps({"spec": {"tls": [{"secretName": "secure-tls"}]}}), stderr=""
        )
        with tempfile.TemporaryDirectory() as temporary:
            tls_dir = Path(temporary)
            (tls_dir / "tls.crt").write_text("test", encoding="utf-8")
            (tls_dir / "tls.key").write_text("test", encoding="utf-8")
            with (
                patch.object(simulator, "run_command", return_value=completed),
                patch.object(simulator, "command_output", side_effect=[observed, completed, completed, ingress]) as output_mock,
                patch.object(simulator, "cluster_kubectl", side_effect=lambda _name, args: ["kubectl", *args]),
            ):
                ok, detail = simulator._validate_fixture("test", item, announce=False, tls_dir=tls_dir)
        self.assertTrue(ok, detail)
        self.assertIn("verified generated TLS", detail)
        flattened = [part for call in output_mock.call_args_list for part in call.args[0]]
        self.assertIn("secure-tls", flattened)
        self.assertIn("patch", flattened)

    def test_scenario_15_generates_private_tls_fixture_without_seeding_solution(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            result = cli("scenario", "create", "15", state=state)
            self.assertEqual(result.returncode, 0, result.stderr)
            fixture = state / "scenarios" / "15" / "fixture"
            self.assertTrue((fixture / "tls.crt").is_file())
            self.assertEqual((fixture / "tls.key").stat().st_mode & 0o777, 0o600)
            resources = json.loads((fixture / "resources.json").read_text(encoding="utf-8"))
            self.assertNotIn("Secret", [item["kind"] for item in resources["items"]])
            services = {item["metadata"]["name"] for item in resources["items"] if item["kind"] == "Service"}
            self.assertEqual(services, {"app", "api"})

    def test_failed_scenario_15_reset_preserves_existing_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"CKS_STATE_DIR": temporary}):
            self.assertEqual(simulator.create_scenario("15"), 0)
            artifact = Path(temporary) / "scenarios" / "15" / "artifacts" / "work.txt"
            artifact.write_text("keep me", encoding="utf-8")
            with patch.object(simulator, "generate_tls_fixture", side_effect=RuntimeError("openssl failed")):
                with self.assertRaisesRegex(RuntimeError, "openssl failed"):
                    simulator.create_scenario("15", reset=True)
            self.assertEqual(artifact.read_text(encoding="utf-8"), "keep me")

    def test_e2e_failure_exports_logs_and_deletes_owned_cluster(self):
        completed = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr="")
        fixture_results = [(False, "fixture failed")] + [(True, "ok")] * 4
        args = SimpleNamespace(name="cks-e2e-test", image="kindest/node:test", wait="1m", keep=False, as_json=True)
        output = StringIO()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, {"CKS_STATE_DIR": temporary}),
            patch.object(simulator, "docker_command", return_value="docker"),
            patch.object(simulator, "kubectl_command", return_value="kubectl"),
            patch.object(simulator, "kind_command", return_value=["kind"]),
            patch.object(simulator, "command_output", return_value=completed),
            patch.object(simulator, "generate_tls_fixture", side_effect=seed_tls_fixture),
            patch.object(simulator, "provision", side_effect=[0, 0]),
            patch.object(
                simulator,
                "node_statuses",
                return_value=[
                    {"name": "cp", "ready": True},
                    {"name": "w1", "ready": True},
                    {"name": "w2", "ready": True},
                ],
            ),
            patch.object(simulator, "_validate_fixture", side_effect=fixture_results),
            patch.object(simulator, "state_is_owned", return_value=True),
            patch.object(
                simulator,
                "cluster_presence",
                side_effect=[False, True, True, False],
            ),
            patch.object(simulator, "_export_e2e_logs", return_value=Path("/tmp/e2e-logs")),
            patch.object(simulator, "delete", return_value=0) as delete_mock,
            redirect_stdout(output),
        ):
            result = simulator.e2e(args)
        self.assertEqual(result, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "fail")
        self.assertTrue(payload["diagnostic_logs"])
        self.assertTrue(payload["checks"][-1]["passed"])
        delete_mock.assert_called_once()

    def test_e2e_marker_failure_force_cleans_exact_claimed_new_cluster(self):
        completed = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr="")
        args = SimpleNamespace(
            name="marker-failed",
            image="kindest/node:test",
            wait="1m",
            keep=False,
            as_json=True,
        )
        output = StringIO()
        with (
            patch.object(simulator, "docker_command", return_value="docker"),
            patch.object(simulator, "kubectl_command", return_value="kubectl"),
            patch.object(simulator, "kind_command", return_value=["kind"]),
            patch.object(simulator, "command_output", return_value=completed),
            patch.object(simulator, "generate_tls_fixture", side_effect=seed_tls_fixture),
            patch.object(simulator, "acquire_e2e_claim", return_value="claim-token"),
            patch.object(simulator, "e2e_claim_is_owned", return_value=True),
            patch.object(simulator, "provision", return_value=1),
            patch.object(simulator, "state_is_owned", return_value=False),
            patch.object(
                simulator,
                "cluster_presence",
                side_effect=[False, True, True, False],
            ),
            patch.object(simulator, "delete", return_value=0) as delete_mock,
            patch.object(simulator, "_remove_state_file"),
            redirect_stdout(output),
        ):
            result = simulator.e2e(args)
        self.assertEqual(result, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["checks"][-1]["detail"], "deleted")
        delete_mock.assert_called_once()
        delete_args = delete_mock.call_args.args[0]
        self.assertEqual(delete_args.name, "marker-failed")
        self.assertTrue(delete_args.force)
        self.assertTrue(delete_args.quiet)

    def test_e2e_refuses_and_preserves_preexisting_cluster(self):
        completed = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr="")
        args = SimpleNamespace(name="existing", image="kindest/node:test", wait="1m", keep=False, as_json=True)
        output = StringIO()
        with (
            patch.object(simulator, "docker_command", return_value="docker"),
            patch.object(simulator, "kubectl_command", return_value="kubectl"),
            patch.object(simulator, "kind_command", return_value=["kind"]),
            patch.object(simulator, "command_output", return_value=completed),
            patch.object(simulator, "generate_tls_fixture", side_effect=seed_tls_fixture),
            patch.object(simulator, "cluster_presence", return_value=True),
            patch.object(simulator, "metadata_path", return_value=Path("/nonexistent/e2e-metadata")),
            patch.object(simulator, "provision") as provision_mock,
            patch.object(simulator, "delete") as delete_mock,
            redirect_stdout(output),
        ):
            result = simulator.e2e(args)
        self.assertEqual(result, 1)
        payload = json.loads(output.getvalue())
        provision_check = next(check for check in payload["checks"] if check["name"] == "cluster provision")
        self.assertIn("refusing pre-existing", provision_check["detail"])
        self.assertEqual(payload["checks"][-1]["detail"], "pre-existing cluster or state left untouched")
        provision_mock.assert_not_called()
        delete_mock.assert_not_called()

    def test_diagnostic_logs_are_reported_only_after_successful_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def successful_export(*_args, **_kwargs):
                (root / "e2e-logs" / "test").mkdir(parents=True)
                return subprocess.CompletedProcess([], 0, stdout="", stderr="")

            with (
                patch.object(simulator, "state_dir", return_value=root),
                patch.object(simulator, "kind_command", return_value=["kind"]),
                patch.object(simulator, "command_output", side_effect=successful_export),
            ):
                self.assertEqual(simulator._export_e2e_logs("test", announce=False), root / "e2e-logs" / "test")

            with (
                patch.object(simulator, "state_dir", return_value=root),
                patch.object(simulator, "kind_command", return_value=["kind"]),
                patch.object(
                    simulator,
                    "command_output",
                    return_value=subprocess.CompletedProcess([], 1, stdout="", stderr="failed"),
                ),
            ):
                self.assertIsNone(simulator._export_e2e_logs("failed", announce=False))

    def test_e2e_claim_is_exclusive_and_token_scoped(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(simulator, "state_dir", return_value=Path(temporary)):
            first = simulator.acquire_e2e_claim("same-name")
            second = simulator.acquire_e2e_claim("same-name")
            self.assertTrue(first)
            self.assertIsNone(second)
            self.assertTrue(simulator.e2e_claim_is_owned("same-name", first))
            self.assertFalse(simulator.e2e_claim_is_owned("same-name", "wrong-token"))

    def test_json_mode_returns_structured_domain_errors(self):
        result = cli("grade", "99", "--json")
        self.assertEqual(result.returncode, 2)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error"]["type"], "ValueError")

    def test_unsupported_scenario_is_still_fixture_and_artifact_checkable(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            result = cli("scenario", "create", "10", "--apply", state=state)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("not applying unsupported fixture", result.stdout)
            self.assertTrue((state / "scenarios" / "10" / "TASK.md").is_file())

    def test_invalid_scenario_has_useful_error(self):
        result = cli("scenario", "create", "99")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown scenario", result.stderr)


if __name__ == "__main__":
    unittest.main()
