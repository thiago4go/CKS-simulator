from __future__ import annotations

import io
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cks_simulator.desktop import DesktopTunnelError, LimaDesktopTunnel
from cks_simulator.providers.base import ProviderHandle


HANDLE = ProviderHandle("lima", "cks-0123456789abcdef-candidate")


class FakeLimactl:
    def __init__(self, stdout: str, *, returncode: int = 0, stderr: str = "") -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((tuple(argv), dict(kwargs)))
        return subprocess.CompletedProcess(
            argv,
            self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


class HungProcess:
    def __init__(self) -> None:
        self.stderr = io.BytesIO(b"")
        self.terminated = 0
        self.killed = 0
        self.waits = []

    def poll(self):
        return None

    def terminate(self) -> None:
        self.terminated += 1

    def kill(self) -> None:
        self.killed += 1

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if not self.killed:
            raise subprocess.TimeoutExpired("ssh", timeout)
        return -9


class FailedProcess:
    def __init__(self) -> None:
        self.stderr = io.BytesIO(b"forward setup failed\n")
        self.waits = 0

    def poll(self):
        return 255

    def wait(self, timeout=None):
        self.waits += 1
        return 255

    def terminate(self) -> None:
        raise AssertionError("an exited process must not be terminated")

    def kill(self) -> None:
        raise AssertionError("an exited process must not be killed")


class LimaDesktopTunnelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.instance_dir = self.home / ".lima" / HANDLE.value
        self.instance_dir.mkdir(parents=True)
        self.config = self.instance_dir / "ssh.config"
        self.config.write_text("Host lima-test\n", encoding="utf-8")
        self.config.chmod(0o600)
        self.limactl = self.root / "limactl"
        self.limactl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.limactl.chmod(0o700)
        self.ssh = self.root / "fake-ssh"
        self.ssh.write_text(
            f"""#!{sys.executable}
import signal
import socket
import sys

forward = sys.argv[sys.argv.index("-L") + 1]
host, port, target_host, target_port = forward.split(":")
assert host == "127.0.0.1"
assert target_host == "127.0.0.1"
assert target_port == "6080"
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((host, int(port)))
listener.listen(8)

def stop(_signum, _frame):
    listener.close()
    raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
while True:
    connection, _address = listener.accept()
    connection.close()
""",
            encoding="utf-8",
        )
        self.ssh.chmod(0o700)

    def tunnel(self, **kwargs) -> LimaDesktopTunnel:
        return LimaDesktopTunnel(
            HANDLE,
            limactl_command=(str(self.limactl),),
            ssh_command=str(self.ssh),
            home=self.home,
            run_command=kwargs.pop(
                "run_command", FakeLimactl(f"{self.config}\n")
            ),
            **kwargs,
        )

    def test_context_starts_exact_loopback_forward_and_exposes_novnc_url(self) -> None:
        limactl = FakeLimactl(f"{self.config}\n")
        observed_ssh = []
        observed_spawn_options = []

        def spawn(argv, **kwargs):
            observed_ssh.append(tuple(argv))
            observed_spawn_options.append(dict(kwargs))
            return subprocess.Popen(argv, **kwargs)

        tunnel = self.tunnel(run_command=limactl, popen_factory=spawn)
        with tunnel as active:
            self.assertIs(active, tunnel)
            self.assertTrue(tunnel.is_running)
            self.assertEqual(tunnel.host, "127.0.0.1")
            self.assertGreater(tunnel.port, 0)
            bound_port = tunnel.port
            self.assertEqual(
                tunnel.url,
                f"http://127.0.0.1:{tunnel.port}/vnc.html?autoconnect=1&resize=scale",
            )
            with socket.create_connection((tunnel.host, tunnel.port), timeout=1):
                pass

            self.assertEqual(
                observed_ssh,
                [
                    (
                        str(self.ssh),
                        "-F",
                        str(self.config),
                        "-N",
                        "-T",
                        "-o",
                        "ExitOnForwardFailure=yes",
                        "-o",
                        "ForwardAgent=no",
                        "-o",
                        "PermitLocalCommand=no",
                        "-o",
                        "ControlMaster=no",
                        "-o",
                        "ControlPath=none",
                        "-o",
                        "ControlPersist=no",
                        "-o",
                        "ClearAllForwardings=no",
                        "-L",
                        f"127.0.0.1:{tunnel.port}:127.0.0.1:6080",
                        f"lima-{HANDLE.value}",
                    )
                ],
            )
            self.assertNotIn("shell", observed_spawn_options[0])

        self.assertFalse(tunnel.is_running)
        with self.assertRaises(OSError):
            socket.create_connection((tunnel.host, bound_port), timeout=0.1)
        tunnel.close()
        self.assertEqual(
            limactl.calls[0][0],
            (
                str(self.limactl),
                "list",
                "--format",
                "{{.SSHConfigFile}}",
                HANDLE.value,
            ),
        )

    def test_rejects_unverified_non_candidate_handles_before_running_commands(self) -> None:
        limactl = FakeLimactl(f"{self.config}\n")
        for handle in (
            ProviderHandle("kind", "cks-0123456789abcdef-cluster"),
            ProviderHandle("lima", "cks-0123456789abcdef-worker1"),
        ):
            with self.subTest(handle=handle):
                with self.assertRaisesRegex(ValueError, "candidate"):
                    LimaDesktopTunnel(
                        handle,
                        limactl_command=(str(self.limactl),),
                        home=self.home,
                        run_command=limactl,
                    )
        self.assertEqual(limactl.calls, [])

    def test_ssh_config_output_must_be_one_exact_absolute_safe_file(self) -> None:
        outside = self.root / "ssh.config"
        outside.write_text("Host outside\n", encoding="utf-8")
        outside.chmod(0o600)
        outputs = (
            "ssh.config\n",
            f"{self.config}\n{outside}\n",
            f"{outside}\n",
            "\n",
        )
        for output in outputs:
            with self.subTest(output=output):
                with self.assertRaises(DesktopTunnelError):
                    self.tunnel(run_command=FakeLimactl(output)).start()

        self.config.chmod(0o620)
        with self.assertRaisesRegex(DesktopTunnelError, "permissions"):
            self.tunnel().start()

        self.config.unlink()
        self.config.symlink_to(outside)
        with self.assertRaisesRegex(DesktopTunnelError, "symlink"):
            self.tunnel().start()

    def test_limactl_failure_stops_before_ssh_spawn(self) -> None:
        spawns = []
        tunnel = self.tunnel(
            run_command=FakeLimactl("", returncode=1, stderr="instance unavailable"),
            popen_factory=lambda *args, **kwargs: spawns.append((args, kwargs)),
        )
        with self.assertRaisesRegex(DesktopTunnelError, "SSH config"):
            tunnel.start()
        self.assertEqual(spawns, [])

    def test_ssh_startup_failure_is_reported_and_reaped(self) -> None:
        process = FailedProcess()
        tunnel = self.tunnel(popen_factory=lambda *args, **kwargs: process)
        with self.assertRaisesRegex(DesktopTunnelError, "forward setup failed"):
            tunnel.start()
        self.assertEqual(process.waits, 1)
        self.assertFalse(tunnel.is_running)

    def test_startup_timeout_terminates_kills_and_reaps_idempotently(self) -> None:
        process = HungProcess()
        tunnel = self.tunnel(
            popen_factory=lambda *args, **kwargs: process,
            startup_timeout=0.02,
            poll_interval=0.001,
            shutdown_timeout=0.01,
        )
        with self.assertRaisesRegex(DesktopTunnelError, "timed out"):
            tunnel.start()
        self.assertEqual(process.terminated, 1)
        self.assertEqual(process.killed, 1)
        self.assertEqual(len(process.waits), 2)

        tunnel.close()
        tunnel.close()
        self.assertEqual(process.terminated, 1)
        self.assertEqual(process.killed, 1)


if __name__ == "__main__":
    unittest.main()
