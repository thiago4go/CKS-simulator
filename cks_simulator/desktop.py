"""Host-only SSH tunnel for the candidate VM's noVNC service."""

from __future__ import annotations

import os
import socket
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Tuple

from .providers.base import ProviderHandle, bounded_redacted


LOOPBACK_HOST = "127.0.0.1"
NOVNC_GUEST_PORT = 6080
NOVNC_PATH = "/vnc.html?autoconnect=1&resize=scale"
SSH_CONFIG_TEMPLATE = "{{.SSHConfigFile}}"


class DesktopTunnelError(RuntimeError):
    """The candidate desktop tunnel could not be established safely."""


def _fixed_command(value: Sequence[str], *, label: str) -> Tuple[str, ...]:
    command = tuple(value)
    if not command or any(
        not isinstance(argument, str) or not argument or "\0" in argument
        for argument in command
    ):
        raise ValueError(f"{label} must contain fixed non-empty argv entries")
    if not Path(command[0]).is_absolute():
        raise ValueError(f"{label} executable must be an absolute path")
    return command


def _candidate_handle(value: ProviderHandle) -> ProviderHandle:
    if (
        not isinstance(value, ProviderHandle)
        or value.provider != "lima"
        or not value.value.endswith("-candidate")
    ):
        raise ValueError("desktop tunneling requires a verified Lima candidate handle")
    return value


def _bounded_stderr(process: Any, limit: int = 4096) -> str:
    stream = getattr(process, "stderr", None)
    if stream is None:
        return ""
    try:
        value = stream.read(limit + 1)
    except (OSError, ValueError):
        return ""
    return bounded_redacted(value, limit=limit).strip()


class LimaDesktopTunnel:
    """Manage one loopback-only OpenSSH forward to candidate noVNC.

    ``candidate_handle`` must come from the caller's existing Lima ownership
    verification.  This class never discovers a target and exposes no target,
    guest-port, or listener-host override.
    """

    def __init__(
        self,
        candidate_handle: ProviderHandle,
        *,
        limactl_command: Sequence[str],
        ssh_command: str = "/usr/bin/ssh",
        home: Optional[Path] = None,
        run_command: Callable[..., Any] = subprocess.run,
        popen_factory: Callable[..., Any] = subprocess.Popen,
        config_timeout: float = 10.0,
        startup_timeout: float = 5.0,
        poll_interval: float = 0.02,
        shutdown_timeout: float = 2.0,
    ) -> None:
        self._handle = _candidate_handle(candidate_handle)
        self._limactl_command = _fixed_command(
            limactl_command, label="limactl command"
        )
        self._ssh_command = _fixed_command(
            (ssh_command,), label="SSH command"
        )[0]
        self._home = Path.home() if home is None else Path(home)
        if not self._home.is_absolute():
            raise ValueError("home directory must be an absolute path")
        for label, value in (
            ("config timeout", config_timeout),
            ("startup timeout", startup_timeout),
            ("poll interval", poll_interval),
            ("shutdown timeout", shutdown_timeout),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value <= 0
            ):
                raise ValueError(f"{label} must be positive")
        self._run_command = run_command
        self._popen_factory = popen_factory
        self._config_timeout = float(config_timeout)
        self._startup_timeout = float(startup_timeout)
        self._poll_interval = float(poll_interval)
        self._shutdown_timeout = float(shutdown_timeout)
        self._process: Optional[Any] = None
        self._port: Optional[int] = None
        self._lock = threading.RLock()

    @property
    def host(self) -> str:
        return LOOPBACK_HOST

    @property
    def port(self) -> int:
        if not self.is_running or self._port is None:
            raise DesktopTunnelError("desktop tunnel is not running")
        return self._port

    @property
    def novnc_url(self) -> str:
        return f"http://{LOOPBACK_HOST}:{self.port}{NOVNC_PATH}"

    @property
    def url(self) -> str:
        return self.novnc_url

    @property
    def is_running(self) -> bool:
        process = self._process
        return (
            process is not None
            and self._port is not None
            and process.poll() is None
        )

    def _query_ssh_config(self) -> Path:
        argv = (
            *self._limactl_command,
            "list",
            "--format",
            SSH_CONFIG_TEMPLATE,
            self._handle.value,
        )
        try:
            result = self._run_command(
                argv,
                capture_output=True,
                text=True,
                timeout=self._config_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise DesktopTunnelError("Lima SSH config lookup timed out") from error
        except OSError as error:
            raise DesktopTunnelError("Lima SSH config lookup failed") from error
        if result.returncode != 0:
            raise DesktopTunnelError("Lima SSH config lookup failed")

        stdout = result.stdout
        if isinstance(stdout, bytes):
            try:
                stdout = stdout.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise DesktopTunnelError("Lima SSH config output is invalid") from error
        if not isinstance(stdout, str) or len(stdout.encode("utf-8")) > 4096:
            raise DesktopTunnelError("Lima SSH config output is invalid")
        lines = stdout.splitlines()
        if len(lines) != 1 or not lines[0] or lines[0] != lines[0].strip():
            raise DesktopTunnelError(
                "Lima SSH config output must contain exactly one path"
            )
        config = Path(lines[0])
        expected = self._home / ".lima" / self._handle.value / "ssh.config"
        if not config.is_absolute() or config != expected:
            raise DesktopTunnelError(
                "Lima SSH config must be the exact absolute per-handle ssh.config"
            )
        self._validate_config_path(config)
        return config

    def _validate_config_path(self, config: Path) -> None:
        directories = (self._home, self._home / ".lima", config.parent)
        for directory in directories:
            try:
                observed = directory.lstat()
            except OSError as error:
                raise DesktopTunnelError(
                    "Lima SSH config parent is unavailable"
                ) from error
            if stat.S_ISLNK(observed.st_mode):
                raise DesktopTunnelError("Lima SSH config parent must not be a symlink")
            if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.getuid():
                raise DesktopTunnelError(
                    "Lima SSH config parent must be an owner-controlled directory"
                )
            if stat.S_IMODE(observed.st_mode) & 0o022:
                raise DesktopTunnelError(
                    "Lima SSH config parent has unsafe permissions"
                )

        try:
            path_observed = config.lstat()
        except OSError as error:
            raise DesktopTunnelError("Lima SSH config is unavailable") from error
        if stat.S_ISLNK(path_observed.st_mode):
            raise DesktopTunnelError("Lima SSH config must not be a symlink")

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(
            os, "O_CLOEXEC", 0
        )
        descriptor = -1
        try:
            descriptor = os.open(str(config), flags)
            observed = os.fstat(descriptor)
        except OSError as error:
            raise DesktopTunnelError("Lima SSH config is unavailable") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not stat.S_ISREG(observed.st_mode):
            raise DesktopTunnelError("Lima SSH config must be a regular file")
        if observed.st_uid != os.getuid():
            raise DesktopTunnelError("Lima SSH config must be owner-controlled")
        if stat.S_IMODE(observed.st_mode) & 0o022:
            raise DesktopTunnelError("Lima SSH config has unsafe permissions")

    @staticmethod
    def _allocate_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind((LOOPBACK_HOST, 0))
            return int(reservation.getsockname()[1])

    @staticmethod
    def _listener_is_ready(port: int, timeout: float) -> bool:
        try:
            with socket.create_connection((LOOPBACK_HOST, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _ssh_argv(self, config: Path, port: int) -> Tuple[str, ...]:
        return (
            self._ssh_command,
            "-F",
            str(config),
            "-N",
            "-T",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            # Lima enables a persistent multiplex master in this config. A
            # forwarded port attached to that shared master survives the
            # short-lived child process, so submission cannot revoke it by
            # terminating the child. Force a dedicated, process-owned SSH
            # connection for the candidate desktop.
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ControlPersist=no",
            "-o",
            # OpenSSH applies ClearAllForwardings after parsing command-line
            # -L options too.  The owned Lima config is already path/mode
            # validated, so keep the one explicit forward instead of silently
            # cancelling it.
            "ClearAllForwardings=no",
            "-L",
            f"{LOOPBACK_HOST}:{port}:{LOOPBACK_HOST}:{NOVNC_GUEST_PORT}",
            f"lima-{self._handle.value}",
        )

    def start(self) -> "LimaDesktopTunnel":
        with self._lock:
            if self.is_running:
                return self
            if self._process is not None:
                self.close()

            config = self._query_ssh_config()
            port = self._allocate_port()
            argv = self._ssh_argv(config, port)
            try:
                process = self._popen_factory(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    start_new_session=True,
                )
            except OSError as error:
                raise DesktopTunnelError(
                    "failed to spawn the SSH desktop tunnel"
                ) from error

            self._process = process
            self._port = port
            deadline = time.monotonic() + self._startup_timeout
            while True:
                returncode = process.poll()
                if returncode is not None:
                    detail = _bounded_stderr(process)
                    self.close()
                    suffix = f": {detail}" if detail else ""
                    raise DesktopTunnelError(
                        f"SSH desktop tunnel exited during startup{suffix}"
                    )
                if self._listener_is_ready(port, min(0.1, self._poll_interval)):
                    return self
                if time.monotonic() >= deadline:
                    self.close()
                    raise DesktopTunnelError("SSH desktop tunnel startup timed out")
                time.sleep(self._poll_interval)

    def close(self) -> None:
        with self._lock:
            process = self._process
            self._process = None
            self._port = None
            if process is None:
                return

            if process.poll() is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=self._shutdown_timeout)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=self._shutdown_timeout)
                    except subprocess.TimeoutExpired as error:
                        raise DesktopTunnelError(
                            "SSH desktop tunnel could not be reaped"
                        ) from error
            else:
                process.wait(timeout=self._shutdown_timeout)

            stream = getattr(process, "stderr", None)
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self.close()

    def __enter__(self) -> "LimaDesktopTunnel":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


DesktopTunnel = LimaDesktopTunnel


__all__ = ["DesktopTunnel", "DesktopTunnelError", "LimaDesktopTunnel"]
