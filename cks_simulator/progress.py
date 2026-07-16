"""Truthful terminal progress for long full-tier setup operations."""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass
from shutil import get_terminal_size
from typing import Callable, Optional, Sequence, TextIO


CKS_TIPS = (
    "kubectl config get-contexts -o name lists every exam context before you change one.",
    "Use kubectl auth can-i --as=<user> <verb> <resource> to verify RBAC decisions.",
    "Static Pod manifests live in /etc/kubernetes/manifests on a kubeadm control plane.",
    "crictl ps -a and crictl logs <container-id> inspect workloads when kubectl is not enough.",
    "journalctl -u kubelet --since '10 min ago' is a fast first check for node failures.",
    "NetworkPolicies are additive: allowed traffic is the union of every matching policy.",
    "AppArmor needs both a profile loaded on the node and a matching Pod configuration.",
    "Enabling etcd encryption does not rewrite existing Secrets; recreate them to encrypt stored data.",
    "Prefer kubectl apply --dry-run=client -o yaml when you need a correct manifest quickly.",
    "After changing a static Pod or kubelet setting, verify the runtime state instead of trusting the file.",
)


@dataclass(frozen=True)
class ProgressEvent:
    """One observable setup milestone or update within a milestone."""

    stage: int
    title: str
    detail: str
    current: Optional[int] = None
    total: Optional[int] = None
    completed: bool = False

    def __post_init__(self) -> None:
        if self.stage < 1:
            raise ValueError("progress stage must be positive")
        if not self.title.strip() or not self.detail.strip():
            raise ValueError("progress title and detail must not be empty")
        if (self.current is None) != (self.total is None):
            raise ValueError("progress current and total must be supplied together")
        if self.current is not None and (
            self.current < 0 or self.total is None or self.total < 1 or self.current > self.total
        ):
            raise ValueError("progress sub-count is invalid")


ProgressCallback = Callable[[ProgressEvent], None]


class SetupProgressDisplay:
    """Render verified lifecycle progress only when attached to an interactive TTY."""

    _SPINNERS = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
    _BAR_WIDTH = 16

    def __init__(
        self,
        *,
        lab_name: str,
        profile_name: str,
        guest_cpus: int,
        guest_memory_gib: int,
        total_stages: int,
        stream: Optional[TextIO] = None,
        enabled: Optional[bool] = None,
        tick_interval: float = 0.2,
        tip_interval: float = 25.0,
        tips: Sequence[str] = CKS_TIPS,
    ) -> None:
        if total_stages < 1:
            raise ValueError("total progress stages must be positive")
        if tick_interval <= 0 or tip_interval <= 0:
            raise ValueError("progress intervals must be positive")
        if not tips or any(not value.strip() for value in tips):
            raise ValueError("at least one non-empty CKS tip is required")
        self._stream = stream or sys.stdout
        interactive = bool(getattr(self._stream, "isatty", lambda: False)())
        self.enabled = interactive if enabled is None else bool(enabled and interactive)
        self._lab_name = lab_name
        self._profile_name = profile_name
        self._guest_cpus = guest_cpus
        self._guest_memory_gib = guest_memory_gib
        self._total_stages = total_stages
        self._tick_interval = tick_interval
        self._tip_interval = tip_interval
        self._tips = tuple(tips)
        self._tip_index = 0
        self._spinner_index = 0
        self._started_at = 0.0
        self._last_tip_at = 0.0
        self._active: Optional[ProgressEvent] = None
        self._started = False
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self.enabled and self._started and not self._stop.is_set()

    def __enter__(self) -> "SetupProgressDisplay":
        self.start()
        return self

    def __exit__(self, exc_type, exc, _traceback) -> None:
        if exc is not None:
            self.fail(str(exc))
        self.close()

    def start(self) -> None:
        if not self.enabled or self._started:
            return
        self._started = True
        self._started_at = time.monotonic()
        self._last_tip_at = self._started_at
        self._write(
            f"\nCKS Simulator · preparing {self._lab_name} "
            f"({self._profile_name} profile)\n"
        )
        self._write("  First build can take tens of minutes; later runs reuse verified state.\n")
        self._write(
            "  Creates 4 local Ubuntu VMs · "
            f"{self._guest_cpus} vCPUs · {self._guest_memory_gib} GiB guest RAM.\n"
        )
        self._write(
            "  Progress reflects verified lifecycle stages, not an estimated timer. "
            "Interrupted setup is safe to rerun.\n"
        )
        self._print_tip()
        if self._stop.is_set():
            return
        self._thread = threading.Thread(
            target=self._refresh_loop,
            name="cks-simulator-progress",
            daemon=True,
        )
        self._thread.start()

    def __call__(self, event: ProgressEvent) -> None:
        if event.stage > self._total_stages:
            raise ValueError("progress event exceeds configured stage count")
        if not self.enabled:
            return
        with self._lock:
            self._clear_line()
            self._active = event
            if event.completed:
                self._write(self._format_line(event, complete=True) + "\n")
                if event.stage == self._total_stages:
                    self._stop.set()
                    self._write(f"✓ setup complete in {self._elapsed()}\n\n")
            else:
                self._render_active()

    def fail(self, detail: str) -> None:
        if not self.enabled or self._stop.is_set():
            return
        with self._lock:
            self._stop.set()
            self._clear_line()
            concise = " ".join(detail.split())[:240] or "setup interrupted"
            self._write(f"✗ setup stopped after {self._elapsed()}: {concise}\n")

    def close(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(1.0, self._tick_interval * 2))
        with self._lock:
            if self._active is not None and not self._active.completed:
                self._clear_line()

    def _refresh_loop(self) -> None:
        while not self._stop.wait(self._tick_interval):
            with self._lock:
                if self._active is None or self._active.completed:
                    continue
                now = time.monotonic()
                self._clear_line()
                if now - self._last_tip_at >= self._tip_interval:
                    self._print_tip()
                    self._last_tip_at = now
                self._render_active()

    def _print_tip(self) -> None:
        tip = self._tips[self._tip_index % len(self._tips)]
        self._tip_index += 1
        self._write(f"  CKS tip: {tip}\n")

    def _render_active(self) -> None:
        if self._active is None or self._active.completed:
            return
        self._write(self._format_line(self._active, complete=False))

    def _format_line(self, event: ProgressEvent, *, complete: bool) -> str:
        completed_stages = event.stage if complete else event.stage - 1
        filled = round(self._BAR_WIDTH * completed_stages / self._total_stages)
        bar = "█" * filled + "░" * (self._BAR_WIDTH - filled)
        marker = "✓" if complete else self._SPINNERS[self._spinner_index % len(self._SPINNERS)]
        self._spinner_index += 1
        count = ""
        if event.current is not None and event.total is not None:
            count = f"{event.current}/{event.total} · "
        suffix = f" · {count}{self._elapsed()}"
        full_prefix = (
            f"{marker} [{bar}] {event.stage}/{self._total_stages} {event.title} · "
        )
        return self._fit_active_line(
            full_prefix,
            event.detail,
            suffix,
            compact_prefix=f"{marker} {event.stage}/{self._total_stages} · ",
        )

    def _elapsed(self) -> str:
        seconds = max(0, int(time.monotonic() - self._started_at))
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours:d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"

    def _clear_line(self) -> None:
        self._write("\r\033[2K")

    def _fit_active_line(
        self,
        prefix: str,
        detail: str,
        suffix: str,
        *,
        compact_prefix: str,
    ) -> str:
        """Fit one row while preserving stage, sub-count, and elapsed time."""
        available = max(0, self._terminal_width() - 1)
        line = prefix + detail + suffix
        if len(line) <= available:
            return line
        if len(prefix) + len(suffix) + 2 > available:
            prefix = compact_prefix
        detail_width = available - len(prefix) - len(suffix)
        if detail_width >= 2:
            return prefix + detail[: detail_width - 1] + "…" + suffix
        essential = compact_prefix.rstrip() + suffix
        if len(essential) <= available:
            return essential
        if available < 2:
            return ""
        return essential[: available - 1] + "…"

    def _terminal_width(self) -> int:
        try:
            return get_terminal_size(fallback=(80, 24)).columns
        except OSError:
            return 80

    def _write(self, value: str) -> None:
        if not self.enabled:
            return
        try:
            self._stream.write(value)
            self._stream.flush()
        except (OSError, ValueError):
            # A disconnected terminal must not affect lab provisioning.
            self.enabled = False
            self._stop.set()


__all__ = ["CKS_TIPS", "ProgressCallback", "ProgressEvent", "SetupProgressDisplay"]
