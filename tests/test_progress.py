from __future__ import annotations

import re
import time
import unittest
from io import StringIO
from unittest.mock import patch

from cks_simulator.cli import build_parser
from cks_simulator.progress import ProgressEvent, SetupProgressDisplay


class TTYBuffer(StringIO):
    def isatty(self) -> bool:
        return True


class FailingTTY(TTYBuffer):
    def __init__(self, *, failure: str) -> None:
        super().__init__()
        self.failure = failure
        self.fail_terminal_io = False

    def write(self, value: str) -> int:
        if self.fail_terminal_io and self.failure == "write":
            raise OSError("terminal disconnected")
        if self.fail_terminal_io and self.failure == "closed":
            raise ValueError("I/O operation on closed file")
        return super().write(value)

    def flush(self) -> None:
        if self.fail_terminal_io and self.failure == "flush":
            raise OSError("terminal disconnected")
        super().flush()


class ProgressDisplayTests(unittest.TestCase):
    def test_long_running_full_commands_accept_an_explicit_progress_opt_out(self) -> None:
        parser = build_parser()

        provision = parser.parse_args(
            ["provision", "--tier", "full", "--no-progress"]
        )
        exam = parser.parse_args(
            ["exam", "start", "--tier", "full", "--no-progress"]
        )

        self.assertTrue(provision.no_progress)
        self.assertTrue(exam.no_progress)

    def test_tty_display_explains_first_run_and_renders_verified_progress(self) -> None:
        output = TTYBuffer()
        display = SetupProgressDisplay(
            lab_name="candidate-exam",
            profile_name="low",
            guest_cpus=8,
            guest_memory_gib=5,
            total_stages=8,
            stream=output,
            tick_interval=60,
            tip_interval=60,
            tips=("kubectl config get-contexts -o name lists every exam context.",),
        )

        with display:
            display(
                ProgressEvent(
                    stage=1,
                    title="Host preflight",
                    detail="Checking host capacity and Lima",
                )
            )
            display(
                ProgressEvent(
                    stage=1,
                    title="Host preflight",
                    detail="Host is ready",
                    completed=True,
                )
            )
            display(
                ProgressEvent(
                    stage=2,
                    title="Ubuntu VMs",
                    detail="Starting control-plane",
                    current=2,
                    total=4,
                )
            )

        rendered = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output.getvalue())
        self.assertIn("CKS Simulator · preparing candidate-exam", rendered)
        self.assertIn("First build can take tens of minutes", rendered)
        self.assertIn("4 local Ubuntu VMs · 8 vCPUs · 5 GiB guest RAM", rendered)
        self.assertIn("verified lifecycle stages, not an estimated timer", rendered)
        self.assertIn("CKS tip: kubectl config get-contexts -o name", rendered)
        self.assertIn("1/8 Host preflight", rendered)
        self.assertIn("2/8 Ubuntu VMs", rendered)
        self.assertIn("2/4", rendered)

    def test_final_verified_event_stops_background_updates(self) -> None:
        output = TTYBuffer()
        display = SetupProgressDisplay(
            lab_name="candidate-exam",
            profile_name="low",
            guest_cpus=8,
            guest_memory_gib=5,
            total_stages=1,
            stream=output,
            tick_interval=0.01,
            tip_interval=0.01,
            tips=("journalctl -u kubelet is the fastest kubelet failure check.",),
        )

        with display:
            display(ProgressEvent(1, "Ready", "Verified", completed=True))
            time.sleep(0.03)

        rendered = output.getvalue()
        self.assertIn("✓", rendered)
        self.assertIn("1/1 Ready", rendered)
        self.assertEqual(rendered.count("\033[2K"), 1)
        self.assertFalse(display.running)

    def test_disabled_display_is_completely_silent(self) -> None:
        output = StringIO()
        display = SetupProgressDisplay(
            lab_name="candidate-exam",
            profile_name="low",
            guest_cpus=8,
            guest_memory_gib=5,
            total_stages=8,
            stream=output,
            enabled=False,
        )

        with display:
            display(ProgressEvent(1, "Host preflight", "Checking"))

        self.assertEqual(output.getvalue(), "")

    def test_terminal_io_failure_disables_progress_without_interrupting_callback(self) -> None:
        for failure in ("write", "flush", "closed"):
            with self.subTest(failure=failure):
                output = FailingTTY(failure=failure)
                display = SetupProgressDisplay(
                    lab_name="candidate-exam",
                    profile_name="low",
                    guest_cpus=8,
                    guest_memory_gib=5,
                    total_stages=2,
                    stream=output,
                    tick_interval=60,
                    tip_interval=60,
                )

                display.start()
                output.fail_terminal_io = True
                display(ProgressEvent(1, "Host preflight", "Checking"))
                display.close()

                self.assertFalse(display.enabled)
                self.assertFalse(display.running)
                self.assertTrue(display._stop.is_set())
                self.assertFalse(display._thread is not None and display._thread.is_alive())

    def test_invalid_progress_event_still_propagates(self) -> None:
        display = SetupProgressDisplay(
            lab_name="candidate-exam",
            profile_name="low",
            guest_cpus=8,
            guest_memory_gib=5,
            total_stages=1,
            stream=TTYBuffer(),
            enabled=False,
        )

        with self.assertRaisesRegex(ValueError, "exceeds configured stage count"):
            display(ProgressEvent(2, "Unexpected", "Invalid stage"))

    def test_active_progress_line_fits_a_narrow_tty(self) -> None:
        output = TTYBuffer()
        display = SetupProgressDisplay(
            lab_name="candidate-exam",
            profile_name="low",
            guest_cpus=8,
            guest_memory_gib=5,
            total_stages=8,
            stream=output,
            tick_interval=60,
            tip_interval=60,
        )

        with patch.object(display, "_terminal_width", return_value=20):
            with display:
                display(
                    ProgressEvent(
                        2,
                        "Ubuntu virtual machines",
                        "Starting the control-plane node",
                        current=2,
                        total=4,
                    )
                )

        active_line = output.getvalue().split("\x1b[2K")[1].rstrip("\r")
        self.assertLessEqual(len(active_line), 19)

    def test_standard_tty_preserves_sub_count_and_elapsed_time(self) -> None:
        output = TTYBuffer()
        display = SetupProgressDisplay(
            lab_name="candidate-exam",
            profile_name="low",
            guest_cpus=8,
            guest_memory_gib=5,
            total_stages=8,
            stream=output,
            tick_interval=60,
            tip_interval=60,
        )

        with patch.object(display, "_terminal_width", return_value=80):
            with display:
                display(
                    ProgressEvent(
                        5,
                        "Security tooling",
                        "control-plane: installing pinned CKS tools",
                        current=9,
                        total=20,
                    )
                )

        active_line = output.getvalue().split("\x1b[2K")[1].rstrip("\r")
        self.assertIn("5/8 Security tooling", active_line)
        self.assertIn("9/20 · 00:00", active_line)
        self.assertLessEqual(len(active_line), 79)


if __name__ == "__main__":
    unittest.main()
