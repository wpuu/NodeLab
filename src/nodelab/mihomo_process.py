"""F1 exact-child lifecycle; real engine launching waits for F2/F3.

No global process enumeration or termination is permitted. The owner of a
Popen object may terminate only that Popen, with a bounded wait and a fixed
error code. The private RunContext owns configuration removal separately.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class ProcessLifecycleError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PROCESS_STOP_FAILED")


def find_mihomo_exe() -> Path | None:
    """Do not select PATH/unverified executables until F2's pinned verifier."""
    return None


def run_version_check(exe: Path) -> tuple[bool, str]:
    """No unverified binary execution or raw stdout in F1."""
    return False, "BINARY_MISMATCH"


def test_config(exe: Path, config_path: Path) -> tuple[bool, str]:
    """Disabled until F2 implements the pinned binary/config path contract."""
    return False, "PROBE_GATE_CLOSED"


def stop_owned_process(proc: subprocess.Popen) -> None:
    """Terminate ONLY the supplied Popen; never use process names/PID scans."""
    try:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=2)
        if proc.poll() is None:
            raise ProcessLifecycleError()
    except BaseException:
        # Cancellation during cleanup must not leave our own child alive.
        try:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            if proc.poll() is not None:
                return  # recovered: the owned child is confirmed gone
        except BaseException:
            pass
        raise ProcessLifecycleError() from None


class MihomoProcess:
    """Ownership wrapper for one exact subprocess.Popen, never a name/PID scan."""

    def __init__(self, proc: subprocess.Popen):
        if not isinstance(proc, subprocess.Popen):
            raise ProcessLifecycleError()
        self.proc = proc
        self.closed = False

    @classmethod
    def start(cls, exe: Path, config_path: Path, wait_seconds: float = 8.0) -> "MihomoProcess":
        # F1 disallows launching the broken/unverified business configuration.
        raise RuntimeError("PROBE_GATE_CLOSED")

    def close(self) -> None:
        if self.closed:
            return
        stop_owned_process(self.proc)
        self.closed = True
