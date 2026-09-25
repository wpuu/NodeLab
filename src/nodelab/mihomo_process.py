"""Mihomo subprocess lifecycle: locate binary, test config, start/stop.

All error text goes through redact_uri() so no credential ever reaches
a log or exception message.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

from nodelab.parser import redact_uri

TOOLS_DIR = Path(__file__).resolve().parents[3] / "tools" / "mihomo"
_CREATE_NO_WINDOW = 0x08000000


def find_mihomo_exe() -> Path | None:
    candidate = TOOLS_DIR / "mihomo.exe"
    if candidate.exists():
        return candidate
    found = shutil.which("mihomo.exe")
    return Path(found) if found else None


def run_version_check(exe: Path) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            [str(exe), "-v"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        out = (r.stdout or r.stderr or "").strip()
        return r.returncode == 0, out
    except Exception as exc:  # noqa: BLE001
        return False, f"version check failed: {redact_uri(str(exc))}"


def test_config(exe: Path, config_path: Path) -> tuple[bool, str]:
    """Run `mihomo -t -f config`; return (ok, redacted_error)."""
    try:
        r = subprocess.run(
            [str(exe), "-t", "-f", str(config_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode == 0:
            return True, ""
        err = ((r.stderr or "") + " " + (r.stdout or "")).strip()
        return False, redact_uri(err)
    except subprocess.TimeoutExpired:
        return False, "config test timed out"
    except Exception as exc:  # noqa: BLE001
        return False, f"config test failed: {redact_uri(str(exc))}"


class MihomoProcess:
    """Wrapper around a started mihomo.exe; close() must always be called."""

    def __init__(self, proc: subprocess.Popen, exe: Path, config_path: Path):
        self.proc = proc
        self.exe = exe
        self.config_path = config_path
        self.closed = False

    @classmethod
    def start(cls, exe: Path, config_path: Path, wait_seconds: float = 8.0) -> "MihomoProcess":
        ok, err = test_config(exe, config_path)
        if not ok:
            raise RuntimeError(f"mihomo config test failed: {err}")

        creationflags = _CREATE_NO_WINDOW if sys.platform == "win32" else 0
        proc = subprocess.Popen(
            [str(exe), "-d", str(config_path.parent), "-f", str(config_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("mihomo exited early after start")
            time.sleep(0.2)
        return cls(proc, exe, config_path)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        shutil.rmtree(self.config_path.parent, ignore_errors=True)


def list_mihomo_pids() -> list[str]:
    """Return PIDs of running mihomo.exe processes (best effort, no-throw)."""
    try:
        output = subprocess.run(
            ["wmic", "process", "where", "name='mihomo.exe'", "get", "ProcessId", "/value"],
            capture_output=True,
            text=True,
            timeout=20,
        ).stdout
        pids = [line.split("=")[1].strip() for line in output.splitlines() if "=" in line]
        return pids
    except Exception:  # noqa: BLE001
        return []


def cleanup_stale_mihomo() -> int:
    """Terminate leftover mihomo.exe processes; returns how many we killed."""
    import ctypes

    killed = 0
    for pid in list_mihomo_pids():
        try:
            handle = ctypes.windll.kernel32.OpenProcess(0x0001, False, int(pid))  # PROCESS_TERMINATE
            if handle:
                ctypes.windll.kernel32.TerminateProcess(handle, 1)
                ctypes.windll.kernel32.CloseHandle(handle)
                killed += 1
        except Exception:  # noqa: BLE001
            pass
    return killed
