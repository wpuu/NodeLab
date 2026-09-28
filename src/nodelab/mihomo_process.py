"""F1 exact-child lifecycle; real engine launching waits for F2/F3.

No global process enumeration or termination is permitted. The owner of a
Popen object may terminate only that Popen, with a bounded wait and a fixed
error code. The private RunContext owns configuration removal separately.
"""

from __future__ import annotations

import hashlib
import math
import os
import select
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from nodelab import engine_binary

STOP_BUDGET_SECONDS = 5.0  # NL-REVIEW-002 F.3 cleanup window


class ProcessLifecycleError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PROCESS_STOP_FAILED")


def exe_fingerprint(path: str | os.PathLike[str] | None) -> str | None:
    """Opaque digest of a canonical executable path; the path itself is never stored."""
    if not path:
        return None
    try:
        canonical = os.path.normcase(os.path.realpath(os.fspath(path)))
    except (OSError, ValueError, TypeError):
        return None
    return hashlib.sha256(canonical.encode("utf-8", errors="surrogatepass")).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """pid + OS creation stamp (+ exe digest): a PID alone is reusable."""

    pid: int
    create_time: int
    exe_fingerprint: str | None

    def matches(self, other: "ProcessIdentity | None") -> bool:
        if other is None or other.pid != self.pid or other.create_time != self.create_time:
            return False
        if self.exe_fingerprint is not None and other.exe_fingerprint is not None:
            return self.exe_fingerprint == other.exe_fingerprint
        return True


def _linux_identity(pid: int) -> ProcessIdentity | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            raw = f.read(4096)
        fields = raw.rsplit(b")", 1)[1].split()
        if fields[0:1] == [b"Z"]:  # a zombie is gone for every purpose we have
            return None
        create_time = int(fields[19])  # starttime, clock ticks since boot
    except (OSError, ValueError, IndexError):
        return None
    try:
        digest = exe_fingerprint(os.readlink(f"/proc/{pid}/exe"))
    except OSError:
        digest = None
    return ProcessIdentity(pid, create_time, digest)


class _WindowsProcess:
    """Minimal handle wrapper; an open handle pins the PID against reuse."""

    _QUERY = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
    _TERMINATE = 0x0001
    _SYNCHRONIZE = 0x00100000

    def __init__(self, pid: int, *, terminate: bool = False) -> None:
        import ctypes
        from ctypes import wintypes

        self._ctypes, self._wintypes = ctypes, wintypes
        kernel = self._kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        # Explicit signatures: a 64-bit HANDLE must never be truncated to int.
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, wintypes.LPDWORD]
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, wintypes.LPDWORD]
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        access = self._QUERY | ((self._TERMINATE | self._SYNCHRONIZE) if terminate else 0)
        self.handle = kernel.OpenProcess(access, False, pid) or None
        self.pid = pid

    def identity(self) -> ProcessIdentity | None:
        ctypes, wintypes = self._ctypes, self._wintypes
        if not self.handle:
            return None
        code = wintypes.DWORD()
        if not self._kernel.GetExitCodeProcess(self.handle, ctypes.byref(code)) or code.value != 259:
            return None  # not STILL_ACTIVE: the object only lingers because of handles
        create, exit_, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not self._kernel.GetProcessTimes(self.handle, ctypes.byref(create), ctypes.byref(exit_),
                                            ctypes.byref(kernel), ctypes.byref(user)):
            return None
        stamp = (create.dwHighDateTime << 32) | create.dwLowDateTime
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        digest = None
        if self._kernel.QueryFullProcessImageNameW(self.handle, 0, buf, ctypes.byref(size)):
            digest = exe_fingerprint(buf.value)
        return ProcessIdentity(self.pid, stamp, digest)

    def terminate_and_wait(self, timeout: float) -> bool:
        if not self.handle:
            return True
        self._kernel.TerminateProcess(self.handle, 1)
        return self._kernel.WaitForSingleObject(self.handle, int(timeout * 1000)) == 0

    def close(self) -> None:
        if self.handle:
            self._kernel.CloseHandle(self.handle)
            self.handle = None


def process_identity(pid: int) -> ProcessIdentity | None:
    """Identity of ONE pid, or None when it does not exist/cannot be verified.

    This is not process enumeration: it never lists or matches by name.
    """
    if type(pid) is not int or pid <= 0:
        return None
    if os.name == "nt":
        proc = _WindowsProcess(pid)
        try:
            return proc.identity()
        finally:
            proc.close()
    if os.path.isdir("/proc"):
        return _linux_identity(pid)
    return None  # no reliable creation stamp here: callers must not kill


def terminate_verified_process(expected: ProcessIdentity, *, budget: float = STOP_BUDGET_SECONDS) -> bool:
    """Terminate a pid only while it still is exactly `expected`; True when gone.

    An identity mismatch means the recorded child already exited (and the pid
    may belong to someone else), so nothing is signalled.
    """
    deadline = time.monotonic() + budget
    if os.name == "nt":
        proc = _WindowsProcess(expected.pid, terminate=True)
        try:
            if not expected.matches(proc.identity()):
                return True
            return proc.terminate_and_wait(max(0.1, deadline - time.monotonic()))
        finally:
            proc.close()
    if not os.path.isdir("/proc"):
        return False  # cannot verify identity on this platform: leave it alone
    pidfd = None
    try:
        if hasattr(os, "pidfd_open"):
            try:
                pidfd = os.pidfd_open(expected.pid)
            except OSError:
                pidfd = None
        if not expected.matches(_linux_identity(expected.pid)):
            return True

        def send(sig: int) -> None:
            if pidfd is not None and hasattr(signal, "pidfd_send_signal"):
                signal.pidfd_send_signal(pidfd, sig)  # bound to this process, not the pid number
            else:
                os.kill(expected.pid, sig)

        def gone(timeout: float) -> bool:
            end = time.monotonic() + timeout
            while True:
                if pidfd is not None:
                    ready, _, _ = select.select([pidfd], [], [], max(0.0, min(0.2, end - time.monotonic())))
                    if ready:
                        return True
                if not expected.matches(_linux_identity(expected.pid)):
                    return True
                if time.monotonic() >= end:
                    return False
                if pidfd is None:
                    time.sleep(0.05)

        try:
            send(signal.SIGTERM)
        except ProcessLookupError:
            return True
        if gone(min(3.0, max(0.1, deadline - time.monotonic()))):
            return True
        try:
            send(signal.SIGKILL)
        except ProcessLookupError:
            return True
        return gone(max(0.1, deadline - time.monotonic()))
    except OSError:
        return not expected.matches(_linux_identity(expected.pid))
    finally:
        if pidfd is not None:
            os.close(pidfd)


def find_mihomo_exe() -> Path | None:
    """The explicitly pinned executable, or None. NEVER searches PATH.

    F2b replaced the F1 hard `None` with a pinned resolver. It still returns
    None unless the Owner has configured an absolute path, so name-based
    discovery of the Owner's own Mihomo remains impossible.
    """
    try:
        return engine_binary.resolve_pinned_exe()
    except engine_binary.BinaryVerificationError:
        return None


def run_version_check(exe: Path) -> tuple[bool, str]:
    """Pinned bytes AND pinned version, or a fixed failure code."""
    return engine_binary.verify_pinned_binary(exe)


def test_config(exe: Path, config_path: Path, *, work_dir: Path | None = None) -> tuple[bool, str]:
    """`-t` against the pinned engine. Necessary, not sufficient (NL-REVIEW-004)."""
    return engine_binary.config_test(
        exe, config_path, work_dir=work_dir if work_dir is not None else Path(config_path).parent
    )


def stop_owned_process(proc: subprocess.Popen, *, budget: float = STOP_BUDGET_SECONDS) -> None:
    """Terminate ONLY the supplied Popen; never use process names/PID scans.

    The whole terminate -> kill -> fallback sequence shares one bounded budget
    (default 5 s, the contract's cleanup window) instead of stacking timeouts.
    """
    if (type(budget) not in (int, float) or not math.isfinite(budget)
            or budget <= 0):
        raise ProcessLifecycleError()
    deadline = time.monotonic() + budget

    def remaining(cap: float) -> float:
        # Never grant a new minimum timeout after the shared budget expired.
        return max(0.0, min(cap, deadline - time.monotonic()))

    try:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=remaining(3.0))
        except subprocess.TimeoutExpired:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=remaining(budget))
        if proc.poll() is None:
            raise ProcessLifecycleError()
    except BaseException:
        # Cancellation during cleanup must not leave our own child alive.
        # Last-resort kill does not reset the deadline, even at budget expiry.
        try:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=remaining(1.0))
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
