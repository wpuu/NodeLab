"""F1 private per-run YAML lifecycle; legacy business config is disabled.

The former sing-box-shaped config generator is intentionally unavailable
until F2 implements the fixed Mihomo v1.19.31 schema.  This module currently
provides a protected temporary run and exact-child ownership for synthetic
safety tests and the internal F2 engine session; it is not authority to probe
a real node.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml

from nodelab.mihomo_process import (
    MihomoProcess, ProcessIdentity, ProcessLifecycleError, process_identity,
    stop_owned_process, terminate_verified_process,
)

PROBE_GROUP = "PROBE"
DELAY_URL = "https://www.gstatic.com/generate_204"
_PRIVATE_CODES = frozenset({
    "PRIVATE_DIR_UNSAFE", "RECOVERY_REVIEW_REQUIRED", "CONFIG_BUILD_FAILED",
    "SECRET_CLEANUP_FAILED", "PROBE_GATE_CLOSED", "PROCESS_START_FAILED",
})
_WINDOWS_ROOT = Path(r"E:\NodeLab.secrets\_runtime")
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_LOCK_SUFFIX = ".lock"
_RECOVER_LOCK = ".recover" + _LOCK_SUFFIX
_MARKER = ".owner.json"
_MARKER_MAX_BYTES = 4096
_LINUX_BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
_BOOT_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")


def _unique_marker_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("RECOVERY_REVIEW_REQUIRED")
        result[key] = value
    return result


def _linux_boot_fingerprint() -> str | None:
    """Bounded read of this boot, storing an opaque domain-separated digest."""
    try:
        with _LINUX_BOOT_ID.open("rb") as source:
            data = source.read(65)
        if len(data) > 64:
            return None
        value = data.decode("ascii", "strict").strip()
        if str(UUID(value)) != value:
            return None
        return hashlib.sha256(b"nodelab-linux-boot-v1\0" + value.encode("ascii")).hexdigest()
    except (OSError, ValueError, UnicodeError):
        return None

_ACL_CHECK_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$target = [Environment]::GetEnvironmentVariable('NODELAB_PRIVATE_PATH', 'Process')
$ownerSid = [Environment]::GetEnvironmentVariable('NODELAB_OWNER_SID', 'Process')
$acl = Get-Acl -LiteralPath $target
$identity = [System.Security.Principal.SecurityIdentifier]
if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical) { exit 2 }
if ($acl.Owner -ne $ownerSid) {
    $owner = [System.Security.Principal.NTAccount]::new($acl.Owner).Translate($identity).Value
    if ($owner -ne $ownerSid) { exit 2 }
}
$userSeen = $false; $systemSeen = $false
foreach ($ace in $acl.Access) {
    $sid = $ace.IdentityReference.Translate($identity).Value
    if ($ace.IsInherited -or $ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { exit 2 }
    if ($sid -ne $ownerSid -and $sid -ne 'S-1-5-18') { exit 2 }
    $full = [int][System.Security.AccessControl.FileSystemRights]::FullControl
    if (([int]$ace.FileSystemRights -band $full) -ne $full) { exit 2 }
    if ($sid -eq $ownerSid) { $userSeen = $true }
    if ($sid -eq 'S-1-5-18') { $systemSeen = $true }
}
if (-not $userSeen -or -not $systemSeen) { exit 2 }
exit 0
"""


class PrivateRunError(RuntimeError):
    """Only fixed diagnostic codes; neither path nor original error is public."""

    def __init__(self, code: str = "PRIVATE_DIR_UNSAFE") -> None:
        self.code = code if type(code) is str and code in _PRIVATE_CODES else "PRIVATE_DIR_UNSAFE"
        super().__init__(self.code)


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _verify_posix(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (_is_reparse(path) or not expected(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)):
        raise PrivateRunError()


def _windows_volume_ok(path: Path) -> bool:
    """Reject removable/network/non-NTFS volumes before creating a YAML."""
    import ctypes

    if len(path.drive) != 2 or path.drive[1] != ":" or not path.is_absolute():
        return False
    root = path.drive + "\\"
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel.GetDriveTypeW.restype = ctypes.c_uint
    if kernel.GetDriveTypeW(root) != 3:  # DRIVE_FIXED
        return False
    filesystem = ctypes.create_unicode_buffer(64)
    kernel.GetVolumeInformationW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint,
    ]
    kernel.GetVolumeInformationW.restype = ctypes.c_int
    return bool(kernel.GetVolumeInformationW(root, None, 0, None, None, None,
                                             filesystem, len(filesystem))) and filesystem.value.upper() == "NTFS"


def _windows_system_dir() -> Path:
    import ctypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel.GetSystemDirectoryW.restype = ctypes.c_uint
    buf = ctypes.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(buf, len(buf))
    if not length or length >= len(buf):
        raise PrivateRunError()
    return Path(buf.value)


def _windows_helper(script: str, *, path: Path | None = None, sid: str | None = None) -> subprocess.CompletedProcess[str]:
    system = _windows_system_dir()
    ps = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    env = {k: v for k, v in os.environ.items() if k.upper() in {
        "SYSTEMROOT", "WINDIR", "PATH", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "PSMODULEPATH",
    }}
    env["PATH"] = str(system)
    if path is not None:
        env["NODELAB_PRIVATE_PATH"] = str(path)
    if sid is not None:
        env["NODELAB_OWNER_SID"] = sid
    command = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return subprocess.run([str(ps), "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
                          env=env, capture_output=True, text=True, timeout=8, check=False)


def _windows_sid() -> str:
    result = _windows_helper("[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
    sid = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"S-1-\d+(?:-\d+)+", sid):
        raise PrivateRunError()
    return sid


def _verify_windows_acl(path: Path, sid: str) -> None:
    try:
        if _is_reparse(path):
            raise PrivateRunError()
        result = _windows_helper(_ACL_CHECK_SCRIPT, path=path, sid=sid)
        if result.returncode != 0:
            raise PrivateRunError()
    except (OSError, subprocess.SubprocessError, ValueError):
        raise PrivateRunError() from None


def _restrict_new_windows(path: Path, sid: str, *, directory: bool) -> None:
    """Only new, empty objects may be changed; existing ACLs are read-only."""
    system = _windows_system_dir()
    rights = "(OI)(CI)F" if directory else "F"
    cmd = [str(system / "icacls.exe"), str(path), "/inheritance:r", "/grant:r",
           f"*{sid}:{rights}", f"*S-1-5-18:{rights}"]
    try:
        env = {k: v for k, v in os.environ.items() if k.upper() in {
            "SYSTEMROOT", "WINDIR", "PATH", "USERPROFILE",
        }}
        env["PATH"] = str(system)
        result = subprocess.run(cmd, env=env, capture_output=True, timeout=8, check=False)
        if result.returncode != 0:
            raise PrivateRunError()
        _verify_windows_acl(path, sid)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise PrivateRunError() from None


def _check_clean_private_tree(path: Path) -> None:
    """Do not delete through links/junctions or paths not owned by this run."""
    pending = [path]
    while pending:
        current = pending.pop()
        if _is_reparse(current):
            raise PrivateRunError("SECRET_CLEANUP_FAILED")
        if current.is_dir():
            pending.extend(current.iterdir())



def _remove_payload_preserving_evidence(path: Path) -> None:
    """Linux failed-stop cleanup; keep only application recovery metadata.

    Staging files must also remain: deleting them could turn an ambiguous
    marker publication into an apparently recoverable old record. They are
    written without credentials, but still require the private directory.
    """
    _check_clean_private_tree(path)

    def metadata(entry: Path) -> bool:
        return entry.is_file() and (entry.name == _MARKER or
                                   (entry.name.startswith(".owner-") and entry.name.endswith(".tmp")))

    for entry in sorted(path.iterdir(), key=lambda p: p.name != "probe.yaml"):
        if metadata(entry):
            continue
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    if any(not metadata(entry) for entry in path.iterdir()):
        raise PrivateRunError("SECRET_CLEANUP_FAILED")


def _acquire_lock(path: Path) -> int:
    """Create `path` exclusively and hold an OS lock on it for this process.

    The OS releases the lock when the owning process dies for any reason,
    so liveness never depends on a (reusable) PID.  Windows additionally
    uses delete-on-close, so a dead owner leaves no lock file at all.
    Children never inherit the descriptor/handle.
    """
    if os.name == "nt":
        import msvcrt

        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOINHERIT | os.O_TEMPORARY, 0o600)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            os.close(fd)
            raise
        return fd
    import fcntl

    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise
    return fd


def _release_lock(path: Path, fd: int | None) -> None:
    if fd is None:
        return
    if os.name == "nt":
        import msvcrt

        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        os.close(fd)  # O_TEMPORARY removes the file with the last handle
        return
    try:
        path.unlink()  # unlink first: nobody can newly open a lock we are dropping
    except OSError:
        pass
    os.close(fd)  # flock is released with the descriptor


def _lock_state(path: Path) -> str:
    """'live' (held by a running process), 'stale' (nobody holds it), 'missing' or 'unsafe'."""
    try:
        if _is_reparse(path):
            return "unsafe"
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unsafe"
    if os.name == "nt":
        import msvcrt

        try:
            fd = os.open(path, os.O_RDWR | os.O_NOINHERIT)
        except PermissionError:
            return "live"  # sharing violation: a delete-on-close handle is open elsewhere
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "unsafe"
        try:
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                return "live"
            try:
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            return "stale"
        finally:
            os.close(fd)
    import fcntl

    try:
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unsafe"
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return "live"
        fcntl.flock(fd, fcntl.LOCK_UN)
        return "stale"
    finally:
        os.close(fd)


def _dir_fingerprint(path: Path) -> str:
    canonical = os.path.normcase(str(path.resolve(strict=False)))
    return hashlib.sha256(canonical.encode("utf-8", errors="surrogatepass")).hexdigest()[:32]


def _classify_root_entries(root: Path) -> tuple[int, list[Path]]:
    """Return (live run count, entries that need recovery/review).

    A live run is a `<run_id>` directory (or a lock alone, i.e. a run that is
    still being created/removed) whose `<run_id>.lock` is held by a running
    process.  Everything else -- stale runs, lone stale locks, unknown names,
    files, reparse points, a recovery in progress -- is reported.
    """
    live = 0
    review: list[Path] = []
    seen_ids: set[str] = set()
    for entry in sorted(root.iterdir()):
        name = entry.name
        if name == _RECOVER_LOCK:
            review.append(entry)  # recovery running (live) or crashed (stale): wait/recover
            continue
        run_id = name[:-len(_LOCK_SUFFIX)] if name.endswith(_LOCK_SUFFIX) else name
        if not _RUN_ID.fullmatch(run_id) or run_id in seen_ids:
            if not _RUN_ID.fullmatch(run_id):
                review.append(entry)
            continue
        seen_ids.add(run_id)
        run_dir = root / run_id
        lock = root / (run_id + _LOCK_SUFFIX)
        state = _lock_state(lock)
        if state == "live":
            live += 1
            continue
        if run_dir.exists() or run_dir.is_symlink():
            review.append(run_dir)
        if state != "missing":
            review.append(lock)
    return live, review


class RunContext:
    """Single owner for one private YAML and one exact Popen object.

    Concurrent live runs coexist under one root: each holds an OS lock that
    dies with its process.  Residue whose lock nobody holds is a crashed run;
    it blocks new runs (`RECOVERY_REVIEW_REQUIRED`) until the explicit
    `recover_stale_runs()` step verifies ownership, stops only an
    identity-verified child and deletes the plaintext.  Nothing is ever
    matched by process name, and an unverified PID is never signalled.
    """

    def __init__(self, root: Path | None = None) -> None:
        if os.name == "nt":
            self.root = _WINDOWS_ROOT if root is None else Path(root)
            if self.root != _WINDOWS_ROOT:
                raise PrivateRunError()
        else:
            self.root = Path(root) if root is not None else _default_posix_root()
        self.run_dir: Path | None = None
        self.run_id: str | None = None
        self.process: MihomoProcess | None = None
        self.raw_child: subprocess.Popen | None = None
        self._windows_owner_sid: str | None = None
        self._linux_boot: str | None = None
        self._private_tree_removed = False
        self._lock_path: Path | None = None
        self._lock_fd: int | None = None
        self.active = False
        self.closed = False

    def _ensure_root(self) -> None:
        if ".." in self.root.parts or not self.root.is_absolute():
            raise PrivateRunError()
        if os.name == "nt":
            if not _windows_volume_ok(self.root):
                raise PrivateRunError()
            sid = _windows_sid()
            self._windows_owner_sid = sid
            for path in (self.root.parent, self.root):
                if path.exists() or path.is_symlink():
                    _verify_windows_acl(path, sid)
                else:
                    path.mkdir(mode=0o700)  # no secret until ACL readback
                    _restrict_new_windows(path, sid, directory=True)
        else:
            if self.root.exists() or self.root.is_symlink():
                _verify_posix(self.root, directory=True)
            else:
                self.root.mkdir(mode=0o700)  # intentionally no parents=True
                _verify_posix(self.root, directory=True)
        _live, review = _classify_root_entries(self.root)
        if review:
            # A crash cannot run finally; unverified remnants require the
            # explicit recovery step.  Live concurrent runs do not block.
            raise PrivateRunError("RECOVERY_REVIEW_REQUIRED")

    def _verify(self, path: Path, *, directory: bool) -> None:
        if os.name == "nt":
            if self._windows_owner_sid is None:
                raise PrivateRunError()
            _verify_windows_acl(path, self._windows_owner_sid)
        else:
            _verify_posix(path, directory=directory)

    def _new_file(self, filename: str) -> Path:
        if not self.active or self.run_dir is None or filename not in {"probe.yaml", ".owner.json"}:
            raise PrivateRunError()
        path = self.run_dir / filename
        with path.open("x", encoding="utf-8"):
            pass  # create empty file exclusively, before writing any credential
        if os.name == "nt":
            _restrict_new_windows(path, self._windows_owner_sid, directory=False)
        else:
            path.chmod(0o600)
            self._verify(path, directory=False)
        return path

    def _write_marker(self, *, child: ProcessIdentity | None = None) -> None:
        assert self.run_dir is not None and self.run_id is not None
        if sys.platform == "linux":
            current_boot = _linux_boot_fingerprint()
            if (current_boot is None or
                    (self._linux_boot is not None and current_boot != self._linux_boot)):
                raise PrivateRunError("RECOVERY_REVIEW_REQUIRED")
            self._linux_boot = current_boot
        marker = self.run_dir / _MARKER
        if sys.platform == "linux":
            self._verify(self.run_dir, directory=True)
            if marker.exists() or marker.is_symlink():
                self._verify(marker, directory=False)
        else:
            if not marker.exists():
                self._new_file(_MARKER)
            self._verify(marker, directory=False)
        owner = process_identity(os.getpid())
        # No credentials, URI, hostname, EXE path, or controller token here:
        # only what recovery needs to prove "same process" and "same dir".
        value = {
            "run_id": self.run_id, "created_at_epoch": int(time.time()),
            "run_dir_fingerprint": _dir_fingerprint(self.run_dir),
            "owner_pid": os.getpid(),
            "owner_create_time": owner.create_time if owner else None,
            "owner_exe_fingerprint": owner.exe_fingerprint if owner else None,
            "child_pid": child.pid if child else None,
            "child_create_time": child.create_time if child else None,
            "child_exe_fingerprint": child.exe_fingerprint if child else None,
        }
        if sys.platform == "linux":
            value["linux_boot_fingerprint"] = self._linux_boot
        if sys.platform == "linux":
            self._publish_linux_marker(marker, value)
        else:
            with marker.open("w", encoding="utf-8") as f:
                json.dump(value, f, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())

    def _publish_linux_marker(self, marker: Path, value: dict[str, Any]) -> None:
        # Same-directory exclusive 0600 staging: interrupted serialization
        # cannot truncate the preceding complete record. A crash may leave a
        # staging file, which the existing recovery allowlist sends to review.
        fd, name = tempfile.mkstemp(prefix=".owner-", suffix=".tmp", dir=self.run_dir)
        temporary = Path(name)
        try:
            stream = os.fdopen(fd, "w", encoding="utf-8")
            fd = None  # stream now owns the descriptor even on serialization failure
            with stream:
                self._verify(temporary, directory=False)
                json.dump(value, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, marker)
            temporary = None  # publication happened; never unlink the new marker
            self._verify(marker, directory=False)
            directory_fd = os.open(self.run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                if fd is not None:
                    os.close(fd)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)

    def __enter__(self) -> "RunContext":
        if self.active or self.closed or self.run_dir is not None:
            raise PrivateRunError()
        try:
            self._ensure_root()
            self.run_id = secrets.token_hex(16)
            # Lock first, then mkdir: a concurrent scanner therefore never
            # sees a run directory whose lock is not yet held.
            self._lock_path = self.root / (self.run_id + _LOCK_SUFFIX)
            self._lock_fd = _acquire_lock(self._lock_path)
            self.run_dir = self.root / self.run_id
            self.run_dir.mkdir(mode=0o700)
            if os.name == "nt":
                _restrict_new_windows(self.run_dir, self._windows_owner_sid, directory=True)
            else:
                self._verify(self.run_dir, directory=True)
            self.active = True
            self._write_marker()
            return self
        except PrivateRunError:
            self._cleanup_empty_failed_enter()
            raise
        except (OSError, ValueError, subprocess.SubprocessError):
            self._cleanup_empty_failed_enter()
            raise PrivateRunError() from None

    def _cleanup_empty_failed_enter(self) -> None:
        if self.run_dir is not None:
            try:
                if self.run_dir.is_dir() and not _is_reparse(self.run_dir):
                    # No YAML can have been written before __enter__ succeeds.
                    shutil.rmtree(self.run_dir)
            except OSError:
                pass
        self._drop_lock()
        self.active = False

    def _drop_lock(self) -> None:
        if self._lock_fd is not None and self._lock_path is not None:
            _release_lock(self._lock_path, self._lock_fd)
        self._lock_fd = None

    def write_yaml(self, value: dict[str, Any]) -> Path:
        """Exclusive empty file, read-back ACL, then write private YAML.

        The same run may rewrite its own probe.yaml (e.g. one retry per port
        attempt, contract F.4); the existing file is re-verified as ours and
        truncated, never followed through a link.
        """
        if (not self.active or self.run_dir is None or not isinstance(value, dict)
                or self.raw_child is not None):
            raise PrivateRunError()
        try:
            path = self.run_dir / "probe.yaml"
            if path.exists() or path.is_symlink():
                if _is_reparse(path):
                    raise PrivateRunError()
            else:
                path = self._new_file("probe.yaml")
            self._verify(path, directory=False)
            text = yaml.safe_dump(value, allow_unicode=True, sort_keys=False)
            with path.open("w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            return path
        except PrivateRunError:
            raise
        except Exception:
            # PyYAML/custom mapping errors may themselves contain a secret.
            raise PrivateRunError("CONFIG_BUILD_FAILED") from None

    def _spawn_engine(self, exe: Path, *, config_test: bool = False) -> subprocess.Popen:
        """Internal: own the child immediately, before wrapper/marker work.

        The session verifies the pinned executable first. Only the fixed
        private YAML path and fixed engine flags can be passed here.
        """
        if (not self.active or self.closed or self.run_dir is None
                or self.raw_child is not None or self.process is not None):
            raise PrivateRunError("PROCESS_START_FAILED")
        try:
            path = self.run_dir / "probe.yaml"
            self._verify(self.run_dir, directory=True)
            if _is_reparse(path):
                raise PrivateRunError()
            self._verify(path, directory=False)
            command = [str(exe)] + (["-t"] if config_test else [])
            command += ["-d", str(self.run_dir), "-f", str(path)]
            proc = subprocess.Popen(
                command, cwd=str(self.run_dir), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
            )
            self.raw_child = proc
            self.process = MihomoProcess(proc)
            identity = process_identity(proc.pid)
            if identity is None or identity.exe_fingerprint is None:
                # A very short-lived -t may already be gone. It needs no
                # recovery identity, but a live unverifiable child is unsafe.
                if proc.poll() is None:
                    raise PrivateRunError("PROCESS_START_FAILED")
            self._write_marker(child=identity)
            return proc
        except PrivateRunError:
            raise
        except Exception:
            raise PrivateRunError("PROCESS_START_FAILED") from None

    def _finish_engine_check(self) -> None:
        """Reap -t before clearing its marker and allowing a runtime child."""
        if self.raw_child is None or self.raw_child.poll() is None:
            raise PrivateRunError("PROCESS_START_FAILED")
        if not self._stop_child():
            raise PrivateRunError("SECRET_CLEANUP_FAILED")
        try:
            self._write_marker()
        except PrivateRunError:
            raise
        except Exception:
            raise PrivateRunError("PROCESS_START_FAILED") from None
        self.process = None
        self.raw_child = None

    def spawn_synthetic_process(self) -> subprocess.Popen:
        """F1 synthetic child only, for proving own-PID cleanup without Mihomo."""
        if not self.active or self.run_dir is None or self.process is not None:
            raise PrivateRunError()
        try:
            env = {k: v for k, v in os.environ.items() if k.upper() in {
                "SYSTEMROOT", "WINDIR", "PATH", "PYTHONHOME", "PYTHONPATH",
            }}
            flags = 0x08000000 if os.name == "nt" else 0
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"], cwd=self.run_dir,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=env, creationflags=flags,
            )
            self.raw_child = proc  # retain ownership even if wrapper/marker raises
            self.process = MihomoProcess(proc)
            self._write_marker(child=process_identity(proc.pid))
            return proc
        except PrivateRunError:
            raise
        except Exception:
            raise PrivateRunError("PROCESS_START_FAILED") from None

    def _stop_child(self) -> bool:
        """Stop only the exact owned child; report, never raise."""
        try:
            if self.process is not None:
                self.process.close()
            elif self.raw_child is not None:
                stop_owned_process(self.raw_child)
        except (OSError, ValueError, ProcessLifecycleError):
            return False
        return True

    def _remove_private_tree(self) -> bool:
        """Delete this run's directory (plaintext YAML first); report, never raise."""
        if self._private_tree_removed:
            return True
        if self.run_dir is None:
            return False
        try:
            if self.run_dir.parent != self.root or not self.run_dir.is_dir():
                return False
            self._verify(self.root, directory=True)
            _check_clean_private_tree(self.run_dir)
            # rmtree unlinks files before their directory, so probe.yaml is
            # gone even if the directory itself is still a live child's cwd.
            shutil.rmtree(self.run_dir)
            if self.run_dir.exists() or self.run_dir.is_symlink():
                return False
        except (OSError, ValueError, PrivateRunError):
            return False
        self._private_tree_removed = True
        return True

    def _remove_private_payload(self) -> bool:
        """On Linux unknown stop, keep evidence without claiming tree removal."""
        if self.run_dir is None:
            return False
        try:
            if self.run_dir.parent != self.root:
                return False
            self._verify(self.root, directory=True)
            self._verify(self.run_dir, directory=True)
            _remove_payload_preserving_evidence(self.run_dir)
        except (OSError, ValueError, PrivateRunError):
            return False
        return True

    def close(self) -> None:
        if self.closed:
            return
        if self.run_dir is None:
            self.closed = True
            return
        # Stop the child first (contract E2), but a stop failure must never
        # skip deleting the plaintext. On Linux an unknown stop keeps the
        # non-secret recovery evidence, so a later owner crash need not lose
        # the last child identity. Neither payload removal nor retained
        # evidence is a successful close; the lock stays owned for retry.
        stopped = removed = False
        try:
            try:
                stopped = self._stop_child() is True
            except BaseException:
                # An unexpected wrapper error or cancellation must not bypass
                # the plaintext deletion attempt. Unknown stop remains FAIL;
                # do not reset its stop budget or kill a guessed replacement.
                pass
        finally:
            try:
                if not stopped and sys.platform == "linux":
                    removed = self._remove_private_payload() is True
                else:
                    removed = self._remove_private_tree() is True
            except BaseException:
                pass
        if not (stopped and removed):
            # Never report a prior success if process/file cleanup is unknown.
            # The lock stays held: the residue is still owned, not stale.
            # Suppress even an earlier body exception that may contain secrets.
            raise PrivateRunError("SECRET_CLEANUP_FAILED") from None
        try:
            self._drop_lock()
        except BaseException:
            # Lock release may have partially completed. Do not claim closed
            # or echo the underlying exception; a later close can retry.
            raise PrivateRunError("SECRET_CLEANUP_FAILED") from None
        self.closed = True
        self.active = False

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> bool:
        self.close()
        return False


def _default_posix_root() -> Path:
    # Stable per-user root so that crash residue is found again; a foreign
    # directory of the same name fails the uid/mode check, never gets used.
    return Path(tempfile.gettempdir()) / f"nodelab-private-{os.getuid()}"


def _recovery_row(number: int, code: str | None) -> dict[str, Any]:
    return {"line_number": number, "probe_status": None, "stage": "CLEANUP", "error_code": code}


class _Recovery:
    """Verified recovery of ONE private root; see recover_stale_runs()."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.sid: str | None = None

    def verify(self, path: Path, *, directory: bool) -> None:
        if os.name == "nt":
            if self.sid is None:
                self.sid = _windows_sid()
            _verify_windows_acl(path, self.sid)
        else:
            _verify_posix(path, directory=directory)

    def read_marker(self, run_dir: Path) -> dict[str, Any] | None:
        marker = run_dir / _MARKER
        if not marker.is_file() or _is_reparse(marker) or marker.stat().st_size > _MARKER_MAX_BYTES:
            return None
        self.verify(marker, directory=False)
        try:
            data = json.loads(marker.read_text(encoding="utf-8"), object_pairs_hook=_unique_marker_fields)
        except (ValueError, UnicodeError):
            return None
        if not isinstance(data, dict) or data.get("run_id") != run_dir.name:
            return None
        if data.get("run_dir_fingerprint") != _dir_fingerprint(run_dir):
            return None
        if sys.platform == "linux":
            recorded = data.get("linux_boot_fingerprint")
            current = _linux_boot_fingerprint()
            # Legacy/unreadable/other-boot records cannot authorize PID lookup,
            # signalling or automatic removal. Never silently rebind them.
            if (type(recorded) is not str or not _BOOT_FINGERPRINT.fullmatch(recorded)
                    or current is None or recorded != current):
                return None
        for key in ("owner_pid", "child_pid", "owner_create_time", "child_create_time"):
            if data.get(key) is not None and type(data.get(key)) is not int:
                return None
        for key in ("owner_exe_fingerprint", "child_exe_fingerprint"):
            if data.get(key) is not None and type(data.get(key)) is not str:
                return None
        return data

    def recover_dir(self, run_dir: Path) -> str | None:
        """Return None when fully recovered, else the fixed code."""
        if _is_reparse(run_dir) or not run_dir.is_dir():
            return "RECOVERY_REVIEW_REQUIRED"
        self.verify(run_dir, directory=True)
        entries = {entry.name for entry in run_dir.iterdir()}
        if not entries <= {_MARKER, "probe.yaml"}:
            return "RECOVERY_REVIEW_REQUIRED"  # not a tree this application creates
        marker = self.read_marker(run_dir) if _MARKER in entries else None
        if marker is None and _MARKER in entries:
            return "RECOVERY_REVIEW_REQUIRED"
        stop_failed = False
        if marker is not None:
            owner_pid, owner_stamp = marker.get("owner_pid"), marker.get("owner_create_time")
            if owner_pid is not None and owner_stamp is not None:
                owner = ProcessIdentity(owner_pid, owner_stamp, marker.get("owner_exe_fingerprint"))
                if owner.matches(process_identity(owner_pid)):
                    return "RECOVERY_REVIEW_REQUIRED"  # owner alive without its lock: never touch
            child_pid, child_stamp = marker.get("child_pid"), marker.get("child_create_time")
            if child_pid is not None and child_stamp is not None:
                child = ProcessIdentity(child_pid, child_stamp, marker.get("child_exe_fingerprint"))
                try:
                    stop_failed = terminate_verified_process(child) is not True
                except BaseException:
                    if sys.platform != "linux":
                        raise
                    # Like owned close, cancellation/unknown stop must not
                    # bypass plaintext cleanup or erase recovery evidence.
                    stop_failed = True
            elif child_pid is not None:
                stop_failed = True  # child recorded but unverifiable: report, never kill
        if stop_failed and sys.platform == "linux":
            _remove_payload_preserving_evidence(run_dir)
            return "PROCESS_STOP_FAILED"
        _check_clean_private_tree(run_dir)
        shutil.rmtree(run_dir)
        if run_dir.exists() or run_dir.is_symlink():
            return "SECRET_CLEANUP_FAILED"
        return "PROCESS_STOP_FAILED" if stop_failed else None

    @staticmethod
    def _remove_stale_lock(lock: Path) -> str | None:
        state = _lock_state(lock)
        if state in {"missing", "live"}:
            return None  # nothing left, or (re)acquired by a live run meanwhile
        if state != "stale":
            return "RECOVERY_REVIEW_REQUIRED"
        lock.unlink()
        return None

    def run(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        _live, review = _classify_root_entries(self.root)
        for entry in review:
            number = len(rows) + 1
            if entry.name == _RECOVER_LOCK:
                continue  # our own recovery lock
            try:
                if entry.name.endswith(_LOCK_SUFFIX):
                    if (self.root / entry.name[:-len(_LOCK_SUFFIX)]) in review:
                        continue  # already handled together with its run directory
                    state = _lock_state(entry)  # a lock without a directory
                    if state == "live":
                        continue  # a run started meanwhile; it is not residue
                    if state == "stale":
                        entry.unlink()
                    if state in {"stale", "missing"}:
                        rows.append(_recovery_row(number, None))
                    else:
                        rows.append(_recovery_row(number, "RECOVERY_REVIEW_REQUIRED"))
                    continue
                if not _RUN_ID.fullmatch(entry.name):
                    rows.append(_recovery_row(number, "RECOVERY_REVIEW_REQUIRED"))
                    continue
                code = self.recover_dir(entry)
                if code is None or (code == "PROCESS_STOP_FAILED" and sys.platform != "linux"):
                    lock_code = self._remove_stale_lock(self.root / (entry.name + _LOCK_SUFFIX))
                    code = code or lock_code
                rows.append(_recovery_row(number, code))
            except (OSError, ValueError, PrivateRunError, ProcessLifecycleError):
                rows.append(_recovery_row(number, "SECRET_CLEANUP_FAILED"))
        return rows


def recover_stale_runs(root: Path | None = None) -> list[dict[str, Any]]:
    """Explicit crash recovery for the private root (CLI: `nodelab recover --confirm`).

    Only directories this application created (run-id name, verified ACL/
    mode, marker naming this very directory) are touched.  A recorded child
    is terminated only while its pid, creation stamp and executable digest
    still match the marker. Untrusted records require review and remain
    untouched. On Linux an unconfirmed child stop removes payload but keeps
    recovery metadata and reports PROCESS_STOP_FAILED (or cleanup failure).
    Live runs are skipped.
    Returns one fixed-shape row per handled entry (no paths, no ids).
    """
    probe = RunContext(root)  # applies the same root rules, never enters
    root_path = probe.root
    if not root_path.exists() and not root_path.is_symlink():
        return []
    recovery = _Recovery(root_path)
    if os.name == "nt":
        if not _windows_volume_ok(root_path):
            raise PrivateRunError()
        recovery.sid = _windows_sid()
        for path in (root_path.parent, root_path):
            _verify_windows_acl(path, recovery.sid)
    else:
        _verify_posix(root_path, directory=True)
    lock_path = root_path / _RECOVER_LOCK
    try:
        fd = _acquire_lock(lock_path)
    except FileExistsError:
        if _lock_state(lock_path) != "stale":
            raise PrivateRunError("RECOVERY_REVIEW_REQUIRED") from None  # another recovery is running
        lock_path.unlink()
        fd = _acquire_lock(lock_path)
    except OSError:
        raise PrivateRunError("RECOVERY_REVIEW_REQUIRED") from None
    try:
        return recovery.run()
    finally:
        _release_lock(lock_path, fd)


def build_mihomo_yaml(*_args: Any, **_kwargs: Any) -> None:
    """Old generator emitted the wrong engine schema; do not use in F1."""
    raise PrivateRunError("PROBE_GATE_CLOSED")


def write_probe_config(*_args: Any, **_kwargs: Any) -> None:
    """Bare config paths had no owner on early failure; use RunContext."""
    raise PrivateRunError("PROBE_GATE_CLOSED")


def scrub_yaml_for_display(_yaml_text: str) -> str:
    """A YAML dump can contain multiline/custom secrets; never display it."""
    return "[CONFIG_REDACTED]"
