"""F1 private per-run YAML lifecycle; legacy business config is disabled.

The former sing-box-shaped config generator is intentionally unavailable
until F2 implements the fixed Mihomo v1.19.31 schema.  This module currently
provides only a protected temporary run and exact-child ownership for
synthetic safety tests; it is not authority to probe a real node.
"""

from __future__ import annotations

import base64
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

import yaml

from nodelab.mihomo_process import MihomoProcess, ProcessLifecycleError, stop_owned_process

PROBE_GROUP = "PROBE"
DELAY_URL = "https://www.gstatic.com/generate_204"
_PRIVATE_CODES = frozenset({
    "PRIVATE_DIR_UNSAFE", "RECOVERY_REVIEW_REQUIRED", "CONFIG_BUILD_FAILED",
    "SECRET_CLEANUP_FAILED", "PROBE_GATE_CLOSED", "PROCESS_START_FAILED",
})
_WINDOWS_ROOT = Path(r"E:\NodeLab.secrets\_runtime")
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


class RunContext:
    """Single owner for one private YAML and one exact Popen object.

    Stale entries in its dedicated root block future runs and require Owner
    review; an unverified PID is never killed. This is safer than global
    process-name cleanup and honest about OS-crash limitations.
    """

    def __init__(self, root: Path | None = None) -> None:
        if os.name == "nt":
            self.root = _WINDOWS_ROOT if root is None else Path(root)
            if self.root != _WINDOWS_ROOT:
                raise PrivateRunError()
        else:
            self.root = Path(root) if root is not None else Path(tempfile.gettempdir()) / ("nodelab-private-" + secrets.token_hex(16))
        self.run_dir: Path | None = None
        self.run_id: str | None = None
        self.process: MihomoProcess | None = None
        self.raw_child: subprocess.Popen | None = None
        self._windows_owner_sid: str | None = None
        self._private_tree_removed = False
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
        if any(self.root.iterdir()):
            # A crash cannot run finally; unverified remnants require review.
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

    def _write_marker(self, *, child_pid: int | None = None) -> None:
        assert self.run_dir is not None and self.run_id is not None
        marker = self.run_dir / ".owner.json"
        if not marker.exists():
            self._new_file(".owner.json")
        self._verify(marker, directory=False)
        # No credentials, URI, hostname, EXE path, or controller token here.
        value = {"run_id": self.run_id, "owner_pid": os.getpid(),
                 "created_at_epoch": int(time.time()), "child_pid": child_pid}
        with marker.open("w", encoding="utf-8") as f:
            json.dump(value, f, sort_keys=True)

    def __enter__(self) -> "RunContext":
        if self.active or self.closed or self.run_dir is not None:
            raise PrivateRunError()
        try:
            self._ensure_root()
            self.run_id = secrets.token_hex(16)
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
        self.active = False

    def write_yaml(self, value: dict[str, Any]) -> Path:
        """Exclusive empty file, read-back ACL, then write private YAML."""
        if not self.active or self.run_dir is None or not isinstance(value, dict):
            raise PrivateRunError()
        try:
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
            self._write_marker(child_pid=proc.pid)
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

    def close(self) -> None:
        if self.closed:
            return
        if self.run_dir is None:
            self.closed = True
            return
        # Stop the child first (contract E2), but a stop failure must never
        # skip deleting the plaintext: an orphaned synthetic child is far less
        # harmful than a credential left on disk.  Both steps always run and
        # a single fixed code reports if either one is not confirmed.
        stopped = self._stop_child()
        removed = self._remove_private_tree()
        if not (stopped and removed):
            # Never report a prior success if process/file cleanup is unknown.
            raise PrivateRunError("SECRET_CLEANUP_FAILED")
        self.closed = True
        self.active = False

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> bool:
        self.close()
        return False


def build_mihomo_yaml(*_args: Any, **_kwargs: Any) -> None:
    """Old generator emitted the wrong engine schema; do not use in F1."""
    raise PrivateRunError("PROBE_GATE_CLOSED")


def write_probe_config(*_args: Any, **_kwargs: Any) -> None:
    """Bare config paths had no owner on early failure; use RunContext."""
    raise PrivateRunError("PROBE_GATE_CLOSED")


def scrub_yaml_for_display(_yaml_text: str) -> str:
    """A YAML dump can contain multiline/custom secrets; never display it."""
    return "[CONFIG_REDACTED]"
