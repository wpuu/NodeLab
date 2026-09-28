"""Bounded Linux residue inspection: no cleanup, signals or lock acquisition."""
from __future__ import annotations

import itertools
import os
from pathlib import Path
import sys

from nodelab import mihomo_config as private

_ENTRY_LIMIT = 256


def _entries(path: Path) -> list[Path]:
    # Path.iterdir may materialize os.listdir on supported Python versions.
    # scandir keeps the enumeration itself bounded, not just the final list.
    with os.scandir(path) as source:
        entries = [path / entry.name for entry in itertools.islice(source, _ENTRY_LIMIT + 1)]
    if len(entries) > _ENTRY_LIMIT:
        raise private.PrivateRunError("RECOVERY_INSPECTION_LIMIT")
    return sorted(entries)


def _lock_description(path: Path) -> str:
    # Deliberately do NOT probe flock: presence is not proof of live ownership.
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "ABSENT"
    except OSError:
        return "UNSAFE"
    if not private._linux_lock_metadata(info):
        return "UNSAFE"
    return "PRESENT_UNCHECKED"


def _reason(path: Path, recovery: private._Recovery) -> str:
    try:
        private._verify_posix(path, directory=True)
    except (OSError, ValueError, private.PrivateRunError):
        return "ENTRY_UNSAFE"
    names = {p.name for p in _entries(path)}
    if private._LAUNCH_PENDING in names:
        return "LAUNCH_PENDING"
    if any(name.startswith(".owner-") and name.endswith(".tmp") for name in names):
        return "MARKER_STAGING_PRESENT"
    if not names <= {private._MARKER, "probe.yaml"}:
        return "UNEXPECTED_CONTENT"
    if private._MARKER not in names:
        return "MARKER_MISSING"
    try:
        marker = recovery.read_marker(path)
    except (OSError, ValueError, private.PrivateRunError):
        return "MARKER_INVALID"
    # This is just static record validation: owner/child identities are never
    # queried. Do not call this safe, stale, recoverable or authorized.
    return "RECOVERY_CHECK_REQUIRED" if marker is not None else "MARKER_INVALID"


def inspect_private_runs(root: Path | None = None) -> list[dict]:
    if sys.platform != "linux":
        raise private.PrivateRunError("RECOVERY_INSPECTION_UNSUPPORTED")
    path = Path(root) if root is not None else private._default_posix_root()
    if not path.is_absolute() or ".." in path.parts:
        raise private.PrivateRunError()
    if not path.exists() and not path.is_symlink():
        return []  # no mkdir and no recovery lock
    private._verify_posix(path, directory=True)
    entries = _entries(path)
    names = {entry.name for entry in entries}
    seen = set()
    rows = []
    recovery = private._Recovery(path)
    for entry in entries:
        name = entry.name
        if name == private._RECOVER_LOCK:
            reason, lock = "RECOVERY_LOCK_PRESENT", _lock_description(entry)
        else:
            run_id = name[:-len(private._LOCK_SUFFIX)] if name.endswith(private._LOCK_SUFFIX) else name
            if not private._RUN_ID.fullmatch(run_id):
                reason, lock = "UNRECOGNIZED_ENTRY", "NOT_APPLICABLE"
            else:
                if run_id in seen:
                    continue
                seen.add(run_id)
                lock = _lock_description(path / (run_id + private._LOCK_SUFFIX))
                reason = _reason(path / run_id, recovery) if run_id in names else "LOCK_WITHOUT_DIRECTORY"
        rows.append({"line_number": len(rows) + 1, "reason": reason, "lock_state": lock})
    return rows
