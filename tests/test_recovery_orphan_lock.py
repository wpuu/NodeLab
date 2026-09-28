"""Linux stale run-lock deletion must own the inode, not trust a probe."""
import os
import sys
from unittest.mock import Mock

import pytest
from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux run lock removal")


@pytest.mark.parametrize("entrypoint", ["helper", "recovery"])
def test_stale_observation_cannot_delete_now_held_run_lock(tmp_path, monkeypatch, entrypoint):
    tmp_path.chmod(0o700)
    lock = tmp_path / ("a" * 32 + ".lock")
    fd = private._acquire_lock(lock)
    inode = os.fstat(fd).st_ino
    try:
        monkeypatch.setattr(private, "_lock_state", Mock(return_value="stale"))
        if entrypoint == "helper":
            assert private._Recovery._remove_stale_lock(lock) == "RECOVERY_REVIEW_REQUIRED"
        else:
            rows = private.recover_stale_runs(tmp_path)
            assert rows == [private._recovery_row(1, "RECOVERY_REVIEW_REQUIRED")]
        assert lock.stat().st_ino == inode
    finally:
        os.close(fd)


def test_missing_lock_is_not_created(tmp_path, monkeypatch):
    lock = tmp_path / "missing.lock"
    opened = os.open

    def no_create(path, flags, *args):
        assert not flags & os.O_CREAT
        return opened(path, flags, *args)

    monkeypatch.setattr(private.os, "open", no_create)
    assert private._Recovery._remove_stale_lock(lock) is None
    assert list(tmp_path.iterdir()) == []


def test_stale_lock_is_held_at_unlink_and_descriptor_closed(tmp_path, monkeypatch):
    lock = tmp_path / "stale.lock"
    lock.touch(mode=0o600)
    original = type(lock).unlink
    descriptors = []
    opened = os.open

    def track(*args):
        fd = opened(*args)
        descriptors.append(fd)
        return fd

    def checked(path, *args, **kwargs):
        assert private._lock_state(path) == "live"
        return original(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(private.os, "open", track)
        patch.setattr(type(lock), "unlink", checked)
        assert private._Recovery._remove_stale_lock(lock) is None
    assert not lock.exists()
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("change", ["replace", "unlink", "unlink_error"])
def test_late_change_preserves_evidence_and_closes_fd(tmp_path, monkeypatch, change):
    import fcntl
    lock = tmp_path / "stale.lock"
    lock.touch(mode=0o600)
    original = fcntl.flock
    descriptors, replacement = [], []

    def race(fd, flags):
        original(fd, flags)
        descriptors.append(fd)
        if change != "unlink_error":
            lock.unlink()
            if change == "replace":
                lock.touch(mode=0o600)
                replacement.append(lock.stat().st_ino)

    with monkeypatch.context() as patch:
        patch.setattr(fcntl, "flock", race)
        if change == "unlink_error":
            patch.setattr(type(lock), "unlink", Mock(side_effect=PermissionError("synthetic")))
        assert private._Recovery._remove_stale_lock(lock) == "RECOVERY_REVIEW_REQUIRED"
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    if change == "replace":
        assert lock.stat().st_ino == replacement[0]
    else:
        assert lock.exists() == (change == "unlink_error")


@pytest.mark.parametrize("fault", ["contents", "permissions", "hardlink", "fifo", "symlink"])
def test_invalid_lock_is_preserved(tmp_path, fault):
    lock = tmp_path / "unsafe.lock"
    lock.touch(mode=0o600)
    if fault == "contents":
        lock.write_bytes(b"synthetic evidence")
    elif fault == "permissions":
        lock.chmod(0o644)
    elif fault == "hardlink":
        os.link(lock, tmp_path / "alias")
    elif fault == "fifo":
        lock.unlink()
        os.mkfifo(lock, 0o600)
    else:
        target = tmp_path / "target"
        lock.rename(target)
        lock.symlink_to(target)
    before = lock.lstat()
    assert private._Recovery._remove_stale_lock(lock) == "RECOVERY_REVIEW_REQUIRED"
    after = lock.lstat()
    assert (before.st_ino, before.st_mode, before.st_size) == (after.st_ino, after.st_mode, after.st_size)


def test_real_child_holding_run_lock_survives_stale_observation(tmp_path, monkeypatch):
    import select
    import subprocess
    lock = tmp_path / ("b" * 32 + ".lock")
    lock.touch(mode=0o600)
    inode = lock.stat().st_ino
    script = r'''
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print("ready", flush=True)
sys.stdin.readline()
os.close(fd)
'''
    child = subprocess.Popen([sys.executable, "-c", script, str(lock)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        assert select.select([child.stdout], [], [], 10)[0]
        assert child.stdout.readline() == b"ready\n"
        with monkeypatch.context() as patch:
            patch.setattr(private, "_lock_state", Mock(return_value="stale"))
            assert private.recover_stale_runs(tmp_path) == [private._recovery_row(1, "RECOVERY_REVIEW_REQUIRED")]
        assert child.poll() is None and lock.stat().st_ino == inode
        child.stdin.write(b"release\n")
        child.stdin.flush()
        assert child.wait(timeout=5) == 0
        assert private.recover_stale_runs(tmp_path) == [private._recovery_row(1, None)]
        assert not lock.exists()
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdin.close()
        child.stdout.close()
