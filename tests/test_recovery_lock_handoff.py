"""Recovery lock takeover must bind and hold the existing inode, not replace it."""
import os
import sys
from unittest.mock import Mock

import pytest

from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux recovery-lock handoff")


@pytest.fixture
def root(tmp_path):
    path = tmp_path / "private"
    path.mkdir(mode=0o700)
    return path


def test_stale_observation_cannot_replace_a_now_held_lock(root, monkeypatch):
    lock = root / ".recover.lock"
    holder = private._acquire_lock(lock)
    inode = os.fstat(holder).st_ino
    try:
        with monkeypatch.context() as patch:
            # Models a stale observation made before another recoverer acquired
            # the inode; actual flock contention, not merely a status string.
            patch.setattr(private, "_lock_state", Mock(return_value="stale"))
            body = Mock(return_value=[])
            patch.setattr(private._Recovery, "run", body)
            with pytest.raises(private.PrivateRunError, match="^RECOVERY_REVIEW_REQUIRED$"):
                private.recover_stale_runs(root)
            body.assert_not_called()
        assert lock.stat().st_ino == inode
    finally:
        os.close(holder)
        lock.unlink(missing_ok=True)


def test_stale_recovery_lock_is_taken_over_without_recreating_inode(root, monkeypatch):
    lock = root / ".recover.lock"
    lock.touch(mode=0o600)
    reference = os.open(lock, os.O_RDONLY)  # pins old inode but does NOT lock it
    inode = os.fstat(reference).st_ino

    def body(recovery):
        assert lock.stat().st_ino == inode
        assert private._lock_state(lock) == "live"
        return []

    try:
        with monkeypatch.context() as patch:
            patch.setattr(private._Recovery, "run", body)
            assert private.recover_stale_runs(root) == []
        assert not lock.exists()
    finally:
        os.close(reference)


@pytest.mark.parametrize("change", ["replace", "unlink"])
def test_path_change_after_flock_cannot_enter_recovery(root, monkeypatch, change):
    import fcntl
    lock = root / ".recover.lock"
    lock.touch(mode=0o600)
    original = fcntl.flock
    descriptors = []
    replacement = []

    def changed(fd, operation):
        original(fd, operation)
        descriptors.append(fd)
        lock.unlink()
        if change == "replace":
            lock.touch(mode=0o600)
            replacement.append(lock.stat().st_ino)

    with monkeypatch.context() as patch:
        body = Mock(return_value=[])
        patch.setattr(private._Recovery, "run", body)
        patch.setattr(fcntl, "flock", changed)
        with pytest.raises(private.PrivateRunError, match="^RECOVERY_REVIEW_REQUIRED$"):
            private.recover_stale_runs(root)
        body.assert_not_called()
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    if change == "replace":
        assert lock.stat().st_ino == replacement[0]
    else:
        assert not lock.exists()


def test_release_preserves_replacement_lock_and_closes_original_fd(root, monkeypatch):
    lock = root / ".recover.lock"
    original_open = os.open
    descriptors, replacement = [], []

    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        descriptors.append(fd)
        return fd

    def body(recovery):
        lock.unlink()
        lock.touch(mode=0o600)
        replacement.append(lock.stat().st_ino)
        return []

    with monkeypatch.context() as patch:
        patch.setattr(private.os, "open", opened)
        patch.setattr(private._Recovery, "run", body)
        with pytest.raises(private.PrivateRunError, match="^RECOVERY_REVIEW_REQUIRED$"):
            private.recover_stale_runs(root)
    assert lock.stat().st_ino == replacement[0]
    assert len(descriptors) == 2  # held lock plus replacement touch
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


@pytest.mark.parametrize("fault", ["contents", "permissions", "hardlink", "fifo", "symlink"])
def test_invalid_existing_recovery_lock_is_never_replaced(root, monkeypatch, fault):
    lock = root / ".recover.lock"
    lock.touch(mode=0o600)
    external = root / "synthetic-target"
    if fault == "contents":
        lock.write_bytes(b"synthetic evidence")
    elif fault == "permissions":
        lock.chmod(0o644)
    elif fault == "hardlink":
        os.link(lock, external)
    elif fault == "fifo":
        lock.unlink()
        os.mkfifo(lock, 0o600)
    else:
        lock.rename(external)
        lock.symlink_to(external)
    before = lock.lstat()
    with monkeypatch.context() as patch:
        body = Mock(return_value=[])
        patch.setattr(private._Recovery, "run", body)
        with pytest.raises(private.PrivateRunError, match="^RECOVERY_REVIEW_REQUIRED$"):
            private.recover_stale_runs(root)
        body.assert_not_called()
    after = lock.lstat()
    assert (after.st_ino, after.st_mode, after.st_size) == (before.st_ino, before.st_mode, before.st_size)


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
def test_failed_acquisition_closes_fd_without_unlinking_evidence(root, monkeypatch, error_type):
    import fcntl
    lock = root / ".recover.lock"
    descriptors = []
    original_open = os.open

    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        descriptors.append(fd)
        assert not os.get_inheritable(fd)
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(private.os, "open", opened)
        patch.setattr(fcntl, "flock", Mock(side_effect=error_type("synthetic")))
        expected = private.PrivateRunError if error_type is OSError else error_type
        with pytest.raises(expected):
            private.recover_stale_runs(root)
    assert lock.exists() and lock.stat().st_size == 0
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert private.recover_stale_runs(root) == []  # stale inode is safely retryable
    assert not lock.exists()


def test_body_error_still_releases_only_its_recovery_lock(root, monkeypatch):
    lock = root / ".recover.lock"
    with monkeypatch.context() as patch:
        patch.setattr(private._Recovery, "run", Mock(side_effect=ValueError("synthetic")))
        with pytest.raises(ValueError):
            private.recover_stale_runs(root)
    assert not lock.exists()
    assert private.recover_stale_runs(root) == []


def test_two_real_recoverers_cannot_enter_on_the_same_stale_lock(root):
    import select
    import subprocess
    lock = root / ".recover.lock"
    lock.touch(mode=0o600)
    reference = os.open(lock, os.O_RDONLY)
    inode = os.fstat(reference).st_ino
    script = r'''
import sys
from pathlib import Path
from nodelab import mihomo_config as private

def body(self):
    print("entered", flush=True)
    sys.stdin.readline()
    return []

private._Recovery.run = body
print("ready", flush=True)
sys.stdin.readline()
try:
    private.recover_stale_runs(Path(sys.argv[1]))
except private.PrivateRunError:
    print("blocked", flush=True)
else:
    print("done", flush=True)
'''
    children = []

    def read(child):
        assert select.select([child.stdout], [], [], 10)[0]
        return child.stdout.readline()

    try:
        for _ in range(2):
            children.append(subprocess.Popen([sys.executable, "-c", script, str(root)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL))
        for child in children:
            assert read(child) == b"ready\n"
        for child in children:
            child.stdin.write(b"go\n")
            child.stdin.flush()
        results = [read(child) for child in children]
        assert sorted(results) == [b"blocked\n", b"entered\n"]
        assert lock.stat().st_ino == inode  # no unlink/recreate even on stale takeover
        winner = children[results.index(b"entered\n")]
        winner.stdin.write(b"release\n")
        winner.stdin.flush()
        assert read(winner) == b"done\n"
        for child in children:
            assert child.wait(timeout=5) == 0
        assert list(root.iterdir()) == []
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()
        os.close(reference)
