"""Unsafe Linux lock metadata/errors cannot stand in for ownership evidence."""
import errno
import json
import os
import sys
from unittest.mock import Mock

import pytest

from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux lock validation")


@pytest.mark.parametrize("fault", ["permissions", "contents", "hardlink", "fifo"])
def test_unsafe_lock_is_not_classified_stale(tmp_path, fault):
    path = tmp_path / "synthetic.lock"
    path.touch(mode=0o600)
    if fault == "permissions":
        path.chmod(0o644)
    elif fault == "contents":
        path.write_bytes(b"not an application lock")
    elif fault == "hardlink":
        os.link(path, tmp_path / "alias")
    else:
        path.unlink()
        os.mkfifo(path, 0o600)
    assert private._lock_state(path) == "unsafe"
    assert path.exists()


@pytest.mark.parametrize("code", [errno.ENOLCK, errno.EINVAL, errno.ENOSYS, errno.EACCES])
def test_flock_backend_failure_is_unknown_not_live(tmp_path, monkeypatch, code):
    import fcntl
    path = tmp_path / "synthetic.lock"
    path.touch(mode=0o600)
    monkeypatch.setattr(fcntl, "flock", Mock(side_effect=OSError(code, "synthetic")))
    assert private._lock_state(path) == "unsafe"


@pytest.mark.parametrize("code", [errno.EAGAIN])
def test_contention_is_still_live(tmp_path, monkeypatch, code):
    import fcntl
    path = tmp_path / "synthetic.lock"
    path.touch(mode=0o600)
    monkeypatch.setattr(fcntl, "flock", Mock(side_effect=OSError(code, "synthetic")))
    assert private._lock_state(path) == "live"


def test_unlock_error_is_not_a_successful_stale_probe(tmp_path, monkeypatch):
    import fcntl
    path = tmp_path / "synthetic.lock"
    path.touch(mode=0o600)
    monkeypatch.setattr(fcntl, "flock", Mock(side_effect=[None, OSError(errno.EIO, "synthetic")]))
    assert private._lock_state(path) == "unsafe"


@pytest.mark.parametrize("fault", ["permissions", "fifo", "uid"])
def test_opened_lock_is_revalidated_before_flock(tmp_path, monkeypatch, fault):
    import fcntl
    from types import SimpleNamespace
    path = tmp_path / "synthetic.lock"
    path.touch(mode=0o600)
    opened, original_stat = os.open, os.fstat
    descriptors = []

    def race(name, flags, *args, **kwargs):
        assert flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW
        if fault == "permissions":
            path.chmod(0o644)
        elif fault == "fifo":
            path.unlink()
            os.mkfifo(path, 0o600)
        fd = opened(name, flags, *args, **kwargs)
        descriptors.append(fd)
        return fd

    def foreign(fd):
        info = original_stat(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() + 1,
                               st_nlink=info.st_nlink, st_size=info.st_size)

    with monkeypatch.context() as patch:
        flock = Mock(side_effect=AssertionError("no flock on unverified object"))
        patch.setattr(private.os, "open", race)
        patch.setattr(fcntl, "flock", flock)
        if fault == "uid":
            patch.setattr(private.os, "fstat", foreign)
        assert private._lock_state(path) == "unsafe"
        flock.assert_not_called()
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_real_lock_lifecycle_is_preserved(tmp_path):
    path = tmp_path / "synthetic.lock"
    assert private._lock_state(path) == "missing"
    fd = private._acquire_lock(path)
    try:
        assert private._lock_state(path) == "live"
    finally:
        os.close(fd)  # like owner death: release lock but leave its file
    assert private._lock_state(path) == "stale"
    path.unlink()
    assert private._lock_state(path) == "missing"


@pytest.mark.parametrize("fault", ["metadata", "becomes_live", "becomes_unsafe"])
def test_recovery_rechecks_lock_before_any_identity_or_cleanup(tmp_path, monkeypatch, fault):
    ctx = private.RunContext(tmp_path / "private")
    ctx.__enter__()
    ctx.write_yaml({"password": "synthetic-only"})
    marker = ctx.run_dir / ".owner.json"
    data = json.loads(marker.read_bytes())
    data["owner_create_time"] += 1
    marker.write_text(json.dumps(data))
    ctx._drop_lock()
    lock = ctx._lock_path
    lock.touch(mode=0o600)
    if fault == "metadata":
        lock.write_bytes(b"not an application lock")
    before = {p.name: p.read_bytes() for p in ctx.run_dir.iterdir()}
    real_state = private._lock_state
    calls = 0

    def changing(path):
        nonlocal calls
        if path == lock:
            calls += 1
            return "stale" if calls == 1 else ("live" if fault == "becomes_live" else "unsafe")
        return real_state(path)

    try:
        with monkeypatch.context() as patch:
            if fault != "metadata":
                patch.setattr(private, "_lock_state", changing)
            owner, stop = Mock(), Mock()
            patch.setattr(private, "linux_owner_gone", owner)
            patch.setattr(private, "terminate_verified_process", stop)
            rows = private.recover_stale_runs(ctx.root)
            assert [r["error_code"] for r in rows] == ["RECOVERY_REVIEW_REQUIRED"]
            owner.assert_not_called()
            stop.assert_not_called()
        assert {p.name: p.read_bytes() for p in ctx.run_dir.iterdir()} == before
        assert lock.exists()
    finally:
        ctx.close()
        lock.unlink(missing_ok=True)


def test_unknown_lock_backend_blocks_new_run(tmp_path, monkeypatch):
    import fcntl
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    lock = root / ("a" * 32 + ".lock")
    lock.touch(mode=0o600)
    with monkeypatch.context() as patch:
        patch.setattr(fcntl, "flock", Mock(side_effect=OSError(errno.ENOLCK, "synthetic")))
        with pytest.raises(private.PrivateRunError, match="^RECOVERY_REVIEW_REQUIRED$"):
            with private.RunContext(root):
                pytest.fail("unknown locks must not be treated as concurrent live runs")
    assert list(root.iterdir()) == [lock]


def test_read_only_inspection_uses_same_empty_lock_policy(tmp_path):
    from nodelab.recovery_inspection import inspect_private_runs
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    lock = root / ("a" * 32 + ".lock")
    lock.write_bytes(b"unexpected contents")
    lock.chmod(0o600)
    rows = inspect_private_runs(root)
    assert rows == [{"line_number": 1, "reason": "LOCK_WITHOUT_DIRECTORY", "lock_state": "UNSAFE"}]
    assert lock.read_bytes() == b"unexpected contents"
