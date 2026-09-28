"""Run-directory recovery holds its run lock throughout the body."""
import os
import sys
from unittest.mock import Mock

import pytest
from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux run recovery transaction')


@pytest.fixture
def residue(tmp_path):
    tmp_path.chmod(0o700)
    directory = tmp_path / ('a' * 32)
    directory.mkdir(mode=0o700)
    return directory, tmp_path / (directory.name + '.lock')


@pytest.mark.parametrize('existing', [True, False])
def test_body_holds_run_lock(residue, monkeypatch, existing):
    directory, lock = residue
    if existing:
        lock.touch(mode=0o600)
    def body(self, path):
        assert path == directory
        assert private._lock_state(lock) == 'live'
        path.rmdir()
        return None
    monkeypatch.setattr(private._Recovery, 'recover_dir', body)
    assert private.recover_stale_runs(directory.parent) == [private._recovery_row(1, None)]
    assert not lock.exists()


def test_stale_observation_does_not_authorize_body(residue, monkeypatch):
    directory, lock = residue
    fd = private._acquire_lock(lock)
    try:
        monkeypatch.setattr(private, '_lock_state', Mock(return_value='stale'))
        body = Mock(return_value=None)
        monkeypatch.setattr(private._Recovery, 'recover_dir', body)
        assert private.recover_stale_runs(directory.parent) == [private._recovery_row(1, 'RECOVERY_REVIEW_REQUIRED')]
        body.assert_not_called()
        assert lock.stat().st_ino == os.fstat(fd).st_ino
    finally:
        os.close(fd)


@pytest.mark.parametrize('existing', [True, False])
@pytest.mark.parametrize('outcome', ['RECOVERY_REVIEW_REQUIRED', 'PROCESS_STOP_FAILED', 'error', 'cancel'])
def test_failed_body_keeps_stale_lock_and_closes_fd(residue, monkeypatch, existing, outcome):
    directory, lock = residue
    if existing:
        lock.touch(mode=0o600)
    def body(self, path):
        assert private._lock_state(lock) == 'live'
        if outcome == 'error':
            raise OSError('synthetic')
        if outcome == 'cancel':
            raise KeyboardInterrupt()
        return outcome
    monkeypatch.setattr(private._Recovery, 'recover_dir', body)
    if outcome == 'cancel':
        with pytest.raises(KeyboardInterrupt):
            private.recover_stale_runs(directory.parent)
    else:
        expected = 'SECRET_CLEANUP_FAILED' if outcome == 'error' else outcome
        assert private.recover_stale_runs(directory.parent) == [private._recovery_row(1, expected)]
    assert directory.exists()
    assert private._lock_state(lock) == 'stale'
    assert not (directory.parent / '.recover.lock').exists()


def test_release_does_not_delete_replacement(residue, monkeypatch):
    directory, lock = residue
    def body(self, path):
        lock.unlink()
        lock.touch(mode=0o600)
        path.rmdir()
        return None
    monkeypatch.setattr(private._Recovery, 'recover_dir', body)
    assert private.recover_stale_runs(directory.parent) == [private._recovery_row(1, 'SECRET_CLEANUP_FAILED')]
    assert lock.exists() and not directory.exists()  # no rollback claim
    assert private._lock_state(lock) == 'stale'


def test_real_competitor_is_blocked_through_recovery_body(residue, monkeypatch):
    import subprocess
    directory, lock = residue
    script = r'''
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(42)
finally:
    os.close(fd)
sys.exit(0)
'''
    def body(self, path):
        result = subprocess.run([sys.executable, '-c', script, str(lock)],
                                capture_output=True, timeout=10)
        assert result.returncode == 42
        return 'RECOVERY_REVIEW_REQUIRED'
    monkeypatch.setattr(private._Recovery, 'recover_dir', body)
    assert private.recover_stale_runs(directory.parent) == [private._recovery_row(1, 'RECOVERY_REVIEW_REQUIRED')]
    assert subprocess.run([sys.executable, '-c', script, str(lock)], capture_output=True, timeout=10).returncode == 0


def test_owner_child_and_tree_cleanup_all_run_under_lock(tmp_path, monkeypatch):
    import json
    ctx = private.RunContext(tmp_path / 'private')
    ctx.__enter__()
    ctx.write_yaml({'password': 'synthetic'})
    marker = ctx.run_dir / '.owner.json'
    data = json.loads(marker.read_bytes())
    data.update(child_pid=123, child_create_time=456, child_exe_fingerprint='a' * 32)
    marker.write_text(json.dumps(data))
    ctx._drop_lock()
    phases = []
    original = private.shutil.rmtree
    def checked(phase):
        assert private._lock_state(ctx._lock_path) == 'live'
        phases.append(phase)
        return True
    def cleanup(path):
        checked('tree')
        original(path)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(private, 'linux_owner_gone', lambda identity: checked('owner'))
            patch.setattr(private, 'terminate_verified_process', lambda identity: checked('child'))
            patch.setattr(private.shutil, 'rmtree', cleanup)
            assert private.recover_stale_runs(ctx.root) == [private._recovery_row(1, None)]
        assert phases == ['owner', 'child', 'tree']
    finally:
        if not ctx.run_dir.exists():
            ctx._private_tree_removed = True
        ctx.close()
