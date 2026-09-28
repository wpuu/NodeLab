"""Linux startup publication and recovery share root-lock admission."""
import os
import sys
from unittest.mock import Mock

import pytest
from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux root admission')


def test_recovery_starting_after_initial_scan_blocks_startup(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    ensure = ctx._ensure_root
    holder = []
    def race():
        ensure()
        holder.append(private._acquire_linux_recovery_lock(ctx.root / '.recover.lock'))
    monkeypatch.setattr(ctx, '_ensure_root', race)
    try:
        with pytest.raises(private.PrivateRunError, match='RECOVERY_REVIEW_REQUIRED'):
            ctx.__enter__()
        assert ctx.run_dir is None
    finally:
        ctx.close()
        if holder:
            private._release_linux_recovery_lock(ctx.root / '.recover.lock', holder[0])


def test_recovery_cannot_enter_during_initial_marker_publication(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    write = ctx._write_marker
    def checked():
        assert private._lock_state(ctx.root / '.recover.lock') == 'live'
        with pytest.raises(private.PrivateRunError, match='RECOVERY_REVIEW_REQUIRED'):
            private.recover_stale_runs(ctx.root)
        write()
    monkeypatch.setattr(ctx, '_write_marker', checked)
    try:
        ctx.__enter__()
        assert not (ctx.root / '.recover.lock').exists()
    finally:
        ctx.close()


def test_late_residue_is_rechecked_under_admission(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    ensure = ctx._ensure_root
    def race():
        ensure()
        (ctx.root / 'unexpected').write_bytes(b'synthetic')
    monkeypatch.setattr(ctx, '_ensure_root', race)
    try:
        with pytest.raises(private.PrivateRunError, match='RECOVERY_REVIEW_REQUIRED'):
            ctx.__enter__()
        assert ctx.run_dir is None
        assert (ctx.root / 'unexpected').read_bytes() == b'synthetic'
    finally:
        ctx.close()


def test_late_stale_root_lock_is_not_taken_over(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    ensure = ctx._ensure_root
    inode = []
    def race():
        ensure()
        lock = ctx.root / '.recover.lock'
        lock.touch(mode=0o600)
        inode.append(lock.stat().st_ino)
    monkeypatch.setattr(ctx, '_ensure_root', race)
    with pytest.raises(private.PrivateRunError, match='RECOVERY_REVIEW_REQUIRED'):
        ctx.__enter__()
    assert (ctx.root / '.recover.lock').stat().st_ino == inode[0]
    assert ctx.run_dir is None
    assert private.recover_stale_runs(ctx.root) == []


@pytest.mark.parametrize('fault', [OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_failed_publication_closes_both_locks(tmp_path, monkeypatch, fault):
    ctx = private.RunContext(tmp_path / 'private')
    monkeypatch.setattr(ctx, '_write_marker', Mock(side_effect=fault('synthetic')))
    expected = private.PrivateRunError if fault in (OSError, ValueError) else fault
    with pytest.raises(expected):
        ctx.__enter__()
    assert not ctx.active and ctx._lock_fd is None
    assert list(ctx.root.iterdir()) == []
    assert private.recover_stale_runs(ctx.root) == []


def test_root_lock_replacement_on_release_fails_and_cleans_partial_run(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    write = ctx._write_marker
    inode = []
    def replaced():
        write()
        lock = ctx.root / '.recover.lock'
        lock.unlink()
        lock.touch(mode=0o600)
        inode.append(lock.stat().st_ino)
    monkeypatch.setattr(ctx, '_write_marker', replaced)
    with pytest.raises(private.PrivateRunError, match='RECOVERY_REVIEW_REQUIRED'):
        ctx.__enter__()
    assert not ctx.active and ctx._lock_fd is None
    assert not ctx.run_dir.exists()
    assert (ctx.root / '.recover.lock').stat().st_ino == inode[0]
    assert private._lock_state(ctx.root / '.recover.lock') == 'stale'


def test_live_runs_can_still_coexist_and_recovery_skips_them(tmp_path):
    root = tmp_path / 'private'
    with private.RunContext(root) as first, private.RunContext(root) as second:
        assert first.run_id != second.run_id
        assert private._lock_state(first._lock_path) == 'live'
        assert private._lock_state(second._lock_path) == 'live'
        assert private.recover_stale_runs(root) == []
        assert first.run_dir.exists() and second.run_dir.exists()
    assert list(root.iterdir()) == []


def test_real_recovery_process_blocked_during_startup(tmp_path, monkeypatch):
    import subprocess
    ctx = private.RunContext(tmp_path / 'private')
    write = ctx._write_marker
    script = r'''
import sys
from pathlib import Path
from nodelab import mihomo_config as private
try:
    private.recover_stale_runs(Path(sys.argv[1]))
except private.PrivateRunError as error:
    sys.exit(42 if str(error) == "RECOVERY_REVIEW_REQUIRED" else 43)
sys.exit(0)
'''
    def attempt():
        return subprocess.run([sys.executable, '-c', script, str(ctx.root)],
                              capture_output=True, timeout=10).returncode
    def checked():
        assert attempt() == 42
        write()
    monkeypatch.setattr(ctx, '_write_marker', checked)
    try:
        ctx.__enter__()
        assert attempt() == 0
        assert ctx.run_dir.exists() and private._lock_state(ctx._lock_path) == 'live'
    finally:
        ctx.close()


def test_second_startup_during_publication_is_refused_without_deleting_first(tmp_path, monkeypatch):
    first = private.RunContext(tmp_path / 'private')
    second = private.RunContext(first.root)
    write = first._write_marker
    def checked():
        with pytest.raises(private.PrivateRunError, match='RECOVERY_REVIEW_REQUIRED'):
            second.__enter__()
        assert first.run_dir.exists()
        assert private._lock_state(first._lock_path) == 'live'
        write()
    monkeypatch.setattr(first, '_write_marker', checked)
    try:
        first.__enter__()
        assert second.run_dir is None
    finally:
        first.close()
        second.close()
