"""A live Linux context must not clean a replacement run directory."""
import os
import shutil
import sys
from unittest.mock import Mock

import pytest
from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux owned directory binding')


@pytest.mark.parametrize('stopped', [True, False])
def test_close_preserves_replacement_tree_and_payload(tmp_path, monkeypatch, stopped):
    ctx = private.RunContext(tmp_path / 'private')
    ctx.__enter__()
    ctx.write_yaml({'password': 'synthetic-owned'})
    moved = tmp_path / 'moved'
    ctx.run_dir.rename(moved)
    ctx.run_dir.mkdir(mode=0o700)
    foreign = ctx.run_dir / 'probe.yaml'
    foreign.write_bytes(b'synthetic foreign evidence')
    try:
        with monkeypatch.context() as patch:
            patch.setattr(ctx, '_stop_child', Mock(return_value=stopped))
            with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
                ctx.close()
        assert foreign.read_bytes() == b'synthetic foreign evidence'
        assert (moved / 'probe.yaml').exists()
        assert not ctx.closed
    finally:
        if ctx.run_dir.exists():
            shutil.rmtree(ctx.run_dir)
        moved.rename(ctx.run_dir)
        ctx.close()


@pytest.mark.parametrize('stopped', [True, False])
def test_changed_directory_permissions_block_cleanup(tmp_path, monkeypatch, stopped):
    ctx = private.RunContext(tmp_path / 'private')
    ctx.__enter__()
    ctx.write_yaml({'password': 'synthetic'})
    ctx.run_dir.chmod(0o755)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(ctx, '_stop_child', Mock(return_value=stopped))
            with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
                ctx.close()
        assert (ctx.run_dir / 'probe.yaml').exists()
        assert ctx._run_dir_fd is not None
    finally:
        ctx.run_dir.chmod(0o700)
        ctx.close()


def test_pin_lifetime_and_noninheritance(tmp_path):
    ctx = private.RunContext(tmp_path / 'private')
    ctx.__enter__()
    fd = ctx._run_dir_fd
    assert fd is not None and not os.get_inheritable(fd)
    assert os.fstat(fd).st_ino == ctx.run_dir.stat().st_ino
    ctx.close()
    assert ctx._run_dir_fd is None
    with pytest.raises(OSError):
        os.fstat(fd)
    ctx.close()  # idempotent, no second fd close


def test_duplication_failure_uses_initialization_cleanup(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    monkeypatch.setattr(private.os, 'dup', Mock(side_effect=OSError('synthetic')))
    with pytest.raises(private.PrivateRunError):
        ctx.__enter__()
    assert ctx._initial_dir_fd is None and ctx._run_dir_fd is None
    assert ctx._lock_fd is None and list(ctx.root.iterdir()) == []
    ctx.close()


def test_failed_stop_retains_pin_for_later_success(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    ctx.__enter__()
    ctx.write_yaml({'password': 'synthetic'})
    fd = ctx._run_dir_fd
    try:
        with monkeypatch.context() as patch:
            patch.setattr(ctx, '_stop_child', Mock(return_value=False))
            with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
                ctx.close()
        assert ctx._run_dir_fd == fd
        assert os.fstat(fd).st_ino == ctx.run_dir.stat().st_ino
        assert not (ctx.run_dir / 'probe.yaml').exists()
        assert (ctx.run_dir / '.owner.json').exists()
    finally:
        ctx.close()
    with pytest.raises(OSError):
        os.fstat(fd)


def test_tree_check_replacement_is_revalidated_before_delete(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    ctx.__enter__()
    moved = tmp_path / 'moved'
    check = private._check_clean_private_tree
    def race(path):
        check(path)
        path.rename(moved)
        path.mkdir(mode=0o700)
        (path / 'foreign').write_bytes(b'synthetic')
    try:
        with monkeypatch.context() as patch:
            patch.setattr(private, '_check_clean_private_tree', race)
            with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
                ctx.close()
        assert (ctx.run_dir / 'foreign').read_bytes() == b'synthetic'
    finally:
        if moved.exists():
            shutil.rmtree(ctx.run_dir)
            moved.rename(ctx.run_dir)
        ctx.close()


@pytest.mark.parametrize('replacement', ['symlink', 'missing'])
def test_missing_or_symlink_directory_is_not_cleanup_success(tmp_path, replacement):
    ctx = private.RunContext(tmp_path / 'private')
    ctx.__enter__()
    moved = tmp_path / 'moved'
    ctx.run_dir.rename(moved)
    if replacement == 'symlink':
        ctx.run_dir.symlink_to(moved, target_is_directory=True)
    try:
        with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
            ctx.close()
        assert moved.exists() and not ctx.closed
    finally:
        if ctx.run_dir.is_symlink():
            ctx.run_dir.unlink()
        moved.rename(ctx.run_dir)
        ctx.close()


def test_actual_owned_child_stops_but_replacement_directory_is_preserved(tmp_path):
    ctx = private.RunContext(tmp_path / 'private')
    ctx.__enter__()
    ctx.write_yaml({'password': 'synthetic'})
    ctx.spawn_synthetic_process()
    child = ctx.raw_child
    moved = tmp_path / 'moved'
    ctx.run_dir.rename(moved)
    ctx.run_dir.mkdir(mode=0o700)
    (ctx.run_dir / 'probe.yaml').write_bytes(b'synthetic foreign')
    try:
        with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
            ctx.close()
        assert child.wait(timeout=5) is not None
        assert (ctx.run_dir / 'probe.yaml').read_bytes() == b'synthetic foreign'
        assert (moved / 'probe.yaml').exists()
    finally:
        shutil.rmtree(ctx.run_dir)
        moved.rename(ctx.run_dir)
        ctx.close()


def test_pin_stat_failure_is_not_permission_to_clean(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    ctx.__enter__()
    stat = os.fstat
    def failed(fd):
        if fd == ctx._run_dir_fd:
            raise OSError('synthetic')
        return stat(fd)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(private.os, 'fstat', failed)
            with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
                ctx.close()
        assert ctx.run_dir.exists() and ctx._run_dir_fd is not None
    finally:
        ctx.close()
