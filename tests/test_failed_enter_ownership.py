"""Failed Linux initialization must not claim an existing/replaced directory."""
import os
import sys

import pytest
from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux failed-entry ownership')


def test_mkdir_collision_preserves_other_directory_and_close_cannot_delete_it(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    original = type(tmp_path).mkdir
    def race(path, *args, **kwargs):
        if path.parent == ctx.root:
            original(path, mode=0o700)
            (path / 'foreign').write_bytes(b'synthetic evidence')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(type(tmp_path), 'mkdir', race)
    with pytest.raises(private.PrivateRunError):
        ctx.__enter__()
    assert (ctx.run_dir / 'foreign').read_bytes() == b'synthetic evidence'
    with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
        ctx.close()
    assert (ctx.run_dir / 'foreign').read_bytes() == b'synthetic evidence'


def test_replaced_directory_is_not_deleted_on_publication_failure(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    moved = tmp_path / 'original'
    def replace():
        ctx.run_dir.rename(moved)
        ctx.run_dir.mkdir(mode=0o700)
        (ctx.run_dir / 'foreign').write_bytes(b'synthetic evidence')
        raise OSError('synthetic')
    monkeypatch.setattr(ctx, '_write_marker', replace)
    with pytest.raises(private.PrivateRunError):
        ctx.__enter__()
    assert (ctx.run_dir / 'foreign').read_bytes() == b'synthetic evidence'
    with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
        ctx.close()
    assert moved.exists() and (ctx.run_dir / 'foreign').exists()


@pytest.mark.parametrize('fault', [OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_owned_failed_directory_is_cleaned_and_pin_closed(tmp_path, monkeypatch, fault):
    ctx = private.RunContext(tmp_path / 'private')
    descriptors = []
    def fail():
        descriptors.append(ctx._initial_dir_fd)
        assert not os.get_inheritable(ctx._initial_dir_fd)
        raise fault('synthetic')
    monkeypatch.setattr(ctx, '_write_marker', fail)
    with pytest.raises(private.PrivateRunError if fault in (OSError, ValueError) else fault):
        ctx.__enter__()
    assert list(ctx.root.iterdir()) == []
    assert ctx._initial_dir_fd is None and ctx._lock_fd is None
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    ctx.close()
    assert ctx.closed


@pytest.mark.parametrize('change', ['symlink', 'missing'])
def test_missing_or_symlink_replacement_cannot_grant_cleanup(tmp_path, monkeypatch, change):
    ctx = private.RunContext(tmp_path / 'private')
    saved = tmp_path / 'saved'
    target = tmp_path / 'target'
    target.mkdir(mode=0o700)
    (target / 'foreign').write_bytes(b'synthetic')
    def fail():
        ctx.run_dir.rename(saved)
        if change == 'symlink':
            ctx.run_dir.symlink_to(target, target_is_directory=True)
        raise OSError('synthetic')
    monkeypatch.setattr(ctx, '_write_marker', fail)
    with pytest.raises(private.PrivateRunError):
        ctx.__enter__()
    for _ in range(2):
        with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
            ctx.close()
    assert saved.exists() and (target / 'foreign').read_bytes() == b'synthetic'
    assert ctx._initial_dir_fd is None


def test_unpinned_directory_is_preserved_when_open_fails(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    opened = os.open
    def fail(path, flags, *args, **kwargs):
        if flags & os.O_DIRECTORY and path == ctx.run_dir:
            raise PermissionError('synthetic')
        return opened(path, flags, *args, **kwargs)
    monkeypatch.setattr(private.os, 'open', fail)
    with pytest.raises(private.PrivateRunError):
        ctx.__enter__()
    assert ctx.run_dir.is_dir()
    with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
        ctx.close()
    assert ctx.run_dir.is_dir()


def test_failed_context_cannot_be_reused_after_precreation_error(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    with monkeypatch.context() as patch:
        def fail():
            raise private.PrivateRunError()
        patch.setattr(ctx, '_ensure_root', fail)
        with pytest.raises(private.PrivateRunError):
            ctx.__enter__()
    with pytest.raises(private.PrivateRunError):
        ctx.__enter__()
    assert ctx.run_dir is None
    ctx.close()


def test_run_lock_replacement_during_failed_enter_is_preserved(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    inode = []
    def fail():
        ctx._lock_path.unlink()
        ctx._lock_path.touch(mode=0o600)
        inode.append(ctx._lock_path.stat().st_ino)
        raise OSError('synthetic')
    monkeypatch.setattr(ctx, '_write_marker', fail)
    with pytest.raises(private.PrivateRunError):
        ctx.__enter__()
    assert ctx._lock_path.stat().st_ino == inode[0]
    assert ctx._lock_fd is None and ctx._initial_dir_fd is None
    with pytest.raises(private.PrivateRunError, match='SECRET_CLEANUP_FAILED'):
        ctx.close()


def test_successful_enter_drops_initial_pin_but_keeps_run_lock(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / 'private')
    descriptors = []
    write = ctx._write_marker
    def tracked():
        descriptors.append(ctx._initial_dir_fd)
        write()
    monkeypatch.setattr(ctx, '_write_marker', tracked)
    with ctx:
        assert ctx._initial_dir_fd is None
        with pytest.raises(OSError):
            os.fstat(descriptors[0])
        assert private._lock_state(ctx._lock_path) == 'live'
    assert list(ctx.root.iterdir()) == []
