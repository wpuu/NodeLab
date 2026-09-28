"""Linux marker publication faults; no power-loss or hostile-filesystem claim."""
import json
import os
import secrets
import stat
import sys
from unittest.mock import Mock

import pytest

from nodelab import mihomo_config as private
from nodelab.mihomo_process import ProcessIdentity

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux atomic private marker")
CHILD = ProcessIdentity(12345, 100, "a" * 32)  # record-only synthetic ID, never signalled


@pytest.fixture
def owner(tmp_path):
    with private.RunContext(tmp_path / "private") as ctx:
        ctx.write_yaml({"password": secrets.token_urlsafe(32)})
        yield ctx


@pytest.mark.parametrize("fault", ["serialize", "file_fsync"])
def test_prepublication_failure_preserves_complete_previous_marker(owner, monkeypatch, fault):
    marker = owner.run_dir / ".owner.json"
    before = marker.read_bytes()
    with monkeypatch.context() as patch:
        if fault == "serialize":
            def broken(value, stream, **kwargs):
                stream.write('{"partial":')
                raise OSError("synthetic")
            patch.setattr(private.json, "dump", broken)
        else:
            patch.setattr(private.os, "fsync", Mock(side_effect=OSError("synthetic")))
        with pytest.raises(OSError):
            owner._write_marker(child=CHILD)
    assert marker.read_bytes() == before
    assert json.loads(marker.read_bytes())["child_pid"] is None
    assert sorted(p.name for p in owner.run_dir.iterdir()) == [".owner.json", "probe.yaml"]


def test_publication_order_permissions_and_no_staging_residue(owner, monkeypatch):
    marker = owner.run_dir / ".owner.json"
    before, old_inode = marker.read_bytes(), marker.stat().st_ino
    fsync, replace = private.os.fsync, private.os.replace
    events = []

    def sync(fd):
        events.append("directory_sync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file_sync")
        return fsync(fd)

    def publish(source, destination):
        assert source.parent == marker.parent and destination == marker
        assert marker.read_bytes() == before
        assert stat.S_IMODE(source.stat().st_mode) == 0o600
        assert json.loads(source.read_bytes())["child_pid"] == CHILD.pid
        events.append("replace")
        return replace(source, destination)

    with monkeypatch.context() as patch:
        patch.setattr(private.os, "fsync", sync)
        patch.setattr(private.os, "replace", publish)
        owner._write_marker(child=CHILD)
    assert events == ["file_sync", "replace", "directory_sync"]
    assert marker.stat().st_ino != old_inode
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert sorted(p.name for p in owner.run_dir.iterdir()) == [".owner.json", "probe.yaml"]


@pytest.mark.parametrize("published", [False, True])
def test_replace_error_never_leaves_truncated_marker(owner, monkeypatch, published):
    marker = owner.run_dir / ".owner.json"
    before = marker.read_bytes()
    original = private.os.replace

    def fail(source, destination):
        if published:
            original(source, destination)
        raise OSError("synthetic")

    with monkeypatch.context() as patch:
        patch.setattr(private.os, "replace", fail)
        with pytest.raises(OSError):
            owner._write_marker(child=CHILD)
    if published:
        assert json.loads(marker.read_bytes())["child_pid"] == CHILD.pid
    else:
        assert marker.read_bytes() == before
    assert sorted(p.name for p in owner.run_dir.iterdir()) == [".owner.json", "probe.yaml"]


def test_directory_fsync_failure_reports_error_but_preserves_complete_published_marker(owner, monkeypatch):
    original = private.os.fsync

    def fail(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("synthetic")
        return original(fd)

    with monkeypatch.context() as patch:
        patch.setattr(private.os, "fsync", fail)
        with pytest.raises(OSError):
            owner._write_marker(child=CHILD)
    assert json.loads((owner.run_dir / ".owner.json").read_bytes())["child_pid"] == CHILD.pid
    assert not list(owner.run_dir.glob(".owner-*.tmp"))


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit])
def test_interrupted_serialization_removes_staging_not_previous_marker(owner, monkeypatch, error_type):
    marker = owner.run_dir / ".owner.json"
    before = marker.read_bytes()

    def fail(value, stream, **kwargs):
        stream.write('{"partial":')
        raise error_type()

    with monkeypatch.context() as patch:
        patch.setattr(private.json, "dump", fail)
        with pytest.raises(error_type):
            owner._write_marker(child=CHILD)
    assert marker.read_bytes() == before
    assert not list(owner.run_dir.glob(".owner-*.tmp"))


def test_fdopen_failure_closes_staging_descriptor(owner, monkeypatch):
    descriptors = []

    def fail(fd, *args, **kwargs):
        descriptors.append(fd)
        raise OSError("synthetic")

    before = (owner.run_dir / ".owner.json").read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(private.os, "fdopen", fail)
        with pytest.raises(OSError):
            owner._write_marker(child=CHILD)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert (owner.run_dir / ".owner.json").read_bytes() == before
    assert not list(owner.run_dir.glob(".owner-*.tmp"))


def test_crash_staging_residue_requires_review_without_process_lookup(owner, monkeypatch):
    staging = owner.run_dir / ".owner-synthetic.tmp"
    staging.write_bytes(b'{"partial":')
    staging.chmod(0o600)
    owner._drop_lock()
    before = {p.name: p.read_bytes() for p in owner.run_dir.iterdir()}
    lookup, stop = Mock(), Mock()
    monkeypatch.setattr(private, "process_identity", lookup)
    monkeypatch.setattr(private, "terminate_verified_process", stop)
    rows = private.recover_stale_runs(owner.root)
    assert [row["error_code"] for row in rows] == ["RECOVERY_REVIEW_REQUIRED"]
    lookup.assert_not_called()
    stop.assert_not_called()
    assert {p.name: p.read_bytes() for p in owner.run_dir.iterdir()} == before


def test_first_publication_failure_cannot_leave_yaml_or_empty_marker(tmp_path, monkeypatch):
    root = tmp_path / "private"
    with monkeypatch.context() as patch:
        patch.setattr(private.os, "replace", Mock(side_effect=OSError("synthetic")))
        with pytest.raises(private.PrivateRunError):
            with private.RunContext(root):
                pytest.fail("must not enter")
    assert list(root.iterdir()) == []
