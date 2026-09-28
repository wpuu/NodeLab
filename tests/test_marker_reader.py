"""Linux descriptor-bound, bounded marker reads; injected pathname races."""
import os
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux marker descriptor checks")


@pytest.fixture
def owner(tmp_path):
    with private.RunContext(tmp_path / "private") as ctx:
        ctx.write_yaml({"password": "synthetic-only"})
        yield ctx


@pytest.mark.parametrize("replacement", ["permissions", "growth", "symlink"])
def test_replacement_after_path_check_cannot_supply_a_marker(owner, tmp_path, monkeypatch, replacement):
    marker = owner.run_dir / ".owner.json"
    before = marker.read_bytes()
    external = tmp_path / "external"
    external.write_bytes(before)
    verify = private._Recovery.verify

    def race(recovery, path, *, directory):
        verify(recovery, path, directory=directory)
        if path == marker:
            if replacement == "permissions":
                marker.chmod(0o644)
            elif replacement == "growth":
                marker.write_bytes(before + b" " * private._MARKER_MAX_BYTES)
            else:
                marker.unlink()
                marker.symlink_to(external)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(private._Recovery, "verify", race)
            assert private._Recovery(owner.root).read_marker(owner.run_dir) is None
        assert external.read_bytes() == before
    finally:
        marker.unlink()
        marker.write_bytes(before)
        marker.chmod(0o600)


def test_fifo_substitution_is_opened_nonblocking_and_rejected(owner, monkeypatch):
    marker = owner.run_dir / ".owner.json"
    before = marker.read_bytes()
    verify, original_open = private._Recovery.verify, os.open
    descriptors = []

    def race(recovery, path, *, directory):
        verify(recovery, path, directory=directory)
        if path == marker:
            marker.unlink()
            os.mkfifo(marker, 0o600)

    def safe_open(path, flags, *args, **kwargs):
        if Path(path) == marker:
            # Assert before opening so removing NONBLOCK cannot hang pytest.
            assert flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW
            fd = original_open(path, flags, *args, **kwargs)
            assert not os.get_inheritable(fd)
            descriptors.append(fd)
            return fd
        return original_open(path, flags, *args, **kwargs)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(private._Recovery, "verify", race)
            patch.setattr(private.os, "open", safe_open)
            read = Mock(side_effect=AssertionError("must reject FIFO before reading"))
            patch.setattr(private.os, "read", read)
            assert private._Recovery(owner.root).read_marker(owner.run_dir) is None
            read.assert_not_called()
        assert len(descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(descriptors[0])
    finally:
        marker.unlink()
        marker.write_bytes(before)
        marker.chmod(0o600)


def test_growth_after_fstat_is_still_read_with_a_hard_byte_limit(owner, monkeypatch):
    marker = owner.run_dir / ".owner.json"
    before = marker.read_bytes()
    original_fstat, original_read = os.fstat, os.read
    requests = []

    def grow(fd):
        info = original_fstat(fd)
        marker.write_bytes(before + b" " * (private._MARKER_MAX_BYTES * 2))
        return info

    def bounded(fd, size):
        requests.append(size)
        return original_read(fd, size)

    with monkeypatch.context() as patch:
        patch.setattr(private.os, "fstat", grow)
        patch.setattr(private.os, "read", bounded)
        assert private._Recovery(owner.root).read_marker(owner.run_dir) is None
    assert requests == [private._MARKER_MAX_BYTES + 1]


@pytest.mark.parametrize("size", [4096, 4097])
def test_marker_limit_counts_bytes_and_accepts_exact_boundary(owner, monkeypatch, size):
    marker = owner.run_dir / ".owner.json"
    before = marker.read_bytes()
    marker.write_bytes(before + b" " * (size - len(before)))
    original = os.read
    reads = []

    def read(fd, count):
        reads.append(count)
        return original(fd, count)

    with monkeypatch.context() as patch:
        patch.setattr(private.os, "read", read)
        data = private._Recovery(owner.root).read_marker(owner.run_dir)
    if size == 4096:
        assert data["run_id"] == owner.run_id
        assert reads == [4097]
    else:
        assert data is None and reads == []


def test_hard_linked_record_is_not_an_exclusive_private_marker(owner, tmp_path):
    marker = owner.run_dir / ".owner.json"
    alias = tmp_path / "alias"
    os.link(marker, alias)
    before = alias.read_bytes()
    try:
        assert private._Recovery(owner.root).read_marker(owner.run_dir) is None
        assert alias.read_bytes() == before
    finally:
        alias.unlink()


def test_opened_object_uid_is_checked_before_read(owner, monkeypatch):
    from types import SimpleNamespace
    original = os.fstat

    def foreign(fd):
        info = original(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() + 1,
                               st_nlink=1, st_size=info.st_size)

    with monkeypatch.context() as patch:
        read = Mock(side_effect=AssertionError("must reject UID before read"))
        patch.setattr(private.os, "fstat", foreign)
        patch.setattr(private.os, "read", read)
        assert private._Recovery(owner.root).read_marker(owner.run_dir) is None
        read.assert_not_called()


@pytest.mark.parametrize("body", [b"", b"\xff", b'{"partial":', b"[" * 1500 + b"]" * 1500])
def test_invalid_encoding_json_or_depth_requires_review_without_process_lookup(owner, monkeypatch, body):
    marker = owner.run_dir / ".owner.json"
    marker.write_bytes(body)
    owner._drop_lock()
    with monkeypatch.context() as patch:
        lookup, stop = Mock(), Mock()
        patch.setattr(private, "process_identity", lookup)
        patch.setattr(private, "terminate_verified_process", stop)
        rows = private.recover_stale_runs(owner.root)
        lookup.assert_not_called()
        stop.assert_not_called()
    assert [row["error_code"] for row in rows] == ["RECOVERY_REVIEW_REQUIRED"]
    assert marker.read_bytes() == body
    assert (owner.run_dir / "probe.yaml").is_file()


@pytest.mark.parametrize("failure", ["fstat", "read"])
def test_read_failure_closes_descriptor_and_preserves_files(owner, monkeypatch, failure):
    original = os.open
    descriptors = []
    before = {p.name: p.read_bytes() for p in owner.run_dir.iterdir()}

    def opened(*args, **kwargs):
        fd = original(*args, **kwargs)
        descriptors.append(fd)
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(private.os, "open", opened)
        patch.setattr(private.os, failure, Mock(side_effect=OSError("synthetic")))
        assert private._Recovery(owner.root).read_marker(owner.run_dir) is None
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert {p.name: p.read_bytes() for p in owner.run_dir.iterdir()} == before


def test_read_uses_verified_descriptor_not_reopened_path(owner, tmp_path, monkeypatch):
    marker = owner.run_dir / ".owner.json"
    original = os.fstat
    moved = tmp_path / "previous-record"

    def replace_path(fd):
        info = original(fd)
        marker.rename(moved)
        marker.write_bytes(b"{}")
        marker.chmod(0o600)
        return info

    try:
        with monkeypatch.context() as patch:
            patch.setattr(private.os, "fstat", replace_path)
            data = private._Recovery(owner.root).read_marker(owner.run_dir)
        assert data["run_id"] == owner.run_id
        assert marker.read_bytes() == b"{}"  # replacement was not what got parsed
    finally:
        if moved.exists():
            os.replace(moved, marker)
