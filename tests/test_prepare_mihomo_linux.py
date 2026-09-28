"""Offline installer mechanics with synthetic pins; NOT official binary evidence."""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

import pytest

SPEC = importlib.util.spec_from_file_location(
    "prepare_mihomo_linux", Path(__file__).resolve().parents[1] / "scripts" / "prepare_mihomo_linux.py",
)
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux-only offline preparation")
PAYLOAD = b"synthetic bytes; never an executable\n" * 64


@pytest.fixture
def staged(tmp_path, monkeypatch):
    archive = tmp_path / "input.gz"
    archive.write_bytes(gzip.compress(PAYLOAD, mtime=0))
    monkeypatch.setattr(prepare, "ARCHIVE_SHA256", hashlib.sha256(archive.read_bytes()).hexdigest())
    monkeypatch.setattr(prepare, "EXECUTABLE_SHA256", hashlib.sha256(PAYLOAD).hexdigest())
    monkeypatch.setattr(prepare.platform, "machine", lambda: "x86_64")
    return archive, tmp_path / "mihomo"


def run_case(staged, capsys, code):
    archive, destination = staged
    result = prepare.main(["--archive", str(archive), "--destination", str(destination)])
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["code"] == code
    assert report["binary_executed"] is False
    assert report["real_node_test_allowed"] is False
    assert report["runtime_acceptance"] == report["route_proof"] == "NOT_RUN"
    assert result == (0 if code == "PINNED_BYTES_PREPARED" else 2)
    assert not list(destination.parent.glob(".nodelab-prepare-*"))
    return report


def test_prepares_exact_bytes_private_mode_without_execution(staged, capsys):
    # PAYLOAD cannot execute; success must not depend on running it.
    assert run_case(staged, capsys, "PINNED_BYTES_PREPARED")["status"] == "PREPARED"
    assert staged[1].read_bytes() == PAYLOAD
    assert stat.S_IMODE(staged[1].stat().st_mode) == 0o700


@pytest.mark.parametrize("pin,code", [
    ("ARCHIVE_SHA256", "ARCHIVE_DIGEST_MISMATCH"),
    ("EXECUTABLE_SHA256", "EXECUTABLE_DIGEST_MISMATCH"),
])
def test_both_byte_pins_required(staged, monkeypatch, capsys, pin, code):
    monkeypatch.setattr(prepare, pin, "0" * 64)
    run_case(staged, capsys, code)
    assert not staged[1].exists()


@pytest.mark.parametrize("limit,code", [
    ("MAX_ARCHIVE_BYTES", "ARCHIVE_TOO_LARGE"),
    ("MAX_EXECUTABLE_BYTES", "EXECUTABLE_TOO_LARGE"),
])
def test_bounded_input_and_expansion(staged, monkeypatch, capsys, limit, code):
    monkeypatch.setattr(prepare, limit, 10)
    run_case(staged, capsys, code)
    assert not staged[1].exists()


@pytest.mark.parametrize("contents", [b"not gzip", gzip.compress(PAYLOAD)[:-6]])
def test_invalid_and_truncated_gzip_clean_up(staged, monkeypatch, capsys, contents):
    staged[0].write_bytes(contents)
    monkeypatch.setattr(prepare, "ARCHIVE_SHA256", hashlib.sha256(contents).hexdigest())
    run_case(staged, capsys, "ARCHIVE_INVALID")
    assert not staged[1].exists()


@pytest.mark.parametrize("kind", ["file", "directory", "symlink", "dangling_symlink"])
def test_never_overwrites_existing_destination(staged, capsys, kind):
    archive, destination = staged
    if kind == "file":
        destination.write_bytes(b"keep")
    elif kind == "directory":
        destination.mkdir()
    else:
        destination.symlink_to(archive if kind == "symlink" else destination.parent / "missing")
    run_case(staged, capsys, "DESTINATION_EXISTS")
    if kind == "file":
        assert destination.read_bytes() == b"keep"
    elif kind == "directory":
        assert destination.is_dir()
    else:
        assert destination.is_symlink()


def test_publish_race_does_not_overwrite(staged, monkeypatch, capsys):
    original = prepare.os.link

    def publish(source, destination, **kwargs):
        Path(destination).write_bytes(b"concurrent owner")
        original(source, destination, **kwargs)

    monkeypatch.setattr(prepare.os, "link", publish)
    run_case(staged, capsys, "DESTINATION_EXISTS")
    assert staged[1].read_bytes() == b"concurrent owner"


def test_uses_verified_snapshot_not_reopened_source(staged, monkeypatch, capsys):
    original = prepare.copy_and_hash

    def copy(source, target, limit, code):
        digest = original(source, target, limit, code)
        if code == "ARCHIVE_TOO_LARGE":
            staged[0].write_bytes(b"changed after snapshot")
        return digest

    monkeypatch.setattr(prepare, "copy_and_hash", copy)
    run_case(staged, capsys, "PINNED_BYTES_PREPARED")
    assert staged[1].read_bytes() == PAYLOAD


@pytest.mark.parametrize("kind", ["input_link", "parent_link", "fifo", "relative", "missing_parent", "writable_parent"])
def test_unsafe_paths_block(staged, tmp_path, capsys, kind):
    archive, destination = staged
    if kind == "input_link":
        link = tmp_path / "link.gz"
        link.symlink_to(archive)
        archive = link
        code = "LINK_PATH_REJECTED"
    elif kind == "parent_link":
        link = tmp_path / "link"
        link.symlink_to(tmp_path, target_is_directory=True)
        destination = link / "mihomo"
        code = "LINK_PATH_REJECTED"
    elif kind == "fifo":
        archive.unlink()
        os.mkfifo(archive)
        code = "ARCHIVE_NOT_REGULAR"
    elif kind == "relative":
        archive = Path("input.gz")
        code = "ABSOLUTE_PATHS_REQUIRED"
    elif kind == "missing_parent":
        destination = tmp_path / "missing" / "mihomo"
        code = "DESTINATION_PARENT_REQUIRED"
    else:
        parent = tmp_path / "writable"
        parent.mkdir(mode=0o700)
        parent.chmod(0o777)
        destination = parent / "mihomo"
        code = "DESTINATION_PARENT_WRITABLE"
    run_case((archive, destination), capsys, code)
    assert not destination.exists()


def test_missing_archive_has_fixed_error(staged, capsys):
    staged[0].unlink()
    run_case(staged, capsys, "PREPARATION_IO_FAILED")


def test_fsync_failure_removes_staging(staged, monkeypatch, capsys):
    def fail(*args):
        raise OSError("private path must not be printed")
    monkeypatch.setattr(prepare.os, "fsync", fail)
    run_case(staged, capsys, "PREPARATION_IO_FAILED")
    assert not staged[1].exists()


def test_architecture_blocks_before_preparation(staged, monkeypatch, capsys):
    monkeypatch.setattr(prepare.platform, "machine", lambda: "aarch64")
    run_case(staged, capsys, "LINUX_AMD64_REQUIRED")
    assert not staged[1].exists()


def test_invalid_args_do_not_echo_values(capsys):
    assert prepare.main(["--unknown", "private-sentinel"]) == 2
    captured = capsys.readouterr()
    assert "private-sentinel" not in captured.out + captured.err
    assert json.loads(captured.out)["code"] == "INVALID_ARGUMENTS"


def test_catalogue_pin_is_not_replaced_by_archive_digest():
    from nodelab.engine_binary import KNOWN_DIGESTS
    assert prepare.EXECUTABLE_SHA256 in KNOWN_DIGESTS
    assert prepare.ARCHIVE_SHA256 != prepare.EXECUTABLE_SHA256


def test_exact_size_limits_are_allowed(staged, monkeypatch, capsys):
    monkeypatch.setattr(prepare, "MAX_ARCHIVE_BYTES", staged[0].stat().st_size)
    monkeypatch.setattr(prepare, "MAX_EXECUTABLE_BYTES", len(PAYLOAD))
    run_case(staged, capsys, "PINNED_BYTES_PREPARED")


@pytest.mark.parametrize("published", [False, True])
def test_interruption_requires_destination_review(staged, monkeypatch, capsys, published):
    original = prepare.os.link

    def interrupt(source, destination, **kwargs):
        if published:
            original(source, destination, **kwargs)
        raise KeyboardInterrupt()

    monkeypatch.setattr(prepare.os, "link", interrupt)
    run_case(staged, capsys, "CANCELLED_REVIEW_DESTINATION")
    assert staged[1].exists() is published
    if published:
        assert staged[1].read_bytes() == PAYLOAD
