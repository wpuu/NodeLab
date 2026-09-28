"""Ambiguous Linux child records never mean that no child exists."""
import json
import sys
from unittest.mock import Mock

import pytest

from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux recovery record shape")


@pytest.fixture
def abandoned(tmp_path):
    ctx = private.RunContext(tmp_path / "private")
    ctx.__enter__()
    ctx.write_yaml({"password": "synthetic-only"})
    marker = ctx.run_dir / ".owner.json"
    data = json.loads(marker.read_bytes())
    data["owner_create_time"] += 1  # simulated stale owner; no actual child
    marker.write_text(json.dumps(data))
    ctx._drop_lock()
    try:
        yield ctx, marker, data
    finally:
        if not ctx.run_dir.exists():
            ctx._private_tree_removed = True
        ctx.close()


def assert_review_without_identity_access(ctx, monkeypatch):
    before = {p.name: p.read_bytes() for p in ctx.run_dir.iterdir()}
    with monkeypatch.context() as patch:
        owner, child = Mock(return_value=True), Mock(return_value=True)
        patch.setattr(private, "linux_owner_gone", owner)
        patch.setattr(private, "terminate_verified_process", child)
        for _ in range(2):
            rows = private.recover_stale_runs(ctx.root)
            assert [r["error_code"] for r in rows] == ["RECOVERY_REVIEW_REQUIRED"]
        owner.assert_not_called()
        child.assert_not_called()
    assert ctx.run_dir.is_dir()
    assert {p.name: p.read_bytes() for p in ctx.run_dir.iterdir()} == before


@pytest.mark.parametrize("missing", ["child_pid", "child_create_time", "child_exe_fingerprint"])
def test_missing_child_field_is_not_implicit_null(abandoned, monkeypatch, missing):
    ctx, marker, data = abandoned
    data.pop(missing)
    marker.write_text(json.dumps(data))
    assert_review_without_identity_access(ctx, monkeypatch)


@pytest.mark.parametrize("remaining_yaml", [True, False])
def test_no_marker_never_authorizes_linux_directory_removal(abandoned, monkeypatch, remaining_yaml):
    ctx, marker, _ = abandoned
    marker.unlink()
    if not remaining_yaml:
        (ctx.run_dir / "probe.yaml").unlink()
    assert_review_without_identity_access(ctx, monkeypatch)


@pytest.mark.parametrize("values", [
    (None, 100, None), (None, None, "a" * 32), (12345, None, None),
    (12345, 100, None), (None, 100, "a" * 32), (12345, None, "a" * 32),
])
def test_partial_identity_is_not_an_empty_child_record(abandoned, monkeypatch, values):
    ctx, marker, data = abandoned
    data.update(zip(("child_pid", "child_create_time", "child_exe_fingerprint"), values))
    marker.write_text(json.dumps(data))
    assert_review_without_identity_access(ctx, monkeypatch)


@pytest.mark.parametrize("field,value", [
    ("child_pid", 0), ("child_pid", -1), ("child_pid", True),
    ("child_create_time", 0), ("child_create_time", -1), ("child_create_time", True),
    ("child_exe_fingerprint", ""), ("child_exe_fingerprint", "a" * 31),
    ("child_exe_fingerprint", "A" * 32), ("child_exe_fingerprint", "g" * 32),
])
def test_invalid_complete_child_identity_is_rejected_before_owner_lookup(abandoned, monkeypatch, field, value):
    ctx, marker, data = abandoned
    data.update(child_pid=12345, child_create_time=100, child_exe_fingerprint="a" * 32)
    data[field] = value
    marker.write_text(json.dumps(data))
    assert_review_without_identity_access(ctx, monkeypatch)


def test_all_child_fields_omitted_is_not_a_no_child_record(abandoned, monkeypatch):
    ctx, marker, data = abandoned
    for key in ("child_pid", "child_create_time", "child_exe_fingerprint"):
        data.pop(key)
    marker.write_text(json.dumps(data))
    assert_review_without_identity_access(ctx, monkeypatch)


@pytest.mark.parametrize("owner_gone", [False, True])
def test_explicit_null_child_record_still_requires_owner_exit(abandoned, monkeypatch, owner_gone):
    ctx, _, _ = abandoned
    with monkeypatch.context() as patch:
        owner, child = Mock(return_value=owner_gone), Mock()
        patch.setattr(private, "linux_owner_gone", owner)
        patch.setattr(private, "terminate_verified_process", child)
        rows = private.recover_stale_runs(ctx.root)
        assert [r["error_code"] for r in rows] == [None if owner_gone else "RECOVERY_REVIEW_REQUIRED"]
        owner.assert_called_once()
        child.assert_not_called()
    assert ctx.run_dir.exists() is not owner_gone


def test_complete_child_record_still_requires_verified_child_stop(abandoned, monkeypatch):
    ctx, marker, data = abandoned
    data.update(child_pid=12345, child_create_time=100, child_exe_fingerprint="a" * 32)
    marker.write_text(json.dumps(data))
    before = marker.read_bytes()
    with monkeypatch.context() as patch:
        owner, child = Mock(return_value=True), Mock(return_value=False)
        patch.setattr(private, "linux_owner_gone", owner)
        patch.setattr(private, "terminate_verified_process", child)
        rows = private.recover_stale_runs(ctx.root)
        owner.assert_called_once()
        child.assert_called_once_with(private.ProcessIdentity(12345, 100, "a" * 32))
    assert [r["error_code"] for r in rows] == ["PROCESS_STOP_FAILED"]
    assert marker.read_bytes() == before
    assert not (ctx.run_dir / "probe.yaml").exists()


def test_ambiguous_record_blocks_new_run_without_modification(abandoned, monkeypatch):
    ctx, marker, data = abandoned
    data.pop("child_pid")
    marker.write_text(json.dumps(data))
    assert_review_without_identity_access(ctx, monkeypatch)
    before = marker.read_bytes()
    with pytest.raises(private.PrivateRunError, match="^RECOVERY_REVIEW_REQUIRED$"):
        with private.RunContext(ctx.root):
            pytest.fail("ambiguous residue must block startup")
    assert marker.read_bytes() == before
