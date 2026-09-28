"""Linux boot-bound private markers; synthetic changes never reboot the host."""
import json
import secrets
import sys
from unittest.mock import Mock
from uuid import uuid4

import pytest

from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux boot identity recovery")


@pytest.fixture
def abandoned(tmp_path):
    owner = private.RunContext(tmp_path / "private")
    owner.__enter__()
    owner.write_yaml({"password": secrets.token_urlsafe(32)})
    marker = owner.run_dir / ".owner.json"
    data = json.loads(marker.read_text())
    data["owner_create_time"] += 1  # simulated stale owner; no child exists
    marker.write_text(json.dumps(data))
    owner._drop_lock()
    try:
        yield owner, marker, data
    finally:
        if not owner.run_dir.exists():
            owner._private_tree_removed = True  # recovered by the tested routine
        owner.close()  # original in-memory owner removes only its own fixture


@pytest.mark.parametrize("value", [None, "different", "0" * 64, True, 7, "A" * 64])
def test_unbound_or_other_boot_marker_is_left_untouched(abandoned, monkeypatch, value):
    owner, marker, data = abandoned
    if value is None:
        data.pop("linux_boot_fingerprint", None)  # pre-upgrade marker
    else:
        data["linux_boot_fingerprint"] = value
    data.update(child_pid=54321, child_create_time=100, child_exe_fingerprint="a" * 32)
    marker.write_text(json.dumps(data))
    before = {p.name: p.read_bytes() for p in owner.run_dir.iterdir()}
    lookup, stop = Mock(), Mock()
    monkeypatch.setattr(private, "process_identity", lookup)
    monkeypatch.setattr(private, "terminate_verified_process", stop)
    rows = private.recover_stale_runs(owner.root)
    assert [row["error_code"] for row in rows] == ["RECOVERY_REVIEW_REQUIRED"]
    assert {p.name: p.read_bytes() for p in owner.run_dir.iterdir()} == before
    lookup.assert_not_called()
    stop.assert_not_called()


def test_same_boot_stale_marker_is_still_recoverable(abandoned):
    owner, _, data = abandoned
    assert data.get("linux_boot_fingerprint") == private._linux_boot_fingerprint()
    rows = private.recover_stale_runs(owner.root)
    assert [row["error_code"] for row in rows] == [None]
    assert not owner.run_dir.exists()
    owner._private_tree_removed = True  # explicitly recovered, no remaining tree


def test_marker_stores_only_boot_digest_not_raw_boot_id(tmp_path):
    with private.RunContext(tmp_path / "private") as owner:
        raw = private._LINUX_BOOT_ID.read_text().strip()
        body = (owner.run_dir / ".owner.json").read_text()
        data = json.loads(body)
        assert len(data["linux_boot_fingerprint"]) == 64
        assert data["linux_boot_fingerprint"] == private._linux_boot_fingerprint()
        assert raw not in body


def test_missing_current_boot_does_not_create_private_yaml(tmp_path, monkeypatch):
    monkeypatch.setattr(private, "_linux_boot_fingerprint", lambda: None)
    root = tmp_path / "private"
    with pytest.raises(private.PrivateRunError):
        with private.RunContext(root) as owner:
            owner.write_yaml({"password": secrets.token_urlsafe(32)})
    assert list(root.iterdir()) == []


def test_missing_current_boot_prevents_recovery(abandoned, monkeypatch):
    owner, marker, _ = abandoned
    before = marker.read_bytes()
    monkeypatch.setattr(private, "_linux_boot_fingerprint", lambda: None)
    stop = Mock()
    monkeypatch.setattr(private, "terminate_verified_process", stop)
    rows = private.recover_stale_runs(owner.root)
    assert [row["error_code"] for row in rows] == ["RECOVERY_REVIEW_REQUIRED"]
    assert marker.read_bytes() == before
    stop.assert_not_called()


def test_active_run_is_not_rebound_to_changed_boot(tmp_path, monkeypatch):
    with private.RunContext(tmp_path / "private") as owner:
        marker = owner.run_dir / ".owner.json"
        before = marker.read_bytes()
        with monkeypatch.context() as patch:
            patch.setattr(private, "_linux_boot_fingerprint", lambda: "f" * 64)
            with pytest.raises(private.PrivateRunError):
                owner._write_marker()
        assert marker.read_bytes() == before


@pytest.mark.parametrize("raw", [b"", b"not-uuid", b"\xff", b"x" * 65])
def test_boot_reader_rejects_malformed_or_oversized_input(tmp_path, monkeypatch, raw):
    path = tmp_path / "boot-id"
    path.write_bytes(raw)
    monkeypatch.setattr(private, "_LINUX_BOOT_ID", path)
    assert private._linux_boot_fingerprint() is None


def test_boot_reader_hash_is_stable_and_changes_across_boots(tmp_path, monkeypatch):
    path = tmp_path / "boot-id"
    first, second = str(uuid4()), str(uuid4())
    path.write_text(first + "\n")
    monkeypatch.setattr(private, "_LINUX_BOOT_ID", path)
    digest = private._linux_boot_fingerprint()
    assert digest is not None and len(digest) == 64
    assert digest == private._linux_boot_fingerprint()
    path.write_text(second + "\n")
    assert digest != private._linux_boot_fingerprint()
    path.unlink()
    assert private._linux_boot_fingerprint() is None


@pytest.mark.parametrize("first", [False, True])
def test_duplicate_boot_binding_is_not_normalized(abandoned, monkeypatch, first):
    owner, marker, data = abandoned
    body = json.dumps(data)
    duplicate = '"linux_boot_fingerprint":"' + "0" * 64 + '"'
    body = "{" + duplicate + "," + body[1:] if first else body[:-1] + "," + duplicate + "}"
    marker.write_text(body)
    lookup, stop = Mock(), Mock()
    monkeypatch.setattr(private, "process_identity", lookup)
    monkeypatch.setattr(private, "terminate_verified_process", stop)
    rows = private.recover_stale_runs(owner.root)
    assert [row["error_code"] for row in rows] == ["RECOVERY_REVIEW_REQUIRED"]
    assert marker.read_text() == body
    lookup.assert_not_called()
    stop.assert_not_called()


def test_changed_boot_during_child_marker_write_still_cleans_owned_child(tmp_path, monkeypatch):
    owner = private.RunContext(tmp_path / "private")
    with pytest.raises(private.PrivateRunError, match="^RECOVERY_REVIEW_REQUIRED$"):
        with owner:
            owner.write_yaml({"password": secrets.token_urlsafe(32)})
            monkeypatch.setattr(private, "_linux_boot_fingerprint", lambda: "f" * 64)
            owner.spawn_synthetic_process()
    assert owner.raw_child is not None and owner.raw_child.poll() is not None
    assert owner.closed and not owner.run_dir.exists()
