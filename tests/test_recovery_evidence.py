"""Linux stop-failure residue: remove payload, keep non-secret recovery evidence."""
import json
import secrets
import sys
from unittest.mock import Mock

import pytest

from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux recovery evidence retention")


@pytest.fixture
def owner(tmp_path):
    ctx = private.RunContext(tmp_path / "private")
    ctx.__enter__()
    ctx.write_yaml({"password": secrets.token_urlsafe(32)})
    ctx.spawn_synthetic_process()
    try:
        yield ctx
    finally:
        if not ctx.run_dir.exists():
            ctx._private_tree_removed = True
        ctx.close()


def abandon(ctx):
    marker = ctx.run_dir / ".owner.json"
    data = json.loads(marker.read_bytes())
    data["owner_create_time"] += 1  # simulate a stale owner, retain real owned child ID
    marker.write_text(json.dumps(data))
    ctx._drop_lock()
    return marker, marker.read_bytes()


def test_owned_stop_failure_deletes_payload_not_recovery_marker(owner, monkeypatch):
    marker = owner.run_dir / ".owner.json"
    before = marker.read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(owner, "_stop_child", lambda: False)
        with pytest.raises(private.PrivateRunError, match="^SECRET_CLEANUP_FAILED$"):
            owner.close()
    assert not (owner.run_dir / "probe.yaml").exists()
    assert marker.read_bytes() == before
    assert owner.raw_child.poll() is None
    assert not owner.closed and not owner._private_tree_removed
    assert private._lock_state(owner._lock_path) == "live"
    owner.close()
    assert owner.closed and not owner.run_dir.exists()


def test_recovery_stop_failure_preserves_record_for_a_later_exact_child_retry(owner, monkeypatch):
    marker, before = abandon(owner)
    with monkeypatch.context() as patch:
        stop = Mock(return_value=False)
        patch.setattr(private, "terminate_verified_process", stop)
        rows = private.recover_stale_runs(owner.root)
        stop.assert_called_once()
    assert [row["error_code"] for row in rows] == ["PROCESS_STOP_FAILED"]
    assert not (owner.run_dir / "probe.yaml").exists()
    assert marker.read_bytes() == before
    assert owner.raw_child.poll() is None
    # A second recovery, with the real identity/pidfd path, can still find and
    # stop precisely the separately owned Python child from the first record.
    rows = private.recover_stale_runs(owner.root)
    assert [row["error_code"] for row in rows] == [None]
    owner.raw_child.wait(timeout=5)
    assert not owner.run_dir.exists()


@pytest.mark.parametrize("result", [None, 1, "stopped"])
def test_recovery_requires_explicit_true_before_destroying_evidence(owner, monkeypatch, result):
    marker, before = abandon(owner)
    with monkeypatch.context() as patch:
        patch.setattr(private, "terminate_verified_process", Mock(return_value=result))
        rows = private.recover_stale_runs(owner.root)
    assert [row["error_code"] for row in rows] == ["PROCESS_STOP_FAILED"]
    assert not (owner.run_dir / "probe.yaml").exists()
    assert marker.read_bytes() == before and owner.raw_child.poll() is None


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_recovery_stop_exception_deletes_yaml_but_keeps_marker_and_fixed_error(owner, monkeypatch, error_type):
    marker, before = abandon(owner)
    sentinel = secrets.token_urlsafe(32)
    with monkeypatch.context() as patch:
        patch.setattr(private, "terminate_verified_process", Mock(side_effect=error_type(sentinel)))
        rows = private.recover_stale_runs(owner.root)
    assert [row["error_code"] for row in rows] == ["PROCESS_STOP_FAILED"]
    assert sentinel not in json.dumps(rows)
    assert str(owner.run_dir) not in json.dumps(rows)
    assert not (owner.run_dir / "probe.yaml").exists()
    assert marker.read_bytes() == before and owner.raw_child.poll() is None


def test_failed_owned_stop_keeps_ambiguous_staging_but_removes_other_payload(owner, monkeypatch):
    stage = owner.run_dir / ".owner-synthetic.tmp"
    stage.write_bytes(b'{"partial":')
    stage.chmod(0o600)
    cache = owner.run_dir / "cache"
    cache.mkdir()
    (cache / "cache.db").write_bytes(b"synthetic payload")
    with monkeypatch.context() as patch:
        patch.setattr(owner, "_stop_child", lambda: False)
        with pytest.raises(private.PrivateRunError):
            owner.close()
    assert {p.name for p in owner.run_dir.iterdir()} == {".owner.json", stage.name}
    assert stage.read_bytes() == b'{"partial":'
    # Keep the ambiguity visible to a later explicit recovery, even if owner
    # identity appears dead. Neither metadata record may be silently selected.
    marker, before = abandon(owner)
    with monkeypatch.context() as patch:
        lookup, stop = Mock(), Mock()
        patch.setattr(private, "process_identity", lookup)
        patch.setattr(private, "terminate_verified_process", stop)
        rows = private.recover_stale_runs(owner.root)
        lookup.assert_not_called()
        stop.assert_not_called()
    assert [row["error_code"] for row in rows] == ["RECOVERY_REVIEW_REQUIRED"]
    assert marker.read_bytes() == before


def test_repeated_failed_recovery_does_not_erase_evidence_or_allow_new_run(owner, monkeypatch):
    marker, before = abandon(owner)
    with monkeypatch.context() as patch:
        patch.setattr(private, "terminate_verified_process", Mock(return_value=False))
        for _ in range(2):
            rows = private.recover_stale_runs(owner.root)
            assert [row["error_code"] for row in rows] == ["PROCESS_STOP_FAILED"]
            assert marker.read_bytes() == before
            assert not (owner.run_dir / "probe.yaml").exists()
        with pytest.raises(private.PrivateRunError, match="^RECOVERY_REVIEW_REQUIRED$"):
            with private.RunContext(owner.root):
                pytest.fail("must not start over orphan evidence")


def test_payload_removal_failure_retains_marker_and_reports_cleanup_failure(owner, monkeypatch):
    marker, before = abandon(owner)
    with monkeypatch.context() as patch:
        patch.setattr(private, "terminate_verified_process", Mock(return_value=False))
        patch.setattr(private, "_remove_payload_preserving_evidence", Mock(side_effect=OSError("synthetic")))
        rows = private.recover_stale_runs(owner.root)
    assert [row["error_code"] for row in rows] == ["SECRET_CLEANUP_FAILED"]
    assert marker.read_bytes() == before
    assert (owner.run_dir / "probe.yaml").is_file()


def test_failed_stop_does_not_follow_link_to_external_file(owner, tmp_path, monkeypatch):
    external = tmp_path / "outside"
    external.write_bytes(b"external synthetic file")
    link = owner.run_dir / "link"
    link.symlink_to(external)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(owner, "_stop_child", lambda: False)
            with pytest.raises(private.PrivateRunError, match="^SECRET_CLEANUP_FAILED$"):
                owner.close()
        assert external.read_bytes() == b"external synthetic file"
        assert (owner.run_dir / ".owner.json").is_file()
        assert not owner.closed
    finally:
        link.unlink()


def test_real_owner_exit_after_failed_stop_leaves_recoverable_child(tmp_path, monkeypatch):
    import os
    import select
    import subprocess

    root = tmp_path / "crashed"
    script = r'''
import json, os, secrets, sys
from pathlib import Path
from nodelab.mihomo_config import RunContext, PrivateRunError
ctx = RunContext(Path(sys.argv[1]))
ctx.__enter__()
ctx.write_yaml({"password": secrets.token_urlsafe(32)})
child = ctx.spawn_synthetic_process()
print(json.dumps({"run_id": ctx.run_id, "child_pid": child.pid}), flush=True)
ctx._stop_child = lambda: False
try:
    ctx.close()
except PrivateRunError:
    pass
os._exit(0)
'''
    proc = subprocess.Popen([sys.executable, "-c", script, str(root)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=os.environ.copy())
    descriptor = None
    try:
        output, _ = proc.communicate(timeout=10)
        assert proc.returncode == 0
        info = json.loads(output)
        run_dir = root / info["run_id"]
        assert not (run_dir / "probe.yaml").exists()
        marker = json.loads((run_dir / ".owner.json").read_bytes())
        assert marker["child_pid"] == info["child_pid"]
        assert private.process_identity(info["child_pid"]) is not None
        assert private._lock_state(root / (info["run_id"] + ".lock")) == "stale"
        descriptor = os.pidfd_open(info["child_pid"])
        with monkeypatch.context() as patch:
            patch.setattr(private, "terminate_verified_process", Mock(return_value=False))
            failed = private.recover_stale_runs(root)
        assert [row["error_code"] for row in failed] == ["PROCESS_STOP_FAILED"]
        assert private._lock_state(root / (info["run_id"] + ".lock")) == "stale"
        assert json.loads((run_dir / ".owner.json").read_bytes()) == marker
        assert select.select([descriptor], [], [], 0)[0] == []
        rows = private.recover_stale_runs(root)
        assert [row["error_code"] for row in rows] == [None]
        assert select.select([descriptor], [], [], 5)[0] == [descriptor]
        assert not run_dir.exists()
        assert list(root.iterdir()) == []
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=5)
        # Cleanup is still identity-checked if an assertion above failed.
        if root.exists():
            private.recover_stale_runs(root)
