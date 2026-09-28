"""Linux owner liveness is not inferred from a failed identity query."""
import json
import os
import sys
from unittest.mock import Mock

import pytest

from nodelab import mihomo_config as private
from nodelab import mihomo_process as lifecycle

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux owner pidfd checks")


@pytest.mark.parametrize("fault", ["unreadable", "exec_changed", "missing_stamp"])
def test_unknown_or_still_live_owner_preserves_all_files(tmp_path, monkeypatch, fault):
    ctx = private.RunContext(tmp_path / "private")
    ctx.__enter__()
    ctx.write_yaml({"password": "synthetic-only"})
    marker = ctx.run_dir / ".owner.json"
    data = json.loads(marker.read_bytes())
    current = lifecycle.process_identity(os.getpid())
    if fault == "missing_stamp":
        data["owner_create_time"] = None
    data.update(child_pid=34567, child_create_time=20, child_exe_fingerprint="a" * 32)
    marker.write_text(json.dumps(data))
    before = {p.name: p.read_bytes() for p in ctx.run_dir.iterdir()}
    ctx._drop_lock()
    try:
        with monkeypatch.context() as patch:
            identity = None if fault == "unreadable" else lifecycle.ProcessIdentity(
                current.pid, current.create_time, "b" * 32)
            patch.setattr(private, "process_identity", Mock(return_value=identity))
            patch.setattr(lifecycle, "_linux_identity", Mock(return_value=identity))
            stop = Mock(return_value=True)
            patch.setattr(private, "terminate_verified_process", stop)
            rows = private.recover_stale_runs(ctx.root)
            assert [r["error_code"] for r in rows] == ["RECOVERY_REVIEW_REQUIRED"]
            stop.assert_not_called()
        assert {p.name: p.read_bytes() for p in ctx.run_dir.iterdir()} == before
    finally:
        if not ctx.run_dir.exists():
            ctx._private_tree_removed = True
        ctx.close()


@pytest.fixture
def rig(monkeypatch):
    expected = lifecycle.ProcessIdentity(12345, 100, "a" * 32)
    opened, closed = Mock(return_value=321), Mock()
    query = Mock(return_value=expected)
    poll = Mock(return_value=([], [], []))
    signal, numeric = Mock(), Mock()
    monkeypatch.setattr(lifecycle.os, "pidfd_open", opened)
    monkeypatch.setattr(lifecycle.os, "close", closed)
    monkeypatch.setattr(lifecycle, "_linux_identity", query)
    monkeypatch.setattr(lifecycle.select, "select", poll)
    monkeypatch.setattr(lifecycle.signal, "pidfd_send_signal", signal)
    monkeypatch.setattr(lifecycle.os, "kill", numeric)
    yield expected, opened, closed, query, poll
    signal.assert_not_called()
    numeric.assert_not_called()


@pytest.mark.parametrize("current", [
    None,
    lifecycle.ProcessIdentity(12345, 100, None),
    lifecycle.ProcessIdentity(12345, 100, "b" * 32),
    lifecycle.ProcessIdentity(12345, 0, "a" * 32),
    lifecycle.ProcessIdentity(54321, 101, "a" * 32),
])
def test_live_or_unknown_identity_never_proves_owner_exit(rig, current):
    expected, opened, closed, query, poll = rig
    query.return_value = current
    assert lifecycle.linux_owner_gone(expected) is False
    opened.assert_called_once_with(expected.pid)
    closed.assert_called_once_with(321)
    assert all(call.args == ([321], [], [], 0.0) for call in poll.call_args_list)


def test_known_reused_pid_proves_original_owner_gone_without_signal(rig):
    expected, _, closed, query, _ = rig
    query.return_value = lifecycle.ProcessIdentity(expected.pid, expected.create_time + 1, None)
    assert lifecycle.linux_owner_gone(expected) is True
    closed.assert_called_once_with(321)


@pytest.mark.parametrize("initial", [True, False])
def test_bound_descriptor_readiness_proves_exit_even_when_proc_is_unreadable(rig, initial):
    expected, _, closed, query, poll = rig
    query.return_value = None
    poll.side_effect = [([321], [], [])] if initial else [([], [], []), ([321], [], [])]
    assert lifecycle.linux_owner_gone(expected) is True
    closed.assert_called_once_with(321)
    if initial:
        query.assert_not_called()


@pytest.mark.parametrize("error, gone", [(ProcessLookupError(), True), (PermissionError(), False),
                                          (OSError(), False), (OverflowError(), False)])
def test_pidfd_open_result_is_not_confused_with_unknown_identity(rig, error, gone):
    expected, opened, closed, query, _ = rig
    opened.side_effect = error
    assert lifecycle.linux_owner_gone(expected) is gone
    query.assert_not_called()
    closed.assert_not_called()


def test_missing_pidfd_api_refuses_recovery_without_numeric_probe(rig, monkeypatch):
    expected, _, closed, query, _ = rig
    monkeypatch.delattr(lifecycle.os, "pidfd_open")
    assert lifecycle.linux_owner_gone(expected) is False
    query.assert_not_called()
    closed.assert_not_called()


@pytest.mark.parametrize("stamp", [None, 0, -1, True])
def test_invalid_recorded_owner_is_not_queried(rig, stamp):
    expected, opened, closed, query, _ = rig
    assert lifecycle.linux_owner_gone(lifecycle.ProcessIdentity(expected.pid, stamp, None)) is False
    opened.assert_not_called()
    query.assert_not_called()
    closed.assert_not_called()


def test_poll_failure_preserves_unknown_result_and_closes_descriptor(rig):
    expected, _, closed, _, poll = rig
    poll.side_effect = OSError("synthetic")
    assert lifecycle.linux_owner_gone(expected) is False
    closed.assert_called_once_with(321)


def test_real_live_owner_and_exited_unreaped_owner_are_distinguished():
    import subprocess
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    fd = None
    try:
        identity = lifecycle.process_identity(proc.pid)
        assert identity is not None
        assert lifecycle.linux_owner_gone(identity) is False
        fd = os.pidfd_open(proc.pid)
        proc.terminate()  # only the Popen owned by this test is signalled
        assert lifecycle.select.select([fd], [], [], 5)[0] == [fd]
        assert lifecycle.linux_owner_gone(identity) is True
    finally:
        if fd is not None:
            os.close(fd)
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
