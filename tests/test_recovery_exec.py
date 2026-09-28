"""A changed executable does not prove the recorded Linux child exited."""
import json
import os
import select
import subprocess
import sys
from unittest.mock import Mock

import pytest

from nodelab import mihomo_config as private
from nodelab import mihomo_process as lifecycle

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux exec/pidfd recovery")


@pytest.fixture
def rig(monkeypatch):
    expected = lifecycle.ProcessIdentity(12345, 100, "a" * 32)
    query = Mock(return_value=lifecycle.ProcessIdentity(12345, 100, "b" * 32))
    poll = Mock(return_value=([], [], []))
    opened, closed, sent, numeric = Mock(return_value=321), Mock(), Mock(), Mock()
    monkeypatch.setattr(lifecycle.os, "pidfd_open", opened)
    monkeypatch.setattr(lifecycle.os, "close", closed)
    monkeypatch.setattr(lifecycle, "_linux_identity", query)
    monkeypatch.setattr(lifecycle.select, "select", poll)
    monkeypatch.setattr(lifecycle.signal, "pidfd_send_signal", sent)
    monkeypatch.setattr(lifecycle.os, "kill", numeric)
    yield expected, query, poll, closed
    sent.assert_not_called()
    numeric.assert_not_called()


def test_same_pid_and_creation_stamp_with_changed_executable_is_not_gone(rig):
    expected, _, _, closed = rig
    assert lifecycle.terminate_verified_process(expected) is False
    closed.assert_called_once_with(321)


def test_inconsistent_query_pid_is_not_proof_of_recorded_child_exit(rig):
    expected, query, _, closed = rig
    query.return_value = lifecycle.ProcessIdentity(54321, 101, "a" * 32)
    assert lifecycle.terminate_verified_process(expected) is False
    closed.assert_called_once_with(321)


@pytest.mark.parametrize("missing", ["expected", "current"])
def test_unreadable_executable_still_allows_kernel_exit_proof(rig, missing):
    expected, query, poll, closed = rig
    if missing == "expected":
        expected = lifecycle.ProcessIdentity(expected.pid, expected.create_time, None)
    else:
        query.return_value = lifecycle.ProcessIdentity(expected.pid, expected.create_time, None)
    poll.side_effect = [([], [], []), ([321], [], [])]
    assert lifecycle.terminate_verified_process(expected) is True
    closed.assert_called_once_with(321)


def test_changed_executable_requires_descriptor_exit_proof_not_a_guess(rig):
    expected, _, poll, closed = rig
    poll.side_effect = [([], [], []), ([321], [], [])]
    assert lifecycle.terminate_verified_process(expected) is True
    closed.assert_called_once_with(321)


def test_changed_image_and_creation_stamp_is_known_different_lifetime(rig):
    expected, query, _, closed = rig
    query.return_value = lifecycle.ProcessIdentity(expected.pid, expected.create_time + 1, "b" * 32)
    assert lifecycle.terminate_verified_process(expected) is True
    closed.assert_called_once_with(321)


def test_exit_poll_error_after_changed_executable_is_unconfirmed(rig):
    expected, _, poll, closed = rig
    poll.side_effect = [([], [], []), OSError("synthetic")]
    assert lifecycle.terminate_verified_process(expected) is False
    closed.assert_called_once_with(321)


EXEC_SCRIPT = r'''
import os, sys
print("before", flush=True)
sys.stdin.readline()
os.execv("/bin/sh", ["sh", "-c", "printf 'after\\n'; read ignored"])
'''
REAL_POPEN = subprocess.Popen


def line(proc, expected):
    assert select.select([proc.stdout], [], [], 5)[0]
    assert proc.stdout.readline() == expected


def change_image(proc):
    line(proc, b"before\n")
    expected = lifecycle.process_identity(proc.pid)
    assert expected is not None and expected.exe_fingerprint is not None
    proc.stdin.write(b"go\n")
    proc.stdin.flush()
    line(proc, b"after\n")
    current = lifecycle.process_identity(proc.pid)
    assert current is not None
    assert current.pid == expected.pid and current.create_time == expected.create_time
    assert current.exe_fingerprint is not None and current.exe_fingerprint != expected.exe_fingerprint
    return expected


def stop_fixture(proc):
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=5)
    proc.stdin.close()
    proc.stdout.close()


def test_real_exec_is_not_exit_but_pidfd_readiness_is():
    proc = REAL_POPEN([sys.executable, "-c", EXEC_SCRIPT], stdin=subprocess.PIPE,
                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    fd = None
    try:
        expected = change_image(proc)
        assert lifecycle.terminate_verified_process(expected) is False
        assert proc.poll() is None
        fd = os.pidfd_open(proc.pid)
        proc.terminate()  # only this test's own Popen, not the recovery function
        assert select.select([fd], [], [], 5)[0] == [fd]
        assert lifecycle.terminate_verified_process(expected) is True
    finally:
        if fd is not None:
            os.close(fd)
        stop_fixture(proc)


def test_real_exec_recovery_removes_yaml_but_retains_identity(tmp_path, monkeypatch):
    ctx = private.RunContext(tmp_path / "private")
    ctx.__enter__()
    ctx.write_yaml({"password": "synthetic-only"})
    proc = None

    class ExecChild(REAL_POPEN):
        def __init__(self, *args, **kwargs):
            super().__init__([sys.executable, "-c", EXEC_SCRIPT], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(private.subprocess, "Popen", ExecChild)
            proc = ctx.spawn_synthetic_process()
        expected = change_image(proc)
        marker = ctx.run_dir / ".owner.json"
        data = json.loads(marker.read_bytes())
        assert data["child_exe_fingerprint"] == expected.exe_fingerprint
        data["owner_create_time"] += 1  # simulated stale owner, real exec child
        marker.write_text(json.dumps(data))
        before = marker.read_bytes()
        ctx._drop_lock()
        with monkeypatch.context() as patch:
            sent, numeric = Mock(), Mock()
            patch.setattr(lifecycle.signal, "pidfd_send_signal", sent)
            patch.setattr(lifecycle.os, "kill", numeric)
            for _ in range(2):
                rows = private.recover_stale_runs(ctx.root)
                assert [r["error_code"] for r in rows] == ["PROCESS_STOP_FAILED"]
                assert marker.read_bytes() == before
                assert proc.poll() is None
            sent.assert_not_called()
            numeric.assert_not_called()
        assert not (ctx.run_dir / "probe.yaml").exists()
    finally:
        if not ctx.run_dir.exists():
            ctx._private_tree_removed = True
        ctx.close()  # still owns the exact Popen; this is not marker-based recovery
        if proc is not None:
            stop_fixture(proc)
