"""Recheck identity before each recovery signal without claiming atomicity."""
import os
import select
import signal
import subprocess
import sys
from unittest.mock import Mock

import pytest

from nodelab import mihomo_process as lifecycle

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux recovery signal guards")


@pytest.fixture
def rig(monkeypatch):
    expected = lifecycle.ProcessIdentity(12345, 100, "a" * 32)
    state = {"now": 100.0, "exited": False}
    query, sent, closed, numeric = Mock(return_value=expected), Mock(), Mock(), Mock()

    def poll(*args):
        state["now"] += args[3]
        return ([321] if state["exited"] else [], [], [])

    monkeypatch.setattr(lifecycle.os, "pidfd_open", Mock(return_value=321))
    monkeypatch.setattr(lifecycle.os, "close", closed)
    monkeypatch.setattr(lifecycle, "_linux_identity", query)
    monkeypatch.setattr(lifecycle.select, "select", poll)
    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: state["now"])
    monkeypatch.setattr(lifecycle.signal, "pidfd_send_signal", sent)
    monkeypatch.setattr(lifecycle.os, "kill", numeric)
    yield expected, state, query, sent, closed
    numeric.assert_not_called()


@pytest.mark.parametrize("phase", ["term", "kill"])
@pytest.mark.parametrize("current", [
    None,
    lifecycle.ProcessIdentity(12345, 100, "b" * 32),
    lifecycle.ProcessIdentity(12345, 101, "a" * 32),
    lifecycle.ProcessIdentity(54321, 100, "a" * 32),
    lifecycle.ProcessIdentity(12345, 100, None),
])
def test_changed_or_unknown_identity_blocks_next_signal(rig, phase, current):
    expected, _, query, sent, closed = rig
    query.side_effect = [expected] + ([expected] if phase == "kill" else []) + [current]
    assert lifecycle.terminate_verified_process(expected) is False
    assert [call.args for call in sent.call_args_list] == ([] if phase == "term" else [(321, signal.SIGTERM)])
    closed.assert_called_once_with(321)


@pytest.mark.parametrize("phase", ["term", "kill"])
def test_recheck_consuming_remaining_budget_prevents_signal(rig, phase):
    expected, state, query, sent, closed = rig
    calls = 0

    def slow(pid):
        nonlocal calls
        calls += 1
        if calls == (2 if phase == "term" else 3):
            state["now"] += 6
        return expected

    query.side_effect = slow
    assert lifecycle.terminate_verified_process(expected) is False
    assert [call.args for call in sent.call_args_list] == ([] if phase == "term" else [(321, signal.SIGTERM)])
    closed.assert_called_once_with(321)


@pytest.mark.parametrize("phase", ["term", "kill"])
def test_recheck_error_never_authorizes_following_signal(rig, phase):
    expected, _, query, sent, closed = rig
    query.side_effect = [expected] + ([expected] if phase == "kill" else []) + [PermissionError("synthetic")]
    assert lifecycle.terminate_verified_process(expected) is False
    assert [call.args for call in sent.call_args_list] == ([] if phase == "term" else [(321, signal.SIGTERM)])
    closed.assert_called_once_with(321)


def test_exit_during_recheck_is_proven_only_by_bound_descriptor(rig):
    expected, state, query, sent, closed = rig
    calls = 0

    def disappear(pid):
        nonlocal calls
        calls += 1
        if calls == 2:
            state["exited"] = True
            return None
        return expected

    query.side_effect = disappear
    assert lifecycle.terminate_verified_process(expected) is True
    sent.assert_not_called()
    closed.assert_called_once_with(321)


def test_real_term_handler_exec_blocks_kill_escalation(monkeypatch):
    script = r'''
import os, signal

def replace(sig, frame):
    os.execv("/bin/sh", ["sh", "-c", "printf 'after\\n'; read ignored"])

signal.signal(signal.SIGTERM, replace)
print("armed", flush=True)
while True:
    signal.pause()
'''
    proc = subprocess.Popen([sys.executable, "-c", script], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        assert select.select([proc.stdout], [], [], 5)[0]
        assert proc.stdout.readline() == b"armed\n"
        expected = lifecycle.process_identity(proc.pid)
        assert expected is not None and expected.exe_fingerprint is not None
        original = signal.pidfd_send_signal
        with monkeypatch.context() as patch:
            sent = Mock(wraps=original)
            numeric = Mock(side_effect=AssertionError("no numeric recovery signal"))
            patch.setattr(lifecycle.signal, "pidfd_send_signal", sent)
            patch.setattr(lifecycle.os, "kill", numeric)
            assert lifecycle.terminate_verified_process(expected, budget=4.0) is False
            assert [call.args[1] for call in sent.call_args_list] == [signal.SIGTERM]
            numeric.assert_not_called()
        assert select.select([proc.stdout], [], [], 5)[0]
        assert proc.stdout.readline() == b"after\n"
        current = lifecycle.process_identity(proc.pid)
        assert current is not None
        assert current.pid == expected.pid and current.create_time == expected.create_time
        assert current.exe_fingerprint is not None and current.exe_fingerprint != expected.exe_fingerprint
        assert proc.poll() is None
    finally:
        if proc.poll() is None:
            proc.kill()  # explicit test-owned Popen cleanup, not recovery escalation
        proc.wait(timeout=5)
        proc.stdin.close()
        proc.stdout.close()
