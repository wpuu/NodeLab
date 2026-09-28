"""Linux recovery must never fall back to signalling a reusable PID number."""
import errno
import os
import signal
import subprocess
import sys
from unittest.mock import Mock

import pytest

from nodelab import mihomo_process as lifecycle

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux pidfd recovery")


@pytest.fixture
def rig(monkeypatch):
    expected = lifecycle.ProcessIdentity(12345, 100, "a" * 32)
    state = {"exited": False, "now": 100.0, "waits": []}
    opened = Mock(return_value=321)
    closed = Mock()
    identity = Mock(return_value=expected)

    def poll(reads, writes, errors, timeout):
        state["waits"].append(timeout)
        state["now"] += timeout
        return ([321] if state["exited"] else [], [], [])

    def stop(*args):
        state["exited"] = True
        identity.return_value = None

    sent = Mock(side_effect=stop)
    numeric = Mock(side_effect=stop)  # never actually signal any PID in unit tests
    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: state["now"])
    monkeypatch.setattr(lifecycle.os, "pidfd_open", opened)
    monkeypatch.setattr(lifecycle.os, "close", closed)
    monkeypatch.setattr(lifecycle.signal, "pidfd_send_signal", sent)
    monkeypatch.setattr(lifecycle.os, "kill", numeric)
    monkeypatch.setattr(lifecycle, "_linux_identity", identity)
    monkeypatch.setattr(lifecycle.select, "select", poll)
    return expected, state, opened, closed, identity, sent, numeric


@pytest.mark.parametrize("failure", [errno.EPERM, errno.ENOSYS, errno.EMFILE])
def test_pidfd_open_failure_never_uses_numeric_pid(rig, failure):
    expected, _, opened, _, _, sent, numeric = rig
    opened.side_effect = OSError(failure, "synthetic")
    assert lifecycle.terminate_verified_process(expected) is False
    sent.assert_not_called()
    numeric.assert_not_called()


@pytest.mark.parametrize("module,name", [(os, "pidfd_open"), (signal, "pidfd_send_signal")])
def test_missing_stable_handle_api_blocks_recovery(rig, monkeypatch, module, name):
    expected, _, opened, _, _, sent, numeric = rig
    monkeypatch.delattr(module, name)
    assert lifecycle.terminate_verified_process(expected) is False
    opened.assert_not_called()
    sent.assert_not_called()
    numeric.assert_not_called()


def test_unreadable_identity_is_not_proof_of_exit(rig):
    expected, _, _, closed, identity, sent, numeric = rig
    identity.return_value = None
    assert lifecycle.terminate_verified_process(expected) is False
    sent.assert_not_called()
    numeric.assert_not_called()
    closed.assert_called_once_with(321)


@pytest.mark.parametrize("missing", ["recorded", "current"])
def test_missing_executable_fingerprint_never_authorizes_signal(rig, missing):
    expected, _, _, _, identity, sent, numeric = rig
    incomplete = lifecycle.ProcessIdentity(expected.pid, expected.create_time, None)
    if missing == "recorded":
        expected = incomplete
    else:
        identity.return_value = incomplete
    assert lifecycle.terminate_verified_process(expected) is False
    sent.assert_not_called()
    numeric.assert_not_called()


def test_known_mismatch_is_not_signalled(rig):
    expected, _, _, closed, identity, sent, numeric = rig
    identity.return_value = lifecycle.ProcessIdentity(expected.pid, 101, "a" * 32)
    assert lifecycle.terminate_verified_process(expected) is True
    sent.assert_not_called()
    numeric.assert_not_called()
    closed.assert_called_once_with(321)


def test_readable_pidfd_proves_exit_without_identity_guess(rig):
    expected, state, _, closed, identity, sent, numeric = rig
    state["exited"] = True
    identity.return_value = None
    assert lifecycle.terminate_verified_process(expected) is True
    sent.assert_not_called()
    numeric.assert_not_called()
    closed.assert_called_once_with(321)


def test_esrch_proves_pid_absent_without_signal(rig):
    expected, _, opened, closed, _, sent, numeric = rig
    opened.side_effect = ProcessLookupError(errno.ESRCH, "synthetic")
    assert lifecycle.terminate_verified_process(expected) is True
    closed.assert_not_called()
    sent.assert_not_called()
    numeric.assert_not_called()


@pytest.mark.parametrize("budget", [0, -1, True, None, "5", float("nan"), float("inf")])
def test_invalid_recovery_budget_has_no_side_effect(rig, budget):
    expected, _, opened, _, _, sent, numeric = rig
    assert lifecycle.terminate_verified_process(expected, budget=budget) is False
    opened.assert_not_called()
    sent.assert_not_called()
    numeric.assert_not_called()


def test_recovery_signals_only_bound_descriptor(rig):
    expected, _, _, closed, _, sent, numeric = rig
    assert lifecycle.terminate_verified_process(expected) is True
    sent.assert_called_once_with(321, signal.SIGTERM)
    numeric.assert_not_called()
    closed.assert_called_once_with(321)


def test_budget_expiry_does_not_grant_extra_kill_wait(rig):
    expected, state, _, closed, _, sent, numeric = rig
    sent.side_effect = None  # remains alive throughout the bounded wait
    assert lifecycle.terminate_verified_process(expected, budget=0.25) is False
    assert state["now"] == pytest.approx(100.25)
    sent.assert_called_once_with(321, signal.SIGTERM)
    numeric.assert_not_called()
    closed.assert_called_once_with(321)


def test_real_pidfd_reaps_only_its_child_and_leaves_external_alive():
    assert hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")
    children = []
    try:
        for _ in range(2):
            children.append(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        child, external = children
        expected = lifecycle.process_identity(child.pid)
        assert expected is not None and expected.exe_fingerprint is not None
        assert lifecycle.terminate_verified_process(expected)
        child.wait(timeout=3)
        assert external.poll() is None
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)


@pytest.mark.parametrize("expected", [None, lifecycle.ProcessIdentity(True, 100, "a" * 32),
    lifecycle.ProcessIdentity(-1, 100, "a" * 32), lifecycle.ProcessIdentity(12345, 0, "a" * 32),
    lifecycle.ProcessIdentity(12345, True, "a" * 32), lifecycle.ProcessIdentity(12345, 100, "invalid")])
def test_invalid_record_never_opens_or_signals(rig, expected):
    _, _, opened, _, _, sent, numeric = rig
    assert lifecycle.terminate_verified_process(expected) is False
    opened.assert_not_called()
    sent.assert_not_called()
    numeric.assert_not_called()


def test_identity_lookup_consuming_budget_prevents_signal(rig):
    expected, state, _, closed, identity, sent, numeric = rig

    def slow_identity(pid):
        state["now"] += 1.0
        return expected

    identity.side_effect = slow_identity
    assert lifecycle.terminate_verified_process(expected, budget=0.25) is False
    sent.assert_not_called()
    numeric.assert_not_called()
    closed.assert_called_once_with(321)


def test_identity_unreadable_after_signal_does_not_claim_death(rig):
    expected, _, _, _, identity, sent, numeric = rig
    sent.side_effect = lambda *args: setattr(identity, "return_value", None)
    assert lifecycle.terminate_verified_process(expected, budget=0.25) is False
    identity.assert_called_once_with(expected.pid)
    numeric.assert_not_called()


def test_kill_escalation_uses_same_pidfd_and_budget(rig):
    expected, state, _, closed, _, sent, numeric = rig

    def stop(fd, sig):
        if sig == signal.SIGKILL:
            state["exited"] = True

    sent.side_effect = stop
    assert lifecycle.terminate_verified_process(expected, budget=5.0) is True
    assert [call.args for call in sent.call_args_list] == [(321, signal.SIGTERM), (321, signal.SIGKILL)]
    assert state["now"] <= 105.0
    numeric.assert_not_called()
    closed.assert_called_once_with(321)


def test_denied_pidfd_signal_never_falls_back(rig):
    expected, _, _, closed, _, sent, numeric = rig
    sent.side_effect = PermissionError(errno.EPERM, "synthetic")
    assert lifecycle.terminate_verified_process(expected) is False
    numeric.assert_not_called()
    closed.assert_called_once_with(321)
