"""Deterministic cleanup faults; no real engine or secrets."""
import secrets
import subprocess
from unittest.mock import Mock

import pytest

from nodelab import engine_launch as launch, mihomo_process as lifecycle


class Clock:
    now = 0.0

    def monotonic(self):
        return self.now


@pytest.mark.parametrize("budget", [0, -1, True, None, "5", float("nan"), float("inf")])
def test_invalid_budget_has_no_process_side_effects(budget):
    proc = Mock()
    with pytest.raises(lifecycle.ProcessLifecycleError, match="^PROCESS_STOP_FAILED$"):
        lifecycle.stop_owned_process(proc, budget=budget)
    assert proc.mock_calls == []


def test_exhausted_budget_never_gains_a_minimum_timeout(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(lifecycle.time, "monotonic", clock.monotonic)
    proc = Mock()
    proc.poll.return_value = None
    waits = []

    def wait(*, timeout):
        waits.append(timeout)
        clock.now += timeout
        raise subprocess.TimeoutExpired("synthetic", timeout)

    proc.wait.side_effect = wait
    with pytest.raises(lifecycle.ProcessLifecycleError):
        lifecycle.stop_owned_process(proc, budget=0.25)
    assert waits == [0.25, 0.0, 0.0]
    assert clock.now == 0.25


def test_grace_kill_and_fallback_share_one_budget(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(lifecycle.time, "monotonic", clock.monotonic)
    proc = Mock()
    proc.poll.return_value = None
    waits = []

    def wait(*, timeout):
        waits.append(timeout)
        clock.now += timeout
        raise subprocess.TimeoutExpired("synthetic", timeout)

    proc.wait.side_effect = wait
    with pytest.raises(lifecycle.ProcessLifecycleError):
        lifecycle.stop_owned_process(proc)
    assert waits == [3.0, 2.0, 0.0]
    assert clock.now == 5.0


def test_cancellation_during_cleanup_still_reaps_owned_child():
    proc = Mock()
    proc.poll.return_value = None
    proc.terminate.side_effect = KeyboardInterrupt
    proc.kill.side_effect = lambda: setattr(proc.poll, "return_value", -9)
    lifecycle.stop_owned_process(proc)
    proc.kill.assert_called_once_with()
    proc.wait.assert_called_once()
    assert proc.poll() == -9


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt, subprocess.TimeoutExpired])
def test_unconfirmed_death_is_always_failure(failure):
    proc = Mock()
    proc.poll.return_value = None
    error = failure("synthetic", 0) if failure is subprocess.TimeoutExpired else failure()
    proc.wait.side_effect = error
    with pytest.raises(lifecycle.ProcessLifecycleError, match="^PROCESS_STOP_FAILED$"):
        lifecycle.stop_owned_process(proc)


@pytest.fixture
def owned():
    proc = Mock()
    proc.poll.return_value = None
    proc.terminate.side_effect = lambda: setattr(proc.poll, "return_value", 0)
    return launch.LaunchedEngine(proc, "http://127.0.0.1:12002", secrets.token_urlsafe(32), 12001)


def test_engine_context_closes_success_and_close_is_repeatable(owned):
    with owned as engine:
        assert engine is owned
    owned.close()
    owned.proc.terminate.assert_called_once_with()
    assert owned.proc.poll() == 0


@pytest.mark.parametrize("error", [ValueError, KeyboardInterrupt])
def test_engine_context_preserves_body_error_when_cleanup_succeeds(owned, error):
    with pytest.raises(error):
        with owned:
            raise error()
    owned.proc.terminate.assert_called_once_with()


def test_engine_context_cleanup_failure_overrides_body_error(owned, monkeypatch):
    monkeypatch.setattr(launch, "stop_owned_process", Mock(side_effect=lifecycle.ProcessLifecycleError))
    with pytest.raises(launch.EngineLaunchError, match="^PROCESS_STOP_FAILED$") as exc:
        with owned:
            raise ValueError("synthetic")
    assert exc.value.__suppress_context__ is True


@pytest.mark.parametrize("cancel", [False, True])
def test_failed_launch_does_not_swallow_cleanup_failure(monkeypatch, tmp_path, cancel):
    proc = Mock(pid=12345)
    proc.poll.return_value = None
    popen = Mock(return_value=proc)
    monkeypatch.setattr(launch.engine_binary, "verify_pinned_binary", lambda _, **kwargs: (True, "OK"))
    monkeypatch.setattr(launch.subprocess, "Popen", popen)
    listener = Mock(side_effect=KeyboardInterrupt) if cancel else Mock(return_value="LISTENER_FOREIGN_OWNER")
    monkeypatch.setattr(launch, "listener_owned_by", listener)
    stop = Mock(side_effect=lifecycle.ProcessLifecycleError)
    monkeypatch.setattr(launch, "stop_owned_process", stop)
    with pytest.raises(launch.EngineLaunchError, match="^PROCESS_STOP_FAILED$"):
        launch.start_verified_engine(
            exe=tmp_path / "synthetic", run_dir=tmp_path, config_path=tmp_path / "probe.yaml",
            mixed_port=12001, controller_port=12002, secret=secrets.token_urlsafe(32),
        )
    stop.assert_called_once_with(proc)
    assert popen.call_args.kwargs["stdout"] == subprocess.DEVNULL
    assert popen.call_args.kwargs["stderr"] == subprocess.DEVNULL


@pytest.mark.parametrize("cancel", [False, True])
def test_real_synthetic_child_context_leaves_external_process_alive(cancel):
    import sys

    def spawn():
        return subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    external = spawn()
    child = None
    try:
        child = spawn()
        engine = launch.LaunchedEngine(child, "http://127.0.0.1:12002", secrets.token_urlsafe(32), 12001)
        if cancel:
            with pytest.raises(KeyboardInterrupt):
                with engine:
                    raise KeyboardInterrupt
        else:
            with engine:
                assert child.poll() is None
        assert child.poll() is not None
        assert external.poll() is None
    finally:
        for proc in (child, external):
            if proc is not None:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=5)
