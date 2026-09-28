"""Synthetic monotonic clocks, no real engine, credentials or Windows claims."""
import hashlib
import secrets
import subprocess
from unittest.mock import Mock

import pytest

from nodelab import deadline as timing, engine_binary as binary, engine_launch as launch


@pytest.fixture
def clock(monkeypatch):
    value = [100.0]
    monkeypatch.setattr(timing.time, "monotonic", lambda: value[0])
    monkeypatch.setattr(timing.time, "sleep", lambda seconds: value.__setitem__(0, value[0] + seconds))
    return value


@pytest.fixture
def harness(monkeypatch, tmp_path, clock):
    proc = Mock(pid=12345)
    proc.poll.return_value = None
    proc.terminate.side_effect = lambda: setattr(proc.poll, "return_value", 0)
    spawn = Mock(return_value=proc)
    monkeypatch.setattr(launch.subprocess, "Popen", spawn)
    events = []
    costs = {}
    token = secrets.token_urlsafe(32)

    def step(name, result, deadline):
        events.append((name, deadline, deadline - clock[0]))
        clock[0] += costs.get(name, 0.0)
        return result

    monkeypatch.setattr(binary, "verify_pinned_binary", lambda exe, *, deadline:
                        step("binary", (True, "OK"), deadline))
    monkeypatch.setattr(launch, "listener_owned_by", lambda pid, port, *, deadline:
                        step(str(port), "LAUNCH_OK", deadline))

    def status(base, path, credential, *, deadline):
        name = "unauth" if credential is None else "auth" if credential == token else "wrong"
        return step(name, 200 if credential == token else 401, deadline)

    snapshots = {
        "/configs": {"mode": "rule"},
        "/proxies": {"proxies": {"NODE": {"type": "Vless"},
                     "PROBE": {"type": "Selector", "now": "NODE", "all": ["NODE"]}}},
        "/rules": {"rules": [{"index": 0, "type": "Match", "payload": "", "proxy": "PROBE"}]},
    }
    monkeypatch.setattr(launch, "_controller_status", status)
    monkeypatch.setattr(launch, "_controller_json", lambda base, path, token, *, deadline:
                        step(path, snapshots[path], deadline))

    def run(budget=1.0):
        return launch.start_verified_engine(
            exe=tmp_path / "synthetic", run_dir=tmp_path, config_path=tmp_path / "probe.yaml",
            mixed_port=12001, controller_port=12002, secret=token, deadline_seconds=budget,
        )

    return run, proc, spawn, events, costs


@pytest.mark.parametrize("budget", [0, -1, True, None, "1", float("nan"), float("inf")])
def test_bad_deadline_rejected_before_any_work(harness, budget):
    run, proc, spawn, events, _ = harness
    with pytest.raises(launch.EngineLaunchError, match="^INVALID_DEADLINE$"):
        run(budget)
    assert events == []
    spawn.assert_not_called()


@pytest.mark.parametrize("stage", ["binary", "12002", "unauth", "wrong", "auth", "12001", "/configs", "/proxies", "/rules"])
def test_expired_stage_never_continues_even_if_it_returned_success(harness, stage):
    run, proc, spawn, events, costs = harness
    costs[stage] = 1.0
    with pytest.raises(launch.EngineLaunchError, match="^LAUNCH_TIMEOUT$"):
        run()
    assert events[-1][0] == stage
    if stage == "binary":
        spawn.assert_not_called()
    else:
        proc.terminate.assert_called_once_with()
        assert proc.poll() == 0


def test_all_stages_use_same_absolute_deadline(harness):
    run, proc, _, events, costs = harness
    costs.update({"binary": 0.2, "12002": 0.1, "unauth": 0.1})
    engine = run()
    assert {event[1] for event in events} == {101.0}
    assert events[-1][2] == pytest.approx(0.6)
    engine.close()


def test_poll_sleep_cannot_extend_small_budget(harness, monkeypatch, clock):
    run, proc, _, _, _ = harness
    monkeypatch.setattr(launch, "listener_owned_by", lambda *a, **k: "LISTENER_MISSING")
    with pytest.raises(launch.EngineLaunchError, match="^LAUNCH_TIMEOUT$"):
        run(0.025)
    assert clock[0] == pytest.approx(100.025)
    proc.terminate.assert_called_once_with()


def test_binary_version_uses_remaining_budget(monkeypatch, tmp_path, clock):
    exe = tmp_path / "synthetic"
    exe.write_bytes(b"not executable; subprocess is mocked")
    monkeypatch.setenv(binary.PIN_ENV, hashlib.sha256(exe.read_bytes()).hexdigest())
    runner = Mock(return_value=subprocess.CompletedProcess([], 0, "Mihomo Meta v1.19.31"))
    monkeypatch.setattr(binary.subprocess, "run", runner)
    assert binary.verify_pinned_binary(exe, deadline=100.125) == (True, "BINARY_OK")
    assert runner.call_args.kwargs["timeout"] == 0.125
    assert binary.verify_pinned_binary(exe, deadline=100.0) == (False, "BINARY_TIMEOUT")
    assert runner.call_count == 1


def test_digest_stops_before_io_after_deadline(tmp_path, clock):
    with pytest.raises(timing.DeadlineExpired):
        binary.file_digest(tmp_path / "nonexistent", deadline=100.0)


def test_windows_helper_passes_remaining_budget_without_claiming_windows(monkeypatch, clock):
    runner = Mock(return_value=subprocess.CompletedProcess([], 0, "127.0.0.1|12345"))
    monkeypatch.setattr(launch.subprocess, "run", runner)
    assert launch._windows_own_listeners(12345, 12002, deadline=100.25) == (True, ["127.0.0.1"])
    assert runner.call_args.kwargs["timeout"] == 0.25


def test_http_open_passes_remaining_budget(monkeypatch, clock):
    opener = Mock()
    monkeypatch.setattr(launch.urllib.request, "build_opener", Mock(return_value=opener))
    request = launch.urllib.request.Request("http://127.0.0.1:12002/configs")
    launch._controller_open(request, deadline=100.125)
    opener.open.assert_called_once_with(request, timeout=0.125)


def test_streamed_body_cannot_return_success_after_deadline(monkeypatch, clock):
    response = Mock(status=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)

    def read(size):
        clock[0] += 0.6
        return b" "

    response.read1.side_effect = read
    monkeypatch.setattr(launch, "_controller_open", lambda *a, **k: response)
    with pytest.raises(timing.DeadlineExpired):
        launch._controller_json("http://127.0.0.1:12002", "/configs", secrets.token_urlsafe(32), deadline=101.0)
    assert response.read1.call_count == 2
    response.__exit__.assert_called_once()


def test_spawn_returning_after_deadline_is_still_cleaned(harness, clock):
    run, proc, spawn, events, _ = harness

    def slow_spawn(*args, **kwargs):
        clock[0] += 1.0
        return proc

    spawn.side_effect = slow_spawn
    with pytest.raises(launch.EngineLaunchError, match="^LAUNCH_TIMEOUT$"):
        run()
    assert [event[0] for event in events] == ["binary"]
    proc.terminate.assert_called_once_with()


def test_cleanup_failure_outranks_deadline(harness, monkeypatch):
    run, proc, _, _, costs = harness
    costs["unauth"] = 1.0
    monkeypatch.setattr(launch, "stop_owned_process", Mock(side_effect=RuntimeError("synthetic")))
    with pytest.raises(launch.EngineLaunchError, match="^PROCESS_STOP_FAILED$"):
        run()


@pytest.mark.parametrize("data", [b" " * (1024 * 1024 + 1), b'"\xff"', b'{"mode":'])
def test_invalid_or_oversized_controller_body_is_not_accepted(monkeypatch, data):
    import io
    response = io.BytesIO(data)
    response.status = 200
    monkeypatch.setattr(launch, "_controller_open", lambda *a, **k: response)
    assert launch._controller_json("http://127.0.0.1:12002", "/configs", secrets.token_urlsafe(32)) is None
    assert response.closed
