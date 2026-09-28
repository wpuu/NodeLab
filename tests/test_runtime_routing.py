"""Pinned controller shape fixtures; not protocol or per-request route proof."""
import secrets
from itertools import chain, repeat
from unittest.mock import Mock

import pytest

from nodelab import engine_launch as launch
from nodelab.types import PROBE_GATE_OPEN


@pytest.fixture
def snapshots():
    return {
        "/configs": {"mode": "rule"},
        "/proxies": {"proxies": {
            "NODE": {"type": "Vless"},
            "PROBE": {"type": "Selector", "now": "NODE", "all": ["NODE"]},
            "DIRECT": {"type": "Direct"},  # built-ins may exist, but not in PROBE
        }},
        "/rules": {"rules": [{
            "index": 0, "type": "Match", "payload": "", "proxy": "PROBE", "size": -1,
            "extra": {"disabled": False, "hitCount": 0},
        }]},
    }


@pytest.fixture
def start(monkeypatch, tmp_path, snapshots):
    proc = Mock(pid=12345)
    proc.poll.return_value = None
    proc.terminate.side_effect = lambda: setattr(proc.poll, "return_value", 0)
    token = secrets.token_urlsafe(32)
    monkeypatch.setattr(launch.engine_binary, "verify_pinned_binary", lambda _, **kwargs: (True, "OK"))
    monkeypatch.setattr(launch.subprocess, "Popen", Mock(return_value=proc))
    monkeypatch.setattr(launch, "listener_owned_by", lambda *args, **kwargs: "LAUNCH_OK")
    monkeypatch.setattr(launch, "_controller_status",
                        lambda base, path, credential, **kwargs: 200 if credential == token else 401)
    reads = []

    def read(base, path, credential, **kwargs):
        assert credential == token
        reads.append(path)
        return snapshots[path]

    monkeypatch.setattr(launch, "_controller_json", read)

    def run():
        return launch.start_verified_engine(
            exe=tmp_path / "synthetic", run_dir=tmp_path,
            config_path=tmp_path / "probe.yaml", mixed_port=12001,
            controller_port=12002, secret=token,
        )

    return run, proc, reads


@pytest.mark.parametrize("protocol", ["Vless", "Trojan"])
@pytest.mark.parametrize("wrapped", [False, True])
def test_accepts_exact_runtime_shape(start, snapshots, protocol, wrapped):
    snapshots["/proxies"]["proxies"]["NODE"]["type"] = protocol
    if not wrapped:
        del snapshots["/rules"]["rules"][0]["extra"]
    run, proc, reads = start
    assert run().proc is proc
    assert reads == ["/configs", "/proxies", "/rules"]
    proc.kill.assert_not_called()
    assert PROBE_GATE_OPEN is False


# Replace one nested field in an otherwise valid response. All must fail at
# the launch boundary and reap only the spawned child, with a fixed code.
@pytest.mark.parametrize("path,value,code", [
    (("/configs",), None, "RUNTIME_MODE_INVALID"),
    (("/configs", "mode"), "direct", "RUNTIME_MODE_INVALID"),
    (("/configs", "mode"), "global", "RUNTIME_MODE_INVALID"),
    (("/configs", "mode"), None, "RUNTIME_MODE_INVALID"),
    (("/proxies",), None, "PROXY_OBJECT_MISSING"),
    (("/proxies", "proxies"), [], "PROXY_OBJECT_MISSING"),
    (("/proxies", "proxies", "NODE"), {}, "PROXY_OBJECT_MISSING"),
    (("/proxies", "proxies", "NODE", "type"), "Direct", "PROXY_OBJECT_MISSING"),
    (("/proxies", "proxies", "NODE", "type"), [], "PROXY_OBJECT_MISSING"),
    (("/proxies", "proxies", "PROBE"), None, "GROUP_OBJECT_MISSING"),
    (("/proxies", "proxies", "PROBE", "now"), "DIRECT", "GROUP_OBJECT_MISSING"),
    (("/proxies", "proxies", "PROBE", "type"), "Fallback", "GROUP_OBJECT_MISSING"),
    (("/proxies", "proxies", "PROBE", "all"), ["NODE", "DIRECT"], "GROUP_OBJECT_MISSING"),
    (("/proxies", "proxies", "PROBE", "all"), [], "GROUP_OBJECT_MISSING"),
    (("/proxies", "proxies", "PROBE", "all"), "NODE", "GROUP_OBJECT_MISSING"),
    (("/rules",), None, "RUNTIME_RULES_INVALID"),
    (("/rules", "rules"), [], "RUNTIME_RULES_INVALID"),
    (("/rules", "rules"), {}, "RUNTIME_RULES_INVALID"),
    (("/rules", "rules"), [None], "RUNTIME_RULES_INVALID"),
    (("/rules", "rules", 0, "proxy"), "DIRECT", "RUNTIME_RULES_INVALID"),
    (("/rules", "rules", 0, "type"), "Domain", "RUNTIME_RULES_INVALID"),
    (("/rules", "rules", 0, "payload"), "example.test", "RUNTIME_RULES_INVALID"),
    (("/rules", "rules", 0, "index"), 1, "RUNTIME_RULES_INVALID"),
    (("/rules", "rules", 0, "index"), False, "RUNTIME_RULES_INVALID"),
    (("/rules", "rules", 0, "extra"), None, "RUNTIME_RULES_INVALID"),
    (("/rules", "rules", 0, "extra"), {}, "RUNTIME_RULES_INVALID"),
    (("/rules", "rules", 0, "extra", "disabled"), True, "RUNTIME_RULES_INVALID"),
    (("/rules", "rules", 0, "extra", "disabled"), 0, "RUNTIME_RULES_INVALID"),
])
def test_invalid_runtime_reaps_child(start, snapshots, path, value, code):
    parent = snapshots
    for part in path[:-1]:
        parent = parent[part]
    parent[path[-1]] = value
    run, proc, _ = start
    with pytest.raises(launch.EngineLaunchError) as exc:
        run()
    assert str(exc.value) == code
    proc.terminate.assert_called_once_with()
    proc.wait.assert_called_once()
    assert 0 <= proc.wait.call_args.kwargs["timeout"] <= 3.0


def test_extra_direct_rule_is_rejected_even_with_match_present(start, snapshots):
    snapshots["/rules"]["rules"].insert(0, {
        "index": 0, "type": "Domain", "payload": "example.test", "proxy": "DIRECT",
    })
    run, proc, _ = start
    with pytest.raises(launch.EngineLaunchError, match="^RUNTIME_RULES_INVALID$"):
        run()
    proc.terminate.assert_called_once_with()


def test_child_exit_during_snapshot_fetch_is_not_success(start, snapshots):
    run, proc, _ = start
    # controller ownership, auth polling, data ownership, final liveness
    proc.poll.side_effect = chain([None, None, None], repeat(1))
    with pytest.raises(launch.EngineLaunchError, match="^ENGINE_EXITED$"):
        run()
    proc.kill.assert_not_called()
