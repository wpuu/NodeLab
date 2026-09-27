"""F2b: runtime facts of a started engine (P0-01 objects, P0-04 auth, P0-05 PID).

The listener-ownership tests are hermetic: they bind ordinary sockets from the
test process, no engine needed. The launch tests are opt-in through
NODELAB_MIHOMO_EXE.

A positive verdict is still impossible: `types.PROBE_GATE_OPEN` is False and
nothing here produces a probe result. These assertions are about the runtime
being the one we asked for, not about a node working.
"""

from __future__ import annotations

import os
import secrets
import socket
import sys
import time
from pathlib import Path

import pytest
import yaml

from nodelab import engine_launch
from nodelab.engine_config import GROUP_NAME, NODE_NAME, build_probe_config
from nodelab.engine_launch import EngineLaunchError, listener_owned_by, start_verified_engine
from nodelab.parser import parse_uri
from nodelab.types import PROBE_GATE_OPEN

REAL_EXE = os.environ.get("NODELAB_MIHOMO_EXE")
FAKE_UUID = "11111111-2222-3333-4444-555555555555"
pytestmark = pytest.mark.skipif(sys.platform == "win32" and not REAL_EXE,
                                reason="Windows listener facts belong to W2")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


# --- hermetic: listener ownership ------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="uses /proc; Windows path is W2")
def test_own_loopback_listener_is_accepted():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(5)
        port = sock.getsockname()[1]
        assert listener_owned_by(os.getpid(), port) == "LAUNCH_OK"


@pytest.mark.skipif(os.name == "nt", reason="uses /proc; Windows path is W2")
def test_a_foreign_mirror_of_the_same_port_does_not_fail_our_socket():
    """Regression: an "all listeners must be loopback" rule was wrong.

    A sandbox/host port-forwarder may mirror the port onto another address
    from another process. Only the sockets our own PID holds may be judged.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(5)
        port = sock.getsockname()[1]
        time.sleep(1.5)  # let any external mirror appear
        assert listener_owned_by(os.getpid(), port) == "LAUNCH_OK"


@pytest.mark.skipif(os.name == "nt", reason="uses /proc; Windows path is W2")
def test_non_loopback_bind_is_refused():
    with socket.socket() as sock:
        sock.bind(("0.0.0.0", 0))
        sock.listen(5)
        port = sock.getsockname()[1]
        assert listener_owned_by(os.getpid(), port) == "LISTENER_NOT_LOOPBACK"


@pytest.mark.skipif(os.name == "nt", reason="uses /proc; Windows path is W2")
def test_port_owned_by_another_process_is_refused():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(5)
        port = sock.getsockname()[1]
        assert listener_owned_by(1, port) == "LISTENER_FOREIGN_OWNER"


@pytest.mark.skipif(os.name == "nt", reason="uses /proc; Windows path is W2")
def test_absent_listener_is_reported_as_missing():
    port = free_port()
    assert listener_owned_by(os.getpid(), port) == "LISTENER_MISSING"


def test_unpinned_binary_never_launches(tmp_path):
    node = parse_uri(f"vless://{FAKE_UUID}@198.51.100.7:443"
                     "?encryption=none&security=tls&sni=a.example&type=tcp#n")
    cfg = build_probe_config(node, mixed_port=free_port(), controller_port=free_port(),
                             secret=secrets.token_urlsafe(36)[:48])
    path = tmp_path / "probe.yaml"
    path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    with pytest.raises(EngineLaunchError) as info:
        start_verified_engine(exe=tmp_path / "no-such-engine", run_dir=tmp_path,
                              config_path=path, mixed_port=cfg["mixed-port"],
                              controller_port=free_port(), secret=cfg["secret"])
    assert info.value.code == "BINARY_REJECTED"


# --- opt-in: the genuine pinned engine --------------------------------------

@pytest.fixture
def launched(tmp_path):
    if not REAL_EXE:
        pytest.skip("set NODELAB_MIHOMO_EXE to a pinned v1.19.31 binary")
    node = parse_uri(f"vless://{FAKE_UUID}@198.51.100.7:443"
                     "?encryption=none&security=tls&sni=a.example&type=tcp&fp=ios#n")
    mixed, controller = free_port(), free_port()
    cfg = build_probe_config(node, mixed_port=mixed, controller_port=controller,
                             secret=secrets.token_urlsafe(36)[:48])
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / ".owner.json").write_text("{}", encoding="utf-8")
    path = run_dir / "probe.yaml"
    path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
    engine = start_verified_engine(exe=REAL_EXE, run_dir=run_dir, config_path=path,
                                   mixed_port=mixed, controller_port=controller,
                                   secret=cfg["secret"])
    try:
        yield engine, run_dir, cfg
    finally:
        if engine.proc.poll() is None:
            engine.proc.kill()
            engine.proc.wait(timeout=10)


def test_preflight_accepts_the_real_engine(launched):
    engine, _run_dir, cfg = launched
    assert engine.proc.poll() is None
    assert engine.mixed_port == cfg["mixed-port"]
    assert listener_owned_by(engine.proc.pid, engine.mixed_port) == "LAUNCH_OK"
    assert engine_launch.probe_socket(engine) is True


def test_controller_rejects_every_wrong_token(launched):
    engine, _run_dir, _cfg = launched
    base = engine.controller
    assert engine_launch._controller_status(base, "/configs", None) == 401
    assert engine_launch._controller_status(base, "/configs", "") == 401
    assert engine_launch._controller_status(base, "/configs", engine.secret[:-1]) == 401
    assert engine_launch._controller_status(base, "/configs", engine.secret + "x") == 401
    assert engine_launch._controller_status(base, "/configs", engine.secret) == 200


def test_declared_objects_exist_in_the_running_engine(launched):
    engine, _run_dir, _cfg = launched
    table = engine_launch._controller_json(engine.controller, "/proxies", engine.secret)
    assert NODE_NAME in table["proxies"]
    assert table["proxies"][GROUP_NAME]["now"] == NODE_NAME


def test_a_real_run_leaves_no_extra_files_in_the_private_dir(launched):
    """Guards the `_Recovery` directory allowlist against engine side files."""
    engine, run_dir, _cfg = launched
    time.sleep(1.0)
    assert sorted(p.name for p in run_dir.iterdir()) == [".owner.json", "probe.yaml"]


def test_failed_preflight_leaves_no_orphan_child(tmp_path):
    """A wrong secret must abort AND reap the child we spawned."""
    if not REAL_EXE:
        pytest.skip("set NODELAB_MIHOMO_EXE to a pinned v1.19.31 binary")
    node = parse_uri(f"vless://{FAKE_UUID}@198.51.100.7:443"
                     "?encryption=none&security=tls&sni=a.example&type=tcp#n")
    mixed, controller = free_port(), free_port()
    cfg = build_probe_config(node, mixed_port=mixed, controller_port=controller,
                             secret=secrets.token_urlsafe(36)[:48])
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    path = run_dir / "probe.yaml"
    path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    before = _child_pids()
    with pytest.raises(EngineLaunchError) as info:
        start_verified_engine(exe=REAL_EXE, run_dir=run_dir, config_path=path,
                              mixed_port=mixed, controller_port=controller,
                              secret=secrets.token_urlsafe(36)[:48],  # not the config's
                              deadline_seconds=15.0)
    assert info.value.code == "CONTROLLER_AUTH_WEAK"
    time.sleep(0.5)
    assert _child_pids() == before


def _child_pids() -> set[int]:
    """Live children of this process, read straight from /proc.

    Deliberately does not shell out: spawning `ps` would itself be a child and
    would pollute the very set being measured.
    """
    if os.name == "nt":  # pragma: no cover - W2 territory
        return set()
    mine = os.getpid()
    found: set[int] = set()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text()
        except OSError:
            continue
        ppid = state = None
        for line in status.splitlines():
            if line.startswith("PPid:"):
                ppid = int(line.split()[1])
            elif line.startswith("State:"):
                state = line.split()[1]
        if ppid == mine and state != "Z":
            found.add(int(entry.name))
    return found


def test_launch_never_opens_the_verdict_gate():
    assert PROBE_GATE_OPEN is False
