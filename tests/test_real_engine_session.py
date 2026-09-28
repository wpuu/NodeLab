"""Opt-in Linux session acceptance; only generated synthetic credentials.

No outbound probe, protocol handshake or Windows acceptance is performed.
Run using scripts/f2_session_gate.py for a supported-Python, no-skip gate.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import uuid

import pytest

from nodelab import engine_binary, engine_launch, engine_session
from nodelab.mihomo_config import RunContext
from nodelab.connection_reader import BoundConnectionReader
from nodelab.parser import parse_uri
from nodelab.types import PROBE_GATE_OPEN

EXE = os.environ.get("NODELAB_MIHOMO_EXE")
pytestmark = [
    pytest.mark.skipif(not EXE, reason="pinned v1.19.31 executable required"),
    pytest.mark.skipif(sys.platform != "linux", reason="Linux gate only; Windows requires W2"),
]


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    if sys.version_info < (3, 12):
        pytest.fail("PYTHON_VERSION_UNSUPPORTED")
    monkeypatch.delenv(engine_binary.PIN_ENV, raising=False)
    exe = Path(EXE)
    assert engine_binary.verify_pinned_binary(exe) == (True, "BINARY_OK")
    assert engine_binary.file_digest(exe) in engine_binary.KNOWN_DIGESTS
    root = tmp_path / "private"
    # Hold distinct mixed/controller ports while choosing them; release just
    # before launch. A competing bind must fail preflight, never be adopted.
    with ExitStack() as sockets:
        selected = []
        for _ in range(2):
            sock = sockets.enter_context(socket.socket())
            sock.bind(("127.0.0.1", 0))
            selected.append(sock.getsockname()[1])
    # A local sentinel listener is the configured upstream. No data-plane
    # request is issued, so there must be no connection to this listener.
    with socket.socket() as upstream:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen()
        upstream.setblocking(False)
        yield exe, root, selected, upstream
        try:
            connection, _ = upstream.accept()
        except BlockingIOError:
            pass
        else:
            connection.close()
            pytest.fail("UNEXPECTED_UPSTREAM_CONNECTION")


def node_for(protocol, transport, upstream):
    secret = str(uuid.uuid4()) if protocol == "vless" else secrets.token_urlsafe(32)
    query = f"security=tls&sni=fixture.example.invalid&type={transport}"
    if protocol == "vless":
        query += "&encryption=none"
    if transport == "ws":
        query += "&host=fixture.example.invalid&path=%2Fsynthetic"
    if transport == "grpc":
        query += "&serviceName=synthetic"
    return parse_uri(f"{protocol}://{secret}@127.0.0.1:{upstream.getsockname()[1]}?{query}")


def open_session(fixture, protocol="trojan", transport="tcp"):
    exe, root, ports, upstream = fixture
    return engine_session.private_engine_session(
        node_for(protocol, transport, upstream), exe=exe, root=root,
        mixed_port=ports[0], controller_port=ports[1], deadline_seconds=20.0,
    )


def assert_clean(root, proc):
    assert proc.poll() is not None
    assert list(root.iterdir()) == []
    assert PROBE_GATE_OPEN is False


@pytest.mark.parametrize("protocol", ["vless", "trojan"])
@pytest.mark.parametrize("transport", ["tcp", "ws", "grpc"])
def test_real_complete_session(fixture, protocol, transport):
    with open_session(fixture, protocol, transport) as engine:
        owner = engine._owner
        proc = engine.proc
        assert proc.poll() is None
        assert owner.raw_child is proc
        assert sorted(p.name for p in owner.run_dir.iterdir()) == [".owner.json", "probe.yaml"]
        assert (owner.run_dir / "probe.yaml").stat().st_mode & 0o777 == 0o600
        marker = json.loads((owner.run_dir / ".owner.json").read_text())
        assert marker["child_pid"] == proc.pid
        assert marker["child_create_time"] is not None
        assert marker["child_exe_fingerprint"] is not None
        assert engine.secret not in json.dumps(marker)
        assert engine_launch.listener_owned_by(proc.pid, fixture[2][0]) == "LAUNCH_OK"
        assert engine_launch.listener_owned_by(proc.pid, fixture[2][1]) == "LAUNCH_OK"
        reader = BoundConnectionReader(engine)
        assert reader.run_id == engine._run_id
        # No data-plane request is made: this only validates authenticated,
        # instance-bound controller reading, not per-request route proof.
        assert reader(time.monotonic() + 10)["connections"] in (None, [])
    assert owner.closed
    assert_clean(fixture[1], proc)


@pytest.mark.parametrize("error", [ValueError, KeyboardInterrupt])
def test_real_session_body_failure_cleans_up(fixture, error):
    with pytest.raises(error):
        with open_session(fixture) as engine:
            proc = engine.proc
            raise error()
    assert_clean(fixture[1], proc)


def test_real_session_close_is_repeatable(fixture):
    with open_session(fixture) as engine:
        proc = engine.proc
        engine.close()
        engine.close()
        assert_clean(fixture[1], proc)
    assert_clean(fixture[1], proc)


def test_real_config_rejection_removes_private_files(fixture, monkeypatch):
    original = RunContext.write_yaml

    def invalid_config(owner, config):
        broken = dict(config)
        broken["proxies"] = "not-a-proxy-list"
        return original(owner, broken)

    monkeypatch.setattr(RunContext, "write_yaml", invalid_config)
    with pytest.raises(engine_launch.EngineLaunchError, match="^CONFIG_TEST_FAILED$"):
        with open_session(fixture):
            pytest.fail("INVALID_CONFIG_ACCEPTED")
    assert list(fixture[1].iterdir()) == []


def test_real_session_does_not_stop_external_process(fixture):
    external = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        with open_session(fixture) as engine:
            proc = engine.proc
        assert_clean(fixture[1], proc)
        assert external.poll() is None
    finally:
        if external.poll() is None:
            external.kill()
        external.wait(timeout=5)
