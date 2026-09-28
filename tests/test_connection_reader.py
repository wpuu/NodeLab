"""Bound reader faults plus real Linux own-PID/controller substitute checks."""
from dataclasses import replace
import json
import secrets
import subprocess
import sys
import time
from unittest.mock import Mock
from uuid import uuid4

import pytest

from nodelab import connection_reader as readers, engine_launch as launch
from nodelab.deadline import DeadlineExpired
from nodelab.mihomo_process import ProcessIdentity, process_identity


@pytest.fixture
def rig(monkeypatch):
    identity = ProcessIdentity(12345, 100, "a" * 32)
    proc = Mock(pid=identity.pid)
    proc.poll.return_value = None
    engine = launch.LaunchedEngine(proc, "http://127.0.0.1:12002", secrets.token_urlsafe(36), 12001,
                                   _identity=identity)
    monkeypatch.setattr(readers.mihomo_process, "process_identity", Mock(return_value=identity))
    owned = Mock(return_value="LAUNCH_OK")
    status = Mock(return_value=401)
    payload = Mock(return_value={"connections": None})
    monkeypatch.setattr(launch, "listener_owned_by", owned)
    monkeypatch.setattr(launch, "_controller_status", status)
    monkeypatch.setattr(launch, "_controller_json", payload)
    return engine, owned, status, payload


def test_bound_reader_uses_only_its_own_engine_identity_and_token(rig):
    engine, owned, status, payload = rig
    deadline = time.monotonic() + 10
    reader = readers.BoundConnectionReader(engine)
    assert reader(deadline) == {"connections": None}
    assert reader.run_id == engine._run_id
    assert reader.mixed_port == engine.mixed_port
    assert status.call_args_list[0].args == (engine.controller, "/connections", None)
    assert status.call_args_list[1].args[2] != engine.secret
    payload.assert_called_once_with(engine.controller, "/connections", engine.secret, deadline=deadline)
    assert {call.args for call in owned.call_args_list} == {(12345, 12001), (12345, 12002)}
    assert all(call.kwargs["deadline"] == deadline for call in owned.call_args_list)
    assert repr(reader) == "BoundConnectionReader(<private>)"
    assert engine.secret not in repr(reader)


@pytest.mark.parametrize("field,value", [
    ("controller", "http://example.invalid:12002"),
    ("controller", "http://127.0.0.1:12002/redirect"),
    ("controller", "http://secret@127.0.0.1:12002"),
    ("controller", "http://127.0.0.1:65536"),
    ("controller", "http://127.0.0.1:012002"),
    ("mixed_port", 12002), ("mixed_port", True), ("secret", "short"),
    ("_run_id", "not-a-run"), ("_identity", None),
    ("_identity", ProcessIdentity(12345, 100, None)),
    ("_identity", ProcessIdentity(12346, 100, "a" * 32)),
])
def test_invalid_binding_never_sends_http(rig, field, value):
    engine, owned, status, payload = rig
    with pytest.raises(readers.ConnectionReaderError, match="^READER_BINDING_INVALID$"):
        readers.BoundConnectionReader(replace(engine, **{field: value}))
    owned.assert_not_called()
    status.assert_not_called()
    payload.assert_not_called()


@pytest.mark.parametrize("identity", [None, ProcessIdentity(12345, 101, "a" * 32),
    ProcessIdentity(12345, 100, "b" * 32), ProcessIdentity(12345, 100, None)])
def test_reuse_or_missing_identity_stops_before_token(rig, monkeypatch, identity):
    engine, owned, status, payload = rig
    monkeypatch.setattr(readers.mihomo_process, "process_identity", lambda pid: identity)
    with pytest.raises(readers.ConnectionReaderError, match="^READER_IDENTITY_CHANGED$"):
        readers.BoundConnectionReader(engine)(time.monotonic() + 10)
    status.assert_not_called()
    payload.assert_not_called()


@pytest.mark.parametrize("code", ["LISTENER_MISSING", "LISTENER_FOREIGN_OWNER",
    "LISTENER_NOT_LOOPBACK", "LISTENER_UNVERIFIABLE"])
def test_untrusted_port_prevents_http(rig, code):
    engine, owned, status, payload = rig
    owned.return_value = code
    with pytest.raises(readers.ConnectionReaderError, match="^READER_LISTENER_UNTRUSTED$"):
        readers.BoundConnectionReader(engine)(time.monotonic() + 10)
    status.assert_not_called()
    payload.assert_not_called()


@pytest.mark.parametrize("when", ["before", "during_auth", "during_snapshot"])
def test_engine_death_never_returns_snapshot(rig, when):
    engine, owned, status, payload = rig
    if when == "before":
        engine.proc.poll.return_value = 1
    else:
        def die(*args, **kwargs):
            engine.proc.poll.return_value = 1
            return 401 if when == "during_auth" else {"connections": None}
        (status if when == "during_auth" else payload).side_effect = die
    with pytest.raises(readers.ConnectionReaderError, match="^READER_ENGINE_EXITED$"):
        readers.BoundConnectionReader(engine)(time.monotonic() + 10)
    if when != "during_snapshot":
        payload.assert_not_called()


@pytest.mark.parametrize("responses", [[200], [401, 200], [None], [401, 403]])
def test_auth_must_still_reject_missing_and_wrong_token(rig, responses):
    engine, owned, status, payload = rig
    status.side_effect = responses
    with pytest.raises(readers.ConnectionReaderError, match="^READER_AUTH_FAILED$"):
        readers.BoundConnectionReader(engine)(time.monotonic() + 10)
    payload.assert_not_called()


@pytest.mark.parametrize("snapshot", [None, {}, [], {"connections": {}},
    {"connections": [None]}, {"connections": [{"id": "invalid", "metadata": {}}]}])
def test_invalid_snapshot_is_refused(rig, snapshot):
    engine, _, _, payload = rig
    payload.return_value = snapshot
    with pytest.raises(readers.ConnectionReaderError, match="^READER_SNAPSHOT_INVALID$"):
        readers.BoundConnectionReader(engine)(time.monotonic() + 10)


def test_duplicate_connection_ids_refused(rig):
    engine, _, _, payload = rig
    row = {"id": str(uuid4()), "metadata": {}}
    payload.return_value = {"connections": [row, row]}
    with pytest.raises(readers.ConnectionReaderError, match="^READER_SNAPSHOT_INVALID$"):
        readers.BoundConnectionReader(engine)(time.monotonic() + 10)


def test_expired_budget_performs_no_http(rig):
    engine, owned, status, payload = rig
    with pytest.raises(DeadlineExpired):
        readers.BoundConnectionReader(engine)(time.monotonic() - 1)
    owned.assert_not_called()
    status.assert_not_called()
    payload.assert_not_called()


def test_identity_lookup_errors_are_fixed_not_raw(rig, monkeypatch):
    engine, _, status, payload = rig
    sentinel = secrets.token_urlsafe(32)
    monkeypatch.setattr(readers.mihomo_process, "process_identity", Mock(side_effect=OSError(sentinel)))
    with pytest.raises(readers.ConnectionReaderError, match="^READER_CHECK_FAILED$") as exc:
        readers.BoundConnectionReader(engine)(time.monotonic() + 10)
    assert sentinel not in str(exc.value)
    status.assert_not_called()


_CHILD = r'''
import json, socket, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
secret = json.loads(sys.stdin.readline())["secret"]
data = socket.socket()
data.bind(("127.0.0.1", 0))
data.listen()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        ok = self.path == "/connections" and self.headers.get("Authorization") == "Bearer " + secret
        self.send_response(200 if ok else 401)
        self.end_headers()
        if ok:
            self.wfile.write(b'{"connections":null}')
    def log_message(self, *args):
        pass
server = HTTPServer(("127.0.0.1", 0), Handler)
print(json.dumps({"mixed":data.getsockname()[1],"controller":server.server_port}), flush=True)
server.serve_forever()
'''


@pytest.mark.skipif(sys.platform != "linux", reason="real /proc assertions; Windows remains W2")
def test_real_owned_controller_and_pid_then_closed_engine():
    token = secrets.token_urlsafe(36)
    child = subprocess.Popen([sys.executable, "-c", _CHILD], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        child.stdin.write(json.dumps({"secret": token}) + "\n")
        child.stdin.flush()
        ports = json.loads(child.stdout.readline())
        child.stdin.close()
        engine = launch.LaunchedEngine(child, f'http://127.0.0.1:{ports["controller"]}', token,
                                       ports["mixed"], _identity=process_identity(child.pid))
        reader = readers.BoundConnectionReader(engine)
        assert reader(time.monotonic() + 10) == {"connections": None}
        engine.close()
        with pytest.raises(readers.ConnectionReaderError, match="^READER_ENGINE_EXITED$"):
            reader(time.monotonic() + 10)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        if not child.stdin.closed:
            child.stdin.close()
        child.stdout.close()


def test_owner_closed_even_if_process_still_alive_is_refused(rig):
    engine, owned, status, payload = rig
    owner = Mock(closed=True, active=False, raw_child=engine.proc)
    reader = readers.BoundConnectionReader(replace(engine, _owner=owner))
    with pytest.raises(readers.ConnectionReaderError, match="^READER_BINDING_INVALID$"):
        reader(time.monotonic() + 10)
    status.assert_not_called()
    payload.assert_not_called()


def test_port_takeover_during_snapshot_discards_response(rig):
    engine, owned, _, payload = rig

    def read(*args, **kwargs):
        owned.return_value = "LISTENER_FOREIGN_OWNER"
        return {"connections": None}

    payload.side_effect = read
    with pytest.raises(readers.ConnectionReaderError, match="^READER_LISTENER_UNTRUSTED$"):
        readers.BoundConnectionReader(engine)(time.monotonic() + 10)


def test_identity_change_during_snapshot_discards_response(rig, monkeypatch):
    engine, _, _, payload = rig

    def read(*args, **kwargs):
        monkeypatch.setattr(readers.mihomo_process, "process_identity", lambda pid:
                            ProcessIdentity(pid, 101, "a" * 32))
        return {"connections": None}

    payload.side_effect = read
    with pytest.raises(readers.ConnectionReaderError, match="^READER_IDENTITY_CHANGED$"):
        readers.BoundConnectionReader(engine)(time.monotonic() + 10)


def test_bound_fixture_adapter_uses_engine_values_and_final_guard(rig, monkeypatch):
    from nodelab import fixture_capture
    engine, _, _, _ = rig
    reader = readers.BoundConnectionReader(engine)
    sink = Mock(return_value="private-capture")
    monkeypatch.setattr(fixture_capture, "collect_fixture_request", sink)
    tls = object()  # only testing delegation here, no HTTP/TLS I/O
    assert fixture_capture.collect_bound_fixture_request(
        "https://localhost/", reader=reader, tls=tls, source="EXIT_A",
    ) == "private-capture"
    kwargs = sink.call_args.kwargs
    assert kwargs["run_id"] == engine._run_id
    assert kwargs["proxy_port"] == engine.mixed_port
    assert kwargs["snapshot_reader"] is reader
    assert kwargs["_runtime_check"] == reader.assert_current
    assert kwargs["tls"] is tls
