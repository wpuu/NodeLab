"""Synthetic controller isolation checks; no engine or real credentials."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import threading
from unittest.mock import Mock

import pytest

from nodelab import engine_launch as launch


@contextmanager
def server(status=200, location=None, body=b'{"ok": true}'):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.headers.get("Authorization"))
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", received
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_never_forwards_token(status):
    token = secrets.token_urlsafe(32)
    with server() as (target, stolen):
        with server(status, target + "/sink") as (base, received):
            assert launch._controller_status(base, "/configs", token) == status
            assert launch._controller_json(base, "/configs", token) is None
            assert received == ["Bearer " + token] * 2
        assert stolen == []


def test_controller_ignores_environment_proxy(monkeypatch):
    token = secrets.token_urlsafe(32)
    with server() as (proxy, stolen), server() as (base, received):
        for key in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
            monkeypatch.setenv(key, proxy)
        for key in ("no_proxy", "NO_PROXY"):
            monkeypatch.setenv(key, "")
        assert launch._controller_status(base, "/configs", token) == 200
        assert launch._controller_json(base, "/configs", token) == {"ok": True}
        assert received == ["Bearer " + token] * 2
        assert stolen == []


@pytest.mark.parametrize("code", ["LISTENER_FOREIGN_OWNER", "LISTENER_NOT_LOOPBACK", "LISTENER_UNVERIFIABLE"])
def test_untrusted_controller_never_receives_http(monkeypatch, tmp_path, code):
    proc = Mock(pid=12345)
    proc.poll.return_value = None
    proc.terminate.side_effect = lambda: setattr(proc.poll, "return_value", 0)
    monkeypatch.setattr(launch.engine_binary, "verify_pinned_binary", lambda _, **kwargs: (True, "OK"))
    monkeypatch.setattr(launch.subprocess, "Popen", Mock(return_value=proc))
    ownership = Mock(return_value=code)
    monkeypatch.setattr(launch, "listener_owned_by", ownership)
    http = Mock(side_effect=AssertionError("HTTP before ownership"))
    monkeypatch.setattr(launch, "_controller_status", http)
    with pytest.raises(launch.EngineLaunchError) as exc:
        launch.start_verified_engine(
            exe=tmp_path / "synthetic", run_dir=tmp_path,
            config_path=tmp_path / "probe.yaml", mixed_port=12001,
            controller_port=12002, secret=secrets.token_urlsafe(32),
        )
    assert exc.value.code == code
    ownership.assert_called_once()
    assert ownership.call_args.args == (proc.pid, 12002)
    assert "deadline" in ownership.call_args.kwargs
    http.assert_not_called()
    proc.terminate.assert_called_once()
    proc.wait.assert_called_once()
    assert 0 <= proc.wait.call_args.kwargs["timeout"] <= 3.0


def test_verified_controller_precedes_auth_and_data_listener(monkeypatch, tmp_path):
    proc = Mock(pid=12345)
    proc.poll.return_value = None
    proc.terminate.side_effect = lambda: setattr(proc.poll, "return_value", 0)
    monkeypatch.setattr(launch.engine_binary, "verify_pinned_binary", lambda _, **kwargs: (True, "OK"))
    monkeypatch.setattr(launch.subprocess, "Popen", Mock(return_value=proc))
    events = []

    def owned(pid, port, **kwargs):
        events.append(("owner", port))
        return "LAUNCH_OK"

    token = secrets.token_urlsafe(32)

    def status(base, path, credential, **kwargs):
        assert events[0] == ("owner", 12002)
        events.append(("http", credential is not None))
        return 200 if credential == token else 401

    monkeypatch.setattr(launch, "listener_owned_by", owned)
    monkeypatch.setattr(launch, "_controller_status", status)
    snapshots = {
        "/configs": {"mode": "rule"},
        "/proxies": {"proxies": {
            "NODE": {"type": "Vless"},
            "PROBE": {"type": "Selector", "now": "NODE", "all": ["NODE"]},
        }},
        "/rules": {"rules": [{"index": 0, "type": "Match", "payload": "", "proxy": "PROBE"}]},
    }
    def snapshot(base, path, token, **kwargs):
        events.append(("json", path))
        return snapshots[path]

    monkeypatch.setattr(launch, "_controller_json", snapshot)
    engine = launch.start_verified_engine(
        exe=tmp_path / "synthetic", run_dir=tmp_path,
        config_path=tmp_path / "probe.yaml", mixed_port=12001,
        controller_port=12002, secret=token,
    )
    assert engine.proc is proc
    expected = [("owner", 12002)]
    for authenticated in (False, True, True):
        expected += [("owner", 12002), ("http", authenticated), ("owner", 12002)]
    expected.append(("owner", 12001))
    for path in ("/configs", "/proxies", "/rules"):
        expected += [("owner", 12002), ("json", path), ("owner", 12002)]
    assert events == expected
    proc.kill.assert_not_called()


@pytest.mark.parametrize("status", [201, 202, 206])
def test_json_requires_http_200_even_if_body_is_valid(status):
    with server(status) as (base, _):
        assert launch._controller_json(base, "/connections", secrets.token_urlsafe(32)) is None


@pytest.mark.parametrize("body", [
    b'{"mode":"direct","mode":"rule"}',
    b'{"mode":"rule","mode":"direct"}',
    b'{"connections":[],"connections":null}',
    b'{"connections":[{"chains":["DIRECT"],"chains":["NODE","PROBE"]}]}',
    b'{"proxies":{"PROBE":{"now":"DIRECT","now":"NODE"}}}',
    b'{"rules":[{"proxy":"DIRECT","proxy":"PROBE"}]}',
    b'{"mode":"direct","\\u006dode":"rule"}',
    b'{"mode":"rule","mode":"rule"}',
    b'{"connections":null,"extra":NaN}',
    b'{"connections":null,"extra":Infinity}',
    b'{"connections":null,"extra":-Infinity}',
    b'{"connections":null,"extra":1e400}',
    b'{"connections":null,"extra":-1e400}',
])
def test_controller_json_rejects_ambiguous_keys_and_nonfinite_numbers(monkeypatch, body):
    import io
    response = io.BytesIO(body)
    response.status = 200
    monkeypatch.setattr(launch, "_controller_open", lambda *a, **k: response)
    assert launch._controller_json("http://127.0.0.1:12002", "/connections", secrets.token_urlsafe(32)) is None
    assert response.closed


@pytest.mark.parametrize("body,expected", [
    (b'{"connections":null}', {"connections": None}),
    (b'{"first":{"mode":"rule"},"second":{"mode":"rule"}}',
     {"first": {"mode": "rule"}, "second": {"mode": "rule"}}),
    (b'{"counter":18446744073709551615,"rate":1.25e2,"note":"NaN Infinity"}',
     {"counter": 18446744073709551615, "rate": 125.0, "note": "NaN Infinity"}),
])
def test_controller_strict_json_preserves_valid_values(monkeypatch, body, expected):
    import io
    response = io.BytesIO(body)
    response.status = 200
    monkeypatch.setattr(launch, "_controller_open", lambda *a, **k: response)
    assert launch._controller_json("http://127.0.0.1:12002", "/connections", secrets.token_urlsafe(32)) == expected
    assert response.closed


@pytest.mark.parametrize("body,expected", [
    (b'{"connections":[],"connections":null}', None),
    (b'{"connections":null,"extra":NaN}', None),
    (b'{"connections":null}', {"connections": None}),
])
def test_controller_strict_json_over_actual_loopback_http(body, expected):
    token = secrets.token_urlsafe(32)
    with server(body=body) as (base, received):
        assert launch._controller_json(base, "/connections", token) == expected
        assert received == ["Bearer " + token]


@pytest.mark.parametrize("stage", range(6), ids=["unauth", "wrong_token", "valid_token", "configs", "proxies", "rules"])
@pytest.mark.parametrize("fault", ["takeover", "exit"])
def test_preflight_discards_each_response_if_controller_owner_changes(monkeypatch, tmp_path, stage, fault):
    proc = Mock(pid=12345)
    proc.poll.return_value = None
    proc.terminate.side_effect = lambda: setattr(proc.poll, "return_value", 0)
    monkeypatch.setattr(launch.engine_binary, "verify_pinned_binary", lambda *a, **k: (True, "BINARY_OK"))
    monkeypatch.setattr(launch.subprocess, "Popen", Mock(return_value=proc))
    token = secrets.token_urlsafe(32)
    state = {"calls": 0, "changed": False}
    ownership = Mock(side_effect=lambda pid, port, **k:
                     "LISTENER_FOREIGN_OWNER" if port == 12002 and state["changed"] else "LAUNCH_OK")
    monkeypatch.setattr(launch, "listener_owned_by", ownership)
    snapshots = {
        "/configs": {"mode": "rule"},
        "/proxies": {"proxies": {"NODE": {"type": "Vless"},
                     "PROBE": {"type": "Selector", "now": "NODE", "all": ["NODE"]}}},
        "/rules": {"rules": [{"index": 0, "type": "Match", "payload": "", "proxy": "PROBE"}]},
    }

    def changed():
        if state["calls"] == stage:
            if fault == "exit":
                proc.poll.return_value = 1
            else:
                state["changed"] = True
        state["calls"] += 1

    def status(base, path, credential, **kwargs):
        changed()
        return 200 if credential == token else 401

    def snapshot(base, path, credential, **kwargs):
        changed()
        return snapshots[path]

    monkeypatch.setattr(launch, "_controller_status", status)
    monkeypatch.setattr(launch, "_controller_json", snapshot)
    expected = "ENGINE_EXITED" if fault == "exit" else "LISTENER_FOREIGN_OWNER"
    with pytest.raises(launch.EngineLaunchError, match=f"^{expected}$"):
        launch.start_verified_engine(exe=tmp_path / "synthetic", run_dir=tmp_path,
            config_path=tmp_path / "probe.yaml", mixed_port=12001, controller_port=12002, secret=token)
    # Do not send the next (possibly authenticated) request after a stale reply.
    assert state["calls"] == stage + 1
    if fault == "takeover":
        proc.terminate.assert_called_once_with()
    else:
        proc.terminate.assert_not_called()
    proc.kill.assert_not_called()
