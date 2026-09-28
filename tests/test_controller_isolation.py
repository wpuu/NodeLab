"""Synthetic controller isolation checks; no engine or real credentials."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import threading
from unittest.mock import Mock

import pytest

from nodelab import engine_launch as launch


@contextmanager
def server(status=200, location=None):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.headers.get("Authorization"))
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

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
    monkeypatch.setattr(launch, "_controller_json", lambda base, path, token, **kwargs: snapshots[path])
    engine = launch.start_verified_engine(
        exe=tmp_path / "synthetic", run_dir=tmp_path,
        config_path=tmp_path / "probe.yaml", mixed_port=12001,
        controller_port=12002, secret=token,
    )
    assert engine.proc is proc
    assert events == [("owner", 12002), ("http", False), ("http", True),
                      ("http", True), ("owner", 12001)]
    proc.kill.assert_not_called()


@pytest.mark.parametrize("status", [201, 202, 206])
def test_json_requires_http_200_even_if_body_is_valid(status):
    with server(status) as (base, _):
        assert launch._controller_json(base, "/connections", secrets.token_urlsafe(32)) is None
