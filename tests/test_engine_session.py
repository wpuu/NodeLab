"""Private session integration with real Python substitute children.

Pin/controller/engine protocol behavior is mocked. POSIX filesystem/PID and
cleanup are real; this is NOT Mihomo handshake or Windows acceptance.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

import pytest

from nodelab import engine_launch as launch, engine_session as session, mihomo_config as private
from nodelab.parser import parse_uri
from nodelab.types import PROBE_GATE_OPEN

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX fixture; Windows requires W1/W2")
_REAL_POPEN = subprocess.Popen


@pytest.fixture
def rig(monkeypatch, tmp_path):
    root = tmp_path / "private"
    children = []
    records = []
    fault = {"config_exit": 0, "spawn": None, "config_timeout": False}
    sentinel = secrets.token_urlsafe(32)
    node = parse_uri(f"trojan://{sentinel}@198.51.100.20:443?security=tls&sni=fixture.example.invalid")
    pins = []

    def verify(exe, *, deadline):
        pins.append(deadline)
        return True, "BINARY_OK"

    monkeypatch.setattr(session.engine_binary, "verify_pinned_binary", verify)

    class Substitute(_REAL_POPEN):
        def __init__(self, args, **kwargs):
            self.check_mode = "-t" in args
            self.run_dir = Path(kwargs["cwd"])
            if fault["spawn"] == ("check" if self.check_mode else "runtime"):
                raise OSError("synthetic failure")
            assert kwargs["stdout"] == subprocess.DEVNULL
            assert kwargs["stderr"] == subprocess.DEVNULL
            if self.check_mode and not fault["config_timeout"]:
                script = f"import time; time.sleep(0.02); raise SystemExit({fault['config_exit']})"
            else:
                script = "import time; time.sleep(60)"
            super().__init__([sys.executable, "-c", script], **kwargs)
            children.append(self)
            self.wait_seen = False

        def wait(self, timeout=None):
            if self.check_mode and not self.wait_seen:
                self.wait_seen = True
                marker = json.loads((self.run_dir / ".owner.json").read_text())
                records.append(marker)
                if fault["config_timeout"]:
                    raise subprocess.TimeoutExpired("synthetic", timeout)
            return super().wait(timeout=timeout)

    monkeypatch.setattr(private.subprocess, "Popen", Substitute)
    monkeypatch.setattr(launch, "listener_owned_by", lambda *a, **k: "LAUNCH_OK")

    def status(base, path, token, **kwargs):
        import yaml
        config = yaml.safe_load((children[-1].run_dir / "probe.yaml").read_text())
        return 200 if token == config["secret"] else 401

    monkeypatch.setattr(launch, "_controller_status", status)
    snapshots = {
        "/configs": {"mode": "rule"},
        "/proxies": {"proxies": {"NODE": {"type": "Trojan"},
            "PROBE": {"type": "Selector", "now": "NODE", "all": ["NODE"]}}},
        "/rules": {"rules": [{"index": 0, "type": "Match", "payload": "", "proxy": "PROBE"}]},
    }
    monkeypatch.setattr(launch, "_controller_json", lambda base, path, token, **kw: snapshots[path])

    def open_session():
        return session.private_engine_session(node, exe=Path(sys.executable),
            mixed_port=12001, controller_port=12002, root=root)

    yield open_session, children, records, fault, root, pins, sentinel
    for child in children:
        if child.poll() is None:
            child.kill()
        # Bypass fixture assertions in emergency teardown.
        _REAL_POPEN.wait(child, timeout=5)


def assert_clean(children, root):
    assert all(child.poll() is not None for child in children)
    assert not list(root.glob("*/probe.yaml"))
    assert not list(root.glob("*/.owner.json"))
    assert not list(root.glob("*.lock"))
    assert not any(p.is_dir() for p in root.iterdir())


def test_one_owner_two_sequential_children_and_private_markers(rig, capsys):
    open_session, children, records, _, root, pins, sentinel = rig
    with open_session() as engine:
        assert len(children) == 2
        assert children[0].poll() == 0
        assert engine.proc is children[1]
        assert records[0]["child_pid"] in (children[0].pid, None)
        marker = json.loads((children[1].run_dir / ".owner.json").read_text())
        assert marker["child_pid"] == engine.proc.pid
        assert marker["child_create_time"] is not None
        assert marker["child_exe_fingerprint"] is not None
        assert sentinel not in json.dumps(marker)
        assert engine.secret not in json.dumps(marker)
        assert (children[1].run_dir / "probe.yaml").stat().st_mode & 0o777 == 0o600
        assert engine._owner.raw_child is engine.proc
        assert engine._identity.pid == engine.proc.pid
        assert engine._identity.create_time == marker["child_create_time"]
        assert engine._identity.exe_fingerprint == marker["child_exe_fingerprint"]
        with pytest.raises(private.PrivateRunError):
            engine._owner.write_yaml({"password": sentinel})
        assert "private" in repr(engine)
    assert len(pins) == 2 and pins[0] == pins[1]
    assert_clean(children, root)
    assert PROBE_GATE_OPEN is False
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("stage", ["check", "runtime"])
def test_spawn_failure_removes_yaml(rig, stage, monkeypatch):
    open_session, children, _, fault, root, _, _ = rig
    fault["spawn"] = stage
    owners = []
    original = private.RunContext.close

    def close(owner):
        owners.append(owner)
        return original(owner)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(private.RunContext, "close", close)
            code = "SECRET_CLEANUP_FAILED" if sys.platform == "linux" else "PROCESS_START_FAILED"
            with pytest.raises(private.PrivateRunError, match=f"^{code}$"):
                with open_session():
                    pytest.fail("must not yield")
        assert all(child.poll() is not None for child in children)
        assert not list(root.glob("*/probe.yaml"))
        if sys.platform == "linux":
            assert len(list(root.glob("*/.owner-launch.tmp"))) == 1
            assert len(list(root.glob("*/.owner.json"))) == 1
            assert owners[-1]._launch_unclaimed and not owners[-1].closed
    finally:
        # This fixture raises BEFORE creating the failed child. Production
        # cannot assume that of arbitrary constructor errors; only test teardown
        # supplies this knowledge, after checking all real fixture children.
        for owner in owners:
            owner._launch_unclaimed = False
            original(owner)
    assert_clean(children, root)


@pytest.mark.parametrize("mode", ["exit", "timeout"])
def test_config_failure_never_spawns_runtime(rig, mode):
    open_session, children, _, fault, root, _, _ = rig
    fault["config_exit"] = 2 if mode == "exit" else 0
    fault["config_timeout"] = mode == "timeout"
    code = "CONFIG_TEST_FAILED" if mode == "exit" else "LAUNCH_TIMEOUT"
    with pytest.raises(launch.EngineLaunchError, match=f"^{code}$"):
        with open_session():
            pytest.fail("must not yield")
    assert len(children) == 1
    assert_clean(children, root)


@pytest.mark.parametrize("error", [KeyboardInterrupt, ValueError])
def test_body_cancel_or_failure_cleans_private_session(rig, error):
    open_session, children, _, _, root, _, _ = rig
    with pytest.raises(error):
        with open_session():
            raise error()
    assert_clean(children, root)


def test_engine_close_delegates_to_owner_and_is_repeatable(rig):
    open_session, children, _, _, root, _, _ = rig
    with open_session() as engine:
        engine.close()
        engine.close()
        assert engine._owner.closed
        assert_clean(children, root)
    assert_clean(children, root)


def test_failed_runtime_preflight_cleans_both_children_and_yaml(rig, monkeypatch):
    open_session, children, _, _, root, _, _ = rig
    monkeypatch.setattr(launch, "listener_owned_by", lambda *a, **kw: "LISTENER_FOREIGN_OWNER")
    with pytest.raises(launch.EngineLaunchError, match="^LISTENER_FOREIGN_OWNER$"):
        with open_session():
            pytest.fail("must not yield")
    assert len(children) == 2
    assert_clean(children, root)


def test_marker_failure_after_runtime_spawn_retains_child_for_cleanup(rig, monkeypatch):
    open_session, children, _, _, root, _, _ = rig
    original = private.RunContext._write_marker

    def write(owner, *, child=None):
        if len(children) == 2:
            raise OSError("synthetic marker failure")
        return original(owner, child=child)

    monkeypatch.setattr(private.RunContext, "_write_marker", write)
    with pytest.raises(private.PrivateRunError, match="^PROCESS_START_FAILED$"):
        with open_session():
            pytest.fail("must not yield")
    assert len(children) == 2
    assert_clean(children, root)


def test_binary_rejection_creates_no_private_tree(rig, monkeypatch):
    open_session, children, _, _, root, _, _ = rig
    monkeypatch.setattr(session.engine_binary, "verify_pinned_binary", lambda *a, **kw: (False, "BINARY_DIGEST_MISMATCH"))
    with pytest.raises(launch.EngineLaunchError, match="^BINARY_REJECTED$"):
        with open_session():
            pytest.fail("must not yield")
    assert not children
    assert not root.exists()


def test_write_failure_still_cleans_private_directory(rig, monkeypatch):
    open_session, children, _, _, root, _, _ = rig
    monkeypatch.setattr(private.RunContext, "write_yaml", lambda *a: (_ for _ in ()).throw(private.PrivateRunError("CONFIG_BUILD_FAILED")))
    with pytest.raises(private.PrivateRunError, match="^CONFIG_BUILD_FAILED$"):
        with open_session():
            pytest.fail("must not yield")
    assert not children
    assert_clean(children, root)


def test_live_unverifiable_child_is_rejected_and_stopped(rig, monkeypatch):
    open_session, children, _, _, root, _, _ = rig
    original = private.process_identity

    def identity(pid):
        if len(children) == 2 and pid == children[-1].pid:
            return None
        return original(pid)

    monkeypatch.setattr(private, "process_identity", identity)
    with pytest.raises(private.PrivateRunError, match="^PROCESS_START_FAILED$"):
        with open_session():
            pytest.fail("must not yield")
    assert_clean(children, root)


def test_stop_failure_removes_yaml_and_overrides_body_error(rig, monkeypatch):
    from nodelab.mihomo_process import ProcessLifecycleError
    open_session, children, _, _, root, _, _ = rig
    owner = None
    try:
        with monkeypatch.context() as patch:
            with pytest.raises(private.PrivateRunError, match="^SECRET_CLEANUP_FAILED$"):
                with open_session() as engine:
                    owner = engine._owner

                    def fail():
                        raise ProcessLifecycleError()

                    patch.setattr(owner.process, "close", fail)
                    raise ValueError("synthetic body failure")
            assert not list(root.glob("*/probe.yaml"))
            assert not owner.closed
            assert children[-1].poll() is None  # failure is reported, not hidden
    finally:
        if owner is not None:
            owner.close()  # fixture restores the real stop method before retry
    assert_clean(children, root)


def test_private_session_does_not_stop_external_substitute(rig):
    open_session, children, _, _, root, _, _ = rig
    external = _REAL_POPEN([sys.executable, "-c", "import time; time.sleep(60)"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with open_session():
            assert external.poll() is None
        assert external.poll() is None
        assert_clean(children, root)
    finally:
        external.kill()
        external.wait(timeout=5)


def test_clearing_check_marker_failure_prevents_runtime_and_stays_fixed(rig, monkeypatch):
    open_session, children, _, _, root, _, sentinel = rig
    original = private.RunContext._write_marker

    def write(owner, *, child=None):
        if len(children) == 1 and child is None:
            raise OSError(sentinel)
        return original(owner, child=child)

    monkeypatch.setattr(private.RunContext, "_write_marker", write)
    with pytest.raises(private.PrivateRunError, match="^PROCESS_START_FAILED$") as exc:
        with open_session():
            pytest.fail("must not yield")
    assert sentinel not in str(exc.value)
    assert len(children) == 1
    assert_clean(children, root)
