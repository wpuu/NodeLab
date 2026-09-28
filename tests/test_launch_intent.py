"""Linux launch intent persists before Popen can create an unclaimed child."""
import json
import os
import subprocess
import sys
from unittest.mock import Mock

import pytest

from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux launch intent")
PENDING = ".owner-launch.tmp"
REAL_POPEN = subprocess.Popen


@pytest.mark.parametrize("engine", [False, True])
def test_launch_intent_exists_before_popen_and_clears_only_after_child_marker(tmp_path, monkeypatch, engine):
    with private.RunContext(tmp_path / "private") as ctx:
        ctx.write_yaml({"password": "synthetic-only"})
        original_marker = ctx._write_marker
        events = []

        class Spawn(REAL_POPEN):
            def __init__(self, *args, **kwargs):
                pending = ctx.run_dir / PENDING
                assert pending.is_file()
                assert pending.stat().st_mode & 0o777 == 0o600
                assert "synthetic-only" not in pending.read_text()
                events.append("spawn")
                super().__init__([sys.executable, "-c", "import time; time.sleep(60)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)

        def marker(*, child=None):
            assert (ctx.run_dir / PENDING).is_file()
            assert ctx.raw_child is not None
            original_marker(child=child)
            events.append("marker")

        with monkeypatch.context() as patch:
            patch.setattr(private.subprocess, "Popen", Spawn)
            patch.setattr(ctx, "_write_marker", marker)
            proc = ctx._spawn_engine(sys.executable) if engine else ctx.spawn_synthetic_process()
        assert events == ["spawn", "marker"]
        assert not (ctx.run_dir / PENDING).exists()
        assert json.loads((ctx.run_dir / ".owner.json").read_bytes())["child_pid"] == proc.pid


@pytest.mark.parametrize("phase", ["file_sync", "directory_sync"])
def test_intent_sync_failure_never_calls_popen(tmp_path, monkeypatch, phase):
    import stat
    with private.RunContext(tmp_path / "private") as ctx:
        ctx.write_yaml({"password": "synthetic-only"})
        original = os.fsync

        def fail(fd):
            directory = stat.S_ISDIR(os.fstat(fd).st_mode)
            if directory == (phase == "directory_sync"):
                raise OSError("synthetic")
            return original(fd)

        with monkeypatch.context() as patch:
            spawn = Mock(side_effect=AssertionError("no child before synced intent"))
            patch.setattr(private.os, "fsync", fail)
            patch.setattr(private.subprocess, "Popen", spawn)
            with pytest.raises(private.PrivateRunError, match="^PROCESS_START_FAILED$"):
                ctx.spawn_synthetic_process()
            spawn.assert_not_called()
        assert not ctx._launch_unclaimed and ctx.raw_child is None
    assert ctx.closed and not ctx.run_dir.exists()


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_constructor_error_after_creation_preserves_unknown_intent(tmp_path, monkeypatch, error_type):
    children = []
    ctx = private.RunContext(tmp_path / "private")
    ctx.__enter__()
    ctx.write_yaml({"password": "synthetic-only"})

    class Unreturned(REAL_POPEN):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            children.append(self)  # only the test harness obtains this Popen
            raise error_type("synthetic")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(private.subprocess, "Popen", Unreturned)
            expected = private.PrivateRunError if issubclass(error_type, Exception) else error_type
            with pytest.raises(expected):
                ctx.spawn_synthetic_process()
        assert len(children) == 1 and children[0].poll() is None
        assert ctx.raw_child is None and ctx._launch_unclaimed
        with pytest.raises(private.PrivateRunError, match="^SECRET_CLEANUP_FAILED$"):
            ctx.close()
        assert not ctx.closed and private._lock_state(ctx._lock_path) == "live"
        assert not (ctx.run_dir / "probe.yaml").exists()
        assert (ctx.run_dir / PENDING).is_file()
        # Unknown constructor outcome cannot be retried or given new secrets.
        with pytest.raises(private.PrivateRunError):
            ctx.spawn_synthetic_process()
        with pytest.raises(private.PrivateRunError):
            ctx._spawn_engine(sys.executable)
        with pytest.raises(private.PrivateRunError):
            ctx.write_yaml({"password": "another-synthetic-value"})
        ctx._drop_lock()  # simulated owner exit for the recovery refusal check
        with monkeypatch.context() as patch:
            owner, stop = Mock(), Mock()
            patch.setattr(private, "linux_owner_gone", owner)
            patch.setattr(private, "terminate_verified_process", stop)
            rows = private.recover_stale_runs(ctx.root)
            owner.assert_not_called()
            stop.assert_not_called()
        assert [r["error_code"] for r in rows] == ["RECOVERY_REVIEW_REQUIRED"]
        assert children[0].poll() is None
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        # Only the harness knows and has stopped the otherwise unclaimed child.
        ctx._launch_unclaimed = False
        ctx.close()


@pytest.mark.parametrize("phase", ["marker", "intent_unlink", "identity"])
def test_claimed_child_is_still_owned_when_launch_completion_fails(tmp_path, monkeypatch, phase):
    ctx = private.RunContext(tmp_path / "private")
    ctx.__enter__()
    ctx.write_yaml({"password": "synthetic-only"})
    try:
        with monkeypatch.context() as patch:
            if phase == "marker":
                patch.setattr(ctx, "_write_marker", Mock(side_effect=OSError("synthetic")))
            elif phase == "intent_unlink":
                patch.setattr(ctx, "_complete_linux_launch", Mock(side_effect=OSError("synthetic")))
            else:
                patch.setattr(private, "process_identity", Mock(return_value=None))
            with pytest.raises(private.PrivateRunError, match="^PROCESS_START_FAILED$"):
                ctx.spawn_synthetic_process()
        assert ctx.raw_child is not None and ctx.raw_child.poll() is None
        assert (ctx.run_dir / PENDING).exists()
        assert not ctx._launch_unclaimed
    finally:
        ctx.close()
    assert ctx.raw_child.poll() is not None and ctx.closed and not ctx.run_dir.exists()


def test_launch_order_syncs_intent_before_spawn_and_marker_before_intent_removal(tmp_path, monkeypatch):
    import stat
    events = []
    with private.RunContext(tmp_path / "private") as ctx:
        ctx.write_yaml({"password": "synthetic-only"})
        fsync = os.fsync

        def sync(fd):
            events.append("dir_sync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file_sync")
            return fsync(fd)

        class Spawn(REAL_POPEN):
            def __init__(self, *args, **kwargs):
                events.append("spawn")
                super().__init__(*args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(private.os, "fsync", sync)
            patch.setattr(private.subprocess, "Popen", Spawn)
            ctx.spawn_synthetic_process()
        assert events == ["file_sync", "dir_sync", "spawn", "file_sync", "dir_sync", "dir_sync"]


def test_actual_owner_exit_before_popen_returns_requires_review(tmp_path):
    from nodelab.mihomo_process import ProcessIdentity, terminate_verified_process
    root = tmp_path / "crashed"
    script = r'''
import json, os, sys
from pathlib import Path
from nodelab import mihomo_config as private
real = private.subprocess.Popen
ctx = private.RunContext(Path(sys.argv[1]))
ctx.__enter__()
ctx.write_yaml({"password": "synthetic-only"})
class Crash(real):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        identity = private.process_identity(self.pid)
        print(json.dumps({"pid": self.pid, "stamp": identity.create_time,
                          "fingerprint": identity.exe_fingerprint, "run_id": ctx.run_id}), flush=True)
        os._exit(0)
private.subprocess.Popen = Crash
ctx.spawn_synthetic_process()
'''
    proc = REAL_POPEN([sys.executable, "-c", script, str(root)],
                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    identity = None
    try:
        output, _ = proc.communicate(timeout=10)
        assert proc.returncode == 0
        info = json.loads(output)
        identity = ProcessIdentity(info["pid"], info["stamp"], info["fingerprint"])
        run_dir = root / info["run_id"]
        assert (run_dir / PENDING).is_file()
        assert json.loads((run_dir / ".owner.json").read_bytes())["child_pid"] is None
        before = {p.name: p.read_bytes() for p in run_dir.iterdir()}
        rows = private.recover_stale_runs(root)
        assert [r["error_code"] for r in rows] == ["RECOVERY_REVIEW_REQUIRED"]
        assert {p.name: p.read_bytes() for p in run_dir.iterdir()} == before
        assert identity.matches(private.process_identity(identity.pid))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=5)
        if identity is not None:
            assert terminate_verified_process(identity)


def test_intent_fdopen_failure_closes_descriptor_before_any_spawn(tmp_path, monkeypatch):
    descriptors = []
    with private.RunContext(tmp_path / "private") as ctx:
        ctx.write_yaml({"password": "synthetic-only"})

        def fail(fd, *args, **kwargs):
            descriptors.append(fd)
            assert not os.get_inheritable(fd)
            raise OSError("synthetic")

        with monkeypatch.context() as patch:
            spawn = Mock(side_effect=AssertionError("must not spawn"))
            patch.setattr(private.os, "fdopen", fail)
            patch.setattr(private.subprocess, "Popen", spawn)
            with pytest.raises(private.PrivateRunError, match="^PROCESS_START_FAILED$"):
                ctx.spawn_synthetic_process()
            spawn.assert_not_called()
        assert len(descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(descriptors[0])
        assert not ctx._launch_unclaimed
    assert ctx.closed


def test_final_directory_sync_failure_keeps_complete_child_record_and_ownership(tmp_path, monkeypatch):
    with private.RunContext(tmp_path / "private") as ctx:
        ctx.write_yaml({"password": "synthetic-only"})
        original = ctx._sync_run_directory
        calls = 0

        def sync():
            nonlocal calls
            calls += 1
            if calls == 2:  # intent unlink happened; marker was already synced
                raise OSError("synthetic")
            return original()

        with monkeypatch.context() as patch:
            patch.setattr(ctx, "_sync_run_directory", sync)
            with pytest.raises(private.PrivateRunError, match="^PROCESS_START_FAILED$"):
                ctx.spawn_synthetic_process()
        assert not (ctx.run_dir / PENDING).exists()
        assert json.loads((ctx.run_dir / ".owner.json").read_bytes())["child_pid"] == ctx.raw_child.pid
        assert ctx.raw_child.poll() is None and not ctx._launch_unclaimed
    assert ctx.raw_child.poll() is not None and ctx.closed
