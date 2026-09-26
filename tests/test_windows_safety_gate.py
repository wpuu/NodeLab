"""W1 gate: real Windows NTFS ACL/PID tests, never simulated by Linux PASS.

Run only on a pinned F1 candidate in the Owner's Windows E:\\NodeLab checkout.
No real proxy, real URI, real password, or API token is used.
"""

from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
from pathlib import Path
from queue import Empty, Queue
from threading import Thread

import pytest

from nodelab import mihomo_config
from nodelab.mihomo_config import PrivateRunError, RunContext

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="real NTFS/Windows required; Linux is not W1 evidence")


def _synthetic() -> str:
    return "FAKE_ONLY_" + secrets.token_urlsafe(25)


def _small_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key.upper() in {
        "SYSTEMROOT", "WINDIR", "PATH", "USERPROFILE",
    }}


def test_windows_e_volume_dacl_before_and_during_private_yaml():
    assert sys.platform == "win32" and os.name == "nt"
    root = Path(r"E:\NodeLab.secrets\_runtime")
    assert mihomo_config._windows_volume_ok(root), "W1 requires fixed local NTFS E:"
    sentinel = _synthetic()
    ctx = RunContext()
    with ctx:
        assert ctx.root == root
        sid = mihomo_config._windows_sid()
        for folder in (root.parent, root, ctx.run_dir):
            mihomo_config._verify_windows_acl(folder, sid)
        config = ctx.write_yaml({"password": sentinel})
        assert sentinel in config.read_text(encoding="utf-8")
        for private_file in (ctx.run_dir / ".owner.json", config):
            mihomo_config._verify_windows_acl(private_file, sid)

        # A *new, empty* test file with a broad ACE must be rejected. Never
        # change the ACL of a real secret file or an existing private root.
        unsafe = ctx.run_dir / "broad_empty_fixture.txt"
        unsafe.touch(exist_ok=False)
        try:
            icacls = mihomo_config._windows_system_dir() / "icacls.exe"
            r = subprocess.run([str(icacls), str(unsafe), "/grant", "*S-1-1-0:R"],
                               env=_small_environment(), capture_output=True, timeout=8, check=False)
            assert r.returncode == 0, "cannot create the Windows negative ACL fixture"
            with pytest.raises(PrivateRunError) as failure:
                mihomo_config._verify_windows_acl(unsafe, sid)
            assert failure.value.code == "PRIVATE_DIR_UNSAFE"
        finally:
            unsafe.unlink(missing_ok=True)
    assert ctx.closed and not ctx.run_dir.exists()
    assert sentinel not in str(ctx) and sentinel not in str(config)


def test_windows_exact_pid_and_external_listening_port_untouched():
    # Independent, synthetic local listener.  It is NOT Mihomo, a proxy or
    # an internet endpoint, and it carries no secret.
    listener_script = (
        "import socket,time; s=socket.socket(); s.bind(('127.0.0.1',0)); "
        "s.listen(2); print(s.getsockname()[1],flush=True); time.sleep(60)"
    )
    external = subprocess.Popen([sys.executable, "-c", listener_script],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL, env=_small_environment())
    try:
        port_data: Queue[bytes] = Queue(maxsize=1)
        Thread(target=lambda: port_data.put(external.stdout.readline()), daemon=True).start()
        try:
            port_line = port_data.get(timeout=5).decode("ascii").strip()
        except Empty:
            raise AssertionError("synthetic listener did not become ready") from None
        assert port_line.isdecimal()
        port = int(port_line)
        assert 1 <= port <= 65535
        ctx = RunContext()
        with ctx:
            ctx.write_yaml({"password": _synthetic()})
            own = ctx.spawn_synthetic_process()
            assert own.pid != external.pid and own.poll() is None
        assert own.poll() is not None and not ctx.run_dir.exists()
        assert external.poll() is None
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass  # external port remains open after NodeLab cleans own PID
    finally:
        external.terminate()
        try:
            external.wait(timeout=3)
        except subprocess.TimeoutExpired:
            external.kill()
            external.wait(timeout=3)
        external.stdout.close()


def test_windows_real_junction_is_not_deleted_through():
    # A failure to create the fixture is a BLOCKER, not a simulated PASS.
    sentinel = _synthetic()
    external = Path(os.environ.get("TEMP", "E:/")) / ("nodelab-junction-fixture-" + secrets.token_hex(8))
    external.mkdir(mode=0o700)
    (external / "keep.txt").write_text(sentinel, encoding="utf-8")
    ctx = RunContext()
    junction = None
    try:
        ctx.__enter__()
        junction = ctx.run_dir / "outside"
        cmd = mihomo_config._windows_system_dir() / "cmd.exe"
        r = subprocess.run([str(cmd), "/c", "mklink", "/J", str(junction), str(external)],
                           env=_small_environment(), capture_output=True, timeout=8, check=False)
        assert r.returncode == 0 and mihomo_config._is_reparse(junction), "junction fixture unavailable"
        with pytest.raises(PrivateRunError) as failure:
            ctx.close()
        assert failure.value.code == "SECRET_CLEANUP_FAILED"
        assert (external / "keep.txt").read_text(encoding="utf-8") == sentinel
    finally:
        try:
            if junction is not None and (junction.exists() or junction.is_symlink()):
                junction.rmdir()  # remove ONLY the newly created junction, not its target
            ctx.close()
        finally:
            (external / "keep.txt").unlink(missing_ok=True)
            external.rmdir()
    assert not ctx.run_dir.exists()
