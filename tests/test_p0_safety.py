"""F1: all values below are fresh fictional sentinels; never real nodes."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import quote

import pytest

import nodelab
from nodelab import cli, mihomo_config, mihomo_process
from nodelab.mihomo_config import PrivateRunError, RunContext, recover_stale_runs, scrub_yaml_for_display
from nodelab.mihomo_process import ProcessIdentity, process_identity, stop_owned_process, terminate_verified_process
from nodelab.types import PROBE_GATE_OPEN
from nodelab.parser import parse_uri, redact_uri
from nodelab.probe import RouteObservation, decide_probe_status, probe_from_file, probe_node, save_probe_results
from nodelab.redaction import redacted_node_dict, redacted_result_dict
from nodelab.types import NodeURIParseError, ParsedNode


def fake_secret() -> str:
    return "FAKE_ONLY_" + secrets.token_urlsafe(28)


def context_for_test(tmp_path: Path) -> RunContext:
    # On Windows the actual NTFS root must be checked, never a fake POSIX ACL.
    return RunContext() if os.name == "nt" else RunContext(tmp_path / "private")


def fake_trojan_uri(secret: str) -> str:
    return f"trojan://{quote(secret, safe='')}@198.51.100.20:443?security=tls&sni=fixture.example.invalid"


def helper_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.upper() in {
        "SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "TMPDIR", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
        "PSMODULEPATH", "PYTHONHOME", "PYTHONUTF8", "PYTHONIOENCODING",
    }}
    env["PYTHONPATH"] = str(Path(nodelab.__file__).resolve().parent.parent)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def root_argument(tmp_path: Path) -> list[str]:
    return [] if os.name == "nt" else [str(tmp_path / "private")]


# Simulated hard crash of an owner: private YAML + synthetic child exist,
# then the process dies without finally/atexit.  The sentinel arrives on
# stdin, never through argv or the environment.
CRASHING_OWNER = """
import json, os, sys
from pathlib import Path
from nodelab.mihomo_config import RunContext
ctx = RunContext(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
ctx.__enter__()
ctx.write_yaml({"password": sys.stdin.readline().strip()})
child = ctx.spawn_synthetic_process()
marker = json.loads((ctx.run_dir / ".owner.json").read_text(encoding="utf-8"))
print(json.dumps({"run_dir": str(ctx.run_dir), "child_pid": child.pid,
                  "child_create_time": marker["child_create_time"],
                  "child_exe_fingerprint": marker["child_exe_fingerprint"]}), flush=True)
os._exit(0)
"""

# A live owner in another process: enters a run and waits for stdin EOF.
LIVE_OWNER = """
import sys
from pathlib import Path
from nodelab.mihomo_config import RunContext
with RunContext(Path(sys.argv[1]) if len(sys.argv) > 1 else None) as ctx:
    ctx.write_yaml({"password": sys.stdin.readline().strip()})
    print("ready", flush=True)
    sys.stdin.read()
"""


def external_sleeper() -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=helper_env())


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def test_s1_s4_private_carriers_and_public_views():
    sentinel = fake_secret()
    domain_sentinel = "fakeonly" + secrets.token_hex(12)  # legal IDNA label
    password = sentinel + ":" + "@"
    uri = (f"trojan://{quote(password, safe='')}@198.51.100.20:443"
           f"?type=ws&security=tls&host={domain_sentinel}.invalid&sni={domain_sentinel}.invalid"
           f"&path=%2F{sentinel}#{quote(sentinel)}")
    node = parse_uri(uri)
    assert node.secret == password and node.ws_path.endswith(sentinel)
    assert node.ws_host == node.sni == f"{domain_sentinel}.invalid"
    assert not hasattr(node, "display_name") and not hasattr(node, "extra_query")
    out = json.dumps(redacted_node_dict(node), ensure_ascii=False) + repr(node) + str(node)
    out += redact_uri(uri)
    for value in (sentinel, domain_sentinel, quote(password, safe=''), password, uri):
        assert value not in out
    assert "display_name" not in out and "redacted_uri" not in out
    with pytest.raises(NodeURIParseError) as info:
        parse_uri(uri.replace("#", f"&auth={quote(sentinel)}#"))
    assert info.value.code == "UNSUPPORTED_QUERY_PARAM"
    assert info.value.probe_status == "UNSUPPORTED" and sentinel not in repr(info.value)


def test_s5_s6_s7_fixed_public_schema_and_nested_adversary():
    sentinel = fake_secret()
    adversarial = {
        "protocol": "trojan", "probe_status": "FAIL", "error_code": sentinel,
        "stage": f"PARSE_{sentinel}", "source_count": 1,
        "display_name": sentinel, sentinel: {"secret": sentinel},
        "metadata": [{"path": sentinel}, (sentinel,)], "config_ok": sentinel,
        "entry_host": sentinel, "exit_ip": sentinel, "redacted_uri": sentinel,
    }
    result = redacted_result_dict([adversarial, {"status": sentinel}])
    data = json.dumps(result, ensure_ascii=False)
    assert sentinel not in data
    assert result[0]["error_code"] == "PUBLIC_SCHEMA_REJECTED"
    assert result[0]["stage"] is None and result[0]["config_ok"] is None
    assert result[0]["source_count"] == 1
    assert set(result[0]) == set(redacted_result_dict({}))


def test_s5_multiline_secret_rejected_or_never_showable():
    sentinel = fake_secret()
    with pytest.raises(NodeURIParseError) as info:
        parse_uri(fake_trojan_uri(sentinel + "\nnext-line"))
    assert sentinel not in str(info.value) and info.value.code == "INVALID_SECRET"
    raw_yaml = "password: |\n  " + sentinel + "\n  continued\n"
    assert scrub_yaml_for_display(raw_yaml) == "[CONFIG_REDACTED]"


def test_s9_argv_and_unknown_arguments_do_not_repeat_uri(capsys):
    sentinel = fake_secret()
    uri = fake_trojan_uri(sentinel)
    for command in (["parse", uri], ["probe", uri], ["parse-file", "--file", uri],
                    ["probe-file", "--file", uri, "--unexpected", sentinel]):
        assert cli.main(list(command)) == 2
        output = capsys.readouterr()
        assert sentinel not in output.out + output.err
        assert uri not in output.out + output.err
        assert "error_code" in output.out and not output.err


def test_s9_file_parse_per_line_no_auto_results(tmp_path: Path, capsys):
    first, second = fake_secret(), fake_secret()
    path = tmp_path / ("FAKE_PATH_" + fake_secret() + ".txt")
    path.write_text(fake_trojan_uri(first) + "\ninvalid-line\n" + fake_trojan_uri(second), encoding="utf-8")
    try:
        assert cli.main(["parse-file", "--file", str(path), "--limit", "3"]) == 0
        public = capsys.readouterr().out
        rows = json.loads(public)
        assert [row["line_number"] for row in rows] == [1, 2, 3]
        # A parsed candidate is not a probe result: status stays null and the
        # error_code says why nothing more happened.  Only the bad line gets a
        # D4 status, and nothing here can be read as a positive verdict.
        assert rows[0]["probe_status"] is None and rows[2]["probe_status"] is None
        assert rows[0]["error_code"] == rows[2]["error_code"] == "PROBE_GATE_CLOSED"
        assert rows[0]["stage"] == rows[2]["stage"] == "PARSE"
        assert rows[1]["probe_status"] == "UNSUPPORTED" and rows[1]["error_code"] == "UNSUPPORTED_PROTOCOL"
        assert all(row["route_verified"] is not True and row["probe_status"] != "PASS" for row in rows)
        for value in (first, second, path.name):
            assert value not in public
        assert cli.main(["probe-file", "--file", str(path)]) == 2
        assert json.loads(capsys.readouterr().out)["error_code"] == "PROBE_GATE_CLOSED"
        assert not (tmp_path / "data" / "probe-results" / "latest.json").exists()
        with pytest.raises(RuntimeError, match="^RESULT_STORAGE_DISABLED$"):
            save_probe_results(rows, str(tmp_path / "data" / "probe-results"))
        assert not (tmp_path / "data").exists()
    finally:
        path.unlink(missing_ok=True)


def test_missing_file_path_cannot_be_echoed(capsys):
    sentinel = fake_secret()
    assert cli.main(["parse-file", "--file", "/tmp/" + sentinel]) == 2
    output = capsys.readouterr()
    assert sentinel not in output.out + output.err
    assert json.loads(output.out)["error_code"] == "INPUT_FILE_UNSAFE"


def test_legacy_live_engine_entry_points_disabled(monkeypatch):
    sentinel = fake_secret()
    node = parse_uri(fake_trojan_uri(sentinel))
    # F2b replaced the F1 hard `None` with a pinned resolver. With no pin
    # configured it must still refuse to discover anything, and it must
    # never fall back to PATH (see tests/test_engine_binary.py).
    monkeypatch.delenv("NODELAB_MIHOMO_EXE", raising=False)
    assert mihomo_process.find_mihomo_exe() is None
    assert not hasattr(mihomo_process, "cleanup_stale_mihomo")
    assert not hasattr(mihomo_process, "list_mihomo_pids")
    for method in (mihomo_config.build_mihomo_yaml, mihomo_config.write_probe_config):
        with pytest.raises(PrivateRunError) as info:
            method(node)
        assert info.value.code == "PROBE_GATE_CLOSED"
    assert sentinel not in repr(node)


def test_f1_probe_has_zero_network_or_process_effects(monkeypatch):
    sentinel = fake_secret()
    node = parse_uri(fake_trojan_uri(sentinel))
    def forbidden(*_args, **_kwargs):
        raise AssertionError("live side effect during F1")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = probe_node(node)
    assert result["probe_status"] == "FAIL"
    assert result["error_code"] == "ROUTE_PROOF_UNAVAILABLE"
    assert result["route_verified"] is False
    assert sentinel not in json.dumps(result)
    assert probe_from_file("/path/that/need/not/exist")[0]["error_code"] == "PROBE_GATE_CLOSED"


def test_s8_success_own_pid_only_external_untouched(tmp_path: Path):
    sentinel = fake_secret()
    external = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR", "PATH"}})
    try:
        ctx = context_for_test(tmp_path)
        with ctx:
            private = ctx.write_yaml({"password": sentinel, "nested": {"path": sentinel}})
            assert sentinel in private.read_text(encoding="utf-8")
            child = ctx.spawn_synthetic_process()
            assert child.pid != external.pid
            assert child.poll() is None
            if os.name != "nt":
                assert private.stat().st_mode & 0o777 == 0o600
                assert ctx.run_dir.stat().st_mode & 0o777 == 0o700
        assert child.poll() is not None
        assert external.poll() is None
        assert not ctx.run_dir.exists() and ctx.closed
    finally:
        external.terminate()
        try:
            external.wait(timeout=3)
        except subprocess.TimeoutExpired:
            external.kill()
            external.wait(timeout=3)


def test_s7_config_error_with_embedded_secret_cleanup(tmp_path: Path, monkeypatch):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    def unsafe_serializer(_value, **_kwargs):
        raise RuntimeError(sentinel)
    monkeypatch.setattr(mihomo_config.yaml, "safe_dump", unsafe_serializer)
    with pytest.raises(PrivateRunError) as info:
        with ctx:
            ctx.write_yaml({"secret": sentinel})
    assert info.value.code == "CONFIG_BUILD_FAILED"
    assert sentinel not in str(info.value)
    assert not ctx.run_dir.exists()


def test_s8_popen_failure_still_deletes_yaml(tmp_path: Path, monkeypatch):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    def unsafe_launcher(*_args, **_kwargs):
        raise OSError(sentinel)
    monkeypatch.setattr(mihomo_config.subprocess, "Popen", unsafe_launcher)
    with pytest.raises(PrivateRunError) as info:
        with ctx:
            ctx.write_yaml({"password": sentinel})
            ctx.spawn_synthetic_process()
    assert info.value.code == "PROCESS_START_FAILED"
    assert sentinel not in str(info.value)
    assert not ctx.run_dir.exists()


def test_s8_after_popen_wrapper_error_still_owns_exact_child(tmp_path: Path, monkeypatch):
    sentinel = fake_secret()
    spawned = []
    ctx = context_for_test(tmp_path)
    def bad_wrapper(proc):
        spawned.append(proc)
        raise RuntimeError(sentinel)
    monkeypatch.setattr(mihomo_config, "MihomoProcess", bad_wrapper)
    with pytest.raises(PrivateRunError) as info:
        with ctx:
            ctx.write_yaml({"password": sentinel})
            ctx.spawn_synthetic_process()
    assert info.value.code == "PROCESS_START_FAILED"
    assert sentinel not in str(info.value)
    assert len(spawned) == 1 and spawned[0].poll() is not None
    assert not ctx.run_dir.exists()


@pytest.mark.parametrize("failure", ["timeout", "cancel", "exception", "child_crash"])
def test_s8_injected_failures_cleanup(tmp_path: Path, failure: str):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    try:
        with ctx:
            ctx.write_yaml({"password": sentinel})
            proc = ctx.spawn_synthetic_process()
            if failure == "timeout":
                raise TimeoutError(sentinel)
            if failure == "cancel":
                raise KeyboardInterrupt()
            if failure == "exception":
                raise RuntimeError(sentinel)
            proc.kill()  # synthetic child crash, not an OS/power failure
            proc.wait(timeout=3)
    except (TimeoutError, KeyboardInterrupt, RuntimeError):
        pass
    assert ctx.closed and not ctx.run_dir.exists()
    assert proc.poll() is not None


def test_terminate_error_falls_back_to_same_child_kill(tmp_path: Path, monkeypatch):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    with ctx:
        ctx.write_yaml({"password": sentinel})
        owned = ctx.spawn_synthetic_process()
        def fail_terminate():
            raise OSError(sentinel)
        monkeypatch.setattr(owned, "terminate", fail_terminate)
    assert owned.poll() is not None
    assert ctx.closed and not ctx.run_dir.exists()


def test_crash_residue_blocks_until_verified_recovery_stops_only_own_orphan(tmp_path: Path):
    sentinel = fake_secret()
    external = external_sleeper()
    crasher = subprocess.Popen([sys.executable, "-c", CRASHING_OWNER, *root_argument(tmp_path)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=helper_env(), text=True, encoding="utf-8")
    try:
        crasher.stdin.write(sentinel + "\n")
        crasher.stdin.flush()
        facts = json.loads(crasher.stdout.readline())
        assert crasher.wait(timeout=20) == 0
        run_dir = Path(facts["run_dir"])
        orphan = ProcessIdentity(facts["child_pid"], facts["child_create_time"], facts["child_exe_fingerprint"])
        # After a hard crash the plaintext and the child are still there ...
        assert sentinel in (run_dir / "probe.yaml").read_text(encoding="utf-8")
        assert orphan.matches(process_identity(orphan.pid))
        # ... and every new run is refused until the explicit recovery step.
        with pytest.raises(PrivateRunError) as blocked:
            context_for_test(tmp_path).__enter__()
        assert blocked.value.code == "RECOVERY_REVIEW_REQUIRED"
        assert external.poll() is None

        rows = recover_stale_runs(run_dir.parent)
        assert [row["error_code"] for row in rows] == [None]
        assert rows[0]["stage"] == "CLEANUP" and rows[0]["probe_status"] is None
        assert sentinel not in json.dumps(rows) and str(run_dir) not in json.dumps(rows)
        assert not run_dir.exists()
        assert not orphan.matches(process_identity(orphan.pid))  # exact orphan stopped ...
        assert external.poll() is None  # ... unrelated process untouched
        assert not [entry for entry in run_dir.parent.iterdir()]
        with context_for_test(tmp_path) as again:
            again.write_yaml({"password": fake_secret()})
        assert again.closed and not again.run_dir.exists()
    finally:
        stop(external)
        stop(crasher)
        crasher.stdin.close()
        crasher.stdout.close()


def test_live_runs_coexist_and_are_never_recovered(tmp_path: Path):
    other = subprocess.Popen([sys.executable, "-c", LIVE_OWNER, *root_argument(tmp_path)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env=helper_env(), text=True, encoding="utf-8")
    contexts: list[RunContext] = []
    try:
        other.stdin.write(fake_secret() + "\n")
        other.stdin.flush()
        assert other.stdout.readline().strip() == "ready"
        for _ in range(10):  # V0 spec: up to 10 concurrent synthetic probes
            ctx = context_for_test(tmp_path)
            ctx.__enter__()
            ctx.write_yaml({"password": fake_secret()})
            contexts.append(ctx)
        root = contexts[0].root
        assert len({ctx.run_dir for ctx in contexts}) == 10
        assert recover_stale_runs(root) == []  # live runs are skipped, not "recovered"
        assert all(ctx.run_dir.is_dir() for ctx in contexts)
    finally:
        for ctx in contexts:
            ctx.close()
        other.stdin.close()
        try:
            assert other.wait(timeout=20) == 0
        finally:
            stop(other)
            other.stdout.close()
    assert all(ctx.closed and not ctx.run_dir.exists() for ctx in contexts)
    assert not [entry for entry in root.iterdir()]


def test_recovery_never_touches_unverifiable_residue_or_foreign_pids(tmp_path: Path):
    external = external_sleeper()
    abandoned: list[RunContext] = []

    def prepare(marker_patch: dict, extra_file: bool = False) -> RunContext:
        # Entered while every earlier fixture is still live (locks held);
        # all locks are dropped together below to simulate dead owners.
        ctx = context_for_test(tmp_path)
        ctx.__enter__()
        ctx.write_yaml({"password": fake_secret()})
        marker_path = ctx.run_dir / ".owner.json"
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        marker["owner_create_time"] = (marker["owner_create_time"] or 0) + 1  # owner "dead" (pid reused)
        marker.update(marker_patch)
        marker_path.write_text(json.dumps(marker), encoding="utf-8")
        if extra_file:
            (ctx.run_dir / "unexpected.txt").write_text("not ours", encoding="utf-8")
        abandoned.append(ctx)
        return ctx

    try:
        real = process_identity(external.pid)
        assert real is not None and real.pid == external.pid
        # A: marker names a different run -> not ours to judge; nothing is deleted or killed.
        foreign = prepare({"run_id": secrets.token_hex(16), "child_pid": external.pid,
                           "child_create_time": real.create_time, "child_exe_fingerprint": real.exe_fingerprint})
        # B: our run, but the recorded child identity no longer matches this pid -> delete, never signal.
        reused = prepare({"child_pid": external.pid, "child_create_time": real.create_time + 1,
                          "child_exe_fingerprint": real.exe_fingerprint})
        # C: unexpected content inside the run dir -> review only.
        odd = prepare({}, extra_file=True)
        for ctx in abandoned:
            ctx._drop_lock()  # the owners "die" without cleanup
        with pytest.raises(PrivateRunError):
            context_for_test(tmp_path).__enter__()
        rows = recover_stale_runs(foreign.root)
        by_dir = dict(zip(sorted(ctx.run_dir.name for ctx in abandoned), rows))
        assert by_dir[foreign.run_dir.name]["error_code"] == "RECOVERY_REVIEW_REQUIRED" and foreign.run_dir.is_dir()
        assert by_dir[reused.run_dir.name]["error_code"] is None and not reused.run_dir.exists()
        assert by_dir[odd.run_dir.name]["error_code"] == "RECOVERY_REVIEW_REQUIRED" and odd.run_dir.is_dir()
        assert external.poll() is None
        assert terminate_verified_process(ProcessIdentity(external.pid, real.create_time + 1, None)) is True
        assert external.poll() is None  # identity mismatch: nothing was signalled
    finally:
        stop(external)
        for ctx in abandoned:
            try:
                ctx.close()  # the synthetic test always cleans its own fixtures
            except PrivateRunError:
                pass
    assert not [entry for entry in abandoned[0].root.iterdir()]


def test_recover_cli_requires_confirmation_and_reports_fixed_rows(tmp_path: Path, capsys):
    assert cli.main(["recover"]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "INVALID_ARGUMENTS"
    assert cli.main(["recover", "--confirm", "--root", "relative/dir"]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "INVALID_ARGUMENTS"
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    ctx.__enter__()
    ctx.write_yaml({"password": sentinel})
    marker_path = ctx.run_dir / ".owner.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["owner_create_time"] = (marker["owner_create_time"] or 0) + 1
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    ctx._drop_lock()
    try:
        assert cli.main(["recover", "--confirm", "--root", str(ctx.root)]) == 0
        out = capsys.readouterr()
        rows = json.loads(out.out)
        assert [row["error_code"] for row in rows] == [None] and rows[0]["stage"] == "CLEANUP"
        assert sentinel not in out.out + out.err and str(ctx.root) not in out.out + out.err
        assert not ctx.run_dir.exists()
        assert cli.main(["recover", "--confirm", "--root", str(ctx.root)]) == 0
        assert json.loads(capsys.readouterr().out) == []
    finally:
        try:
            ctx.close()
        except PrivateRunError:
            pass


def test_cleanup_failure_is_hard_fail_but_residue_stays_owned(tmp_path: Path, monkeypatch):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    ctx.__enter__()
    ctx.write_yaml({"password": sentinel})
    with monkeypatch.context() as patch:
        def deny(_path):
            raise PermissionError(sentinel)
        patch.setattr(mihomo_config.shutil, "rmtree", deny)
        with pytest.raises(PrivateRunError) as info:
            ctx.close()
        assert info.value.code == "SECRET_CLEANUP_FAILED"
        assert sentinel not in str(info.value)
    try:
        # The failed owner is alive and still holds its lock: the residue is
        # owned, not crashed, so other runs proceed and recovery skips it.
        with context_for_test(tmp_path) as other:
            other.write_yaml({"password": fake_secret()})
        assert recover_stale_runs(ctx.root) == [] and ctx.run_dir.is_dir()
    finally:
        ctx.close()
    assert ctx.closed and not ctx.run_dir.exists()


def test_marker_carries_identities_but_no_secret_or_path(tmp_path: Path):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    with ctx:
        ctx.write_yaml({"password": sentinel})
        child = ctx.spawn_synthetic_process()
        marker = json.loads((ctx.run_dir / ".owner.json").read_text(encoding="utf-8"))
        assert marker["run_id"] == ctx.run_id and marker["owner_pid"] == os.getpid()
        assert marker["child_pid"] == child.pid
        own = process_identity(os.getpid())
        if own is not None:  # platforms with a creation stamp must record it
            assert marker["owner_create_time"] == own.create_time
            assert marker["child_create_time"] == process_identity(child.pid).create_time
        text = json.dumps(marker)
        assert sentinel not in text and str(ctx.run_dir) not in text and sys.executable not in text
    assert process_identity(child.pid) is None or process_identity(child.pid).create_time != marker["child_create_time"]


def test_write_yaml_can_be_rewritten_by_the_same_run_only(tmp_path: Path):
    first, second = fake_secret(), fake_secret()
    ctx = context_for_test(tmp_path)
    with ctx:
        path = ctx.write_yaml({"password": first})
        assert ctx.write_yaml({"password": second}) == path  # one retry per port attempt (F.4)
        text = path.read_text(encoding="utf-8")
        assert second in text and first not in text
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="SIGTERM cannot be ignored on Windows; terminate is already forceful")
def test_stop_owned_process_stays_within_the_cleanup_budget():
    stubborn = subprocess.Popen(
        [sys.executable, "-c", "import signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                               "print('armed', flush=True); time.sleep(60)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=helper_env(),
    )
    try:
        assert stubborn.stdout.readline().strip() == b"armed"
        started = time.monotonic()
        stop_owned_process(stubborn)
        elapsed = time.monotonic() - started
        assert stubborn.poll() is not None
        assert 2.5 <= elapsed <= 5.5, elapsed  # terminate ignored, kill within one 5 s budget
    finally:
        stop(stubborn)
        stubborn.stdout.close()


def test_stop_failure_still_deletes_plaintext_and_reports_cleanup_failure(tmp_path: Path, monkeypatch):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    ctx.__enter__()
    yaml_path = ctx.write_yaml({"password": sentinel})
    owned = ctx.spawn_synthetic_process()
    run_dir = ctx.run_dir
    try:
        with monkeypatch.context() as patch:
            def unkillable(_proc):
                raise mihomo_process.ProcessLifecycleError()
            patch.setattr(mihomo_config, "stop_owned_process", unkillable)
            patch.setattr(mihomo_process, "stop_owned_process", unkillable)
            with pytest.raises(PrivateRunError) as info:
                ctx.close()
        assert info.value.code == "SECRET_CLEANUP_FAILED"
        assert sentinel not in str(info.value)
        # The credential must not outlive the run just because the child did.
        assert not yaml_path.exists() and not run_dir.exists()
        assert not ctx.closed and owned.poll() is None  # honestly still owned, not "closed"
        # A later retry with a stoppable child completes the same run.
        ctx.close()
        assert ctx.closed and owned.poll() is not None and not run_dir.exists()
    finally:
        if owned.poll() is None:
            owned.kill()
            owned.wait(timeout=5)
        if run_dir.exists():
            shutil.rmtree(run_dir, ignore_errors=True)


@pytest.mark.skipif(os.name == "nt", reason="real Windows junction covered in Windows-only gate")
def test_reparse_escape_is_never_deleted(tmp_path: Path):
    external = tmp_path / "external"
    external.mkdir()
    sentinel = fake_secret()
    (external / "keep.txt").write_text(sentinel, encoding="utf-8")
    ctx = context_for_test(tmp_path)
    ctx.__enter__()
    link = ctx.run_dir / "escape"
    link.symlink_to(external, target_is_directory=True)
    try:
        with pytest.raises(PrivateRunError) as info:
            ctx.close()
        assert info.value.code == "SECRET_CLEANUP_FAILED"
        assert (external / "keep.txt").read_text(encoding="utf-8") == sentinel
    finally:
        try:
            link.unlink(missing_ok=True)
            ctx.close()
        finally:
            (external / "keep.txt").unlink(missing_ok=True)
            external.rmdir()
    assert not ctx.run_dir.exists()


def test_p0_07a_verdict_requires_two_route_backed_observations():
    # No network: RFC documentation IPs only, and OFFLINE-only mode.
    good = RouteObservation("203.0.113.10", route_verified=True, tls_verified=True, http_ok=True)
    other = RouteObservation("203.0.113.11", route_verified=True, tls_verified=True, http_ok=True)
    no_proof = RouteObservation("203.0.113.10", route_verified=False, tls_verified=True, http_ok=True)
    direct = RouteObservation("203.0.113.10", route_verified=True, tls_verified=True,
                              http_ok=True, direct_seen=True)
    common = {"runtime_verified": True, "cleanup_ok": True, "production": False}
    assert decide_probe_status(no_proof, no_proof, **common) == ("FAIL", None)
    assert decide_probe_status(good, no_proof, **common) == ("PARTIAL", None)
    assert decide_probe_status(good, other, **common) == ("CONFLICT", None)
    assert decide_probe_status(good, good, **common) == ("PASS", "203.0.113.10")
    assert decide_probe_status(good, good, **(common | {"cleanup_ok": False})) == ("FAIL", None)
    assert decide_probe_status(good, direct, **common) == ("FAIL", None)
    assert decide_probe_status(good, good, runtime_verified=False, cleanup_ok=True,
                               production=False) == ("FAIL", None)
    assert decide_probe_status(good, good, runtime_verified=True, cleanup_ok=True,
                               production=True) == ("FAIL", None)  # documentation IP, not public
    assert decide_probe_status(good, good, **(common | {"unsupported": True})) == ("UNSUPPORTED", None)


def test_unsafe_parent_or_symlink_never_receives_plaintext(tmp_path: Path):
    if os.name == "nt":
        pytest.skip("Windows NTFS parent/reparse checked in test_windows_safety_gate.py")
    sentinel = fake_secret()
    unsafe_root = tmp_path / "unsafe"
    unsafe_root.mkdir(mode=0o700)
    unsafe_root.chmod(0o777)
    with pytest.raises(PrivateRunError) as info:
        with RunContext(unsafe_root) as ctx:
            ctx.write_yaml({"password": sentinel})
    assert info.value.code == "PRIVATE_DIR_UNSAFE"
    assert not list(unsafe_root.iterdir())

    external = tmp_path / "external"
    external.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(external, target_is_directory=True)
    try:
        with pytest.raises(PrivateRunError):
            with RunContext(link) as ctx:
                ctx.write_yaml({"password": sentinel})
        assert not list(external.iterdir())
    finally:
        link.unlink(missing_ok=True)
    unsafe_root.chmod(0o700)


def test_acl_failure_precedes_plaintext_write(tmp_path: Path, monkeypatch):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    original_verify = ctx._verify

    def fail_yaml(path: Path, *, directory: bool):
        if path.name == "probe.yaml":
            raise PrivateRunError("PRIVATE_DIR_UNSAFE")
        return original_verify(path, directory=directory)

    monkeypatch.setattr(ctx, "_verify", fail_yaml)
    with pytest.raises(PrivateRunError) as info:
        with ctx:
            ctx.write_yaml({"password": sentinel})
    assert info.value.code == "PRIVATE_DIR_UNSAFE"
    assert ctx.closed and not ctx.run_dir.exists()


def test_empty_or_list_public_results_never_throw_or_leak():
    sentinel = fake_secret()
    assert redacted_result_dict([]) == []
    unsafe = [{"error_code": sentinel, "metadata": [{sentinel: sentinel}]}, sentinel]
    out = redacted_result_dict(unsafe)
    assert sentinel not in json.dumps(out)
    assert out[0]["error_code"] == out[1]["error_code"] == "PUBLIC_SCHEMA_REJECTED"


def test_closed_context_cannot_be_reused_to_leave_yaml_behind(tmp_path: Path):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    with ctx:
        ctx.write_yaml({"password": sentinel})
    with pytest.raises(PrivateRunError):
        with ctx:
            ctx.write_yaml({"password": sentinel})
    assert not ctx.run_dir.exists()


def test_f1_public_boundary_cannot_be_tricked_into_pass():
    assert PROBE_GATE_OPEN is False  # the single switch; F3 flips it with route-proof tests
    for unproven in ("PASS", "PARTIAL", "CONFLICT"):
        sentinel = fake_secret()
        output = redacted_result_dict({
            "probe_status": unproven, "route_verified": True, "source_count": 2,
            "sources_agree": True, "confirmed_exit_ip": sentinel,
        })
        assert output["probe_status"] == "FAIL"
        assert output["error_code"] == "ROUTE_PROOF_UNAVAILABLE"
        assert output["route_verified"] is False and output["source_count"] == 0
        assert sentinel not in json.dumps(output)
