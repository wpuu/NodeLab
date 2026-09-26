"""F1: all values below are fresh fictional sentinels; never real nodes."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

import pytest

from nodelab import cli, mihomo_config, mihomo_process
from nodelab.mihomo_config import PrivateRunError, RunContext, scrub_yaml_for_display
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
    return f"trojan://{quote(secret, safe='')}@198.51.100.20:443?security=tls"


def test_s1_s4_private_carriers_and_public_views():
    sentinel = fake_secret()
    password = sentinel + ":" + "@"
    uri = (f"trojan://{quote(password, safe='')}@198.51.100.20:443"
           f"?type=ws&security=tls&host={sentinel}.invalid&sni={sentinel}.invalid"
           f"&path=%2F{sentinel}&auth={quote(sentinel)}#{quote(sentinel)}")
    node = parse_uri(uri)
    assert node.secret == password
    assert node.path.endswith(sentinel)
    assert node.display_name == sentinel
    assert sentinel in node.extra_query["auth"]
    out = json.dumps(redacted_node_dict(node), ensure_ascii=False) + repr(node) + str(node)
    out += redact_uri(uri)
    for value in (sentinel, quote(sentinel), quote(password, safe=''), password, uri):
        assert value not in out
    assert "display_name" not in out and "redacted_uri" not in out


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
        assert rows[0]["probe_status"] == rows[2]["probe_status"] == "UNSUPPORTED"
        assert rows[1]["error_code"] == "UNSUPPORTED_PROTOCOL"
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


def test_legacy_live_engine_entry_points_disabled():
    sentinel = fake_secret()
    node = parse_uri(fake_trojan_uri(sentinel))
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


def test_crash_recovery_is_fail_closed_not_global_kill(tmp_path: Path):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    ctx.__enter__()
    try:
        ctx.write_yaml({"password": sentinel})
        with pytest.raises(PrivateRunError) as info:
            context_for_test(tmp_path).__enter__()
        assert info.value.code == "RECOVERY_REVIEW_REQUIRED"
        assert ctx.run_dir.is_dir()  # forced OS death cannot run finally
    finally:
        ctx.close()  # the synthetic test itself always cleans up
    assert not ctx.run_dir.exists()


def test_cleanup_failure_is_hard_fail_and_stale_dir_blocks(tmp_path: Path, monkeypatch):
    sentinel = fake_secret()
    ctx = context_for_test(tmp_path)
    ctx.__enter__()
    ctx.write_yaml({"password": sentinel})
    real_rmtree = shutil.rmtree
    with monkeypatch.context() as patch:
        def deny(_path):
            raise PermissionError(sentinel)
        patch.setattr(mihomo_config.shutil, "rmtree", deny)
        with pytest.raises(PrivateRunError) as info:
            ctx.close()
        assert info.value.code == "SECRET_CLEANUP_FAILED"
        assert sentinel not in str(info.value)
    try:
        with pytest.raises(PrivateRunError) as blocked:
            context_for_test(tmp_path).__enter__()
        assert blocked.value.code == "RECOVERY_REVIEW_REQUIRED"
    finally:
        ctx.close()
    assert not ctx.run_dir.exists()


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
