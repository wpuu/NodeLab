"""Gate reporting tests. Mocked reports are never real-engine evidence."""
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
from unittest.mock import Mock

import pytest

SPEC = importlib.util.spec_from_file_location(
    "f2_session_gate", Path(__file__).resolve().parents[1] / "scripts" / "f2_session_gate.py",
)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


@pytest.fixture
def ready(monkeypatch, tmp_path):
    monkeypatch.setattr(gate.sys, "platform", "linux")
    monkeypatch.setattr(gate.sys, "version_info", (3, 12, 0))
    monkeypatch.setattr(gate.importlib.util, "find_spec", lambda name: object())
    exe = tmp_path / "synthetic-placeholder"
    exe.write_bytes(b"not executed")
    return ["--exe", str(exe)]


def output(capsys):
    captured = capsys.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)
    assert value["real_node_used"] is False
    assert value["real_node_test_allowed"] is False
    assert value["route_proof"] == "NOT_RUN"
    return value


def test_old_python_blocks_without_subprocess(ready, monkeypatch, capsys):
    monkeypatch.setattr(gate.sys, "version_info", (3, 11, 2))
    run = Mock()
    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.main(ready) == 2
    assert output(capsys)["code"] == "PYTHON_VERSION_UNSUPPORTED"
    run.assert_not_called()


def test_non_linux_blocks(ready, monkeypatch, capsys):
    monkeypatch.setattr(gate.sys, "platform", "win32")
    assert gate.main(ready) == 2
    assert output(capsys)["code"] == "LINUX_REQUIRED"


def test_argv_errors_never_echo_supplied_text(capsys):
    sentinel = secrets.token_urlsafe(32)
    assert gate.main(["--unexpected", sentinel]) == 2
    value = output(capsys)
    assert value["code"] == "INVALID_ARGUMENTS"
    assert sentinel not in json.dumps(value)


def test_missing_dependency_blocks(ready, monkeypatch, capsys):
    monkeypatch.setattr(gate.importlib.util, "find_spec", lambda name: None)
    assert gate.main(ready) == 2
    assert output(capsys)["code"] == "DEPENDENCIES_MISSING"


@pytest.mark.parametrize("count,tag,rc,expected", [
    (11, "", 0, "SYNTHETIC_SESSION_OK"),
    (11, "skipped", 0, "INCOMPLETE_ACCEPTANCE"),
    (0, "", 0, "INCOMPLETE_ACCEPTANCE"),
    (10, "", 0, "INCOMPLETE_ACCEPTANCE"),
    (12, "", 0, "INCOMPLETE_ACCEPTANCE"),
    (11, "failure", 0, "TESTS_FAILED"),
    (11, "error", 0, "TESTS_FAILED"),
    (11, "", 1, "TESTS_FAILED"),
])
def test_report_must_be_complete_and_failure_free(ready, monkeypatch, capsys, count, tag, rc, expected):
    reports = []

    def run(args, **kwargs):
        report = Path(args[args.index("--junitxml") + 1])
        reports.append(report)
        content = f"<{tag}/>" if tag else ""
        report.write_text("<testsuites><testsuite>" +
                          f"<testcase>{content}</testcase>" * count + "</testsuite></testsuites>")
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        assert "NODELAB_MIHOMO_SHA256" not in kwargs["env"]
        assert "PYTEST_ADDOPTS" not in kwargs["env"]
        assert kwargs["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
        return subprocess.CompletedProcess(args, rc)

    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.main(ready) == (0 if expected == "SYNTHETIC_SESSION_OK" else 2)
    assert output(capsys)["code"] == expected
    assert all(not path.exists() for path in reports)


@pytest.mark.parametrize("kind", ["missing", "malformed"])
def test_unreadable_report_never_passes(ready, monkeypatch, capsys, kind):
    def run(args, **kwargs):
        if kind == "malformed":
            Path(args[args.index("--junitxml") + 1]).write_text("not xml")
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.main(ready) == 2
    assert output(capsys)["status"] != "PASS"


@pytest.mark.parametrize("count,skip,status", [(4, False, "PASS"), (4, True, "BLOCKED"),
                                             (0, False, "BLOCKED"), (3, False, "BLOCKED"), (5, False, "BLOCKED")])
@pytest.mark.parametrize("protocol", ["trojan", "vless"])
def test_protocol_gate_requires_all_four_cases(ready, monkeypatch, capsys, count, skip, status, protocol):
    def run(args, **kwargs):
        assert any(str(arg).endswith(f"test_real_{protocol}_tcp.py") for arg in args)
        report = Path(args[args.index("--junitxml") + 1])
        tag = "<skipped/>" if skip else ""
        report.write_text("<testsuites><testsuite>" + f"<testcase>{tag}</testcase>" * count +
                          "</testsuite></testsuites>")
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.main(ready + ["--suite", f"{protocol}-tcp"]) == (0 if status == "PASS" else 2)
    captured = capsys.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)
    assert value["gate"] == f"F3_LINUX_{protocol.upper()}_TCP"
    assert value["status"] == status
    assert value["route_proof"] == ("LOCAL_FIXTURE_ONLY" if status == "PASS" else "NOT_RUN")
    assert value["real_node_test_allowed"] is False
