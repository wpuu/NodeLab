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


@pytest.mark.parametrize("change,expected", [
    ("none", "PASS"), ("missing", "BLOCKED"), ("extra", "BLOCKED"),
    ("duplicate", "BLOCKED"), ("unexpected_skip", "BLOCKED"),
    ("wrong_skip_identity", "BLOCKED"), ("xfail", "BLOCKED"),
    ("windows_not_skipped", "BLOCKED"), ("failure", "FAIL"),
    ("error", "FAIL"), ("nonzero", "FAIL"),
])
def test_full_regression_requires_exact_count_and_named_windows_skips(ready, monkeypatch, capsys, change, expected):
    import xml.etree.ElementTree as ET

    def run(args, **kwargs):
        assert str(gate.ROOT / "tests") in args
        tree = ET.Element("testsuites")
        suite = ET.SubElement(tree, "testsuite")
        rows = []
        for i in range(gate.FULL_EXPECTED_CASES - 3):
            rows.append(ET.SubElement(suite, "testcase", classname="tests.test_sample", name=f"test_case_{i}"))
        for module, name in sorted(gate.WINDOWS_SKIPS):
            row = ET.SubElement(suite, "testcase", classname=module, name=name)
            ET.SubElement(row, "skipped", type="pytest.skip")
        if change == "missing":
            suite.remove(rows[-1])
        elif change == "extra":
            ET.SubElement(suite, "testcase", classname="tests.test_sample", name="test_extra")
        elif change == "duplicate":
            rows[1].set("name", rows[0].get("name"))
        elif change == "unexpected_skip":
            ET.SubElement(rows[0], "skipped", type="pytest.skip")
        elif change == "wrong_skip_identity":
            suite[-1].set("name", "test_not_windows")
        elif change == "xfail":
            suite[-1].find("skipped").set("type", "pytest.xfail")
        elif change == "windows_not_skipped":
            suite[-1].remove(suite[-1].find("skipped"))
        elif change in ("failure", "error"):
            ET.SubElement(rows[0], change).text = "private-raw-output"
        ET.ElementTree(tree).write(args[args.index("--junitxml") + 1])
        return subprocess.CompletedProcess(args, 1 if change == "nonzero" else 0)

    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.main(ready + ["--suite", "full"]) == (0 if expected == "PASS" else 2)
    value = output(capsys)
    assert value["gate"] == "LINUX_FULL_REGRESSION"
    assert value["status"] == expected
    assert "private-raw-output" not in json.dumps(value)
    if expected == "PASS":
        assert value["passed"] == gate.FULL_EXPECTED_CASES - 3
        assert value["skipped"] == 3
        assert value["code"] == "FULL_REGRESSION_OK"


def test_failure_ids_never_include_parameters_or_raw_exception_text():
    import xml.etree.ElementTree as ET
    sentinel = secrets.token_urlsafe(32)
    known = ET.Element("testcase", classname="tests.test_engine_binary",
                       name=f"test_real_binary_reports_the_pinned_version[{sentinel}]")
    ET.SubElement(known, "failure").text = sentinel
    unknown = ET.Element("testcase", classname=sentinel, name=sentinel)
    ET.SubElement(unknown, "error").text = sentinel
    assert gate.safe_failure_ids([known, unknown]) == [
        "UNCLASSIFIED", "tests.test_engine_binary::test_real_binary_reports_the_pinned_version",
    ]
