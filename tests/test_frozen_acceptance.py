"""Fictional startup acceptance and privacy failures, with isolated audit hooks."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tkinter
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts/nodelab_offline.pyw"
PRIVATE = "FICTIONAL_PRIVATE_FAILURE_CANARY_Z917"


def _source(*args):
    return subprocess.run(
        [sys.executable, "-I", str(ENTRY), *args],
        text=True, capture_output=True, timeout=30,
    )


def _child(code, *args):
    return subprocess.run(
        [sys.executable, "-I", "-c", code, str(ENTRY), *map(str, args)],
        text=True, capture_output=True, timeout=30,
    )


def test_source_acceptance_follows_exact_runtime_profile_without_leaks(request):
    completed = _source("--acceptance-check")
    actual_tcl_patchlevel = tkinter.Tcl().eval("info patchlevel")
    recorded_version = actual_tcl_patchlevel if all(
        part.isdecimal() for part in actual_tcl_patchlevel.split(".")
    ) and len(actual_tcl_patchlevel.split(".")) == 3 else "UNRECOGNIZED"
    request.node.user_properties.extend([
        ("source_python_version", ".".join(map(str, sys.version_info[:3]))),
        ("source_tcl_patchlevel", recorded_version),
        ("source_runtime_acceptance", "SUPPORTED_PROFILE" if actual_tcl_patchlevel in {"8.6.15", "9.0.4"} else "REJECTED_PROFILE"),
    ])
    if actual_tcl_patchlevel not in {"8.6.15", "9.0.4"}:
        # A source test on a runner with an unsupported Tcl is expected to
        # reject, not to masquerade as a native build acceptance result.
        assert completed.returncode == 2
        assert completed.stdout == ""
        assert completed.stderr.strip() == "ACCEPTANCE_FAILED"
        assert PRIVATE not in completed.stderr
        return
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "acceptance_check": "PASS", "mode": "FICTIONAL_ONLY",
        "network_used": False, "engine_started": False, "frozen": False,
        "ignore_environment": True,
        "input_formats_checked": ["uri_lines", "base64"],
        "report_round_trips": 3, "report_schema_version": 2,
        "records": 3, "parsed": 2, "invalid": 1,
        "input_unchanged": True, "reports_unchanged": True,
        "markdown_mismatch": "REJECTED", "private_text": "ABSENT",
        "audit_negative_controls": {
            "socket_create": "BLOCKED", "dns": "BLOCKED", "child_process": "BLOCKED",
        },
        "tcl_runtime": "PASS",
        "gui_runtime": "WINDOWS_HIDDEN_WINDOW_PASS" if os.name == "nt" else "NOT_CHECKED_NO_DISPLAY",
        "tcl_patchlevel": actual_tcl_patchlevel,
        "tk_patchlevel": actual_tcl_patchlevel if os.name == "nt" else None,
    }
    for value in ("FICTIONAL_PASSWORD", "private-host-a741", "FICTIONAL_FRAGMENT", "FICTIONAL_SECRET_LINE",
                  "FICTIONAL_FILENAME", "FICTIONAL_MISMATCH", "nodelab-fictional-", str(ENTRY)):
        assert value not in completed.stdout + completed.stderr


@pytest.mark.parametrize("arguments", [
    ("--acceptance-check", PRIVATE),
    ("--acceptance-check", "--self-check"),
    ("--acceptance-check", "--"),
    ("--acceptance-check", "--input-format", "base64"),
    ("--acceptance-check", "--acceptance-check"),
    ("--self-check", "--acceptance-check"),
    ("--ACCEPTANCE-CHECK",),
    ("--acceptance-check=" + PRIVATE,),
])
def test_acceptance_rejects_every_extra_parameter(arguments):
    completed = _source(*arguments)
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr.strip() == "ARGUMENTS_FORBIDDEN"
    assert PRIVATE not in completed.stderr


def test_absent_audit_guard_fails_before_network_or_process_api_calls():
    code = r'''
import json, runpy, socket, subprocess, sys
entry = runpy.run_path(sys.argv[1], run_name="missing_guard_acceptance")
globals_ = entry["main"].__globals__
globals_["install_offline_guard"] = lambda: None
calls = []
def forbidden(*args, **kwargs):
    calls.append("CALLED")
    raise AssertionError("FICTIONAL_PRIVATE_FAILURE_CANARY_Z917")
socket.socket = forbidden
socket.getaddrinfo = forbidden
subprocess.Popen = forbidden
sys.argv = [sys.argv[1], "--acceptance-check"]
code = entry["main"]()
print(json.dumps({"returned": code, "forbidden_calls": calls}))
raise SystemExit(code)
'''
    completed = _child(code)
    assert completed.returncode == 2
    assert json.loads(completed.stdout) == {"returned": 2, "forbidden_calls": []}
    assert completed.stderr.strip() == "ACCEPTANCE_FAILED"
    assert PRIVATE not in completed.stdout + completed.stderr


def test_unrelated_audit_failure_does_not_count_as_offline_blocking():
    code = r'''
import runpy, sys
entry = runpy.run_path(sys.argv[1], run_name="incorrect_guard_acceptance")
def wrong_guard(event, args):
    if event.startswith("socket."):
        raise RuntimeError("FICTIONAL_PRIVATE_FAILURE_CANARY_Z917")
entry["main"].__globals__["install_offline_guard"] = lambda: sys.addaudithook(wrong_guard)
sys.argv = [sys.argv[1], "--acceptance-check"]
raise SystemExit(entry["main"]())
'''
    completed = _child(code)
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr.strip() == "ACCEPTANCE_FAILED"
    assert PRIVATE not in completed.stderr


@pytest.mark.parametrize("fault", [
    "unexpected_exception", "metadata_changed", "input_mtime_changed", "report_mtime_changed",
    "mismatch_accepted", "engine_imported", "probe_gate_open", "tcl_failure", "frozen_source_loader",
    "unsupported_tcl_patchlevel", "mismatched_tk_patchlevel",
    "frozen_environment_not_ignored",
])
def test_acceptance_detects_faults_without_exposing_exception_or_private_data(fault):
    code = r'''
import os, runpy, sys, types
from pathlib import Path
entry = runpy.run_path(sys.argv[1], run_name="acceptance_fault_injection")
globals_ = entry["main"].__globals__
fault = sys.argv[2]
reached_fault = []
import nodelab.offline_file as writer
import nodelab.offline_report as reader
# These are fault-isolation fixtures, not native runtime evidence. A runner's
# unrelated Tcl version must not reject before the intended fault is reached.
import tkinter
class SupportedTcl:
    def eval(self, expression):
        if expression == "expr {1 + 1}":
            return "2"
        if expression == "info patchlevel":
            return "8.6.15"
        raise AssertionError("FICTIONAL_PRIVATE_FAILURE_CANARY_Z917")
class SupportedTk:
    def __init__(self):
        self.tk = self
    def eval(self, expression):
        if expression == "package provide Tk":
            return "8.6.15"
        raise AssertionError("FICTIONAL_PRIVATE_FAILURE_CANARY_Z917")
    def withdraw(self):
        pass
    def update_idletasks(self):
        pass
    def update(self):
        pass
    def state(self):
        return "withdrawn"
    def destroy(self):
        pass
tkinter.Tcl = SupportedTcl
tkinter.Tk = SupportedTk
if fault == "unexpected_exception":
    def fail():
        reached_fault.append("FAULT")
        raise RuntimeError("FICTIONAL_PRIVATE_FAILURE_CANARY_Z917")
    globals_["_acceptance_check"] = fail
elif fault == "metadata_changed":
    original = reader.load_reports
    def altered(folder):
        result = original(folder)
        reached_fault.append("FAULT")
        result["metadata"]["decoding_passes"] = True
        return result
    reader.load_reports = altered
elif fault == "input_mtime_changed":
    original = writer.run_file
    def altered(source, destination, **kwargs):
        result = original(source, destination, **kwargs)
        reached_fault.append("FAULT")
        info = source.stat()
        os.utime(source, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        return result
    writer.run_file = altered
elif fault == "report_mtime_changed":
    original = reader.load_reports
    def altered(folder):
        result = original(folder)
        reached_fault.append("FAULT")
        path = folder / "COMPLETE.json"
        info = path.stat()
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        return result
    reader.load_reports = altered
elif fault == "mismatch_accepted":
    original = reader.load_reports
    def altered(folder):
        try:
            return original(folder)
        except reader.OfflineReportError:
            reached_fault.append("FAULT")
            return {"FICTIONAL_PRIVATE_FAILURE_CANARY_Z917": True}
    reader.load_reports = altered
elif fault == "engine_imported":
    sys.modules["nodelab.engine"] = types.ModuleType("nodelab.engine")
elif fault == "probe_gate_open":
    import nodelab.types
    nodelab.types.PROBE_GATE_OPEN = True
elif fault == "frozen_source_loader":
    sys.frozen = True
elif fault == "frozen_environment_not_ignored":
    sys.frozen = True
    import nodelab
    class AcceptedFrozenLoader:
        pass
    AcceptedFrozenLoader.__module__ = "pyimod02_importers"
    nodelab.__spec__.loader = AcceptedFrozenLoader()
    values = {name: getattr(sys.flags, name) for name in dir(sys.flags) if not name.startswith("_")}
    values["ignore_environment"] = 0
    sys.flags = types.SimpleNamespace(**values)
    environment_probe_events = []
    real_audit = sys.audit
    def record_audit(event, *args):
        environment_probe_events.append(event)
        return real_audit(event, *args)
    sys.audit = record_audit
elif fault == "tcl_failure":
    import tkinter
    class BrokenTcl:
        def eval(self, expression):
            reached_fault.append("FAULT")
            raise RuntimeError("FICTIONAL_PRIVATE_FAILURE_CANARY_Z917")
    tkinter.Tcl = BrokenTcl
elif fault == "unsupported_tcl_patchlevel":
    import tkinter
    class UnsupportedTcl:
        def eval(self, expression):
            if expression == "info patchlevel":
                reached_fault.append("FAULT")
            return "2" if expression == "expr {1 + 1}" else "FICTIONAL_PRIVATE_FAILURE_CANARY_Z917"
    tkinter.Tcl = UnsupportedTcl
elif fault == "mismatched_tk_patchlevel":
    globals_["os"] = types.SimpleNamespace(name="nt")
    reached_tk_patchlevel = []
    class MismatchedTk:
        tk = None
        def __init__(self):
            self.tk = self
        def eval(self, expression):
            reached_tk_patchlevel.append(expression)
            return "FICTIONAL_PRIVATE_FAILURE_CANARY_Z917"
        def withdraw(self):
            pass
        def update_idletasks(self):
            pass
        def update(self):
            pass
        def state(self):
            return "withdrawn"
        def destroy(self):
            pass
    tkinter.Tk = MismatchedTk
sys.argv = [sys.argv[1], "--acceptance-check"]
returned = entry["main"]()
if fault in {"unexpected_exception", "metadata_changed", "input_mtime_changed", "report_mtime_changed",
             "mismatch_accepted", "tcl_failure", "unsupported_tcl_patchlevel"} and not reached_fault:
    raise SystemExit(57)
if fault == "mismatched_tk_patchlevel" and reached_tk_patchlevel != ["package provide Tk"]:
    raise SystemExit(57)
if fault == "frozen_environment_not_ignored" and environment_probe_events:
    raise SystemExit(57)
raise SystemExit(returned)
'''
    completed = _child(code, fault)
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr.strip() == "ACCEPTANCE_FAILED"
    assert PRIVATE not in completed.stdout + completed.stderr


@pytest.mark.parametrize("operation", ["pass_without_stdout", "failure_without_streams", "guard_install_failure_without_streams"])
def test_missing_console_streams_never_turn_failure_into_success(operation):
    code = r'''
import json, runpy, sys
entry = runpy.run_path(sys.argv[1], run_name="windowed_acceptance")
operation = sys.argv[2]
globals_ = entry["main"].__globals__
if operation == "pass_without_stdout":
    globals_["_acceptance_check"] = lambda: {"acceptance_check": "PASS"}
else:
    def fail():
        raise RuntimeError("FICTIONAL_PRIVATE_FAILURE_CANARY_Z917")
    globals_["install_offline_guard" if operation == "guard_install_failure_without_streams" else "_acceptance_check"] = fail
sys.argv = [sys.argv[1], "--acceptance-check"]
sys.stdout = None
sys.stderr = None
code = entry["main"]()
sys.stdout = sys.__stdout__
sys.stderr = sys.__stderr__
print(json.dumps({"returned": code}))
raise SystemExit(code)
'''
    completed = _child(code, operation)
    assert completed.returncode == 2
    assert json.loads(completed.stdout) == {"returned": 2}
    assert completed.stderr == ""
    assert PRIVATE not in completed.stdout + completed.stderr


def test_self_check_remains_read_write_free():
    code = r'''
import runpy, sys, tempfile
from pathlib import Path
entry = runpy.run_path(sys.argv[1], run_name="self_check_files_forbidden")
def forbidden(*args, **kwargs):
    raise AssertionError("FICTIONAL_PRIVATE_FAILURE_CANARY_Z917")
for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text", "mkdir"):
    setattr(Path, name, forbidden)
tempfile.TemporaryDirectory = forbidden
sys.argv = [sys.argv[1], "--self-check"]
raise SystemExit(entry["main"]())
'''
    completed = _child(code)
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {"self_check": "PASS", "mode": "FICTIONAL_ONLY", "network_used": False}


def test_frozen_entry_does_not_insert_adjacent_source_checkout(tmp_path):
    # The actual frozen executable is verified separately. This source test
    # covers the startup routing branch without claiming frozen import proof.
    copied = tmp_path / "application/scripts/nodelab_offline.pyw"
    copied.parent.mkdir(parents=True)
    copied.write_bytes(ENTRY.read_bytes())
    old_source = copied.parent.parent / "src/nodelab"
    old_source.mkdir(parents=True)
    (old_source / "__init__.py").write_text("raise RuntimeError('OLD_CHECKOUT_IMPORTED')\n", encoding="utf-8")
    adjacent_bundle = copied.parent / "nodelab"
    adjacent_bundle.mkdir()
    (adjacent_bundle / "__init__.py").write_text("raise RuntimeError('OLD_BUNDLE_IMPORTED')\n", encoding="utf-8")
    code = r'''
import json, runpy, sys
before = list(sys.path)
sys.frozen = True
runpy.run_path(sys.argv[2], run_name="frozen_routing_branch")
print(json.dumps({"source_path_unchanged": sys.path == before}))
'''
    completed = _child(code, copied)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"source_path_unchanged": True}
    assert completed.stderr == ""
