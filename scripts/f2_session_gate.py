"""Linux-only synthetic real-engine gate. Prints fixed fields, never pytest logs.

Usage: python scripts/f2_session_gate.py --exe /absolute/path/to/pinned/mihomo
Optional: --suite trojan-tcp or vless-tcp for actual local TLS/TCP protocol gates.
--suite full runs the complete regression; only three named Windows skips allowed.
No downloads, external probes, environment repairs, Git operations or credential input.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
# Update explicitly when reviewed tests are added/removed; not derived from the
# report under evaluation. A reduced collection must not authorize itself.
FULL_EXPECTED_CASES = 707
WINDOWS_SKIPS = {
    ("tests.test_windows_safety_gate", name) for name in (
        "test_windows_e_volume_dacl_before_and_during_private_yaml",
        "test_windows_exact_pid_and_external_listening_port_untouched",
        "test_windows_real_junction_is_not_deleted_through",
    )
}
SUITES = {
    "full": ("LINUX_FULL_REGRESSION", "", FULL_EXPECTED_CASES, "FULL_REGRESSION_OK"),
    "session": ("F2_LINUX_SESSION", "test_real_engine_session.py", 11, "SYNTHETIC_SESSION_OK"),
    "trojan-tcp": ("F3_LINUX_TROJAN_TCP", "test_real_trojan_tcp.py", 4, "LOCAL_TROJAN_TCP_OK"),
    "vless-tcp": ("F3_LINUX_VLESS_TCP", "test_real_vless_tcp.py", 4, "LOCAL_VLESS_TCP_OK"),
}


class ArgumentsInvalid(Exception):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentsInvalid()


def result(status, code, *, passed=0, skipped=0, gate_name="F2_LINUX_SESSION", failed_tests=None):
    payload = {
        "gate": gate_name, "status": status, "code": code,
        "passed": passed, "skipped": skipped,
        "real_node_used": False, "real_node_test_allowed": False,
        "windows_acceptance": "NOT_RUN",
        "route_proof": "LOCAL_FIXTURE_ONLY" if gate_name in ("F3_LINUX_TROJAN_TCP", "F3_LINUX_VLESS_TCP") and status == "PASS" else "NOT_RUN",
    }
    if failed_tests is not None:
        payload["failed_tests"] = failed_tests
    print(json.dumps(payload, separators=(",", ":")))
    return 0 if status == "PASS" else 2


def safe_failure_ids(cases):
    """Only source-declared function names, never params, exception text or XML.

    AST-derived allowlist excludes credentials that might appear in parameter
    IDs. Unknown collection/setup errors get a fixed fallback identifier.
    """
    allowed = set()
    for path in (ROOT / "tests").rglob("test_*.py"):
        module = ".".join(path.relative_to(ROOT).with_suffix("").parts)
        try:
            source = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(source):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                allowed.add((module, node.name))
    found = set()
    for case in cases:
        if all(case.find(tag) is None for tag in ("failure", "error")):
            continue
        key = (case.get("classname", ""), case.get("name", "").split("[", 1)[0])
        found.add("::".join(key) if key in allowed else "UNCLASSIFIED")
    return sorted(found)


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    parser.add_argument("--suite", choices=tuple(SUITES), default="session")
    try:
        args = parser.parse_args(argv)
    except ArgumentsInvalid:
        return result("BLOCKED", "INVALID_ARGUMENTS")
    gate_name, test_file, expected_tests, success_code = SUITES[args.suite]

    def emit(status, code, **kwargs):
        return result(status, code, gate_name=gate_name, **kwargs)

    if sys.platform != "linux":
        return emit("BLOCKED", "LINUX_REQUIRED")
    if sys.version_info < (3, 12):
        return emit("BLOCKED", "PYTHON_VERSION_UNSUPPORTED")
    try:
        exe = Path(args.exe)
        if not exe.is_absolute() or not exe.is_file():
            return emit("BLOCKED", "BINARY_UNAVAILABLE")
        if any(importlib.util.find_spec(name) is None for name in ("pytest", "yaml", "httpx", "idna")):
            return emit("BLOCKED", "DEPENDENCIES_MISSING")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        env["NODELAB_MIHOMO_EXE"] = str(exe)
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        for key in ("NODELAB_MIHOMO_SHA256", "PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
            env.pop(key, None)
        with tempfile.TemporaryDirectory(prefix="nodelab-f2-gate-") as temporary:
            report = Path(temporary) / "results.xml"
            # No wrapper timeout: killing pytest mid-cleanup could orphan a
            # child. Each session has its own work/cleanup budgets. Hard crash
            # recovery remains a separate, explicitly unclosed acceptance gate.
            run = subprocess.run([
                sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                "-o", "addopts=", str(ROOT / "tests" / test_file),
                "--junitxml", str(report),
            ], cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not report.is_file() or report.stat().st_size > 4 * 1024 * 1024:
                return emit("FAIL", "REPORT_UNAVAILABLE")
            tree = ET.parse(report)
            cases = tree.findall(".//testcase")
            skipped = sum(case.find("skipped") is not None for case in cases)
            failures = len(tree.findall(".//failure")) + len(tree.findall(".//error"))
            passed = sum(all(case.find(tag) is None for tag in ("skipped", "failure", "error")) for case in cases)
            if run.returncode != 0 or failures:
                return emit("FAIL", "TESTS_FAILED", passed=passed, skipped=skipped,
                            **({"failed_tests": safe_failure_ids(cases)} if args.suite == "full" else {}))
            if args.suite == "full":
                identities = [(case.get("classname"), case.get("name")) for case in cases]
                skipped_cases = [case for case in cases if case.find("skipped") is not None]
                skipped_ids = {(case.get("classname"), case.get("name")) for case in skipped_cases}
                complete = (len(cases) == expected_tests
                            and len(set(identities)) == len(cases)
                            and all(module and name for module, name in identities)
                            and skipped_ids == WINDOWS_SKIPS
                            and skipped == len(WINDOWS_SKIPS)
                            and all(case.find("skipped").get("type") == "pytest.skip" for case in skipped_cases))
                if not complete:
                    return emit("BLOCKED", "INCOMPLETE_ACCEPTANCE", passed=passed, skipped=skipped)
                return emit("PASS", success_code, passed=passed, skipped=skipped)
            if skipped or len(cases) != expected_tests:
                return emit("BLOCKED", "INCOMPLETE_ACCEPTANCE", passed=passed, skipped=skipped)
            return emit("PASS", success_code, passed=passed)
    except KeyboardInterrupt:
        return emit("BLOCKED", "CANCELLED_REVIEW_RECOVERY")
    except (OSError, ValueError, ET.ParseError, ImportError):
        return emit("BLOCKED", "GATE_EXECUTION_FAILED")


if __name__ == "__main__":
    raise SystemExit(main())
