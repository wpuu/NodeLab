"""Linux-only synthetic real-engine gate. Prints fixed fields, never pytest logs.

Usage: python scripts/f2_session_gate.py --exe /absolute/path/to/pinned/mihomo
Optional: --suite trojan-tcp or vless-tcp for actual local TLS/TCP protocol gates.
No downloads, external probes, environment repairs, Git operations or credential input.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SUITES = {
    "session": ("F2_LINUX_SESSION", "test_real_engine_session.py", 11, "SYNTHETIC_SESSION_OK"),
    "trojan-tcp": ("F3_LINUX_TROJAN_TCP", "test_real_trojan_tcp.py", 4, "LOCAL_TROJAN_TCP_OK"),
    "vless-tcp": ("F3_LINUX_VLESS_TCP", "test_real_vless_tcp.py", 4, "LOCAL_VLESS_TCP_OK"),
}


class ArgumentsInvalid(Exception):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentsInvalid()


def result(status, code, *, passed=0, skipped=0, gate_name="F2_LINUX_SESSION"):
    print(json.dumps({
        "gate": gate_name, "status": status, "code": code,
        "passed": passed, "skipped": skipped,
        "real_node_used": False, "real_node_test_allowed": False,
        "windows_acceptance": "NOT_RUN",
        "route_proof": "LOCAL_FIXTURE_ONLY" if gate_name in ("F3_LINUX_TROJAN_TCP", "F3_LINUX_VLESS_TCP") and status == "PASS" else "NOT_RUN",
    }, separators=(",", ":")))
    return 0 if status == "PASS" else 2


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
                return emit("FAIL", "TESTS_FAILED", passed=passed, skipped=skipped)
            if skipped or len(cases) != expected_tests:
                return emit("BLOCKED", "INCOMPLETE_ACCEPTANCE", passed=passed, skipped=skipped)
            return emit("PASS", success_code, passed=passed)
    except KeyboardInterrupt:
        return emit("BLOCKED", "CANCELLED_REVIEW_RECOVERY")
    except (OSError, ValueError, ET.ParseError, ImportError):
        return emit("BLOCKED", "GATE_EXECUTION_FAILED")


if __name__ == "__main__":
    raise SystemExit(main())
