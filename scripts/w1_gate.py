#!/usr/bin/env python3
"""NL-P0-006 / W1 deterministic runner.

One command, no judgement calls, no LLM in the loop.

The operator runs this from OUTSIDE the repository working tree; the script
performs every check that NL-P0-006 sections 1, 1a and 2 require, runs the two
Windows gate test modules, and prints the fixed NL-P0-006_RESULT block.

Design rules (do not relax):
  * Fail closed. Anything unverifiable becomes a BLOCKER, never a PASS.
  * Never repair the operator's environment. No ACL edits, no git clean, no
    reset/stash/rebase/merge/pull, no taskkill, no manual deletes.
  * Never print secrets: no raw pytest output, no tracebacks, no YAML, no
    private paths, no sentinels. Only fixed identifiers and counts.
  * Local `main` must point at the same commit when the script exits.

Usage (Windows, NON-elevated PowerShell):

    py -3 C:\\path\\to\\w1_gate.py

Optional flags:
    --repo PATH     repository location (default E:\\NodeLab)
    --recover       allow the sanctioned `nodelab recover --confirm` routine to
                    reclaim verified crash residue before the run. Without this
                    flag residue is reported as a blocker and nothing is
                    touched.
    --keep-verify   keep the verify/ branch checked out on exit (default:
                    return to the original branch)
    --allow-non-windows
                    self-test path for the Technical Owner only. Windows-only
                    facts become NOT_RUN and W1_OVERALL can never be PASS.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

CANDIDATE_BRANCH = "candidate/w1-gate"
SCRIPT_PATH_IN_REPO = "scripts/w1_gate.py"
TEST_FILES = ("tests/test_p0_safety.py", "tests/test_windows_safety_gate.py")
LEGACY_RESCUE_SHA = "b48a50033f865003c67bc9f35370fb25348d69fe"
REQUIRED_MODULES = ("yaml", "httpx", "idna", "pytest")
MIN_PYTHON = (3, 12)

DRIVE_FIXED = 3
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# Fixed test-node -> result-field mapping. A field is PASS only when every
# mapped node passed; a skip or a missing node makes it NOT_RUN, a failure or
# error makes it FAIL.
FIELD_TESTS: dict[str, tuple[str, ...]] = {
    "DYNAMIC_SENTINEL_SCAN": (
        "test_s1_s4_private_carriers_and_public_views",
        "test_s5_s6_s7_fixed_public_schema_and_nested_adversary",
        "test_s5_multiline_secret_rejected_or_never_showable",
        "test_empty_or_list_public_results_never_throw_or_leak",
        "test_marker_carries_identities_but_no_secret_or_path",
    ),
    "PUBLIC_ALLOWLIST_AND_URI_ARGV": (
        "test_s9_argv_and_unknown_arguments_do_not_repeat_uri",
        "test_s9_file_parse_per_line_no_auto_results",
        "test_missing_file_path_cannot_be_echoed",
        "test_legacy_live_engine_entry_points_disabled",
        "test_f1_public_boundary_cannot_be_tricked_into_pass",
        "test_p0_07a_verdict_requires_two_route_backed_observations",
    ),
    "WINDOWS_ACL_AND_REPARSE": (
        "test_windows_e_volume_dacl_before_and_during_private_yaml",
        "test_windows_real_junction_is_not_deleted_through",
        "test_unsafe_parent_or_symlink_never_receives_plaintext",
        "test_acl_failure_precedes_plaintext_write",
        "test_reparse_escape_is_never_deleted",
    ),
    "OWN_PID_ONLY": (
        "test_s8_success_own_pid_only_external_untouched",
        "test_s8_after_popen_wrapper_error_still_owns_exact_child",
        "test_terminate_error_falls_back_to_same_child_kill",
        "test_windows_exact_pid_and_external_listening_port_untouched",
        "test_stop_owned_process_stays_within_the_cleanup_budget",
    ),
    "EXTERNAL_PROCESS_UNTOUCHED": (
        "test_s8_success_own_pid_only_external_untouched",
        "test_windows_exact_pid_and_external_listening_port_untouched",
        "test_live_runs_coexist_and_are_never_recovered",
        "test_recovery_never_touches_unverifiable_residue_or_foreign_pids",
    ),
    "CONFIG_FAIL_CLEANUP": (
        "test_s7_config_error_with_embedded_secret_cleanup",
    ),
    "POPEN_FAIL_CLEANUP": (
        "test_s8_popen_failure_still_deletes_yaml",
    ),
    "TIMEOUT_CLEANUP": (
        "test_s8_injected_failures_cleanup[timeout]",
    ),
    "CANCELLATION_CLEANUP": (
        "test_s8_injected_failures_cleanup[cancel]",
    ),
    "PROCESS_CRASH_CLEANUP": (
        "test_s8_injected_failures_cleanup[child_crash]",
        "test_crash_residue_blocks_until_verified_recovery_stops_only_own_orphan",
    ),
    "NORMAL_EXIT_CLEANUP": (
        "test_s8_success_own_pid_only_external_untouched",
        "test_closed_context_cannot_be_reused_to_leave_yaml_behind",
        "test_stop_failure_still_deletes_plaintext_and_reports_cleanup_failure",
        "test_cleanup_failure_is_hard_fail_but_residue_stays_owned",
    ),
}

RESULT_ORDER = (
    "WINDOWS_ENVIRONMENT",
    "NTFS_VOLUME",
    "LOCAL_MAIN_PRESERVED_SHA",
    "RESCUE_REF",
    "RESCUE_SHA",
    "CANDIDATE_SHA",
    "PYTEST",
    "DYNAMIC_SENTINEL_SCAN",
    "PUBLIC_ALLOWLIST_AND_URI_ARGV",
    "WINDOWS_ACL_AND_REPARSE",
    "OWN_PID_ONLY",
    "EXTERNAL_PROCESS_UNTOUCHED",
    "CONFIG_FAIL_CLEANUP",
    "POPEN_FAIL_CLEANUP",
    "TIMEOUT_CLEANUP",
    "CANCELLATION_CLEANUP",
    "PROCESS_CRASH_CLEANUP",
    "NORMAL_EXIT_CLEANUP",
    "REAL_NODE_USED",
    "REAL_SECRET_SENT_TO_MODEL_OR_GIT",
    "GIT_STATUS",
    "BLOCKERS",
    "W1_OVERALL",
)

SENTINEL_PATTERNS = (re.compile(r"FAKE_ONLY_"), re.compile(r"fakeonly[0-9a-f]{8}"))


class Report:
    """Accumulates fixed fields only. Nothing free-form ever reaches stdout."""

    def __init__(self) -> None:
        self.fields: dict[str, str] = {name: "NOT_RUN" for name in RESULT_ORDER}
        self.fields["WINDOWS_ENVIRONMENT"] = "FAIL"
        self.fields["NTFS_VOLUME"] = "UNKNOWN"
        self.fields["LOCAL_MAIN_PRESERVED_SHA"] = "UNKNOWN"
        self.fields["RESCUE_REF"] = "NONE"
        self.fields["RESCUE_SHA"] = "UNKNOWN"
        self.fields["CANDIDATE_SHA"] = "UNKNOWN"
        self.fields["REAL_NODE_USED"] = "NO"
        self.fields["REAL_SECRET_SENT_TO_MODEL_OR_GIT"] = "NO"
        self.fields["GIT_STATUS"] = "UNKNOWN"
        self.fields["W1_OVERALL"] = "BLOCKED"
        self.blockers: list[str] = []

    def block(self, code: str) -> None:
        if code not in self.blockers:
            self.blockers.append(code)

    def emit(self) -> None:
        self.fields["BLOCKERS"] = ", ".join(self.blockers) if self.blockers else "NONE"
        print("")
        print("NL-P0-006_RESULT")
        for name in RESULT_ORDER:
            print(f"{name}: {self.fields[name]}")


def note(message: str) -> None:
    """Operator-facing guidance. Never contains a value read from the machine."""
    print(f"[w1] {message}", flush=True)


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None,
        timeout: int = 600) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, env=env, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return 127, "", ""
    return proc.returncode, proc.stdout, proc.stderr


def git(repo: Path, *args: str, timeout: int = 300) -> tuple[int, str]:
    code, out, _ = run(["git", "-C", str(repo), *args], timeout=timeout)
    return code, out.strip()


# --------------------------------------------------------------------------
# Windows facts
# --------------------------------------------------------------------------

def is_elevated() -> bool | None:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return None


def drive_facts(drive_root: str) -> tuple[int | None, str | None]:
    """(drive type, filesystem name) for e.g. 'E:\\'."""
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        dtype = int(kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive_root)))
        fs_buf = ctypes.create_unicode_buffer(64)
        name_buf = ctypes.create_unicode_buffer(261)
        ok = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive_root), name_buf, ctypes.sizeof(name_buf),
            None, None, None, fs_buf, ctypes.sizeof(fs_buf),
        )
        return dtype, (fs_buf.value if ok else None)
    except Exception:
        return None, None


def is_reparse_point(path: Path) -> bool:
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))  # type: ignore[attr-defined]
    except Exception:
        return False
    if attrs == -1:
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def current_user_sid() -> str | None:
    code, out, _ = run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    ], timeout=60)
    sid = out.strip()
    return sid if code == 0 and sid.startswith("S-1-") else None


_ACL_CHECK = r"""
$ErrorActionPreference = 'Stop'
$target = [Environment]::GetEnvironmentVariable('W1_TARGET', 'Process')
$ownerSid = [Environment]::GetEnvironmentVariable('W1_SID', 'Process')
$acl = Get-Acl -LiteralPath $target
$identity = [System.Security.Principal.SecurityIdentifier]
if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical) { exit 2 }
if ($acl.Owner -ne $ownerSid) {
    $owner = [System.Security.Principal.NTAccount]::new($acl.Owner).Translate($identity).Value
    if ($owner -ne $ownerSid) { exit 2 }
}
$userSeen = $false; $systemSeen = $false
foreach ($ace in $acl.Access) {
    $sid = $ace.IdentityReference.Translate($identity).Value
    if ($ace.IsInherited -or $ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { exit 2 }
    if ($sid -ne $ownerSid -and $sid -ne 'S-1-5-18') { exit 2 }
    $full = [int][System.Security.AccessControl.FileSystemRights]::FullControl
    if (([int]$ace.FileSystemRights -band $full) -ne $full) { exit 2 }
    if ($sid -eq $ownerSid) { $userSeen = $true }
    if ($sid -eq 'S-1-5-18') { $systemSeen = $true }
}
if (-not $userSeen -or -not $systemSeen) { exit 2 }
exit 0
"""


def acl_is_private(path: Path, sid: str) -> bool:
    env = dict(os.environ)
    env["W1_TARGET"] = str(path)
    env["W1_SID"] = sid
    code, _, _ = run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command", _ACL_CHECK,
    ], env=env, timeout=120)
    return code == 0


# --------------------------------------------------------------------------
# Phases
# --------------------------------------------------------------------------

def phase_environment(rep: Report, args: argparse.Namespace, repo: Path) -> bool:
    if sys.version_info < MIN_PYTHON:
        rep.block("BLOCKED_PYTHON_VERSION")
        return False

    if sys.platform != "win32" or os.name != "nt":
        if not args.allow_non_windows:
            rep.block("BLOCKED_WRONG_EXECUTION_ENVIRONMENT")
            return False
        note("self-test mode: Windows-only facts are NOT_RUN and PASS is impossible")
        rep.fields["WINDOWS_ENVIRONMENT"] = "NOT_RUN"
        rep.fields["NTFS_VOLUME"] = "UNKNOWN"
        rep.block("SELFTEST_NON_WINDOWS")
        return True

    # A WSL or container interpreter reports sys.platform == "linux" and was
    # already rejected above; only a real Windows interpreter reaches here.
    elevated = is_elevated()
    if elevated is None:
        rep.block("BLOCKED_ELEVATION_UNKNOWN")
        return False
    if elevated:
        note("this is an ELEVATED PowerShell. New objects would be owned by "
             "BUILTIN\\Administrators and the owner check would report a false "
             "PRIVATE_DIR_UNSAFE. Re-run from a normal, non-elevated shell.")
        rep.block("BLOCKED_ELEVATED_SESSION")
        return False

    drive_root = os.path.splitdrive(str(repo.resolve()))[0] + "\\"
    dtype, fsname = drive_facts(drive_root)
    if dtype is None or fsname is None:
        rep.fields["NTFS_VOLUME"] = "UNKNOWN"
        rep.block("BLOCKED_VOLUME_UNSAFE")
        return False
    if dtype != DRIVE_FIXED or fsname.upper() != "NTFS":
        rep.fields["NTFS_VOLUME"] = "FAIL"
        rep.block("BLOCKED_VOLUME_UNSAFE")
        return False

    rep.fields["NTFS_VOLUME"] = "PASS"
    rep.fields["WINDOWS_ENVIRONMENT"] = "PASS"
    return True


def phase_script_location(rep: Report, repo: Path) -> bool:
    try:
        here = Path(__file__).resolve()
        here.relative_to(repo.resolve())
    except ValueError:
        return True
    except Exception:
        rep.block("BLOCKED_SCRIPT_LOCATION_UNKNOWN")
        return False
    note("this script is inside the repository working tree; checking out the "
         "verify branch could replace it mid-run. Copy it somewhere outside "
         "the repo and re-run.")
    rep.block("BLOCKED_SCRIPT_INSIDE_WORKTREE")
    return False


def phase_git_safety(rep: Report, repo: Path) -> tuple[bool, str | None, str | None]:
    """Returns (ok, original_ref, main_sha)."""
    if not (repo / ".git").exists():
        rep.block("BLOCKED_REPO_NOT_FOUND")
        return False, None, None

    code, status = git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if code != 0:
        rep.block("BLOCKED_REPO_NOT_FOUND")
        return False, None, None
    if status:
        rep.fields["GIT_STATUS"] = "DIRTY"
        note("the working tree is not clean. Commit or stash your own changes "
             "first; this script will not reset, stash or clean anything.")
        rep.block("BLOCKED_DIRTY_WORKTREE")
        return False, None, None
    rep.fields["GIT_STATUS"] = "CLEAN"

    code, original = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
    if code != 0:
        code, original = git(repo, "rev-parse", "HEAD")
        if code != 0:
            rep.block("BLOCKED_REPO_NOT_FOUND")
            return False, None, None

    code, main_sha = git(repo, "rev-parse", "--verify", "--quiet", "main")
    if code != 0 or len(main_sha) != 40:
        rep.block("BLOCKED_NO_LOCAL_MAIN")
        return False, original, None
    rep.fields["LOCAL_MAIN_PRESERVED_SHA"] = main_sha

    rescue = f"rescue/nl-p0-006-main-{main_sha[:7]}"
    code, existing = git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{rescue}")
    if code == 0:
        if existing != main_sha:
            note("a rescue ref with the expected name already exists but points "
                 "at a different commit. Resolve that by hand before retrying.")
            rep.block("BLOCKED_RESCUE_REF_CONFLICT")
            return False, original, main_sha
    else:
        code, _ = git(repo, "branch", rescue, main_sha)
        if code != 0:
            rep.block("BLOCKED_RESCUE_REF_CONFLICT")
            return False, original, main_sha
    rep.fields["RESCUE_REF"] = rescue
    rep.fields["RESCUE_SHA"] = main_sha

    # The historical unprotected commit, if this clone still has it.
    code, _ = git(repo, "cat-file", "-e", f"{LEGACY_RESCUE_SHA}^{{commit}}")
    if code == 0:
        code, _ = git(repo, "merge-base", "--is-ancestor", LEGACY_RESCUE_SHA, main_sha)
        if code != 0:
            legacy = f"rescue/nl-p0-006-{LEGACY_RESCUE_SHA[:7]}"
            code, existing = git(repo, "rev-parse", "--verify", "--quiet",
                                 f"refs/heads/{legacy}")
            if code == 0:
                if existing != LEGACY_RESCUE_SHA:
                    rep.block("BLOCKED_RESCUE_REF_CONFLICT")
                    return False, original, main_sha
            else:
                git(repo, "branch", legacy, LEGACY_RESCUE_SHA)

    return True, original, main_sha


def phase_candidate(rep: Report, repo: Path) -> tuple[bool, str | None]:
    code, _ = git(repo, "fetch", "origin", "--prune")
    if code != 0:
        rep.block("BLOCKED_FETCH_FAILED")
        return False, None

    code, sha = git(repo, "rev-parse", "--verify", "--quiet",
                    f"refs/remotes/origin/{CANDIDATE_BRANCH}")
    if code != 0 or len(sha) != 40:
        rep.block("BLOCKED_CANDIDATE_MISMATCH")
        return False, None
    rep.fields["CANDIDATE_SHA"] = sha

    # Self-consistency: the script that is running must be byte-identical to the
    # one recorded in the candidate commit. This is what pins the candidate.
    code, _, _ = run(["git", "-C", str(repo), "cat-file", "-e",
                      f"{sha}:{SCRIPT_PATH_IN_REPO}"])
    if code != 0:
        rep.block("BLOCKED_CANDIDATE_MISMATCH")
        return False, None
    proc = subprocess.run(["git", "-C", str(repo), "show", f"{sha}:{SCRIPT_PATH_IN_REPO}"],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    recorded = hashlib.sha256(proc.stdout.replace(b"\r\n", b"\n")).hexdigest()
    try:
        local = hashlib.sha256(
            Path(__file__).resolve().read_bytes().replace(b"\r\n", b"\n")
        ).hexdigest()
    except OSError:
        rep.block("BLOCKED_CANDIDATE_MISMATCH")
        return False, None
    if recorded != local:
        note("this script does not match the copy recorded in the candidate "
             "commit. Re-download it from the candidate branch.")
        rep.block("BLOCKED_CANDIDATE_MISMATCH")
        return False, None

    for rel in TEST_FILES:
        code, _, _ = run(["git", "-C", str(repo), "cat-file", "-e", f"{sha}:{rel}"])
        if code != 0:
            rep.block("BLOCKED_CANDIDATE_MISMATCH")
            return False, None

    return True, sha


def phase_verify_branch(rep: Report, repo: Path, sha: str) -> tuple[bool, str | None]:
    name = f"verify/nl-p0-006-{sha[:7]}"
    code, existing = git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{name}")
    if code == 0:
        if existing != sha:
            note("a verify branch with the expected name exists but points "
                 "elsewhere. It will not be reused or overwritten.")
            rep.block("BLOCKED_VERIFY_BRANCH_CONFLICT")
            return False, None
    else:
        code, _ = git(repo, "branch", name, sha)
        if code != 0:
            rep.block("BLOCKED_VERIFY_BRANCH_CONFLICT")
            return False, None
    code, _ = git(repo, "checkout", "--quiet", name)
    if code != 0:
        rep.block("BLOCKED_VERIFY_BRANCH_CONFLICT")
        return False, None
    return True, name


def phase_dependencies(rep: Report, repo: Path) -> bool:
    missing = []
    for mod in REQUIRED_MODULES:
        code, _, _ = run([sys.executable, "-c", f"import {mod}"], timeout=120)
        if code != 0:
            missing.append(mod)
    if missing:
        note("missing Python packages for the interpreter running this script: "
             + ", ".join(missing) + ". Install them yourself with: "
             "py -3 -m pip install PyYAML httpx \"idna>=3.10,<4\" pytest . This "
             "script will not install anything or edit pyproject.toml.")
        rep.block("BLOCKED_DEPENDENCIES")
        return False
    return True


def phase_private_root(rep: Report, args: argparse.Namespace, repo: Path) -> bool:
    """NL-P0-006 section 1a. Never modifies anything."""
    if sys.platform != "win32":
        return True

    secrets_root = Path(os.path.splitdrive(str(repo.resolve()))[0] + "\\NodeLab.secrets")
    runtime = secrets_root / "_runtime"

    if not secrets_root.exists():
        note("private root does not exist yet; the product code will create and "
             "tighten it. Nothing to prepare.")
        return True

    if is_reparse_point(secrets_root):
        rep.block("BLOCKED_PRIVATE_ROOT_ACL")
        return False

    sid = current_user_sid()
    if sid is None:
        rep.block("BLOCKED_PRIVATE_ROOT_ACL")
        return False

    if not acl_is_private(secrets_root, sid):
        note("the existing private root does not satisfy the required DACL "
             "(owner = you, inheritance disabled, only you + SYSTEM with full "
             "control). This script will NOT change permissions. If the "
             "directory holds nothing you care about, you can tighten it "
             "yourself with the two-line icacls snippet in NL-P0-006 1a.3; if "
             "it holds real files, stop and hand this back to the Owner.")
        rep.block("BLOCKED_PRIVATE_ROOT_ACL")
        return False

    if runtime.exists():
        try:
            entries = list(runtime.iterdir())
        except OSError:
            rep.block("BLOCKED_PRIVATE_ROOT_ACL")
            return False
        if entries:
            if not args.recover:
                note("the runtime root is not empty. That is either a concurrent "
                     "live run or crash residue. Nothing was touched. Re-run "
                     "with --recover to let the product's own verified routine "
                     "reclaim it (it only removes directories whose ownership it "
                     "can prove, and only terminates a child whose pid, creation "
                     "time and executable fingerprint all match the marker). "
                     "Do not delete anything by hand and do not use taskkill.")
                rep.block("RECOVERY_REVIEW_REQUIRED")
                return False
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            code, _, _ = run([sys.executable, "-m", "nodelab.cli", "recover", "--confirm"],
                             cwd=repo, env=env, timeout=300)
            if code != 0:
                rep.block("RECOVERY_REVIEW_REQUIRED")
                return False
            note("recovery routine completed.")
    return True


def phase_pytest(rep: Report, repo: Path) -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTEST_ADDOPTS", None)

    with tempfile.TemporaryDirectory(prefix="w1-report-") as tmp:
        xml_path = Path(tmp) / "w1.xml"
        cmd = [
            sys.executable, "-m", "pytest",
            "-p", "no:cacheprovider", "-o", "addopts=",
            "-q", "--tb=no", "-rN",
            f"--junit-xml={xml_path}",
            *TEST_FILES,
        ]
        code, out, err = run(cmd, cwd=repo, env=env, timeout=1800)
        combined = out + err

        leaked = any(p.search(combined) for p in SENTINEL_PATTERNS)

        if not xml_path.exists():
            rep.fields["PYTEST"] = "FAIL"
            rep.block("BLOCKED_PYTEST_DID_NOT_RUN")
            return

        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            rep.fields["PYTEST"] = "FAIL"
            rep.block("BLOCKED_PYTEST_DID_NOT_RUN")
            return

    outcomes: dict[str, str] = {}
    totals = {"passed": 0, "failed": 0, "skipped": 0}
    for case in root.iter("testcase"):
        name = case.get("name") or ""
        status = "passed"
        for child in case:
            tag = child.tag.lower()
            if tag in {"failure", "error"}:
                status = "failed"
                break
            if tag == "skipped":
                status = "skipped"
        outcomes[name] = status
        totals[status] += 1

    rep.fields["PYTEST"] = (
        "PASS" if (code == 0 and totals["failed"] == 0 and totals["passed"] > 0)
        else "FAIL"
    )
    note(f"pytest: {totals['passed']} passed, {totals['failed']} failed, "
         f"{totals['skipped']} skipped (raw output withheld on purpose)")
    if totals["failed"]:
        failed_names = sorted(n for n, s in outcomes.items() if s == "failed")
        note("failed test identifiers (no tracebacks, no values):")
        for name in failed_names:
            note(f"    {name}")
        rep.block("FAILED_ASSERTIONS")

    for field, nodes in FIELD_TESTS.items():
        statuses = [outcomes.get(n) for n in nodes]
        if any(s == "failed" for s in statuses):
            rep.fields[field] = "FAIL"
        elif any(s is None or s == "skipped" for s in statuses):
            rep.fields[field] = "NOT_RUN"
        else:
            rep.fields[field] = "PASS"

    if leaked:
        rep.fields["DYNAMIC_SENTINEL_SCAN"] = "FAIL"
        rep.block("SENTINEL_VISIBLE_IN_TEST_OUTPUT")


def phase_restore(rep: Report, repo: Path, original: str | None, main_sha: str | None,
                  keep_verify: bool) -> None:
    if original and not keep_verify:
        git(repo, "checkout", "--quiet", original)

    code, status = git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if code != 0:
        rep.fields["GIT_STATUS"] = "UNKNOWN"
    elif status:
        rep.fields["GIT_STATUS"] = "DIRTY"
        note("the working tree is dirty after the run. Nothing was cleaned. "
             "Inspect it yourself and report back.")
        rep.block("DIRTY_AFTER_RUN")
    else:
        rep.fields["GIT_STATUS"] = "CLEAN"

    if main_sha:
        code, now = git(repo, "rev-parse", "--verify", "--quiet", "main")
        if code != 0 or now != main_sha:
            rep.block("LOCAL_MAIN_MOVED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--repo", default=r"E:\NodeLab")
    parser.add_argument("--recover", action="store_true")
    parser.add_argument("--keep-verify", action="store_true")
    parser.add_argument("--allow-non-windows", action="store_true")
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    rep = Report()
    repo = Path(args.repo)
    original: str | None = None
    main_sha: str | None = None

    try:
        if not phase_environment(rep, args, repo):
            return finish(rep)
        if not phase_script_location(rep, repo):
            return finish(rep)

        ok, original, main_sha = phase_git_safety(rep, repo)
        if not ok:
            return finish(rep)

        ok, sha = phase_candidate(rep, repo)
        if not ok:
            return finish(rep)
        assert sha is not None

        ok, _branch = phase_verify_branch(rep, repo, sha)
        if not ok:
            return finish(rep)

        if not phase_dependencies(rep, repo):
            phase_restore(rep, repo, original, main_sha, args.keep_verify)
            return finish(rep)

        if not phase_private_root(rep, args, repo):
            phase_restore(rep, repo, original, main_sha, args.keep_verify)
            return finish(rep)

        phase_pytest(rep, repo)
        phase_restore(rep, repo, original, main_sha, args.keep_verify)
        return finish(rep)
    except KeyboardInterrupt:
        rep.block("BLOCKED_INTERRUPTED")
        try:
            phase_restore(rep, repo, original, main_sha, args.keep_verify)
        except Exception:
            pass
        return finish(rep)
    except Exception:
        # Never surface the exception text: it can carry paths.
        rep.block("BLOCKED_RUNNER_INTERNAL_ERROR")
        try:
            phase_restore(rep, repo, original, main_sha, args.keep_verify)
        except Exception:
            pass
        return finish(rep)


def finish(rep: Report) -> int:
    windows_ok = rep.fields["WINDOWS_ENVIRONMENT"] == "PASS"
    ntfs_ok = rep.fields["NTFS_VOLUME"] == "PASS"
    gated = [f for f in FIELD_TESTS if rep.fields[f] == "PASS"]
    all_gates = len(gated) == len(FIELD_TESTS)

    if rep.blockers and rep.fields["PYTEST"] != "FAIL":
        rep.fields["W1_OVERALL"] = "BLOCKED"
    elif rep.fields["PYTEST"] == "FAIL" or not all_gates:
        rep.fields["W1_OVERALL"] = "FAIL"
    elif windows_ok and ntfs_ok and rep.fields["GIT_STATUS"] == "CLEAN" and not rep.blockers:
        rep.fields["W1_OVERALL"] = "PASS"
    else:
        rep.fields["W1_OVERALL"] = "BLOCKED"

    rep.emit()
    print("")
    note("copy the block above back to the Technical Owner verbatim. "
         "It contains no paths, no secrets and no sentinels.")
    return 0 if rep.fields["W1_OVERALL"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
