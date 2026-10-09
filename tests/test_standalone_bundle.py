"""Bounded build-contract tests; fake compilers are never Windows evidence."""
from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import types
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_SENTINEL = "FICTIONAL_PRIVATE_BUILD_SENTINEL"


@pytest.fixture
def builder():
    spec = importlib.util.spec_from_file_location(
        "standalone_builder_test", ROOT / "scripts/build_standalone_bundle.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _allow_build_preflight(monkeypatch, builder):
    monkeypatch.setattr(builder, "_target", lambda: "Linux")
    monkeypatch.setattr(builder, "_check_venv", lambda: None)
    monkeypatch.setattr(
        builder, "_check_dependencies", lambda target: {"PyInstaller": "6.22.3", "idna": "3.20"}
    )


def _assert_no_completed_build(folder):
    assert not list(folder.rglob("NodeLab_Offline_Windows_x64.zip"))
    assert not list(folder.rglob("NodeLab_Offline_LinuxValidation.zip"))
    assert not list(folder.rglob("NodeLab_Offline_Windows_x64.zip.sha256"))
    assert not list(folder.rglob("NodeLab_Offline_LinuxValidation.zip.sha256"))
    assert not list(folder.rglob("MANIFEST.json"))


def test_build_error_does_not_echo_untrusted_text(builder):
    error = builder.StandaloneBuildError(PRIVATE_SENTINEL)
    assert PRIVATE_SENTINEL not in str(error)
    assert PRIVATE_SENTINEL not in error.code


@pytest.mark.parametrize("failing_step", ["_target", "_check_venv", "_check_dependencies"])
def test_preflight_failure_does_not_publish_or_enter_compiler(
    tmp_path, monkeypatch, builder, failing_step
):
    _allow_build_preflight(monkeypatch, builder)
    reached = []

    def fail(*args):
        raise ValueError(PRIVATE_SENTINEL)

    monkeypatch.setattr(builder, failing_step, fail)
    monkeypatch.setattr(builder, "_compile", lambda *args: reached.append(args))
    output = tmp_path / "output"
    output.mkdir()
    untouched = output / "caller-owned.txt"
    untouched.write_text("CALLER_OWNED", encoding="utf-8")
    with pytest.raises(builder.StandaloneBuildError) as caught:
        builder.build_standalone(output)
    assert PRIVATE_SENTINEL not in str(caught.value)
    assert reached == []
    _assert_no_completed_build(output)
    assert untouched.read_text(encoding="utf-8") == "CALLER_OWNED"


def test_compile_failure_has_no_completed_archive_or_private_diagnostic(
    tmp_path, monkeypatch, builder
):
    _allow_build_preflight(monkeypatch, builder)

    def fail(stage, work, target):
        assert target == "Linux"
        raise RuntimeError(PRIVATE_SENTINEL)

    monkeypatch.setattr(builder, "_compile", fail)
    output = tmp_path / "output"
    with pytest.raises(builder.StandaloneBuildError) as caught:
        builder.build_standalone(output)
    assert PRIVATE_SENTINEL not in str(caught.value)
    _assert_no_completed_build(output)


def test_staging_excludes_unrelated_project_modules_and_real_input(
    tmp_path, monkeypatch, builder
):
    # Add unrelated files to a copy of the checkout; only allowlisted sources
    # may enter the staged import tree.
    # The test exercises the real staging function, not a fake dependency scan.
    import shutil

    repository = tmp_path / "fictional-checkout"
    shutil.copytree(ROOT, repository, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    (repository / "test_nodes.txt").write_text(PRIVATE_SENTINEL, encoding="utf-8")
    (repository / "src/nodelab/owner_secret.py").write_text(PRIVATE_SENTINEL, encoding="utf-8")
    monkeypatch.setattr(builder, "ROOT", repository)
    work = tmp_path / "work"
    work.mkdir()
    stage, source_manifest = builder._stage_source(work)
    package = stage / "nodelab"
    assert {path.name for path in package.glob("*.py")} == {
        "__init__.py", "types.py", "parser.py", "inventory.py", "subscription_input.py",
        "offline_file.py", "offline_report.py",
    }
    assert not list(stage.rglob("test_nodes.txt"))
    assert not list(stage.rglob("owner_secret.py"))
    assert isinstance(source_manifest, dict)
    for path in stage.rglob("*"):
        if path.is_file():
            assert PRIVATE_SENTINEL.encode("ascii") not in path.read_bytes()
    entry_files = list(stage.glob("nodelab_standalone.py"))
    assert len(entry_files) == 1
    assert not list(stage.glob("nodelab_offline.pyw"))


@pytest.mark.parametrize(
    ("system", "machine", "wordsize", "python_version", "code"),
    [
        ("Darwin", "x86_64", 8, "3.12.14", "BUILD_PLATFORM"),
        ("Linux", "aarch64", 8, "3.12.14", "BUILD_PLATFORM"),
        ("Windows", "AMD64", 4, "3.12.14", "BUILD_PLATFORM"),
        ("Windows", "AMD64", 8, "3.12.13", "BUILD_RUNTIME"),
    ],
)
def test_target_rejects_unsupported_native_build_profile(
    monkeypatch, builder, system, machine, wordsize, python_version, code
):
    monkeypatch.setattr(builder.platform, "system", lambda: system)
    monkeypatch.setattr(builder.platform, "machine", lambda: machine)
    monkeypatch.setattr(builder.platform, "python_version", lambda: python_version)
    monkeypatch.setattr(builder.struct, "calcsize", lambda format: wordsize)
    with pytest.raises(builder.StandaloneBuildError) as caught:
        builder._target()
    assert caught.value.code == code


@pytest.mark.parametrize("dependency", ["pyinstaller", "idna", "pyinstaller-hooks-contrib", "pefile"])
def test_dependency_version_mismatch_is_rejected_before_compilation(
    monkeypatch, builder, dependency
):
    pins = builder.PINS | builder.WINDOWS_PINS
    monkeypatch.setattr(
        builder.importlib.metadata, "version",
        lambda name: "0.0.0" if name == dependency else pins[name],
    )
    with pytest.raises(builder.StandaloneBuildError) as caught:
        builder._check_dependencies("Windows")
    assert caught.value.code == "BUILD_DEPENDENCY_VERSION"


@pytest.mark.parametrize("fault", ["base_python", "not_isolated", "system_site"])
def test_build_environment_requires_isolated_venv_without_system_site(
    tmp_path, monkeypatch, builder, fault
):
    virtualenv = tmp_path / "venv"
    virtualenv.mkdir()
    (virtualenv / "pyvenv.cfg").write_text(
        "include-system-site-packages = " + ("true" if fault == "system_site" else "false") + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        builder, "sys", types.SimpleNamespace(
            prefix=str(virtualenv),
            base_prefix=str(virtualenv) if fault == "base_python" else str(tmp_path / "base-python"),
            flags=types.SimpleNamespace(isolated=fault != "not_isolated"),
        ),
    )
    with pytest.raises(builder.StandaloneBuildError) as caught:
        builder._check_venv()
    assert caught.value.code == "BUILD_ENVIRONMENT"


def _frozen_outputs(target="Linux"):
    return {
        "--self-check": {"self_check": "PASS", "mode": "FICTIONAL_ONLY", "network_used": False},
        "--acceptance-check": {
            "acceptance_check": "PASS", "mode": "FICTIONAL_ONLY", "network_used": False,
            "engine_started": False, "frozen": True,
            "ignore_environment": True,
            "input_formats_checked": ["uri_lines", "base64"], "report_round_trips": 3,
            "report_schema_version": 2, "records": 3, "parsed": 2, "invalid": 1,
            "input_unchanged": True, "reports_unchanged": True,
            "markdown_mismatch": "REJECTED", "private_text": "ABSENT",
            "audit_negative_controls": {
                "socket_create": "BLOCKED", "dns": "BLOCKED", "child_process": "BLOCKED",
            },
            "tcl_runtime": "PASS",
            "gui_runtime": "WINDOWS_HIDDEN_WINDOW_PASS" if target == "Windows" else "NOT_CHECKED_NO_DISPLAY",
            "tcl_patchlevel": "8.6.15" if target == "Windows" else "9.0.4",
            "tk_patchlevel": "8.6.15" if target == "Windows" else None,
        },
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("frozen", False), ("ignore_environment", False), ("report_round_trips", True), ("records", 3.0),
        ("network_used", 0), ("engine_started", 0), ("input_unchanged", 1),
        ("reports_unchanged", False), ("report_schema_version", True),
        ("input_formats_checked", ["uri_lines"]), ("owner_private_text", PRIVATE_SENTINEL),
    ],
)
def test_frozen_acceptance_rejects_false_proof_types_missing_scope_and_extra_text(
    tmp_path, monkeypatch, builder, field, value
):
    outputs = _frozen_outputs()
    outputs["--acceptance-check"][field] = value

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(outputs[command[-1]]), stderr="")

    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    with pytest.raises(builder.StandaloneBuildError) as caught:
        builder._verify_frozen(tmp_path / "fictional-executable", tmp_path, "Linux")
    assert caught.value.code == "BUILD_ACCEPTANCE"
    assert PRIVATE_SENTINEL not in str(caught.value)


@pytest.mark.parametrize("fault", ["exit_failure", "stderr", "malformed_json", "timeout"])
def test_failed_frozen_process_is_not_a_success(
    tmp_path, monkeypatch, builder, fault
):
    def fake_run(command, **kwargs):
        if fault == "timeout":
            raise subprocess.TimeoutExpired(command, 45, output=PRIVATE_SENTINEL)
        return subprocess.CompletedProcess(
            command, 2 if fault == "exit_failure" else 0,
            stdout="[" if fault == "malformed_json" else json.dumps(_frozen_outputs()[command[-1]]),
            stderr=PRIVATE_SENTINEL if fault == "stderr" else "",
        )

    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    # Public build maps JSON/timeout failures to a fixed diagnostic. The
    # internal check may raise their native exceptions; it must never return.
    with pytest.raises((builder.StandaloneBuildError, json.JSONDecodeError, subprocess.TimeoutExpired)):
        builder._verify_frozen(tmp_path / "fictional-executable", tmp_path, "Linux")


def test_runtime_checks_use_empty_cwd_without_python_path_or_tcl_environment(
    tmp_path, monkeypatch, builder
):
    for name in ("PYTHONPATH", "PYTHONHOME", "TCL_LIBRARY", "TK_LIBRARY", "TCLLIBPATH", "TKPATH", "LD_LIBRARY_PATH", "LD_PRELOAD"):
        monkeypatch.setenv(name, PRIVATE_SENTINEL)
    calls = []

    def fake_run(command, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(_frozen_outputs()[command[-1]]), stderr="")

    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    builder._verify_frozen(tmp_path / "fictional-executable", tmp_path, "Linux")
    assert len(calls) == 2
    for call in calls:
        assert list(call["cwd"].iterdir()) == []
        assert call["env"]["PATH"] == ""
        assert all(PRIVATE_SENTINEL != value for value in call["env"].values())


def _fake_external_build(monkeypatch, builder, *, target="Linux", fault=None):
    """Only unit-test publication orchestration, never platform acceptance."""
    _allow_build_preflight(monkeypatch, builder)
    monkeypatch.setattr(builder, "_target", lambda: target)
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    compiled = {}

    def compile(stage, work, actual_target):
        compiled["stage"] = stage
        executable = work / "dist/NodeLab_Offline" / (
            "NodeLab_Offline.exe" if actual_target == "Windows" else "NodeLab_Offline"
        )
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"FICTIONAL_COMPILER_OUTPUT_NOT_AN_ACTUAL_EXECUTABLE")
        return executable

    def copy_licenses(app, *args, **kwargs):
        if fault == "license":
            raise builder.StandaloneBuildError("BUILD_LICENSE")
        (app / "licenses").mkdir()
        (app / "licenses/fixture-LICENSE.txt").write_bytes(b"FICTIONAL_LICENSE_FIXTURE")
        return {"fixture_only": True}

    def run(command, **kwargs):
        assert not compiled["stage"].exists(), "staged sources still present at frozen check"
        result = _frozen_outputs(target)[command[-1]]
        if fault == "acceptance" and command[-1] == "--acceptance-check":
            result["frozen"] = False
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(result), stderr="")

    monkeypatch.setattr(builder, "_compile", compile)
    monkeypatch.setattr(builder, "_inspect_archive", lambda executable: sorted(builder.OFFLINE_MODULES))
    monkeypatch.setattr(builder, "_copy_licenses", copy_licenses)
    monkeypatch.setattr(builder.subprocess, "run", run)


@pytest.mark.parametrize("fault", ["license", "acceptance"])
def test_mock_build_with_missing_license_or_failed_acceptance_does_not_publish(
    tmp_path, monkeypatch, builder, fault
):
    _fake_external_build(monkeypatch, builder, fault=fault)
    output = tmp_path / "output"
    with pytest.raises(builder.StandaloneBuildError):
        builder.build_standalone(output)
    _assert_no_completed_build(output)


@pytest.mark.parametrize("target", ["Linux", "Windows"])
def test_mock_build_manifest_distinguishes_native_profile_from_desktop_acceptance(
    tmp_path, monkeypatch, builder, target
):
    _fake_external_build(monkeypatch, builder, target=target)
    artifact = builder.build_standalone(tmp_path / "output")
    prefix = "NodeLab_Offline_Windows_x64/" if target == "Windows" else "NodeLab_Offline_LinuxValidation/"
    with zipfile.ZipFile(artifact) as archive:
        assert all(name.startswith(prefix) for name in archive.namelist())
        manifest = json.loads(archive.read(prefix + "MANIFEST.json"))
        assert manifest["platform"] == target
        assert manifest["architecture"] == "x64"
        assert manifest["validation_only"] is (target != "Windows")
        assert manifest["windows_desktop_user_acceptance"] is False
        assert manifest["python_required_on_user_machine"] is False
        assert manifest["standalone_executable"] is True
        assert manifest["input_included"] is False
        assert manifest["code_commit"] == "UNVERIFIED_LOCAL"
        assert set(manifest["offline_modules"]) == builder.OFFLINE_MODULES
        assert set(archive.namelist()) == {prefix + name for name in manifest["sha256"]} | {prefix + "MANIFEST.json"}
        for name, digest in manifest["sha256"].items():
            assert hashlib.sha256(archive.read(prefix + name)).hexdigest() == digest
    sidecar = artifact.with_suffix(".zip.sha256").read_text(encoding="ascii")
    assert sidecar.split() == [hashlib.sha256(artifact.read_bytes()).hexdigest(), artifact.name]


def test_publication_hash_failure_does_not_leave_a_completed_zip(
    tmp_path, monkeypatch, builder
):
    _fake_external_build(monkeypatch, builder)
    original = Path.write_text

    def fail_sidecar(path, *args, **kwargs):
        if path.name == "NodeLab_Offline_LinuxValidation.zip.sha256":
            # Disk-full style writes can create a short file before raising.
            original(path, "PARTIAL_HASH\n", encoding="ascii")
            raise OSError(PRIVATE_SENTINEL)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_sidecar)
    output = tmp_path / "output"
    with pytest.raises(builder.StandaloneBuildError) as caught:
        builder.build_standalone(output)
    assert PRIVATE_SENTINEL not in str(caught.value)
    _assert_no_completed_build(output)


def test_archive_publish_failure_removes_its_prepared_hash(
    tmp_path, monkeypatch, builder
):
    _fake_external_build(monkeypatch, builder)
    original = builder.os.replace

    def fail_publish(source, destination):
        if Path(destination).name == "NodeLab_Offline_LinuxValidation.zip":
            raise OSError(PRIVATE_SENTINEL)
        return original(source, destination)

    monkeypatch.setattr(builder.os, "replace", fail_publish)
    output = tmp_path / "output"
    with pytest.raises(builder.StandaloneBuildError) as caught:
        builder.build_standalone(output)
    assert PRIVATE_SENTINEL not in str(caught.value)
    _assert_no_completed_build(output)
