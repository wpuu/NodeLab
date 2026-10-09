"""Build a native onedir candidate from only the offline source allowlist."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINS = {"pyinstaller": "6.22.3", "pyinstaller-hooks-contrib": "2026.8", "idna": "3.20",
        "altgraph": "0.17.5", "packaging": "26.3", "setuptools": "84.0.0"}
WINDOWS_PINS = {"pefile": "2024.8.26", "pywin32-ctypes": "0.2.3"}
PYTHON_PROFILES = {"Windows": "3.13.16", "Linux": "3.12.14"}
OFFLINE_MODULES = frozenset({"nodelab", "nodelab.types", "nodelab.parser", "nodelab.inventory",
                            "nodelab.subscription_input", "nodelab.offline_file", "nodelab.offline_report"})
EXCLUDES = ("nodelab.cli", "nodelab.probe", "nodelab.redaction", "nodelab.mihomo_config",
            "nodelab.mihomo_process", "nodelab.engine_binary", "nodelab.engine_config",
            "nodelab.engine_launch", "httpx", "yaml")
_CODES = frozenset({"BUILD_PLATFORM", "BUILD_RUNTIME", "BUILD_ENVIRONMENT", "BUILD_DEPENDENCY_VERSION",
                    "BUILD_SOURCE", "BUILD_LICENSE", "BUILD_COMPILE", "BUILD_ARCHIVE", "BUILD_ACCEPTANCE", "BUILD_OUTPUT"})


class StandaloneBuildError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else "BUILD_OUTPUT"
        super().__init__(self.code)


def _target() -> str:
    target = platform.system()
    if target not in {"Windows", "Linux"} or platform.machine().lower() not in {"amd64", "x86_64"} or struct.calcsize("P") != 8:
        raise StandaloneBuildError("BUILD_PLATFORM")
    if platform.python_version() != PYTHON_PROFILES[target]:
        raise StandaloneBuildError("BUILD_RUNTIME")
    return target


def _check_venv() -> None:
    if sys.prefix == sys.base_prefix or not sys.flags.isolated:
        raise StandaloneBuildError("BUILD_ENVIRONMENT")
    text = (Path(sys.prefix) / "pyvenv.cfg").read_text(encoding="utf-8").lower()
    if not re.search(r"^include-system-site-packages\s*=\s*false\s*$", text, re.M):
        raise StandaloneBuildError("BUILD_ENVIRONMENT")
    if any(value for key, value in os.environ.items() if key.startswith(("TCL", "TK", "LD_", "DYLD_"))):
        raise StandaloneBuildError("BUILD_ENVIRONMENT")


def _check_dependencies(target: str) -> dict:
    pins = PINS | (WINDOWS_PINS if target == "Windows" else {})
    for name, expected in pins.items():
        if importlib.metadata.version(name) != expected:
            raise StandaloneBuildError("BUILD_DEPENDENCY_VERSION")
    return dict(pins)


def _stage_source(work: Path) -> tuple[Path, dict]:
    spec = importlib.util.spec_from_file_location("offline_bundle_builder", ROOT / "scripts/build_offline_bundle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    archive_path = module.build_bundle(work / "source-bundle")
    stage = work / "stage"
    stage.mkdir()
    with zipfile.ZipFile(archive_path) as archive:
        prefix = "NodeLab_Offline_V1/"
        manifest = json.loads(archive.read(prefix + "MANIFEST.json"))
        if set(archive.namelist()) != {prefix + path for path in manifest["sha256"]} | {prefix + "MANIFEST.json"}:
            raise StandaloneBuildError("BUILD_SOURCE")
        modules = set()
        for name, digest in manifest["sha256"].items():
            path = Path(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
                raise StandaloneBuildError("BUILD_SOURCE")
            data = archive.read(prefix + name)
            if hashlib.sha256(data).hexdigest() != digest:
                raise StandaloneBuildError("BUILD_SOURCE")
            if name.startswith("nodelab/"):
                if path.suffix != ".py" or len(path.parts) != 2:
                    raise StandaloneBuildError("BUILD_SOURCE")
                modules.add("nodelab" if path.stem == "__init__" else "nodelab." + path.stem)
            if name.startswith(("nodelab/", "idna/")) or name == "nodelab_offline.pyw":
                destination = stage / ("nodelab_standalone.py" if name == "nodelab_offline.pyw" else name)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
        if modules != OFFLINE_MODULES or not (stage / "idna/__init__.py").is_file() or not (stage / "nodelab_standalone.py").is_file():
            raise StandaloneBuildError("BUILD_SOURCE")
    return stage, manifest


def _build_env(work: Path, *, runtime=False) -> dict:
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(("PYTHON", "PYI_", "_PYI_", "TCL", "TK", "LD_", "DYLD_"))}
    environment["PYINSTALLER_CONFIG_DIR"] = str(work / "pyinstaller-cache")
    if runtime:
        environment["PATH"] = ""
    return environment


def _compile(stage: Path, work: Path, target: str) -> Path:
    command = [sys.executable, "-I", "-m", "PyInstaller", "--onedir", "--console", "--noupx", "--clean",
               "--noconfirm", "--log-level", "WARN", "--name", "NodeLab_Offline",
               "--paths", str(stage), "--distpath", str(work / "dist"),
               "--workpath", str(work / "compile"), "--specpath", str(work / "spec")]
    if target == "Windows":
        command.extend(["--hide-console", "hide-late"])
    else:
        # This validation runtime keeps Tcl9 libraries in Python's prefix,
        # outside the ELF dependency search used by PyInstaller. Collect these
        # exact native libraries; never compensate with an ambient LD path.
        for name in ("libtcl9.0.so", "libtcl9tk9.0.so"):
            library = Path(sys.base_prefix) / "lib" / name
            if not library.is_file():
                raise StandaloneBuildError("BUILD_RUNTIME")
            command.extend(["--add-binary", str(library) + ":."])
    for name in EXCLUDES:
        command.extend(["--exclude-module", name])
    command.append(str(stage / "nodelab_standalone.py"))
    result = subprocess.run(command, cwd=stage, env=_build_env(work), capture_output=True, timeout=300)
    (work / "compile.stdout").write_bytes(result.stdout)
    (work / "compile.stderr").write_bytes(result.stderr)
    if result.returncode != 0:
        raise StandaloneBuildError("BUILD_COMPILE")
    executable = work / "dist/NodeLab_Offline" / ("NodeLab_Offline.exe" if target == "Windows" else "NodeLab_Offline")
    if not executable.is_file() or executable.is_symlink():
        raise StandaloneBuildError("BUILD_COMPILE")
    return executable


def _inspect_archive(executable: Path) -> list[str]:
    from PyInstaller.archive.readers import CArchiveReader
    reader = CArchiveReader(str(executable))
    pyz_names = [name for name in reader.toc if name.endswith(".pyz")]
    if len(pyz_names) != 1:
        raise StandaloneBuildError("BUILD_ARCHIVE")
    names = sorted(reader.open_embedded_archive(pyz_names[0]).toc)
    actual = {name for name in names if name == "nodelab" or name.startswith("nodelab.")}
    if actual != OFFLINE_MODULES or any(name == prefix or name.startswith(prefix + ".") for name in names for prefix in EXCLUDES):
        raise StandaloneBuildError("BUILD_ARCHIVE")
    return names


def _copy_licenses(app: Path) -> dict:
    license_dir = app / "licenses"
    license_dir.mkdir()
    python_license = next((p for p in (Path(sys.base_prefix) / "LICENSE.txt",
                           Path(sys.base_prefix) / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/LICENSE.txt") if p.is_file()), None)
    if python_license is None:
        raise StandaloneBuildError("BUILD_LICENSE")
    shutil.copyfile(python_license, license_dir / "Python-LICENSE.txt")
    for name in ("idna", "pyinstaller-hooks-contrib"):
        distribution = importlib.metadata.distribution(name)
        files = [item for item in distribution.files or [] if item.name.lower() in {"license", "license.txt", "license.md"}]
        if not files:
            raise StandaloneBuildError("BUILD_LICENSE")
        for index, item in enumerate(files):
            shutil.copyfile(distribution.locate_file(item), license_dir / f"{name}-{index}-LICENSE.txt")
    import tkinter
    version = tkinter.Tcl().eval("info patchlevel")
    if version not in {"8.6.15", "9.0.4"}:
        raise StandaloneBuildError("BUILD_LICENSE")
    for name in ("tcl", "tk"):
        shutil.copyfile(ROOT / "docs/licenses" / f"{name}-{version}-license.terms", license_dir / f"{name}-LICENSE.txt")
    for name in ("PYINSTALLER_COPYING.txt", "PYINSTALLER_BOOTLOADER_ZLIB_LICENSE.txt"):
        shutil.copyfile(ROOT / "docs/licenses" / name, license_dir / name)
    licenses = {"python": platform.python_version(), "tcl_license_source_version": version,
                "tk_license_source_version": version, "runtime_hooks_license": "Apache-2.0"}
    if platform.system() == "Windows":
        # The pinned CPython Windows runtime's actual DLL versions were read
        # from its PE metadata. Preserve these runtime notices separately from
        # PyInstaller's own Apache/zlib texts; full native review is still pending.
        for name in ("OPENSSL_3.5.9_LICENSE.txt", "OPENSSL_3.5.9_ATTRIBUTION.txt", "ZLIB_1.3.1_LICENSE.txt"):
            shutil.copyfile(ROOT / "docs/licenses" / name, license_dir / name)
        licenses.update(openssl_license_source_version="3.5.9", zlib_license_source_version="1.3.1")
    return licenses


def _verify_frozen(executable: Path, work: Path, target: str) -> dict:
    empty = work / "runtime-cwd"
    empty.mkdir()
    checks = {}
    for argument, key in (("--self-check", "self_check"), ("--acceptance-check", "acceptance_check")):
        result = subprocess.run([str(executable), argument], cwd=empty, env=_build_env(work, runtime=True),
                                capture_output=True, text=True, encoding="utf-8", timeout=45)
        if result.returncode != 0 or result.stderr:
            raise StandaloneBuildError("BUILD_ACCEPTANCE")
        value = json.loads(result.stdout)
        if type(value) is not dict or value.get(key) != "PASS" or value.get("mode") != "FICTIONAL_ONLY" or value.get("network_used") is not False:
            raise StandaloneBuildError("BUILD_ACCEPTANCE")
        checks[key] = value
    if checks["self_check"] != {"self_check": "PASS", "mode": "FICTIONAL_ONLY", "network_used": False} or set(checks["self_check"]) != {"self_check", "mode", "network_used"}:
        raise StandaloneBuildError("BUILD_ACCEPTANCE")
    value = checks["acceptance_check"]
    expected = {"acceptance_check": "PASS", "mode": "FICTIONAL_ONLY", "network_used": False,
                "frozen": True, "ignore_environment": True, "engine_started": False, "report_round_trips": 3,
                "records": 3, "parsed": 2, "invalid": 1, "input_unchanged": True, "reports_unchanged": True,
                "markdown_mismatch": "REJECTED", "private_text": "ABSENT", "tcl_runtime": "PASS",
                "input_formats_checked": ["uri_lines", "base64"], "report_schema_version": 2,
                "tcl_patchlevel": "8.6.15" if target == "Windows" else "9.0.4",
                "tk_patchlevel": "8.6.15" if target == "Windows" else None,
                "gui_runtime": "WINDOWS_HIDDEN_WINDOW_PASS" if target == "Windows" else "NOT_CHECKED_NO_DISPLAY",
                "audit_negative_controls": {"socket_create": "BLOCKED", "dns": "BLOCKED", "child_process": "BLOCKED"}}
    if set(value) != set(expected) or any(type(value.get(key)) is not type(item) or value[key] != item for key, item in expected.items()):
        raise StandaloneBuildError("BUILD_ACCEPTANCE")
    return checks


def build_standalone(output_dir: Path) -> Path:
    """Native builds only; Linux output is explicitly validation-only."""
    try:
        target = _target()
        _check_venv()
        dependencies = _check_dependencies(target)
        output_dir = output_dir.absolute()
        output_dir.mkdir(parents=True, exist_ok=True)
        work = output_dir / ("build-" + uuid.uuid4().hex)
        work.mkdir()
        stage, source = _stage_source(work)
        executable = _compile(stage, work, target)
        _inspect_archive(executable)
        licenses = _copy_licenses(executable.parent)
        # Prove the frozen program can run after its staged Python sources vanish.
        shutil.rmtree(stage)
        checks = _verify_frozen(executable, work, target)
        app = executable.parent
        shutil.copyfile(ROOT / "docs/NodeLab_Standalone_Readme.txt", app / "README.txt")
        payload = {}
        for file in sorted(app.rglob("*")):
            if file.is_file():
                if file.is_symlink() and not file.resolve().is_relative_to(app.resolve()):
                    raise StandaloneBuildError("BUILD_OUTPUT")
                payload[file.relative_to(app).as_posix()] = file.read_bytes()
        sha = os.environ.get("GITHUB_SHA", "")
        manifest = {"schema_version": 1, "status": "COMPLETE", "mode": "frozen_offline",
                    "platform": target, "architecture": "x64", "python_build_version": platform.python_version(),
                    "python_required_on_user_machine": False, "standalone_executable": True,
                    "validation_only": target != "Windows", "windows_desktop_user_acceptance": False,
                    "release_ready": False, "native_dependency_license_review": "PENDING",
                    "code_commit": sha if re.fullmatch(r"[0-9a-f]{40}", sha) else "UNVERIFIED_LOCAL",
                    "dependencies": dependencies, "licenses": licenses, "input_included": False,
                    "builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "source_sha256": source["sha256"], "offline_modules": sorted(OFFLINE_MODULES),
                    "checks": checks, "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in payload.items()}}
        payload["MANIFEST.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
        name = "NodeLab_Offline_Windows_x64" if target == "Windows" else "NodeLab_Offline_LinuxValidation"
        temporary = work / ".bundle.tmp"
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path, data in payload.items():
                info = zipfile.ZipInfo(name + "/" + path, date_time=(2026, 10, 9, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100755 if path == executable.name else 0o100644) << 16
                archive.writestr(info, data)
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                raise StandaloneBuildError("BUILD_OUTPUT")
        destination = work / (name + ".zip")
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
        hash_path = destination.with_suffix(".zip.sha256")
        # Prepare the hash before publishing the completed archive. A failed
        # write must not leave a completed ZIP while returning a failure.
        try:
            hash_path.write_text(digest + "  " + destination.name + "\n", encoding="ascii")
            os.replace(temporary, destination)
        except Exception:
            hash_path.unlink(missing_ok=True)
            raise
        return destination
    except StandaloneBuildError:
        raise
    except importlib.metadata.PackageNotFoundError:
        raise StandaloneBuildError("BUILD_DEPENDENCY_VERSION") from None
    except subprocess.TimeoutExpired:
        raise StandaloneBuildError("BUILD_ACCEPTANCE") from None
    except Exception:
        raise StandaloneBuildError("BUILD_OUTPUT") from None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build a native offline candidate; no owner input is included.")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_standalone(args.output_dir)
    except StandaloneBuildError as exc:
        print(exc.code, file=sys.stderr)
        raise SystemExit(2)
    print("STANDALONE_BUILT: " + result.name)
    print("BUILD_RESULT_DIRECTORY: " + result.parent.name)
