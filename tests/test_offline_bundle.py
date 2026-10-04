from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_extracted_bundle_is_complete_and_runs_without_site_packages(tmp_path):
    spec = importlib.util.spec_from_file_location("bundle_builder", ROOT / "scripts/build_offline_bundle.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    archive_path = builder.build_bundle(tmp_path / "build")
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        assert all(name.startswith("NodeLab_Offline_V1/") and ".." not in name.split("/") for name in names)
        archive.extractall(tmp_path / "unpacked")
    folder = tmp_path / "unpacked/NodeLab_Offline_V1"
    manifest = json.loads((folder / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["dependency"]["version"] == "3.20"
    assert manifest["input_included"] is False
    assert manifest["standalone_executable"] is False
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()}
    assert actual == set(manifest["sha256"]) | {"MANIFEST.json"}
    assert set(p.name for p in (folder / "nodelab").glob("*.py")) == {
        "__init__.py", "types.py", "parser.py", "inventory.py", "offline_file.py"
    }
    for name, expected in manifest["sha256"].items():
        assert hashlib.sha256((folder / name).read_bytes()).hexdigest() == expected
    assert (folder / "LICENSE-idna.txt").stat().st_size > 100
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONUTF8"] = "1"
    process = subprocess.run(
        [sys.executable, "-S", str(folder / "nodelab_offline.pyw"), "--self-check"],
        cwd=tmp_path, env=environment, text=True, capture_output=True, timeout=20,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["self_check"] == "PASS"
    assert process.stderr == ""
    assert archive_path.with_suffix(".zip.sha256").read_text(encoding="ascii").split()[0] == hashlib.sha256(archive_path.read_bytes()).hexdigest()

