"""Build the small Python/Tk entry bundle from an explicit source allowlist."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDNA_VERSION = "3.20"
SOURCE_FILES = {
    "scripts/NodeLab_Offline.cmd": "NodeLab_Offline.cmd",
    "scripts/nodelab_offline.pyw": "nodelab_offline.pyw",
    "docs/NodeLab_Offline_Readme.txt": "README.txt",
    "src/nodelab/__init__.py": "nodelab/__init__.py",
    "src/nodelab/types.py": "nodelab/types.py",
    "src/nodelab/parser.py": "nodelab/parser.py",
    "src/nodelab/inventory.py": "nodelab/inventory.py",
    "src/nodelab/offline_file.py": "nodelab/offline_file.py",
}


def build_bundle(output_dir: Path) -> Path:
    distribution = importlib.metadata.distribution("idna")
    if distribution.version != IDNA_VERSION:
        raise ValueError("BUILD_DEPENDENCY_VERSION")
    payload = {target: (ROOT / source).read_bytes() for source, target in SOURCE_FILES.items()}
    license_found = False
    for item in distribution.files or []:
        parts = item.parts
        if parts and parts[0] == "idna" and item.suffix in {".py", ".typed"}:
            payload[item.as_posix()] = distribution.locate_file(item).read_bytes()
        if item.name.lower() in {"license", "license.md", "license.txt"}:
            payload["LICENSE-idna.txt"] = distribution.locate_file(item).read_bytes()
            license_found = True
    if "idna/__init__.py" not in payload or not license_found:
        raise ValueError("BUILD_DEPENDENCY_INCOMPLETE")
    sha = os.environ.get("GITHUB_SHA", "")
    manifest = {
        "bundle": "NodeLab_Offline_V1",
        "python_required": "3.12+ with Tk",
        "standalone_executable": False,
        "code_commit": sha if re.fullmatch(r"[0-9a-f]{40}", sha) else "UNVERIFIED_LOCAL",
        "parser_base_commit": "5502e902cb29dc6801ee9f32a75cf8da7a0673a0",
        "dependency": {"name": "idna", "version": IDNA_VERSION, "license": "BSD-3-Clause"},
        "input_included": False,
        "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(payload.items())},
    }
    payload["MANIFEST.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / "NodeLab_Offline_V1.zip"
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo("NodeLab_Offline_V1/" + name, date_time=(2026, 10, 5, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(".zip.sha256").write_text(digest + "  " + destination.name + "\n", encoding="ascii")
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build offline entry; no real input is included.")
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()
    result = build_bundle(arguments.output_dir)
    print("BUNDLE_BUILT: " + result.name)

