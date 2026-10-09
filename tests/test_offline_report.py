"""Adversarial checks for read-only, anonymous saved-report verification.

All private-looking values are fictional canaries. The legacy Markdown below
is an independent literal checked against the pinned fe8c1399 baseline
renderer, rather than a slice of the candidate renderer under test.
"""
from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import nodelab.offline_report as offline_report
from nodelab.inventory import build_inventory, render_inventory_report
from nodelab.offline_file import save_reports
from nodelab.offline_report import OfflineReportError, load_reports


CANARY = "synthetic-report-private-sentinel"
PRIVATE_PATH = "synthetic-report-private-path-sentinel"
URI = f"trojan://{CANARY}@{CANARY}.example.invalid:443?security=tls#{CANARY}"
FILES = ("COMPLETE.json", "inventory.json", "inventory.md")
EXPECTED_METADATA = {
    "uri_lines": {"input_format": "uri_lines", "line_number_basis": "source_text", "decoding_passes": 0},
    "base64": {"input_format": "base64", "line_number_basis": "decoded_text", "decoding_passes": 1},
    "not_recorded": {"input_format": "not_recorded", "line_number_basis": "parser_text", "decoding_passes": None},
}
LEGACY_REPORT = {
    "schema_version": 1, "mode": "offline_inventory", "complete": True, "network_used": False,
    "summary": {"physical_lines": 0, "blank_lines": 0, "records": 0, "parsed": 0,
                "unsupported": 0, "invalid": 0, "unique_configurations": 0, "duplicate_records": 0},
    "protocol_counts": {}, "dialect_counts": {}, "error_counts": {}, "records": [],
}
LEGACY_MARKER = {
    "status": "COMPLETE", "schema_version": 1, "mode": "offline_file",
    "network_requests": 0, "engine_started": False,
    "created_at_utc": "2026-10-09T02:00:00.123456+00:00",
    "files": ["inventory.json", "inventory.md"],
}
LEGACY_MARKDOWN = """# NodeLab 离线资产盘点

范围：全部受限输入已处理；未联网、未启动代理引擎、未测真实节点。

| 项目 | 数量 |
| --- | ---: |
| 物理行 | 0 |
| 空白行 | 0 |
| 非空记录 | 0 |
| 解析成功（未测） | 0 |
| 当前不支持 | 0 |
| 格式或字段错误 | 0 |
| 规范化配置组 | 0 |
| 重复配置记录 | 0 |

规范化配置组不是独立线路、上游账号或出口数量；这三项仍未知。
来源与转售授权均未知；质量、寿命、稳定性及住宅属性未核验。
配置组编号和重复关系仅在本次输入内有效，不是跨次追踪身份。
协议列是安全枚举的声明或解析结果，不支持项不是已确认的坏节点。

| 记录 | 输入行 | 协议 | 状态 | 方言 | 配置组 | 重复于 | 固定错误码 |
| --- | ---: | --- | --- | --- | --- | --- | --- |

本报告未包含URI、凭据、节点地址、备注、秘密哈希或原始文件路径。
"""


def _safe_text(text: str, folder: Path | None = None) -> None:
    for private in (CANARY, PRIVATE_PATH, URI, "trojan://"):
        assert private not in text
    if folder is not None:
        assert str(folder) not in text


def _assert_error(folder: Path, code: str, capsys=None) -> OfflineReportError:
    with pytest.raises(OfflineReportError) as raised:
        load_reports(folder)
    error = raised.value
    assert error.code == code
    assert str(error) == code
    assert error.args == (code,)
    _safe_text(str(error) + repr(error) + repr(error.args), folder)
    if capsys is not None:
        captured = capsys.readouterr()
        assert captured.out == captured.err == ""
    return error


def _folder(tmp_path: Path, input_format: str = "uri_lines") -> Path:
    return save_reports(build_inventory(URI + "\n\n" + URI + "\n"),
                        tmp_path / PRIVATE_PATH, input_format=input_format)


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _legacy(tmp_path: Path) -> Path:
    folder = tmp_path / PRIVATE_PATH
    folder.mkdir()
    _write_json(folder / "COMPLETE.json", copy.deepcopy(LEGACY_MARKER))
    _write_json(folder / "inventory.json", copy.deepcopy(LEGACY_REPORT))
    (folder / "inventory.md").write_text(LEGACY_MARKDOWN, encoding="utf-8", newline="\n")
    return folder


@pytest.mark.parametrize("input_format", list(EXPECTED_METADATA))
def test_current_saved_reports_return_exact_safe_contract(tmp_path, capsys, input_format):
    folder = _folder(tmp_path, input_format)
    expected_report = _json(folder / "inventory.json")
    result = load_reports(folder)
    assert type(result) is dict
    assert set(result) == {"report", "metadata", "marker_schema_version", "markdown"}
    assert result["report"] == expected_report
    assert result["metadata"] == EXPECTED_METADATA[input_format]
    assert result["marker_schema_version"] == 2
    assert type(result["marker_schema_version"]) is int
    assert result["markdown"] == render_inventory_report(expected_report, input_format=input_format)
    assert result["report"]["summary"]["records"] == 2
    assert result["report"]["summary"]["duplicate_records"] == 1
    assert result["report"]["records"][1]["line_number"] == 3
    _safe_text(json.dumps(result, ensure_ascii=False) + repr(result), folder)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_fixed_legacy_v1_report_gets_explicit_unknown_metadata(tmp_path):
    folder = _legacy(tmp_path)
    result = load_reports(folder)
    assert result["marker_schema_version"] == 1
    assert result["report"] == LEGACY_REPORT
    assert result["metadata"] == EXPECTED_METADATA["not_recorded"]
    assert result["markdown"] == render_inventory_report(LEGACY_REPORT, input_format="not_recorded")
    assert "原始包装方式未知" in result["markdown"]
    assert "输入格式：未记录" in result["markdown"]
    assert result["markdown"] != LEGACY_MARKDOWN


def test_legacy_marker_cannot_claim_new_format_without_version_change(tmp_path):
    folder = _legacy(tmp_path)
    marker = _json(folder / "COMPLETE.json")
    marker.update(EXPECTED_METADATA["uri_lines"])
    _write_json(folder / "COMPLETE.json", marker)
    _assert_error(folder, "REPORT_INVALID")


def test_legacy_report_rejects_new_markdown_instead_of_guessing_source_format(tmp_path):
    folder = _legacy(tmp_path)
    (folder / "inventory.md").write_text(render_inventory_report(LEGACY_REPORT), encoding="utf-8")
    _assert_error(folder, "REPORT_MISMATCH")


def test_loading_is_read_only_and_ignores_unrelated_readme(tmp_path):
    folder = _folder(tmp_path)
    extra = folder / "README.txt"
    extra.write_text(CANARY, encoding="utf-8")
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_size) for p in folder.iterdir()}
    if os.name != "nt":
        for name in FILES:
            (folder / name).chmod(0o400)
    try:
        result = load_reports(folder)
        after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_size) for p in folder.iterdir()}
        assert before == after
        _safe_text(json.dumps(result), folder)
    finally:
        if os.name != "nt":
            for name in FILES:
                (folder / name).chmod(0o600)


@pytest.mark.parametrize("name", FILES)
def test_missing_report_component_is_unsafe_and_does_not_modify_others(tmp_path, name):
    folder = _folder(tmp_path)
    (folder / name).unlink()
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    _assert_error(folder, "REPORT_UNSAFE")
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before


@pytest.mark.parametrize("name", FILES)
def test_report_component_must_be_regular_file(tmp_path, name):
    folder = _folder(tmp_path)
    (folder / name).unlink()
    (folder / name).mkdir()
    _assert_error(folder, "REPORT_UNSAFE")


@pytest.mark.parametrize("kind", ["relative", "absent", "regular_file"])
def test_non_directory_or_nonabsolute_folder_is_unsafe(tmp_path, kind):
    folder = {"relative": Path(PRIVATE_PATH), "absent": tmp_path / PRIVATE_PATH,
              "regular_file": tmp_path / "ordinary-file"}[kind]
    if kind == "regular_file":
        folder.write_text(CANARY, encoding="utf-8")
    _assert_error(folder, "REPORT_UNSAFE")


@pytest.mark.parametrize("kind", ["folder", "parent", *FILES])
def test_symlink_at_any_report_path_boundary_is_rejected(tmp_path, kind):
    folder = _folder(tmp_path)
    try:
        if kind == "folder":
            link = tmp_path / "linked-folder"
            link.symlink_to(folder, target_is_directory=True)
            folder = link
        elif kind == "parent":
            link = tmp_path / "linked-parent"
            link.symlink_to(folder.parent, target_is_directory=True)
            folder = link / folder.name
        else:
            target = tmp_path / ("target-" + kind)
            target.write_bytes((folder / kind).read_bytes())
            (folder / kind).unlink()
            (folder / kind).symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks is not allowed in this runner")
    _assert_error(folder, "REPORT_UNSAFE")


MARKER_BAD_VALUES = [
    ("status", CANARY), ("status", "complete"), ("mode", CANARY),
    ("schema_version", True), ("schema_version", False), ("schema_version", 2.0),
    ("schema_version", "2"), ("schema_version", 0), ("schema_version", 3),
    ("network_requests", False), ("network_requests", 0.0), ("network_requests", 1),
    ("network_requests", "0"), ("engine_started", 0), ("engine_started", "false"),
    ("engine_started", True), ("files", ["inventory.md", "inventory.json"]),
    ("files", ["inventory.json", "inventory.md", "README.txt"]),
    ("files", ["../" + PRIVATE_PATH, "inventory.md"]),
    ("files", "inventory.json"), ("files", []), ("files", None),
    ("input_format", CANARY), ("input_format", "auto"), ("input_format", None),
    ("input_format", ["uri_lines"]), ("line_number_basis", "decoded_text"),
    ("line_number_basis", CANARY), ("decoding_passes", False),
    ("decoding_passes", 0.0), ("decoding_passes", 1), ("decoding_passes", None),
]


@pytest.mark.parametrize("key,value", MARKER_BAD_VALUES)
def test_marker_requires_exact_fields_values_and_types(tmp_path, capsys, key, value):
    folder = _folder(tmp_path)
    marker = _json(folder / "COMPLETE.json")
    marker[key] = value
    _write_json(folder / "COMPLETE.json", marker)
    _assert_error(folder, "REPORT_INVALID", capsys)


@pytest.mark.parametrize("input_format,value", [("base64", True), ("base64", 1.0),
                                               ("not_recorded", 0), ("not_recorded", "null")])
def test_other_format_decode_count_cannot_use_equal_boolean_or_float(tmp_path, input_format, value):
    folder = _folder(tmp_path, input_format)
    marker = _json(folder / "COMPLETE.json")
    marker["decoding_passes"] = value
    _write_json(folder / "COMPLETE.json", marker)
    _assert_error(folder, "REPORT_INVALID")


@pytest.mark.parametrize("key", list(LEGACY_MARKER) + list(EXPECTED_METADATA["uri_lines"]))
def test_every_current_marker_key_is_required(tmp_path, key):
    folder = _folder(tmp_path)
    marker = _json(folder / "COMPLETE.json")
    del marker[key]
    _write_json(folder / "COMPLETE.json", marker)
    _assert_error(folder, "REPORT_INVALID")


BAD_TIMESTAMPS = [
    None, True, 0, [], CANARY, "", "2026-10-09", "2026-10-09T02:00:00",
    "2026-10-09T02:00:00Z", "2026-10-09T02:00:00+08:00",
    "2026-10-09T02:00:00-00:00", "2026-10-09 02:00:00+00:00",
    "2026-10-09T02:00:00.1234567+00:00", "2026-10-09T02:00:00.+00:00",
    "2026-13-09T02:00:00+00:00", "2026-02-30T02:00:00+00:00",
    "2026-10-09T24:00:00+00:00", "2026-10-09T02:00:60+00:00",
    "2026-10-09T02:00:00+00:00\n", "2026-10-09T02:00:00+00:00" + CANARY,
]


@pytest.mark.parametrize("value", BAD_TIMESTAMPS)
def test_timestamp_is_exact_iso_utc_not_arbitrary_saved_text(tmp_path, value):
    folder = _folder(tmp_path)
    marker = _json(folder / "COMPLETE.json")
    marker["created_at_utc"] = value
    _write_json(folder / "COMPLETE.json", marker)
    _assert_error(folder, "REPORT_INVALID")


@pytest.mark.parametrize("value", ["2026-10-09T02:00:00+00:00", "2026-10-09T02:00:00.1+00:00",
                                   "2026-10-09T02:00:00.123456+00:00"])
def test_writer_compatible_utc_timestamps_are_accepted(tmp_path, value):
    folder = _folder(tmp_path)
    marker = _json(folder / "COMPLETE.json")
    marker["created_at_utc"] = value
    _write_json(folder / "COMPLETE.json", marker)
    assert load_reports(folder)["marker_schema_version"] == 2


@pytest.mark.parametrize("name", ["COMPLETE.json", "inventory.json"])
@pytest.mark.parametrize("raw", [b"[]", b"null", b"true", b"0", b'"private"', b"{", b"\xff", b"\xef\xbb\xbf{}"])
def test_json_documents_must_be_strict_utf8_objects(tmp_path, name, raw):
    folder = _folder(tmp_path)
    (folder / name).write_bytes(raw)
    _assert_error(folder, "REPORT_INVALID")


@pytest.mark.parametrize("name", ["COMPLETE.json", "inventory.json"])
@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_json_numbers_are_rejected(tmp_path, name, constant):
    folder = _folder(tmp_path)
    raw = (folder / name).read_text(encoding="utf-8")
    raw = raw.replace('"schema_version": 2' if name == "COMPLETE.json" else '"schema_version": 1',
                      '"schema_version": ' + constant, 1)
    (folder / name).write_text(raw, encoding="utf-8")
    _assert_error(folder, "REPORT_INVALID")


@pytest.mark.parametrize("payload", [
    b'{"x":' + b"[" * 9 + b"0" + b"]" * 9 + b"}",
    b'{"' + b"x" * 1025 + b'":0}',
    b'{"x":' + b"9" * 65 + b"}",
])
def test_resource_hostile_json_is_rejected_before_json_object_allocation(tmp_path, monkeypatch, payload):
    folder = _folder(tmp_path)
    (folder / "inventory.json").write_bytes(payload)
    original = offline_report.json.loads
    calls = []

    def watched(document, *args, **kwargs):
        # The marker still needs ordinary parsing; only the hostile inventory
        # document must be rejected before the JSON decoder allocates objects.
        if document.encode("utf-8") == payload:
            calls.append(True)
            raise AssertionError("hostile inventory reached json.loads")
        return original(document, *args, **kwargs)

    monkeypatch.setattr(offline_report.json, "loads", watched)
    _assert_error(folder, "REPORT_INVALID")
    assert calls == []


@pytest.mark.parametrize("name,nested", [("COMPLETE.json", False), ("inventory.json", False),
                                        ("inventory.json", True)])
def test_duplicate_json_keys_are_rejected_even_when_equal(tmp_path, name, nested):
    folder = _folder(tmp_path)
    raw = (folder / name).read_text(encoding="utf-8")
    key = '"records": 2' if nested else ('"schema_version": 2' if name == "COMPLETE.json" else '"schema_version": 1')
    raw = raw.replace(key, key + ", " + key, 1)
    (folder / name).write_text(raw, encoding="utf-8")
    _assert_error(folder, "REPORT_INVALID")


@pytest.mark.parametrize("name", ["COMPLETE.json", "inventory.json"])
def test_extra_private_fields_are_rejected_without_echo(tmp_path, capsys, name):
    folder = _folder(tmp_path)
    value = _json(folder / name)
    value["private_source"] = URI + str(folder)
    _write_json(folder / name, value)
    _assert_error(folder, "REPORT_INVALID", capsys)


@pytest.mark.parametrize("kind", ["private_row_field", "private_protocol", "count_mismatch",
                                 "boolean_count", "incomplete", "network_true", "wrong_schema"])
def test_inventory_uses_existing_strict_public_schema(tmp_path, capsys, kind):
    folder = _folder(tmp_path)
    report = _json(folder / "inventory.json")
    if kind == "private_row_field":
        report["records"][0]["private_uri"] = URI
    elif kind == "private_protocol":
        report["records"][0]["protocol"] = URI
    elif kind == "count_mismatch":
        report["summary"]["records"] = 3
    elif kind == "boolean_count":
        report["summary"]["unique_configurations"] = True
    elif kind == "incomplete":
        report["complete"] = False
    elif kind == "network_true":
        report["network_used"] = True
    else:
        report["schema_version"] = 2
    _write_json(folder / "inventory.json", report)
    _assert_error(folder, "REPORT_INVALID", capsys)


@pytest.mark.parametrize("kind", ["private_suffix", "different_count", "crlf", "missing_newline", "utf8_bom"])
def test_saved_markdown_must_match_validated_current_inventory_byte_for_byte(tmp_path, capsys, kind):
    folder = _folder(tmp_path)
    path = folder / "inventory.md"
    raw = path.read_bytes()
    changed = {
        "private_suffix": raw + URI.encode(),
        "different_count": raw.replace("| 非空记录 | 2 |".encode(), "| 非空记录 | 3 |".encode()),
        "crlf": raw.replace(b"\n", b"\r\n"),
        "missing_newline": raw.removesuffix(b"\n"),
        "utf8_bom": b"\xef\xbb\xbf" + raw,
    }[kind]
    assert changed != raw
    path.write_bytes(changed)
    _assert_error(folder, "REPORT_MISMATCH", capsys)


@pytest.mark.parametrize("name", FILES)
def test_oversized_component_rejected_before_opening_it(tmp_path, monkeypatch, name):
    folder = _folder(tmp_path)
    limit = 32
    constant = {"COMPLETE.json": "MAX_MARKER_BYTES", "inventory.json": "MAX_REPORT_BYTES",
                "inventory.md": "MAX_MARKDOWN_BYTES"}[name]
    monkeypatch.setattr(offline_report, constant, limit)
    (folder / name).write_bytes(b" " * (limit + 1))
    _assert_error(folder, "REPORT_TOO_LARGE")


@pytest.mark.parametrize("name", FILES)
def test_exact_report_byte_limit_is_accepted_and_one_extra_byte_rejected(tmp_path, monkeypatch, name):
    folder = _folder(tmp_path)
    component = folder / name
    limit = component.stat().st_size
    constant = {"COMPLETE.json": "MAX_MARKER_BYTES", "inventory.json": "MAX_REPORT_BYTES",
                "inventory.md": "MAX_MARKDOWN_BYTES"}[name]
    monkeypatch.setattr(offline_report, constant, limit)
    assert load_reports(folder)["report"]["summary"]["records"] == 2
    component.write_bytes(component.read_bytes() + b" ")
    _assert_error(folder, "REPORT_TOO_LARGE")


def test_size_growth_seen_during_read_is_bounded_and_rejected(tmp_path, monkeypatch):
    folder = _folder(tmp_path)
    marker = folder / "COMPLETE.json"
    limit = marker.stat().st_size
    marker_identity = (marker.stat().st_dev, marker.stat().st_ino)
    original_read, original_fstat = offline_report.os.read, offline_report.os.fstat
    monkeypatch.setattr(offline_report, "MAX_MARKER_BYTES", limit)
    calls = []

    def growing(fd, count):
        current = original_fstat(fd)
        if (current.st_dev, current.st_ino) == marker_identity:
            calls.append(count)
            assert 0 < count <= limit + 1
            if len(calls) == 1:
                # Grow after the initial size/identity check. The reader must
                # stop at limit+1 even though the first stat was under limit.
                with marker.open("ab") as handle:
                    handle.write(b" " * 1000)
        return original_read(fd, count)

    monkeypatch.setattr(offline_report.os, "read", growing)
    _assert_error(folder, "REPORT_TOO_LARGE")
    assert calls and sum(calls) <= limit + 1


def test_previously_read_component_change_is_detected_before_success(tmp_path, monkeypatch):
    folder = _folder(tmp_path)
    marker = folder / "COMPLETE.json"
    markdown = folder / "inventory.md"
    markdown_identity = (markdown.stat().st_dev, markdown.stat().st_ino)
    original_read, original_fstat = offline_report.os.read, offline_report.os.fstat
    changed = []

    def altering(fd, count):
        current = original_fstat(fd)
        if (current.st_dev, current.st_ino) == markdown_identity and not changed:
            raw = marker.read_bytes()
            # The parsed marker remains valid and same length; only a
            # cross-file reread/stat check can detect this later replacement.
            raw = raw.replace(b'"network_requests": 0', b'"network_requests": 1')
            marker.write_bytes(raw)
            changed.append(True)
        return original_read(fd, count)

    monkeypatch.setattr(offline_report.os, "read", altering)
    _assert_error(folder, "REPORT_UNSAFE")
    assert changed == [True]


@pytest.mark.parametrize("kind", ["identity", "nonregular", "reparse", "offline", "recall_open", "recall_data"])
def test_open_handle_identity_type_and_attributes_checked_before_read(tmp_path, monkeypatch, kind):
    folder = _folder(tmp_path)
    original = offline_report.os.fstat
    attributes = {"reparse": 0x400, "offline": 0x1000, "recall_open": 0x40000, "recall_data": 0x400000}

    def forged(fd):
        current = original(fd)
        result = {name: getattr(current, name) for name in dir(current) if name.startswith("st_")}
        if kind == "identity":
            result["st_ino"] += 1
        elif kind == "nonregular":
            result["st_mode"] = stat.S_IFIFO | 0o600
        else:
            result["st_file_attributes"] = attributes[kind]
        return SimpleNamespace(**result)

    monkeypatch.setattr(offline_report.os, "fstat", forged)
    _assert_error(folder, "REPORT_UNSAFE")


def test_os_read_failure_has_fixed_error_without_private_exception_text(tmp_path, monkeypatch, capsys):
    folder = _folder(tmp_path)

    def forbidden(*args, **kwargs):
        raise PermissionError(URI + str(folder))

    monkeypatch.setattr(offline_report.os, "open", forbidden)
    _assert_error(folder, "REPORT_UNSAFE", capsys)


def test_current_format_marker_is_compared_with_saved_markdown(tmp_path):
    folder = _folder(tmp_path, "uri_lines")
    marker = _json(folder / "COMPLETE.json")
    marker.update(EXPECTED_METADATA["base64"])
    _write_json(folder / "COMPLETE.json", marker)
    _assert_error(folder, "REPORT_MISMATCH")


def test_coherent_anonymous_files_are_not_claimed_to_authenticate_original_input(tmp_path):
    # The old marker has no hash/signature. A consistent replacement is accepted;
    # the API checks schema/agreement, not the historical source or provenance.
    folder = _folder(tmp_path, "uri_lines")
    marker = _json(folder / "COMPLETE.json")
    marker.update(EXPECTED_METADATA["base64"])
    _write_json(folder / "COMPLETE.json", marker)
    report = _json(folder / "inventory.json")
    (folder / "inventory.md").write_text(render_inventory_report(report, input_format="base64"), encoding="utf-8")
    result = load_reports(folder)
    assert result["metadata"] == EXPECTED_METADATA["base64"]
    assert "source_authenticated" not in result


def test_report_loading_under_network_and_process_audit_blocker_has_no_engine_import(tmp_path):
    folder = _folder(tmp_path)
    source = Path(__file__).resolve().parents[1] / "src"
    child = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
def guard(event, args):
    if event.startswith("socket.") or event.startswith("subprocess.") or event in {"os.system", "os.posix_spawn", "os.spawn"}:
        raise RuntimeError("OFFLINE_OPERATION_BLOCKED")
sys.addaudithook(guard)
from pathlib import Path
from nodelab.offline_report import load_reports
result = load_reports(Path(sys.argv[2]))
forbidden = {"nodelab.cli", "nodelab.mihomo_config", "nodelab.probe", "nodelab.engine", "nodelab.recovery"}
print(json.dumps({"records": result["report"]["summary"]["records"], "engine_imports": sorted(forbidden.intersection(sys.modules)), "network_used": result["report"]["network_used"]}))
'''
    completed = subprocess.run([sys.executable, "-I", "-c", child, str(source), str(folder)],
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {"records": 2, "engine_imports": [], "network_used": False}
    _safe_text(completed.stdout + completed.stderr, folder)
