"""Fictional input-format provenance checks at publication and entry boundaries."""
from __future__ import annotations

import base64
import io
import json
import os
import runpy
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

import nodelab.offline_file as offline_file
from nodelab.cli import main
from nodelab.inventory import build_inventory
from nodelab.offline_file import OfflineFileError, inspect_file, run_file, save_reports
from nodelab.types import PROBE_GATE_OPEN

_SECRET = "fictional-origin-secret-sentinel"
_HOST = "fictional-origin-host.example.invalid"
_PRIVATE_NAME = "fictional-origin-private-name.txt"
_URI = f"trojan://{_SECRET}@{_HOST}:443?security=tls#fictional-origin-label"
_RAW = (_URI + "\n\n" + _URI + "\n").encode("utf-8")
_WRAPPED = base64.b64encode(_RAW)
_ROOT = Path(__file__).resolve().parents[1]
_METADATA = {
    "uri_lines": {"input_format": "uri_lines", "line_number_basis": "source_text", "decoding_passes": 0},
    "base64": {"input_format": "base64", "line_number_basis": "decoded_text", "decoding_passes": 1},
    "not_recorded": {"input_format": "not_recorded", "line_number_basis": "parser_text", "decoding_passes": None},
}


def _assert_private_absent(text: str, *paths: Path) -> None:
    for value in (_SECRET, _HOST, _PRIVATE_NAME, _URI, _WRAPPED.decode("ascii"), "fictional-origin-label"):
        assert value not in text
    for path in paths:
        assert str(path) not in text
        assert path.name not in text


def _metadata(marker: dict) -> dict:
    return {key: marker[key] for key in ("input_format", "line_number_basis", "decoding_passes")}


def _published(folder: Path) -> str:
    return "".join(path.read_text(encoding="utf-8") for path in folder.iterdir() if path.is_file())


def _assert_format_text(markdown: str, input_format: str) -> None:
    format_lines = [line for line in markdown.splitlines() if "输入格式" in line]
    basis_lines = [line for line in markdown.splitlines() if "物理行和输入行的依据" in line]
    assert format_lines and basis_lines
    if input_format == "base64":
        assert any("Base64" in line for line in format_lines)
        assert any("解码" in line for line in basis_lines)
    elif input_format == "uri_lines":
        assert any("逐行 URI" in line for line in format_lines)
        assert any("源文本行" in line for line in basis_lines)
    else:
        assert any("未记录" in line for line in format_lines)
        assert any("解析器" in line for line in basis_lines)


@pytest.fixture
def no_network_or_engine(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("format-recording entry attempted network or subprocess")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


@pytest.mark.parametrize("input_format,data", [("uri_lines", _RAW), ("base64", _WRAPPED)], ids=["uri_lines", "base64"])
def test_file_entry_marker_records_processed_format_without_changing_inventory(tmp_path, capsys, input_format, data, no_network_or_engine):
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(data)
    before = source.stat()
    report, folder = run_file(source, tmp_path / "outputs", input_format=input_format)
    assert report == build_inventory(_RAW)
    stored = json.loads((folder / "inventory.json").read_text(encoding="utf-8"))
    assert stored == report and stored["schema_version"] == 1
    assert not set(_METADATA[input_format]).intersection(stored)
    marker = json.loads((folder / "COMPLETE.json").read_text(encoding="utf-8"))
    assert marker["schema_version"] == 2
    assert _metadata(marker) == _METADATA[input_format]
    assert marker["files"] == ["inventory.json", "inventory.md"]
    assert marker["status"] == "COMPLETE"
    assert marker["network_requests"] == 0 and marker["engine_started"] is False
    _assert_format_text((folder / "inventory.md").read_text(encoding="utf-8"), input_format)
    output = capsys.readouterr()
    _assert_private_absent(_published(folder) + output.out + output.err, source)
    assert source.read_bytes() == data
    assert source.stat().st_mtime_ns == before.st_mtime_ns
    assert PROBE_GATE_OPEN is False


def test_default_file_entry_records_actual_plain_format(tmp_path, no_network_or_engine):
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(_RAW)
    _, folder = run_file(source, tmp_path / "outputs")
    marker = json.loads((folder / "COMPLETE.json").read_text(encoding="utf-8"))
    assert marker["schema_version"] == 2
    assert _metadata(marker) == _METADATA["uri_lines"]
    _assert_format_text((folder / "inventory.md").read_text(encoding="utf-8"), "uri_lines")


def test_direct_save_without_origin_does_not_invent_a_format(tmp_path, no_network_or_engine):
    report = build_inventory(_RAW)
    folder = save_reports(report, tmp_path / "outputs")
    marker = json.loads((folder / "COMPLETE.json").read_text(encoding="utf-8"))
    assert marker["schema_version"] == 2
    assert _metadata(marker) == _METADATA["not_recorded"]
    _assert_format_text((folder / "inventory.md").read_text(encoding="utf-8"), "not_recorded")
    assert json.loads((folder / "inventory.json").read_text(encoding="utf-8")) == report
    _assert_private_absent(_published(folder))


class _StringSubclass(str):
    pass


@pytest.mark.parametrize("operation", ["inspect", "run"])
@pytest.mark.parametrize("invalid", ["not_recorded", "unknown-private-origin", _StringSubclass("base64")],
                         ids=["unknown_is_not_read_mode", "arbitrary_source", "string_subclass"])
def test_invalid_read_format_is_rejected_before_input_or_output_io(tmp_path, monkeypatch, operation, invalid):
    source = tmp_path / _PRIVATE_NAME
    destination = tmp_path / "never-created"
    touched = []

    def forbidden_io(*args, **kwargs):
        touched.append("filesystem")
        raise AssertionError("invalid read mode reached filesystem")

    with monkeypatch.context() as patch:
        patch.setattr(offline_file, "_check_local_path", forbidden_io)
        patch.setattr(Path, "mkdir", forbidden_io)
        patch.setattr(Path, "open", forbidden_io)
        with pytest.raises(OfflineFileError) as raised:
            if operation == "inspect":
                inspect_file(source, input_format=invalid)
            else:
                run_file(source, destination, input_format=invalid)
    assert touched == []
    assert raised.value.code == "INVALID_ARGUMENTS"
    _assert_private_absent(str(raised.value) + repr(raised.value), source)
    assert "unknown-private-origin" not in str(raised.value)
    assert not source.exists() and not destination.exists()


@pytest.mark.parametrize("invalid", ["unknown-private-origin", "", _SECRET, True, 1, None,
    {"input_format": "base64", "line_number_basis": "source_text", "decoding_passes": 0},
    _StringSubclass("base64")])
def test_unknown_or_forged_format_is_rejected_before_filesystem_access(tmp_path, monkeypatch, invalid):
    report = build_inventory(_RAW)
    destination = tmp_path / "never-created"
    touched = []

    def forbidden_io(*args, **kwargs):
        touched.append("filesystem")
        raise AssertionError("metadata validation was too late")

    with monkeypatch.context() as patch:
        patch.setattr(offline_file, "_check_local_path", forbidden_io)
        patch.setattr(Path, "mkdir", forbidden_io)
        patch.setattr(Path, "open", forbidden_io)
        with pytest.raises(OfflineFileError) as raised:
            save_reports(report, destination, input_format=invalid)
    assert touched == []
    assert str(raised.value) in {"INVALID_ARGUMENTS", "OUTPUT_FAILED"}
    _assert_private_absent(str(raised.value) + repr(raised.value))
    assert "unknown-private-origin" not in str(raised.value)
    assert not destination.exists()


@pytest.mark.parametrize("forgery", ["top_level", "row_source", "summary"])
def test_forged_inventory_is_rejected_before_origin_publication_or_io(tmp_path, monkeypatch, forgery):
    report = build_inventory(_RAW)
    if forgery == "top_level":
        report["input_format"] = "base64"
        report["private_origin"] = _URI
    elif forgery == "row_source":
        report["records"][0]["source_status"] = "base64:" + _SECRET
    else:
        report["summary"]["private_origin"] = _HOST
    touched = []

    def forbidden_io(*args, **kwargs):
        touched.append("filesystem")
        raise AssertionError("forged report reached filesystem")

    destination = tmp_path / "never-created"
    with monkeypatch.context() as patch:
        patch.setattr(offline_file, "_check_local_path", forbidden_io)
        patch.setattr(Path, "mkdir", forbidden_io)
        patch.setattr(Path, "open", forbidden_io)
        with pytest.raises(OfflineFileError) as raised:
            save_reports(report, destination, input_format="base64")
    assert touched == []
    _assert_private_absent(str(raised.value) + repr(raised.value))
    assert not destination.exists()


def test_completion_metadata_serialization_failure_happens_before_io(tmp_path, monkeypatch):
    report = build_inventory(_RAW)
    original_dumps = offline_file.json.dumps
    preflight_seen, touched = [], []

    def failing_marker_serialization(value, *args, **kwargs):
        if type(value) is dict and value.get("status") == "COMPLETE":
            preflight_seen.append(_metadata(value))
            raise ValueError(_URI)
        return original_dumps(value, *args, **kwargs)

    def forbidden_io(*args, **kwargs):
        touched.append("filesystem")
        raise AssertionError("marker preflight was too late")

    destination = tmp_path / "never-created"
    with monkeypatch.context() as patch:
        patch.setattr(offline_file.json, "dumps", failing_marker_serialization)
        patch.setattr(offline_file, "_check_local_path", forbidden_io)
        patch.setattr(Path, "mkdir", forbidden_io)
        patch.setattr(Path, "open", forbidden_io)
        with pytest.raises(OfflineFileError) as raised:
            save_reports(report, destination, input_format="base64")
    assert preflight_seen == [_METADATA["base64"]]
    assert touched == []
    assert raised.value.code == "OUTPUT_FAILED"
    _assert_private_absent(str(raised.value) + repr(raised.value))
    assert not destination.exists()


def test_marker_is_published_last_with_validated_format_record(tmp_path, monkeypatch):
    original_replace = offline_file.os.replace
    observations = []

    def observe_publish(source, destination):
        source, destination = Path(source), Path(destination)
        assert destination.name == "COMPLETE.json"
        assert not destination.exists()
        assert (source.parent / "inventory.json").is_file()
        assert (source.parent / "inventory.md").is_file()
        marker = json.loads(source.read_text(encoding="utf-8"))
        assert marker["schema_version"] == 2
        assert _metadata(marker) == _METADATA["base64"]
        observations.append(marker)
        return original_replace(source, destination)

    monkeypatch.setattr(offline_file.os, "replace", observe_publish)
    folder = save_reports(build_inventory(_RAW), tmp_path / "outputs", input_format="base64")
    assert len(observations) == 1
    assert not (folder / ".complete.tmp").exists()
    assert json.loads((folder / "COMPLETE.json").read_text(encoding="utf-8")) == observations[0]


@pytest.mark.parametrize("failure", ["dump", "replace"])
def test_interrupted_v2_marker_has_no_completion_record_or_private_exception(tmp_path, monkeypatch, failure):
    def interrupted_dump(value, handle, *args, **kwargs):
        handle.write('{"status":"COMPLETE","schema_version":2,')
        raise OSError(_SECRET + _HOST)

    def failed_publish(*args, **kwargs):
        raise OSError(_URI)

    if failure == "dump":
        monkeypatch.setattr(offline_file.json, "dump", interrupted_dump)
    else:
        monkeypatch.setattr(offline_file.os, "replace", failed_publish)
    destination = tmp_path / "outputs"
    with pytest.raises(OfflineFileError) as raised:
        save_reports(build_inventory(_RAW), destination, input_format="base64")
    assert raised.value.code == "OUTPUT_FAILED"
    assert not list(destination.rglob("COMPLETE.json"))
    published = "".join(path.read_text(encoding="utf-8") for path in destination.rglob("*") if path.is_file())
    _assert_private_absent(published + str(raised.value) + repr(raised.value))


def _cli_input(kind: str, data: bytes, tmp_path: Path, monkeypatch):
    if kind == "file":
        source = tmp_path / _PRIVATE_NAME
        source.write_bytes(data)
        return ["inventory-file", "--file", str(source)], source
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data), encoding="utf-8"))
    return ["inventory-stdin"], None


@pytest.mark.parametrize("kind", ["file", "stdin"])
@pytest.mark.parametrize("input_format,data", [("uri_lines", _RAW), ("base64", _WRAPPED)], ids=["uri_lines", "base64"])
def test_cli_markdown_records_selected_format_and_line_basis(tmp_path, monkeypatch, capsys, kind, input_format, data, no_network_or_engine):
    args, source = _cli_input(kind, data, tmp_path, monkeypatch)
    assert main(args + ["--input-format", input_format, "--format", "markdown"]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    _assert_format_text(output.out, input_format)
    assert "| 非空记录 | 2 |" in output.out
    _assert_private_absent(output.out, *([source] if source else []))


@pytest.mark.parametrize("kind", ["file", "stdin"])
@pytest.mark.parametrize("input_format,data", [("uri_lines", _RAW), ("base64", _WRAPPED)], ids=["uri_lines", "base64"])
def test_cli_json_remains_a_single_unwrapped_inventory_v1(tmp_path, monkeypatch, capsys, kind, input_format, data, no_network_or_engine):
    args, source = _cli_input(kind, data, tmp_path, monkeypatch)
    assert main(args + ["--input-format", input_format]) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report == build_inventory(_RAW)
    assert report["schema_version"] == 1
    assert not set(_METADATA[input_format]).intersection(report)
    assert output.err == ""
    _assert_private_absent(output.out, *([source] if source else []))


@pytest.mark.skipif(os.name != "nt", reason="Windows/Tk marker integration requires a Windows runner")
def test_windows_gui_selected_base64_reaches_v2_marker(tmp_path, monkeypatch):
    import tkinter as tk
    from tkinter import filedialog, ttk

    namespace = runpy.run_path(str(_ROOT / "scripts/nodelab_offline.pyw"), run_name="origin_gui_test")
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(_WRAPPED)
    local = tmp_path / "local"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    window = tk.Tk()
    window.withdraw()
    monkeypatch.setattr(tk, "Tk", lambda: window)
    buttons, combos = [], []
    original_button, original_combo = ttk.Button, ttk.Combobox

    def capture_button(*args, **kwargs):
        widget = original_button(*args, **kwargs)
        buttons.append(widget)
        return widget

    def capture_combo(*args, **kwargs):
        widget = original_combo(*args, **kwargs)
        combos.append(widget)
        return widget

    monkeypatch.setattr(ttk, "Button", capture_button)
    monkeypatch.setattr(ttk, "Combobox", capture_combo)
    monkeypatch.setattr(filedialog, "askopenfilename", lambda **kwargs: str(source))
    clipboard = []
    monkeypatch.setattr(window, "clipboard_clear", lambda: None)
    monkeypatch.setattr(window, "clipboard_append", clipboard.append)
    outcome = {}
    deadline = time.monotonic() + 20

    def tick():
        if time.monotonic() > deadline:
            outcome["timeout"] = True
            window.destroy()
            return
        if str(buttons[1]["state"]) == "normal":
            buttons[1].invoke()
            outcome["markers"] = list(local.rglob("COMPLETE.json"))
            window.destroy()
            return
        window.after(50, tick)

    def begin():
        if len(combos) != 1:
            outcome["missing_selector"] = True
            window.destroy()
            return
        combos[0].current(1)
        buttons[0].invoke()
        window.after(50, tick)

    window.after(100, begin)
    assert namespace["_gui"]() == 0
    assert "timeout" not in outcome and "missing_selector" not in outcome
    assert len(outcome["markers"]) == 1 and len(clipboard) == 1
    marker = json.loads(outcome["markers"][0].read_text(encoding="utf-8"))
    assert marker["schema_version"] == 2
    assert _metadata(marker) == _METADATA["base64"]
    _assert_format_text((outcome["markers"][0].parent / "inventory.md").read_text(encoding="utf-8"), "base64")
    assert "Base64" in clipboard[0] and "解码" in clipboard[0]
    _assert_private_absent(_published(outcome["markers"][0].parent) + clipboard[0], source)
