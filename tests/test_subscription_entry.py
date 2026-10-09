"""Fictional integration checks for explicitly selected Base64 subscriptions.

These checks exercise the existing file, CLI, publication and Windows GUI
boundaries. They never open owner input or use a live node.
"""
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

from nodelab.cli import main
from nodelab.inventory import build_inventory
from nodelab.offline_file import OfflineFileError, inspect_file, run_file
from nodelab.types import PROBE_GATE_OPEN

_SECRET = "fictional-subscription-secret-sentinel"
_HOST = "fictional-subscription-host.example.invalid"
_LABEL = "fictional-subscription-label-sentinel"
_PRIVATE_NAME = "fictional-subscription-private-name.txt"
_URI = f"trojan://{_SECRET}@{_HOST}:443?security=tls#{_LABEL}"
_RAW = (_URI + "\n\n" + _URI + "\n").encode("utf-8")
_WRAPPED = base64.b64encode(_RAW)
_ROOT = Path(__file__).resolve().parents[1]


def _assert_private_absent(text: str, *paths: Path) -> None:
    private = (_SECRET, _HOST, _LABEL, _PRIVATE_NAME, _URI,
               _RAW.decode("utf-8"), _WRAPPED.decode("ascii"))
    for value in private:
        assert value not in text
    for path in paths:
        assert str(path) not in text
        assert path.name not in text


@pytest.fixture
def no_network_or_engine(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("subscription entry attempted network or subprocess")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


def test_base64_file_produces_same_reports_and_preserves_source(tmp_path, capsys, no_network_or_engine):
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(_WRAPPED)
    before = source.stat()
    report, folder = run_file(source, tmp_path / "outputs", input_format="base64")
    assert report == build_inventory(_RAW)
    assert report["summary"]["parsed"] == 2
    assert report["summary"]["duplicate_records"] == 1
    assert source.read_bytes() == _WRAPPED
    assert source.stat().st_mtime_ns == before.st_mtime_ns
    assert source.stat().st_size == before.st_size
    assert json.loads((folder / "inventory.json").read_text(encoding="utf-8")) == report
    markdown = (folder / "inventory.md").read_text(encoding="utf-8")
    assert "| 非空记录 | 2 |" in markdown
    assert "| 重复配置记录 | 1 |" in markdown
    marker = json.loads((folder / "COMPLETE.json").read_text(encoding="utf-8"))
    assert marker["status"] == "COMPLETE"
    assert marker["network_requests"] == 0 and marker["engine_started"] is False
    captured = capsys.readouterr()
    published = "".join(path.read_text(encoding="utf-8") for path in folder.iterdir())
    _assert_private_absent(published + captured.out + captured.err, source)
    assert PROBE_GATE_OPEN is False


@pytest.mark.parametrize("explicit", [False, True])
def test_default_file_input_keeps_plain_uri_behavior(tmp_path, explicit, no_network_or_engine):
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(_RAW)
    options = {"input_format": "uri_lines"} if explicit else {}
    report = inspect_file(source, **options)
    assert report == build_inventory(_RAW)
    assert report["summary"]["records"] == 2
    _assert_private_absent(json.dumps(report), source)


def test_default_file_mode_does_not_guess_base64(tmp_path, no_network_or_engine):
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(_WRAPPED)
    report = inspect_file(source)
    assert report == build_inventory(_WRAPPED)
    assert report["summary"]["parsed"] == 0
    assert report["summary"]["records"] == 1
    assert report["summary"]["unique_configurations"] == 0
    _assert_private_absent(json.dumps(report), source)


@pytest.mark.parametrize("bad", [b"not+base64!private-sentinel", b"A", b"abc===", b"%%%%"])
def test_bad_base64_outer_file_has_fixed_error_and_no_output(tmp_path, capsys, bad, no_network_or_engine):
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(bad)
    destination = tmp_path / "must-not-exist"
    with pytest.raises(OfflineFileError) as raised:
        run_file(source, destination, input_format="base64")
    assert raised.value.code == "INVALID_BASE64"
    assert not destination.exists()
    assert source.read_bytes() == bad
    captured = capsys.readouterr()
    error_text = str(raised.value) + repr(raised.value) + captured.out + captured.err
    _assert_private_absent(error_text, source)
    assert str(raised.value) == "INVALID_BASE64"
    if len(bad) > 8:
        assert bad.decode("ascii") not in error_text


def test_base64_decoded_invalid_utf8_is_a_record_not_outer_failure(tmp_path, no_network_or_engine):
    data = (_URI + "\n").encode("utf-8") + b"\xff\n"
    wrapped = base64.b64encode(data)
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(wrapped)
    report, folder = run_file(source, tmp_path / "outputs", input_format="base64")
    assert report == build_inventory(data)
    assert report["summary"]["parsed"] == 1
    assert report["summary"]["invalid"] == 1
    assert report["error_counts"] == {"INVALID_UTF8": 1}
    assert (folder / "COMPLETE.json").is_file()
    published = "".join(path.read_text(encoding="utf-8") for path in folder.iterdir())
    _assert_private_absent(published, source)
    assert wrapped.decode("ascii") not in published


def _cli_input(kind: str, data: bytes, tmp_path: Path, monkeypatch) -> tuple[list[str], Path | None]:
    if kind == "file":
        source = tmp_path / _PRIVATE_NAME
        source.write_bytes(data)
        return ["inventory-file", "--file", str(source)], source
    stream = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)
    return ["inventory-stdin"], None


@pytest.mark.parametrize("kind", ["file", "stdin"])
@pytest.mark.parametrize("output_format", ["json", "markdown"])
def test_explicit_base64_cli_file_and_stdin_are_anonymous(tmp_path, monkeypatch, capsys, kind, output_format, no_network_or_engine):
    args, source = _cli_input(kind, _WRAPPED, tmp_path, monkeypatch)
    assert main(args + ["--input-format", "base64", "--format", output_format]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    if output_format == "json":
        assert json.loads(output.out) == build_inventory(_RAW)
    else:
        assert "| 非空记录 | 2 |" in output.out
        assert "| 规范化配置组 | 1 |" in output.out
        assert "| 重复配置记录 | 1 |" in output.out
    _assert_private_absent(output.out + output.err, *([source] if source else []))
    assert PROBE_GATE_OPEN is False


@pytest.mark.parametrize("kind", ["file", "stdin"])
@pytest.mark.parametrize("data", [_RAW, _WRAPPED])
def test_cli_default_preserves_plain_input_and_never_guesses_wrapping(tmp_path, monkeypatch, capsys, kind, data, no_network_or_engine):
    args, source = _cli_input(kind, data, tmp_path, monkeypatch)
    assert main(args) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == build_inventory(data)
    assert output.err == ""
    _assert_private_absent(output.out + output.err, *([source] if source else []))


@pytest.mark.parametrize("kind", ["file", "stdin"])
def test_bad_base64_cli_emits_no_partial_inventory_or_private_input(tmp_path, monkeypatch, capsys, kind, no_network_or_engine):
    bad = _WRAPPED + b"!fictional-outer-sentinel"
    args, source = _cli_input(kind, bad, tmp_path, monkeypatch)
    assert main(args + ["--input-format", "base64"]) == 2
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["error_code"] == "INVALID_BASE64"
    assert result["complete"] is False
    assert "summary" not in result and "records" not in result
    assert output.err == ""
    _assert_private_absent(output.out + output.err, *([source] if source else []))
    assert "fictional-outer-sentinel" not in output.out + output.err
    assert not list(tmp_path.rglob("COMPLETE.json"))


@pytest.mark.skipif(os.name != "nt", reason="Windows/Tk GUI integration requires a Windows runner")
def test_windows_gui_base64_selection_and_failure_clear_summary(tmp_path, monkeypatch):
    import tkinter as tk
    from tkinter import filedialog, ttk

    namespace = runpy.run_path(str(_ROOT / "scripts/nodelab_offline.pyw"), run_name="subscription_gui_test")
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(_WRAPPED)
    bad_source = tmp_path / "fictional-bad-subscription.txt"
    bad_source.write_bytes(b"%%%%!fictional-outer-sentinel")
    local = tmp_path / "local"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    window = tk.Tk()
    window.withdraw()
    monkeypatch.setattr(tk, "Tk", lambda: window)
    buttons, combos, texts = [], [], []
    original_button, original_combo, original_text = ttk.Button, ttk.Combobox, tk.Text

    def capture_button(*args, **kwargs):
        widget = original_button(*args, **kwargs)
        buttons.append(widget)
        return widget

    def capture_combo(*args, **kwargs):
        widget = original_combo(*args, **kwargs)
        combos.append(widget)
        return widget

    def capture_text(*args, **kwargs):
        widget = original_text(*args, **kwargs)
        texts.append(widget)
        return widget

    monkeypatch.setattr(ttk, "Button", capture_button)
    monkeypatch.setattr(ttk, "Combobox", capture_combo)
    monkeypatch.setattr(tk, "Text", capture_text)
    selections = iter([str(source), str(bad_source)])
    monkeypatch.setattr(filedialog, "askopenfilename", lambda **kwargs: next(selections))
    clipboard = []
    monkeypatch.setattr(window, "clipboard_clear", lambda: None)
    monkeypatch.setattr(window, "clipboard_append", clipboard.append)
    outcome = {"stage": "start"}
    deadline = time.monotonic() + 20

    def tick():
        if time.monotonic() > deadline:
            outcome["timeout"] = True
            window.destroy()
            return
        if outcome["stage"] == "success" and str(buttons[1]["state"]) == "normal":
            buttons[1].invoke()
            outcome["success_reports"] = list(local.rglob("COMPLETE.json"))
            combos[0].current(1)
            buttons[0].invoke()
            outcome["stage"] = "failure"
        elif outcome["stage"] == "failure" and str(buttons[0]["state"]) == "normal":
            outcome["copy_disabled"] = str(buttons[1]["state"]) == "disabled"
            buttons[1].invoke()
            outcome["message"] = texts[0].get("1.0", "end")
            outcome["reports_after_failure"] = list(local.rglob("COMPLETE.json"))
            window.destroy()
            return
        window.after(50, tick)

    def begin():
        if len(combos) != 1:
            outcome["missing_format_selector"] = True
            window.destroy()
            return
        outcome["readonly"] = str(combos[0]["state"]) == "readonly"
        combos[0].current(1)
        buttons[0].invoke()
        outcome["stage"] = "success"
        window.after(50, tick)

    window.after(100, begin)
    assert namespace["_gui"]() == 0
    assert "timeout" not in outcome
    assert "missing_format_selector" not in outcome
    assert outcome["readonly"] is True
    assert outcome["copy_disabled"] is True
    assert len(outcome["success_reports"]) == 1
    assert len(outcome["reports_after_failure"]) == 1
    assert len(clipboard) == 1
    assert "非空记录：2" in clipboard[0]
    assert "解析成功：2" in clipboard[0]
    assert "INVALID_BASE64" in outcome["message"]
    published = "".join(path.read_text(encoding="utf-8") for path in local.rglob("*") if path.is_file())
    _assert_private_absent(published + clipboard[0] + outcome["message"], source, bad_source)
    assert "fictional-outer-sentinel" not in outcome["message"]
    assert source.read_bytes() == _WRAPPED
