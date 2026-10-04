"""Synthetic command-level checks; neither a real URI nor an engine is used."""

from __future__ import annotations

import io
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from nodelab.cli import main
from nodelab.inventory import MAX_INPUT_BYTES
from nodelab.types import PROBE_GATE_OPEN

_SECRET = "fictional-cli-secret"
_HOST = "fictional-cli-host.example.invalid"
_URI = f"trojan://{_SECRET}@{_HOST}:443?security=tls"


@pytest.fixture
def no_network_or_engine(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline command attempted network or subprocess")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


def test_file_command_processes_all_records_and_emits_no_secrets(tmp_path, capsys, no_network_or_engine):
    path = tmp_path / "private-input.txt"
    path.write_text("\n".join([_URI] * 105), encoding="utf-8")
    assert main(["inventory-file", "--file", str(path)]) == 0
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["summary"]["records"] == 105
    assert result["summary"]["unique_configurations"] == 1
    assert result["summary"]["duplicate_records"] == 104
    assert result["complete"] is True
    assert output.err == ""
    for value in (_SECRET, _HOST, _URI, str(path)):
        assert value not in output.out
    assert PROBE_GATE_OPEN is False


def test_markdown_command_uses_same_counts(tmp_path, capsys, no_network_or_engine):
    path = tmp_path / "private-input.txt"
    path.write_text(_URI + "\n" + _URI, encoding="utf-8")
    assert main(["inventory-file", "--file", str(path), "--format", "markdown"]) == 0
    out = capsys.readouterr()
    assert "| 非空记录 | 2 |" in out.out
    assert "| 规范化配置组 | 1 |" in out.out
    assert "| 重复配置记录 | 1 |" in out.out
    assert "独立线路" in out.out and "未知" in out.out
    assert _SECRET not in out.out and _HOST not in out.out
    assert out.err == ""


def test_stdin_command_handles_blank_and_bad_lines(monkeypatch, capsys, no_network_or_engine):
    fake = io.TextIOWrapper(io.BytesIO((_URI + "\n\n").encode() + b"\xff\n"), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", fake)
    assert main(["inventory-stdin"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["physical_lines"] == 3
    assert result["summary"]["blank_lines"] == 1
    assert result["summary"]["parsed"] == 1
    assert result["summary"]["invalid"] == 1


@pytest.mark.parametrize("argument", ["relative-private.txt", _URI])
def test_unsafe_file_input_does_not_echo_argument(argument, capsys):
    assert main(["inventory-file", "--file", argument]) == 2
    out = capsys.readouterr()
    result = json.loads(out.out)
    assert result["error_code"] == "INPUT_FILE_UNSAFE"
    assert result["complete"] is False
    assert argument not in out.out + out.err


def test_oversized_stdin_has_no_partial_or_complete_counts(monkeypatch, capsys):
    fake = io.TextIOWrapper(io.BytesIO(b"x" * (MAX_INPUT_BYTES + 1)), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", fake)
    assert main(["inventory-stdin"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["error_code"] == "INPUT_TOO_LARGE"
    assert result["complete"] is False
    assert "summary" not in result


def test_unexpected_error_text_is_not_published(monkeypatch, tmp_path, capsys):
    path = tmp_path / "private-input.txt"
    path.write_text(_URI, encoding="utf-8")
    def broken(data):
        raise RuntimeError(_URI)
    monkeypatch.setattr("nodelab.cli.build_inventory", broken)
    assert main(["inventory-file", "--file", str(path)]) == 2
    out = capsys.readouterr()
    assert json.loads(out.out)["error_code"] == "INVENTORY_FAILED"
    assert _SECRET not in out.out + out.err


def test_unknown_cli_argument_remains_secret_safe(capsys):
    assert main(["inventory-stdin", "--unexpected", _URI]) == 2
    out = capsys.readouterr()
    assert _URI not in out.out + out.err
    assert _SECRET not in out.out + out.err


def test_live_probe_command_stays_closed(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("closed probe tried to open private input")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    assert main(["probe-file", "--file", _URI]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "PROBE_GATE_CLOSED"
    assert PROBE_GATE_OPEN is False
