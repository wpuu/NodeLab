"""Synthetic acceptance checks for the local-only entry and publication boundary.

No owner file or real node is opened. Audit hooks run in disposable Python
children because hooks cannot be removed from the pytest interpreter.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import nodelab.offline_file as offline_file
from nodelab.inventory import MAX_INPUT_BYTES, build_inventory
from nodelab.offline_file import OfflineFileError, inspect_file, run_file, save_reports

_SECRET = "fictional-secret-sentinel"
_HOST = "fictional-host-sentinel.example.invalid"
_PRIVATE_NAME = "fictional-private-path-sentinel.txt"
_URI = f"trojan://{_SECRET}@{_HOST}:443?security=tls#fictional-label-sentinel"
_REPO = Path(__file__).resolve().parents[1]
_ENTRY = _REPO / "scripts" / "nodelab_offline.pyw"


def assert_private_values_absent(text: str, source: Path | None = None) -> None:
    for value in (_SECRET, _HOST, _PRIVATE_NAME, _URI, "fictional-label-sentinel"):
        assert value not in text
    if source is not None:
        assert str(source) not in text


def test_one_file_produces_matching_reports_without_modifying_input(tmp_path, capsys):
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(b"\xef\xbb\xbf" + (_URI + "\r\n\r\n" + _URI + "\r\n").encode())
    before = source.stat()
    before_content = source.read_bytes()
    report, folder = run_file(source, tmp_path / "outputs")
    assert source.read_bytes() == before_content
    assert source.stat().st_mtime_ns == before.st_mtime_ns
    assert source.stat().st_size == before.st_size
    assert json.loads((folder / "inventory.json").read_text(encoding="utf-8")) == report
    assert report["summary"]["records"] == 2
    assert report["summary"]["duplicate_records"] == 1
    assert report["complete"] is True and report["network_used"] is False
    markdown = (folder / "inventory.md").read_text(encoding="utf-8")
    assert "\u79bb\u7ebf" in markdown and "\u672a\u77e5" in markdown
    assert "C000001" in markdown and "R000002" in markdown
    marker = json.loads((folder / "COMPLETE.json").read_text(encoding="utf-8"))
    assert marker["status"] == "COMPLETE"
    assert marker["network_requests"] == 0 and marker["engine_started"] is False
    assert set(p.name for p in folder.iterdir()) == {"inventory.json", "inventory.md", "COMPLETE.json"}
    captured = capsys.readouterr()
    published = "".join(p.read_text(encoding="utf-8") for p in folder.iterdir())
    assert_private_values_absent(published + captured.out + captured.err, source)


def test_exact_byte_limit_accepted_and_excess_rejected_without_partial_output(tmp_path):
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(b" " * MAX_INPUT_BYTES)
    assert inspect_file(source)["summary"]["records"] == 0
    source.write_bytes(b" " * (MAX_INPUT_BYTES + 1))
    destination = tmp_path / "must-not-be-created"
    with pytest.raises(OfflineFileError) as raised:
        run_file(source, destination)
    assert raised.value.code == "INPUT_TOO_LARGE"
    assert not destination.exists()
    assert_private_values_absent(str(raised.value) + repr(raised.value), source)


def test_empty_and_bad_utf8_are_accounted_without_echoing_input(tmp_path):
    source = tmp_path / _PRIVATE_NAME
    source.write_bytes(b"")
    assert inspect_file(source)["summary"]["records"] == 0
    source.write_bytes((_URI + "\n").encode() + b"\xff\n")
    report = inspect_file(source)
    assert report["summary"]["parsed"] == 1
    assert report["summary"]["invalid"] == 1
    assert report["error_counts"] == {"INVALID_UTF8": 1}
    assert_private_values_absent(json.dumps(report), source)


@pytest.mark.parametrize("kind,code", [("unreadable", "INPUT_UNSAFE"), ("parser", "INVENTORY_FAILED")])
def test_private_exception_messages_do_not_escape(tmp_path, monkeypatch, capsys, kind, code):
    source = tmp_path / _PRIVATE_NAME
    source.write_text(_URI, encoding="utf-8")
    if kind == "unreadable":
        original_open = Path.open

        def failing_open(self, *args, **kwargs):
            if self == source:
                raise PermissionError(str(source) + _URI)
            return original_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", failing_open)
    else:
        def failing_parser(data):
            raise RuntimeError(str(source) + _URI)

        monkeypatch.setattr(offline_file, "build_inventory", failing_parser)
    with pytest.raises(OfflineFileError) as raised:
        inspect_file(source)
    assert raised.value.code == code
    captured = capsys.readouterr()
    assert_private_values_absent(str(raised.value) + repr(raised.value) + captured.out + captured.err, source)


def test_nonfile_and_relative_input_are_rejected(tmp_path):
    for source in (tmp_path, Path(_PRIVATE_NAME), tmp_path / _PRIVATE_NAME):
        with pytest.raises(OfflineFileError) as raised:
            inspect_file(source)
        assert raised.value.code == "INPUT_UNSAFE"
        assert_private_values_absent(str(raised.value) + repr(raised.value), source)


def test_report_write_failure_has_no_completion_marker(tmp_path, monkeypatch):
    report = build_inventory(_URI)
    original_open = Path.open

    def failing_open(self, *args, **kwargs):
        if self.name == "inventory.md":
            raise PermissionError(_URI + _PRIVATE_NAME)
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)
    destination = tmp_path / "outputs"
    with pytest.raises(OfflineFileError) as raised:
        save_reports(report, destination)
    assert raised.value.code == "OUTPUT_FAILED"
    assert not list(destination.rglob("COMPLETE.json"))
    assert_private_values_absent(str(raised.value) + repr(raised.value))


def test_completion_marker_write_failure_cannot_leave_a_success_marker(tmp_path, monkeypatch):
    def interrupted_dump(*args, **kwargs):
        args[1].write('{"status": "COMPLETE",')
        raise OSError(_URI + _PRIVATE_NAME)

    monkeypatch.setattr(offline_file.json, "dump", interrupted_dump)
    destination = tmp_path / "outputs"
    with pytest.raises(OfflineFileError) as raised:
        save_reports(build_inventory(_URI), destination)
    assert raised.value.code == "OUTPUT_FAILED"
    assert not list(destination.rglob("COMPLETE.json"))
    assert_private_values_absent(str(raised.value) + repr(raised.value))


def test_completion_marker_publish_failure_cannot_leave_a_success_marker(tmp_path, monkeypatch):
    def failed_replace(*args, **kwargs):
        raise OSError(_URI + _PRIVATE_NAME)

    monkeypatch.setattr(offline_file.os, "replace", failed_replace)
    destination = tmp_path / "outputs"
    with pytest.raises(OfflineFileError) as raised:
        save_reports(build_inventory(_URI), destination)
    assert raised.value.code == "OUTPUT_FAILED"
    assert not list(destination.rglob("COMPLETE.json"))
    assert_private_values_absent(str(raised.value) + repr(raised.value))


def test_forged_public_report_is_rejected_before_creating_output(tmp_path):
    report = build_inventory(_URI)
    report["private_uri"] = _URI
    destination = tmp_path / "not-created"
    with pytest.raises(OfflineFileError) as raised:
        save_reports(report, destination)
    assert raised.value.code == "OUTPUT_FAILED"
    assert not destination.exists()
    assert_private_values_absent(str(raised.value) + repr(raised.value))


def test_reports_are_unique_and_a_collision_never_overwrites_existing_files(tmp_path, monkeypatch):
    destination = tmp_path / "outputs"
    report = build_inventory(_URI)
    first = save_reports(report, destination)
    second = save_reports(report, destination)
    assert first != second
    original = {p.name: p.read_bytes() for p in first.iterdir()}
    monkeypatch.setattr(offline_file.uuid, "uuid4", lambda: SimpleNamespace(hex=first.name.removeprefix("report-")))
    with pytest.raises(OfflineFileError) as raised:
        save_reports(build_inventory(b""), destination)
    assert raised.value.code == "OUTPUT_FAILED"
    assert {p.name: p.read_bytes() for p in first.iterdir()} == original
    assert len(list(destination.iterdir())) == 2


def test_symlink_input_and_symlink_parent_are_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    source = target / _PRIVATE_NAME
    source.write_text(_URI, encoding="utf-8")
    direct = tmp_path / "linked-input.txt"
    parent = tmp_path / "linked-parent"
    try:
        direct.symlink_to(source)
        parent.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks is not allowed in this runner")
    for candidate in (direct, parent / _PRIVATE_NAME):
        with pytest.raises(OfflineFileError) as raised:
            inspect_file(candidate)
        assert raised.value.code == "INPUT_UNSAFE"
    with pytest.raises(OfflineFileError) as raised:
        save_reports(build_inventory(_URI), parent / "outputs")
    assert raised.value.code == "OUTPUT_UNSAFE"


@pytest.mark.skipif(os.name != "nt", reason="Windows path and drive policy")
@pytest.mark.parametrize("raw", [r"\\server\share\secret.txt", r"\\?\C:\secret.txt", r"\\.\C:\secret.txt", r"C:\secret.txt:stream", r"C:\CON"])
def test_windows_special_paths_are_rejected_before_metadata_access(monkeypatch, raw):
    def forbidden_metadata(*args, **kwargs):
        pytest.fail("Unsafe path reached filesystem metadata")

    monkeypatch.setattr(Path, "lstat", forbidden_metadata)
    with pytest.raises(OfflineFileError) as raised:
        offline_file._check_local_path(Path(raw))
    assert raised.value.code == "INPUT_UNSAFE"


@pytest.mark.skipif(os.name != "nt", reason="Windows path and drive policy")
@pytest.mark.parametrize("drive_kind", [0, 1, 4, 5, 6])
def test_windows_network_or_unrecognized_drive_is_rejected_before_stat(tmp_path, monkeypatch, drive_kind):
    monkeypatch.setattr(offline_file, "_drive_type", lambda root: drive_kind)
    monkeypatch.setattr(Path, "lstat", lambda *args, **kwargs: pytest.fail("Rejected drive reached metadata"))
    with pytest.raises(OfflineFileError) as raised:
        offline_file._check_local_path(tmp_path / _PRIVATE_NAME)
    assert raised.value.code == "INPUT_UNSAFE"


@pytest.mark.skipif(os.name != "nt", reason="Windows file attributes")
@pytest.mark.parametrize("attributes", [0x400, 0x1000, 0x40000, 0x400000])
def test_windows_reparse_and_cloud_placeholder_attributes_are_rejected(tmp_path, monkeypatch, attributes):
    monkeypatch.setattr(offline_file, "_drive_type", lambda root: 3)
    monkeypatch.setattr(Path, "lstat", lambda *args, **kwargs: SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_file_attributes=attributes))
    with pytest.raises(OfflineFileError) as raised:
        offline_file._check_local_path(tmp_path / _PRIVATE_NAME)
    assert raised.value.code == "INPUT_UNSAFE"


@pytest.mark.parametrize("attributes", [0x400, 0x1000, 0x40000, 0x400000])
def test_opened_handle_attributes_are_checked_before_reading(tmp_path, monkeypatch, attributes):
    source = tmp_path / _PRIVATE_NAME
    source.write_text(_URI, encoding="utf-8")
    actual = source.stat()
    opened = SimpleNamespace(st_mode=actual.st_mode, st_dev=actual.st_dev, st_ino=actual.st_ino, st_file_attributes=attributes)
    monkeypatch.setattr(offline_file.os, "fstat", lambda fd: opened)
    original_open = Path.open

    class GuardedHandle:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.handle.close()

        def fileno(self):
            return self.handle.fileno()

        def read(self, *args):
            pytest.fail("Unsafe opened handle reached read")

    def guarded_open(self, *args, **kwargs):
        handle = original_open(self, *args, **kwargs)
        return GuardedHandle(handle) if self == source else handle

    monkeypatch.setattr(Path, "open", guarded_open)
    with pytest.raises(OfflineFileError) as raised:
        inspect_file(source)
    assert raised.value.code == "INPUT_UNSAFE"
    assert_private_values_absent(str(raised.value) + repr(raised.value), source)


def test_guard_blocks_actual_dns_socket_and_child_process_operations_in_child():
    child = r'''
import json, os, runpy, socket, subprocess, sys
namespace = runpy.run_path(sys.argv[1], run_name="offline_entry_audit_test")
connection = socket.socket()
namespace["install_offline_guard"]()
operations = {
    "dns": lambda: socket.getaddrinfo("localhost", 9),
    "socket_create": lambda: socket.socket(),
    "socket_connect": lambda: connection.connect(("127.0.0.1", 9)),
    "child_process": lambda: subprocess.Popen([sys.executable, "-c", "pass"]),
    "shell": lambda: os.system("exit 0"),
}
results = {}
for name, operation in operations.items():
    try:
        operation()
    except RuntimeError as exc:
        results[name] = str(exc)
    except Exception:
        results[name] = "WRONG_FAILURE"
    else:
        results[name] = "NOT_BLOCKED"
connection.close()
from nodelab.inventory import build_inventory
from nodelab.types import PROBE_GATE_OPEN
build_inventory(b"trojan://FICTIONAL_ONLY@demo.example.invalid:443\n")
forbidden = {"nodelab.cli", "nodelab.mihomo_config", "nodelab.probe", "nodelab.engine"}
print(json.dumps({"blocked": results, "engine_imports": sorted(forbidden.intersection(sys.modules)), "probe_gate": PROBE_GATE_OPEN}))
'''
    completed = subprocess.run([sys.executable, "-I", "-c", child, str(_ENTRY)], capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert set(result["blocked"]) == {"dns", "socket_create", "socket_connect", "child_process", "shell"}
    assert set(result["blocked"].values()) == {"OFFLINE_OPERATION_BLOCKED"}
    assert result["engine_imports"] == []
    assert result["probe_gate"] is False


def test_entry_self_check_runs_without_gui_or_node_input():
    completed = subprocess.run([sys.executable, "-I", str(_ENTRY), "--self-check"], capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {"self_check": "PASS", "mode": "FICTIONAL_ONLY", "network_used": False}


def test_entry_invalid_arguments_do_not_echo_private_text():
    completed = subprocess.run([sys.executable, "-I", str(_ENTRY), _URI, _PRIVATE_NAME], capture_output=True, text=True, timeout=30)
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr.strip() == "ARGUMENTS_FORBIDDEN"
    assert_private_values_absent(completed.stdout + completed.stderr)
