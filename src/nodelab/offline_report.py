"""Read and compare saved anonymous reports, without revisiting the input."""
from __future__ import annotations

import json
import os
import re
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from nodelab.inventory import build_input_metadata, render_inventory_report, validate_inventory
from nodelab.offline_file import OfflineFileError, _check_local_path

# A 512KiB input can contain 262,144 nonblank one-byte records. Keep the
# existing writer's capacity: these bounds cover its pretty JSON and Markdown.
# JSON parsing is byte bounded, but is not a streaming or constant-memory parser.
MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_MARKDOWN_BYTES = 128 * 1024 * 1024
MAX_MARKER_BYTES = 4096
_CHUNK_BYTES = 64 * 1024
_ATTRIBUTES = 0x400 | 0x1000 | 0x40000 | 0x400000
_CODES = frozenset({"REPORT_UNSAFE", "REPORT_TOO_LARGE", "REPORT_INVALID", "REPORT_MISMATCH"})
_MARKER_KEYS = frozenset({"status", "schema_version", "mode", "network_requests",
                          "engine_started", "created_at_utc", "files"})
_METADATA_KEYS = frozenset({"input_format", "line_number_basis", "decoding_passes"})
_UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\+00:00\Z")


class OfflineReportError(ValueError):
    def __init__(self, code: str):
        self.code = code if type(code) is str and code in _CODES else "REPORT_INVALID"
        super().__init__(self.code)


def _identity(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, getattr(info, "st_file_attributes", 0))


@contextmanager
def _open_checked(path: Path, limit: int, observed: dict):
    _check_local_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise OfflineReportError("REPORT_UNSAFE")
    if before.st_size > limit:
        raise OfflineReportError("REPORT_TOO_LARGE")
    # NONBLOCK prevents a substituted FIFO from hanging before fstat; NOFOLLOW
    # rejects a substituted final symlink where the platform supports it.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before)
                or getattr(opened, "st_file_attributes", 0) & _ATTRIBUTES):
            raise OfflineReportError("REPORT_UNSAFE")
        yield fd
        _check_local_path(path)
        if _identity(os.fstat(fd)) != _identity(before) or _identity(path.lstat()) != _identity(before):
            raise OfflineReportError("REPORT_UNSAFE")
        observed[path] = _identity(before)
    finally:
        os.close(fd)


def _read_file(path: Path, limit: int, observed: dict) -> bytes:
    chunks, total = [], 0
    with _open_checked(path, limit, observed) as fd:
        while True:
            chunk = os.read(fd, min(_CHUNK_BYTES, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise OfflineReportError("REPORT_TOO_LARGE")
            chunks.append(chunk)
    return b"".join(chunks)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("NON_JSON_NUMBER")


def _check_json_shape(data: bytes) -> None:
    # Every public string is a short enum/key/UTC stamp. Even a JSON spelling
    # that escapes every character fits 1024 bytes; no private free text exists.
    # Bound depth and tokens before json.loads allocates nested Python objects.
    first = next((char for char in data if char not in (9, 10, 13, 32)), None)
    if first != 123:
        raise OfflineReportError("REPORT_INVALID")
    depth, quoted, escaped, token = 0, False, False, 0
    for char in data:
        if quoted:
            token += 1
            if token > 1024:
                raise OfflineReportError("REPORT_INVALID")
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted, token = False, 0
        elif char == 34:
            quoted, token = True, 0
        elif char in (91, 123):
            depth += 1
            token = 0
            if depth > 8:
                raise OfflineReportError("REPORT_INVALID")
        elif char in (93, 125):
            depth -= 1
            token = 0
            if depth < 0:
                raise OfflineReportError("REPORT_INVALID")
        elif char in (9, 10, 13, 32, 44, 58):
            token = 0
        else:
            token += 1
            if token > 64:
                raise OfflineReportError("REPORT_INVALID")


def _json(data: bytes):
    _check_json_shape(data)
    return json.loads(data.decode("utf-8", errors="strict"),
                      object_pairs_hook=_object, parse_constant=_reject_constant)


def _validate_marker(marker: object) -> tuple[int, dict]:
    if type(marker) is not dict or type(marker.get("schema_version")) is not int:
        raise OfflineReportError("REPORT_INVALID")
    version = marker["schema_version"]
    keys = _MARKER_KEYS if version == 1 else _MARKER_KEYS | _METADATA_KEYS
    if version not in {1, 2} or set(marker) != keys:
        raise OfflineReportError("REPORT_INVALID")
    if (type(marker["status"]) is not str or marker["status"] != "COMPLETE"
            or type(marker["mode"]) is not str or marker["mode"] != "offline_file"
            or type(marker["network_requests"]) is not int or marker["network_requests"] != 0
            or marker["engine_started"] is not False
            or type(marker["files"]) is not list or marker["files"] != ["inventory.json", "inventory.md"]):
        raise OfflineReportError("REPORT_INVALID")
    stamp = marker["created_at_utc"]
    if type(stamp) is not str or not _UTC_TIMESTAMP.fullmatch(stamp):
        raise OfflineReportError("REPORT_INVALID")
    if datetime.fromisoformat(stamp).tzinfo != timezone.utc:
        raise OfflineReportError("REPORT_INVALID")
    metadata = build_input_metadata("not_recorded" if version == 1 else marker["input_format"])
    if version == 2:
        for key, value in metadata.items():
            if type(marker[key]) is not type(value) or marker[key] != value:
                raise OfflineReportError("REPORT_INVALID")
    return version, metadata


def _compare_markdown(path: Path, expected: str, observed: dict) -> None:
    data = expected.encode("utf-8")
    if len(data) > MAX_MARKDOWN_BYTES:
        raise OfflineReportError("REPORT_TOO_LARGE")
    with _open_checked(path, MAX_MARKDOWN_BYTES, observed) as fd:
        position = 0
        while True:
            actual = os.read(fd, _CHUNK_BYTES)
            if not actual:
                break
            end = position + len(actual)
            if end > MAX_MARKDOWN_BYTES:
                raise OfflineReportError("REPORT_TOO_LARGE")
            if actual != data[position:end]:
                raise OfflineReportError("REPORT_MISMATCH")
            position = end
        if position != len(data):
            raise OfflineReportError("REPORT_MISMATCH")


def load_reports(folder: Path) -> dict:
    """Check fixed files and return validated public data; never return raw text.

    This is consistency checking, not authorship or input-origin verification.
    The caller receives a freshly rendered public Markdown, also for legacy v1.
    """
    try:
        _check_local_path(folder)
        before = folder.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise OfflineReportError("REPORT_UNSAFE")
        observed = {}
        version, metadata = _validate_marker(_json(_read_file(folder / "COMPLETE.json", MAX_MARKER_BYTES, observed)))
        report = _json(_read_file(folder / "inventory.json", MAX_REPORT_BYTES, observed))
        validate_inventory(report)
        markdown = render_inventory_report(report, input_format=metadata["input_format"])
        expected = markdown
        if version == 1:
            # Pinned v1 writer predates the four-line format explanation block.
            # Never infer a historical wrapper from its anonymous inventory.
            lines = markdown.split("\n")
            expected = "\n".join(lines[:4] + lines[8:])
        _compare_markdown(folder / "inventory.md", expected, observed)
        for path, identity in observed.items():
            _check_local_path(path)
            if _identity(path.lstat()) != identity:
                raise OfflineReportError("REPORT_UNSAFE")
        _check_local_path(folder)
        after = folder.lstat()
        if not stat.S_ISDIR(after.st_mode) or _identity(before) != _identity(after):
            raise OfflineReportError("REPORT_UNSAFE")
        return {"report": report, "metadata": metadata,
                "marker_schema_version": version, "markdown": markdown}
    except OfflineReportError:
        raise
    except (OfflineFileError, OSError, TypeError, AttributeError):
        raise OfflineReportError("REPORT_UNSAFE") from None
    except Exception:
        raise OfflineReportError("REPORT_INVALID") from None
