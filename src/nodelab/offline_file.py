"""One chosen local file to anonymous reports. No engine, recovery or network."""
from __future__ import annotations

import ctypes
import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

from nodelab.inventory import MAX_INPUT_BYTES, InventoryInputError, build_inventory, build_input_metadata, render_inventory_report
from nodelab.subscription_input import decode_subscription_input

_CODES = frozenset({"INPUT_UNSAFE", "INPUT_TOO_LARGE", "OUTPUT_UNSAFE", "OUTPUT_FAILED", "INVENTORY_FAILED", "INVALID_BASE64", "INVALID_ARGUMENTS"})


class OfflineFileError(ValueError):
    def __init__(self, code: str):
        self.code = code if code in _CODES else "INVENTORY_FAILED"
        super().__init__(self.code)


def _drive_type(root: str) -> int:
    api = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
    api.argtypes = [ctypes.c_wchar_p]
    api.restype = ctypes.c_uint
    return int(api(root))


def _check_local_path(path: Path, *, output: bool = False) -> None:
    code = "OUTPUT_UNSAFE" if output else "INPUT_UNSAFE"
    if not path.is_absolute():
        raise OfflineFileError(code)
    if os.name == "nt":
        # Reject UNC, extended/device namespaces, ADS and mapped network drives
        # before stat/resolve/open can hydrate a remote or placeholder file.
        if (len(path.drive) != 2 or not path.drive[0].isascii()
                or not path.drive[0].isalpha() or path.drive[1] != ":"
                or path.is_reserved() or any(":" in p for p in path.parts[1:])):
            raise OfflineFileError(code)
        if _drive_type(path.anchor) not in {2, 3}:  # removable / fixed only
            raise OfflineFileError(code)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if output:
                break
            raise OfflineFileError(code) from None
        except OSError:
            raise OfflineFileError(code) from None
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or attributes & (0x400 | 0x1000 | 0x40000 | 0x400000):
            # Reparse, offline, recall-on-open, recall-on-data-access.
            raise OfflineFileError(code)


def inspect_file(source: Path, *, input_format: str = "uri_lines") -> dict:
    """Read at most limit+1; raw input stays in process memory."""
    try:
        if type(input_format) is not str or input_format not in {"uri_lines", "base64"}:
            raise OfflineFileError("INVALID_ARGUMENTS")
        _check_local_path(source)
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise OfflineFileError("INPUT_UNSAFE")
        if before.st_size > MAX_INPUT_BYTES:
            raise OfflineFileError("INPUT_TOO_LARGE")
        with source.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (not stat.S_ISREG(opened.st_mode)
                    or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                    or getattr(opened, "st_file_attributes", 0) & (0x400 | 0x1000 | 0x40000 | 0x400000)):
                raise OfflineFileError("INPUT_UNSAFE")
            data = handle.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise OfflineFileError("INPUT_TOO_LARGE")
        return build_inventory(decode_subscription_input(data, input_format=input_format))
    except OfflineFileError:
        raise
    except InventoryInputError as exc:
        code = exc.code if exc.code in {"INPUT_TOO_LARGE", "INVALID_BASE64", "INVALID_ARGUMENTS"} else "INVENTORY_FAILED"
        raise OfflineFileError(code) from None
    except (OSError, ValueError):
        raise OfflineFileError("INPUT_UNSAFE") from None
    except Exception:
        raise OfflineFileError("INVENTORY_FAILED") from None


def save_reports(report: dict, destination: Path, *, input_format: str = "not_recorded") -> Path:
    """All serialized contents are validated before any file is written."""
    try:
        metadata = build_input_metadata(input_format)
        markdown = render_inventory_report(report, input_format=input_format)
        contents = {
            "inventory.json": json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            "inventory.md": markdown,
        }
        completed = {
            "status": "COMPLETE", "schema_version": 2, "mode": "offline_file",
            "network_requests": 0, "engine_started": False,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "files": ["inventory.json", "inventory.md"],
            **metadata,
        }
        # Reject nonserializable metadata before touching any destination.
        json.dumps(completed, ensure_ascii=False)
        _check_local_path(destination, output=True)
        destination.mkdir(parents=True, exist_ok=True)
        _check_local_path(destination, output=True)
        if not destination.is_dir():
            raise OfflineFileError("OUTPUT_UNSAFE")
        folder = destination / ("report-" + uuid.uuid4().hex)
        folder.mkdir()  # no reuse/overwrite, even if a UUID collision is injected
        for name, text in contents.items():
            with (folder / name).open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        # Publish a marker only after its entire contents reach the file.
        temporary = folder / ".complete.tmp"
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(completed, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, folder / "COMPLETE.json")
        return folder
    except OfflineFileError:
        raise
    except InventoryInputError as exc:
        raise OfflineFileError("INVALID_ARGUMENTS" if exc.code == "INVALID_ARGUMENTS" else "OUTPUT_FAILED") from None
    except Exception:
        raise OfflineFileError("OUTPUT_FAILED") from None


def run_file(source: Path, destination: Path, *, input_format: str = "uri_lines") -> tuple[dict, Path]:
    report = inspect_file(source, input_format=input_format)
    return report, save_reports(report, destination, input_format=input_format)
