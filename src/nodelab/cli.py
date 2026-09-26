"""Secret-safe local CLI; live probing remains disabled until F3/W2 gates."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from nodelab.parser import parse_uri
from nodelab.redaction import redacted_node_dict, redacted_result_dict
from nodelab.types import NodeURIParseError

_MAX_INPUT_BYTES = 512 * 1024
_MAX_LINE_BYTES = 8192


class _ArgumentsInvalid(Exception):
    pass


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's default includes the entire unknown argv, possibly a URI.
        raise _ArgumentsInvalid


def _emit(result: Any) -> None:
    print(json.dumps(redacted_result_dict(result), ensure_ascii=False, separators=(",", ":")))


def _failure(code: str, stage: str = "INPUT") -> int:
    _emit({"probe_status": "FAIL", "stage": stage, "error_code": code})
    return 2


def _parse_lines(data: bytes, limit: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for line_number, line in enumerate(data.split(b"\n"), 1):
        if len(results) >= limit:
            break
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line.strip():
            continue
        if len(line) > _MAX_LINE_BYTES:
            result = {"line_number": line_number, "probe_status": "FAIL", "stage": "PARSE", "error_code": "LINE_TOO_LONG"}
        else:
            try:
                node = parse_uri(line.decode("utf-8", errors="strict"))
                result = redacted_node_dict(node)
                # Parsing under the old model does not certify a probe dialect.
                result.update(line_number=line_number, probe_status="UNSUPPORTED", stage="PARSE",
                              error_code="PROBE_GATE_CLOSED")
            except UnicodeDecodeError:
                result = {"line_number": line_number, "probe_status": "FAIL", "stage": "PARSE", "error_code": "INVALID_UTF8"}
            except NodeURIParseError as exc:
                result = {"line_number": line_number, "probe_status": "FAIL", "stage": "PARSE", "error_code": exc.code}
            except (ValueError, OverflowError):
                result = {"line_number": line_number, "probe_status": "FAIL", "stage": "PARSE", "error_code": "INVALID_URI"}
        results.append(redacted_result_dict(result))
    return results


def _cmd_parse_file(args: argparse.Namespace) -> int:
    if not 1 <= args.limit <= 100:
        return _failure("INVALID_ARGUMENTS")
    try:
        path = Path(args.file)
        if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_INPUT_BYTES:
            return _failure("INPUT_FILE_UNSAFE")
        data = path.read_bytes()
        if len(data) > _MAX_INPUT_BYTES:
            return _failure("INPUT_TOO_LARGE")
    except (OSError, ValueError):
        return _failure("INPUT_FILE_UNSAFE")
    _emit(_parse_lines(data, args.limit))
    return 0


def _cmd_parse_stdin(args: argparse.Namespace) -> int:
    if not 1 <= args.limit <= 100:
        return _failure("INVALID_ARGUMENTS")
    if sys.stdin.isatty():
        return _failure("INPUT_FILE_UNSAFE")
    try:
        data = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
        if len(data) > _MAX_INPUT_BYTES:
            return _failure("INPUT_TOO_LARGE")
    except (OSError, ValueError, AttributeError):
        return _failure("INPUT_FILE_UNSAFE")
    _emit(_parse_lines(data, args.limit))
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    # Reject legacy URI argv before argparse can quote unknown argument text.
    if argv and argv[0] in {"parse", "probe"}:
        return _failure("URI_ARGV_FORBIDDEN")

    parser = _SafeArgumentParser(prog="nodelab", add_help=True)
    sub = parser.add_subparsers(dest="command", parser_class=_SafeArgumentParser)
    p_pf = sub.add_parser("parse-file", help="Parse a small local file into fixed public fields")
    p_pf.add_argument("--file", required=True)
    p_pf.add_argument("--limit", type=int, default=1)
    p_ps = sub.add_parser("parse-stdin", help="Read input from a protected-file pipe")
    p_ps.add_argument("--limit", type=int, default=1)
    p_probe = sub.add_parser("probe-file", help="Reserved until route-proof and Windows gates")
    p_probe.add_argument("--file", required=True)
    p_probe.add_argument("--limit", type=int, default=1)
    sub.add_parser("probe-stdin", help="Reserved until route-proof and Windows gates")
    try:
        args = parser.parse_args(argv)
    except _ArgumentsInvalid:
        return _failure("INVALID_ARGUMENTS")
    except SystemExit as exc:  # --help, whose text contains no user-supplied args
        return 0 if exc.code == 0 else _failure("INVALID_ARGUMENTS")

    if args.command == "parse-file":
        return _cmd_parse_file(args)
    if args.command == "parse-stdin":
        return _cmd_parse_stdin(args)
    if args.command in {"probe-file", "probe-stdin"}:
        # Do not even open the input while P0-01/03/07 remain unclosed.
        return _failure("PROBE_GATE_CLOSED", "ROUTE")
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
