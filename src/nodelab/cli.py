"""NodeLab CLI: parse / probe / probe-file. All output is redacted JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from nodelab.parser import parse_uri, parse_uris, redact_uri
from nodelab.probe import probe_node, probe_from_file, save_probe_results
from nodelab.redaction import redacted_node_dict, redacted_result_dict
from nodelab.types import NodeURIParseError


def _cmd_parse(args: argparse.Namespace) -> int:
    try:
        node = parse_uri(args.uri)
    except NodeURIParseError as exc:
        print(json.dumps({"error": redact_uri(str(exc))}, ensure_ascii=False))
        return 2
    print(json.dumps(redacted_node_dict(node), indent=2, ensure_ascii=False))
    return 0


def _cmd_probe(args: argparse.Namespace) -> int:
    try:
        node = parse_uri(args.uri)
    except NodeURIParseError as exc:
        print(json.dumps({"error": redact_uri(str(exc))}, ensure_ascii=False))
        return 2
    result = probe_node(node)
    print(json.dumps(redacted_result_dict(result), indent=2, ensure_ascii=False))
    return 0


def _cmd_probe_file(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        print(json.dumps({"error": f"file not found: {path}"}, ensure_ascii=False))
        return 2
    results = probe_from_file(str(path), limit=args.limit)
    out_path = save_probe_results(results)
    print(json.dumps(redacted_result_dict(results), indent=2, ensure_ascii=False))
    print(f"results written to {out_path}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nodelab")
    sub = parser.add_subparsers(dest="command")

    p_parse = sub.add_parser("parse", help="Parse a URI into a redacted node dict")
    p_parse.add_argument("uri")

    p_probe = sub.add_parser("probe", help="Run a full probe for one URI")
    p_probe.add_argument("uri")

    p_pf = sub.add_parser("probe-file", help="Probe each line of a file, limited to --limit entries")
    p_pf.add_argument("file")
    p_pf.add_argument("--limit", type=int, default=2)

    args = parser.parse_args(argv)
    if args.command == "parse":
        return _cmd_parse(args)
    if args.command == "probe":
        return _cmd_probe(args)
    if args.command == "probe-file":
        return _cmd_probe_file(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
