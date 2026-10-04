"""Reproducible demo with reserved .invalid hosts and fictional credentials."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from nodelab.inventory import build_inventory, render_inventory_report

_UUID = "11111111-2222-4333-8444-abcdef012345"
_NOTE = "> 示例：本文件全部来自固定虚构输入，不包含用户节点，也不证明真实资源价值。\n\n"


def synthetic_input() -> bytes:
    lines = [
        b"trojan://demo-only-password@alpha.example.invalid:443?security=tls&type=tcp#demo-private-label",
        b"",
        b"trojan://demo-only-password@ALPHA.EXAMPLE.INVALID:443?type=TCP&security=TLS#another-label",
        b"trojan://different-demo-password@alpha.example.invalid:443?security=tls",
        b"trojan://demo-only-password@ws.example.invalid:443?type=ws&security=tls&host=front.example.invalid&path=%2Fdemo%3Ftoken%3Dfictional",
        f"vless://{_UUID}@beta.example.invalid:443?security=tls&type=tcp".encode(),
        f"vless://{_UUID.upper()}@BETA.EXAMPLE.INVALID:443?type=TCP&security=TLS#different-label".encode(),
        b" \t",
        f"vless://{_UUID}@grpc.example.invalid:443?type=grpc&security=tls&serviceName=demo".encode(),
        f"vless://{_UUID}@reality.example.invalid:443?security=reality&sni=front.example.invalid&fp=chrome&pbk={'A' * 43}&sid=01".encode(),
        f"vless://{_UUID}@upgrade.example.invalid:443?type=httpupgrade&security=tls".encode(),
        b"vmess://fictional-input-not-a-real-node",
        b"vless://not-a-valid-uuid@error.example.invalid:443?security=tls",
        b"\xff",
    ]
    return b"\xef\xbb\xbf" + b"\n".join(lines) + b"\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("docs/examples"))
    parser.add_argument("--check", action="store_true", help="Verify committed examples match this synthetic input")
    parser.add_argument("--emit-evidence", action="store_true", help="Print safe generated example data for remote evidence retrieval")
    args = parser.parse_args()
    result = build_inventory(synthetic_input())
    outputs = {
        "NL-OFFLINE-INVENTORY-SAMPLE.json": json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        "NL-OFFLINE-INVENTORY-SAMPLE.md": _NOTE + render_inventory_report(result),
    }
    if args.check:
        for filename, content in outputs.items():
            path = args.output_dir / filename
            if not path.is_file() or path.read_text(encoding="utf-8") != content:
                raise SystemExit("SYNTHETIC_EXAMPLE_MISMATCH")
    else:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for filename, content in outputs.items():
            (args.output_dir / filename).write_text(content, encoding="utf-8", newline="\n")
    print("NODELAB_OFFLINE_DEMO_SUMMARY=" + json.dumps(result["summary"], separators=(",", ":")))
    if args.emit_evidence:
        for filename, content in outputs.items():
            value = base64.b64encode(content.encode("utf-8")).decode("ascii")
            print("NODELAB_OFFLINE_DEMO_FILE=" + json.dumps({"filename": filename, "utf8_base64": value}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
