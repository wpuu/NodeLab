"""Offline configuration inventory. Never probes or exports private node fields."""

from __future__ import annotations

from collections import Counter
from typing import Any

from nodelab.parser import parse_uris
from nodelab.types import NodeURIParseError, ParsedNode

MAX_INPUT_BYTES = 512 * 1024
# Fixed public rows still amplify small input; cap records before parsing.
MAX_INPUT_RECORDS = 1000
_PROTOCOLS = frozenset({
    "vless", "trojan", "vmess", "ss", "ssr", "hysteria", "hysteria2", "tuic",
    "http", "https", "socks", "socks5", "other",
})
_DIALECTS = frozenset({
    "tls_tcp", "tls_ws", "tls_grpc", "unsupported_reality",
    "unsupported_httpupgrade", "unclassified",
})
_INPUT_CODES = frozenset({
    "INPUT_TOO_LARGE", "INPUT_TOO_MANY_RECORDS", "INVALID_UTF8", "INPUT_TYPE_INVALID", "INPUT_FILE_UNSAFE",
    "PUBLIC_SCHEMA_REJECTED", "INVALID_ARGUMENTS", "INVENTORY_FAILED",
})
_ROW_KEYS = frozenset({
    "record_id", "line_number", "parse_status", "protocol", "transport", "tls_mode",
    "dialect", "error_code", "configuration_id", "duplicate_of", "source_status",
    "resale_authorization", "measurement_status",
})
_SUMMARY_KEYS = frozenset({
    "physical_lines", "blank_lines", "records", "parsed", "unsupported", "invalid",
    "unique_configurations", "duplicate_records",
})
_REPORT_KEYS = frozenset({
    "schema_version", "mode", "complete", "network_used", "summary",
    "protocol_counts", "dialect_counts", "error_counts", "records",
})


class InventoryInputError(ValueError):
    """Fixed error codes only; private input and exception text stay private."""

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in _INPUT_CODES else "INVENTORY_FAILED"
        super().__init__(self.code)


def _configuration_key(node: ParsedNode) -> tuple[Any, ...]:
    # Exact parsed behavior, including credentials and ordered ALPN. No hash or
    # endpoint is published. IDs are scoped to this input order, not durable IDs.
    return (
        node.protocol, node.secret, node.entry_host, node.entry_port, node.transport,
        node.tls_mode, node.sni, node.ws_host, node.ws_path, node.grpc_service_name,
        node.alpn, node.client_fingerprint, node.flow, node.reality_public_key,
        node.reality_short_id, node.allow_insecure_requested,
    )


def _physical_lines(data: bytes) -> list[bytes]:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    lines = data.split(b"\n") if data else []
    if data.endswith(b"\n"):
        lines.pop()
    return lines


def _claimed_protocol(raw: bytes) -> str:
    prefix, marker, _ = raw.strip(b" \t\r\x0b\x0c").partition(b"://")
    if not marker or len(prefix) > 12:
        return "other"
    # Bytes compare avoids decoding or printing untrusted scheme text.
    return next((p for p in _PROTOCOLS if prefix.lower() == p.encode("ascii")), "other")


def _aggregate(rows: list[dict[str, Any]], physical: int, blank: int) -> dict[str, Any]:
    statuses = Counter(row["parse_status"] for row in rows)
    summary = {
        "physical_lines": physical, "blank_lines": blank, "records": len(rows),
        "parsed": statuses["parsed"], "unsupported": statuses["unsupported"],
        "invalid": statuses["invalid"],
        "unique_configurations": sum(row["parse_status"] == "parsed" and row["duplicate_of"] is None for row in rows),
        "duplicate_records": sum(row["duplicate_of"] is not None for row in rows),
    }
    return {
        "schema_version": 1, "mode": "offline_inventory", "complete": True,
        "network_used": False, "summary": summary,
        "protocol_counts": dict(sorted(Counter(row["protocol"] for row in rows).items())),
        "dialect_counts": dict(sorted(Counter(row["dialect"] for row in rows).items())),
        "error_counts": dict(sorted(Counter(row["error_code"] for row in rows if row["error_code"] is not None).items())),
        "records": rows,
    }


def build_inventory(data: bytes | str) -> dict[str, Any]:
    """Process all bounded input; parsed means syntax, not a usable resource.

    No engine, subprocess, DNS or HTTP is used. The input and configuration keys
    exist only in memory; callers receive a fixed public structure.
    """
    if type(data) is str:
        try:
            data = data.encode("utf-8", errors="strict")
        except UnicodeError:
            raise InventoryInputError("INVALID_UTF8") from None
    if type(data) is not bytes:
        raise InventoryInputError("INPUT_TYPE_INVALID")
    if len(data) > MAX_INPUT_BYTES:
        raise InventoryInputError("INPUT_TOO_LARGE")
    physical = _physical_lines(data)
    records = 0
    for raw in physical:
        if raw.strip():
            records += 1
            if records > MAX_INPUT_RECORDS:
                raise InventoryInputError("INPUT_TOO_MANY_RECORDS")
    batch = parse_uris(data)  # Entire accepted input; never truncate records.
    groups: dict[tuple[Any, ...], tuple[str, str]] = {}
    rows: list[dict[str, Any]] = []
    for line in batch.lines:
        record_id = f"R{len(rows) + 1:06d}"
        protocol = _claimed_protocol(physical[line.line_number - 1])
        configuration_id = duplicate_of = transport = tls_mode = None
        error_code = line.error_code
        dialect = "unclassified"
        if line.node is not None:
            node = line.node
            protocol, transport, tls_mode = node.protocol, node.transport, node.tls_mode
            dialect = "tls_" + transport
            parse_status, error_code = "parsed", None
            key = _configuration_key(node)
            previous = groups.get(key)
            if previous is None:
                configuration_id = f"C{len(groups) + 1:06d}"
                groups[key] = (configuration_id, record_id)
            else:
                configuration_id, duplicate_of = previous
        else:
            parse_status = "unsupported" if error_code and error_code.startswith("UNSUPPORTED_") else "invalid"
            if error_code == "UNSUPPORTED_REALITY":
                dialect = "unsupported_reality"
            elif error_code == "UNSUPPORTED_HTTPUPGRADE":
                dialect = "unsupported_httpupgrade"
        rows.append({
            "record_id": record_id, "line_number": line.line_number,
            "parse_status": parse_status, "protocol": protocol,
            "transport": transport, "tls_mode": tls_mode, "dialect": dialect,
            "error_code": error_code, "configuration_id": configuration_id,
            "duplicate_of": duplicate_of, "source_status": "unknown",
            "resale_authorization": "unknown", "measurement_status": "not_measured",
        })
    report = _aggregate(rows, len(physical), batch.skipped_count)
    validate_inventory(report)
    return report


def validate_inventory(report: Any) -> None:
    """Reject extra or arbitrary text before JSON or Markdown publication."""
    def reject() -> None:
        raise InventoryInputError("PUBLIC_SCHEMA_REJECTED")

    if type(report) is not dict or set(report) != _REPORT_KEYS:
        reject()
    if (type(report["schema_version"]) is not int or report["schema_version"] != 1
            or type(report["mode"]) is not str or report["mode"] != "offline_inventory"
            or report["complete"] is not True or report["network_used"] is not False):
        reject()
    summary, rows = report["summary"], report["records"]
    if type(summary) is not dict or set(summary) != _SUMMARY_KEYS or type(rows) is not list:
        reject()
    if any(type(v) is not int or not 0 <= v <= MAX_INPUT_BYTES for v in summary.values()):
        reject()
    if len(rows) > MAX_INPUT_RECORDS:
        reject()
    first: dict[str, str] = {}
    last_line = 0
    for number, row in enumerate(rows, 1):
        if type(row) is not dict or set(row) != _ROW_KEYS:
            reject()
        if type(row["record_id"]) is not str or row["record_id"] != f"R{number:06d}":
            reject()
        line = row["line_number"]
        if type(line) is not int or not last_line < line <= summary["physical_lines"]:
            reject()
        last_line = line
        if any(type(row[k]) is not str or row[k] != v for k, v in (
                ("source_status", "unknown"), ("resale_authorization", "unknown"),
                ("measurement_status", "not_measured"))):
            reject()
        if type(row["protocol"]) is not str or row["protocol"] not in _PROTOCOLS:
            reject()
        if type(row["dialect"]) is not str or row["dialect"] not in _DIALECTS:
            reject()
        status = row["parse_status"]
        if type(status) is not str or status not in {"parsed", "unsupported", "invalid"}:
            reject()
        if status == "parsed":
            transport = row["transport"]
            if (row["protocol"] not in {"trojan", "vless"} or type(transport) is not str
                    or transport not in {"tcp", "ws", "grpc"} or row["tls_mode"] != "tls"
                    or type(row["tls_mode"]) is not str or row["dialect"] != "tls_" + transport
                    or row["error_code"] is not None):
                reject()
            group, duplicate = row["configuration_id"], row["duplicate_of"]
            if type(group) is not str:
                reject()
            if duplicate is None:
                if group != f"C{len(first) + 1:06d}" or group in first:
                    reject()
                first[group] = row["record_id"]
            elif type(duplicate) is not str or first.get(group) != duplicate:
                reject()
        else:
            code = row["error_code"]
            if type(code) is not str or NodeURIParseError(code).code != code:
                reject()
            if (status == "unsupported") != code.startswith("UNSUPPORTED_"):
                reject()
            expected = {"UNSUPPORTED_REALITY": "unsupported_reality", "UNSUPPORTED_HTTPUPGRADE": "unsupported_httpupgrade"}.get(code, "unclassified")
            if row["dialect"] != expected or any(row[k] is not None for k in ("transport", "tls_mode", "configuration_id", "duplicate_of")):
                reject()
    expected_report = _aggregate(rows, summary["physical_lines"], summary["blank_lines"])
    if summary["physical_lines"] != summary["blank_lines"] + len(rows):
        reject()
    for name in ("protocol_counts", "dialect_counts", "error_counts"):
        counts = report[name]
        if type(counts) is not dict or any(type(k) is not str or type(v) is not int or v < 1 for k, v in counts.items()):
            reject()
    if report != expected_report:
        reject()


def render_inventory_report(report: dict[str, Any]) -> str:
    """Render the validated public result, never the private parser objects."""
    validate_inventory(report)
    s = report["summary"]
    text = [
        "# NodeLab 离线资产盘点", "",
        "范围：全部受限输入已处理；未联网、未启动代理引擎、未测真实节点。", "",
        "| 项目 | 数量 |", "| --- | ---: |",
    ]
    labels = {
        "physical_lines": "物理行", "blank_lines": "空白行", "records": "非空记录",
        "parsed": "解析成功（未测）", "unsupported": "当前不支持",
        "invalid": "格式或字段错误", "unique_configurations": "规范化配置组",
        "duplicate_records": "重复配置记录",
    }
    text.extend(f"| {label} | {s[key]} |" for key, label in labels.items())
    text.extend([
        "", "规范化配置组不是独立线路、上游账号或出口数量；这三项仍未知。",
        "来源与转售授权均未知；质量、寿命、稳定性及住宅属性未核验。",
        "配置组编号和重复关系仅在本次输入内有效，不是跨次追踪身份。",
        "协议列是安全枚举的声明或解析结果，不支持项不是已确认的坏节点。", "",
        "| 记录 | 输入行 | 协议 | 状态 | 方言 | 配置组 | 重复于 | 固定错误码 |",
        "| --- | ---: | --- | --- | --- | --- | --- | --- |",
    ])
    states = {"parsed": "解析成功（未测）", "unsupported": "当前不支持", "invalid": "格式或字段错误"}
    dialects = {
        "tls_tcp": "TLS/TCP", "tls_ws": "TLS/WebSocket", "tls_grpc": "TLS/gRPC",
        "unsupported_reality": "Reality未支持", "unsupported_httpupgrade": "HTTPUpgrade未支持",
        "unclassified": "未分类",
    }
    for row in report["records"]:
        text.append("| " + " | ".join(str(v) for v in (
            row["record_id"], row["line_number"], row["protocol"], states[row["parse_status"]],
            dialects[row["dialect"]], row["configuration_id"] or "—",
            row["duplicate_of"] or "—", row["error_code"] or "—",
        )) + " |")
    text.extend(["", "本报告未包含URI、凭据、节点地址、备注、秘密哈希或原始文件路径。", ""])
    return "\n".join(text)
