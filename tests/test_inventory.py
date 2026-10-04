"""Acceptance contract for the strictly offline, synthetic asset inventory.

Every URI below is synthetic. Reserved .invalid names and documentation IPs
are never contacted. Counts describe parsed configurations, not usable routes.
"""

from __future__ import annotations

import copy
import json
import socket
import subprocess
from collections import Counter
from urllib.parse import quote

import pytest

from nodelab.inventory import (
    MAX_INPUT_BYTES,
    InventoryInputError,
    build_inventory,
    render_inventory_report,
)
from nodelab.types import PROBE_GATE_OPEN


UUID_A = "12345678-1234-4234-8234-123456789abc"
UUID_B = "22345678-1234-4234-8234-123456789abc"
HOST = "node.example.invalid"
SNI = "tls.example.invalid"


def vless(*, secret: str = UUID_A, host: str = HOST, query: str | None = None) -> str:
    if query is None:
        query = f"security=tls&sni={SNI}"
    return f"vless://{secret}@{host}:443?{query}"


def trojan(*, secret: str = "synthetic-password-only", query: str | None = None) -> str:
    if query is None:
        query = f"security=tls&sni={SNI}"
    return f"trojan://{quote(secret, safe='')}@{HOST}:443?{query}"


def assert_count_invariants(public: dict) -> None:
    summary = public["summary"]
    assert summary["records"] == summary["parsed"] + summary["unsupported"] + summary["invalid"]
    assert summary["parsed"] == summary["unique_configurations"] + summary["duplicate_records"]
    assert summary["physical_lines"] == summary["records"] + summary["blank_lines"]
    assert len(public["records"]) == summary["records"]
    assert sum(public["protocol_counts"].values()) == summary["records"]
    assert sum(public["dialect_counts"].values()) == summary["records"]
    assert sum(public["error_counts"].values()) == summary["unsupported"] + summary["invalid"]


def test_mixed_inventory_retains_records_and_does_not_claim_measurement() -> None:
    lines = [
        vless(),
        "",
        vless(secret=UUID_A.upper(), host=HOST.upper(), query=f"sni={SNI}&security=tls") + "#different-label",
        trojan(),
        vless(query=f"security=reality&sni={SNI}&fp=chrome&pbk={'A' * 43}&sid="),
        f"vless://{UUID_A}@{HOST}:0?security=tls&sni={SNI}",
        " \t",
    ]
    public = build_inventory(b"\xef\xbb\xbf" + ("\n".join(lines) + "\n").encode("utf-8"))
    assert public["schema_version"] == 1
    assert public["mode"] == "offline_inventory"
    assert public["complete"] is True
    assert public["network_used"] is False
    assert public["summary"] == {
        "physical_lines": 7,
        "blank_lines": 2,
        "records": 5,
        "parsed": 3,
        "unsupported": 1,
        "invalid": 1,
        "unique_configurations": 2,
        "duplicate_records": 1,
    }
    assert public["protocol_counts"] == {"vless": 4, "trojan": 1}
    assert public["dialect_counts"] == {"tls_tcp": 3, "unsupported_reality": 1, "unclassified": 1}
    assert public["error_counts"] == {"UNSUPPORTED_REALITY": 1, "INVALID_PORT": 1}
    assert [r["line_number"] for r in public["records"]] == [1, 3, 4, 5, 6]
    assert [r["record_id"] for r in public["records"]] == [f"R{n:06d}" for n in range(1, 6)]
    assert public["records"][0]["configuration_id"] == "C000001"
    assert public["records"][1]["configuration_id"] == "C000001"
    assert public["records"][1]["duplicate_of"] == "R000001"
    assert public["records"][2]["configuration_id"] == "C000002"
    for row in public["records"]:
        assert row["source_status"] == "unknown"
        assert row["resale_authorization"] == "unknown"
        assert row["measurement_status"] == "not_measured"
        if row["parse_status"] != "parsed":
            assert row["configuration_id"] is None
            assert row["duplicate_of"] is None
    assert_count_invariants(public)


def test_normalized_configuration_dedup_is_private_and_batch_local() -> None:
    encoded_uuid = UUID_A.replace("a", "%61")
    inputs = [
        vless(),
        vless(secret=encoded_uuid, host=HOST.upper(), query=f"sni={SNI}&security=TLS&type=TCP") + "#50%off",
        vless() + "#arbitrary-remark",
    ]
    public = build_inventory("\n".join(inputs))
    assert public["summary"]["unique_configurations"] == 1
    assert public["summary"]["duplicate_records"] == 2
    assert [r["duplicate_of"] for r in public["records"]] == [None, "R000001", "R000001"]
    other_batch = build_inventory(vless(secret=UUID_B))
    assert other_batch["records"][0]["configuration_id"] == "C000001"
    assert other_batch["records"][0]["duplicate_of"] is None
    assert UUID_A not in json.dumps(public)
    assert HOST not in json.dumps(public)


@pytest.mark.parametrize(
    "first,second",
    [
        (vless(), vless(secret=UUID_B)),
        (trojan(), trojan(secret="another-synthetic-password")),
        (vless(), vless(host="other.example.invalid")),
        (vless(), vless().replace(":443?", ":8443?")),
        (vless(), vless(query="security=tls&sni=other-tls.example.invalid")),
        (
            vless(query=f"security=tls&sni={SNI}&type=ws&host=ws.example.invalid&path=%2Ffirst"),
            vless(query=f"security=tls&sni={SNI}&type=ws&host=ws.example.invalid&path=%2Fsecond"),
        ),
        (
            vless(query=f"security=tls&sni={SNI}&type=ws&host=ws.example.invalid&path=%2F"),
            vless(query=f"security=tls&sni={SNI}&type=ws&host=other-ws.example.invalid&path=%2F"),
        ),
        (
            vless(query=f"security=tls&sni={SNI}&type=grpc&serviceName=first"),
            vless(query=f"security=tls&sni={SNI}&type=grpc&serviceName=second"),
        ),
        (
            vless(query=f"security=tls&sni={SNI}&alpn=h2,http%2F1.1"),
            vless(query=f"security=tls&sni={SNI}&alpn=http%2F1.1,h2"),
        ),
        (vless(), vless(query=f"security=tls&sni={SNI}&fp=chrome")),
        (vless(), vless(query=f"security=tls&sni={SNI}&flow=xtls-rprx-vision")),
    ],
)
def test_behavior_or_credential_changes_are_not_merged(first: str, second: str) -> None:
    public = build_inventory(first + "\n" + second)
    assert public["summary"]["parsed"] == 2
    assert public["summary"]["unique_configurations"] == 2
    assert public["summary"]["duplicate_records"] == 0
    assert all(r["duplicate_of"] is None for r in public["records"])


def test_unsupported_is_distinct_from_invalid() -> None:
    public = build_inventory("\n".join([
        vless(query=f"security=tls&sni={SNI}&type=httpupgrade"),
        "ss://synthetic-only@node.example.invalid:443",
        vless(query=f"security=tls&sni={SNI}&unknown=synthetic-only"),
        vless(secret="not-a-uuid"),
        vless(query=f"security=tls&sni={SNI}&sni={SNI}"),
    ]))
    assert [r["parse_status"] for r in public["records"]] == ["unsupported"] * 3 + ["invalid"] * 2
    assert [r["error_code"] for r in public["records"]] == [
        "UNSUPPORTED_HTTPUPGRADE", "UNSUPPORTED_PROTOCOL", "UNSUPPORTED_QUERY_PARAM",
        "INVALID_SECRET", "DUPLICATE_PARAM",
    ]
    assert public["records"][0]["dialect"] == "unsupported_httpupgrade"
    assert public["records"][1]["protocol"] == "ss"
    assert public["summary"]["unique_configurations"] == 0
    assert_count_invariants(public)


def test_line_accounting_empty_input_crlf_and_invalid_utf8() -> None:
    for data, physical_lines, blank_lines in [(b"", 0, 0), (b"\n", 1, 1), (b"\r\n\t\r\n", 2, 2)]:
        public = build_inventory(data)
        assert public["summary"]["physical_lines"] == physical_lines
        assert public["summary"]["blank_lines"] == blank_lines
        assert public["summary"]["records"] == 0
        assert_count_invariants(public)
    public = build_inventory((vless() + "\r\n").encode() + b"\xff\r\n")
    assert public["summary"]["physical_lines"] == 2
    assert public["records"][1]["line_number"] == 2
    assert public["records"][1]["parse_status"] == "invalid"
    assert public["records"][1]["error_code"] == "INVALID_UTF8"
    assert_count_invariants(public)


def test_inventory_does_not_inherit_parse_cli_one_or_hundred_record_limit() -> None:
    public = build_inventory("\n".join([vless()] * 105))
    assert public["complete"] is True
    assert public["summary"]["records"] == 105
    assert public["summary"]["parsed"] == 105
    assert public["summary"]["unique_configurations"] == 1
    assert public["summary"]["duplicate_records"] == 104
    assert public["records"][-1]["record_id"] == "R000105"


def test_input_byte_limit_rejects_whole_batch_with_fixed_code() -> None:
    assert MAX_INPUT_BYTES == 512 * 1024
    assert build_inventory(b" " * MAX_INPUT_BYTES)["complete"] is True
    for data in [b" " * (MAX_INPUT_BYTES + 1), "\u4e2d" * (MAX_INPUT_BYTES // 3 + 1)]:
        with pytest.raises(InventoryInputError) as raised:
            build_inventory(data)
        assert raised.value.code == "INPUT_TOO_LARGE"
        assert str(raised.value) == "INPUT_TOO_LARGE"


def test_synthetic_sentinels_never_escape_public_results_or_report(capsys: pytest.CaptureFixture) -> None:
    sentinel = "synthetic-secret-sentinel"
    lines = [
        trojan(secret=sentinel),
        trojan(query=f"security=tls&sni={sentinel}.example.invalid"),
        f"trojan://synthetic-only@{sentinel}.example.invalid:443?security=tls&sni={SNI}",
        trojan(query=f"security=tls&sni={SNI}&type=ws&host={sentinel}.example.invalid&path=%2F{sentinel}"),
        trojan(query=f"security=tls&sni={SNI}&type=grpc&serviceName={sentinel}"),
        trojan() + f"#{sentinel}",
        trojan(query=f"security=tls&sni={SNI}&{sentinel}={sentinel}"),
        f"{sentinel}://{sentinel}",
        f"vless://{sentinel}@{HOST}:443?security=tls&sni={SNI}",
    ]
    public = build_inventory("\n".join(lines))
    report = render_inventory_report(public)
    captured = capsys.readouterr()
    combined = json.dumps(public, ensure_ascii=False) + repr(public) + report + captured.out + captured.err
    for private_value in [sentinel, HOST, SNI, UUID_A, "synthetic-password-only", "vless://", "trojan://"]:
        assert private_value not in combined
    assert public["records"][7]["protocol"] == "other"
    assert PROBE_GATE_OPEN is False


def test_build_and_render_perform_no_network_or_child_process(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def blocked(*args, **kwargs):
        calls.append("forbidden operation")
        raise AssertionError("offline inventory attempted network or subprocess")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "call", blocked)
    monkeypatch.setattr(subprocess, "check_call", blocked)
    monkeypatch.setattr(subprocess, "check_output", blocked)
    public = build_inventory(vless() + "\n" + trojan())
    render_inventory_report(public)
    assert calls == []
    assert public["network_used"] is False
    assert PROBE_GATE_OPEN is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(private_uri="synthetic-secret-sentinel"),
        lambda p: p.update(network_used=True),
        lambda p: p.update(complete=False),
        lambda p: p["records"][0].update(secret="synthetic-secret-sentinel"),
        lambda p: p["records"][0].update(protocol="synthetic-secret-sentinel"),
        lambda p: p["records"][0].update(parse_status="PASS"),
        lambda p: p["records"][0].update(source_status="verified"),
        lambda p: p["records"][0].update(resale_authorization="approved"),
        lambda p: p["records"][0].update(measurement_status="measured"),
        lambda p: p["records"][0].update(error_code="synthetic-secret-sentinel"),
        lambda p: p["error_counts"].update({"synthetic-secret-sentinel": 1}),
        lambda p: p["summary"].update(parsed=True),
        lambda p: p["summary"].update(unique_configurations=2),
    ],
)
def test_report_rejects_forged_or_nonpublic_structures(mutation) -> None:
    forged = copy.deepcopy(build_inventory(vless()))
    mutation(forged)
    with pytest.raises(InventoryInputError) as raised:
        render_inventory_report(forged)
    assert raised.value.code == "PUBLIC_SCHEMA_REJECTED"
    assert str(raised.value) == "PUBLIC_SCHEMA_REJECTED"
    assert "synthetic-secret-sentinel" not in repr(raised.value)


def test_chinese_report_and_public_data_describe_configuration_not_assets() -> None:
    public = build_inventory(vless() + "\n" + vless() + "\n" + trojan())
    report = render_inventory_report(public)
    assert isinstance(report, str)
    assert "\u79bb\u7ebf" in report
    assert "\u89c4\u8303\u5316\u914d\u7f6e" in report
    assert "\u72ec\u7acb\u7ebf\u8def" in report
    assert "\u51fa\u53e3" in report
    assert "\u672a\u77e5" in report
    assert "\u672a\u6d4b" in report
    assert "C000001" in report
    assert "C000002" in report
    assert Counter(r["parse_status"] for r in public["records"]) == {"parsed": 3}
    assert_count_invariants(public)
