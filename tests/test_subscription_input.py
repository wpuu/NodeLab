"""Independent acceptance boundaries for the explicit offline subscription input.

Source contract: NodeLab snapshot fe8c1399af7485aff70ead0015b5ab6dd6441455
inventory.py/parse_uris, and synthetic fixtures S01-S10/B01 from the prior
reuse-validation-20261009/fixtures.json. The four-URI payload below reproduces
B01's decoded bytes. No network source, live credentials or node is used.

These tests check input preservation and public outcomes, not the decoder's
implementation. Decoded line numbers refer to the URI payload, not folded
Base64 source lines. This API returns private bytes; only build_inventory's
validated public schema is suitable for display.
"""

from __future__ import annotations

import base64
import json
import socket
import subprocess

import pytest

from nodelab.inventory import (
    MAX_INPUT_BYTES,
    InventoryInputError,
    build_inventory,
    render_inventory_report,
)
from nodelab.subscription_input import decode_subscription_input


S01 = (
    "trojan://dummy-secret@trojan.example.invalid:443?security=tls"
    "&sni=cover.example.invalid&alpn=h2%2Chttp%2F1.1#S01"
)
S02 = (
    "vless://11111111-1111-4111-8111-111111111111@ws.example.invalid:443?"
    "security=tls&type=ws&sni=tls.example.invalid&host=ws-cover.example.invalid"
    "&path=%2Fchat%3Ftoken%3Ddummy-path-token&alpn=http%2F1.1&fp=chrome#S02"
)
S03 = (
    "vless://11111111-1111-4111-8111-111111111111@ws.example.invalid:443?"
    "fp=chrome&alpn=http%2F1.1&path=%2Fchat%3Ftoken%3Ddummy-path-token"
    "&host=ws-cover.example.invalid&sni=tls.example.invalid&type=ws"
    "&security=tls#renamed-S03"
)
S04 = (
    "vless://22222222-2222-4222-8222-222222222222@grpc.example.invalid:443?"
    "security=tls&type=grpc&sni=grpc-cover.example.invalid"
    "&serviceName=demo-service&alpn=h2#S04"
)
B01_PAYLOAD = "\n".join([S01, S02, S03, S04]).encode("utf-8")
S06 = "http://dummy-user:dummy-password@198.51.100.16:8080#S06"
S07 = "socks5://dummy-socks-user:dummy-socks-password@198.51.100.17:1080#S07"
S08 = (
    "vless://not-a-uuid@invalid-uuid.example.invalid:443?security=tls"
    "&type=tcp&sni=cover.example.invalid#S08"
)
S09 = (
    "vless://44444444-4444-4444-8444-444444444444@dup-query.example.invalid:443?"
    "security=tls&security=none&type=tcp&sni=cover.example.invalid#S09"
)


def assert_input_error(data, *, code: str, input_format="base64") -> None:
    with pytest.raises(InventoryInputError) as raised:
        decode_subscription_input(data, input_format=input_format)
    assert raised.value.code == code
    assert str(raised.value) == code
    assert raised.value.args == (code,)


@pytest.mark.parametrize(
    "data",
    [
        b"", b"TWFu", b"YQ==", B01_PAYLOAD, b"\xef\xbb\xbf" + B01_PAYLOAD,
        b"\xff\x00\r\nordinary text\t", "TWFu", "ordinary text", S01,
    ],
)
def test_default_uri_lines_preserves_input_without_auto_detection(data) -> None:
    expected = data.encode("utf-8") if isinstance(data, str) else data
    assert decode_subscription_input(data) == expected
    assert decode_subscription_input(data, input_format="uri_lines") == expected
    assert build_inventory(decode_subscription_input(data)) == build_inventory(expected)


def test_base64_looking_plain_text_is_not_automatically_decoded() -> None:
    encoded = base64.b64encode(B01_PAYLOAD)
    default = build_inventory(decode_subscription_input(encoded))
    explicit = build_inventory(decode_subscription_input(encoded, input_format="base64"))
    assert default["summary"]["records"] == 1
    assert default["summary"]["parsed"] == 0
    assert explicit["summary"]["parsed"] == 4
    assert default["records"][0]["line_number"] == 1
    assert_input_error(S01, code="INVALID_BASE64")


@pytest.mark.parametrize(
    "encoded,expected",
    [
        (b"TQ==", b"M"), (b"TQ", b"M"),
        (b"TWE=", b"Ma"), (b"TWE", b"Ma"), (b"TWFu", b"Man"),
        (b"++//", b"\xfb\xef\xff"), (b"--__", b"\xfb\xef\xff"),
        (b"/w==", b"\xff"), (b"/w", b"\xff"),
        (b"_w==", b"\xff"), (b"_w", b"\xff"),
        (b"//8=", b"\xff\xff"), (b"__8", b"\xff\xff"),
        (b" \tT\r\nW F\tu\r\n", b"Man"),
        (b"\xef\xbb\xbfTQ==\r\n", b"M"), ("\ufeff TQ==\r\n", b"M"),
    ],
)
def test_supported_alphabets_padding_and_ascii_wrapping(encoded, expected: bytes) -> None:
    assert decode_subscription_input(encoded, input_format="base64") == expected


@pytest.mark.parametrize(
    "encoded",
    [
        b"", b" \t\r\n", b"\xef\xbb\xbf", b"\xef\xbb\xbf \r\n",
        b"A", b"AAAAA", b"!TQ==", b"TQ==:private-sentinel",
        b"TQ==\x00", b"TQ==\x0b", b"TQ==\x0c", b"TQ==\x7f",
        "TQ==\u00a0", "TQ==\u2003", "TQ==\u200b", "TQ==\u2028",
        b" \xef\xbb\xbfTQ==", b"TQ\xef\xbb\xbf==", b"TQ==\xef\xbb\xbf",
        b"=TQ==", b"T=Q=", b"TQ=", b"TQ===", b"TQ====", b"TWE==",
        b"TWFu=", b"TQ==A", b"TQ==TQ==", b"====", b"AA=AA",
        b"+-//", b"++_/", b"--/_", b"/+_-", b"//8_",
        # Noncanonical unused bits must not alias a valid padded/unpadded input.
        b"Zh==", b"Zh", b"Zm9=", b"Zm9", b"_x==", b"_x", b"__9=", b"__9",
        b"\xffTQ==", b"TQ==\xfe",
    ],
)
def test_malformed_or_noncanonical_base64_has_one_fixed_error(encoded) -> None:
    assert_input_error(encoded, code="INVALID_BASE64")


@pytest.mark.parametrize("input_format", ["auto", "BASE64", "base64 ", "", None, 1, [], {}])
def test_unknown_format_is_not_an_auto_detection_request(input_format) -> None:
    assert_input_error(b"TQ==", input_format=input_format, code="INVALID_ARGUMENTS")


@pytest.mark.parametrize("data", [None, True, 1, bytearray(b"TQ=="), memoryview(b"TQ=="), [], {}])
@pytest.mark.parametrize("input_format", ["uri_lines", "base64"])
def test_other_input_types_are_rejected_without_coercion(data, input_format: str) -> None:
    assert_input_error(data, input_format=input_format, code="INPUT_TYPE_INVALID")


@pytest.mark.parametrize("input_format", ["uri_lines", "base64"])
def test_unencodable_string_is_a_fixed_utf8_error(input_format: str) -> None:
    assert_input_error("private-sentinel-\ud800", input_format=input_format, code="INVALID_UTF8")


def test_four_fixture_payload_retains_configuration_grouping_and_privacy_schema() -> None:
    encoded = base64.b64encode(B01_PAYLOAD)
    # Folded source has more physical lines than the four decoded URI lines.
    folded = b"\r\n".join(encoded[i:i + 31] for i in range(0, len(encoded), 31))
    public = build_inventory(decode_subscription_input(folded, input_format="base64"))
    assert public == build_inventory(B01_PAYLOAD)
    assert public["summary"] == {
        "physical_lines": 4, "blank_lines": 0, "records": 4, "parsed": 4,
        "unsupported": 0, "invalid": 0, "unique_configurations": 3, "duplicate_records": 1,
    }
    assert [row["line_number"] for row in public["records"]] == [1, 2, 3, 4]
    assert public["records"][2]["duplicate_of"] == "R000002"
    assert public["records"][1]["configuration_id"] == public["records"][2]["configuration_id"]
    assert public["complete"] is True
    assert public["network_used"] is False
    assert all(row["measurement_status"] == "not_measured" for row in public["records"])


def test_decoded_blank_invalid_and_unsupported_lines_are_all_accounted_for() -> None:
    lines = [
        S01.encode(), b"", S02.encode(), S03.encode(), S06.encode(), S07.encode(),
        S08.encode(), S09.encode(), b"\xff", b"synthetic-unrecognized-record", b" \t",
    ]
    payload = b"\xef\xbb\xbf" + b"\r\n".join(lines) + b"\r\n"
    decoded = decode_subscription_input(base64.b64encode(payload), input_format="base64")
    assert decoded == payload
    public = build_inventory(decoded)
    assert public == build_inventory(payload)
    assert public["summary"] == {
        "physical_lines": 11, "blank_lines": 2, "records": 9, "parsed": 3,
        "unsupported": 3, "invalid": 3, "unique_configurations": 2, "duplicate_records": 1,
    }
    assert [row["line_number"] for row in public["records"]] == [1, 3, 4, 5, 6, 7, 8, 9, 10]
    assert [row["error_code"] for row in public["records"]][3:8] == [
        "UNSUPPORTED_PROTOCOL", "UNSUPPORTED_PROTOCOL", "INVALID_SECRET",
        "DUPLICATE_PARAM", "INVALID_UTF8",
    ]
    assert public["records"][3]["protocol"] == "http"
    assert public["records"][4]["protocol"] == "socks5"
    assert public["summary"]["physical_lines"] == public["summary"]["records"] + public["summary"]["blank_lines"]


@pytest.mark.parametrize("payload", [b"\n", b"\r\n\t\r\n", b"\x00\n", b"\xff\n"])
def test_decodable_non_uri_content_is_not_silently_filtered(payload: bytes) -> None:
    public = build_inventory(decode_subscription_input(base64.b64encode(payload), input_format="base64"))
    assert public == build_inventory(payload)


def test_nested_base64_is_decoded_exactly_once() -> None:
    inner = base64.b64encode(B01_PAYLOAD)
    outer = base64.b64encode(inner)
    decoded = decode_subscription_input(outer, input_format="base64")
    assert decoded == inner
    public = build_inventory(decoded)
    assert public == build_inventory(inner)
    assert public["summary"]["records"] == 1
    assert public["summary"]["parsed"] == 0


def test_more_than_one_hundred_decoded_records_are_preserved() -> None:
    payload = ((S01 + "\n") * 105).encode()
    public = build_inventory(decode_subscription_input(base64.b64encode(payload), input_format="base64"))
    assert public == build_inventory(payload)
    assert public["summary"]["parsed"] == 105
    assert public["summary"]["duplicate_records"] == 104
    assert public["records"][-1]["line_number"] == 105


def test_size_limit_applies_before_removing_bom_or_folding_whitespace() -> None:
    assert MAX_INPUT_BYTES == 512 * 1024
    padded = b"TQ==" + b" " * (MAX_INPUT_BYTES - 4)
    assert decode_subscription_input(padded, input_format="base64") == b"M"
    assert_input_error(padded + b" ", code="INPUT_TOO_LARGE")
    assert_input_error(b"\xef\xbb\xbf" + padded, code="INPUT_TOO_LARGE")
    assert_input_error("\u00e9" * (MAX_INPUT_BYTES // 2 + 1), code="INPUT_TOO_LARGE")
    full = decode_subscription_input(b"A" * MAX_INPUT_BYTES, input_format="base64")
    assert len(full) == MAX_INPUT_BYTES * 3 // 4
    assert len(full) <= MAX_INPUT_BYTES
    assert_input_error(b"A" * (MAX_INPUT_BYTES + 1), code="INPUT_TOO_LARGE")
    assert decode_subscription_input(b" " * MAX_INPUT_BYTES) == b" " * MAX_INPUT_BYTES
    assert_input_error(b" " * (MAX_INPUT_BYTES + 1), input_format="uri_lines", code="INPUT_TOO_LARGE")


def test_private_plain_and_encoded_sentinels_do_not_escape_public_output(capsys: pytest.CaptureFixture) -> None:
    sentinel = "synthetic-base64-private-sentinel"
    payload = S01.replace("dummy-secret", sentinel).replace("#S01", "#" + sentinel).encode()
    encoded = base64.b64encode(payload)
    public = build_inventory(decode_subscription_input(encoded, input_format="base64"))
    report = render_inventory_report(public)
    assert_input_error(b"!" + sentinel.encode(), code="INVALID_BASE64")
    captured = capsys.readouterr()
    output = json.dumps(public, ensure_ascii=False) + repr(public) + report + captured.out + captured.err
    for private in [sentinel, payload.decode(), encoded.decode(), "trojan.example.invalid", "cover.example.invalid"]:
        assert private not in output


def test_decoder_and_inventory_have_no_network_or_subprocess_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def blocked(*args, **kwargs):
        calls.append("forbidden operation")
        raise AssertionError("offline subscription import attempted external work")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    public = build_inventory(decode_subscription_input(base64.b64encode(B01_PAYLOAD), input_format="base64"))
    render_inventory_report(public)
    assert calls == []
