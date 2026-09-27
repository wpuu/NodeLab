"""F2a strict URI contract; every credential is generated for this test run.

No real proxy nodes, network requests, controller, Mihomo binary or YAML.
A parser success is only a typed private *candidate*, not SUPPORTED/PASS.
"""

from __future__ import annotations

import base64
import json
import secrets
import uuid
from urllib.parse import quote

import pytest

from nodelab.parser import parse_uri, parse_uris
from nodelab.probe import probe_node
from nodelab.redaction import redacted_node_dict
from nodelab.types import NodeURIParseError


@pytest.fixture
def vless_uuid() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def trojan_password() -> str:
    return "FAKE_ONLY_" + secrets.token_urlsafe(24) + ":%40"


def vless(fake_uuid: str, query: str, host: str = "entry.example.invalid") -> str:
    return f"vless://{fake_uuid}@{host}:443?{query}"


def trojan(password: str, query: str = "", host: str = "entry.example.invalid") -> str:
    suffix = "?" + query if query else ""
    return f"trojan://{quote(password, safe='')}@{host}:443{suffix}"


def rejected(uri: str, code: str, *private: str) -> None:
    with pytest.raises(NodeURIParseError) as info:
        parse_uri(uri)
    assert info.value.code == code
    assert info.value.probe_status == ("UNSUPPORTED" if code.startswith("UNSUPPORTED_") else "FAIL")
    for value in private:
        assert value not in str(info.value) + repr(info.value)


def test_vless_tcp_tls_typed_metadata_and_disabled_probe(vless_uuid):
    uri = vless(vless_uuid, "security=TLS&type=TCP&encryption=none&alpn=h2,http%2F1.1&fp=Chrome&flow=xtls-rprx-vision")
    node = parse_uri(uri)
    assert node.protocol == "vless" and node.secret == vless_uuid
    assert node.entry_host == node.sni == "entry.example.invalid"
    assert node.transport == "tcp" and node.tls_mode == "tls"
    assert node.alpn == ("h2", "http/1.1") and node.client_fingerprint == "chrome"
    assert node.flow == "xtls-rprx-vision" and not node.allow_insecure_requested
    assert node.ws_host is node.ws_path is node.grpc_service_name is None
    assert node.reality_public_key is node.reality_short_id is None
    assert node.secret not in json.dumps(redacted_node_dict(node))
    assert probe_node(node)["error_code"] == "ROUTE_PROOF_UNAVAILABLE"


def test_ws_host_sni_path_are_independent_and_percent_decoded_once(vless_uuid):
    node = parse_uri(vless(
        vless_uuid, "security=tls&type=ws&sni=sni.example.invalid"
        "&host=ws.example.invalid:8443&path=%2Fa%252Fb#FAKE_ONLY_FRAGMENT",
    ))
    assert node.transport == "ws" and node.ws_host == "ws.example.invalid:8443"
    assert node.sni == "sni.example.invalid" and node.ws_path == "/a%2Fb"
    plus = parse_uri(vless(vless_uuid, "security=tls&type=ws&sni=sni.example.invalid"
                           "&host=ws.example.invalid&path=%2Fa%2Bb"))
    assert plus.ws_path == "/a+b"  # encoded plus is literal
    form_plus = parse_uri(vless(vless_uuid, "security=tls&type=ws&sni=sni.example.invalid"
                                "&host=ws.example.invalid&path=%2Fa+b"))
    assert form_plus.ws_path == "/a b"  # raw '+' in form query is a space
    assert not hasattr(node, "display_name") and "FAKE_ONLY_FRAGMENT" not in repr(node)
    assert "FAKE_ONLY_FRAGMENT" not in json.dumps(redacted_node_dict(node))
    rejected(vless(vless_uuid, "security=tls&type=ws&host=ws.example.invalid&path=%252F"),
             "INVALID_PATH", vless_uuid)


def test_grpc_service_and_h2_alpn(vless_uuid):
    uri = vless(vless_uuid, "security=tls&type=grpc&sni=grpc.example.invalid&serviceName=svc-1%2Fapi")
    node = parse_uri(uri)
    assert node.grpc_service_name == "svc-1/api" and node.alpn == ("h2",)
    assert node.ws_host is node.ws_path is None
    rejected(uri + "&alpn=http%2F1.1", "UNSUPPORTED_ALPN", vless_uuid)
    assert parse_uri(uri + "&alpn=http%2F1.1,h2").alpn == ("http/1.1", "h2")


def test_trojan_whole_password_and_tls_default(trojan_password):
    node = parse_uri(trojan(trojan_password, "fp=IOS&alpn=h2", "entry.example.invalid"))
    assert node.protocol == "trojan" and node.secret == trojan_password
    assert node.transport == "tcp" and node.tls_mode == "tls"
    assert node.sni == "entry.example.invalid" and node.client_fingerprint == "iOS"
    assert node.alpn == ("h2",)
    assert trojan_password not in repr(node) and trojan_password not in str(node.public_dict())


def test_trojan_ws_and_grpc_dialects_are_typed(trojan_password):
    ws = parse_uri(trojan(trojan_password, "type=ws&host=ws.example.invalid&path=%2Ft&security=tls"))
    assert ws.ws_host == "ws.example.invalid" and ws.ws_path == "/t" and ws.sni == "entry.example.invalid"
    grpc = parse_uri(trojan(trojan_password, "type=grpc&serviceName=my.Service%2Fapi"))
    assert grpc.grpc_service_name == "my.Service/api" and grpc.alpn == ("h2",)


def test_ipv6_brackets_idna2008_and_strict_host_normalization(vless_uuid):
    ip6 = parse_uri(vless(vless_uuid, "security=tls&sni=sni.example.invalid", "[2001:db8::1]"))
    assert ip6.entry_host == "2001:db8::1" and ip6.sni == "sni.example.invalid"
    idn = parse_uri(vless(vless_uuid, "security=tls", "bücher.example"))
    assert idn.entry_host == idn.sni == "xn--bcher-kva.example"
    assert parse_uri(vless(vless_uuid, "security=tls", "EXAMPLE.INVALID")).entry_host == "example.invalid"
    for invalid_host in ("2001:db8::1", "[fe80::1%25eth0]", "999.999.999.999", "bad..example", "\u0378.example"):
        rejected(vless(vless_uuid, "security=tls&sni=sni.example.invalid", invalid_host),
                 "INVALID_HOST", vless_uuid)


def test_ports_sni_conflicts_and_ws_host_validation(vless_uuid):
    for address, code in (
        ("entry.example.invalid", "INVALID_PORT"),
        ("[2001:db8::1]", "INVALID_PORT"),
        ("entry.example.invalid:0", "INVALID_PORT"),
        ("entry.example.invalid:65536", "INVALID_PORT"),
        ("entry.example.invalid:abc", "INVALID_PORT"),
        ("entry.example.invalid:123456", "INVALID_PORT"),
        ("[2001:db8::1]:70000", "INVALID_PORT"),
    ):
        uri = f"vless://{vless_uuid}@{address}?security=tls&sni=sni.example.invalid"
        rejected(uri, code, vless_uuid)
    for host in ("bad%0Ahost", "x.example.invalid:0", "x.example.invalid:99999", "[2001:db8::1]:abc"):
        code = "INVALID_QUERY" if "%0A" in host else "INVALID_HOST_HEADER"
        rejected(vless(vless_uuid, f"security=tls&type=ws&sni=sni.example.invalid&host={host}&path=%2F"),
                 code, vless_uuid)
    rejected(vless(vless_uuid, "security=tls&sni=bad+host"), "INVALID_HOST", vless_uuid)
    rejected(vless(vless_uuid, "security=tls#bad%0Afragment"), "INVALID_URI", vless_uuid)


def test_userinfo_percent_control_and_double_at_are_rejected(trojan_password):
    for userinfo, expected in (("", "INVALID_SECRET"), ("bad%", "INVALID_PERCENT_ENCODING"),
                               ("bad%G1", "INVALID_PERCENT_ENCODING"),
                               ("bad%0A", "INVALID_SECRET"), ("bad@extra", "INVALID_SECRET")):
        rejected(f"trojan://{userinfo}@entry.example.invalid:443", expected, trojan_password)
    plus = "FAKE_ONLY_" + secrets.token_urlsafe(12) + "+@"
    assert parse_uri(trojan(plus)).secret == plus
    assert parse_uri(f"trojan://FAKE_ONLY_%252F@entry.example.invalid:443").secret == "FAKE_ONLY_%2F"
    literal_colon = "FAKE_ONLY_" + secrets.token_hex(12) + ":with:colons"
    assert parse_uri(f"trojan://{literal_colon}@entry.example.invalid:443").secret == literal_colon


def test_casefold_duplicate_query_unknown_and_alias_conflict(vless_uuid):
    baseline = vless(vless_uuid, "security=tls")
    rejected(baseline + "&Security=tls", "DUPLICATE_PARAM", vless_uuid)
    rejected(baseline + "&type=tcp&TYPE=tcp", "DUPLICATE_PARAM", vless_uuid)
    rejected(baseline + "&sni=x.example.invalid&peer=x.example.invalid", "DUPLICATE_PARAM", vless_uuid)
    fake = "FAKE_ONLY_" + secrets.token_urlsafe(12)
    rejected(baseline + "&auth=" + fake, "UNSUPPORTED_QUERY_PARAM", fake, vless_uuid)
    rejected(baseline + "&Password=" + fake, "UNSUPPORTED_QUERY_PARAM", fake, vless_uuid)
    rejected(baseline + "&sni=bad%ZZ", "INVALID_PERCENT_ENCODING", fake, vless_uuid)
    rejected(baseline + "&sni=x.example.invalid&", "INVALID_QUERY", vless_uuid)


def test_unsupported_dialects_do_not_fall_back(vless_uuid, trojan_password):
    for raw_query, expected in (
        ("type=ws&host=ws.example.invalid&path=%2Fws", "UNSUPPORTED_SECURITY"),
        ("security=none", "UNSUPPORTED_SECURITY"),
        ("security=real", "UNSUPPORTED_SECURITY"),
        ("security=tls&type=h2", "UNSUPPORTED_TRANSPORT"),
        ("security=tls&type=httpupgrade&host=ws.example.invalid&path=%2F", "UNSUPPORTED_HTTPUPGRADE"),
        ("security=tls&allowInsecure=true", "UNSUPPORTED_INSECURE_NOT_APPROVED"),
        ("security=tls&allowInsecure=maybe", "INVALID_FLAG"),
        ("security=tls&encryption=unknown", "UNSUPPORTED_ENCRYPTION"),
        ("security=tls&fp=random", "UNSUPPORTED_FINGERPRINT"),
        ("security=tls&alpn=h3", "UNSUPPORTED_ALPN"),
        ("security=tls&type=ws&host=ws.example.invalid&path=%2Fws&flow=xtls-rprx-vision", "UNSUPPORTED_FLOW_COMBINATION"),
        ("security=tls&type=grpc&serviceName=api&host=unused.example.invalid", "UNSUPPORTED_TRANSPORT"),
    ):
        rejected(vless(vless_uuid, raw_query), expected, vless_uuid)
    rejected(trojan(trojan_password, "security=none"), "UNSUPPORTED_SECURITY", trojan_password)
    rejected(trojan(trojan_password, "encryption=none"), "UNSUPPORTED_ENCRYPTION", trojan_password)
    rejected(trojan(trojan_password, "type=httpupgrade&path=%2F"), "UNSUPPORTED_HTTPUPGRADE", trojan_password)


def test_reality_key_sid_are_checked_but_mode_stays_unsupported(vless_uuid):
    public_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    sid = secrets.token_hex(8)
    common = f"security=reality&type=tcp&pbk={public_key}&sid={sid}&sni=sni.example.invalid&fp=chrome"
    rejected(vless(vless_uuid, common), "UNSUPPORTED_REALITY", public_key, vless_uuid)
    rejected(vless(vless_uuid, common.replace(public_key, "bad-key")), "UNSUPPORTED_REALITY", vless_uuid)
    rejected(vless(vless_uuid, common.replace(sid, "f")), "UNSUPPORTED_REALITY", vless_uuid)
    rejected(vless(vless_uuid, common.replace(f"sid={sid}", "sid=")), "UNSUPPORTED_REALITY", vless_uuid)
    rejected(vless(vless_uuid, "security=reality&pbk=missing&sid=&sni=sni.example.invalid"),
             "UNSUPPORTED_REALITY", vless_uuid)


def test_ws_grpc_validation_and_ip_requires_sni(vless_uuid):
    for query, expected in (
        ("security=tls&type=ws&path=%2Fpath", "UNSUPPORTED_TRANSPORT"),
        ("security=tls&type=ws&host=ws.example.invalid", "UNSUPPORTED_TRANSPORT"),
        ("security=tls&type=ws&host=ws.example.invalid&path=%0A", "INVALID_QUERY"),
        ("security=tls&type=ws&host=bad%0Ahost&path=%2F", "INVALID_QUERY"),
        ("security=tls&type=grpc", "UNSUPPORTED_TRANSPORT"),
        ("security=tls&type=grpc&serviceName=bad%20space", "INVALID_SERVICE_NAME"),
        ("security=tls&type=grpc&serviceName=api&alpn=http%2F1.1", "UNSUPPORTED_ALPN"),
        ("security=tls&type=tcp&path=%2Funused", "UNSUPPORTED_TRANSPORT"),
    ):
        rejected(vless(vless_uuid, query), expected, vless_uuid)
    rejected(vless(vless_uuid, "security=tls", "203.0.113.2"), "UNSUPPORTED_SNI_REQUIRED", vless_uuid)
    node = parse_uri(vless(vless_uuid, "security=tls&sni=fixture.example.invalid", "203.0.113.2"))
    assert node.sni == "fixture.example.invalid"


def test_bad_line_does_not_hide_next_line_or_leak_secret(vless_uuid, trojan_password):
    first = vless(vless_uuid, "security=tls")
    last = trojan(trojan_password)
    data = (first + "\r\n" + "FAKE_ONLY_BAD%G1" + "\n\n" + last + "\n").encode("utf-8")
    batch = parse_uris(data)
    assert [line.line_number for line in batch.lines] == [1, 2, 4]
    assert batch.skipped_count == 1
    assert batch.lines[0].node is not None and batch.lines[2].node is not None
    assert batch.lines[1].node is None and batch.lines[1].error_code == "UNSUPPORTED_PROTOCOL"
    assert vless_uuid not in repr(batch) and trojan_password not in repr(batch)


def test_utf8_oversize_and_empty_batch_are_fixed_failures(vless_uuid):
    valid = vless(vless_uuid, "security=tls").encode("utf-8")
    batch = parse_uris(valid + b"\n\xff\n" + valid + b"\n")
    assert [line.error_code for line in batch.lines] == ["PROBE_GATE_CLOSED", "INVALID_UTF8", "PROBE_GATE_CLOSED"]
    assert [line.line_number for line in batch.lines] == [1, 2, 3]
    assert batch.skipped_count == 0 and parse_uris(b"").skipped_count == 0
    too_long = b"X" * 8193
    assert parse_uris(too_long).lines[0].error_code == "LINE_TOO_LONG"
    rejected(vless(vless_uuid, "security=tls&path=" + "X" * 8200), "LINE_TOO_LONG", vless_uuid)
