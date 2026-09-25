"""Unit tests: redaction invariants."""

import json

from nodelab.parser import parse_uri, redact_uri
from nodelab.redaction import redacted_node_dict, redacted_result_dict

VLESS_UUID = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
TROJAN_PW = "p@ss-w0rd-x"


def test_vless_json_has_no_uuid():
    uri = f"vless://{VLESS_UUID}@198.51.100.44:443?security=tls#n"
    node = parse_uri(uri)
    out = json.dumps(redacted_node_dict(node), ensure_ascii=False)
    assert VLESS_UUID not in out
    assert "***" in out


def test_trojan_json_has_no_password():
    uri = f"trojan://{TROJAN_PW}@198.51.100.45:443?security=tls#n"
    node = parse_uri(uri)
    out = json.dumps(redacted_result_dict(node.public_dict() | {"redacted_uri": redact_uri(uri)}),
                     ensure_ascii=False)
    assert TROJAN_PW not in out


def test_exception_text_never_contains_secret():
    from nodelab.types import NodeURIParseError

    bad = f"vless://definitely-not-a-uuid@198.51.100.46:443?security=tls"
    try:
        parse_uri(bad)
        raise AssertionError("expected NodeURIParseError")
    except NodeURIParseError as exc:
        msg = str(exc)
        # the raw secret never appears; only the redacted form is allowed
        assert "definitely-not-a-uuid" not in msg


def test_redacted_result_swallows_nested_uuid():
    base = redacted_node_dict(parse_uri(f"vless://{VLESS_UUID}@198.51.100.47:443"))
    base["note"] = f"uuid={VLESS_UUID} was seen"
    scrubbed = redacted_result_dict(base)
    out = json.dumps(scrubbed, ensure_ascii=False)
    assert VLESS_UUID not in out
    assert scrubbed.get("secret") is None
