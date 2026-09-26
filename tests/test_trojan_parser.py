"""Legacy parser sanity only; F2 will implement strict protocol dialects."""

import secrets
from urllib.parse import quote

import pytest

from nodelab.parser import parse_uri, parse_uris, redact_uri


@pytest.fixture
def trojan_ws():
    password = "FAKE_ONLY_" + secrets.token_urlsafe(25)
    uri = (f"trojan://{quote(password)}@203.0.113.20:443"
           "?type=ws&security=tls&path=%2Ftrojan-ws&host=203.0.113.20&fp=chrome"
           "#TROJAN-ws-fixture")
    return uri, password


def test_trojan_ws_fields_are_private(trojan_ws):
    uri, password = trojan_ws
    node = parse_uri(uri)
    assert (node.protocol, node.entry_host, node.entry_port) == ("trojan", "203.0.113.20", 443)
    assert node.transport == "ws" and node.tls is True
    assert node.sni == "203.0.113.20" and node.host_header == "203.0.113.20"
    assert node.path == "/trojan-ws" and node.secret == password
    assert node.display_name == "TROJAN-ws-fixture"


def test_trojan_public_dict_has_no_password(trojan_ws):
    uri, password = trojan_ws
    node = parse_uri(uri)
    assert password not in str(node.public_dict())
    assert password not in repr(node) and password not in str(node)
    assert "entry_host" not in node.public_dict()


def test_trojan_redacted_uri_never_contains_the_original(trojan_ws):
    uri, password = trojan_ws
    result = redact_uri(uri)
    assert result == "[URI_REDACTED]" and password not in result


def test_trojan_unicode_fragment_and_encoded_password():
    password = "FAKE_ONLY_" + secrets.token_urlsafe(25) + "+@:"
    uri = (f"trojan://{quote(password, safe='')}@198.51.100.33:8443"
           "?type=ws&security=tls&host=example.invalid&sni=example.invalid"
           "#%E8%AE%A8%E8%AE%AE%E5%8D%95%E8%8A%82%E7%82%B9")
    node = parse_uri(uri)
    assert node.secret == password and node.display_name == "讨议单节点"
    assert node.sni == "example.invalid" and node.host_header == "example.invalid"


def test_trojan_bad_line_does_not_echo_password(trojan_ws):
    uri, password = trojan_ws
    out = parse_uris(uri + "\ngarbage-line\n")
    assert out[0] is not None and out[1] is None
    assert password not in repr(out)
