"""Trojan URI parsing uses only runtime-generated fictional passwords."""

import secrets
from urllib.parse import quote

import pytest

from nodelab.parser import parse_uri, parse_uris, redact_uri


@pytest.fixture
def trojan_ws():
    password = "FAKE_ONLY_" + secrets.token_urlsafe(25)
    uri = (f"trojan://{quote(password)}@203.0.113.20:443"
           "?type=ws&security=tls&path=%2Ftrojan-ws&host=203.0.113.20"
           "&sni=203.0.113.20&fp=chrome#TROJAN-ws-fixture")
    return uri, password


def test_trojan_ws_fields_are_private(trojan_ws):
    uri, password = trojan_ws
    node = parse_uri(uri)
    assert (node.protocol, node.entry_host, node.entry_port) == ("trojan", "203.0.113.20", 443)
    assert node.transport == "ws" and node.tls_mode == "tls"
    assert node.sni == "203.0.113.20" and node.ws_host == "203.0.113.20"
    assert node.ws_path == "/trojan-ws" and node.secret == password
    assert node.client_fingerprint == "chrome"
    assert not hasattr(node, "display_name")  # fragment is never persisted


def test_trojan_public_dict_has_no_password(trojan_ws):
    uri, password = trojan_ws
    node = parse_uri(uri)
    assert password not in str(node.public_dict())
    assert password not in repr(node) and password not in str(node)
    assert "entry_host" not in node.public_dict()


def test_trojan_redacted_uri_never_contains_original(trojan_ws):
    uri, password = trojan_ws
    result = redact_uri(uri)
    assert result == "[URI_REDACTED]" and password not in result


def test_trojan_unicode_fragment_and_encoded_password():
    password = "FAKE_ONLY_" + secrets.token_urlsafe(25) + "+@:"
    uri = (f"trojan://{quote(password, safe='')}@198.51.100.33:8443"
           "?type=ws&security=tls&host=example.invalid&sni=example.invalid"
           "&path=%2Fdemo#%E8%AE%A8%E8%AE%AE%E5%8D%95%E8%8A%82%E7%82%B9")
    node = parse_uri(uri)
    assert node.secret == password and not hasattr(node, "display_name")
    assert node.sni == node.ws_host == "example.invalid"
    assert node.ws_path == "/demo"


def test_trojan_bad_line_has_fixed_status_not_silent_loss(trojan_ws):
    uri, password = trojan_ws
    batch = parse_uris(uri + "\ngarbage-line\n")
    assert len(batch.lines) == 2 and batch.skipped_count == 0
    assert batch.lines[0].node is not None and batch.lines[1].node is None
    assert batch.lines[1].probe_status == "UNSUPPORTED"
    assert batch.lines[1].error_code == "UNSUPPORTED_PROTOCOL"
    assert password not in repr(batch)
