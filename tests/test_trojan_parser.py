"""Unit tests: Trojan parser (fictional credentials only)."""

import pytest

from nodelab.parser import parse_uri, redact_uri
from nodelab.types import NodeURIParseError

TROJAN_WS = (
    "trojan://s3cr3t-p4ssw0rd@203.0.113.20:443"
    "?type=ws&security=tls&path=%2Ftrojan-ws&host=203.0.113.20&fp=chrome"
    "#TROJAN-ws-02"
)


def test_trojan_ws_tls_fields():
    node = parse_uri(TROJAN_WS)
    assert node.protocol == "trojan"
    assert node.entry_host == "203.0.113.20"
    assert node.entry_port == 443
    assert node.transport == "ws"
    assert node.tls is True
    assert node.sni == "203.0.113.20"
    assert node.host_header == "203.0.113.20"
    assert node.path == "/trojan-ws"
    assert node.display_name == "TROJAN-ws-02"
    assert node.secret == "s3cr3t-p4ssw0rd"


def test_trojan_public_dict_has_no_password():
    node = parse_uri(TROJAN_WS)
    d = node.public_dict()
    assert "secret" not in d
    assert "s3cr3t-p4ssw0rd" not in str(d)
    assert "s3cr3t-p4ssw0rd" not in repr(node)


def test_trojan_redact_uri_blanks_password():
    r = redact_uri(TROJAN_WS)
    assert "s3cr3t-p4ssw0rd" not in r
    assert "***" in r


def test_trojan_chinese_fragment_and_host():
    uri = (
        "trojan://another%2Bpw@198.51.100.33:8443"
        "?type=ws&security=tls&host=example.com&sni=example.com"
        "#%E8%AE%A8%E8%AE%AE%E5%8D%95%E8%8A%82%E7%82%B9"
    )
    node = parse_uri(uri)
    assert node.display_name == "讨议单节点"
    assert node.sni == "example.com"
    assert node.host_header == "example.com"
    assert node.secret == "another+pw"


def test_trojan_unparseable_line_in_batch():
    from nodelab.parser import parse_uris

    text = f"{TROJAN_WS}\ngarbage-line\n"
    out = parse_uris(text)
    assert out[0] is not None
    assert out[1] is None
