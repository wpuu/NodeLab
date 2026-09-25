"""Unit tests: VLESS parser (fictional credentials and RFC example IPs only)."""

import pytest

from nodelab.parser import parse_uri, redact_uri
from nodelab.types import NodeURIParseError

VLESS_WS = (
    "vless://6c4c6c3e-8d8d-4c8c-9e8c-6c3f0f5c2d1e@203.0.113.10:443"
    "?type=ws&security=tls&path=%2Fws-node&host=203.0.113.10&fp=chrome"
    "#WS-node-01"
)


def test_vless_ws_tls_fields():
    node = parse_uri(VLESS_WS)
    assert node.protocol == "vless"
    assert node.entry_host == "203.0.113.10"
    assert node.entry_port == 443
    assert node.transport == "ws"
    assert node.tls is True
    assert node.sni == "203.0.113.10"
    assert node.host_header == "203.0.113.10"
    assert node.path == "/ws-node"
    assert node.client_fingerprint == "chrome"
    assert node.display_name == "WS-node-01"
    assert node.secret == "6c4c6c3e-8d8d-4c8c-9e8c-6c3f0f5c2d1e"


def test_vless_public_dict_has_no_uuid():
    node = parse_uri(VLESS_WS)
    d = node.public_dict()
    assert "secret" not in d
    assert node.secret not in str(d)
    # repr also safe
    assert node.secret not in repr(node)


def test_vless_redact_uri_blanks_secret():
    r = redact_uri(VLESS_WS)
    assert "6c4c6c3e-8d8d-4c8c-9e8c-6c3f0f5c2d1e" not in r
    assert "***" in r


def test_vless_sniproxy_path_flagged_not_claimed():
    uri = (
        "vless://6c4c6c3e-8d8d-4c8c-9e8c-6c3f0f5c2d1e@198.51.100.7:443"
        "?type=ws&security=tls&path=%2Fproxyip%3D2.2.2.2%3A443%2C3.3.3.3%3A443"
        "#flag"
    )
    node = parse_uri(uri)
    assert "contains_proxyip_list" in node.path_features
    # no hop-count claim anywhere
    assert "2-hop" not in repr(node) and "3-hop" not in repr(node)


def test_vless_invalid_uuid_raises():
    uri = "vless://not-a-uuid@198.51.100.8:443?security=tls"
    with pytest.raises(NodeURIParseError) as exc:
        parse_uri(uri)
    assert "not-a-uuid" not in str(exc.value)


def test_vless_missing_port_raises():
    uri = "vless://6c4c6c3e-8d8d-4c8c-9e8c-6c3f0f5c2d1e@198.51.100.9?security=tls"
    with pytest.raises(NodeURIParseError):
        parse_uri(uri)


def test_vless_unsupported_scheme_rejected():
    with pytest.raises(NodeURIParseError):
        parse_uri("vmess://deadbeef@198.51.100.9:443")
    with pytest.raises(NodeURIParseError):
        parse_uri("ss://c2VjcmV0AQ@198.51.100.9:8388")


def test_vless_chinese_fragment_decodes():
    uri = (
        "vless://6c4c6c3e-8d8d-4c8c-9e8c-6c3f0f5c2d1e@198.51.100.9:443"
        "?security=tls"
        "#%E4%B8%AD%E6%96%87%E5%A4%87%E6%B3%A8"
    )
    node = parse_uri(uri)
    assert node.display_name == "中文备注"
