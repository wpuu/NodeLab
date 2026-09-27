"""VLESS URI parsing uses runtime-generated fictional UUIDs only."""

import secrets
import uuid

import pytest

from nodelab.parser import parse_uri, redact_uri
from nodelab.types import NodeURIParseError


@pytest.fixture
def vless_ws():
    fake_uuid = str(uuid.uuid4())
    uri = (f"vless://{fake_uuid}@203.0.113.10:443"
           "?type=ws&security=tls&path=%2Fws-node&host=203.0.113.10"
           "&sni=203.0.113.10&fp=chrome#WS-node-fixture")
    return uri, fake_uuid


def test_vless_ws_fields_are_private(vless_ws):
    uri, fake_uuid = vless_ws
    node = parse_uri(uri)
    assert node.protocol == "vless" and node.entry_host == "203.0.113.10"
    assert node.entry_port == 443 and node.transport == "ws" and node.tls_mode == "tls"
    assert node.sni == "203.0.113.10" and node.ws_host == "203.0.113.10"
    assert node.ws_path == "/ws-node" and node.client_fingerprint == "chrome"
    assert node.secret == fake_uuid and not hasattr(node, "display_name")


def test_vless_public_dict_has_no_uuid(vless_ws):
    uri, fake_uuid = vless_ws
    node = parse_uri(uri)
    assert fake_uuid not in str(node.public_dict())
    assert fake_uuid not in repr(node)
    assert "display_name" not in node.public_dict()


def test_vless_uri_never_displayed_even_when_masked(vless_ws):
    uri, fake_uuid = vless_ws
    output = redact_uri(uri)
    assert output == "[URI_REDACTED]" and fake_uuid not in output


def test_vless_path_hint_is_not_hop_count():
    fake_uuid = str(uuid.uuid4())
    uri = (f"vless://{fake_uuid}@198.51.100.7:443"
           "?type=ws&security=tls&path=%2Fproxyip%3D2.2.2.2%3A443%2C3.3.3.3%3A443"
           "&host=proxy.example.invalid&sni=proxy.example.invalid#fixture")
    node = parse_uri(uri)
    assert "contains_proxyip_list" in node.path_features
    assert "2-hop" not in repr(node) and "3-hop" not in repr(node)


def test_vless_invalid_uuid_raises_fixed_code():
    fake_invalid = "FAKE_ONLY_" + secrets.token_urlsafe(25)
    with pytest.raises(NodeURIParseError) as info:
        parse_uri(f"vless://{fake_invalid}@198.51.100.8:443?security=tls")
    assert info.value.code == "INVALID_SECRET"
    assert fake_invalid not in str(info.value)


def test_vless_missing_port_raises():
    fake_uuid = str(uuid.uuid4())
    with pytest.raises(NodeURIParseError):
        parse_uri(f"vless://{fake_uuid}@198.51.100.9?security=tls")


def test_vless_unsupported_scheme_rejected():
    fake_value = "FAKE_ONLY_" + secrets.token_urlsafe(25)
    for scheme in ("vmess", "ss"):
        with pytest.raises(NodeURIParseError) as info:
            parse_uri(f"{scheme}://{fake_value}@198.51.100.9:443")
        assert info.value.code == "UNSUPPORTED_PROTOCOL" and info.value.probe_status == "UNSUPPORTED"


def test_vless_chinese_fragment_is_never_stored():
    fake_uuid = str(uuid.uuid4())
    uri = (f"vless://{fake_uuid}@198.51.100.9:443?security=tls&sni=fixture.example.invalid"
           "#%E4%B8%AD%E6%96%87%E5%A4%87%E6%B3%A8")
    node = parse_uri(uri)
    assert not hasattr(node, "display_name")
    assert "中文备注" not in str(node.public_dict()) and "中文备注" not in repr(node)
