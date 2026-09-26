"""Fixed public serialization: fresh fictional secrets, no regexp masking."""

import json
import secrets
import uuid
from urllib.parse import quote

from nodelab.parser import parse_uri, redact_uri
from nodelab.redaction import redacted_node_dict, redacted_result_dict
from nodelab.types import NodeURIParseError


def test_vless_json_has_no_uuid_or_fragment():
    fake_uuid = str(uuid.uuid4())
    fragment = "FAKE_ONLY_" + secrets.token_urlsafe(25)
    uri = f"vless://{fake_uuid}@198.51.100.44:443?security=tls#{fragment}"
    node = parse_uri(uri)
    public = json.dumps(redacted_node_dict(node), ensure_ascii=False)
    assert fake_uuid not in public and fragment not in public
    assert "redacted_uri" not in public and "display_name" not in public
    assert node.public_dict()["protocol"] == "vless"


def test_trojan_password_inside_uri_component_never_enters_public_view():
    password = "FAKE_ONLY_" + secrets.token_urlsafe(25) + "@colons:allowed"
    uri = f"trojan://{quote(password, safe='')}@198.51.100.45:443?security=tls#{quote(password)}"
    node = parse_uri(uri)
    assert node.secret == password
    result = redacted_result_dict(node.public_dict() | {"redacted_uri": redact_uri(uri)})
    out = json.dumps(result, ensure_ascii=False)
    assert password not in out and quote(password, safe='') not in out
    assert "redacted_uri" not in out


def test_exception_has_fixed_code_only():
    secret = "FAKE_ONLY_" + secrets.token_urlsafe(25)
    try:
        parse_uri(f"vless://{secret}@198.51.100.46:443?security=tls")
    except NodeURIParseError as exc:
        assert str(exc) == exc.code == "INVALID_SECRET"
        assert secret not in repr(exc)
    else:
        raise AssertionError("invalid synthetic UUID was accepted")


def test_arbitrary_nested_strings_and_keys_are_dropped():
    secret = "FAKE_ONLY_" + secrets.token_urlsafe(25)
    fake_uuid = str(uuid.uuid4())
    base = redacted_node_dict(parse_uri(f"vless://{fake_uuid}@198.51.100.47:443"))
    base["note"] = {secret: [{"password": secret}]}
    base["error_code"] = "FAIL_" + secret
    result = redacted_result_dict(base)
    assert result["error_code"] == "PUBLIC_SCHEMA_REJECTED"
    assert secret not in json.dumps(result, ensure_ascii=False)
