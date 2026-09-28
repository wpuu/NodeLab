"""Pure response syntax/address tests; no network or production authorization."""
import json
import secrets

import pytest

from nodelab.exit_response import ExitResponseError, parse_exit_response


def body(source, ip):
    return json.dumps({"ip": ip}).encode() if source == "EXIT_A" else f"ip={ip}\n".encode()


@pytest.mark.parametrize("source", ["EXIT_A", "EXIT_B"])
@pytest.mark.parametrize("ip,normalized", [("8.8.8.8", "8.8.8.8"),
    ("2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111")])
def test_valid_global_unicast_ip(source, ip, normalized):
    parsed = parse_exit_response(source, body(source, ip))
    assert str(parsed.address) == normalized
    assert parsed.source == source
    assert repr(parsed) == "ExitAddress(<private>)"


@pytest.mark.parametrize("source", ["EXIT_A", "EXIT_B"])
@pytest.mark.parametrize("ip", ["192.0.2.7", "198.51.100.7", "203.0.113.7", "2001:db8::7"])
def test_documentation_addresses_require_explicit_fixture_flag(source, ip):
    with pytest.raises(ExitResponseError, match="^EXIT_IP_NOT_PUBLIC$"):
        parse_exit_response(source, body(source, ip))
    assert str(parse_exit_response(source, body(source, ip), fixture_addresses=True).address) == ip


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "169.254.1.1", "100.64.0.1",
    "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "fc00::1", "ff02::1"])
def test_fixture_mode_does_not_accept_arbitrary_nonpublic_or_multicast(ip):
    with pytest.raises(ExitResponseError, match="^EXIT_IP_NOT_PUBLIC$"):
        parse_exit_response("EXIT_A", body("EXIT_A", ip), fixture_addresses=True)


@pytest.mark.parametrize("ip", ["", " 8.8.8.8", "8.8.8.8 ", "8.8.8.8\n", "008.8.8.8",
    "8.8.8.8:443", "[2606:4700::1111]", "::ffff:8.8.8.8", "2606:4700::1111%secret",
    "example.invalid", "８.8.8.8", "1" * 100, True, 123, None, ["8.8.8.8"]])
def test_ip_values_are_not_coerced(ip):
    with pytest.raises(ExitResponseError, match="^EXIT_IP_INVALID$"):
        parse_exit_response("EXIT_A", body("EXIT_A", ip))


@pytest.mark.parametrize("value", [
    b'{"ip":"8.8.8.8","ip":"8.8.8.8"}', b'{"ip":"8.8.8.8","ip":"1.1.1.1"}',
    b'{"ip":"8.8.8.8","extra":true}', b'["8.8.8.8"]', b'"8.8.8.8"',
    b'{"ip":NaN}', b'{"ip":Infinity}', b'{}', b'null', b'{', b'\xff',
    b'\xef\xbb\xbf{"ip":"8.8.8.8"}', b'{"ip":"8.8.8.8"}garbage',
])
def test_ipify_ambiguous_or_malformed_json_rejected(value):
    with pytest.raises(ExitResponseError, match="^EXIT_BODY_INVALID$"):
        parse_exit_response("EXIT_A", value)


def test_trace_allows_unrelated_fields_and_crlf_but_not_duplicate_ip():
    response = b"fl=synthetic\r\nh=localhost\r\nip=8.8.8.8\r\nuag=synthetic=a\r\ntls=TLSv1.3\r\n"
    assert str(parse_exit_response("EXIT_B", response).address) == "8.8.8.8"


@pytest.mark.parametrize("value", [b"ip=8.8.8.8\nip=8.8.8.8\n", b"h=a\nh=b\nip=8.8.8.8\n",
    b"IP=8.8.8.8\n", b"ip:8.8.8.8", b"h=localhost\n", b"ip=8.8.8.8\n\n",
    b"ip=8.8.8.8\nh=abc\x00\n", b"ip=8.8.8.8\rh=a", b"ip=8.8.8.8\r", b"\xff", b"ip=8.8.8.8\n" * 129])
def test_trace_malformed_or_ambiguous_fields_rejected(value):
    with pytest.raises(ExitResponseError, match="^EXIT_BODY_INVALID$"):
        parse_exit_response("EXIT_B", value)


@pytest.mark.parametrize("source", ["EXIT_A", "EXIT_B"])
def test_body_size_and_input_type_are_bounded(source):
    with pytest.raises(ExitResponseError, match="^EXIT_BODY_TOO_LARGE$"):
        parse_exit_response(source, b"x" * (64 * 1024 + 1))
    with pytest.raises(ExitResponseError, match="^EXIT_BODY_INVALID$"):
        parse_exit_response(source, "ip=8.8.8.8")
    with pytest.raises(ExitResponseError, match="^EXIT_BODY_INVALID$"):
        parse_exit_response(source, body(source, "8.8.8.8"), fixture_addresses=1)


def test_errors_do_not_echo_secret_like_values():
    sentinel = secrets.token_urlsafe(32)
    for source in ("EXIT_A", "EXIT_B"):
        with pytest.raises(ExitResponseError) as exc:
            parse_exit_response(source, body(source, sentinel))
        assert sentinel not in str(exc.value)
        assert sentinel not in repr(exc.value)
    with pytest.raises(ExitResponseError, match="^EXIT_SOURCE_INVALID$"):
        parse_exit_response(sentinel, b"{}")
