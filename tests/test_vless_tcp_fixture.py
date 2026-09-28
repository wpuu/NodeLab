"""Actual local VLESS v0/TCP+TLS fixture, independently encoded Python client.

These tests are not Mihomo interoperability evidence and generate no route rows.
"""
import secrets
import socket
import ssl
import struct
from uuid import UUID, uuid4

import pytest

from tests.fixtures.vless_tcp import VlessTCPFixture
from tests.test_trojan_tcp_fixture import tls_material, echo_server, connect, exact, header as trojan_header


def header(uuid_text, host, port, kind="domain", *, version=0, command=1, addons=b""):
    if kind == "ipv4":
        address = b"\x01" + socket.inet_pton(socket.AF_INET, host)
    elif kind == "ipv6":
        address = b"\x03" + socket.inet_pton(socket.AF_INET6, host)
    else:
        raw = host.encode("ascii")
        address = b"\x02" + bytes([len(raw)]) + raw
    return (bytes([version]) + UUID(uuid_text).bytes + bytes([len(addons)]) + addons
            + bytes([command]) + struct.pack("!H", port) + address)


@pytest.mark.parametrize("host,kind", [("localhost", "domain"), ("127.0.0.1", "ipv4"), ("::1", "ipv6")])
@pytest.mark.parametrize("fragmented", [False, True])
def test_vless_response_header_and_bidirectional_payload(tls_material, host, kind, fragmented):
    credential = str(uuid4())
    payload = secrets.token_bytes(8192)
    with echo_server() as (port, received):
        with VlessTCPFixture(credential, tls_material[0], {(host, port)}) as server:
            with connect(server, tls_material[1]) as client:
                greeting = header(credential, host, port, kind)
                if fragmented:
                    for byte in greeting:
                        client.sendall(bytes([byte]))
                    client.sendall(payload)
                else:
                    # Mihomo includes its initial application bytes in the
                    # same write as the header; they must not be discarded.
                    client.sendall(greeting + payload)
                assert exact(client, 2) == b"\x00\x00"
                assert exact(client, len(payload)) == payload
                client.sendall(b"second-write")
                assert exact(client, 12) == b"second-write"  # no second response header
        assert server.counts["authenticated"] == 1
        assert server.counts["forwarded"] == 1
        assert b"".join(received) == payload + b"second-write"
        assert credential not in repr(server)


@pytest.mark.parametrize("fault", ["uuid", "text_uuid", "version", "addons", "vision_addons", "udp", "mux",
    "address_type", "socks5_domain_type", "empty_host", "external_host", "external_ip", "zero_port", "truncated", "trojan_header"])
def test_invalid_vless_never_acknowledges_or_forwards(tls_material, fault):
    credential = str(uuid4())
    with echo_server() as (port, received):
        with VlessTCPFixture(credential, tls_material[0], {("localhost", port)}) as server:
            greeting = header(credential, "localhost", port)
            if fault == "uuid":
                greeting = header(str(uuid4()), "localhost", port)
            elif fault == "text_uuid":
                greeting = b"\x00" + credential.encode() + greeting[17:]
            elif fault == "version":
                greeting = header(credential, "localhost", port, version=1)
            elif fault in ("addons", "vision_addons"):
                addons = b"x" if fault == "addons" else b"\x0a\x10xtls-rprx-vision"
                greeting = header(credential, "localhost", port, addons=addons)
            elif fault in ("udp", "mux"):
                greeting = header(credential, "localhost", port, command=2 if fault == "udp" else 3)
            elif fault == "address_type":
                greeting = greeting[:21] + b"\x04" + greeting[22:]
            elif fault == "socks5_domain_type":
                greeting = greeting[:21] + b"\x03" + b"\x09localhost".ljust(16, b"\x00")
            elif fault == "empty_host":
                greeting = greeting[:21] + b"\x02\x00"
            elif fault == "external_host":
                greeting = header(credential, "outside.example.invalid", port)
            elif fault == "external_ip":
                greeting = header(credential, "198.51.100.1", port, "ipv4")
            elif fault == "zero_port":
                greeting = header(credential, "localhost", 0)
            elif fault == "trojan_header":
                greeting = trojan_header(secrets.token_urlsafe(32), "localhost", port)
            else:
                greeting = greeting[:10]
            with connect(server, tls_material[1]) as client:
                client.sendall(greeting)
                if fault != "truncated":
                    try:
                        assert client.recv(2) == b""
                    except (ssl.SSLError, ConnectionResetError):
                        pass
        assert server.counts["forwarded"] == 0
        assert server.counts["rejected"] >= 1
        assert received == []


@pytest.mark.parametrize("fault", ["untrusted_ca", "wrong_hostname"])
def test_vless_tls_verification_is_required(tls_material, fault):
    with echo_server() as (port, received):
        with VlessTCPFixture(str(uuid4()), tls_material[0], {("localhost", port)}) as server:
            context = ssl.create_default_context() if fault == "untrusted_ca" else tls_material[1]
            hostname = "wrong.example.invalid" if fault == "wrong_hostname" else "fixture.example.invalid"
            with pytest.raises(ssl.SSLCertVerificationError):
                connect(server, context, hostname)
        assert server.counts["forwarded"] == 0
        assert received == []


def test_no_vless_ack_if_allowed_upstream_is_not_listening(tls_material):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))  # owned but deliberately not listening
        port = reserved.getsockname()[1]
        credential = str(uuid4())
        with VlessTCPFixture(credential, tls_material[0], {("localhost", port)}) as server:
            with connect(server, tls_material[1]) as client:
                client.sendall(header(credential, "localhost", port))
                try:
                    assert client.recv(2) == b""
                except (ssl.SSLError, ConnectionResetError):
                    pass
        assert server.counts["forwarded"] == 0
        assert server.counts["rejected"] >= 1


@pytest.mark.parametrize("credential", [None, "not-a-uuid", "1" * 32])
def test_invalid_uuid_rejected_before_listener(tls_material, credential):
    with pytest.raises(ValueError, match="^INVALID_LOCAL_FIXTURE$"):
        VlessTCPFixture(credential, tls_material[0], {("localhost", 443)})


def test_nonlocal_allowlist_rejected(tls_material):
    with pytest.raises(ValueError, match="^INVALID_LOCAL_FIXTURE$"):
        VlessTCPFixture(str(uuid4()), tls_material[0], {("example.invalid", 443)})


@pytest.mark.parametrize("protocol", ["trojan", "vless"])
def test_shared_fixture_close_interrupts_incomplete_header_and_is_repeatable(tls_material, protocol):
    from tests.fixtures.trojan_tcp import TrojanTCPFixture
    factory = VlessTCPFixture if protocol == "vless" else TrojanTCPFixture
    credential = str(uuid4()) if protocol == "vless" else secrets.token_urlsafe(32)
    with echo_server() as (port, received):
        with factory(credential, tls_material[0], {("localhost", port)}) as server:
            with connect(server, tls_material[1]) as client:
                client.sendall(b"\x00" if protocol == "vless" else b"0")
                server.close()
                server.close()
                assert not server._thread.is_alive()
                try:
                    assert client.recv(2) == b""
                except (ssl.SSLError, ConnectionResetError):
                    pass
        assert server.counts["forwarded"] == 0
        assert received == []
