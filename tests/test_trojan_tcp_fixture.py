"""Actual local Trojan/TCP + TLS handshakes, independent Python test client.

No Mihomo/controller substitute and no invented connection evidence here.
Passing proves only this fixture/client pair, not Mihomo interoperability.
"""
from contextlib import contextmanager
import hashlib
import secrets
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import threading

import pytest

from tests.fixtures.trojan_tcp import TrojanTCPFixture


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("OpenSSL needed for local Trojan/TLS fixture")
    folder = tmp_path_factory.mktemp("trojan-tcp-ca")
    key, cert = folder / "key.pem", folder / "cert.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=fixture.example.invalid", "-addext",
        "subjectAltName=DNS:fixture.example.invalid,DNS:localhost,IP:127.0.0.1",
        "-keyout", str(key), "-out", str(cert)], check=True, timeout=15,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    server.set_alpn_protocols(["http/1.1"])
    client = ssl.create_default_context(cafile=str(cert))
    client.set_alpn_protocols(["http/1.1"])
    yield server, client, cert
    key.unlink()
    cert.unlink()


@contextmanager
def echo_server():
    received = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                while chunk := self.request.recv(65536):
                    received.append(chunk)
                    self.request.sendall(chunk)
            except OSError:
                pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def header(password, host, port, kind="domain"):
    # Independent client-side encoder from the fixed transport specification.
    if kind == "ipv4":
        address = b"\x01" + socket.inet_pton(socket.AF_INET, host)
    elif kind == "ipv6":
        address = b"\x04" + socket.inet_pton(socket.AF_INET6, host)
    else:
        encoded = host.encode("ascii")
        address = b"\x03" + bytes([len(encoded)]) + encoded
    return hashlib.sha224(password.encode()).hexdigest().encode() + b"\r\n\x01" + address + struct.pack("!H", port) + b"\r\n"


def connect(server, context, hostname="fixture.example.invalid"):
    raw = socket.create_connection(("127.0.0.1", server.port), timeout=2)
    try:
        return context.wrap_socket(raw, server_hostname=hostname)
    except BaseException:
        raw.close()
        raise


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        assert chunk
        data.extend(chunk)
    return bytes(data)


@pytest.mark.parametrize("host,kind", [("localhost", "domain"), ("127.0.0.1", "ipv4"), ("::1", "ipv6")])
@pytest.mark.parametrize("fragmented", [False, True])
def test_actual_trojan_header_and_bidirectional_payload(tls_material, host, kind, fragmented):
    password, payload = secrets.token_urlsafe(32), secrets.token_bytes(8192)
    with echo_server() as (port, received):
        with TrojanTCPFixture(password, tls_material[0], {(host, port)}) as server:
            with connect(server, tls_material[1]) as client:
                assert client.selected_alpn_protocol() == "http/1.1"
                greeting = header(password, host, port, kind)
                if fragmented:
                    for byte in greeting:
                        client.sendall(bytes([byte]))
                else:
                    client.sendall(greeting)
                client.sendall(payload)
                assert exact(client, len(payload)) == payload
        assert server.counts["authenticated"] == 1
        assert server.counts["forwarded"] == 1
        assert b"".join(received) == payload
        assert password not in repr(server)


@pytest.mark.parametrize("fault", ["password", "uppercase_hash", "auth_crlf", "udp", "mux", "address_type",
                                    "external_host", "external_ip", "other_port", "end_crlf", "truncated"])
def test_bad_credentials_framing_or_destination_never_forwards(tls_material, fault):
    password = secrets.token_urlsafe(32)
    with echo_server() as (port, received):
        with TrojanTCPFixture(password, tls_material[0], {("localhost", port)}) as server:
            greeting = header(password, "localhost", port)
            if fault == "password":
                greeting = header(secrets.token_urlsafe(32), "localhost", port)
            elif fault == "uppercase_hash":
                greeting = greeting[:56].upper() + greeting[56:]
            elif fault == "auth_crlf":
                greeting = greeting[:56] + b"xx" + greeting[58:]
            elif fault in ("udp", "mux"):
                greeting = greeting[:58] + (b"\x03" if fault == "udp" else b"\x7f") + greeting[59:]
            elif fault == "address_type":
                greeting = greeting[:59] + b"\x09" + greeting[60:]
            elif fault == "external_host":
                greeting = header(password, "outside.example.invalid", port)
            elif fault == "external_ip":
                greeting = header(password, "198.51.100.1", port, "ipv4")
            elif fault == "other_port":
                greeting = header(password, "localhost", 1)
            elif fault == "end_crlf":
                greeting = greeting[:-2] + b"xx"
            else:
                greeting = greeting[:30]
            with connect(server, tls_material[1]) as client:
                client.sendall(greeting)
                if fault != "truncated":
                    try:
                        assert client.recv(1) == b""
                    except (ssl.SSLError, ConnectionResetError):
                        pass
        assert server.counts["forwarded"] == 0
        assert server.counts["rejected"] >= 1
        assert received == []


@pytest.mark.parametrize("fault", ["untrusted_ca", "wrong_hostname"])
def test_tls_verification_is_not_bypassed(tls_material, fault):
    password = secrets.token_urlsafe(32)
    with echo_server() as (port, received):
        with TrojanTCPFixture(password, tls_material[0], {("localhost", port)}) as server:
            context = ssl.create_default_context() if fault == "untrusted_ca" else tls_material[1]
            hostname = "wrong.example.invalid" if fault == "wrong_hostname" else "fixture.example.invalid"
            with pytest.raises(ssl.SSLCertVerificationError):
                connect(server, context, hostname)
        assert server.counts["forwarded"] == 0
        assert received == []


def test_fixture_refuses_nonlocal_allowlist(tls_material):
    with pytest.raises(ValueError, match="^INVALID_LOCAL_FIXTURE$"):
        TrojanTCPFixture(secrets.token_urlsafe(32), tls_material[0], {("8.8.8.8", 443)})
