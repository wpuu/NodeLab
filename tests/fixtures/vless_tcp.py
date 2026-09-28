"""Test-only VLESS v0/TCP over verified TLS, no addons/flow/encryption extension.

Anchored to Mihomo v1.19.31 transport/vless/{vless,conn}.go. VLESS address types
and port placement are NOT SOCKS5/Trojan's; a shared relay must not share codecs.
No controller data is synthesized. Never use real credentials with this fixture.
"""
import hmac
import socket
from uuid import UUID

from tests.fixtures.tls_forwarder import LocalTLSForwarder, _exact


class VlessTCPFixture(LocalTLSForwarder):
    def __init__(self, uuid_text, tls, allowed_destinations):
        try:
            if type(uuid_text) is not str or str(UUID(uuid_text)) != uuid_text:
                raise ValueError()
            credential = UUID(uuid_text).bytes
        except ValueError:
            raise ValueError("INVALID_LOCAL_FIXTURE") from None
        super().__init__(credential, tls, allowed_destinations)

    def __repr__(self):
        return "VlessTCPFixture(<private>)"

    def _read_destination(self, secure):
        if _exact(secure, 1) != b"\x00":
            raise ValueError("VERSION_REJECTED")
        if not hmac.compare_digest(_exact(secure, 16), self._expected):
            raise ValueError("AUTH_REJECTED")
        # Nonzero addons may request Vision/flow or other extensions. They
        # must not silently become ordinary TLS/TCP in a basic fixture.
        if _exact(secure, 1) != b"\x00":
            raise ValueError("ADDONS_UNSUPPORTED")
        if _exact(secure, 1) != b"\x01":
            raise ValueError("TCP_ONLY")
        port = int.from_bytes(_exact(secure, 2), "big")
        kind = _exact(secure, 1)
        if kind == b"\x01":
            host = socket.inet_ntop(socket.AF_INET, _exact(secure, 4))
        elif kind == b"\x03":
            host = socket.inet_ntop(socket.AF_INET6, _exact(secure, 16))
        elif kind == b"\x02":
            length = _exact(secure, 1)[0]
            if not length:
                raise ValueError("EMPTY_HOST")
            host = _exact(secure, length).decode("ascii")
        else:
            raise ValueError("ADDRESS_TYPE_REJECTED")
        return host, port

    def _acknowledge(self, secure):
        # Version zero + zero response addons. Only sent once authentication,
        # destination allowlisting and the actual upstream connect succeeded.
        secure.sendall(b"\x00\x00")
