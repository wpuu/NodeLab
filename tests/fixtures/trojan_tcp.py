"""Test-only Trojan/TCP over TLS endpoint. No UDP/mux/WS/gRPC or fallback."""
import hashlib
import hmac
import socket

from tests.fixtures.tls_forwarder import LocalTLSForwarder, _exact


class TrojanTCPFixture(LocalTLSForwarder):
    def __init__(self, password, tls, allowed_destinations):
        if type(password) is not str or not password:
            raise ValueError("INVALID_LOCAL_FIXTURE")
        credential = hashlib.sha224(password.encode()).hexdigest().encode("ascii")
        super().__init__(credential, tls, allowed_destinations)

    def __repr__(self):
        return "TrojanTCPFixture(<private>)"

    def _read_destination(self, secure):
        auth = _exact(secure, 56)
        if not hmac.compare_digest(auth, self._expected) or _exact(secure, 2) != b"\r\n":
            raise ValueError("AUTH_REJECTED")
        if _exact(secure, 1) != b"\x01":
            raise ValueError("TCP_ONLY")
        kind = _exact(secure, 1)
        if kind == b"\x01":
            host = socket.inet_ntop(socket.AF_INET, _exact(secure, 4))
        elif kind == b"\x04":
            host = socket.inet_ntop(socket.AF_INET6, _exact(secure, 16))
        elif kind == b"\x03":
            length = _exact(secure, 1)[0]
            if length == 0:
                raise ValueError("EMPTY_HOST")
            host = _exact(secure, length).decode("ascii")
        else:
            raise ValueError("ADDRESS_TYPE_REJECTED")
        port = int.from_bytes(_exact(secure, 2), "big")
        if _exact(secure, 2) != b"\r\n":
            raise ValueError("HEADER_REJECTED")
        return host, port
