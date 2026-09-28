"""Test-only TLS/loopback forwarding shared by strict protocol fixtures.

This is not a server for real credentials or external destinations. Protocol
subclasses must authenticate and decode a destination before any upstream I/O.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
import select
import socket
import socketserver
import ssl
import threading
import time


def _exact(stream, size):
    value = bytearray()
    while len(value) < size:
        chunk = stream.recv(size - len(value))
        if not chunk:
            raise ValueError("INCOMPLETE_FIXTURE_HEADER")
        value.extend(chunk)
    return bytes(value)


def _close(stream):
    try:
        stream.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    stream.close()


class LocalTLSForwarder(ABC):
    def __init__(self, credential: bytes, tls: ssl.SSLContext, allowed_destinations: set[tuple[str, int]]):
        if (type(credential) is not bytes or not credential or not allowed_destinations
                or any(host not in ("localhost", "127.0.0.1", "::1") or type(port) is not int
                       or not 1 <= port <= 65535 for host, port in allowed_destinations)):
            raise ValueError("INVALID_LOCAL_FIXTURE")
        self._expected = credential
        self._allowed = frozenset(allowed_destinations)
        self._tls = tls
        self._lock = threading.Lock()
        self._sockets = set()
        self._stop = threading.Event()
        self._authenticated = 0
        self._rejected = 0
        self._rejected_event = threading.Event()
        self._forwarded = []
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                owner._handle(self.request)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = False  # server_close joins after we close every owned socket

            def handle_error(self, request, client_address):
                # No arbitrary exception/credential bytes in pytest output.
                with owner._lock:
                    owner._rejected += 1

        self._server = Server(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()

    def __repr__(self):
        return "LocalTLSForwarder(<private>)"

    @property
    def port(self):
        return self._server.server_address[1]

    @property
    def counts(self):
        with self._lock:
            return {"authenticated": self._authenticated, "rejected": self._rejected,
                    "forwarded": len(self._forwarded)}

    def wait_rejected(self, timeout=2):
        return self._rejected_event.wait(timeout)

    def _track(self, stream):
        with self._lock:
            if self._stop.is_set():
                _close(stream)
                raise OSError("FIXTURE_CLOSED")
            self._sockets.add(stream)
        return stream

    @abstractmethod
    def _read_destination(self, secure):
        raise NotImplementedError("FIXTURE_CODEC_REQUIRED")

    def _acknowledge(self, secure):
        pass

    def _handle(self, raw):
        secure = remote = None
        try:
            raw.settimeout(2)
            self._track(raw)
            secure = self._tls.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            self._track(secure)
            secure.do_handshake()
            host, port = self._read_destination(secure)
            if (host, port) not in self._allowed:
                raise ValueError("DESTINATION_REJECTED")
            with self._lock:
                self._authenticated += 1
            # Never resolve supplied DNS or dial a supplied IP: all allowlisted
            # aliases map to the fixture's controlled IPv4 loopback service.
            remote = self._track(socket.create_connection(("127.0.0.1", port), timeout=2))
            remote.settimeout(0.5)
            secure.settimeout(0.5)
            self._acknowledge(secure)
            with self._lock:
                self._forwarded.append((host, port))
            deadline = time.monotonic() + 20
            while not self._stop.is_set() and time.monotonic() < deadline:
                ready, _, _ = select.select([secure, remote], [], [], 0.05)
                if secure.pending() and secure not in ready:
                    ready.append(secure)
                for stream in ready:
                    try:
                        chunk = stream.recv(65536)
                    except socket.timeout:
                        continue
                    if not chunk:
                        return
                    (remote if stream is secure else secure).sendall(chunk)
        except (OSError, ValueError, UnicodeError):
            with self._lock:
                self._rejected += 1
            self._rejected_event.set()
        finally:
            for stream in (remote, secure, raw):
                if stream is not None:
                    with self._lock:
                        self._sockets.discard(stream)
                    _close(stream)

    def close(self):
        self._stop.set()
        self._server.shutdown()
        with self._lock:
            streams = list(self._sockets)
        for stream in streams:
            _close(stream)
        self._server.server_close()
        self._thread.join(timeout=3)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
        return False
