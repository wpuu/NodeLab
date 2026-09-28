"""Shared opt-in REAL pinned-engine protocol experiment, never a substitute.

Only the source-body release is observed: controller payloads remain unmodified.
Both protocols use the same trust, cleanup, evidence and negative-control rules.
"""
from contextlib import contextmanager, ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import socket
import sys
import threading
from uuid import uuid4

import pytest

from nodelab import engine_binary
from nodelab.connection_reader import BoundConnectionReader
from nodelab.offline_fixture import run_offline_fixture
from nodelab.parser import parse_uri
from nodelab.types import PROBE_GATE_OPEN
from tests.fixtures.trojan_tcp import TrojanTCPFixture
from tests.fixtures.vless_tcp import VlessTCPFixture

@contextmanager
def source_endpoint(tls, body):
    holding, release = threading.Event(), threading.Event()
    hits = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            hits.append(1)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.flush()
            holding.set()
            # Real controller reader observation releases the ORIGINAL body.
            # Timeout is a failed fixture, never a fabricated route proof.
            if release.wait(10):
                try:
                    self.wfile.write(body)
                    self.wfile.flush()
                except OSError:
                    pass
            self.close_connection = True

        def log_message(self, *args):
            pass

    class Server(ThreadingHTTPServer):
        def get_request(self):
            raw, addr = self.socket.accept()
            raw.settimeout(3)
            try:
                return tls.wrap_socket(raw, server_side=True), addr
            except BaseException:
                raw.close()
                raise

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server.server_port, holding, release, hits
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def exercise_real_protocol(tmp_path, monkeypatch, tls_material, case, *, protocol, exe_path):
    assert protocol in ("trojan", "vless")
    if sys.version_info < (3, 12):
        pytest.fail("PYTHON_VERSION_UNSUPPORTED")
    monkeypatch.delenv(engine_binary.PIN_ENV, raising=False)
    exe = Path(exe_path)
    assert engine_binary.verify_pinned_binary(exe) == (True, "BINARY_OK")
    assert engine_binary.file_digest(exe) in engine_binary.KNOWN_DIGESTS
    server_tls, client_tls, cert = tls_material
    empty_ca = tmp_path / "empty-ca.pem"
    empty_ca.write_bytes(b"")
    empty_dir = tmp_path / "empty-ca-directory"
    empty_dir.mkdir()
    # Go SystemCertPool reads these for this child only; no host trust store
    # modification, no skip-cert-verify, no public CA or real node credentials.
    monkeypatch.setenv("SSL_CERT_FILE", str(empty_ca if case == "untrusted_ca" else cert))
    monkeypatch.setenv("SSL_CERT_DIR", str(empty_dir))
    monkeypatch.setenv("DISABLE_EMBED_CA", "true")
    monkeypatch.setenv("DISABLE_SYSTEM_CA", "false")
    with source_endpoint(server_tls, b'{"ip":"192.0.2.7"}') as source_a, \
         source_endpoint(server_tls, b"ip=192.0.2.7\n") as source_b:
        credential = str(uuid4()) if protocol == "vless" else secrets.token_urlsafe(32)
        factory = VlessTCPFixture if protocol == "vless" else TrojanTCPFixture
        with factory(credential, server_tls,
            {(host, source[0]) for host in ("localhost", "127.0.0.1") for source in (source_a, source_b)}) as endpoint:
            original = BoundConnectionReader._read
            observations = []

            def observed_read(reader, deadline):
                payload = original(reader, deadline)  # authenticated real controller, unmodified payload
                for row in payload["connections"] or []:
                    metadata = row["metadata"]
                    for host, source in (("localhost", source_a), ("127.0.0.1", source_b)):
                        target_matches = (metadata.get("host") == host if host == "localhost" else
                                          metadata.get("host") == "" and metadata.get("destinationIP") == host)
                        if (target_matches and metadata.get("destinationPort") == str(source[0])
                                and source[1].is_set()):
                            observations.append((row["id"], row.get("chains")))
                            source[2].set()
                return payload

            monkeypatch.setattr(BoundConnectionReader, "_read", observed_read)
            with ExitStack() as held:
                ports = []
                for _ in range(2):
                    sock = held.enter_context(socket.socket())
                    sock.bind(("127.0.0.1", 0))
                    ports.append(sock.getsockname()[1])
            candidate = credential
            if case in ("wrong_password", "wrong_uuid"):
                candidate = str(uuid4()) if protocol == "vless" else secrets.token_urlsafe(32)
            sni = "wrong.example.invalid" if case == "wrong_sni" else "fixture.example.invalid"
            query = f"security=tls&sni={sni}&type=tcp"
            if protocol == "vless":
                query += "&encryption=none"
            node = parse_uri(f"{protocol}://{candidate}@127.0.0.1:{endpoint.port}?{query}")
            root = tmp_path / "private"
            verdict = run_offline_fixture(node, exe=exe, mixed_port=ports[0], controller_port=ports[1],
                source_a_url=f"https://localhost:{source_a[0]}/a",
                source_b_url=f"https://127.0.0.1:{source_b[0]}/b", tls=client_tls, root=root)
            assert list(root.iterdir()) == []
            if case == "valid":
                assert verdict.status == "PASS", verdict.code  # PRIVATE fixture candidate only
                assert verdict.candidate_ip == "192.0.2.7"
                assert source_a[3] == [1] and source_b[3] == [1]
                assert endpoint.counts["forwarded"] == 2
                assert len({identity for identity, chain in observations if chain == ["NODE", "PROBE"]}) == 2
            else:
                assert verdict.status == "FAIL"
                assert verdict.candidate_ip is None
                assert source_a[3] == [] and source_b[3] == []
                # A preflight/config failure is not a valid protocol negative:
                # prove the engine actually reached and was rejected by TLS/
                # the protocol rather than passing merely because nothing started.
                assert endpoint.wait_rejected(2)
                assert endpoint.counts["rejected"] >= 1
                assert endpoint.counts["forwarded"] == 0
            assert PROBE_GATE_OPEN is False
