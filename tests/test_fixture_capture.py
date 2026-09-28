"""Real loopback CONNECT + TLS; controller rows remain synthetic, NOT Mihomo."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import shutil
import socketserver
import ssl
import subprocess
import threading
import time
from uuid import uuid4

import pytest

from nodelab.fixture_capture import collect_fixture_request, FixtureCaptureError
from nodelab.route_evidence import match_pair
from nodelab.types import PROBE_GATE_OPEN


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("local TLS fixture requires openssl")
    folder = tmp_path_factory.mktemp("synthetic-tls")
    key, cert = folder / "key.pem", folder / "cert.pem"
    subprocess.run([
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout", str(key), "-out", str(cert),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    key.chmod(0o600)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    client = ssl.create_default_context(cafile=str(cert))
    yield server, client
    key.unlink()
    cert.unlink()


@contextmanager
def proxy_fixture(certificates, *, status=200, body=b'{"ip":"192.0.2.7"}', mutate=None, second_body=None):
    server_tls, client_tls = certificates
    release = threading.Event()
    closed = threading.Event()
    facts = {"row": None, "connections": 0, "snapshots": 0, "request": None}

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            facts["connections"] += 1
            try:
                with self.request.makefile("rb") as stream:
                    line = stream.readline(8192).decode("ascii")
                    assert line.startswith("CONNECT ")
                    authority = line.split()[1]
                    while stream.readline(8192) not in (b"\r\n", b"\n", b""):
                        pass
                host, port = authority.rsplit(":", 1)
                facts["row"] = {
                    "id": str(uuid4()), "start": datetime.now(timezone.utc).isoformat(),
                    "chains": ["NODE", "PROBE"], "rule": "Match", "rulePayload": "",
                    "metadata": {"network": "tcp", "type": "HTTPS", "host": "" if host == "127.0.0.1" else host,
                        "destinationIP": "127.0.0.1" if host == "127.0.0.1" else "",
                        "destinationPort": port, "sourceIP": self.client_address[0],
                        "sourcePort": str(self.client_address[1]), "inboundIP": "127.0.0.1",
                        "inboundPort": str(self.server.server_address[1])},
                }
                self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                with server_tls.wrap_socket(self.request, server_side=True) as secure:
                    with secure.makefile("rb") as stream:
                        facts["request"] = stream.readline(8192)
                        while stream.readline(8192) not in (b"\r\n", b"\n", b""):
                            pass
                        response_body = second_body if facts["connections"] == 2 and second_body is not None else body
                        headers = f"HTTP/1.1 {status} Fixture\r\nContent-Length: {len(response_body)}\r\n"
                        if status == 302:
                            headers += "Location: https://localhost:443/redirected\r\n"
                        secure.sendall((headers + "\r\n").encode("ascii"))
                        if status == 200:
                            assert release.wait(3), "snapshot must precede body release"
                            secure.sendall(response_body)
                            # Client must close its stream, including failure paths.
                            secure.recv(1)
            except (OSError, ssl.SSLError):
                pass  # expected TLS rejection / closed client
            finally:
                closed.set()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

        def handle_error(self, request, client_address):
            facts["fixture_error"] = True

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def reader(deadline):
        assert time.monotonic() < deadline
        facts["snapshots"] += 1
        if facts["snapshots"] == 1:
            assert facts["row"] is None
            return {"connections": None}
        try:
            assert facts["request"] is not None
            row = deepcopy(facts["row"])
            payload = {"connections": [row]}
            return mutate(payload) if mutate else payload
        finally:
            release.set()

    def collect(**kwargs):
        options = dict(proxy_port=server.server_address[1], tls=client_tls,
                       snapshot_reader=reader, run_id=str(uuid4()), source="EXIT_A")
        options.update(kwargs)
        return collect_fixture_request(options.pop("url", "https://localhost:443/original"), **options)

    def reset():
        assert closed.is_set()
        facts.update(row=None, snapshots=0, request=None)
        release.clear()
        closed.clear()

    facts["reset"] = reset
    try:
        yield collect, facts, closed
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_real_tls_socket_port_matches_snapshot_while_body_is_held(certificates, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    with proxy_fixture(certificates) as (collect, facts, closed):
        capture = collect()
        assert capture.evidence.matched
        assert capture.request.source_port == int(facts["row"]["metadata"]["sourcePort"])
        assert capture.body == b'{"ip":"192.0.2.7"}'
        assert facts["snapshots"] == 2
        assert facts["request"].startswith(b"GET /original ")
        assert facts["connections"] == 1
        assert closed.wait(2)
        assert PROBE_GATE_OPEN is False
        assert repr(capture) == "FixtureCapture(<private>)"


@pytest.mark.parametrize("status", [302, 500])
def test_redirects_and_non_200_never_read_body_or_take_evidence(certificates, status):
    with proxy_fixture(certificates, status=status) as (collect, facts, closed):
        with pytest.raises(FixtureCaptureError, match="^FIXTURE_HTTP_STATUS$"):
            collect()
        assert facts["connections"] == 1
        assert facts["snapshots"] == 1
        assert closed.wait(2)


def test_untrusted_certificate_fails_without_snapshot(certificates):
    with proxy_fixture(certificates) as (collect, facts, closed):
        with pytest.raises(FixtureCaptureError, match="^FIXTURE_HTTP_FAILED$"):
            collect(tls=ssl.create_default_context())
        assert facts["snapshots"] == 1
        assert closed.wait(2)


@pytest.mark.parametrize("kind", ["missing", "direct", "wrong_port"])
def test_synthetic_controller_negatives_never_match(certificates, kind):
    def mutate(payload):
        if kind == "missing":
            return {"connections": None}
        row = payload["connections"][0]
        if kind == "direct":
            row["chains"] = ["DIRECT"]
        else:
            row["metadata"]["sourcePort"] = "1"
        return payload

    with proxy_fixture(certificates, mutate=mutate) as (collect, facts, closed):
        capture = collect()
        assert not capture.evidence.matched
        assert capture.evidence.connection_id is None
        assert closed.wait(2)


def test_body_limit_closes_connection(certificates):
    with proxy_fixture(certificates, body=b"x" * (64 * 1024 + 1)) as (collect, facts, closed):
        with pytest.raises(FixtureCaptureError, match="^FIXTURE_BODY_TOO_LARGE$"):
            collect()
        assert closed.wait(2)


@pytest.mark.parametrize("second_ip,status", [("192.0.2.7", "PASS"), ("192.0.2.8", "CONFLICT"),
                                              ("2001:db8::7", "PARTIAL")])
def test_two_original_requests_have_independent_socket_connections(certificates, second_ip, status):
    from nodelab.fixture_verdict import assess_fixture_pair
    run = str(uuid4())
    with proxy_fixture(certificates, second_body=f"ip={second_ip}\n".encode()) as (collect, facts, closed):
        first = collect(run_id=run)
        assert closed.wait(2)
        facts["reset"]()
        second = collect(run_id=run, source="EXIT_B", url="https://127.0.0.1:443/original",
                         previous_ids=frozenset({first.evidence.connection_id}))
        assert closed.wait(2)
        assert facts["connections"] == 2
        assert first.request.mixed_port == second.request.mixed_port
    assert all(x.matched for x in match_pair(first.request, first.snapshot, second.request, second.snapshot))
    # Local TLS/proxy/socket cleanup is real; runtime and route rows are
    # synthetic fixtures, so this remains a PRIVATE candidate verdict.
    verdict = assess_fixture_pair(first, second, runtime_verified=True, cleanup_ok=True)
    assert verdict.status == status
    assert verdict.candidate_ip == ("192.0.2.7" if status == "PASS" else None)
    assert first.evidence.connection_id in second.previous_ids


@pytest.mark.parametrize("url", ["http://localhost/", "https://example.com/",
    "https://secret@localhost/", "https://localhost/#secret"])
def test_non_fixture_targets_rejected_before_reader(certificates, url):
    def forbidden(deadline):
        pytest.fail("must not capture or connect")

    with pytest.raises(FixtureCaptureError, match="^FIXTURE_INPUT_INVALID$"):
        collect_fixture_request(url, proxy_port=12001, tls=certificates[1],
            snapshot_reader=forbidden, run_id=str(uuid4()), source="EXIT_A")


def test_insecure_tls_context_is_rejected(certificates):
    with pytest.raises(FixtureCaptureError, match="^FIXTURE_TLS_REQUIRED$"):
        collect_fixture_request("https://localhost:443/", proxy_port=12001,
            tls=ssl._create_unverified_context(), snapshot_reader=lambda _: None,
            run_id=str(uuid4()), source="EXIT_A")


def test_missing_socket_metadata_closes_without_fabricating_port(certificates, monkeypatch):
    from httpcore._backends.sync import SyncStream
    original = SyncStream.get_extra_info

    def info(stream, key):
        return None if key == "client_addr" else original(stream, key)

    monkeypatch.setattr(SyncStream, "get_extra_info", info)
    with proxy_fixture(certificates) as (collect, facts, closed):
        with pytest.raises(FixtureCaptureError, match="^FIXTURE_SOCKET_UNAVAILABLE$"):
            collect()
        assert facts["snapshots"] == 1
        # Release server body after the client already aborted its stream.


@pytest.mark.parametrize("fault", ["exception", "timeout", "cancel"])
def test_capture_failure_or_cancellation_closes_stream(certificates, fault):
    from nodelab.deadline import DeadlineExpired

    def mutate(payload):
        if fault == "timeout":
            raise DeadlineExpired()
        if fault == "cancel":
            raise KeyboardInterrupt()
        raise ValueError("synthetic private controller text")

    with proxy_fixture(certificates, mutate=mutate) as (collect, facts, closed):
        expected = KeyboardInterrupt if fault == "cancel" else FixtureCaptureError
        with pytest.raises(expected) as exc:
            collect()
        if fault != "cancel":
            assert str(exc.value) == ("FIXTURE_TIMEOUT" if fault == "timeout" else "FIXTURE_SNAPSHOT_FAILED")
        assert closed.wait(2)


def test_previous_id_replay_is_not_evidence(certificates):
    consumed = str(uuid4())

    def mutate(payload):
        payload["connections"][0]["id"] = consumed
        return payload

    with proxy_fixture(certificates, mutate=mutate) as (collect, facts, closed):
        capture = collect(previous_ids=frozenset({consumed}))
        assert capture.evidence.code == "EVIDENCE_REPLAYED"
        assert closed.wait(2)


def test_bad_baseline_aborts_before_connect(certificates):
    with proxy_fixture(certificates) as (collect, facts, closed):
        with pytest.raises(FixtureCaptureError, match="^FIXTURE_BASELINE_INVALID$"):
            collect(snapshot_reader=lambda deadline: {})
        assert facts["connections"] == 0


def test_backward_clock_jump_aborts_before_connect(certificates, monkeypatch):
    from nodelab import fixture_capture
    values = iter([time.time_ns(), 1])
    monkeypatch.setattr(fixture_capture.time, "time_ns", lambda: next(values))
    with proxy_fixture(certificates) as (collect, facts, closed):
        with pytest.raises(FixtureCaptureError, match="^FIXTURE_CLOCK_CHANGED$"):
            collect()
        assert facts["connections"] == 0


def test_post_response_runtime_guard_can_veto_success(certificates):
    from nodelab.connection_reader import ConnectionReaderError
    checks = []

    def guard(deadline):
        checks.append(deadline)
        if len(checks) == 2:
            raise ConnectionReaderError("READER_ENGINE_EXITED")

    with proxy_fixture(certificates) as (collect, facts, closed):
        with pytest.raises(ConnectionReaderError, match="^READER_ENGINE_EXITED$"):
            collect(_runtime_check=guard)
        assert facts["snapshots"] == 2
        assert checks[0] == checks[1]
        assert closed.wait(2)
