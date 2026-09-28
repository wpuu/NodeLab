"""Full composed local experiment with a synthetic engine executable.

Only binary verification/engine executable are replaced. Config/YAML lifecycle,
child identities, PID-owned ports, authenticated HTTP, CONNECT/TLS, source-port
capture, body parsing, matching and cleanup run through actual implementation.
The substitute supplies invented chains: this is NOT real Mihomo acceptance.
"""
from contextlib import ExitStack
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys

import pytest

from nodelab import engine_binary
from nodelab.offline_fixture import run_offline_fixture
from nodelab.parser import parse_uri
from nodelab.types import PROBE_GATE_OPEN

_REAL_POPEN = subprocess.Popen
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux substitute, Windows still W2")


@pytest.mark.parametrize("direct", [False, True])
def test_composed_session_real_local_io_and_cleanup(tmp_path, monkeypatch, direct):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("OpenSSL needed for synthetic local TLS")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout", str(key), "-out", str(cert)], check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    key.chmod(0o600)
    tls = ssl.create_default_context(cafile=str(cert))
    monkeypatch.setenv("NODELAB_FIXTURE_CERT", str(cert))
    monkeypatch.setenv("NODELAB_FIXTURE_KEY", str(key))
    monkeypatch.setenv("NODELAB_FIXTURE_DIRECT", "1" if direct else "0")
    monkeypatch.setattr(engine_binary, "verify_pinned_binary", lambda *a, **kw: (True, "BINARY_OK"))
    children = []
    script = Path(__file__).parent / "fixtures" / "f3_engine_substitute.py"

    class Substitute(_REAL_POPEN):
        def __init__(self, args, **kwargs):
            super().__init__([sys.executable, str(script), *args[1:]], **kwargs)
            children.append(self)

    monkeypatch.setattr(subprocess, "Popen", Substitute)
    with ExitStack() as held:
        ports = []
        for _ in range(2):
            sock = held.enter_context(socket.socket())
            sock.bind(("127.0.0.1", 0))
            ports.append(sock.getsockname()[1])
    root = tmp_path / "private"
    node = parse_uri(f"trojan://{secrets.token_urlsafe(32)}@127.0.0.1:443?security=tls&sni=fixture.example.invalid")
    try:
        verdict = run_offline_fixture(node, exe=Path(sys.executable), mixed_port=ports[0],
            controller_port=ports[1], source_a_url="https://localhost/a",
            source_b_url="https://127.0.0.1/b", tls=tls, root=root)
        assert verdict.status == ("FAIL" if direct else "PASS"), verdict.code
        assert verdict.candidate_ip == (None if direct else "192.0.2.7")
        if direct:
            assert verdict.code == "EVIDENCE_ROUTE_MISMATCH"
        assert len(children) == 2  # one -t then one runtime, never one per source
        assert all(child.poll() is not None for child in children)
        assert list(root.iterdir()) == []
        assert PROBE_GATE_OPEN is False
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        key.unlink()
        cert.unlink()
