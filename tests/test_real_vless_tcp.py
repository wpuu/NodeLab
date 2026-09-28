"""Opt-in pinned Mihomo -> actual VLESS v0/TLS/TCP -> local HTTPS sources.

No flow, Vision, encryption extension, WS, gRPC or Reality claims. No synthetic
controller or route chains. Requires Python >=3.12 and the genuine pinned binary.
"""
import os
import sys

import pytest

from tests.fixtures.real_protocol_case import exercise_real_protocol
from tests.test_trojan_tcp_fixture import tls_material

EXE = os.environ.get("NODELAB_MIHOMO_EXE")
pytestmark = [
    pytest.mark.skipif(not EXE, reason="pinned v1.19.31 binary required for actual VLESS handshake"),
    pytest.mark.skipif(sys.platform != "linux", reason="Linux protocol fixture; Windows remains W2"),
]


@pytest.mark.parametrize("case", ["valid", "wrong_uuid", "wrong_sni", "untrusted_ca"])
def test_real_vless_tcp_end_to_end(tmp_path, monkeypatch, tls_material, case):
    exercise_real_protocol(tmp_path, monkeypatch, tls_material, case, protocol="vless", exe_path=EXE)
