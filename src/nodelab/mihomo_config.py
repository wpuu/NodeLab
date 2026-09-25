"""Generate minimal Mihomo YAML configs for probing a single node."""

from __future__ import annotations

import re
import socket
import tempfile
import uuid
from pathlib import Path

import yaml

from nodelab.types import ParsedNode

PROBE_GROUP = "PROBE"
DELAY_URL = "https://www.gstatic.com/generate_204"


def find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _proxy_server(node: ParsedNode, name: str) -> dict:
    if node.protocol == "vless":
        server = {
            "name": name,
            "type": "vless",
            "server": node.entry_host,
            "port": node.entry_port,
            "uuid": node.secret,
            "flow": node.flow,
            "tls": node.tls,
            "client-fingerprint": node.client_fingerprint,
            "servername": node.sni,
            "skip-cert-verify": node.allow_insecure,
        }
        if node.transport == "ws":
            headers = {}
            if node.host_header:
                headers["Host"] = node.host_header
            server["ws"] = {"path": node.path or "/", "headers": headers}
        elif node.transport == "grpc":
            server["grpc"] = {"grpc-kwargs": {}}
        elif node.transport == "httpupgrade":
            server["httpupgrade"] = {"path": node.path or "/"}
        return server

    # trojan
    server = {
        "name": name,
        "type": "trojan",
        "server": node.entry_host,
        "port": node.entry_port,
        "password": node.secret,
        "tls": node.tls,
        "servername": node.sni or node.host_header or node.entry_host,
        "skip-cert-verify": node.allow_insecure,
    }
    if node.transport == "ws":
        headers = {}
        if node.host_header:
            headers["Host"] = node.host_header
        server["ws"] = {"path": node.path or "/", "headers": headers}
    elif node.transport == "grpc":
        server["grpc"] = {}
    return server


def build_mihomo_yaml(node: ParsedNode) -> tuple[dict, str, int, int]:
    """Build a minimal one-proxy Mihomo config.

    Returns (config_dict, controller_secret, mixed_port, controller_port).
    All listeners bind 127.0.0.1 only.
    """
    name = PROBE_GROUP
    proxy = _proxy_server(node, name)
    mixed_port = find_free_port()
    controller_port = find_free_port()
    controller_secret = uuid.uuid4().hex

    config = {
        "log": {"level": "warning", "disable-access-log": True},
        "dns": {
            "enable": True,
            "listen": "127.0.0.1:1053",
            "nameserver": ["https://doh.pub/dns-query"],
            "nameserver-fallback": ["1.1.1.1"],
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "port": mixed_port,
            }
        ],
        "outbounds": [
            {"type": "select", "tag": PROBE_GROUP, "proxies": [name]},
            {"type": "direct", "tag": "DIRECT"},
            {"type": "block", "tag": "BLOCK"},
            proxy,
        ],
        "rules": [
            {"type": "ip-is-private", "no-resolve": True, "outbound": "DIRECT"},
            {"type": "final", "outbound": PROBE_GROUP},
        ],
    }
    config["external-controller"] = f"127.0.0.1:{controller_port}"
    config["external-controller-secret"] = controller_secret
    return config, controller_secret, mixed_port, controller_port


def write_probe_config(node: ParsedNode) -> tuple[Path, str, int, int, str]:
    """Write a fresh temp YAML; returns (config_path, secret, mixed, controller, group)."""
    tmpdir = Path(tempfile.mkdtemp(prefix="nodelab-probe-"))
    config, controller_secret, mixed_port, controller_port = build_mihomo_yaml(node)
    config_path = tmpdir / "probe.yaml"
    config_path.write_text(
        yaml.safe_dump(config, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return config_path, controller_secret, mixed_port, controller_port, PROBE_GROUP


def scrub_yaml_for_display(yaml_text: str) -> str:
    """Remove uuid / password / external-controller-secret so a YAML dump is safe to show."""
    text = re.sub(r"(?m)^\s*(uuid|password):\s*.+$", r"\1: ***", yaml_text)
    text = re.sub(r"(?m)^\s*(external-controller-secret):\s*.+$", r"\1: ***", text)
    return text
