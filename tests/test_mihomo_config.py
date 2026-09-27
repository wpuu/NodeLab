"""F1: old unsafe engine config is gated; YAML exists only in a private run."""

import os
import secrets
from pathlib import Path

import pytest

from nodelab.mihomo_config import (
    PrivateRunError, RunContext, build_mihomo_yaml, scrub_yaml_for_display,
    write_probe_config,
)
from nodelab.parser import parse_uri


def _node():
    password = "FAKE_ONLY_" + secrets.token_urlsafe(25)
    return parse_uri(f"trojan://{password}@203.0.113.50:443?security=tls&sni=fixture.example.invalid"), password


def _context(tmp_path: Path) -> RunContext:
    return RunContext() if os.name == "nt" else RunContext(tmp_path / "private")


def test_legacy_wrong_mihomo_config_is_not_executable():
    node, _password = _node()
    for old_api in (build_mihomo_yaml, write_probe_config):
        with pytest.raises(PrivateRunError) as info:
            old_api(node)
        assert info.value.code == "PROBE_GATE_CLOSED"


def test_private_yaml_only_during_owned_run(tmp_path: Path):
    node, password = _node()
    ctx = _context(tmp_path)
    with ctx:
        yaml_path = ctx.write_yaml({"proxies": [{"password": node.secret}]})
        assert yaml_path.is_file()
        assert password in yaml_path.read_text(encoding="utf-8")
        assert password not in scrub_yaml_for_display(yaml_path.read_text(encoding="utf-8"))
    assert ctx.closed and not yaml_path.exists() and not ctx.run_dir.exists()
