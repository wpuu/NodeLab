"""Unit tests: mihomo YAML generation + display scrub (no secrets in showable output)."""

import json

import yaml

from nodelab.mihomo_config import build_mihomo_yaml, scrub_yaml_for_display, write_probe_config
from nodelab.parser import parse_uri

UUID_X = "2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e"
PW_X = "tr0jan-secret-pw"


def test_yaml_contains_secret_in_temp_config():
    node = parse_uri(f"vless://{UUID_X}@203.0.113.50:443?security=tls&type=ws&path=%2Fws&host=203.0.113.50")
    config, _sec, _m, _c, group = write_probe_config(node)
    text = config.read_text(encoding="utf-8")
    cfg = yaml.safe_load(text)
    assert group == "PROBE"
    # secret exists in the temp YAML (required to run)
    assert UUID_X in text
    # but listeners are loopback-only
    assert cfg["external-controller"].startswith("127.0.0.1:")
    assert cfg["inbounds"][0]["listen"] == "127.0.0.1"
    assert "0.0.0.0" not in json.dumps(cfg)


def test_display_json_has_no_secret():
    node = parse_uri(f"vless://{UUID_X}@203.0.113.50:443?security=tls")
    config, _sec, _m, _c, _g = write_probe_config(node)
    text = config.read_text(encoding="utf-8")
    scrubbed = scrub_yaml_for_display(text)
    assert UUID_X not in scrubbed
    assert "***" in scrubbed

    # trojan variant
    node2 = parse_uri(f"trojan://{PW_X}@203.0.113.51:443?security=tls")
    config2, _s2, _m2, _c2, _g2 = write_probe_config(node2)
    text2 = config2.read_text(encoding="utf-8")
    scrubbed2 = scrub_yaml_for_display(text2)
    assert PW_X not in scrubbed2


def test_yaml_ports_are_loopback_free():
    node = parse_uri(f"vless://{UUID_X}@203.0.113.52:443?security=tls")
    cfg, sec, mixed, ctrl = build_mihomo_yaml(node)
    assert cfg["external-controller"] == f"127.0.0.1:{ctrl}"
    assert cfg["external-controller-secret"] == sec
    assert cfg["inbounds"][0]["port"] == mixed
    assert cfg["inbounds"][0]["listen"] == "127.0.0.1"
