"""F2b: ParsedNode -> Mihomo v1.19.31 config, checked against the pinned source.

Why this file does not rely on `mihomo -t`
------------------------------------------
NL-REVIEW-002 treats "one `-t` pass" as evidence for P0-01. Measured against
the real v1.19.31 binary, `-t` is a *weak* oracle: it validates references and
required fields, but silently ACCEPTS every misnamed or unknown key. Observed
on the pinned binary (see docs/audits/NL-REVIEW-004-t-flag-oracle.md):

    trojan `servername` instead of `sni`      -> ACCEPTED
    trojan with an extra `tls` key            -> ACCEPTED
    client-fingerprint: iOS   (the B1 bug!)   -> ACCEPTED
    client-fingerprint: netscape              -> ACCEPTED
    an entirely invented proxy key            -> ACCEPTED
    sing-box style ws-opts.host               -> ACCEPTED
    sing-box style top-level outbounds        -> ACCEPTED
    a malformed uuid                          -> ACCEPTED

So the whole "silently dropped / misnamed field" class - exactly what P0-03
and B1 are about - passes `-t` cleanly. The strong oracle below is a key
allowlist transcribed from the pinned Go struct tags; `-t` is kept only as an
opt-in secondary smoke test.

Source of the allowlists (github.com/MetaCubeX/mihomo @ v1.19.31):
    adapter/outbound/base.go:  BasicOption
    adapter/outbound/vless.go:58-91    VlessOption
    adapter/outbound/trojan.go:45-69   TrojanOption
    adapter/outbound/vmess.go:156-172  GrpcOptions / WSOptions
    component/tls/utls.go:78-101       client-fingerprint keys
"""

from __future__ import annotations

import os
import secrets
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

from nodelab.engine_config import (
    CLIENT_FINGERPRINTS,
    EngineConfigError,
    NODE_NAME,
    build_node_proxy,
    build_probe_config,
)
from nodelab.parser import parse_uri
from nodelab.types import ParsedNode

# --- transcribed from the pinned source; do not "fix" from the wiki ---------

BASIC_OPTION_KEYS = frozenset({
    "tfo", "mptcp", "interface-name", "routing-mark", "ip-version",
    "dialer-proxy",
})

# `type` carries no `proxy:"..."` tag because it is consumed before decoding:
# adapter/parser.go:13 reads mapping["type"] to dispatch and errors with
# "missing type" when it is absent. It is therefore required, not unknown.
DISPATCH_KEYS = frozenset({"type"})

VLESS_KEYS = frozenset({
    "name", "server", "port", "uuid", "flow", "tls", "alpn", "udp",
    "packet-addr", "xudp", "packet-encoding", "encryption", "network",
    "ech-opts", "shadow-tls-opts", "restls-opts", "jls-opts", "reality-opts",
    "http-opts", "h2-opts", "grpc-opts", "ws-opts", "xhttp-opts", "ws-headers",
    "skip-cert-verify", "name-cert-verify", "fingerprint", "certificate",
    "private-key", "servername", "client-fingerprint",
}) | BASIC_OPTION_KEYS | DISPATCH_KEYS

TROJAN_KEYS = frozenset({
    "name", "server", "port", "password", "alpn", "sni", "skip-cert-verify",
    "name-cert-verify", "fingerprint", "certificate", "private-key", "udp",
    "network", "ech-opts", "shadow-tls-opts", "restls-opts", "jls-opts",
    "reality-opts", "grpc-opts", "ws-opts", "ss-opts", "client-fingerprint",
}) | BASIC_OPTION_KEYS | DISPATCH_KEYS

WS_OPTS_KEYS = frozenset({
    "path", "headers", "max-early-data", "early-data-header-name",
    "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open",
})

GRPC_OPTS_KEYS = frozenset({
    "grpc-service-name", "grpc-user-agent", "ping-interval",
    "max-connections", "min-streams", "max-streams",
})

SOURCE_FINGERPRINTS = frozenset({
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "chrome120", "firefox120", "safari16", "chrome_psk",
    "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq",
    "chrome_pq_psk", "randomized",
})

FAKE_UUID = "11111111-2222-3333-4444-555555555555"
FAKE_HOST = "198.51.100.7"


def fake_password() -> str:
    return "FAKE_ONLY_" + secrets.token_urlsafe(20)


def fake_secret_token() -> str:
    return secrets.token_urlsafe(36)[:48]


def vless_uri(**q: str) -> str:
    base = {"encryption": "none", "security": "tls", "sni": "a.example", "type": "tcp"}
    base.update(q)
    query = "&".join(f"{k}={v}" for k, v in base.items())
    return f"vless://{FAKE_UUID}@{FAKE_HOST}:443?{query}#label"


def trojan_uri(password: str, **q: str) -> str:
    base = {"sni": "a.example", "type": "tcp"}
    base.update(q)
    query = "&".join(f"{k}={v}" for k, v in base.items())
    return f"trojan://{password}@{FAKE_HOST}:443?{query}#label"


def config_for(node: ParsedNode) -> dict:
    return build_probe_config(node, mixed_port=17890, controller_port=17891,
                              secret=fake_secret_token())


# --- strong oracle: every emitted key must exist in the pinned structs ------

@pytest.mark.parametrize("uri_factory,allowed", [
    (lambda: vless_uri(), VLESS_KEYS),
    (lambda: vless_uri(type="ws", host="a.example", path="%2Fws"), VLESS_KEYS),
    (lambda: vless_uri(type="ws", host="b.example", path="%2Fws"), VLESS_KEYS),
    (lambda: vless_uri(type="grpc", serviceName="gs"), VLESS_KEYS),
    (lambda: vless_uri(fp="ios"), VLESS_KEYS),
    (lambda: vless_uri(alpn="h2%2Chttp%2F1.1"), VLESS_KEYS),
    (lambda: vless_uri(flow="xtls-rprx-vision"), VLESS_KEYS),
    (lambda: trojan_uri(fake_password()), TROJAN_KEYS),
    (lambda: trojan_uri(fake_password(), type="ws", host="a.example", path="%2Fws"), TROJAN_KEYS),
    (lambda: trojan_uri(fake_password(), type="ws", host="b.example", path="%2Fws"), TROJAN_KEYS),
    (lambda: trojan_uri(fake_password(), type="grpc", serviceName="gs"), TROJAN_KEYS),
    (lambda: trojan_uri(fake_password(), fp="chrome"), TROJAN_KEYS),
])
def test_every_emitted_key_exists_in_the_pinned_structs(uri_factory, allowed):
    proxy = build_node_proxy(parse_uri(uri_factory()))
    unknown = set(proxy) - allowed
    assert not unknown, f"keys absent from the v1.19.31 struct: {sorted(unknown)}"
    if "ws-opts" in proxy:
        assert not set(proxy["ws-opts"]) - WS_OPTS_KEYS
    if "grpc-opts" in proxy:
        assert not set(proxy["grpc-opts"]) - GRPC_OPTS_KEYS


def test_trojan_never_emits_tls_or_servername():
    """TrojanOption has neither key; emitting them is silently ignored."""
    proxy = build_node_proxy(parse_uri(trojan_uri(fake_password())))
    assert "tls" not in proxy
    assert "servername" not in proxy
    assert proxy["sni"] == "a.example"


def test_vless_uses_servername_and_an_explicit_tls_bool():
    """VLESS is not implicitly TLS and does not know the `sni` key."""
    proxy = build_node_proxy(parse_uri(vless_uri()))
    assert proxy["tls"] is True
    assert proxy["servername"] == "a.example"
    assert "sni" not in proxy


def test_client_fingerprint_is_a_subset_of_the_source_map():
    assert CLIENT_FINGERPRINTS == SOURCE_FINGERPRINTS
    proxy = build_node_proxy(parse_uri(vless_uri(fp="ios")))
    assert proxy["client-fingerprint"] == "ios"
    assert proxy["client-fingerprint"] in SOURCE_FINGERPRINTS


def test_unknown_fingerprint_is_refused_rather_than_silently_downgraded():
    """`-t` accepts `iOS`; Mihomo then falls back to plain Go TLS (B1)."""
    good = parse_uri(vless_uri(fp="ios"))
    for bad_value in ("iOS", "Chrome", "netscape", "", "ios "):
        node = ParsedNode(**{**{f.name: getattr(good, f.name)
                               for f in good.__dataclass_fields__.values()},
                             "client_fingerprint": bad_value})
        with pytest.raises(EngineConfigError) as info:
            build_node_proxy(node)
        assert info.value.code == "UNSUPPORTED_FINGERPRINT"


@pytest.mark.parametrize("scheme", ["vless", "trojan"])
def test_ws_host_differing_from_sni_becomes_an_explicit_header(scheme):
    """trojan.go:96-98 overwrites wsOpts.Host with the SNI; only an explicit
    header survives (transport/vmess/websocket.go:404)."""
    uri = (vless_uri(type="ws", host="b.example", path="%2Fws") if scheme == "vless"
           else trojan_uri(fake_password(), type="ws", host="b.example", path="%2Fws"))
    proxy = build_node_proxy(parse_uri(uri))
    assert proxy["ws-opts"]["headers"]["Host"] == "b.example"
    assert proxy["ws-opts"]["path"] == "/ws"


@pytest.mark.parametrize("scheme", ["vless", "trojan"])
def test_ws_host_equal_to_sni_needs_no_header(scheme):
    uri = (vless_uri(type="ws", host="a.example", path="%2Fws") if scheme == "vless"
           else trojan_uri(fake_password(), type="ws", host="a.example", path="%2Fws"))
    proxy = build_node_proxy(parse_uri(uri))
    assert "headers" not in proxy["ws-opts"]


def test_grpc_service_name_uses_the_pinned_key():
    proxy = build_node_proxy(parse_uri(vless_uri(type="grpc", serviceName="gs")))
    assert proxy["grpc-opts"] == {"grpc-service-name": "gs"}


def test_alpn_is_preserved_as_a_list():
    proxy = build_node_proxy(parse_uri(vless_uri(alpn="h2%2Chttp%2F1.1")))
    assert proxy["alpn"] == ["h2", "http/1.1"]


def test_skip_cert_verify_is_never_emitted():
    for uri in (vless_uri(), trojan_uri(fake_password())):
        assert "skip-cert-verify" not in build_node_proxy(parse_uri(uri))


def test_reality_stays_closed():
    node = parse_uri(vless_uri())
    fields = {f.name: getattr(node, f.name) for f in node.__dataclass_fields__.values()}
    with pytest.raises(EngineConfigError) as info:
        build_node_proxy(ParsedNode(**{**fields, "tls_mode": "reality"}))
    assert info.value.code == "UNSUPPORTED_REALITY"


def test_allow_insecure_never_becomes_skip_cert_verify():
    node = parse_uri(vless_uri())
    fields = {f.name: getattr(node, f.name) for f in node.__dataclass_fields__.values()}
    with pytest.raises(EngineConfigError) as info:
        build_node_proxy(ParsedNode(**{**fields, "allow_insecure_requested": True}))
    assert info.value.code == "UNSUPPORTED_INSECURE_NOT_APPROVED"


def test_object_name_is_fixed_and_never_derived_from_the_label():
    """A URI fragment can carry anything; it must not become an engine name."""
    sentinel = "FAKE_ONLY_" + secrets.token_hex(8)
    node = parse_uri(vless_uri() .replace("#label", "#" + sentinel))
    cfg = config_for(node)
    assert cfg["proxies"][0]["name"] == NODE_NAME
    assert cfg["proxy-groups"][0]["proxies"] == [NODE_NAME]
    assert sentinel not in yaml.safe_dump(cfg)


# --- top level / control plane ---------------------------------------------

def test_top_level_shape_matches_config_go():
    cfg = config_for(parse_uri(vless_uri()))
    assert cfg["mixed-port"] == 17890
    assert cfg["external-controller"] == "127.0.0.1:17891"
    assert cfg["allow-lan"] is False
    assert cfg["bind-address"] == "127.0.0.1"
    assert cfg["rules"] == ["MATCH,PROBE"]
    assert all(type(rule) is str for rule in cfg["rules"])
    assert cfg["profile"] == {"store-selected": False, "store-fake-ip": False}
    # sing-box vocabulary must never appear.
    assert not {"outbounds", "inbounds", "route", "experimental"} & set(cfg)


def test_controller_secret_is_per_run_and_validated():
    node = parse_uri(vless_uri())
    a = config_for(node)["secret"]
    b = config_for(node)["secret"]
    assert a != b and len(a) >= 32
    for bad in ("", "short", "has space!", None, 12345):
        with pytest.raises(EngineConfigError) as info:
            build_probe_config(node, mixed_port=17890, controller_port=17891, secret=bad)
        assert info.value.code == "INVALID_SECRET"


def test_ports_are_validated_and_must_differ():
    node = parse_uri(vless_uri())
    for bad in (0, -1, 65536, 3.5, True, "8080"):
        with pytest.raises(EngineConfigError) as info:
            build_probe_config(node, mixed_port=bad, controller_port=17891,
                               secret=fake_secret_token())
        assert info.value.code == "INVALID_PORT"
    with pytest.raises(EngineConfigError) as info:
        build_probe_config(node, mixed_port=17890, controller_port=17890,
                           secret=fake_secret_token())
    assert info.value.code == "INVALID_PORT"


def test_errors_never_carry_the_node_secret():
    password = fake_password()
    node = parse_uri(trojan_uri(password))
    fields = {f.name: getattr(node, f.name) for f in node.__dataclass_fields__.values()}
    with pytest.raises(EngineConfigError) as info:
        build_node_proxy(ParsedNode(**{**fields, "tls_mode": "reality"}))
    blob = f"{info.value!r} {info.value} {info.value.args}"
    assert password not in blob
    assert info.value.code == "UNSUPPORTED_REALITY"


def test_secret_lives_only_inside_the_private_mapping():
    password = fake_password()
    cfg = config_for(parse_uri(trojan_uri(password)))
    assert cfg["proxies"][0]["password"] == password
    public = parse_uri(trojan_uri(password)).public_dict()
    assert password not in repr(public)
    assert set(public) == {"schema_version", "protocol", "transport", "tls_mode"}


# --- optional secondary smoke test against the real pinned binary -----------

MIHOMO_EXE = os.environ.get("NODELAB_MIHOMO_EXE")


@pytest.mark.skipif(not MIHOMO_EXE, reason="set NODELAB_MIHOMO_EXE to a pinned v1.19.31 binary")
@pytest.mark.parametrize("uri_factory", [
    lambda: vless_uri(),
    lambda: vless_uri(type="ws", host="b.example", path="%2Fws"),
    lambda: vless_uri(type="grpc", serviceName="gs"),
    lambda: vless_uri(fp="ios", alpn="h2%2Chttp%2F1.1"),
    lambda: trojan_uri(fake_password()),
    lambda: trojan_uri(fake_password(), type="ws", host="b.example", path="%2Fws"),
    lambda: trojan_uri(fake_password(), type="grpc", serviceName="gs"),
])
def test_pinned_binary_loads_the_generated_config(uri_factory):
    """Necessary, not sufficient: `-t` only proves the config is loadable."""
    cfg = config_for(parse_uri(uri_factory()))
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.yaml"
        path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False),
                        encoding="utf-8")
        proc = subprocess.run([MIHOMO_EXE, "-t", "-d", tmp, "-f", str(path)],
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0
        # The engine must not leave unexpected files in the private run dir.
        assert sorted(p.name for p in Path(tmp).iterdir()) == ["probe.yaml"]
