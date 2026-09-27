"""F2b: ParsedNode -> Mihomo v1.19.31 probe configuration.

Every emitted key is anchored to the pinned engine source, not to the wiki.
NL-REVIEW-003 B1 exists precisely because the wiki disagreed with the code
(`iOS` vs `ios`), and an unknown uTLS fingerprint is only `log.Warnln`-ed
before Mihomo silently falls back to plain Go TLS.

Source anchors (github.com/MetaCubeX/mihomo @ v1.19.31):

  adapter/outbound/vless.go:58-91    VlessOption field tags
  adapter/outbound/trojan.go:45-69   TrojanOption field tags
  adapter/outbound/trojan.go:96-98   ws: `if SNI != "" { wsOpts.Host = SNI }`
  adapter/outbound/trojan.go:106,153 DefaultWebsocketALPN / DefaultALPN
  adapter/outbound/trojan.go:286-287 `if SNI == "" { SNI = Server }`
  adapter/outbound/vmess.go:156-161  GrpcOptions field tags
  adapter/outbound/vmess.go:165-172  WSOptions field tags (NO `host` key)
  transport/vmess/websocket.go:404   an explicit `Host` header wins over
                                     WebsocketConfig.Host
  component/tls/utls.go:78-101       the complete client-fingerprint key set
  config/config.go:407,422,432,454   top-level mixed-port / external-controller
                                     / secret / rules

This module is pure: it builds and returns a private mapping. It performs no
I/O, starts no process and never returns a public-facing object. The result
contains the node secret and must only reach `RunContext.write_yaml`.
"""

from __future__ import annotations

import re
from typing import Any, Final

from nodelab.types import ParsedNode

# component/tls/utls.go:78-101. Lookup is case sensitive and a miss degrades
# silently to plain Go TLS, so the generator must never emit anything else.
CLIENT_FINGERPRINTS: Final[frozenset[str]] = frozenset({
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "chrome120", "firefox120", "safari16",
    "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle",
    "chrome_pq", "chrome_pq_psk", "randomized",
})

# Fixed, non-derived identifiers. A user-supplied label (URI fragment) must
# never become a Mihomo object name: it would travel into controller output,
# logs and any future public row.
NODE_NAME: Final[str] = "NODE"
GROUP_NAME: Final[str] = "PROBE"

SUPPORTED_PROTOCOLS: Final[frozenset[str]] = frozenset({"vless", "trojan"})
SUPPORTED_TRANSPORTS: Final[frozenset[str]] = frozenset({"tcp", "ws", "grpc"})

_ENGINE_CODES: Final[frozenset[str]] = frozenset({
    "CONFIG_BUILD_FAILED", "INVALID_PORT", "INVALID_SECRET",
    "UNSUPPORTED_PROTOCOL", "UNSUPPORTED_TRANSPORT", "UNSUPPORTED_SECURITY",
    "UNSUPPORTED_FINGERPRINT", "UNSUPPORTED_REALITY",
    "UNSUPPORTED_INSECURE_NOT_APPROVED",
})

_SECRET_RE = re.compile(r"\A[A-Za-z0-9_-]{32,128}\Z")


class EngineConfigError(ValueError):
    """Fixed code only. The node secret must never reach the message."""

    def __init__(self, code: str = "CONFIG_BUILD_FAILED") -> None:
        self.code = code if type(code) is str and code in _ENGINE_CODES else "CONFIG_BUILD_FAILED"
        super().__init__(self.code)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"EngineConfigError({self.code})"


def _port(value: object) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise EngineConfigError("INVALID_PORT")
    if not 1 <= value <= 65535:
        raise EngineConfigError("INVALID_PORT")
    return value


def _fingerprint(node: ParsedNode) -> str | None:
    fp = node.client_fingerprint
    if fp is None:
        return None
    if type(fp) is not str or fp not in CLIENT_FINGERPRINTS:
        # Emitting an unknown value would be a silent TLS downgrade (B1).
        raise EngineConfigError("UNSUPPORTED_FINGERPRINT")
    return fp


def _guard(node: ParsedNode) -> None:
    if not isinstance(node, ParsedNode):
        raise EngineConfigError()
    if node.protocol not in SUPPORTED_PROTOCOLS:
        raise EngineConfigError("UNSUPPORTED_PROTOCOL")
    if node.transport not in SUPPORTED_TRANSPORTS:
        raise EngineConfigError("UNSUPPORTED_TRANSPORT")
    if node.tls_mode == "reality" or node.reality_public_key or node.reality_short_id:
        # No local handshake proof exists for Reality; contract keeps it closed.
        raise EngineConfigError("UNSUPPORTED_REALITY")
    if node.tls_mode != "tls":
        raise EngineConfigError("UNSUPPORTED_SECURITY")
    if node.allow_insecure_requested:
        # `allowInsecure=true` in a URI must never become skip-cert-verify.
        raise EngineConfigError("UNSUPPORTED_INSECURE_NOT_APPROVED")
    if type(node.secret) is not str or not node.secret:
        raise EngineConfigError("INVALID_SECRET")
    if type(node.entry_host) is not str or not node.entry_host:
        raise EngineConfigError("CONFIG_BUILD_FAILED")
    if type(node.sni) is not str or not node.sni:
        # Trojan would fall back to SNI = server (trojan.go:286); the contract
        # requires the parser to have resolved an explicit SNI already.
        raise EngineConfigError("CONFIG_BUILD_FAILED")


def _transport_opts(node: ParsedNode, *, explicit_ws_host: str | None) -> dict[str, Any]:
    """ws-opts / grpc-opts exactly as the pinned structs name them."""
    opts: dict[str, Any] = {}
    if node.transport == "ws":
        ws: dict[str, Any] = {}
        # WSOptions has `path`, `headers`, ... and deliberately NO `host` key
        # (vmess.go:165-172). A Host that differs from the SNI can only be
        # expressed as an explicit header (websocket.go:404 makes it win).
        ws["path"] = node.ws_path if node.ws_path else "/"
        if explicit_ws_host:
            ws["headers"] = {"Host": explicit_ws_host}
        opts["ws-opts"] = ws
    elif node.transport == "grpc":
        # GrpcOptions.GrpcServiceName -> `grpc-service-name` (vmess.go:156-161)
        opts["grpc-opts"] = {"grpc-service-name": node.grpc_service_name or ""}
    return opts


def _vless_proxy(node: ParsedNode) -> dict[str, Any]:
    proxy: dict[str, Any] = {
        "name": NODE_NAME,
        "type": "vless",
        "server": node.entry_host,
        "port": node.entry_port,
        "uuid": node.secret,
        # VlessOption.TLS is a real bool field (vless.go:65); unlike Trojan,
        # VLESS is NOT implicitly TLS.
        "tls": True,
        # VlessOption.ServerName -> `servername` (vless.go:89).
        "servername": node.sni,
        "network": node.transport,
        "udp": False,
        # VlessOption.Encryption (vless.go:71). The parser only accepts
        # `encryption=none`; make it explicit rather than relying on a default.
        "encryption": "none",
    }
    if node.flow:
        proxy["flow"] = node.flow
    if node.alpn:
        proxy["alpn"] = list(node.alpn)
    fp = _fingerprint(node)
    if fp:
        # `client-fingerprint` is the uTLS ClientHello selector.
        # `fingerprint` (vless.go:86) is certificate SHA-256 pinning - a very
        # different field that must not be confused with it.
        proxy["client-fingerprint"] = fp
    # For VLESS over ws the TLS ServerName comes from `servername` first, so an
    # explicit Host header is only needed when it genuinely differs.
    ws_host = node.ws_host if (node.ws_host and node.ws_host != node.sni) else None
    proxy.update(_transport_opts(node, explicit_ws_host=ws_host))
    return proxy


def _trojan_proxy(node: ParsedNode) -> dict[str, Any]:
    proxy: dict[str, Any] = {
        "name": NODE_NAME,
        "type": "trojan",
        "server": node.entry_host,
        "port": node.entry_port,
        "password": node.secret,
        # TrojanOption has NO `tls` and NO `servername` key (trojan.go:45-69):
        # Trojan is always TLS and the name is carried by `sni`. Emitting
        # `servername` here would be silently ignored by the engine.
        "sni": node.sni,
        "network": node.transport,
        "udp": False,
    }
    if node.alpn:
        # Left absent the engine applies DefaultWebsocketALPN for ws and
        # DefaultALPN for tcp (trojan.go:106 / 153).
        proxy["alpn"] = list(node.alpn)
    fp = _fingerprint(node)
    if fp:
        proxy["client-fingerprint"] = fp
    # trojan.go:96-98 forces wsOpts.Host = SNI whenever SNI is set, so a Host
    # that differs from the SNI is lost unless written as an explicit header.
    ws_host = node.ws_host if (node.ws_host and node.ws_host != node.sni) else None
    proxy.update(_transport_opts(node, explicit_ws_host=ws_host))
    return proxy


def build_node_proxy(node: ParsedNode) -> dict[str, Any]:
    """One `proxies:` entry. Private: it carries the UUID / password."""
    _guard(node)
    if node.protocol == "vless":
        return _vless_proxy(node)
    return _trojan_proxy(node)


def build_probe_config(
    node: ParsedNode,
    *,
    mixed_port: int,
    controller_port: int,
    secret: str,
) -> dict[str, Any]:
    """Full private probe configuration for one candidate node.

    `secret` is the per-run controller token. It is generated fresh by the
    caller for every run (P0-04) and is never derived from the node.
    """
    _guard(node)
    mixed = _port(mixed_port)
    controller = _port(controller_port)
    if mixed == controller:
        raise EngineConfigError("INVALID_PORT")
    if type(secret) is not str or not _SECRET_RE.match(secret):
        raise EngineConfigError("INVALID_SECRET")

    return {
        # config/config.go:407 - top level, not under a `listeners:` block.
        "mixed-port": mixed,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        # Keep engine warnings visible: an unknown client-fingerprint is only
        # reported as a warning, and F2b's start-up check asserts on it.
        "log-level": "warning",
        "ipv6": False,
        # config/config.go:422 / 432 - authenticated, loopback-only control
        # plane with a fresh token per run.
        "external-controller": f"127.0.0.1:{controller}",
        "secret": secret,
        # Prevent the engine from persisting selections or a fake-ip store into
        # the private run directory, which must stay a known, allow-listed set
        # of files for the recovery classifier.
        "profile": {"store-selected": False, "store-fake-ip": False},
        "unified-delay": False,
        "proxies": [build_node_proxy(node)],
        "proxy-groups": [{
            "name": GROUP_NAME,
            "type": "select",
            "proxies": [NODE_NAME],
        }],
        # config/config.go:454 - `rules` is a list of plain strings.
        "rules": [f"MATCH,{GROUP_NAME}"],
    }
