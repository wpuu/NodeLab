"""Strict private node model and fixed-code parser failures.

A ParsedNode is not a public JSON/document object. SNI, WS Host/path,
fragment, Reality parameters and even a harmless-looking label can carry
credentials. Never log/serialize the dataclass itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_PARSE_CODES = frozenset({
    "INVALID_URI", "INVALID_UTF8", "INVALID_PERCENT_ENCODING", "INVALID_HOST",
    "INVALID_HOST_HEADER", "INVALID_PORT", "INVALID_SECRET", "INVALID_PATH",
    "INVALID_SERVICE_NAME", "INVALID_FLAG", "INVALID_ALPN", "INVALID_QUERY", "LINE_TOO_LONG",
    "DUPLICATE_PARAM", "UNSUPPORTED_PROTOCOL", "UNSUPPORTED_QUERY_PARAM",
    "UNSUPPORTED_SECURITY", "UNSUPPORTED_TRANSPORT", "UNSUPPORTED_SNI_REQUIRED",
    "UNSUPPORTED_FLOW_COMBINATION", "UNSUPPORTED_FLOW", "UNSUPPORTED_ALPN",
    "UNSUPPORTED_FINGERPRINT", "UNSUPPORTED_INSECURE_NOT_APPROVED",
    "UNSUPPORTED_ENCRYPTION", "UNSUPPORTED_REALITY", "UNSUPPORTED_HTTPUPGRADE",
})


class NodeURIParseError(ValueError):
    """Fixed code only: URI, path, parser/library error text never attached."""

    def __init__(self, code: str = "INVALID_URI") -> None:
        self.code = code if type(code) is str and code in _PARSE_CODES else "INVALID_URI"
        super().__init__(self.code)

    @property
    def probe_status(self) -> str:
        return "UNSUPPORTED" if self.code.startswith("UNSUPPORTED_") else "FAIL"


@dataclass(frozen=True, slots=True, repr=False)
class ParsedNode:
    """One strictly typed, private VLESS/Trojan configuration candidate.

    This does not mean the dialect has passed a synthetic handshake or is
    approved for a live probe. That remains gated in probe.py through F3/W2.
    """

    protocol: str
    secret: str
    entry_host: str
    entry_port: int
    transport: str
    tls_mode: str
    sni: str
    ws_host: str | None = None
    ws_path: str | None = None
    grpc_service_name: str | None = None
    alpn: tuple[str, ...] = ()
    client_fingerprint: str | None = None
    flow: str | None = None
    reality_public_key: str | None = None
    reality_short_id: str | None = None
    allow_insecure_requested: bool = False
    path_features: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return "ParsedNode(<private>)"

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def secret_kind(self) -> str:
        return "uuid" if self.protocol == "vless" else "password"

    def public_dict(self) -> dict[str, Any]:
        """Construct only enum-valued public fields; no dynamic metadata."""
        return {
            "schema_version": 1,
            "protocol": self.protocol if type(self.protocol) is str and self.protocol in {"vless", "trojan"} else None,
            "transport": self.transport if type(self.transport) is str and self.transport in {"tcp", "ws", "grpc"} else None,
            "tls_mode": self.tls_mode if type(self.tls_mode) is str and self.tls_mode in {"tls", "reality"} else None,
        }
