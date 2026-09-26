"""Private parsed-node data and fixed, non-reflective public metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_PARSE_CODES = frozenset({
    "INVALID_URI", "INVALID_HOST", "INVALID_PORT", "INVALID_SECRET",
    "INVALID_QUERY", "LINE_TOO_LONG", "UNSUPPORTED_PROTOCOL",
})


class NodeURIParseError(ValueError):
    """Parse failure with a fixed code only: never carry a URI or exception text."""

    def __init__(self, code: str = "INVALID_URI") -> None:
        self.code = code if type(code) is str and code in _PARSE_CODES else "INVALID_URI"
        super().__init__(self.code)


@dataclass
class ParsedNode:
    """Private node; do not serialize it automatically or send it to a logger.

    Fragment, hostname, path, query values and even a 'redacted URI' may
    contain arbitrary credentials.  Only public_dict() may cross the public
    boundary; the model remains private even when repr() is called by a test.
    F2 will replace the legacy protocol fields with a strictly typed model.
    """

    protocol: str
    display_name: str = ""
    entry_host: str = ""
    entry_port: int = 0
    transport: str = ""
    tls: bool = False
    sni: str = ""
    host_header: str = ""
    path: str = ""
    flow: str = ""
    client_fingerprint: str = ""
    allow_insecure: bool = False
    path_features: list[str] = field(default_factory=list)
    extra_query: dict[str, str] = field(default_factory=dict)
    secret: str = ""

    def __repr__(self) -> str:
        return "ParsedNode(<private>)"

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def secret_kind(self) -> str:
        return "uuid" if self.protocol == "vless" else "password"

    def public_dict(self) -> dict[str, Any]:
        """Build from a fixed allowlist, never from dataclasses.asdict()."""
        return {
            "schema_version": 1,
            "protocol": self.protocol if type(self.protocol) is str and self.protocol in {"vless", "trojan"} else None,
            "transport": self.transport if type(self.transport) is str and self.transport in {"tcp", "ws", "grpc"} else None,
            # The old boolean cannot distinguish ordinary TLS from Reality.
            "tls_mode": None,
        }
