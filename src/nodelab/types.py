"""Typed data models for parsed proxy nodes."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Optional


class NodeURIParseError(ValueError):
    """Raised when a URI cannot be parsed into a known node shape."""


def _redacted_secret() -> str:
    return "***"


@dataclass
class ParsedNode:
    """One parsed vless:// or trojan:// node.

    The secret (UUID for VLESS, password for Trojan) is kept in `secret`
    only. All repr-style output via `public_dict()` and str() is redacted.
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
    raw_uri_public: str = ""

    def __repr__(self) -> str:
        masked = "***" if self.secret else ""
        safe = dataclasses.replace(self, secret=masked)
        parts = [f"{f.name}={getattr(safe, f.name)!r}" for f in dataclasses.fields(self)]
        return f"{'.'.join((self.__class__.__module__, self.__class__.__qualname__)).split('.')[-1]}({', '.join(parts)})"

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def secret_kind(self) -> str:
        return "uuid" if self.protocol == "vless" else "password"

    def public_dict(self) -> dict[str, Any]:
        """Field dict safe to log / serialize. Secret is never included."""
        out = dataclasses.asdict(self)
        out.pop("secret", None)
        return out
