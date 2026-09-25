"""Redaction helpers: build public-safe views of parsed nodes and probe results."""

from __future__ import annotations

import re
from typing import Any

from nodelab.types import ParsedNode

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_SECRET_QUERY_RE = re.compile(r"((?:uuid|password)=)([^&\s#]+)", re.IGNORECASE)
_USERINFO_SECRET_RE = re.compile(r"^(?:[a-z0-9+.\-]+://)([^@/]+@)", re.IGNORECASE)


def redact_value(value: Any) -> Any:
    """Recursively replace UUIDs and secret query values in a value tree."""
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    if isinstance(value, str):
        s = _UUID_RE.sub("***", value)
        s = _SECRET_QUERY_RE.sub(r"\1***", s)
        return s
    return value


def redacted_node_dict(node: ParsedNode) -> dict[str, Any]:
    """Public dict for one node: secrets absent, redacted_uri attached."""
    d = node.public_dict()
    d["redacted_uri"] = node.raw_uri_public
    return redact_value(d)


def redacted_result_dict(result: dict[str, Any]) -> dict[str, Any]:
    """Public dict for a probe result (secrets scrubbed everywhere)."""
    scrubbed = redact_value(result)
    scrubbed.pop("secret", None)
    return scrubbed
