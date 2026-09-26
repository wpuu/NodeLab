"""Legacy URI parser isolated behind the F1 probe gate.

F2 will define the strict, lossless VLESS/Trojan dialect.  Until then no
parsed value may cause a network probe, and no original URI is displayable.
"""

from __future__ import annotations

import urllib.parse

from nodelab.types import NodeURIParseError, ParsedNode

_SUPPORTED = ("vless://", "trojan://")
_SECRET_QUERY_KEYS = {"uuid", "password"}


def _is_valid_uuid(value: str) -> bool:
    v = value.lower()
    parts = v.split("-")
    if len(parts) != 5:
        return False
    for size, part in zip((8, 4, 4, 4, 12), parts):
        if len(part) != size:
            return False
        try:
            int(part, 16)
        except ValueError:
            return False
    return True


def _flag_path_features(node: ParsedNode) -> None:
    # A private hint, not a hop-count assertion or public metadata.
    if "proxyip=" in node.path or any(f"{k}=" in node.path for k in node.extra_query):
        node.path_features.append("contains_proxyip_list")


def parse_uri(uri: str) -> ParsedNode:
    """Parse a single line into a *private* node, never into probe authority.

    Raises only fixed-code NodeURIParseError; no untrusted exception message
    is chained into a public result.  This is not F2 dialect validation.
    """
    if not isinstance(uri, str) or not uri or uri != uri.strip() or any(c in uri for c in "\r\n\x00"):
        raise NodeURIParseError("INVALID_URI")
    try:
        size = len(uri.encode("utf-8", errors="strict"))
    except UnicodeError:
        raise NodeURIParseError("INVALID_URI") from None
    if size > 8192:
        raise NodeURIParseError("LINE_TOO_LONG")
    if not uri.lower().startswith(_SUPPORTED):
        raise NodeURIParseError("UNSUPPORTED_PROTOCOL")

    try:
        head, _, fragment = uri.partition("#")
        parsed = urllib.parse.urlparse(head)
        protocol = parsed.scheme.lower()
        if parsed.netloc.count("@") != 1:
            raise NodeURIParseError("INVALID_SECRET")
        userinfo, _hostport = parsed.netloc.split("@", 1)
        # Trojan passwords include literal ':'; an '@' in a password must
        # be percent-encoded. VLESS secrets remain UUIDs only.
        secret = urllib.parse.unquote(userinfo, encoding="utf-8", errors="strict")
        if not secret or any(ord(c) < 32 or ord(c) == 127 for c in secret):
            raise NodeURIParseError("INVALID_SECRET")

        host = parsed.hostname or ""
        port = parsed.port
        if port is None or not (0 < port <= 65535):
            raise NodeURIParseError("INVALID_PORT")
        if not host:
            raise NodeURIParseError("INVALID_HOST")

        pairs = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, encoding="utf-8", errors="strict", max_num_fields=100,
        )
        query: dict[str, str] = {}
        for key, value in pairs:
            query.setdefault(key, value)
        display_name = urllib.parse.unquote(fragment, encoding="utf-8", errors="strict") if fragment else ""

        if protocol == "vless" and not _is_valid_uuid(secret):
            raise NodeURIParseError("INVALID_SECRET")
        node = ParsedNode(protocol=protocol, display_name=display_name, entry_host=host,
                          entry_port=port, secret=secret)
        node.transport = query.get("type", "").lower()
        node.tls = query.get("security", "") in ("tls", "real")
        node.sni = query.get("sni", "") or query.get("peer", "") or host
        node.host_header = query.get("host", "")
        node.path = urllib.parse.unquote(query.get("path", ""), encoding="utf-8", errors="strict")
        node.flow = query.get("flow", "")
        node.client_fingerprint = query.get("fp", "")
        node.allow_insecure = query.get("allowInsecure", "").lower() in ("1", "true", "yes")
        node.extra_query = {k: v for k, v in query.items() if k.lower() not in _SECRET_QUERY_KEYS}
        _flag_path_features(node)
        return node
    except NodeURIParseError:
        raise
    except (ValueError, UnicodeError, OverflowError):
        raise NodeURIParseError("INVALID_URI") from None


def parse_uris(text: str) -> list[ParsedNode | None]:
    """Compatibility helper; strict per-line input and statuses arrive in F2."""
    out: list[ParsedNode | None] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            out.append(parse_uri(line))
        except NodeURIParseError:
            out.append(None)
    return out


def redact_uri(uri: str) -> str:
    """Legacy API: an arbitrary URI is *never* safe to show, even masked."""
    return "[URI_REDACTED]"
