"""URI parsing for vless:// and trojan://.

Secrets (VLESS UUID, Trojan password) are kept in memory on ParsedNode.secret
and are never included in public_dict(), redacted URIs, or error messages.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Optional

from nodelab.types import NodeURIParseError, ParsedNode

_SUPPORTED = ("vless://", "trojan://")
_SECRET_QUERY_KEYS = {"uuid", "password"}


def _is_valid_uuid(value: str) -> bool:
    v = value.strip().lower()
    if len(v) != 36 or v.count("-") != 4:
        return False
    parts = v.split("-")
    sizes = [8, 4, 4, 4, 12]
    if len(parts) != 5:
        return False
    for size, part in zip(sizes, parts):
        if len(part) != size:
            return False
        try:
            int(part, 16)
        except ValueError:
            return False
    return True


def _flag_path_features(node: ParsedNode) -> None:
    # Only a flag, not a claim: proxyip in path/query is evidence of a
    # multi-hop setup but NL-002 must not assert hop counts from strings.
    if "proxyip=" in node.path or any(f"{k}=" in node.path for k in node.extra_query):
        if "contains_proxyip_list" not in node.path_features:
            node.path_features.append("contains_proxyip_list")


def parse_uri(uri: str) -> ParsedNode:
    """Parse a vless:// or trojan:// URI into a ParsedNode.

    Raises NodeURIParseError (redacted text, no raw secret) on failure.
    """
    if not isinstance(uri, str) or not uri.strip():
        raise NodeURIParseError("empty or non-string URI")
    raw = uri.strip()

    if not any(raw.lower().startswith(s) for s in _SUPPORTED):
        raise NodeURIParseError(
            "unsupported protocol; NL-002 supports vless:// and trojan://"
        )

    head, _, frag = raw.partition("#")
    parsed = urllib.parse.urlparse(head)

    protocol = parsed.scheme.lower()
    userinfo = parsed.netloc.split("@", 1)[0] if "@" in parsed.netloc else ""
    secret = urllib.parse.unquote(userinfo.split(":", 1)[0]) if userinfo else ""

    host = parsed.hostname or ""
    port = parsed.port
    if port is None or not (0 < port <= 65535):
        raise NodeURIParseError("missing or invalid port")
    if not host:
        raise NodeURIParseError("missing host")

    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query: dict[str, str] = {}
    for k, v in pairs:
        query.setdefault(k, v)

    display_name = urllib.parse.unquote(frag) if frag else ""

    if protocol == "vless":
        if not _is_valid_uuid(secret):
            raise NodeURIParseError("invalid vless secret")
        node = ParsedNode(
            protocol="vless",
            display_name=display_name,
            entry_host=host,
            entry_port=port,
            secret=secret,
        )
    else:
        node = ParsedNode(
            protocol="trojan",
            display_name=display_name,
            entry_host=host,
            entry_port=port,
            secret=secret,
        )

    node.transport = query.get("type", "").lower()
    security = query.get("security", "")
    node.tls = security in ("tls", "real")

    node.sni = query.get("sni", "") or query.get("peer", "") or host
    node.host_header = query.get("host", "")
    node.path = urllib.parse.unquote(query.get("path", ""))
    node.flow = query.get("flow", "")
    node.client_fingerprint = query.get("fp", "")
    node.allow_insecure = query.get("allowInsecure", "").lower() in ("1", "true", "yes")

    node.extra_query = {k: v for k, v in query.items() if k.lower() not in _SECRET_QUERY_KEYS}
    node.raw_uri_public = redact_uri(raw)
    _flag_path_features(node)
    return node


def parse_uris(text: str) -> list[Optional[ParsedNode]]:
    """Parse newline-separated URIs; None marks an unparseable line."""
    out: list[Optional[ParsedNode]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(parse_uri(line))
        except NodeURIParseError:
            out.append(None)
    return out


def redact_uri(uri: str) -> str:
    """Return the URI with its credential replaced by ***.

    Works on parseable URIs (blank the userinfo secret, uuid=, password=)
    and on unparseable ones (best-effort blank of uuid=/password= values).
    Never echoes the secret.
    """
    raw = (uri or "").strip()
    if not raw:
        return raw

    known = raw.lower().startswith(_SUPPORTED)
    if known:
        prefix_end = raw.index("://") + 3
        remainder = raw[prefix_end:]
        at = remainder.find("@")
        secret = remainder[:at] if at != -1 else ""
        if secret:
            raw = raw[:prefix_end] + "***" + remainder[at:]
    raw = re.sub(r"(uuid=)([^&\s#]+)", r"\1***", raw)
    raw = re.sub(r"(password=)([^&\s#]+)", r"\1***", raw)
    return raw
