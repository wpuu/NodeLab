"""F2a strict, single-decode VLESS/Trojan URI parser (offline only).

A successfully parsed node is a *private candidate*, not a claim that the
Mihomo configuration/handshake/route works. The F1 probe gate remains closed.
Reality and HTTPUpgrade explicitly remain UNSUPPORTED until independent
local handshake fixtures exist; unknown fields never silently fall back.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import unicodedata
import urllib.parse
import uuid
from dataclasses import dataclass

import idna

from nodelab.types import NodeURIParseError, ParsedNode

_SUPPORTED_SCHEMES = {"vless", "trojan"}
_QUERY_KEYS = {
    key.lower(): key for key in (
        "type", "security", "sni", "peer", "host", "path", "serviceName", "alpn",
        "fp", "flow", "pbk", "sid", "allowInsecure", "encryption",
    )
}
_ALLOWED_ALPN = frozenset({"h2", "http/1.1"})
_FINGERPRINTS = {
    "chrome": "chrome", "firefox": "firefox", "safari": "safari",
    "edge": "edge", "android": "android", "ios": "iOS", "360": "360", "qq": "qq",
}
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_UUID_SHAPE = re.compile(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\Z")
_SERVICE_NAME = re.compile(r"[A-Za-z0-9._/-]+\Z")
_SHORT_ID = re.compile(r"(?:[0-9a-fA-F]{2}){1,8}\Z")
_PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def _has_control(value: str) -> bool:
    return any(unicodedata.category(ch) in {"Cc", "Cs", "Zl", "Zp"} for ch in value)


def _decode(raw: str, *, form: bool = False) -> str:
    if _BAD_PERCENT.search(raw):
        raise NodeURIParseError("INVALID_PERCENT_ENCODING")
    try:
        decoder = urllib.parse.unquote_plus if form else urllib.parse.unquote
        return decoder(raw, encoding="utf-8", errors="strict")
    except UnicodeError:
        raise NodeURIParseError("INVALID_UTF8") from None


def _normalize_host(value: str, *, ipv6_bracketed: bool = False) -> str:
    if not value or _has_control(value) or any(ch in value for ch in "%/@?#\\"):
        raise NodeURIParseError("INVALID_HOST")
    if ipv6_bracketed:
        try:
            addr = ipaddress.IPv6Address(value)
        except ValueError:
            raise NodeURIParseError("INVALID_HOST") from None
        if addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            raise NodeURIParseError("INVALID_HOST")
        return addr.compressed
    if ":" in value or value.endswith("."):
        raise NodeURIParseError("INVALID_HOST")
    try:
        addr4 = ipaddress.IPv4Address(value)
        if addr4.is_link_local or addr4.is_multicast or addr4.is_unspecified:
            raise NodeURIParseError("INVALID_HOST")
        return str(addr4)
    except ipaddress.AddressValueError:
        # Invalid numeric dotted quads must not turn into DNS names.
        if re.fullmatch(r"[0-9.]+", value):
            raise NodeURIParseError("INVALID_HOST") from None
    try:
        alabel = idna.encode(value, uts46=False, std3_rules=True).decode("ascii").lower()
        if len(alabel) > 253 or not all(0 < len(part) <= 63 for part in alabel.split(".")):
            raise NodeURIParseError("INVALID_HOST")
        if idna.encode(idna.decode(alabel), uts46=False, std3_rules=True).decode("ascii").lower() != alabel:
            raise NodeURIParseError("INVALID_HOST")
        return alabel
    except (idna.IDNAError, UnicodeError):
        raise NodeURIParseError("INVALID_HOST") from None


def _authority(netloc: str) -> tuple[str, str, int]:
    if netloc.count("@") != 1:
        raise NodeURIParseError("INVALID_SECRET")
    userinfo, hostport = netloc.split("@", 1)
    if not userinfo or not hostport:
        raise NodeURIParseError("INVALID_SECRET" if not userinfo else "INVALID_HOST")
    if hostport.startswith("["):
        closing = hostport.find("]")
        if closing < 0:
            raise NodeURIParseError("INVALID_HOST")
        if not hostport[closing + 1:]:
            raise NodeURIParseError("INVALID_PORT")
        if hostport[closing + 1:closing + 2] != ":":
            raise NodeURIParseError("INVALID_HOST")
        host = _normalize_host(hostport[1:closing], ipv6_bracketed=True)
        port_text = hostport[closing + 2:]
    else:
        if hostport.count(":") == 0:
            raise NodeURIParseError("INVALID_PORT")
        if hostport.count(":") != 1:
            raise NodeURIParseError("INVALID_HOST")
        raw_host, port_text = hostport.rsplit(":", 1)
        host = _normalize_host(raw_host)
    if not port_text or len(port_text) > 5 or not re.fullmatch(r"[0-9]+", port_text):
        raise NodeURIParseError("INVALID_PORT")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise NodeURIParseError("INVALID_PORT")
    return userinfo, host, port


def _parse_query(raw: str) -> dict[str, str]:
    params: dict[str, str] = {}
    if not raw:
        return params
    for field in raw.split("&"):
        raw_key, separator, raw_value = field.partition("=")
        if not field or not separator or not raw_key:
            raise NodeURIParseError("INVALID_QUERY")
        key = _decode(raw_key, form=True)
        if _has_control(key):
            raise NodeURIParseError("INVALID_QUERY")
        canonical = _QUERY_KEYS.get(key.lower()) if key.isascii() else None
        if canonical is None:
            raise NodeURIParseError("UNSUPPORTED_QUERY_PARAM")
        if canonical in params:
            raise NodeURIParseError("DUPLICATE_PARAM")
        value = _decode(raw_value, form=True)
        if _has_control(value):
            raise NodeURIParseError("INVALID_QUERY")
        if not value and canonical != "sid":
            raise NodeURIParseError("INVALID_QUERY")
        params[canonical] = value
    return params


def _sni(value: str) -> str:
    if value.startswith("[") and value.endswith("]"):
        return _normalize_host(value[1:-1], ipv6_bracketed=True)
    return _normalize_host(value)


def _ws_host(value: str) -> str:
    if _has_control(value) or any(ch in value for ch in "/@?#\\"):
        raise NodeURIParseError("INVALID_HOST_HEADER")
    try:
        if value.startswith("["):
            ending = value.find("]")
            if ending < 0:
                raise NodeURIParseError("INVALID_HOST_HEADER")
            host = "[" + _normalize_host(value[1:ending], ipv6_bracketed=True) + "]"
            remainder = value[ending + 1:]
        else:
            if value.count(":") > 1:
                raise NodeURIParseError("INVALID_HOST_HEADER")
            raw_host, separator, raw_port = value.partition(":")
            host = _normalize_host(raw_host)
            remainder = ":" + raw_port if separator else ""
        if not remainder:
            return host
        if not remainder.startswith(":") or len(remainder[1:]) > 5 or not re.fullmatch(r"[0-9]+", remainder[1:]):
            raise NodeURIParseError("INVALID_HOST_HEADER")
        port = int(remainder[1:])
        if not 1 <= port <= 65535:
            raise NodeURIParseError("INVALID_HOST_HEADER")
        return f"{host}:{port}"
    except NodeURIParseError:
        raise NodeURIParseError("INVALID_HOST_HEADER") from None


def _alpn(raw: str | None, *, grpc: bool) -> tuple[str, ...]:
    if raw is None:
        return ("h2",) if grpc else ()
    parts = raw.split(",")
    if any(not part or part not in _ALLOWED_ALPN for part in parts) or len(set(parts)) != len(parts):
        raise NodeURIParseError("UNSUPPORTED_ALPN")
    if grpc and "h2" not in parts:
        raise NodeURIParseError("UNSUPPORTED_ALPN")
    return tuple(parts)


def _validate_reality(params: dict[str, str], *, protocol: str, transport: str) -> None:
    if protocol != "vless" or transport != "tcp":
        raise NodeURIParseError("UNSUPPORTED_REALITY")
    public_key = params.get("pbk")
    short_id = params.get("sid")
    if not public_key or short_id is None or not params.get("sni") or not params.get("fp"):
        raise NodeURIParseError("UNSUPPORTED_REALITY")
    if not _PUBLIC_KEY.fullmatch(public_key):
        raise NodeURIParseError("UNSUPPORTED_REALITY")
    try:
        key = base64.urlsafe_b64decode(public_key + "=")
        if len(key) != 32 or base64.urlsafe_b64encode(key).decode("ascii").rstrip("=") != public_key:
            raise NodeURIParseError("UNSUPPORTED_REALITY")
    except (ValueError, base64.binascii.Error):
        raise NodeURIParseError("UNSUPPORTED_REALITY") from None
    if short_id and not _SHORT_ID.fullmatch(short_id):
        raise NodeURIParseError("UNSUPPORTED_REALITY")


def parse_uri(uri: str) -> ParsedNode:
    """Parse ONE URI into a private typed candidate; errors are fixed codes.

    A supported *parse dialect* must still pass F2b engine mapping, a local
    synthetic handshake and F3 route proof before any production PASS.
    """
    if not isinstance(uri, str) or not uri or uri != uri.strip() or any(ch.isspace() for ch in uri) or _has_control(uri):
        raise NodeURIParseError("INVALID_URI")
    try:
        size = len(uri.encode("utf-8", errors="strict"))
    except UnicodeError:
        raise NodeURIParseError("INVALID_UTF8") from None
    if size > 8192:
        raise NodeURIParseError("LINE_TOO_LONG")
    if not uri.lower().startswith(("vless://", "trojan://")):
        raise NodeURIParseError("UNSUPPORTED_PROTOCOL")
    try:
        parsed = urllib.parse.urlsplit(uri)
        protocol = parsed.scheme.lower()
        if protocol not in _SUPPORTED_SCHEMES or parsed.path:
            raise NodeURIParseError("INVALID_URI")
        raw_userinfo, entry_host, entry_port = _authority(parsed.netloc)
        secret = _decode(raw_userinfo)
        if not secret or not secret.strip() or _has_control(secret):
            raise NodeURIParseError("INVALID_SECRET")
        if protocol == "vless":
            if not _UUID_SHAPE.fullmatch(secret):
                raise NodeURIParseError("INVALID_SECRET")
            try:
                secret = str(uuid.UUID(secret))
            except ValueError:
                raise NodeURIParseError("INVALID_SECRET") from None
        # Decode fragment once only to check syntax; never store the value.
        if parsed.fragment and _has_control(_decode(parsed.fragment)):
            raise NodeURIParseError("INVALID_URI")
        params = _parse_query(parsed.query)
        if "sni" in params and "peer" in params:
            raise NodeURIParseError("DUPLICATE_PARAM")

        transport = params.get("type", "tcp").lower()
        if transport == "httpupgrade":
            raise NodeURIParseError("UNSUPPORTED_HTTPUPGRADE")
        if transport not in {"tcp", "ws", "grpc"}:
            raise NodeURIParseError("UNSUPPORTED_TRANSPORT")
        security = params.get("security", "tls" if protocol == "trojan" else "").lower()
        if security not in {"tls", "reality"} or (protocol == "trojan" and security != "tls"):
            raise NodeURIParseError("UNSUPPORTED_SECURITY")

        insecure = params.get("allowInsecure", "false").lower()
        if insecure not in {"0", "1", "false", "true"}:
            raise NodeURIParseError("INVALID_FLAG")
        if insecure in {"1", "true"}:
            raise NodeURIParseError("UNSUPPORTED_INSECURE_NOT_APPROVED")
        if "encryption" in params and (protocol != "vless" or params["encryption"].lower() != "none"):
            raise NodeURIParseError("UNSUPPORTED_ENCRYPTION")

        raw_flow = params.get("flow")
        if raw_flow and raw_flow != "xtls-rprx-vision":
            raise NodeURIParseError("UNSUPPORTED_FLOW")
        if raw_flow and (protocol != "vless" or transport != "tcp"):
            raise NodeURIParseError("UNSUPPORTED_FLOW_COMBINATION")
        fp_raw = params.get("fp")
        fingerprint = _FINGERPRINTS.get(fp_raw.lower()) if fp_raw is not None and fp_raw.isascii() else None
        if fp_raw is not None and fingerprint is None:
            raise NodeURIParseError("UNSUPPORTED_FINGERPRINT")

        if security == "reality":
            _validate_reality(params, protocol=protocol, transport=transport)
            if "peer" in params:
                raise NodeURIParseError("UNSUPPORTED_REALITY")
            _sni(params["sni"])
            # No local Reality keypair/listener handshake fixture yet.
            raise NodeURIParseError("UNSUPPORTED_REALITY")
        if "pbk" in params or "sid" in params:
            raise NodeURIParseError("UNSUPPORTED_REALITY")

        raw_sni = params.get("sni", params.get("peer"))
        if raw_sni is None:
            try:
                ipaddress.ip_address(entry_host)
            except ValueError:
                raw_sni = entry_host  # documented DNS-only ordinary-TLS default
            else:
                raise NodeURIParseError("UNSUPPORTED_SNI_REQUIRED")
        sni = _sni(raw_sni)

        ws_host: str | None = None
        ws_path: str | None = None
        grpc_service_name: str | None = None
        if transport == "ws":
            if "serviceName" in params or "host" not in params or "path" not in params:
                raise NodeURIParseError("UNSUPPORTED_TRANSPORT")
            ws_host = _ws_host(params["host"])
            ws_path = params["path"]
            if not ws_path.startswith("/") or _has_control(ws_path):
                raise NodeURIParseError("INVALID_PATH")
        elif transport == "grpc":
            if "host" in params or "path" in params or "serviceName" not in params:
                raise NodeURIParseError("UNSUPPORTED_TRANSPORT")
            grpc_service_name = params["serviceName"]
            if not _SERVICE_NAME.fullmatch(grpc_service_name):
                raise NodeURIParseError("INVALID_SERVICE_NAME")
        elif any(key in params for key in ("host", "path", "serviceName")):
            raise NodeURIParseError("UNSUPPORTED_TRANSPORT")

        alpn = _alpn(params.get("alpn"), grpc=(transport == "grpc"))
        hints = ("contains_proxyip_list",) if ws_path and "proxyip=" in ws_path.lower() else ()
        return ParsedNode(
            protocol=protocol, secret=secret, entry_host=entry_host, entry_port=entry_port,
            transport=transport, tls_mode="tls", sni=sni, ws_host=ws_host, ws_path=ws_path,
            grpc_service_name=grpc_service_name, alpn=alpn,
            client_fingerprint=fingerprint, flow=raw_flow, path_features=hints,
        )
    except NodeURIParseError:
        raise
    except (ValueError, UnicodeError, OverflowError, idna.IDNAError):
        raise NodeURIParseError("INVALID_URI") from None


@dataclass(frozen=True, slots=True, repr=False)
class ParsedLine:
    line_number: int
    node: ParsedNode | None
    probe_status: str
    error_code: str | None

    def __repr__(self) -> str:
        return "ParsedLine(<private>)"


@dataclass(frozen=True, slots=True, repr=False)
class ParseBatch:
    lines: tuple[ParsedLine, ...]
    skipped_count: int

    def __repr__(self) -> str:
        return "ParseBatch(<private>)"


def parse_uris(data: bytes | str, *, limit: int | None = None) -> ParseBatch:
    """Strict per-physical-line processing; never discard a bad line.

    Input remains private, and callers must use the fixed public serializer.
    Empty lines are counted, not passed to parse_uri().
    """
    if isinstance(data, str):
        try:
            data = data.encode("utf-8", errors="strict")
        except UnicodeError:
            return ParseBatch((ParsedLine(1, None, "FAIL", "INVALID_UTF8"),), 0)
    if not isinstance(data, bytes):
        return ParseBatch((ParsedLine(1, None, "FAIL", "INVALID_URI"),), 0)
    lines: list[ParsedLine] = []
    skipped = 0
    physical_lines = data.split(b"\n") if data else []
    if data.endswith(b"\n"):
        physical_lines.pop()  # the final delimiter is not an extra line
    for number, raw_line in enumerate(physical_lines, 1):
        if limit is not None and len(lines) >= max(0, limit):
            break
        if raw_line.endswith(b"\r"):
            raw_line = raw_line[:-1]
        if not raw_line.strip():
            skipped += 1
            continue
        if len(raw_line) > 8192:
            lines.append(ParsedLine(number, None, "FAIL", "LINE_TOO_LONG"))
            continue
        try:
            uri = raw_line.decode("utf-8", errors="strict")
            node = parse_uri(uri)
            lines.append(ParsedLine(number, node, "UNSUPPORTED", "PROBE_GATE_CLOSED"))
        except UnicodeError:
            lines.append(ParsedLine(number, None, "FAIL", "INVALID_UTF8"))
        except NodeURIParseError as exc:
            lines.append(ParsedLine(number, None, exc.probe_status, exc.code))
    return ParseBatch(tuple(lines), skipped)


def redact_uri(_uri: str) -> str:
    """Legacy API: no arbitrary URI (even masked) is safe for display."""
    return "[URI_REDACTED]"
