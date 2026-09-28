"""Pure, private parsers for the two fixed exit-response formats. No I/O."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re

_CODES = frozenset({"EXIT_SOURCE_INVALID", "EXIT_BODY_INVALID", "EXIT_BODY_TOO_LARGE",
                    "EXIT_IP_INVALID", "EXIT_IP_NOT_PUBLIC"})
_DOCUMENTATION = tuple(ipaddress.ip_network(net) for net in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))
_KEY = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")


class ExitResponseError(ValueError):
    def __init__(self, code: str):
        self.code = code if type(code) is str and code in _CODES else "EXIT_BODY_INVALID"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True, repr=False)
class ExitAddress:
    source: str
    address: ipaddress.IPv4Address | ipaddress.IPv6Address

    def __repr__(self):
        return "ExitAddress(<private>)"


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExitResponseError("EXIT_BODY_INVALID")
        result[key] = value
    return result


def _bad_constant(value):
    raise ExitResponseError("EXIT_BODY_INVALID")


def parse_exit_response(source: str, body: bytes, *, fixture_addresses: bool = False) -> ExitAddress:
    """EXIT_A: ipify JSON; EXIT_B: Cloudflare trace. Never echo input errors.

    The only non-global addresses allowed by the explicit fixture flag are
    documentation ranges. Private/loopback/link-local never become valid exits.
    This validates a body, not its HTTP/TLS provenance or per-request route.
    """
    if type(source) is not str or source not in ("EXIT_A", "EXIT_B"):
        raise ExitResponseError("EXIT_SOURCE_INVALID")
    if type(body) is not bytes or type(fixture_addresses) is not bool:
        raise ExitResponseError("EXIT_BODY_INVALID")
    if len(body) > 64 * 1024:
        raise ExitResponseError("EXIT_BODY_TOO_LARGE")
    try:
        text = body.decode("utf-8", "strict")
        if source == "EXIT_A":
            payload = json.loads(text, object_pairs_hook=_pairs, parse_constant=_bad_constant)
            if type(payload) is not dict or set(payload) != {"ip"}:
                raise ExitResponseError("EXIT_BODY_INVALID")
            raw = payload["ip"]
        else:
            if "\r" in text.replace("\r\n", ""):
                raise ExitResponseError("EXIT_BODY_INVALID")
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()  # accept exactly the usual terminal LF/CRLF
            if not lines or len(lines) > 128:
                raise ExitResponseError("EXIT_BODY_INVALID")
            payload = {}
            for line in lines:
                if line.endswith("\r"):
                    line = line[:-1]
                key, separator, value = line.partition("=")
                if (not separator or not _KEY.fullmatch(key) or key in payload
                        or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                    raise ExitResponseError("EXIT_BODY_INVALID")
                payload[key] = value
            if "ip" not in payload:
                raise ExitResponseError("EXIT_BODY_INVALID")
            raw = payload["ip"]
    except ExitResponseError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise ExitResponseError("EXIT_BODY_INVALID") from None
    if type(raw) is not str or not raw or len(raw) > 45 or "%" in raw or not raw.isascii():
        raise ExitResponseError("EXIT_IP_INVALID")
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        raise ExitResponseError("EXIT_IP_INVALID") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise ExitResponseError("EXIT_IP_INVALID")
    documentary = any(address.version == net.version and address in net for net in _DOCUMENTATION)
    if not ((fixture_addresses and documentary) or (
        address.is_global and not address.is_multicast and not address.is_reserved
        and not address.is_unspecified and not address.is_loopback and not address.is_link_local
    )):
        raise ExitResponseError("EXIT_IP_NOT_PUBLIC")
    return ExitAddress(source, address)
