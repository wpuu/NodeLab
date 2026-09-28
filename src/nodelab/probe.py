"""F1 fail-closed probe gate and pure verdict rules; no live network probes.

The former code could return PASS solely because two exit-IP sites agreed,
without proving either request went through NODE.  F3 will wire validated,
connection-specific Mihomo evidence into this decision boundary.  Until F3
and Windows offline acceptance, every production probe is disabled.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

from nodelab.redaction import redacted_result_dict
from nodelab.types import PROBE_GATE_OPEN, ParsedNode


@dataclass(frozen=True, repr=False)
class RouteObservation:
    """Private evidence candidate, NOT proof until F3 verifies controller IDs.

    No arbitrary string here is ever serialized to public output.
    """

    ip: str | None = None
    route_verified: bool = False
    tls_verified: bool = False
    http_ok: bool = False
    direct_seen: bool = False

    def __repr__(self) -> str:
        return "RouteObservation(<private>)"


def decide_probe_status(
    source_a: RouteObservation | None,
    source_b: RouteObservation | None,
    *,
    runtime_verified: bool,
    cleanup_ok: bool,
    unsupported: bool = False,
    hard_failure: bool = False,
    production: bool = True,
) -> tuple[str, str | None]:
    """Pure fail-closed verdict; F1 product never supplies positive evidence.

    Only F3's per-original-request association may assert route_verified.
    A validated public exit IP is returned privately only after both sources
    agree; the public serializer deliberately has no confirmed-IP field.
    """
    if any(type(flag) is not bool for flag in (unsupported, hard_failure, production)):
        return "FAIL", None
    if cleanup_ok is not True or hard_failure:
        return "FAIL", None
    if unsupported:
        # UNSUPPORTED belongs before process/network work, not after observations
        # have been collected. It must never hide failed cleanup or route facts.
        return ("UNSUPPORTED", None) if source_a is None and source_b is None else ("FAIL", None)
    if runtime_verified is not True:
        return "FAIL", None
    if any(item is not None and type(item) is not RouteObservation for item in (source_a, source_b)):
        return "FAIL", None
    if (source_a and source_a.direct_seen) or (source_b and source_b.direct_seen):
        return "FAIL", None

    def valid(observation: RouteObservation | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        if (observation is None or type(observation.route_verified) is not bool
                or not observation.route_verified or observation.tls_verified is not True
                or observation.http_ok is not True or not isinstance(observation.ip, str)):
            return None
        try:
            if "%" in observation.ip:
                return None
            address = ipaddress.ip_address(observation.ip)
            if address.is_multicast or (production and not address.is_global):
                return None
            return address
        except ValueError:
            return None

    first = valid(source_a)
    second = valid(source_b)
    if first is not None and second is not None:
        if first.version != second.version:
            return "PARTIAL", None
        if first != second:
            return "CONFLICT", None
        return "PASS", str(first)
    if first is not None or second is not None:
        return "PARTIAL", None
    return "FAIL", None


def probe_node(node: ParsedNode) -> dict:
    """Always fail without side effects while route proof is unavailable."""
    if PROBE_GATE_OPEN:
        # Tripwire: F3 must replace this function together with the switch.
        raise RuntimeError("PROBE_GATE_OPEN_WITHOUT_ROUTE_PROOF")
    result = node.public_dict() if isinstance(node, ParsedNode) else {}
    result.update({
        "probe_status": "FAIL", "stage": "ROUTE", "error_code": "ROUTE_PROOF_UNAVAILABLE",
        "route_verified": False, "config_ok": False, "source_count": 0,
    })
    return redacted_result_dict(result)


def probe_from_file(path: str, limit: int = 1) -> list[dict]:
    """Legacy API: intentionally does not even read a sensitive file in F1."""
    return [redacted_result_dict({
        "probe_status": "FAIL", "stage": "ROUTE", "error_code": "PROBE_GATE_CLOSED",
        "route_verified": False, "source_count": 0,
    })]


def save_probe_results(results: list[dict], out_dir: str = "data/probe-results") -> Path:
    """Plaintext latest.json is forbidden; private persistence is a later gate."""
    raise RuntimeError("RESULT_STORAGE_DISABLED")
