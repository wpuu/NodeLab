"""F3 candidate: pure matching of a private v1.19.31 /connections snapshot.

No network, no PASS verdict, no claim of authenticated controller provenance.
A future collector must supply local socket facts, request/capture time windows,
per-run identity and baseline IDs from the SAME verified engine. Untrusted JSON
cannot establish those facts by itself. Production probing remains disabled.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
from uuid import UUID

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(r"(?=.{1,253}\Z)" + _LABEL + r"(?:\." + _LABEL + r")*\Z")
_STAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True, repr=False)
class RequestWindow:
    run_id: str
    source: str  # EXIT_A or EXIT_B, assigned by the local collector
    host: str  # canonical ASCII host used in the original CONNECT
    port: int
    mixed_port: int
    source_port: int  # mandatory in this first, deliberately strict slice
    opened_ns: int  # UTC epoch ns, sampled locally before the original request
    closed_ns: int  # sampled locally after the streaming response is released

    def __repr__(self):
        return "RequestWindow(<private>)"


@dataclass(frozen=True, slots=True, repr=False)
class ConnectionSnapshot:
    run_id: str
    started_ns: int  # local capture interval, not values from JSON
    finished_ns: int
    payload: object

    def __repr__(self):
        return "ConnectionSnapshot(<private>)"


@dataclass(frozen=True, slots=True, repr=False)
class EvidenceMatch:
    code: str
    connection_id: str | None = None

    @property
    def matched(self):
        return self.code == "EVIDENCE_MATCHED"

    def __repr__(self):
        return "EvidenceMatch(<private>)"


def _uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _port(value: object) -> bool:
    return type(value) is int and 1 <= value <= 65535


def _ns(value: object) -> bool:
    return type(value) is int and value > 0


def _timestamp_ns(value: object) -> int | None:
    if type(value) is not str:
        return None
    match = _STAMP.fullmatch(value)
    if not match:
        return None
    try:
        base = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))
        delta = base.astimezone(timezone.utc) - _EPOCH
        # Integer arithmetic preserves Go time.Time's nanosecond precision.
        return (delta.days * 86400 + delta.seconds) * 10**9 + int((match[2] or "").ljust(9, "0"))
    except (ValueError, OverflowError):
        return None


def match_connection(
    request: RequestWindow, snapshot: ConnectionSnapshot,
    *, previous_ids: frozenset[str] = frozenset(),
) -> EvidenceMatch:
    """One original request -> exactly one active connection, or fixed refusal.

    `previous_ids` includes baseline (pre-request) IDs and already consumed IDs
    in this run. Caller-owned provenance is required; matching alone is NOT a
    route proof or permission to set RouteObservation.route_verified in product.
    Unknown/malformed required fields are never coerced into positive evidence.
    """
    reject = EvidenceMatch
    if type(request) is not RequestWindow or type(snapshot) is not ConnectionSnapshot:
        return reject("EVIDENCE_INPUT_INVALID")
    if (not _uuid(request.run_id) or request.source not in ("EXIT_A", "EXIT_B")
            or type(request.host) is not str or not _HOST.fullmatch(request.host)
            or not all(_port(x) for x in (request.port, request.mixed_port, request.source_port))
            or not all(_ns(x) for x in (request.opened_ns, request.closed_ns,
                                       snapshot.started_ns, snapshot.finished_ns))
            or type(previous_ids) is not frozenset or not all(_uuid(x) for x in previous_ids)):
        return reject("EVIDENCE_INPUT_INVALID")
    if snapshot.run_id != request.run_id:
        return reject("EVIDENCE_RUN_MISMATCH")
    if not (request.opened_ns <= snapshot.started_ns <= snapshot.finished_ns <= request.closed_ns):
        return reject("EVIDENCE_WINDOW_MISMATCH")
    payload = snapshot.payload
    if type(payload) is not dict or "connections" not in payload:
        return reject("EVIDENCE_SNAPSHOT_INVALID")
    rows = payload["connections"]
    # An empty Go slice is serialized as null by this tag's Manager.Snapshot.
    if rows is None:
        return reject("EVIDENCE_MISSING")
    if type(rows) is not list or len(rows) > 4096:
        return reject("EVIDENCE_SNAPSHOT_INVALID")
    candidates = []
    seen = set()
    for row in rows:
        if type(row) is not dict or not _uuid(row.get("id")) or type(row.get("metadata")) is not dict:
            return reject("EVIDENCE_SNAPSHOT_INVALID")
        if row["id"] in seen:
            return reject("EVIDENCE_AMBIGUOUS")
        seen.add(row["id"])
        meta = row["metadata"]
        # The pinned Go metadata uses JSON strings for all three uint16 ports.
        # SetRemoteAddress at the pinned tag clears Host for IP literals and
        # puts the address in destinationIP. Never treat an empty Host as a
        # wildcard, or accept a domain record as evidence for an IP request.
        try:
            literal = ipaddress.ip_address(request.host)
        except ValueError:
            target_fields = {"host": request.host}
        else:
            target_fields = {"host": "", "destinationIP": str(literal)}
        expected = {
            "network": "tcp", "type": "HTTPS", **target_fields,
            "destinationPort": str(request.port), "sourceIP": "127.0.0.1",
            "sourcePort": str(request.source_port), "inboundIP": "127.0.0.1",
            "inboundPort": str(request.mixed_port),
        }
        if all(type(meta.get(key)) is str and meta[key] == value for key, value in expected.items()):
            candidates.append(row)
    if not candidates:
        return reject("EVIDENCE_MISSING")
    if len(candidates) != 1:
        return reject("EVIDENCE_AMBIGUOUS")
    row = candidates[0]
    if row["id"] in previous_ids:
        return reject("EVIDENCE_REPLAYED")
    started = _timestamp_ns(row.get("start"))
    if started is None or not request.opened_ns <= started <= snapshot.finished_ns:
        return reject("EVIDENCE_WINDOW_MISMATCH")
    if row.get("chains") != ["NODE", "PROBE"]:
        return reject("EVIDENCE_ROUTE_MISMATCH")
    if (type(row.get("rule")) is not str or row["rule"].upper() != "MATCH"
            or row.get("rulePayload") != ""):
        return reject("EVIDENCE_ROUTE_MISMATCH")
    return EvidenceMatch("EVIDENCE_MATCHED", row["id"])


def match_pair(
    first: RequestWindow, first_snapshot: ConnectionSnapshot,
    second: RequestWindow, second_snapshot: ConnectionSnapshot,
    *, previous_ids: frozenset[str] = frozenset(),
) -> tuple[EvidenceMatch, EvidenceMatch]:
    """Two sequential independent sources; no ID reuse or duplicate target."""
    invalid = EvidenceMatch("EVIDENCE_PAIR_INVALID")
    a = match_connection(first, first_snapshot, previous_ids=previous_ids)
    b = match_connection(second, second_snapshot, previous_ids=previous_ids)
    if (type(first) is not RequestWindow or type(second) is not RequestWindow
            or not _ns(first.closed_ns) or not _ns(second.opened_ns)):
        return a, b
    if (first.source != "EXIT_A" or second.source != "EXIT_B"
            or first.run_id != second.run_id or first.mixed_port != second.mixed_port
            or first.host == second.host
            or first.closed_ns > second.opened_ns
            or (a.matched and b.matched and a.connection_id == b.connection_id)):
        return invalid, invalid
    return a, b
