"""F3 local-fixture-only HTTPS capture; never a production probe entry point.

Only loopback HTTPS URLs and a loopback HTTP proxy are permitted. The injected
snapshot reader is NOT authenticated evidence: results remain private candidate
records. No probe verdict, no public serialization, no gate change.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import ssl
import time

import httpx

from nodelab.deadline import DeadlineExpired, after, remaining
from nodelab.route_evidence import (
    ConnectionSnapshot, EvidenceMatch, RequestWindow, match_connection, _uuid,
)

_CODES = frozenset({
    "FIXTURE_INPUT_INVALID", "FIXTURE_TLS_REQUIRED", "FIXTURE_HTTP_FAILED",
    "FIXTURE_HTTP_STATUS", "FIXTURE_BODY_INVALID", "FIXTURE_BODY_TOO_LARGE",
    "FIXTURE_SOCKET_UNAVAILABLE", "FIXTURE_BASELINE_INVALID",
    "FIXTURE_SNAPSHOT_FAILED", "FIXTURE_CLOCK_CHANGED", "FIXTURE_TIMEOUT",
})


class FixtureCaptureError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code if type(code) is str and code in _CODES else "FIXTURE_INPUT_INVALID")


@dataclass(frozen=True, slots=True, repr=False)
class FixtureCapture:
    request: RequestWindow
    snapshot: ConnectionSnapshot
    evidence: EvidenceMatch
    body: bytes
    previous_ids: frozenset[str] = frozenset()

    def __repr__(self):
        return "FixtureCapture(<private>)"


def _baseline_ids(payload: object) -> frozenset[str]:
    if type(payload) is not dict or "connections" not in payload:
        raise FixtureCaptureError("FIXTURE_BASELINE_INVALID")
    rows = payload["connections"]
    if rows is None:
        return frozenset()
    if type(rows) is not list or len(rows) > 4096:
        raise FixtureCaptureError("FIXTURE_BASELINE_INVALID")
    ids = []
    for row in rows:
        if type(row) is not dict or not _uuid(row.get("id")):
            raise FixtureCaptureError("FIXTURE_BASELINE_INVALID")
        ids.append(row["id"])
    if len(ids) != len(set(ids)):
        raise FixtureCaptureError("FIXTURE_BASELINE_INVALID")
    return frozenset(ids)


def collect_fixture_request(
    url: str, *, proxy_port: int, tls: ssl.SSLContext,
    snapshot_reader: Callable[[float], object], run_id: str, source: str,
    previous_ids: frozenset[str] = frozenset(), deadline_seconds: float = 10.0,
    _runtime_check: Callable[[float], None] | None = None,
    _deadline: float | None = None,
) -> FixtureCapture:
    """Stream one original local HTTPS response and capture before body read.

    New client per call; no keepalive reuse, redirects, environment proxies or
    TLS downgrade. Missing source-port or snapshot evidence never gets guessed.
    Snapshot reader receives the SAME absolute monotonic work deadline.
    """
    try:
        target = httpx.URL(url)
        deadline = after(deadline_seconds) if _deadline is None else _deadline
        if (target.scheme != "https" or target.host not in ("localhost", "127.0.0.1")
                or target.userinfo or target.fragment
                or (target.port is not None and not 1 <= target.port <= 65535)
                or type(proxy_port) is not int or not 1 <= proxy_port <= 65535
                or not _uuid(run_id) or source not in ("EXIT_A", "EXIT_B")
                or type(previous_ids) is not frozenset or not all(_uuid(x) for x in previous_ids)):
            raise ValueError()
    except (ValueError, TypeError, httpx.InvalidURL):
        raise FixtureCaptureError("FIXTURE_INPUT_INVALID") from None
    if (not isinstance(tls, ssl.SSLContext) or tls.verify_mode != ssl.CERT_REQUIRED
            or tls.check_hostname is not True):
        raise FixtureCaptureError("FIXTURE_TLS_REQUIRED")
    origin_wall, origin_mono = time.time_ns(), time.monotonic_ns()
    last_wall = origin_wall

    def stamp():
        nonlocal last_wall
        wall, mono = time.time_ns(), time.monotonic_ns()
        if wall < last_wall or abs((wall - origin_wall) - (mono - origin_mono)) > 100_000_000:
            raise FixtureCaptureError("FIXTURE_CLOCK_CHANGED")
        last_wall = wall
        return wall

    def snapshot():
        remaining(10.0, deadline)
        try:
            payload = snapshot_reader(deadline)
        except DeadlineExpired:
            raise
        except Exception:
            raise FixtureCaptureError("FIXTURE_SNAPSHOT_FAILED") from None
        remaining(10.0, deadline)
        return payload

    try:
        baseline = _baseline_ids(snapshot()) | previous_ids
        stamp()
        with httpx.Client(
            proxy=f"http://127.0.0.1:{proxy_port}", verify=tls, trust_env=False,
            follow_redirects=False, http2=False,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
            timeout=remaining(10.0, deadline),
        ) as client:
            if _runtime_check is not None:
                _runtime_check(deadline)
            opened = stamp()
            with client.stream("GET", target, headers={"Accept-Encoding": "identity"},
                               timeout=remaining(10.0, deadline)) as response:
                remaining(10.0, deadline)
                if response.status_code != 200:
                    raise FixtureCaptureError("FIXTURE_HTTP_STATUS")
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise FixtureCaptureError("FIXTURE_BODY_INVALID")
                try:
                    stream = response.extensions["network_stream"]
                    address = stream.get_extra_info("client_addr")
                    peer = stream.get_extra_info("server_addr")
                    tls_object = stream.get_extra_info("ssl_object")
                    if (not isinstance(address, tuple) or len(address) != 2
                            or address[0] != "127.0.0.1" or type(address[1]) is not int
                            or not 1 <= address[1] <= 65535
                            or peer != ("127.0.0.1", proxy_port) or tls_object is None):
                        raise ValueError()
                    local_port = address[1]
                except Exception:
                    raise FixtureCaptureError("FIXTURE_SOCKET_UNAVAILABLE") from None
                start = stamp()
                payload = snapshot()
                captured = ConnectionSnapshot(run_id, start, stamp(), payload)
                body = bytearray()
                for chunk in response.iter_raw(chunk_size=4096):
                    remaining(10.0, deadline)
                    body.extend(chunk)
                    if len(body) > 64 * 1024:
                        raise FixtureCaptureError("FIXTURE_BODY_TOO_LARGE")
            closed = stamp()
            remaining(10.0, deadline)
        if _runtime_check is not None:
            _runtime_check(deadline)
        request = RequestWindow(run_id, source, target.host, target.port or 443,
                                proxy_port, local_port, opened, closed)
        evidence = match_connection(request, captured, previous_ids=baseline)
        return FixtureCapture(request, captured, evidence, bytes(body), baseline)
    except DeadlineExpired:
        raise FixtureCaptureError("FIXTURE_TIMEOUT") from None
    except httpx.TimeoutException:
        raise FixtureCaptureError("FIXTURE_TIMEOUT") from None
    except httpx.HTTPError:
        raise FixtureCaptureError("FIXTURE_HTTP_FAILED") from None


def collect_bound_fixture_request(
    url: str, *, reader, tls: ssl.SSLContext, source: str,
    previous_ids: frozenset[str] = frozenset(), deadline_seconds: float = 10.0,
    _deadline: float | None = None,
) -> FixtureCapture:
    """Local-only capture with engine-derived run/port and lifecycle guards.

    Cannot override the controller URL, token, PID, run ID or proxy port here.
    It remains a fixture API, not an authorized production probe path.
    """
    from nodelab.connection_reader import BoundConnectionReader
    if type(reader) is not BoundConnectionReader:
        raise FixtureCaptureError("FIXTURE_INPUT_INVALID")
    return collect_fixture_request(
        url, proxy_port=reader.mixed_port, tls=tls, snapshot_reader=reader,
        run_id=reader.run_id, source=source, previous_ids=previous_ids,
        deadline_seconds=deadline_seconds, _runtime_check=reader.assert_current,
        _deadline=_deadline,
    )
