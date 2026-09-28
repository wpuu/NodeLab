"""One internal local-only F3 experiment; no CLI integration or live-node gate.

This composes session, bound reader, captures and private assessment. A result
is a fixture candidate, never authority to publish a production exit address.
"""
from __future__ import annotations

from pathlib import Path
import ssl

import httpx

from nodelab.connection_reader import BoundConnectionReader, ConnectionReaderError
from nodelab.deadline import DeadlineExpired, after, remaining
from nodelab.engine_config import EngineConfigError
from nodelab.engine_launch import EngineLaunchError
from nodelab.engine_session import private_engine_session
from nodelab.fixture_capture import collect_bound_fixture_request, FixtureCaptureError, _baseline_ids
from nodelab.fixture_verdict import FixtureVerdict, assess_fixture_pair
from nodelab.mihomo_config import PrivateRunError
from nodelab.route_evidence import match_connection
from nodelab.types import ParsedNode

_SOFT_SOURCE_ERRORS = frozenset({
    "FIXTURE_HTTP_STATUS", "FIXTURE_HTTP_FAILED", "FIXTURE_BODY_INVALID",
    "FIXTURE_BODY_TOO_LARGE", "FIXTURE_TIMEOUT",
})


def _local_inputs(node, first_url, second_url, tls):
    if type(node) is not ParsedNode or node.entry_host != "127.0.0.1":
        return False
    if (not isinstance(tls, ssl.SSLContext) or tls.verify_mode != ssl.CERT_REQUIRED
            or tls.check_hostname is not True):
        return False
    targets = []
    for raw in (first_url, second_url):
        if type(raw) is not str:
            return False
        target = httpx.URL(raw)
        if (target.scheme != "https" or target.host not in ("localhost", "127.0.0.1")
                or target.userinfo or target.fragment
                or (target.port is not None and not 1 <= target.port <= 65535)):
            return False
        targets.append(target)
    return targets[0].host != targets[1].host


def run_offline_fixture(
    node: ParsedNode, *, exe: Path, mixed_port: int, controller_port: int,
    source_a_url: str, source_b_url: str, tls: ssl.SSLContext,
    root: Path | None = None, deadline_seconds: float = 45.0,
) -> FixtureVerdict:
    """Two sequential local requests, one budget, verdict only after cleanup.

    Soft per-source HTTP/body errors may leave PARTIAL if the other source is
    sound; a total deadline, reader/runtime, or cleanup failure is always FAIL.
    No retries, production endpoints, result files, or user credentials are
    requested. Cancellation propagates after the session's cleanup runs.
    """
    try:
        deadline = after(deadline_seconds)
        if not _local_inputs(node, source_a_url, source_b_url, tls):
            return FixtureVerdict("FAIL", "FIXTURE_INPUT_INVALID")
    except (ValueError, TypeError, httpx.InvalidURL):
        return FixtureVerdict("FAIL", "FIXTURE_INPUT_INVALID")

    captures = []
    previous_ids = frozenset()
    entered = False
    try:
        remaining(45.0, deadline)
        with private_engine_session(
            node, exe=exe, mixed_port=mixed_port, controller_port=controller_port,
            root=root, _deadline=deadline,
        ) as engine:
            entered = True
            reader = BoundConnectionReader(engine)
            for source, url in (("EXIT_A", source_a_url), ("EXIT_B", source_b_url)):
                remaining(45.0, deadline)
                reader.assert_current(deadline)
                try:
                    capture = collect_bound_fixture_request(
                        url, reader=reader, tls=tls, source=source,
                        previous_ids=previous_ids, _deadline=deadline,
                    )
                except FixtureCaptureError as error:
                    remaining(45.0, deadline)
                    if str(error) not in _SOFT_SOURCE_ERRORS:
                        raise
                    # A transport failure is not evidence the engine stayed
                    # alive or kept its listeners. Recheck before continuing.
                    reader.assert_current(deadline)
                    captures.append(None)
                    continue
                remaining(45.0, deadline)
                evidence = match_connection(capture.request, capture.snapshot,
                                            previous_ids=capture.previous_ids)
                if evidence.code not in ("EVIDENCE_MATCHED", "EVIDENCE_MISSING"):
                    # Return only AFTER __exit__, so cleanup failure can still
                    # override this evidence failure. Do not launch source B.
                    failure = FixtureVerdict("FAIL", evidence.code)
                    break
                previous_ids |= capture.previous_ids | _baseline_ids(capture.snapshot.payload)
                captures.append(capture)
            else:
                failure = None
            remaining(45.0, deadline)
            reader.assert_current(deadline)
        # The session is the only cleanup owner; no guessed cleanup_ok=True
        # while the engine/YAML are still active.
        owner = engine._owner
        if owner is None or owner.closed is not True or engine.proc.poll() is None:
            return FixtureVerdict("FAIL", "SECRET_CLEANUP_FAILED")
        # Cleanup retains its independent budget but cannot turn a late run
        # into agreement after the total deadline has already elapsed.
        remaining(45.0, deadline)
        if failure is not None:
            return failure
        verdict = assess_fixture_pair(*captures, runtime_verified=True, cleanup_ok=True)
        remaining(45.0, deadline)
        return verdict
    except DeadlineExpired:
        return FixtureVerdict("FAIL", "FIXTURE_TIMEOUT")
    except PrivateRunError as error:
        return FixtureVerdict("FAIL", error.code)
    except EngineConfigError as error:
        return FixtureVerdict("UNSUPPORTED" if not entered and error.code.startswith("UNSUPPORTED_") else "FAIL", error.code)
    except EngineLaunchError as error:
        return FixtureVerdict("FAIL", error.code)
    except (ConnectionReaderError, FixtureCaptureError) as error:
        return FixtureVerdict("FAIL", str(error))  # constructors restrict to fixed codes
    except Exception:
        return FixtureVerdict("FAIL", "FIXTURE_EXECUTION_FAILED")
