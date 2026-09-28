"""Private F3 fixture assessment, NOT a production verdict authority.

Captures must come from the local collector. Python dataclasses are not an
attestation boundary; hand-built objects only serve synthetic unit tests.
All product CLI/output gates remain closed even when this candidate says PASS.
"""
from __future__ import annotations

from dataclasses import dataclass

from nodelab.exit_response import ExitResponseError, parse_exit_response
from nodelab.fixture_capture import FixtureCapture
from nodelab.probe import RouteObservation, decide_probe_status
from nodelab.route_evidence import RequestWindow, match_connection, match_pair


@dataclass(frozen=True, slots=True, repr=False)
class FixtureVerdict:
    status: str
    code: str
    source_count: int = 0
    candidate_ip: str | None = None  # private; never a confirmed/published exit

    def __repr__(self):
        return "FixtureVerdict(<private>)"


def assess_fixture_pair(
    first: FixtureCapture | None, second: FixtureCapture | None, *,
    runtime_verified: bool, cleanup_ok: bool, hard_failure: bool = False,
    fixture_addresses: bool = True,
) -> FixtureVerdict:
    """Recompute evidence and parse original bodies before applying priorities.

    Missing capture/evidence or an invalid source body can leave one useful
    observation. Wrong route/run, replay, ambiguity or malformed evidence is
    conservatively a hard failure. Cached EvidenceMatch is never authoritative.
    Call only AFTER the owning session has confirmed cleanup, not inside it.
    """
    if cleanup_ok is not True:
        return FixtureVerdict("FAIL", "SECRET_CLEANUP_FAILED")
    if runtime_verified is not True or type(hard_failure) is not bool or hard_failure:
        return FixtureVerdict("FAIL", "RUNTIME_MISMATCH")
    if type(fixture_addresses) is not bool:
        return FixtureVerdict("FAIL", "FIXTURE_INPUT_INVALID")
    for capture, expected in ((first, "EXIT_A"), (second, "EXIT_B")):
        if capture is not None and (
            type(capture) is not FixtureCapture or type(capture.request) is not RequestWindow
            or capture.request.source != expected
        ):
            return FixtureVerdict("FAIL", "EVIDENCE_PAIR_INVALID")
    if first is not None and second is not None:
        pairing = match_pair(first.request, first.snapshot, second.request, second.snapshot)
        if any(item.code == "EVIDENCE_PAIR_INVALID" for item in pairing):
            return FixtureVerdict("FAIL", "EVIDENCE_PAIR_INVALID")

    observations = []
    count = 0
    for capture in (first, second):
        if capture is None:
            observations.append(None)
            continue
        evidence = match_connection(capture.request, capture.snapshot, previous_ids=capture.previous_ids)
        if evidence.code not in ("EVIDENCE_MATCHED", "EVIDENCE_MISSING"):
            # Never let a malformed body or a valid other source mask DIRECT,
            # another run's snapshot, reused IDs, or ambiguous associations.
            return FixtureVerdict("FAIL", evidence.code)
        if not evidence.matched:
            observations.append(None)
            continue
        try:
            parsed = parse_exit_response(capture.request.source, capture.body,
                                         fixture_addresses=fixture_addresses)
        except ExitResponseError:
            observations.append(None)
            continue
        observations.append(RouteObservation(str(parsed.address), route_verified=True,
                                             tls_verified=True, http_ok=True))
        count += 1
    status, candidate = decide_probe_status(*observations, runtime_verified=True, cleanup_ok=True,
                                            production=not fixture_addresses)
    code = {"PASS": "FIXTURE_AGREEMENT", "CONFLICT": "EXIT_CONFLICT",
            "PARTIAL": "EXIT_INCOMPLETE", "FAIL": "EXIT_UNPROVEN"}[status]
    return FixtureVerdict(status, code, count, candidate if status == "PASS" else None)
