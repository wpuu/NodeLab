"""Synthetic candidate verdicts only; public serializer must remain closed."""
from dataclasses import replace
import json
from uuid import uuid4

import pytest

from nodelab.fixture_capture import FixtureCapture
from nodelab.fixture_verdict import assess_fixture_pair
from nodelab.probe import RouteObservation, decide_probe_status
from nodelab.redaction import redacted_result_dict
from nodelab.route_evidence import RequestWindow, ConnectionSnapshot, EvidenceMatch, match_connection
from nodelab.types import PROBE_GATE_OPEN

BASE = 1_790_553_600 * 10**9


@pytest.fixture
def captures():
    run = str(uuid4())
    result = []
    for index, source in enumerate(("EXIT_A", "EXIT_B")):
        start = index * 6
        request = RequestWindow(run, source, f"source-{index}.example.invalid", 443, 12001,
                                45001 + index, BASE + start * 10**9, BASE + (start + 5) * 10**9)
        row = {"id": str(uuid4()), "start": f"2026-09-28T00:00:0{start + 1}Z",
               "chains": ["NODE", "PROBE"], "rule": "Match", "rulePayload": "",
               "metadata": {"network": "tcp", "type": "HTTPS", "host": request.host,
                   "destinationPort": "443", "sourceIP": "127.0.0.1", "inboundIP": "127.0.0.1",
                   "sourcePort": str(request.source_port), "inboundPort": "12001"}}
        snapshot = ConnectionSnapshot(run, BASE + (start + 2) * 10**9, BASE + (start + 3) * 10**9,
                                      {"connections": [row]})
        body = b'{"ip":"192.0.2.7"}' if index == 0 else b"ip=192.0.2.7\n"
        result.append(FixtureCapture(request, snapshot, match_connection(request, snapshot), body))
    return result


def assess(first, second, **kwargs):
    return assess_fixture_pair(first, second, runtime_verified=True, cleanup_ok=True, **kwargs)


def test_fixture_agreement_is_private_and_public_output_stays_closed(captures):
    verdict = assess(*captures)
    assert (verdict.status, verdict.candidate_ip, verdict.source_count) == ("PASS", "192.0.2.7", 2)
    assert repr(verdict) == "FixtureVerdict(<private>)"
    assert PROBE_GATE_OPEN is False
    public = redacted_result_dict({"probe_status": verdict.status, "confirmed_exit_ip": verdict.candidate_ip})
    assert public["probe_status"] == "FAIL"
    assert "192.0.2.7" not in json.dumps(public)
    assert redacted_result_dict(verdict)["probe_status"] == "FAIL"


@pytest.mark.parametrize("body,status", [(b"ip=192.0.2.8\n", "CONFLICT"),
    (b"ip=2001:db8::7\n", "PARTIAL"), (b"ip=not-an-ip\n", "PARTIAL"),
    (b"ip=127.0.0.1\n", "PARTIAL"), (b"ip=192.0.2.7\nip=192.0.2.7\n", "PARTIAL")])
def test_disagreement_family_and_invalid_body_never_select_first_ip(captures, body, status):
    first, second = captures
    verdict = assess(first, replace(second, body=body))
    assert verdict.status == status
    assert verdict.candidate_ip is None


def test_missing_source_or_missing_snapshot_only_allows_partial(captures):
    first, second = captures
    assert assess(first, None).status == "PARTIAL"
    assert assess(None, second).status == "PARTIAL"
    assert assess(None, None).status == "FAIL"
    second.snapshot.payload["connections"] = None
    assert assess(first, second).status == "PARTIAL"
    first.snapshot.payload["connections"] = None
    assert assess(first, second).status == "FAIL"


@pytest.mark.parametrize("fault", ["direct", "reject", "replay", "duplicate", "foreign_snapshot", "malformed"])
def test_hard_evidence_failure_overrides_good_other_source_and_invalid_body(captures, fault):
    first, second = captures
    row = second.snapshot.payload["connections"][0]
    if fault in ("direct", "reject"):
        row["chains"] = [fault.upper()]
    elif fault == "replay":
        second = replace(second, previous_ids=frozenset({row["id"]}))
    elif fault == "duplicate":
        second.snapshot.payload["connections"].append(row)
    elif fault == "foreign_snapshot":
        second = replace(second, snapshot=replace(second.snapshot, run_id=str(uuid4())))
    else:
        second.snapshot.payload["connections"] = [{}]
    second = replace(second, body=b"invalid body")
    verdict = assess(first, second)
    assert verdict.status == "FAIL"
    assert verdict.candidate_ip is None


@pytest.mark.parametrize("fault", ["source", "run", "mixed", "overlap", "same_id", "same_host"])
def test_pair_context_is_validated_independently_of_body(captures, fault):
    first, second = captures
    row = second.snapshot.payload["connections"][0]
    if fault == "source":
        second = replace(second, request=replace(second.request, source="EXIT_A"))
    elif fault == "run":
        run = str(uuid4())
        second = replace(second, request=replace(second.request, run_id=run),
                         snapshot=replace(second.snapshot, run_id=run))
    elif fault == "mixed":
        second = replace(second, request=replace(second.request, mixed_port=12002))
        row["metadata"]["inboundPort"] = "12002"
    elif fault == "overlap":
        first = replace(first, request=replace(first.request, closed_ns=second.request.opened_ns + 1))
    elif fault == "same_id":
        row["id"] = first.snapshot.payload["connections"][0]["id"]
    else:
        second = replace(second, request=replace(second.request, host=first.request.host))
        row["metadata"]["host"] = first.request.host
    verdict = assess(first, second)
    assert verdict.status == "FAIL"
    assert verdict.candidate_ip is None


def test_cross_run_is_hard_even_when_other_snapshot_is_missing(captures):
    first, second = captures
    second = replace(second, request=replace(second.request, run_id=str(uuid4())),
                     snapshot=replace(second.snapshot, payload={"connections": None}))
    assert assess(first, second).code == "EVIDENCE_PAIR_INVALID"


def test_cached_match_cannot_override_original_snapshot_or_history(captures):
    first, second = captures
    second = replace(second, evidence=EvidenceMatch("EVIDENCE_MATCHED", str(uuid4())))
    row = second.snapshot.payload["connections"][0]
    replay = replace(second, previous_ids=frozenset({row["id"]}))
    assert assess(first, replay).code == "EVIDENCE_REPLAYED"
    row["chains"] = ["DIRECT"]
    assert assess(first, second).code == "EVIDENCE_ROUTE_MISMATCH"


@pytest.mark.parametrize("runtime,cleanup,hard", [(False, True, False), (True, False, False),
    (True, True, True), (True, 1, False), (1, True, False), (True, True, None)])
def test_runtime_cleanup_and_hard_failure_take_priority(captures, runtime, cleanup, hard):
    verdict = assess_fixture_pair(*captures, runtime_verified=runtime, cleanup_ok=cleanup, hard_failure=hard)
    assert verdict.status == "FAIL"
    assert verdict.candidate_ip is None


def test_global_mode_rejects_documentation_but_accepts_global_agreement(captures):
    assert assess(*captures, fixture_addresses=False).status == "FAIL"
    a, b = captures
    verdict = assess(replace(a, body=b'{"ip":"8.8.8.8"}'), replace(b, body=b"ip=8.8.8.8\n"),
                     fixture_addresses=False)
    assert verdict.status == "PASS"  # still only a pure candidate, not product PASS
    assert verdict.candidate_ip == "8.8.8.8"


def test_unsupported_is_pre_network_and_never_hides_cleanup_failure():
    assert decide_probe_status(None, None, unsupported=True, runtime_verified=False,
                               cleanup_ok=True) == ("UNSUPPORTED", None)
    assert decide_probe_status(None, None, unsupported=True, runtime_verified=False,
                               cleanup_ok=False) == ("FAIL", None)
    assert decide_probe_status(None, None, unsupported=True, runtime_verified=False,
                               cleanup_ok=True, hard_failure=True) == ("FAIL", None)
    observation = RouteObservation("8.8.8.8", True, True, True)
    assert decide_probe_status(observation, None, unsupported=True, runtime_verified=True,
                               cleanup_ok=True) == ("FAIL", None)
