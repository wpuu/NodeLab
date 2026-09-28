"""Synthetic evidence candidates only: none of these tests establish routing."""
from copy import deepcopy
from dataclasses import replace
import secrets
from uuid import uuid4

import pytest

from nodelab.route_evidence import (
    ConnectionSnapshot, RequestWindow, match_connection, match_pair, _timestamp_ns,
)
from nodelab.types import PROBE_GATE_OPEN

BASE = 1_790_553_600 * 10**9  # 2026-09-28T00:00:00Z


@pytest.fixture
def sample():
    request = RequestWindow(str(uuid4()), "EXIT_A", "source-a.example.invalid",
                            443, 12001, 45001, BASE, BASE + 5 * 10**9)
    row = {
        "id": str(uuid4()), "start": "2026-09-28T00:00:01.123456789Z",
        "chains": ["NODE", "PROBE"], "rule": "Match", "rulePayload": "",
        "metadata": {
            "network": "tcp", "type": "HTTPS", "host": request.host,
            "destinationPort": "443", "sourceIP": "127.0.0.1", "sourcePort": "45001",
            "inboundIP": "127.0.0.1", "inboundPort": "12001",
        },
    }
    snapshot = ConnectionSnapshot(request.run_id, BASE + 2 * 10**9, BASE + 3 * 10**9,
                                  {"connections": [row]})
    return request, snapshot, row


def test_exact_candidate_matches_without_opening_gate(sample):
    request, snapshot, row = sample
    original = deepcopy(snapshot.payload)
    result = match_connection(request, snapshot)
    assert result.matched and result.connection_id == row["id"]
    assert snapshot.payload == original
    assert PROBE_GATE_OPEN is False


@pytest.mark.parametrize("field,value", [
    ("network", "udp"), ("type", "HTTP"), ("type", "Socks5"),
    ("host", "source-b.example.invalid"), ("destinationPort", "80"),
    ("sourceIP", "192.0.2.1"), ("sourcePort", "45002"),
    ("inboundIP", "0.0.0.0"), ("inboundPort", "12002"),
    ("sourcePort", 45001), ("inboundPort", 12001), ("destinationPort", 443),
    ("sourcePort", True), ("sourcePort", "045001"), ("sourcePort", None),
])
def test_other_request_or_wrong_metadata_type_cannot_match(sample, field, value):
    request, snapshot, row = sample
    row["metadata"][field] = value
    result = match_connection(request, snapshot)
    assert result.code == "EVIDENCE_MISSING"
    assert result.connection_id is None


@pytest.mark.parametrize("chains", [["DIRECT"], ["REJECT"], ["PROBE", "NODE"],
    ["NODE"], ["NODE", "PROBE", "DIRECT"], ["NODE", "other"], [], None, "NODE,PROBE"])
def test_wrong_chain_is_not_node_evidence(sample, chains):
    request, snapshot, row = sample
    row["chains"] = chains
    assert match_connection(request, snapshot).code == "EVIDENCE_ROUTE_MISMATCH"


@pytest.mark.parametrize("field,value", [("rule", "Domain"), ("rule", None),
    ("rule", " MATCH "), ("rulePayload", "example.invalid"), ("rulePayload", None)])
def test_rule_must_match_exact_contract(sample, field, value):
    request, snapshot, row = sample
    row[field] = value
    assert match_connection(request, snapshot).code == "EVIDENCE_ROUTE_MISMATCH"


@pytest.mark.parametrize("stamp", [None, "invalid", "2026-09-28T00:00:01",
    "2026-09-27T23:59:59Z", "2026-09-28T00:00:04Z", "2026-09-28T00:00:01+00:99",
    "2026-09-28T00:00:01.1234567890Z", "2026-02-30T00:00:01Z"])
def test_stale_future_or_invalid_start_is_unproven(sample, stamp):
    request, snapshot, row = sample
    row["start"] = stamp
    assert match_connection(request, snapshot).code == "EVIDENCE_WINDOW_MISMATCH"


def test_nanoseconds_and_timezone_preserved():
    assert _timestamp_ns("2026-09-28T00:00:01.123456789Z") == BASE + 1_123_456_789
    assert _timestamp_ns("2026-09-28T08:00:01.123456789+08:00") == BASE + 1_123_456_789


@pytest.mark.parametrize("field,value", [("source_port", None), ("source_port", True),
    ("source_port", 0), ("mixed_port", 65536), ("port", "443"),
    ("host", "UPPER.example"), ("host", "a..example"), ("host", "-a.example"),
    ("opened_ns", float("nan")), ("run_id", "unknown"), ("source", "EXIT_C")])
def test_bad_local_request_facts_are_rejected(sample, field, value):
    request, snapshot, _ = sample
    assert match_connection(replace(request, **{field: value}), snapshot).code == "EVIDENCE_INPUT_INVALID"


@pytest.mark.parametrize("payload", [None, [], {}, {"connections": {}}, {"connections": [None]}])
def test_invalid_snapshot_has_no_evidence(sample, payload):
    request, snapshot, _ = sample
    assert match_connection(request, replace(snapshot, payload=payload)).code == "EVIDENCE_SNAPSHOT_INVALID"


@pytest.mark.parametrize("rows", [None, []])
def test_empty_snapshot_is_missing_not_history(sample, rows):
    request, snapshot, _ = sample
    assert match_connection(request, replace(snapshot, payload={"connections": rows})).code == "EVIDENCE_MISSING"


def test_foreign_run_and_snapshot_outside_request_window(sample):
    request, snapshot, _ = sample
    assert match_connection(request, replace(snapshot, run_id=str(uuid4()))).code == "EVIDENCE_RUN_MISMATCH"
    assert match_connection(request, replace(snapshot, started_ns=BASE - 1)).code == "EVIDENCE_WINDOW_MISMATCH"
    assert match_connection(request, replace(snapshot, finished_ns=request.closed_ns + 1)).code == "EVIDENCE_WINDOW_MISMATCH"
    assert match_connection(request, replace(snapshot, finished_ns=snapshot.started_ns - 1)).code == "EVIDENCE_WINDOW_MISMATCH"


@pytest.mark.parametrize("reuse_id", [False, True])
def test_ambiguous_connection_never_selects_first_good_chain(sample, reuse_id):
    request, snapshot, row = sample
    other = deepcopy(row)
    if not reuse_id:
        other["id"] = str(uuid4())
    other["chains"] = ["DIRECT"]
    snapshot.payload["connections"].append(other)
    assert match_connection(request, snapshot).code == "EVIDENCE_AMBIGUOUS"


def test_baseline_or_consumed_id_cannot_be_reused(sample):
    request, snapshot, row = sample
    assert match_connection(request, snapshot, previous_ids=frozenset({row["id"]})).code == "EVIDENCE_REPLAYED"


def test_unrelated_direct_connection_does_not_replace_matching_tuple(sample):
    request, snapshot, row = sample
    other = deepcopy(row)
    other["id"] = str(uuid4())
    other["metadata"]["sourcePort"] = "45002"
    other["chains"] = ["DIRECT"]
    snapshot.payload["connections"].append(other)
    assert match_connection(request, snapshot).matched


def pair(sample):
    first, first_snapshot, row = sample
    second = replace(first, source="EXIT_B", host="source-b.example.invalid", source_port=45002,
                     opened_ns=BASE + 6 * 10**9, closed_ns=BASE + 10 * 10**9)
    other = deepcopy(row)
    other.update(id=str(uuid4()), start="2026-09-28T00:00:07Z")
    other["metadata"].update(host=second.host, sourcePort="45002")
    snapshot = ConnectionSnapshot(first.run_id, BASE + 8 * 10**9, BASE + 9 * 10**9,
                                  {"connections": [other]})
    return first, first_snapshot, second, snapshot


def test_distinct_sequential_sources_each_need_their_own_candidate(sample):
    values = pair(sample)
    assert all(result.matched for result in match_pair(*values))
    absent = replace(values[3], payload={"connections": None})
    a, b = match_pair(*values[:3], absent)
    assert a.matched and not b.matched


@pytest.mark.parametrize("case", ["same_id", "same_source", "same_host", "other_run", "other_mixed_port", "overlap"])
def test_pair_cannot_reuse_or_mix_evidence(sample, case):
    first, snap_a, second, snap_b = pair(sample)
    if case == "same_id":
        snap_b.payload["connections"][0]["id"] = snap_a.payload["connections"][0]["id"]
    elif case == "same_source":
        second = replace(second, source="EXIT_A")
    elif case == "same_host":
        second = replace(second, host=first.host)
        snap_b.payload["connections"][0]["metadata"]["host"] = first.host
    elif case == "other_mixed_port":
        second = replace(second, mixed_port=12002)
        snap_b.payload["connections"][0]["metadata"]["inboundPort"] = "12002"
    elif case == "other_run":
        second = replace(second, run_id=str(uuid4()))
        snap_b = replace(snap_b, run_id=second.run_id)
    else:
        first = replace(first, closed_ns=second.opened_ns + 1)
    assert all(result.code == "EVIDENCE_PAIR_INVALID" for result in match_pair(first, snap_a, second, snap_b))


def test_private_repr_contains_no_controller_or_request_data(sample):
    request, snapshot, row = sample
    sentinel = secrets.token_urlsafe(32)
    row["metadata"]["processPath"] = sentinel
    request = replace(request, host=sentinel.lower() + ".invalid")
    assert sentinel not in repr(snapshot)
    assert request.host not in repr(request)
    assert row["id"] not in repr(match_connection(*sample[:2]))


@pytest.mark.parametrize("field,value", [("id", None), ("id", "not-a-uuid"), ("metadata", [])])
def test_malformed_connection_rejects_whole_snapshot(sample, field, value):
    request, snapshot, row = sample
    row[field] = value
    assert match_connection(request, snapshot).code == "EVIDENCE_SNAPSHOT_INVALID"


def test_snapshot_and_history_bounds_fail_closed(sample):
    request, snapshot, row = sample
    oversized = replace(snapshot, payload={"connections": [row] * 4097})
    assert match_connection(request, oversized).code == "EVIDENCE_SNAPSHOT_INVALID"
    assert match_connection(request, snapshot, previous_ids=set()).code == "EVIDENCE_INPUT_INVALID"
    assert match_connection(request, snapshot, previous_ids=frozenset({"unknown"})).code == "EVIDENCE_INPUT_INVALID"


def test_nanosecond_before_request_cannot_round_into_valid_window(sample):
    request, snapshot, row = sample
    request = replace(request, opened_ns=BASE + 1_123_456_790)
    assert match_connection(request, snapshot).code == "EVIDENCE_WINDOW_MISMATCH"
    row["start"] = "2026-09-28T00:00:01.123456790Z"
    assert match_connection(request, snapshot).matched


@pytest.mark.parametrize("metadata_host,destination_ip,matched", [
    ("", "127.0.0.1", True), ("", "127.0.0.2", False),
    ("127.0.0.1", "127.0.0.1", False), ("", None, False),
    ("", "::ffff:127.0.0.1", False), ("unrelated.example", "127.0.0.1", False),
])
def test_literal_target_requires_empty_host_and_exact_destination_ip(sample, metadata_host, destination_ip, matched):
    request, snapshot, row = sample
    request = replace(request, host="127.0.0.1")
    row["metadata"].update(host=metadata_host, destinationIP=destination_ip)
    assert match_connection(request, snapshot).matched is matched
