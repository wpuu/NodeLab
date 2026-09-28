"""Orchestration faults with real RunContext/Python child cleanup.

Engine startup/ports and request captures are synthetic here. This does NOT
replace the opt-in real Mihomo gate or the separate real local HTTPS tests.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import time
from uuid import uuid4

import httpx
import pytest

from nodelab import offline_fixture as offline, engine_launch, fixture_capture
from nodelab.fixture_verdict import assess_fixture_pair
from nodelab.mihomo_config import RunContext, PrivateRunError
from nodelab.mihomo_process import process_identity
from nodelab.parser import parse_uri
from nodelab.route_evidence import ConnectionSnapshot, RequestWindow, match_connection
from nodelab.types import PROBE_GATE_OPEN

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="real POSIX private child lifecycle")
BASE = 1_790_553_600 * 10**9


@pytest.fixture
def rig(monkeypatch, tmp_path):
    node = parse_uri(f"trojan://{secrets.token_urlsafe(32)}@127.0.0.1:443?security=tls&sni=fixture.example.invalid")
    root = tmp_path / "private"
    state = {"events": [], "captures": [], "children": [], "deadlines": [], "fault": {}}
    options = dict(exe=Path(sys.executable), mixed_port=12001, controller_port=12002,
                   source_a_url="https://localhost/a", source_b_url="https://127.0.0.1/b",
                   tls=ssl.create_default_context(), root=root)

    @contextmanager
    def session(candidate, **kwargs):
        state["events"].append("enter")
        state["deadlines"].append(kwargs["_deadline"])
        with RunContext(root) as owner:
            state["owner"] = owner
            owner.write_yaml({"password": candidate.secret})
            child = owner.spawn_synthetic_process()
            state["children"].append(child)
            engine = engine_launch.LaunchedEngine(child, "http://127.0.0.1:12002",
                secrets.token_urlsafe(36), 12001, _owner=owner, _identity=process_identity(child.pid))
            try:
                yield engine
            finally:
                state["events"].append("leaving")
        state["events"].append("cleaned")
        if state["fault"].get("cleanup"):
            raise PrivateRunError("SECRET_CLEANUP_FAILED")

    monkeypatch.setattr(offline, "private_engine_session", session)
    monkeypatch.setattr(engine_launch, "listener_owned_by", lambda *a, **kw: "LAUNCH_OK")

    def collect(url, *, reader, source, previous_ids, _deadline, tls):
        state["events"].append(source)
        state["deadlines"].append(_deadline)
        assert state["owner"].active and not state["owner"].closed
        assert (state["owner"].run_dir / "probe.yaml").is_file()
        assert previous_ids == (frozenset() if source == "EXIT_A" else
                                frozenset({state["captures"][0].evidence.connection_id})
                                if state["captures"] else frozenset())
        fault = state["fault"].get(source)
        if isinstance(fault, BaseException):
            raise fault
        offset = 0 if source == "EXIT_A" else 6
        request = RequestWindow(reader.run_id, source, httpx.URL(url).host, 443, reader.mixed_port,
                                45001 + offset, BASE + offset * 10**9, BASE + (offset + 5) * 10**9)
        row = {"id": str(uuid4()), "start": f"2026-09-28T00:00:0{offset + 1}Z",
               "chains": ["NODE", "PROBE"], "rule": "Match", "rulePayload": "",
               "metadata": {"network": "tcp", "type": "HTTPS", "host": "" if request.host == "127.0.0.1" else request.host,
                   "destinationIP": "127.0.0.1" if request.host == "127.0.0.1" else "",
                   "destinationPort": "443", "sourceIP": "127.0.0.1", "inboundIP": "127.0.0.1",
                   "sourcePort": str(request.source_port), "inboundPort": str(reader.mixed_port)}}
        rows = [] if fault == "missing" else [row]
        if fault == "direct":
            row["chains"] = ["DIRECT"]
        if fault == "replay":
            row["id"] = next(iter(previous_ids))
        snapshot = ConnectionSnapshot(reader.run_id, BASE + (offset + 2) * 10**9,
                                      BASE + (offset + 3) * 10**9, {"connections": rows})
        body = b'{"ip":"192.0.2.7"}' if source == "EXIT_A" else b"ip=192.0.2.7\n"
        if fault == "conflict":
            body = b"ip=192.0.2.8\n"
        if fault == "family":
            body = b"ip=2001:db8::7\n"
        if fault == "body":
            body = b"not an IP response"
        capture = fixture_capture.FixtureCapture(request, snapshot,
            match_connection(request, snapshot, previous_ids=previous_ids), body, previous_ids)
        state["captures"].append(capture)
        if fault == "exit":
            child = state["children"][-1]
            child.kill()
            child.wait(timeout=5)
        if fault == "expire":
            monkeypatch.setattr(time, "monotonic", lambda: _deadline + 1)
        return capture

    monkeypatch.setattr(offline, "collect_bound_fixture_request", collect)

    def assess(*args, **kwargs):
        assert state["owner"].closed
        assert all(child.poll() is not None for child in state["children"])
        assert not list(root.iterdir())
        state["events"].append("assess")
        return assess_fixture_pair(*args, **kwargs)

    monkeypatch.setattr(offline, "assess_fixture_pair", assess)

    def run(**overrides):
        return offline.run_offline_fixture(overrides.pop("node", node), **(options | overrides))

    yield run, state, root, node
    for child in state["children"]:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


def clean(state, root):
    assert all(child.poll() is not None for child in state["children"])
    if "owner" in state:
        assert state["owner"].closed
        assert not list(root.iterdir())
    assert PROBE_GATE_OPEN is False


def test_one_session_shared_deadline_and_assessment_only_after_cleanup(rig, capsys):
    run, state, root, _ = rig
    verdict = run()
    assert verdict.status == "PASS" and verdict.candidate_ip == "192.0.2.7"
    assert state["events"] == ["enter", "EXIT_A", "EXIT_B", "leaving", "cleaned", "assess"]
    assert len(set(state["deadlines"])) == 1
    assert len(state["deadlines"]) == 3
    assert len(state["children"]) == 1
    clean(state, root)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("fault,status", [("missing", "PARTIAL"), ("body", "PARTIAL"),
    ("conflict", "CONFLICT"), ("family", "PARTIAL"), ("direct", "FAIL"), ("replay", "FAIL")])
def test_second_source_branches_do_not_publish_first_ip(rig, fault, status):
    run, state, root, _ = rig
    state["fault"]["EXIT_B"] = fault
    verdict = run()
    assert verdict.status == status
    assert verdict.candidate_ip is None
    clean(state, root)


@pytest.mark.parametrize("source", ["EXIT_A", "EXIT_B"])
@pytest.mark.parametrize("code", ["FIXTURE_HTTP_FAILED", "FIXTURE_HTTP_STATUS", "FIXTURE_BODY_INVALID",
                                  "FIXTURE_BODY_TOO_LARGE", "FIXTURE_TIMEOUT"])
def test_soft_source_failures_can_leave_partial_within_total_budget(rig, source, code):
    run, state, root, _ = rig
    state["fault"][source] = fixture_capture.FixtureCaptureError(code)
    verdict = run()
    assert verdict.status == "PARTIAL" and verdict.candidate_ip is None
    assert "EXIT_B" in state["events"]
    clean(state, root)


@pytest.mark.parametrize("code", ["FIXTURE_SNAPSHOT_FAILED", "FIXTURE_BASELINE_INVALID",
                                  "FIXTURE_SOCKET_UNAVAILABLE", "FIXTURE_CLOCK_CHANGED"])
def test_hard_capture_error_aborts_second_source(rig, code):
    run, state, root, _ = rig
    state["fault"]["EXIT_A"] = fixture_capture.FixtureCaptureError(code)
    verdict = run()
    assert verdict.status == "FAIL" and verdict.code == code
    assert "EXIT_B" not in state["events"]
    clean(state, root)


@pytest.mark.parametrize("fault", ["direct", "exit", "expire"])
def test_hard_first_source_runtime_or_deadline_failure_aborts_second(rig, fault):
    run, state, root, _ = rig
    state["fault"]["EXIT_A"] = fault
    verdict = run()
    assert verdict.status == "FAIL" and verdict.candidate_ip is None
    assert "EXIT_B" not in state["events"]
    clean(state, root)


@pytest.mark.parametrize("earlier", [None, "direct", "conflict"])
def test_cleanup_failure_overrides_agreement_route_failure_and_conflict(rig, earlier):
    run, state, root, _ = rig
    state["fault"].update(EXIT_B=earlier, cleanup=True)
    verdict = run()
    assert (verdict.status, verdict.code, verdict.candidate_ip) == ("FAIL", "SECRET_CLEANUP_FAILED", None)
    assert "assess" not in state["events"]
    clean(state, root)


def test_cancel_propagates_only_after_cleanup(rig):
    run, state, root, _ = rig
    state["fault"]["EXIT_B"] = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        run()
    clean(state, root)
    assert "assess" not in state["events"]


def test_unexpected_exception_is_fixed_and_cleaned(rig):
    run, state, root, _ = rig
    sentinel = secrets.token_urlsafe(32)
    state["fault"]["EXIT_A"] = RuntimeError(sentinel)
    verdict = run()
    assert verdict.code == "FIXTURE_EXECUTION_FAILED"
    assert sentinel not in repr(verdict)
    clean(state, root)


@pytest.mark.parametrize("override", [
    {"source_a_url": "https://example.com/"}, {"source_a_url": "http://localhost/"},
    {"source_a_url": "https://secret@localhost/"}, {"source_a_url": "https://localhost/#secret"},
    {"source_b_url": "https://localhost/other"}, {"deadline_seconds": 0}, {"deadline_seconds": True},
])
def test_bad_local_inputs_create_no_session(rig, override):
    run, state, root, _ = rig
    assert run(**override).code == "FIXTURE_INPUT_INVALID"
    assert state["events"] == []
    assert not root.exists()


def test_nonlocal_node_or_insecure_tls_is_rejected_before_session(rig):
    run, state, root, node = rig
    assert run(node=replace(node, entry_host="198.51.100.1")).code == "FIXTURE_INPUT_INVALID"
    assert run(tls=ssl._create_unverified_context()).code == "FIXTURE_INPUT_INVALID"
    assert state["events"] == []
    assert not root.exists()


def test_actual_private_tree_removal_failure_cannot_return_agreement(rig, monkeypatch):
    run, state, root, _ = rig
    try:
        with monkeypatch.context() as patch:
            patch.setattr(RunContext, "_remove_private_tree", lambda owner: False)
            verdict = run()
            assert verdict.code == "SECRET_CLEANUP_FAILED"
            assert verdict.status == "FAIL" and verdict.candidate_ip is None
            assert "assess" not in state["events"]
            assert all(child.poll() is not None for child in state["children"])
            assert not state["owner"].closed
            assert (state["owner"].run_dir / "probe.yaml").exists()
    finally:
        if "owner" in state:
            state["owner"].close()  # restored removal method; do not leave a fake credential behind
    clean(state, root)


def test_unsupported_exception_after_session_started_cannot_hide_runtime_failure(rig):
    from nodelab.engine_config import EngineConfigError
    run, state, root, _ = rig
    state["fault"]["EXIT_A"] = EngineConfigError("UNSUPPORTED_REALITY")
    assert run().status == "FAIL"
    clean(state, root)


def test_late_assessment_cannot_return_success_after_deadline(rig, monkeypatch):
    from nodelab.fixture_verdict import FixtureVerdict
    run, state, root, _ = rig

    def late(*args, **kwargs):
        assert state["owner"].closed
        monkeypatch.setattr(time, "monotonic", lambda: state["deadlines"][0] + 1)
        return FixtureVerdict("PASS", "FIXTURE_AGREEMENT", 2, "192.0.2.7")

    monkeypatch.setattr(offline, "assess_fixture_pair", late)
    verdict = run()
    assert verdict.code == "FIXTURE_TIMEOUT" and verdict.candidate_ip is None
    clean(state, root)
