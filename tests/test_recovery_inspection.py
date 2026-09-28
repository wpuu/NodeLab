"""Read-only, redacted Linux residue inspection is not cleanup authorization."""
import json
import os
from pathlib import Path
import secrets
import sys
from unittest.mock import Mock

import pytest

from nodelab import cli
from nodelab import mihomo_config as private

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux residue inspection")


@pytest.fixture
def owner(tmp_path):
    with private.RunContext(tmp_path / "private") as ctx:
        ctx.write_yaml({"password": secrets.token_urlsafe(32)})
        yield ctx


def test_inspect_pending_record_never_cleans_or_checks_processes(owner, monkeypatch, capsys):
    (owner.run_dir / ".owner-launch.tmp").write_bytes(b'{"state":"launch_pending"}')
    before = {p.name: p.read_bytes() for p in owner.run_dir.iterdir()}
    original_open = os.open

    def readonly(path, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        assert Path(path).name not in {"probe.yaml", ".recover.lock"}
        return original_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(private.os, "open", readonly)
        for name in ("recover_stale_runs",):
            patch.setattr(cli, name, Mock(side_effect=AssertionError("no recovery")))
        for name in ("linux_owner_gone", "process_identity", "terminate_verified_process", "_acquire_lock", "_lock_state"):
            patch.setattr(private, name, Mock(side_effect=AssertionError("no process/lock action")))
        assert cli.main(["recover", "--inspect", "--root", str(owner.root)]) == 0
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert data["mode"] == "RECOVERY_INSPECTION"
    assert data["inspection_status"] == "COMPLETE"
    assert data["rows"] == [{"line_number": 1, "reason": "LAUNCH_PENDING", "lock_state": "PRESENT_UNCHECKED"}]
    for field in ("cleanup_performed", "process_signals_sent", "process_identity_checked", "recovery_authorized"):
        assert data[field] is False
    assert str(owner.root) not in output.out and output.err == ""
    assert {p.name: p.read_bytes() for p in owner.run_dir.iterdir()} == before
    assert not (owner.root / ".recover.lock").exists()


@pytest.mark.parametrize("fault,reason", [
    ("none", "RECOVERY_CHECK_REQUIRED"), ("missing", "MARKER_MISSING"),
    ("invalid", "MARKER_INVALID"), ("staging", "MARKER_STAGING_PRESENT"),
    ("unexpected", "UNEXPECTED_CONTENT"),
])
def test_static_reasons_never_read_yaml_or_authorize_recovery(owner, monkeypatch, capsys, fault, reason):
    from pathlib import Path
    marker = owner.run_dir / ".owner.json"
    if fault == "missing":
        marker.unlink()
    elif fault == "invalid":
        marker.write_bytes(b"invalid synthetic marker")
    elif fault == "staging":
        (owner.run_dir / ".owner-synthetic.tmp").write_bytes(b"partial")
    elif fault == "unexpected":
        (owner.run_dir / secrets.token_hex(16)).write_bytes(b"synthetic")
    original = Path.open

    def opened(path, *args, **kwargs):
        assert path.name != "probe.yaml"
        return original(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", opened)
        assert cli.main(["recover", "--inspect", "--root", str(owner.root)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["rows"][0]["reason"] == reason
    assert report["recovery_authorized"] is False
    assert (owner.run_dir / "probe.yaml").exists()


def test_missing_root_is_not_created(tmp_path, capsys):
    root = tmp_path / "absent"
    assert cli.main(["recover", "--inspect", "--root", str(root)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["rows"] == [] and report["cleanup_performed"] is False
    assert not root.exists()


@pytest.mark.parametrize("args", [[], ["--confirm", "--inspect"], ["--inspect", "--root", "relative"]])
def test_inspection_cli_rejects_ambiguous_or_unsafe_arguments(capsys, args):
    assert cli.main(["recover"] + args) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "INVALID_ARGUMENTS"


def test_linux_only_rejects_other_platform_without_scanning(owner, monkeypatch, capsys):
    from nodelab import recovery_inspection as inspection
    with monkeypatch.context() as patch:
        patch.setattr(inspection.sys, "platform", "unsupported-platform")
        patch.setattr(inspection, "_entries", Mock(side_effect=AssertionError("no scan")))
        assert cli.main(["recover", "--inspect", "--root", str(owner.root)]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "RECOVERY_INSPECTION_UNSUPPORTED"


@pytest.mark.parametrize("location", ["root", "run"])
def test_entry_limit_fails_without_modifying_residue(owner, monkeypatch, capsys, location):
    from nodelab import recovery_inspection as inspection
    parent = owner.root if location == "root" else owner.run_dir
    for i in range(3):
        (parent / f"extra-{i}").write_bytes(b"synthetic")
    with monkeypatch.context() as patch:
        patch.setattr(inspection, "_ENTRY_LIMIT", 4)
        assert cli.main(["recover", "--inspect", "--root", str(owner.root)]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "RECOVERY_INSPECTION_LIMIT"
    assert all((parent / f"extra-{i}").read_bytes() == b"synthetic" for i in range(3))


def test_link_entry_is_not_traversed_and_names_are_not_printed(owner, tmp_path, capsys):
    external = tmp_path / "external"
    external.mkdir()
    sentinel = secrets.token_urlsafe(32)
    (external / "probe.yaml").write_text(sentinel)
    link = owner.root / ("a" * 32)
    link.symlink_to(external, target_is_directory=True)
    try:
        assert cli.main(["recover", "--inspect", "--root", str(owner.root)]) == 0
        output = capsys.readouterr().out
        report = json.loads(output)
        assert "ENTRY_UNSAFE" in [r["reason"] for r in report["rows"]]
        assert sentinel not in output and str(external) not in output and link.name not in output
        assert (external / "probe.yaml").read_text() == sentinel
    finally:
        link.unlink()


def test_lock_files_are_only_described_not_probed_or_removed(owner, capsys):
    recovery = owner.root / ".recover.lock"
    orphan = owner.root / ("b" * 32 + ".lock")
    for path in (recovery, orphan):
        path.write_bytes(b"")
        path.chmod(0o600)
    try:
        assert cli.main(["recover", "--inspect", "--root", str(owner.root)]) == 0
        report = json.loads(capsys.readouterr().out)
        reasons = {r["reason"] for r in report["rows"]}
        assert reasons == {"RECOVERY_LOCK_PRESENT", "LOCK_WITHOUT_DIRECTORY", "RECOVERY_CHECK_REQUIRED"}
        assert all(r["lock_state"] == "PRESENT_UNCHECKED" for r in report["rows"])
        assert recovery.exists() and orphan.exists()
    finally:
        recovery.unlink()
        orphan.unlink()


@pytest.mark.parametrize("fault", ["reason", "lock_state", "line_number", "rows_type"])
def test_inspection_redactor_rejects_untrusted_fields_without_echo(fault):
    from nodelab.redaction import redacted_recovery_inspection
    sentinel = secrets.token_urlsafe(32)
    rows = [{"line_number": 1, "reason": "MARKER_MISSING", "lock_state": "ABSENT"}]
    if fault == "rows_type":
        rows = sentinel
    else:
        rows[0][fault] = sentinel
    report = redacted_recovery_inspection(rows)
    assert report["inspection_status"] == "FAILED"
    assert report["error_code"] == "PUBLIC_SCHEMA_REJECTED"
    assert sentinel not in json.dumps(report)
    assert report["rows"] == [] and report["recovery_authorized"] is False


def test_inspection_redactor_drops_extra_fields_and_never_grants_authority():
    from nodelab.redaction import redacted_recovery_inspection
    sentinel = secrets.token_urlsafe(32)
    report = redacted_recovery_inspection([{
        "line_number": 1, "reason": "RECOVERY_CHECK_REQUIRED", "lock_state": "PRESENT_UNCHECKED",
        "pid": 12345, "secret": sentinel, "path": sentinel,
        "cleanup_performed": True, "recovery_authorized": True,
    }])
    assert sentinel not in json.dumps(report)
    assert set(report["rows"][0]) == {"line_number", "reason", "lock_state"}
    assert report["recovery_authorized"] is report["cleanup_performed"] is False


def test_inspection_io_failure_is_fixed_and_does_not_echo_exception(owner, monkeypatch, capsys):
    from nodelab import recovery_inspection as inspection
    sentinel = secrets.token_urlsafe(32)
    with monkeypatch.context() as patch:
        patch.setattr(inspection.os, "scandir", Mock(side_effect=OSError(sentinel)))
        assert cli.main(["recover", "--inspect", "--root", str(owner.root)]) == 2
    output = capsys.readouterr()
    assert json.loads(output.out)["error_code"] == "RECOVERY_INSPECTION_FAILED"
    assert sentinel not in output.out + output.err
    assert (owner.run_dir / "probe.yaml").is_file()


def test_live_child_is_untouched_by_inspection(owner, capsys):
    child = owner.spawn_synthetic_process()
    before = {p.name: p.read_bytes() for p in owner.run_dir.iterdir()}
    assert cli.main(["recover", "--inspect", "--root", str(owner.root)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["rows"][0] == {"line_number": 1, "reason": "RECOVERY_CHECK_REQUIRED", "lock_state": "PRESENT_UNCHECKED"}
    assert report["process_identity_checked"] is report["process_signals_sent"] is False
    assert child.poll() is None
    assert {p.name: p.read_bytes() for p in owner.run_dir.iterdir()} == before
