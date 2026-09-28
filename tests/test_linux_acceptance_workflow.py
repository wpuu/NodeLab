"""Static CI guardrails, not execution or real-engine acceptance evidence."""
from pathlib import Path
import re

import pytest
import yaml

PATH = Path(__file__).resolve().parents[1] / ".github/workflows/linux-local-acceptance.yml"
WORKFLOW = yaml.safe_load(PATH.read_text())
JOB = WORKFLOW["jobs"]["local-acceptance"]
STEPS = JOB["steps"]


def test_workflow_is_explicit_opt_in_without_inputs_or_write_permissions():
    assert WORKFLOW["on"] == {
        "workflow_dispatch": None,
        "pull_request": {"branches": ["main"], "types": ["labeled", "synchronize", "reopened"]},
    }
    assert JOB["if"] == (
        "github.event_name == 'workflow_dispatch' || "
        "(github.event.pull_request.head.repo.full_name == github.repository &&\n"
        " contains(github.event.pull_request.labels.*.name, 'run-local-acceptance'))"
    )
    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert WORKFLOW["concurrency"]["cancel-in-progress"] is False
    assert JOB["runs-on"] == "ubuntu-24.04"
    assert "secrets." not in PATH.read_text()


def test_actions_are_commit_pinned_and_checkout_does_not_persist_token():
    actions = [step for step in STEPS if "uses" in step]
    assert {step["uses"] for step in actions} == {
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    }
    assert len(actions) == 3
    assert "ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION" not in PATH.read_text()
    for step in actions:
        assert re.fullmatch(r"actions/(checkout|setup-python|upload-artifact)@[0-9a-f]{40}", step["uses"])
    checkout = next(step for step in actions if step["uses"].startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    assert not checkout["with"].get("allow-unsafe-pr-checkout", False)
    python = next(step for step in actions if step["uses"].startswith("actions/setup-python@"))
    assert python["with"]["python-version"] == "3.12"


def test_preparation_uses_https_fixed_resource_and_offline_verifier():
    command = next(step["run"] for step in STEPS if step.get("id") == "prepare")
    assert "--proto '=https' --proto-redir '=https'" in command
    assert "--fail" in command and "--max-time 180" in command
    assert "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.31/mihomo-linux-amd64-compatible-v1.19.31.gz" in command
    assert "python scripts/prepare_mihomo_linux.py" in command
    assert ' --destination "$PWD/tools/mihomo/mihomo"' in command
    assert "umask 077" in command
    assert "--insecure" not in command and "curl -k" not in command


@pytest.mark.parametrize("suite", ["session", "trojan-tcp", "vless-tcp", "full"])
def test_each_gate_runs_without_masking_failure_and_has_exact_report(suite):
    matches = [step for step in STEPS if f"--suite {suite} " in step.get("run", "")]
    assert len(matches) == 1
    step = matches[0]
    assert step["if"] == "${{ !cancelled() && steps.prepare.outcome == 'success' && steps.dependencies.outcome == 'success' }}"
    assert f"| tee tools/acceptance-report/{suite}.json" in step["run"]
    assert "scripts/f2_session_gate.py" in step["run"]
    assert ' --exe "$PWD/tools/mihomo/mihomo"' in step["run"]
    # Explicit bash in Actions supplies -e -o pipefail; tee cannot hide exit 2.
    assert WORKFLOW["defaults"]["run"]["shell"] == "bash"
    assert "continue-on-error" not in JOB
    assert all("continue-on-error" not in entry for entry in STEPS)
    assert "|| true" not in step["run"]


def test_artifact_upload_is_explicit_allowlist_not_logs_or_runtime():
    upload = next(step for step in STEPS if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert set(upload["with"]["path"].splitlines()) == {
        f"tools/acceptance-report/{name}.json"
        for name in ("preparation", "session", "trojan-tcp", "vless-tcp", "full")
    }
    assert upload["with"]["retention-days"] == 7
    assert "!cancelled()" in upload["if"]
    assert upload["with"]["include-hidden-files"] is False
    assert upload["with"]["archive"] is True


def test_annotations_only_publish_known_fixed_field_reports():
    step = next(step for step in STEPS if step["name"] == "Publish fixed-field check annotations")
    assert "for report in preparation session trojan-tcp vless-tcp full; do" in step["run"]
    assert 'path="tools/acceptance-report/$report.json"' in step["run"]
    assert "::notice title=Local acceptance" in step["run"]
    assert "!cancelled()" in step["if"]
