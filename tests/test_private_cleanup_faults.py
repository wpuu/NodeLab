"""Actual private files/owned Python child with injected cleanup faults.

No real credentials or Mihomo. Exceptions injected into cleanup are not proof
of arbitrary crash recovery, filesystem atomicity, or Windows acceptance.
"""
import secrets
import sys
import traceback
from unittest.mock import Mock

import pytest

from nodelab.mihomo_config import RunContext, PrivateRunError, _lock_state

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="real POSIX private cleanup faults")


@pytest.fixture
def owner(tmp_path):
    ctx = RunContext(tmp_path / "private")
    ctx.__enter__()
    ctx.write_yaml({"password": secrets.token_urlsafe(32)})
    ctx.spawn_synthetic_process()
    try:
        yield ctx
    finally:
        # Each test's monkeypatch context has exited before this retry.
        ctx.close()


def capture_failure(call):
    # Deliberately catch injected cancellation here so a red test doesn't abort
    # pytest and leave its separately owned child without teardown.
    try:
        call()
    except BaseException as error:
        return error
    return None


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_unexpected_stop_exception_still_removes_yaml_and_reports_fixed_failure(owner, monkeypatch, error_type):
    sentinel = secrets.token_urlsafe(32)
    child = owner.raw_child
    with monkeypatch.context() as patch:
        patch.setattr(owner.process, "close", Mock(side_effect=error_type(sentinel)))
        error = capture_failure(owner.close)
        assert type(error) is PrivateRunError
        assert error.code == "SECRET_CLEANUP_FAILED"
        assert sentinel not in "".join(traceback.format_exception(error))
        assert not (owner.run_dir / "probe.yaml").exists()
        assert (owner.run_dir / ".owner.json").is_file()
        assert child.poll() is None  # do not pretend that failing stop succeeded
        assert owner.closed is False and owner.active is True
        assert _lock_state(owner._lock_path) == "live"
    owner.close()
    assert child.poll() is not None and owner.closed
    assert not owner._lock_path.exists()


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_unexpected_tree_exception_keeps_failed_cleanup_owned_and_retryable(owner, monkeypatch, error_type):
    sentinel = secrets.token_urlsafe(32)
    child = owner.raw_child
    with monkeypatch.context() as patch:
        patch.setattr(owner, "_remove_private_tree", Mock(side_effect=error_type(sentinel)))
        error = capture_failure(owner.close)
        assert type(error) is PrivateRunError
        assert error.code == "SECRET_CLEANUP_FAILED"
        assert sentinel not in "".join(traceback.format_exception(error))
        assert child.poll() is not None
        assert (owner.run_dir / "probe.yaml").exists()
        assert owner.closed is False and _lock_state(owner._lock_path) == "live"
    owner.close()
    assert owner.closed and not owner.run_dir.exists()


@pytest.mark.parametrize("phase", ["_stop_child", "_remove_private_tree"])
def test_truthy_nonboolean_cleanup_result_never_counts_as_confirmation(owner, monkeypatch, phase):
    original = getattr(owner, phase)

    def not_a_confirmation():
        original()
        return 1

    with monkeypatch.context() as patch:
        patch.setattr(owner, phase, not_a_confirmation)
        error = capture_failure(owner.close)
        assert type(error) is PrivateRunError
        assert error.code == "SECRET_CLEANUP_FAILED"
        assert owner.closed is False
        assert _lock_state(owner._lock_path) == "live"
    owner.close()
    assert owner.closed


@pytest.mark.parametrize("after_release", [False, True])
def test_lock_release_exception_is_fixed_and_not_reported_as_closed(owner, monkeypatch, after_release):
    sentinel = secrets.token_urlsafe(32)
    original = owner._drop_lock

    def fail_release():
        if after_release:
            original()
        raise RuntimeError(sentinel)

    with monkeypatch.context() as patch:
        patch.setattr(owner, "_drop_lock", fail_release)
        error = capture_failure(owner.close)
        assert type(error) is PrivateRunError
        assert error.code == "SECRET_CLEANUP_FAILED"
        assert sentinel not in "".join(traceback.format_exception(error))
        assert owner.raw_child.poll() is not None
        assert not owner.run_dir.exists()
        assert owner.closed is False
        assert _lock_state(owner._lock_path) == ("missing" if after_release else "live")
    owner.close()
    assert owner.closed


def test_cleanup_failure_suppresses_earlier_body_error_text(owner, monkeypatch):
    sentinel = secrets.token_urlsafe(32)

    def body():
        try:
            raise RuntimeError(sentinel)
        except RuntimeError:
            owner.__exit__(*sys.exc_info())

    with monkeypatch.context() as patch:
        patch.setattr(owner, "_stop_child", lambda: False)
        error = capture_failure(body)
        assert type(error) is PrivateRunError
        assert error.code == "SECRET_CLEANUP_FAILED"
        assert error.__suppress_context__ is True
        assert sentinel not in "".join(traceback.format_exception(error))
        assert not (owner.run_dir / "probe.yaml").exists()
        assert (owner.run_dir / ".owner.json").is_file()


def test_both_cleanup_faults_still_attempt_both_phases(owner, monkeypatch):
    with monkeypatch.context() as patch:
        stop = Mock(side_effect=RuntimeError(secrets.token_urlsafe(32)))
        remove = Mock(side_effect=KeyboardInterrupt(secrets.token_urlsafe(32)))
        patch.setattr(owner, "_stop_child", stop)
        patch.setattr(owner, "_remove_private_payload", remove)
        error = capture_failure(owner.close)
        assert type(error) is PrivateRunError
        assert error.code == "SECRET_CLEANUP_FAILED"
        stop.assert_called_once_with()
        remove.assert_called_once_with()
        assert owner.closed is False and _lock_state(owner._lock_path) == "live"
        assert owner.raw_child.poll() is None
        assert (owner.run_dir / "probe.yaml").exists()
