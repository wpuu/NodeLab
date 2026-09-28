"""Internal F2 private engine session; not a live-node probe entry point.

One RunContext owns probe.yaml, both sequential children (-t and runtime),
recovery metadata and cleanup. No public verdict is produced. Windows/route
proof gates remain closed; use only synthetic fixtures before acceptance.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import secrets
import subprocess
from collections.abc import Iterator

from nodelab import engine_binary
from nodelab.deadline import DeadlineExpired, after, remaining
from nodelab.engine_config import build_probe_config
from nodelab.engine_launch import EngineLaunchError, LaunchedEngine, start_verified_engine
from nodelab.mihomo_config import RunContext
from nodelab.types import ParsedNode


@contextmanager
def private_engine_session(
    node: ParsedNode, *, exe: Path, mixed_port: int, controller_port: int,
    root: Path | None = None, deadline_seconds: float = 20.0,
    _deadline: float | None = None,
) -> Iterator[LaunchedEngine]:
    """Internal synthetic-fixture session with one cleanup owner.

    The deadline includes config generation, private-file work, pin checking,
    one -t and runtime preflight. Cleanup retains its separate stop budget.
    This is not authority to use real credentials or return a probe PASS.
    """
    try:
        deadline = after(deadline_seconds) if _deadline is None else _deadline
    except ValueError:
        raise EngineLaunchError("INVALID_DEADLINE") from None
    secret = secrets.token_urlsafe(36)
    config = build_probe_config(node, mixed_port=mixed_port,
                                controller_port=controller_port, secret=secret)
    try:
        remaining(30.0, deadline)
        ok, code = engine_binary.verify_pinned_binary(exe, deadline=deadline)
        remaining(30.0, deadline)
        if not ok:
            raise EngineLaunchError("LAUNCH_TIMEOUT" if code == "BINARY_TIMEOUT" else "BINARY_REJECTED")
        with RunContext(root) as owner:
            remaining(30.0, deadline)
            config_path = owner.write_yaml(config)
            remaining(30.0, deadline)
            check = owner._spawn_engine(exe, config_test=True)
            try:
                result = check.wait(timeout=remaining(30.0, deadline))
            except subprocess.TimeoutExpired:
                raise EngineLaunchError("LAUNCH_TIMEOUT") from None
            except DeadlineExpired:
                raise
            except (OSError, subprocess.SubprocessError):
                raise EngineLaunchError("CONFIG_TEST_FAILED") from None
            remaining(30.0, deadline)
            if result != 0:
                raise EngineLaunchError("CONFIG_TEST_FAILED")
            owner._finish_engine_check()
            remaining(30.0, deadline)
            # Reverify the pin immediately before runtime spawn as well; do
            # not cache a prior digest across the -t subprocess boundary.
            engine = start_verified_engine(
                exe=exe, run_dir=owner.run_dir, config_path=config_path,
                mixed_port=mixed_port, controller_port=controller_port,
                secret=secret, _owner=owner, _deadline=deadline,
            )
            yield engine
    except DeadlineExpired:
        raise EngineLaunchError("LAUNCH_TIMEOUT") from None
