"""F3 private controller reader bound to one launched child, not an arbitrary URL.

Checks are fail-closed pre/post observations, NOT atomic socket-to-PID attestation.
This does not open the product probe gate or prove a node protocol handshake.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from nodelab import engine_launch, mihomo_process
from nodelab.deadline import DeadlineExpired, remaining
from nodelab.route_evidence import _uuid

_CODES = frozenset({
    "READER_BINDING_INVALID", "READER_ENGINE_EXITED", "READER_IDENTITY_CHANGED",
    "READER_LISTENER_UNTRUSTED", "READER_AUTH_FAILED", "READER_SNAPSHOT_INVALID",
    "READER_CHECK_FAILED",
})
_CONTROLLER = re.compile(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_FINGERPRINT = re.compile(r"[0-9a-f]{32}\Z")


class ConnectionReaderError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code if type(code) is str and code in _CODES else "READER_CHECK_FAILED")


def _complete_identity(value):
    return (type(value) is mihomo_process.ProcessIdentity
            and type(value.pid) is int and value.pid > 0
            and type(value.create_time) is int and value.create_time > 0
            and type(value.exe_fingerprint) is str
            and _FINGERPRINT.fullmatch(value.exe_fingerprint) is not None)


@dataclass(frozen=True, slots=True, repr=False, init=False)
class BoundConnectionReader:
    _engine: engine_launch.LaunchedEngine
    _controller_port: int

    def __init__(self, engine: engine_launch.LaunchedEngine):
        if type(engine) is not engine_launch.LaunchedEngine:
            raise ConnectionReaderError("READER_BINDING_INVALID")
        endpoint = _CONTROLLER.fullmatch(engine.controller) if type(engine.controller) is str else None
        if (endpoint is None or not 1 <= int(endpoint[1]) <= 65535
                or type(engine.mixed_port) is not int or not 1 <= engine.mixed_port <= 65535
                or int(endpoint[1]) == engine.mixed_port
                or type(engine.secret) is not str or not _TOKEN.fullmatch(engine.secret)
                or not _uuid(engine._run_id) or not _complete_identity(engine._identity)
                or engine._identity.pid != engine.proc.pid):
            raise ConnectionReaderError("READER_BINDING_INVALID")
        object.__setattr__(self, "_engine", engine)
        object.__setattr__(self, "_controller_port", int(endpoint[1]))

    def __repr__(self):
        return "BoundConnectionReader(<private>)"

    @property
    def run_id(self):
        return self._engine._run_id

    @property
    def mixed_port(self):
        return self._engine.mixed_port

    def assert_current(self, deadline: float) -> None:
        """Both listeners and exact creation/executable identity, never by name."""
        try:
            self._assert_current(deadline)
        except (ConnectionReaderError, DeadlineExpired):
            raise
        except Exception:
            raise ConnectionReaderError("READER_CHECK_FAILED") from None

    def _assert_current(self, deadline: float) -> None:
        remaining(3.0, deadline)
        engine = self._engine
        try:
            if engine.proc.poll() is not None:
                raise ConnectionReaderError("READER_ENGINE_EXITED")
            owner = engine._owner
            if owner is not None and (owner.closed or not owner.active or owner.raw_child is not engine.proc):
                raise ConnectionReaderError("READER_BINDING_INVALID")
            current = mihomo_process.process_identity(engine.proc.pid)
            # Deliberately NOT ProcessIdentity.matches: recovery permits a
            # missing executable fingerprint, but evidence collection may not.
            if not _complete_identity(current) or current != engine._identity:
                raise ConnectionReaderError("READER_IDENTITY_CHANGED")
        except ConnectionReaderError:
            raise
        except Exception:
            raise ConnectionReaderError("READER_CHECK_FAILED") from None
        for port in (self._controller_port, engine.mixed_port):
            remaining(3.0, deadline)
            code = engine_launch.listener_owned_by(engine.proc.pid, port, deadline=deadline)
            remaining(3.0, deadline)
            if code != "LAUNCH_OK":
                raise ConnectionReaderError("READER_LISTENER_UNTRUSTED")
        # Reject death/reuse occurring during the port queries too.
        if engine.proc.poll() is not None:
            raise ConnectionReaderError("READER_ENGINE_EXITED")
        current = mihomo_process.process_identity(engine.proc.pid)
        if not _complete_identity(current) or current != engine._identity:
            raise ConnectionReaderError("READER_IDENTITY_CHANGED")
        remaining(3.0, deadline)

    def __call__(self, deadline: float) -> dict:
        try:
            return self._read(deadline)
        except (ConnectionReaderError, DeadlineExpired):
            raise
        except Exception:
            raise ConnectionReaderError("READER_CHECK_FAILED") from None

    def _read(self, deadline: float) -> dict:
        """Recheck authentication and child ownership around every HTTP call.

        Only fixed /connections is accessible. The token is never sent before
        listener checks. JSON is size-bounded, no proxy env/redirects, HTTP 200
        required. Snapshot acceptance is separate from request route matching.
        """
        engine = self._engine
        wrong = engine.secret[:-1] + ("x" if engine.secret[-1] != "x" else "y")
        for token in (None, wrong):
            self.assert_current(deadline)
            status = engine_launch._controller_status(engine.controller, "/connections", token, deadline=deadline)
            self.assert_current(deadline)
            if status != 401:
                raise ConnectionReaderError("READER_AUTH_FAILED")
        self.assert_current(deadline)
        payload = engine_launch._controller_json(engine.controller, "/connections", engine.secret, deadline=deadline)
        self.assert_current(deadline)
        if type(payload) is not dict or "connections" not in payload:
            raise ConnectionReaderError("READER_SNAPSHOT_INVALID")
        rows = payload["connections"]
        if rows is None:
            return payload
        if type(rows) is not list or len(rows) > 4096:
            raise ConnectionReaderError("READER_SNAPSHOT_INVALID")
        seen = set()
        for row in rows:
            if (type(row) is not dict or not _uuid(row.get("id"))
                    or type(row.get("metadata")) is not dict or row["id"] in seen):
                raise ConnectionReaderError("READER_SNAPSHOT_INVALID")
            seen.add(row["id"])
        return payload
