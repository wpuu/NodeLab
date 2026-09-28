"""F2b: start the pinned engine and prove the runtime is the one we asked for.

This module does NOT decide a probe verdict. `types.PROBE_GATE_OPEN` stays
False and `probe.py` still refuses to publish a positive result; per-request
route proof is F3's job. What this does is turn "the process exited 0" into a
set of checked runtime facts:

  * the executable is the pinned, digest-verified one (P0-02);
  * the control plane answers on loopback and rejects the wrong token
    (P0-04): no token -> 401, wrong token -> 401, run token -> 200;
  * the mixed-port listener exists, is bound to loopback, and is owned by the
    exact child PID we spawned - never matched by process name (P0-05);
  * the running engine is in rule mode, NODE is a supported proxy, PROBE is
    a NODE-only selector, and the sole active rule is MATCH -> PROBE (P0-01).
    These controller snapshots are preflight facts, not per-request proof.

Every failure is a fixed code. Engine stdout/stderr is discarded: it can echo the config path and secret
values. An unread PIPE could fill and deadlock the owned engine.

Measured on the pinned v1.19.31 binary (2026-09-27, synthetic credentials): a
real launch leaves NO extra files in the run directory when
`profile.store-selected` and `profile.store-fake-ip` are false, so the
`_Recovery` directory allowlist `{.owner.json, probe.yaml}` stays valid.
"""

from __future__ import annotations

import json
import math
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4
from typing import Any, Final, TYPE_CHECKING

from nodelab import engine_binary
from nodelab.deadline import DeadlineExpired, after, remaining
from nodelab.engine_config import GROUP_NAME, NODE_NAME
from nodelab.mihomo_process import ProcessIdentity, process_identity, stop_owned_process

if TYPE_CHECKING:
    from nodelab.mihomo_config import RunContext

_LAUNCH_CODES: Final[frozenset[str]] = frozenset({
    "LAUNCH_OK", "INVALID_DEADLINE", "BINARY_REJECTED", "SPAWN_FAILED", "ENGINE_EXITED",
    "CONTROLLER_UNREACHABLE", "CONTROLLER_AUTH_WEAK", "LISTENER_MISSING",
    "LISTENER_NOT_LOOPBACK", "LISTENER_FOREIGN_OWNER", "LISTENER_UNVERIFIABLE",
    "PROXY_OBJECT_MISSING", "GROUP_OBJECT_MISSING", "LAUNCH_TIMEOUT",
    "RUNTIME_MODE_INVALID", "RUNTIME_RULES_INVALID", "PROCESS_STOP_FAILED",
    "CONFIG_TEST_FAILED",
})

_POLL_INTERVAL: Final[float] = 0.1
_HTTP_TIMEOUT: Final[float] = 3.0


class EngineLaunchError(RuntimeError):
    """Fixed code only; no path, no token, no engine output."""

    def __init__(self, code: str = "SPAWN_FAILED") -> None:
        self.code = code if type(code) is str and code in _LAUNCH_CODES else "SPAWN_FAILED"
        super().__init__(self.code)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"EngineLaunchError({self.code})"


@dataclass(frozen=True, repr=False)
class LaunchedEngine:
    """Handle for exactly one verified child. Private: holds the run token."""

    proc: subprocess.Popen
    controller: str
    secret: str
    mixed_port: int
    _owner: RunContext | None = None
    _identity: ProcessIdentity | None = None
    _run_id: str = field(default_factory=lambda: str(uuid4()))

    def __repr__(self) -> str:
        return "LaunchedEngine(<private>)"

    def __str__(self) -> str:
        return self.__repr__()

    def close(self) -> None:
        """Reap only this child; failure must override any earlier success."""
        if self._owner is not None:
            self._owner.close()
        else:
            _stop_engine(self.proc)

    def __enter__(self) -> "LaunchedEngine":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> bool:
        self.close()
        return False


def _stop_engine(proc: subprocess.Popen) -> None:
    try:
        stop_owned_process(proc)
    except BaseException:
        raise EngineLaunchError("PROCESS_STOP_FAILED") from None


# --------------------------------------------------------------------------
# control plane
# --------------------------------------------------------------------------

class _NoControllerRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward a private controller request/token to another endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _controller_open(request: urllib.request.Request, *, deadline: float | None = None):
    # The controller is local IPC, not internet traffic. Ignore HTTP_PROXY,
    # ALL_PROXY and NO_PROXY rather than trusting the caller's environment.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoControllerRedirect(),
    )
    return opener.open(request, timeout=remaining(_HTTP_TIMEOUT, deadline))


def _controller_status(base: str, path: str, token: str | None, *, deadline: float | None = None) -> int | None:
    request = urllib.request.Request(base + path)
    if token is not None:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with _controller_open(request, deadline=deadline) as response:
            remaining(_HTTP_TIMEOUT, deadline)
            return int(response.status)
    except DeadlineExpired:
        raise
    except urllib.error.HTTPError as error:
        error.close()
        return int(error.code)
    except Exception:
        return None


def _controller_object(pairs):
    # json.loads normally keeps the last duplicate key. Never allow one
    # routing/auth/evidence field to silently overwrite another, at any depth.
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("CONTROLLER_JSON_INVALID")
        result[key] = value
    return result


def _controller_bad_number(value):
    raise ValueError("CONTROLLER_JSON_INVALID")


def _controller_float(value):
    number = float(value)
    # parse_constant alone does not catch valid JSON exponent overflow.
    if not math.isfinite(number):
        raise ValueError("CONTROLLER_JSON_INVALID")
    return number


def _controller_json(base: str, path: str, token: str, *, deadline: float | None = None) -> Any:
    request = urllib.request.Request(base + path)
    request.add_header("Authorization", "Bearer " + token)
    try:
        with _controller_open(request, deadline=deadline) as response:
            if response.status != 200:
                return None
            data = bytearray()
            while True:
                remaining(_HTTP_TIMEOUT, deadline)
                chunk = response.read1(min(65536, 1024 * 1024 + 1 - len(data)))
                remaining(_HTTP_TIMEOUT, deadline)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > 1024 * 1024:
                    return None
            return json.loads(data.decode("utf-8", "strict"),
                              object_pairs_hook=_controller_object,
                              parse_constant=_controller_bad_number,
                              parse_float=_controller_float)
    except DeadlineExpired:
        raise
    except urllib.error.HTTPError as error:
        error.close()
        return None
    except Exception:
        return None


def _verify_runtime_routing(configs: Any, proxies: Any, rules: Any) -> None:
    """Validate private v1.19.31 controller snapshots, NOT request route proof.

    API spellings come from tunnel/mode.go, constant/adapters.go,
    adapter/outboundgroup/selector.go and hub/route/rules.go at the pinned tag.
    Unknown/missing fields required for routing fail closed; unrelated engine
    metadata (histories, counters, built-in proxies) is intentionally ignored.
    """
    if not isinstance(configs, dict) or configs.get("mode") != "rule":
        raise EngineLaunchError("RUNTIME_MODE_INVALID")
    if not isinstance(proxies, dict) or not isinstance(proxies.get("proxies"), dict):
        raise EngineLaunchError("PROXY_OBJECT_MISSING")
    table = proxies["proxies"]
    node = table.get(NODE_NAME)
    if not isinstance(node, dict) or node.get("type") not in ("Vless", "Trojan"):
        raise EngineLaunchError("PROXY_OBJECT_MISSING")
    group = table.get(GROUP_NAME)
    if (not isinstance(group, dict) or group.get("type") != "Selector"
            or group.get("now") != NODE_NAME or group.get("all") != [NODE_NAME]):
        raise EngineLaunchError("GROUP_OBJECT_MISSING")
    rows = rules.get("rules") if isinstance(rules, dict) else None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise EngineLaunchError("RUNTIME_RULES_INVALID")
    rule = rows[0]
    if (type(rule.get("index")) is not int or rule["index"] != 0
            or rule.get("type") != "Match" or rule.get("payload") != ""
            or rule.get("proxy") != GROUP_NAME):
        raise EngineLaunchError("RUNTIME_RULES_INVALID")
    # The optional RuleWrapper exposes disabled rules. Do not accept truthy/
    # falsey substitutes or a malformed wrapper as evidence of an active rule.
    if "extra" in rule:
        extra = rule["extra"]
        if not isinstance(extra, dict) or extra.get("disabled") is not False:
            raise EngineLaunchError("RUNTIME_RULES_INVALID")


# --------------------------------------------------------------------------
# listener ownership (never by process name)
# --------------------------------------------------------------------------

_LOOPBACK_HEX = {"0100007F", "00000000000000000000000001000000"}


def _own_socket_inodes(pid: int) -> set[str]:
    inodes: set[str] = set()
    try:
        handles = list((Path("/proc") / str(pid) / "fd").iterdir())
    except OSError:
        return inodes
    for handle in handles:
        try:
            target = os.readlink(handle)
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            inodes.add(match.group(1))
    return inodes


def _linux_listeners(port: int) -> list[tuple[str, str]]:
    """[(local address hex, inode)] for every LISTEN socket on `port`."""
    rows: list[tuple[str, str]] = []
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(table).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A":  # 0A == TCP_LISTEN
                continue
            host_hex, _, port_hex = parts[1].partition(":")
            try:
                if int(port_hex, 16) != port:
                    continue
            except ValueError:
                continue
            rows.append((host_hex.upper(), parts[9]))
    return rows


def _linux_own_listeners(pid: int, port: int) -> tuple[bool, list[str]]:
    """(port has any listener, addresses of the listeners owned by `pid`).

    Only sockets held by `pid` are judged. A sandbox or host port-forwarder
    may legitimately mirror the same port on another address from another
    process; that is not our listener and must not fail our own check. This
    was not hypothetical: the E2B sandbox mirrors every listening port onto a
    link-local address, which made an "all listeners must be loopback" rule
    report LISTENER_NOT_LOOPBACK for a socket bound strictly to 127.0.0.1.
    """
    rows = _linux_listeners(port)
    if not rows:
        return False, []
    ours = _own_socket_inodes(pid)
    return True, [host for host, inode in rows if inode in ours]


_WINDOWS_OWNER_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$port = [int][Environment]::GetEnvironmentVariable('NODELAB_PORT', 'Process')
$rows = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction Stop
$out = @()
foreach ($r in $rows) { $out += ('{0}|{1}' -f $r.LocalAddress, $r.OwningProcess) }
$out -join ';'
"""


def _windows_own_listeners(pid: int, port: int, *, deadline: float | None = None) -> tuple[bool, list[str]]:
    env = {k: v for k, v in os.environ.items()
           if k.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "USERPROFILE", "TEMP"}}
    env["NODELAB_PORT"] = str(port)
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    exe = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    try:
        proc = subprocess.run(
            [str(exe), "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_OWNER_SCRIPT],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
            timeout=remaining(20.0, deadline), text=True, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        raise EngineLaunchError("LISTENER_UNVERIFIABLE") from None
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return False, []
    ours: list[str] = []
    any_row = False
    for row in proc.stdout.strip().split(";"):
        address, _, owner = row.partition("|")
        if not owner.strip().isdigit():
            continue
        any_row = True
        if int(owner.strip()) == pid:
            ours.append(address.strip())
    return any_row, ours


_LOOPBACK_TEXT = {"127.0.0.1", "::1"}


def listener_owned_by(pid: int, port: int, *, deadline: float | None = None) -> str:
    """Fixed code: LAUNCH_OK when `pid` itself listens on `port`, loopback only."""
    try:
        remaining(20.0, deadline)
        if os.name == "nt":
            any_listener, ours = _windows_own_listeners(pid, port, deadline=deadline)
            loopback = all(address in _LOOPBACK_TEXT for address in ours)
        else:
            any_listener, ours = _linux_own_listeners(pid, port)
            loopback = all(address in _LOOPBACK_HEX for address in ours)
    except DeadlineExpired:
        raise
    except EngineLaunchError as error:
        return error.code
    except Exception:
        return "LISTENER_UNVERIFIABLE"
    remaining(20.0, deadline)
    if not any_listener:
        return "LISTENER_MISSING"
    if not ours:
        # The port is taken, but not by the child we spawned.
        return "LISTENER_FOREIGN_OWNER"
    if not loopback:
        return "LISTENER_NOT_LOOPBACK"
    return "LAUNCH_OK"


# --------------------------------------------------------------------------
# launch
# --------------------------------------------------------------------------

def start_verified_engine(
    *,
    exe: Path | str,
    run_dir: Path | str,
    config_path: Path | str,
    mixed_port: int,
    controller_port: int,
    secret: str,
    deadline_seconds: float = 20.0,
    _owner: RunContext | None = None,
    _deadline: float | None = None,
) -> LaunchedEngine:
    """Spawn the pinned engine and assert runtime facts, or raise.

    One monotonic deadline starts before binary verification; blocking helpers
    receive the remaining budget and late results are never accepted. Cleanup
    has its separate bounded stop budget. This is not a hard OS-level wall
    clock guarantee: process creation/filesystem calls cannot be interrupted,
    and urllib socket timeouts apply to blocking I/O, not whole transactions.
    """
    try:
        deadline = after(deadline_seconds) if _deadline is None else _deadline
    except ValueError:
        raise EngineLaunchError("INVALID_DEADLINE") from None

    def check() -> None:
        try:
            remaining(_HTTP_TIMEOUT, deadline)
        except DeadlineExpired:
            raise EngineLaunchError("LAUNCH_TIMEOUT") from None

    def step(function, *args):
        check()
        try:
            result = function(*args, deadline=deadline)
        except DeadlineExpired:
            raise EngineLaunchError("LAUNCH_TIMEOUT") from None
        check()
        return result

    def pause() -> None:
        check()
        time.sleep(max(0.0, min(_POLL_INTERVAL, deadline - time.monotonic())))
        check()

    ok, _code = step(engine_binary.verify_pinned_binary, exe)
    if not ok:
        raise EngineLaunchError("LAUNCH_TIMEOUT" if _code == "BINARY_TIMEOUT" else "BINARY_REJECTED")

    base = f"http://127.0.0.1:{int(controller_port)}"
    check()

    try:
        if _owner is not None:
            if _owner.run_dir != Path(run_dir) or Path(config_path) != Path(run_dir) / "probe.yaml":
                raise EngineLaunchError("SPAWN_FAILED")
            proc = _owner._spawn_engine(Path(exe))
        else:
            proc = subprocess.Popen(
                [str(exe), "-d", str(run_dir), "-f", str(config_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, cwd=str(run_dir),
                close_fds=True,
            )
    except (OSError, ValueError):
        raise EngineLaunchError("SPAWN_FAILED") from None

    try:
        # Retain the OS identity observed at spawn, not one sampled later by
        # a collector after a possible PID reuse. Missing identity means a
        # future bound reader must refuse this handle.
        identity = process_identity(proc.pid)
        # Establish controller ownership BEFORE any HTTP traffic, especially
        # before disclosing the run token. Auth alone does not identify a PID.
        controller_code = "LISTENER_MISSING"
        while True:
            check()
            if proc.poll() is not None:
                raise EngineLaunchError("ENGINE_EXITED")
            controller_code = step(listener_owned_by, proc.pid, int(controller_port))
            if controller_code != "LISTENER_MISSING":
                break
            pause()
        if controller_code != "LAUNCH_OK":
            raise EngineLaunchError(controller_code)

        # 1. control plane reachable. An unauthenticated probe must answer 401
        #    rather than 200; a 200 here means the run token was not applied.
        status = None
        while True:
            check()
            if proc.poll() is not None:
                raise EngineLaunchError("ENGINE_EXITED")
            status = step(_controller_status, base, "/configs", None)
            if status is not None:
                break
            pause()
        if status is None:
            raise EngineLaunchError("CONTROLLER_UNREACHABLE")
        if status != 401:
            raise EngineLaunchError("CONTROLLER_AUTH_WEAK")

        # 2. a wrong token stays rejected, the run token is accepted.
        wrong = secret[:-1] + ("x" if secret[-1] != "x" else "y")
        if step(_controller_status, base, "/configs", wrong) != 401:
            raise EngineLaunchError("CONTROLLER_AUTH_WEAK")
        if step(_controller_status, base, "/configs", secret) != 200:
            raise EngineLaunchError("CONTROLLER_AUTH_WEAK")

        # 3. the data-plane listener belongs to this exact child.
        code = "LISTENER_MISSING"
        while True:
            check()
            if proc.poll() is not None:
                raise EngineLaunchError("ENGINE_EXITED")
            code = step(listener_owned_by, proc.pid, int(mixed_port))
            if code != "LISTENER_MISSING":
                break
            pause()
        if code != "LAUNCH_OK":
            raise EngineLaunchError(code)

        # 4. Query actual routing state: group selection alone does not exclude
        # global/direct mode, fallback members, extra rules or disabled MATCH.
        configs = step(_controller_json, base, "/configs", secret)
        proxies = step(_controller_json, base, "/proxies", secret)
        rules = step(_controller_json, base, "/rules", secret)
        _verify_runtime_routing(configs, proxies, rules)

        if proc.poll() is not None:
            raise EngineLaunchError("ENGINE_EXITED")
        if time.monotonic() >= deadline:
            raise EngineLaunchError("LAUNCH_TIMEOUT")
        return LaunchedEngine(proc=proc, controller=base, secret=secret,
                              mixed_port=int(mixed_port), _owner=_owner, _identity=identity)
    except BaseException:
        # Never leave our own child running after a failed preflight.
        # Cleanup failure outranks the preflight error/cancellation. Never
        # hide an unconfirmed orphan behind an ordinary launch failure.
        if _owner is None:
            _stop_engine(proc)
        # Otherwise the session's RunContext is the sole cleanup owner.
        raise


def probe_socket(engine: LaunchedEngine, timeout: float = 2.0) -> bool:
    """TCP reachability of the mixed port. NOT evidence of routing."""
    try:
        with socket.create_connection(("127.0.0.1", engine.mixed_port), timeout=timeout):
            return True
    except OSError:
        return False
