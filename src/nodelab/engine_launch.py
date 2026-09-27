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
  * the proxy object and selector group the config declared actually exist in
    the running engine (P0-01).

Every failure is a fixed code. Engine stdout/stderr is captured into a private
buffer and never returned: it echoes the config path and can quote offending
values.

Measured on the pinned v1.19.31 binary (2026-09-27, synthetic credentials): a
real launch leaves NO extra files in the run directory when
`profile.store-selected` and `profile.store-fake-ip` are false, so the
`_Recovery` directory allowlist `{.owner.json, probe.yaml}` stays valid.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from nodelab import engine_binary
from nodelab.engine_config import GROUP_NAME, NODE_NAME

_LAUNCH_CODES: Final[frozenset[str]] = frozenset({
    "LAUNCH_OK", "BINARY_REJECTED", "SPAWN_FAILED", "ENGINE_EXITED",
    "CONTROLLER_UNREACHABLE", "CONTROLLER_AUTH_WEAK", "LISTENER_MISSING",
    "LISTENER_NOT_LOOPBACK", "LISTENER_FOREIGN_OWNER", "LISTENER_UNVERIFIABLE",
    "PROXY_OBJECT_MISSING", "GROUP_OBJECT_MISSING", "LAUNCH_TIMEOUT",
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

    def __repr__(self) -> str:
        return "LaunchedEngine(<private>)"

    def __str__(self) -> str:
        return self.__repr__()


# --------------------------------------------------------------------------
# control plane
# --------------------------------------------------------------------------

def _controller_status(base: str, path: str, token: str | None) -> int | None:
    request = urllib.request.Request(base + path)
    if token is not None:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)
    except Exception:
        return None


def _controller_json(base: str, path: str, token: str) -> Any:
    request = urllib.request.Request(base + path)
    request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except Exception:
        return None


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


def _windows_own_listeners(pid: int, port: int) -> tuple[bool, list[str]]:
    env = {k: v for k, v in os.environ.items()
           if k.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "USERPROFILE", "TEMP"}}
    env["NODELAB_PORT"] = str(port)
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    exe = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    try:
        proc = subprocess.run(
            [str(exe), "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_OWNER_SCRIPT],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
            timeout=20.0, text=True, encoding="utf-8", errors="replace",
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


def listener_owned_by(pid: int, port: int) -> str:
    """Fixed code: LAUNCH_OK when `pid` itself listens on `port`, loopback only."""
    try:
        if os.name == "nt":
            any_listener, ours = _windows_own_listeners(pid, port)
            loopback = all(address in _LOOPBACK_TEXT for address in ours)
        else:
            any_listener, ours = _linux_own_listeners(pid, port)
            loopback = all(address in _LOOPBACK_HEX for address in ours)
    except EngineLaunchError as error:
        return error.code
    except Exception:
        return "LISTENER_UNVERIFIABLE"
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
) -> LaunchedEngine:
    """Spawn the pinned engine and assert the runtime facts, or raise."""
    ok, _code = engine_binary.verify_pinned_binary(exe)
    if not ok:
        raise EngineLaunchError("BINARY_REJECTED")

    deadline = time.monotonic() + float(deadline_seconds)
    base = f"http://127.0.0.1:{int(controller_port)}"

    try:
        proc = subprocess.Popen(
            [str(exe), "-d", str(run_dir), "-f", str(config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, cwd=str(run_dir),
            close_fds=True,
        )
    except (OSError, ValueError):
        raise EngineLaunchError("SPAWN_FAILED") from None

    try:
        # 1. control plane reachable. An unauthenticated probe must answer 401
        #    rather than 200; a 200 here means the run token was not applied.
        status = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise EngineLaunchError("ENGINE_EXITED")
            status = _controller_status(base, "/configs", None)
            if status is not None:
                break
            time.sleep(_POLL_INTERVAL)
        if status is None:
            raise EngineLaunchError("CONTROLLER_UNREACHABLE")
        if status != 401:
            raise EngineLaunchError("CONTROLLER_AUTH_WEAK")

        # 2. a wrong token stays rejected, the run token is accepted.
        wrong = secret[:-1] + ("x" if secret[-1] != "x" else "y")
        if _controller_status(base, "/configs", wrong) != 401:
            raise EngineLaunchError("CONTROLLER_AUTH_WEAK")
        if _controller_status(base, "/configs", secret) != 200:
            raise EngineLaunchError("CONTROLLER_AUTH_WEAK")

        # 3. the data-plane listener belongs to this exact child.
        code = "LISTENER_MISSING"
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise EngineLaunchError("ENGINE_EXITED")
            code = listener_owned_by(proc.pid, int(mixed_port))
            if code != "LISTENER_MISSING":
                break
            time.sleep(_POLL_INTERVAL)
        if code != "LAUNCH_OK":
            raise EngineLaunchError(code)

        # 4. the objects the config declared are really in the running engine.
        proxies = _controller_json(base, "/proxies", secret)
        if not isinstance(proxies, dict) or not isinstance(proxies.get("proxies"), dict):
            raise EngineLaunchError("PROXY_OBJECT_MISSING")
        table = proxies["proxies"]
        if NODE_NAME not in table:
            raise EngineLaunchError("PROXY_OBJECT_MISSING")
        group = table.get(GROUP_NAME)
        if not isinstance(group, dict) or group.get("now") != NODE_NAME:
            raise EngineLaunchError("GROUP_OBJECT_MISSING")

        if time.monotonic() >= deadline:
            raise EngineLaunchError("LAUNCH_TIMEOUT")
        return LaunchedEngine(proc=proc, controller=base, secret=secret,
                              mixed_port=int(mixed_port))
    except BaseException:
        # Never leave our own child running after a failed preflight.
        try:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5.0)
        except Exception:
            pass
        raise


def probe_socket(engine: LaunchedEngine, timeout: float = 2.0) -> bool:
    """TCP reachability of the mixed port. NOT evidence of routing."""
    try:
        with socket.create_connection(("127.0.0.1", engine.mixed_port), timeout=timeout):
            return True
    except OSError:
        return False
