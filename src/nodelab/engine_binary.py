"""F2b / P0-02: resolve and verify the pinned Mihomo executable.

Threat model
------------
The old code searched `PATH` and ran whatever answered to the name "mihomo".
On the Owner's machine another Mihomo (their own client) is expected to exist,
so name-based discovery can pick up a different build, a wrapper script, or an
attacker-writable shim. Nothing here ever searches `PATH` or matches by name.

An executable is usable only when ALL of the following hold:

  1. It was named explicitly (argument, or the `NODELAB_MIHOMO_EXE` pin).
  2. It is a regular file, not a symlink / reparse point, and resolving it
     does not change the path.
  3. Its SHA-256 is in `KNOWN_DIGESTS`, or matches an Owner-supplied pin.
  4. `-v` reports exactly the pinned version string.

Provenance caveat (recorded honestly)
-------------------------------------
MetaCubeX publishes **no** checksum file and no signature for the v1.19.31
release assets. The digests below were computed by downloading the official
release URLs on 2026-09-27; they attest *download provenance on that date*,
not an upstream signature. A digest match therefore proves "the same bytes we
examined", not "the bytes upstream intended". This is a real limitation of the
supply chain and must not be described as verified authenticity.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Final

from nodelab.deadline import DeadlineExpired, remaining

PINNED_VERSION: Final[str] = "v1.19.31"

# sha256 -> human descriptor. Extracted from the official release assets on
# 2026-09-27; see the provenance caveat above.
KNOWN_DIGESTS: Final[dict[str, str]] = {
    "b341a765412c192685264e038a6aad2ac1c67c12b8aceeb5c6f64955cf43f5ed":
        "mihomo-linux-amd64-compatible-v1.19.31",
    "1fa8055e03596fc35167f70e9ecd1890517d38d960a39177445746a1b0defc2b":
        "mihomo-windows-amd64-compatible-v1.19.31.exe",
}

EXE_ENV: Final[str] = "NODELAB_MIHOMO_EXE"
PIN_ENV: Final[str] = "NODELAB_MIHOMO_SHA256"

_BINARY_CODES: Final[frozenset[str]] = frozenset({
    "BINARY_NOT_CONFIGURED", "BINARY_NOT_FOUND", "BINARY_NOT_REGULAR_FILE",
    "BINARY_IS_LINK", "BINARY_WORLD_WRITABLE", "BINARY_DIGEST_MISMATCH",
    "BINARY_TIMEOUT", "BINARY_VERSION_MISMATCH", "BINARY_EXEC_FAILED", "BINARY_PIN_INVALID",
})

_DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")
# `mihomo -v` prints e.g.
#   Mihomo Meta v1.19.31 linux amd64 with go1.26.8 Mon Sep 14 13:20:38 UTC 2026
_VERSION_RE = re.compile(r"\bMihomo Meta (v\d+\.\d+\.\d+)\b")

_VERSION_TIMEOUT: Final[float] = 10.0
_CONFIG_TEST_TIMEOUT: Final[float] = 30.0


class BinaryVerificationError(RuntimeError):
    """Fixed code only; never carries a path or raw engine output."""

    def __init__(self, code: str = "BINARY_NOT_CONFIGURED") -> None:
        self.code = code if type(code) is str and code in _BINARY_CODES else "BINARY_NOT_CONFIGURED"
        super().__init__(self.code)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"BinaryVerificationError({self.code})"


def file_digest(path: Path, *, deadline: float | None = None) -> str:
    remaining(_VERSION_TIMEOUT, deadline)
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            remaining(_VERSION_TIMEOUT, deadline)
            digest.update(chunk)
    remaining(_VERSION_TIMEOUT, deadline)
    return digest.hexdigest()


def owner_pin() -> str | None:
    """An Owner-supplied digest pin, for a build we have not catalogued."""
    raw = os.environ.get(PIN_ENV)
    if raw is None or not raw.strip():
        # An exported-but-empty variable means "no pin", not "invalid pin";
        # failing hard there is a confusing operator trap.
        return None
    value = raw.strip().lower()
    if not _DIGEST_RE.match(value):
        raise BinaryVerificationError("BINARY_PIN_INVALID")
    return value


def _structural_checks(exe: Path) -> None:
    try:
        info = exe.lstat()
    except OSError:
        raise BinaryVerificationError("BINARY_NOT_FOUND") from None
    if stat.S_ISLNK(info.st_mode):
        raise BinaryVerificationError("BINARY_IS_LINK")
    if info.st_file_attributes & 0x400 if hasattr(info, "st_file_attributes") else False:
        raise BinaryVerificationError("BINARY_IS_LINK")  # Windows reparse point
    if not stat.S_ISREG(info.st_mode):
        raise BinaryVerificationError("BINARY_NOT_REGULAR_FILE")
    if os.name != "nt" and info.st_mode & stat.S_IWOTH:
        # Anyone could swap the bytes between verification and launch.
        raise BinaryVerificationError("BINARY_WORLD_WRITABLE")
    if exe.resolve() != exe:
        # A component of the path was a link; the verified bytes and the
        # launched bytes could differ.
        raise BinaryVerificationError("BINARY_IS_LINK")


def resolve_pinned_exe(explicit: Path | str | None = None) -> Path | None:
    """Return the configured executable, or None. NEVER searches PATH."""
    raw = explicit if explicit is not None else os.environ.get(EXE_ENV)
    if raw is None or not str(raw).strip():
        # Same rule as the digest pin: exported-but-blank means "not set".
        return None
    path = Path(str(raw).strip())
    if not path.is_absolute():
        # A relative path resolves against an arbitrary cwd.
        raise BinaryVerificationError("BINARY_NOT_CONFIGURED")
    return path


def verify_pinned_binary(exe: Path | str | None, *, deadline: float | None = None) -> tuple[bool, str]:
    """(ok, fixed_code). `ok` means: pinned bytes AND pinned version."""
    try:
        remaining(_VERSION_TIMEOUT, deadline)
        if exe is None:
            raise BinaryVerificationError("BINARY_NOT_CONFIGURED")
        path = Path(exe)
        if not path.is_absolute():
            raise BinaryVerificationError("BINARY_NOT_CONFIGURED")
        _structural_checks(path)

        digest = file_digest(path, deadline=deadline)
        allowed = set(KNOWN_DIGESTS)
        pin = owner_pin()
        if pin:
            allowed.add(pin)
        if digest not in allowed:
            raise BinaryVerificationError("BINARY_DIGEST_MISMATCH")

        try:
            proc = subprocess.run(
                [str(path), "-v"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=remaining(_VERSION_TIMEOUT, deadline), text=True, encoding="utf-8", errors="replace",
            )
        except DeadlineExpired:
            raise
        except subprocess.TimeoutExpired:
            if deadline is not None:
                remaining(_VERSION_TIMEOUT, deadline)
            raise BinaryVerificationError("BINARY_EXEC_FAILED") from None
        except (OSError, subprocess.SubprocessError):
            raise BinaryVerificationError("BINARY_EXEC_FAILED") from None
        remaining(_VERSION_TIMEOUT, deadline)
        if proc.returncode != 0:
            raise BinaryVerificationError("BINARY_EXEC_FAILED")
        # Match a fixed pattern; never return or log the raw banner, which
        # carries build paths on some builds.
        found = _VERSION_RE.search(proc.stdout or "")
        if not found or found.group(1) != PINNED_VERSION:
            raise BinaryVerificationError("BINARY_VERSION_MISMATCH")
        return True, "BINARY_OK"
    except DeadlineExpired:
        return False, "BINARY_TIMEOUT"
    except BinaryVerificationError as error:
        return False, error.code
    except Exception:
        return False, "BINARY_EXEC_FAILED"


def config_test(exe: Path | str, config_path: Path | str, *, work_dir: Path | str) -> tuple[bool, str]:
    """Run `-t` against the pinned engine.

    NECESSARY, NOT SUFFICIENT. NL-REVIEW-004 measured this flag against the
    pinned binary: it silently accepts misnamed and unknown keys, including
    the `client-fingerprint: iOS` silent TLS downgrade. It only catches
    reference errors, missing required fields and top-level type errors.
    Key correctness is enforced by the source-anchored allowlist in
    tests/test_engine_config.py, not here.
    """
    try:
        proc = subprocess.run(
            [str(exe), "-t", "-d", str(work_dir), "-f", str(config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=_CONFIG_TEST_TIMEOUT, text=True, encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        return False, "CONFIG_TEST_TIMEOUT"
    except (OSError, subprocess.SubprocessError):
        return False, "CONFIG_TEST_FAILED"
    # The engine echoes the config path and may quote offending values, so the
    # output is dropped rather than returned.
    if proc.returncode != 0:
        return False, "CONFIG_TEST_FAILED"
    return True, "CONFIG_TEST_OK"
