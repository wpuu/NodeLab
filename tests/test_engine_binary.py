"""F2b / P0-02: the pinned-binary verifier refuses everything unpinned.

Hermetic by default. The tests that need a real engine are opt-in through
NODELAB_MIHOMO_EXE so the suite never downloads anything.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from nodelab import engine_binary, mihomo_process
from nodelab.engine_binary import (
    KNOWN_DIGESTS,
    PINNED_VERSION,
    BinaryVerificationError,
    file_digest,
    resolve_pinned_exe,
    verify_pinned_binary,
)

REAL_EXE = os.environ.get("NODELAB_MIHOMO_EXE")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(engine_binary.EXE_ENV, raising=False)
    monkeypatch.delenv(engine_binary.PIN_ENV, raising=False)


def make_fake_exe(tmp_path: Path, banner: str) -> Path:
    exe = tmp_path / "fake-engine"
    exe.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import sys
        print({banner!r})
        sys.exit(0)
        """), encoding="utf-8")
    exe.chmod(0o755)
    return exe


# --- resolution never touches PATH -----------------------------------------

def test_no_pin_means_no_executable():
    assert resolve_pinned_exe() is None
    assert mihomo_process.find_mihomo_exe() is None


def test_path_is_never_searched(tmp_path, monkeypatch):
    """A `mihomo` sitting on PATH must stay invisible."""
    decoy = tmp_path / "mihomo"
    decoy.write_text("#!/bin/sh\necho Mihomo Meta v1.19.31 linux amd64\n", encoding="utf-8")
    decoy.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    assert resolve_pinned_exe() is None
    assert mihomo_process.find_mihomo_exe() is None


def test_relative_pin_is_refused(monkeypatch):
    monkeypatch.setenv(engine_binary.EXE_ENV, "bin/mihomo")
    with pytest.raises(BinaryVerificationError) as info:
        resolve_pinned_exe()
    assert info.value.code == "BINARY_NOT_CONFIGURED"
    assert mihomo_process.find_mihomo_exe() is None


# --- verification ----------------------------------------------------------

def test_missing_and_unconfigured(tmp_path):
    assert verify_pinned_binary(None) == (False, "BINARY_NOT_CONFIGURED")
    assert verify_pinned_binary("relative/path") == (False, "BINARY_NOT_CONFIGURED")
    assert verify_pinned_binary(tmp_path / "absent") == (False, "BINARY_NOT_FOUND")


def test_directory_is_not_an_executable(tmp_path):
    assert verify_pinned_binary(tmp_path) == (False, "BINARY_NOT_REGULAR_FILE")


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlink_is_refused(tmp_path):
    real = make_fake_exe(tmp_path, "Mihomo Meta v1.19.31 linux amd64")
    link = tmp_path / "linked"
    link.symlink_to(real)
    assert verify_pinned_binary(link) == (False, "BINARY_IS_LINK")


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_world_writable_is_refused(tmp_path, monkeypatch):
    exe = make_fake_exe(tmp_path, "Mihomo Meta v1.19.31 linux amd64")
    monkeypatch.setenv(engine_binary.PIN_ENV, file_digest(exe))
    exe.chmod(exe.stat().st_mode | stat.S_IWOTH)
    assert verify_pinned_binary(exe) == (False, "BINARY_WORLD_WRITABLE")


def test_unknown_digest_is_refused(tmp_path):
    """The decisive check: right banner, wrong bytes."""
    exe = make_fake_exe(tmp_path, f"Mihomo Meta {PINNED_VERSION} linux amd64")
    assert verify_pinned_binary(exe) == (False, "BINARY_DIGEST_MISMATCH")


def test_owner_pin_admits_a_catalogued_build(tmp_path, monkeypatch):
    exe = make_fake_exe(tmp_path, f"Mihomo Meta {PINNED_VERSION} linux amd64 with go1.26.8")
    monkeypatch.setenv(engine_binary.PIN_ENV, file_digest(exe))
    assert verify_pinned_binary(exe) == (True, "BINARY_OK")


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_exported_but_empty_pin_means_no_pin(tmp_path, monkeypatch, blank):
    """An empty variable must not turn into BINARY_PIN_INVALID."""
    exe = make_fake_exe(tmp_path, f"Mihomo Meta {PINNED_VERSION} linux amd64")
    monkeypatch.setenv(engine_binary.PIN_ENV, blank)
    assert engine_binary.owner_pin() is None
    assert verify_pinned_binary(exe) == (False, "BINARY_DIGEST_MISMATCH")


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_exported_but_empty_exe_means_not_configured(monkeypatch, blank):
    monkeypatch.setenv(engine_binary.EXE_ENV, blank)
    assert resolve_pinned_exe() is None
    assert mihomo_process.find_mihomo_exe() is None


def test_owner_pin_must_be_a_sha256(tmp_path, monkeypatch):
    exe = make_fake_exe(tmp_path, f"Mihomo Meta {PINNED_VERSION} linux amd64")
    monkeypatch.setenv(engine_binary.PIN_ENV, "not-a-digest")
    assert verify_pinned_binary(exe) == (False, "BINARY_PIN_INVALID")


def test_wrong_version_is_refused_even_when_pinned(tmp_path, monkeypatch):
    exe = make_fake_exe(tmp_path, "Mihomo Meta v1.19.30 linux amd64")
    monkeypatch.setenv(engine_binary.PIN_ENV, file_digest(exe))
    assert verify_pinned_binary(exe) == (False, "BINARY_VERSION_MISMATCH")


def test_unparsable_banner_is_refused(tmp_path, monkeypatch):
    exe = make_fake_exe(tmp_path, "clash version 1.18.0")
    monkeypatch.setenv(engine_binary.PIN_ENV, file_digest(exe))
    assert verify_pinned_binary(exe) == (False, "BINARY_VERSION_MISMATCH")


def test_non_executable_file_fails_closed(tmp_path, monkeypatch):
    exe = tmp_path / "not-runnable"
    exe.write_bytes(b"\x00\x01\x02")
    monkeypatch.setenv(engine_binary.PIN_ENV, file_digest(exe))
    ok, code = verify_pinned_binary(exe)
    assert ok is False and code in {"BINARY_EXEC_FAILED", "BINARY_VERSION_MISMATCH"}


def test_failures_never_leak_the_path_or_banner(tmp_path):
    secret_name = "FAKE_ONLY_directory_name"
    nested = tmp_path / secret_name
    nested.mkdir()
    exe = make_fake_exe(nested, "Mihomo Meta v1.19.31 linux amd64")
    ok, code = verify_pinned_binary(exe)
    assert ok is False
    assert secret_name not in code
    error = BinaryVerificationError(code)
    assert secret_name not in f"{error!r} {error} {error.args}"


def test_catalogued_digests_are_well_formed():
    assert len(KNOWN_DIGESTS) >= 2
    for digest, label in KNOWN_DIGESTS.items():
        assert len(digest) == 64 and digest == digest.lower()
        assert PINNED_VERSION.lstrip("v") in label


# --- opt-in checks against the genuine pinned engine ------------------------

@pytest.mark.skipif(not REAL_EXE, reason="set NODELAB_MIHOMO_EXE to a pinned v1.19.31 binary")
def test_real_pinned_binary_is_accepted_by_digest_alone():
    """No Owner pin in the environment: the catalogued digest must suffice."""
    assert verify_pinned_binary(REAL_EXE) == (True, "BINARY_OK")
    assert file_digest(Path(REAL_EXE)) in KNOWN_DIGESTS


@pytest.mark.skipif(not REAL_EXE, reason="set NODELAB_MIHOMO_EXE to a pinned v1.19.31 binary")
def test_one_flipped_byte_is_rejected(tmp_path):
    """Digest pinning must not degrade to a size or name check."""
    data = bytearray(Path(REAL_EXE).read_bytes())
    data[-1] ^= 0xFF
    tampered = tmp_path / "tampered"
    tampered.write_bytes(bytes(data))
    tampered.chmod(0o755)
    assert verify_pinned_binary(tampered) == (False, "BINARY_DIGEST_MISMATCH")


@pytest.mark.skipif(not REAL_EXE, reason="set NODELAB_MIHOMO_EXE to a pinned v1.19.31 binary")
def test_real_binary_reports_the_pinned_version():
    proc = subprocess.run([REAL_EXE, "-v"], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0
    assert f"Mihomo Meta {PINNED_VERSION} " in proc.stdout
