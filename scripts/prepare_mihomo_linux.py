"""Offline preparation only; does not run Mihomo or authorize any probe.

Accepts the official v1.19.31 Linux amd64 compatible gzip archive. Requires
Python 3.11+ for preparation; runtime acceptance still requires Python 3.12+.
No downloads, PATH discovery, custom digest pins, or overwrite mode.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys
import tempfile
import zlib

# GitHub release asset 563462721 metadata, re-read 2026-09-28.
# This is a byte/provenance pin, NOT an upstream signature.
ARCHIVE_SHA256 = "04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc"
# Existing reviewed executable pin in nodelab.engine_binary.KNOWN_DIGESTS.
EXECUTABLE_SHA256 = "b341a765412c192685264e038a6aad2ac1c67c12b8aceeb5c6f64955cf43f5ed"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


class PreparationError(Exception):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise PreparationError("INVALID_ARGUMENTS")


def copy_and_hash(source, target, limit, size_code):
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = source.read(min(CHUNK_BYTES, limit - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise PreparationError(size_code)
        target.write(chunk)
        digest.update(chunk)
    return digest.hexdigest()


def prepare(archive: Path, destination: Path):
    """Stage privately and publish using a no-clobber hard link.

    Paths must have existing canonical parents. Like other local preparation
    tools, this assumes those parents are not concurrently renamed/replaced by
    another process. It is not a hostile-filesystem or crash-recovery boundary.
    """
    if not archive.is_absolute() or not destination.is_absolute():
        raise PreparationError("ABSOLUTE_PATHS_REQUIRED")
    if archive.resolve() != archive or destination.parent.resolve() != destination.parent:
        raise PreparationError("LINK_PATH_REJECTED")
    if not destination.parent.is_dir():
        raise PreparationError("DESTINATION_PARENT_REQUIRED")
    if destination.parent.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PreparationError("DESTINATION_PARENT_WRITABLE")
    if os.path.lexists(destination):
        raise PreparationError("DESTINATION_EXISTS")

    # NONBLOCK avoids blocking on a FIFO swapped in before open; NOFOLLOW
    # rejects a final symlink. Hash the bounded snapshot, then decompress that
    # same snapshot rather than reopening the input path after verification.
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise PreparationError("ARCHIVE_NOT_REGULAR")
        with tempfile.TemporaryDirectory(prefix=".nodelab-prepare-", dir=destination.parent) as temporary:
            root = Path(temporary)
            snapshot = root / "archive.gz"
            staged = root / "mihomo"
            with snapshot.open("xb") as target:
                digest = copy_and_hash(source, target, MAX_ARCHIVE_BYTES, "ARCHIVE_TOO_LARGE")
            if digest != ARCHIVE_SHA256:
                raise PreparationError("ARCHIVE_DIGEST_MISMATCH")
            try:
                with gzip.open(snapshot, "rb") as compressed, staged.open("xb") as target:
                    digest = copy_and_hash(compressed, target, MAX_EXECUTABLE_BYTES, "EXECUTABLE_TOO_LARGE")
                    target.flush()
                    os.fsync(target.fileno())
            except (gzip.BadGzipFile, EOFError, zlib.error):
                raise PreparationError("ARCHIVE_INVALID") from None
            if digest != EXECUTABLE_SHA256:
                raise PreparationError("EXECUTABLE_DIGEST_MISMATCH")
            staged.chmod(0o700)
            try:
                os.link(staged, destination, follow_symlinks=False)
            except FileExistsError:
                raise PreparationError("DESTINATION_EXISTS") from None


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--destination", required=True)
    code = "PREPARATION_FAILED"
    try:
        args = parser.parse_args(argv)
        if sys.platform != "linux" or platform.machine().lower() not in ("amd64", "x86_64"):
            raise PreparationError("LINUX_AMD64_REQUIRED")
        prepare(Path(args.archive), Path(args.destination))
        code = "PINNED_BYTES_PREPARED"
    except PreparationError as error:
        code = str(error)
    except (OSError, ValueError):
        code = "PREPARATION_IO_FAILED"
    except KeyboardInterrupt:
        code = "CANCELLED_REVIEW_DESTINATION"
    ok = code == "PINNED_BYTES_PREPARED"
    print(json.dumps({
        "status": "PREPARED" if ok else "BLOCKED", "code": code,
        "binary_executed": False, "runtime_acceptance": "NOT_RUN",
        "route_proof": "NOT_RUN", "real_node_test_allowed": False,
    }, separators=(",", ":")))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
