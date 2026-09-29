"""Streaming file hashing."""

from __future__ import annotations

import os
import re
from pathlib import Path

from hashvault.algorithms import DEFAULT_ALGORITHM, get_algorithm, new_hasher
from hashvault.errors import FileError, UsageError
from hashvault.models import HashResult

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB

_UNITS = {
    "": 1, "b": 1,
    "k": 1024, "kb": 1024, "kib": 1024,
    "m": 1024**2, "mb": 1024**2, "mib": 1024**2,
    "g": 1024**3, "gb": 1024**3, "gib": 1024**3,
}  # fmt: skip


def parse_size(value: int | str) -> int:
    """Parse '64KB', '1MB', '4096' into bytes. Units are powers of 1024."""
    if isinstance(value, int):
        size = value
    else:
        m = re.fullmatch(r"\s*(\d+)\s*([a-zA-Z]*)\s*", value)
        if not m or m.group(2).lower() not in _UNITS:
            raise UsageError(f"invalid size {value!r} (examples: 4096, 64KB, 1MB)")
        size = int(m.group(1)) * _UNITS[m.group(2).lower()]
    if size <= 0:
        raise UsageError("chunk size must be greater than zero")
    return size


def hash_file(
    path: str | Path,
    algorithm: str = DEFAULT_ALGORITHM,
    chunk_size: int | str = DEFAULT_CHUNK_SIZE,
) -> HashResult:
    """Hash a file in fixed-size chunks so memory use stays constant."""
    alg = get_algorithm(algorithm)
    size = parse_size(chunk_size)
    p = Path(path)
    if not p.exists():
        raise FileError(f"file not found: {p}")
    if not p.is_file():
        raise FileError(f"not a regular file: {p}")

    hasher = new_hasher(alg)
    total = 0
    buf = bytearray(size)
    view = memoryview(buf)
    try:
        with open(p, "rb", buffering=0) as f:
            before = os.fstat(f.fileno())
            while n := f.readinto(view):
                hasher.update(view[:n])
                total += n
            after = os.fstat(f.fileno())
    except OSError as exc:
        raise FileError(f"cannot read {p}: {exc.strerror or exc}") from exc
    # A file modified mid-read yields a digest of a state that never existed on disk.
    if (
        (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
        or total != after.st_size
    ):
        raise FileError(f"{p} changed while it was being hashed; the digest would be unreliable")
    return HashResult(str(p), alg.name, hasher.hexdigest(), total)
