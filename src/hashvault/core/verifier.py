"""Verify a file against an expected digest."""

from __future__ import annotations

import hmac
import string
from pathlib import Path

from hashvault.algorithms import Algorithm, get_algorithm
from hashvault.core.hasher import DEFAULT_CHUNK_SIZE, hash_file
from hashvault.errors import UsageError
from hashvault.models import VerificationResult


def normalize_expected(expected: str, algorithm: Algorithm) -> str:
    """Lowercase and validate an expected digest; accepts an 'algo:' prefix."""
    value = expected.strip().lower()
    if ":" in value:
        prefix, _, value = value.partition(":")
        if get_algorithm(prefix).name != algorithm.name:
            raise UsageError(f"hash prefix {prefix!r} does not match algorithm {algorithm.name}")
    if not value or any(c not in string.hexdigits for c in value):
        raise UsageError("expected hash must be a hexadecimal string")
    if len(value) != algorithm.hex_length:
        raise UsageError(
            f"{algorithm.display} digests are {algorithm.hex_length} hex characters; "
            f"got {len(value)}. Use --algorithm if the hash came from a different algorithm."
        )
    return value


def verify_file(
    path: str | Path,
    expected: str,
    algorithm: str = "sha256",
    chunk_size: int | str = DEFAULT_CHUNK_SIZE,
) -> VerificationResult:
    alg = get_algorithm(algorithm)
    want = normalize_expected(expected, alg)
    result = hash_file(path, alg.name, chunk_size)
    ok = hmac.compare_digest(result.digest, want)
    return VerificationResult(result.path, alg.name, want, result.digest, ok, result.size)
