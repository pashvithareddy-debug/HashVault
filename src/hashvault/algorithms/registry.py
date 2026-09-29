"""Registry of supported hash algorithms."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from hashvault.errors import UsageError

DEFAULT_ALGORITHM = "sha256"


@dataclass(frozen=True)
class Algorithm:
    name: str  # canonical CLI/manifest name, e.g. "sha3-256"
    display: str  # human name, e.g. "SHA3-256"
    hashlib_name: str
    digest_size: int  # bytes
    legacy: bool = False  # not recommended for security-sensitive integrity checks

    @property
    def hex_length(self) -> int:
        return self.digest_size * 2


_ALGORITHMS = (
    Algorithm("sha256", "SHA-256", "sha256", 32),
    Algorithm("sha512", "SHA-512", "sha512", 64),
    Algorithm("sha3-256", "SHA3-256", "sha3_256", 32),
    Algorithm("sha3-512", "SHA3-512", "sha3_512", 64),
    Algorithm("blake2b", "BLAKE2b", "blake2b", 64),
    Algorithm("blake2s", "BLAKE2s", "blake2s", 32),
    Algorithm("sha1", "SHA-1 (legacy)", "sha1", 20, legacy=True),
    Algorithm("md5", "MD5 (legacy)", "md5", 16, legacy=True),
)
_BY_KEY = {a.name.replace("-", ""): a for a in _ALGORITHMS}


def available_algorithms(include_legacy: bool = True) -> list[Algorithm]:
    return [a for a in _ALGORITHMS if include_legacy or not a.legacy]


def get_algorithm(name: str) -> Algorithm:
    """Resolve a user-supplied name ('SHA-256', 'sha3_256', ...) to an Algorithm."""
    key = name.strip().lower().replace("-", "").replace("_", "")
    try:
        return _BY_KEY[key]
    except KeyError:
        supported = ", ".join(a.name for a in _ALGORITHMS)
        raise UsageError(f"unsupported algorithm {name!r} (supported: {supported})") from None


def new_hasher(algorithm: Algorithm) -> "hashlib._Hash":
    # usedforsecurity=False lets legacy digests work on FIPS-restricted builds;
    # they remain labelled legacy and are never the default.
    return hashlib.new(algorithm.hashlib_name, usedforsecurity=not algorithm.legacy)
