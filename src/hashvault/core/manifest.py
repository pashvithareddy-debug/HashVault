"""Create, write and load integrity manifests."""

from __future__ import annotations

import json
import os
import string
import tempfile
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from hashvault.algorithms import get_algorithm
from hashvault.core.hasher import DEFAULT_CHUNK_SIZE
from hashvault.core.scanner import snapshot
from hashvault.errors import ManifestError, UsageError
from hashvault.models import Manifest

MANIFEST_VERSION = "1.0"
DEFAULT_MANIFEST_NAME = "hashvault.manifest.json"


def create_manifest(
    root: Path,
    algorithm: str,
    exclude: Iterable[str] = (),
    follow_symlinks: bool = False,
    chunk_size: int | str = DEFAULT_CHUNK_SIZE,
    skip: Iterable[Path] = (),
) -> Manifest:
    alg = get_algorithm(algorithm)
    patterns = tuple(exclude)
    files = snapshot(root, alg.name, patterns, follow_symlinks, chunk_size, skip)
    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return Manifest(alg.name, files, created, MANIFEST_VERSION, patterns, follow_symlinks)


def write_manifest(manifest: Manifest, path: Path, overwrite: bool = False) -> None:
    """Write atomically (temp file + rename) so a crash never leaves a half-written manifest."""
    if path.exists() and not overwrite:
        raise ManifestError(f"{path} already exists (use --force to overwrite)")
    text = json.dumps(manifest.to_dict(), indent=2) + "\n"
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".hashvault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise ManifestError(f"cannot write manifest {path}: {exc.strerror or exc}") from exc


def _safe_relative(path: str) -> bool:
    if not path or "\\" in path or PurePosixPath(path).is_absolute():
        return False
    if PureWindowsPath(path).drive:
        return False
    return ".." not in PurePosixPath(path).parts


def load_manifest(path: Path) -> Manifest:
    """Load and strictly validate a manifest. Never trusts paths or digests blindly."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ManifestError(f"manifest not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest {path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ManifestError("manifest must be a JSON object")
    if data.get("version") != MANIFEST_VERSION:
        raise ManifestError(f"unsupported manifest version: {data.get('version')!r}")
    try:
        alg = get_algorithm(str(data.get("algorithm", "")))
    except UsageError as exc:
        raise ManifestError(f"manifest has invalid algorithm: {exc}") from exc

    files = data.get("files")
    if not isinstance(files, dict):
        raise ManifestError("manifest 'files' must be an object")
    for rel, digest in files.items():
        if not _safe_relative(rel):
            raise ManifestError(f"manifest contains unsafe path: {rel!r}")
        if (
            not isinstance(digest, str)
            or len(digest) != alg.hex_length
            or any(c not in string.hexdigits for c in digest)
        ):
            raise ManifestError(f"manifest has invalid {alg.display} digest for {rel!r}")

    exclude = data.get("exclude", [])
    if not isinstance(exclude, list) or not all(isinstance(e, str) for e in exclude):
        raise ManifestError("manifest 'exclude' must be a list of strings")
    follow = data.get("follow_symlinks", False)
    if not isinstance(follow, bool):
        raise ManifestError("manifest 'follow_symlinks' must be a boolean")

    return Manifest(
        algorithm=alg.name,
        files={k: v.lower() for k, v in files.items()},
        created_at=str(data.get("created_at", "")),
        version=MANIFEST_VERSION,
        exclude=tuple(exclude),
        follow_symlinks=follow,
    )
