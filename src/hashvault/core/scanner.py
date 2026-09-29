"""Directory snapshots and baseline comparison."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from hashvault.algorithms import get_algorithm
from hashvault.core.hasher import DEFAULT_CHUNK_SIZE, hash_file
from hashvault.models import ChangeStatus, FileChange, ScanResult
from hashvault.utils.filesystem import walk_files

log = logging.getLogger(__name__)


def snapshot(
    root: Path,
    algorithm: str,
    exclude: Iterable[str] = (),
    follow_symlinks: bool = False,
    chunk_size: int | str = DEFAULT_CHUNK_SIZE,
    skip: Iterable[Path] = (),
) -> dict[str, str]:
    """Hash every eligible file under root. Returns {posix_relative_path: hex_digest}."""
    alg = get_algorithm(algorithm)
    files: dict[str, str] = {}
    for rel, full in walk_files(root, exclude, follow_symlinks, skip):
        log.debug("hashing %s", rel)
        files[rel] = hash_file(full, alg.name, chunk_size).digest
    log.info("hashed %d files under %s", len(files), root)
    return files


def compare(baseline: dict[str, str], current: dict[str, str]) -> list[FileChange]:
    """Classify differences. A deleted+added pair with the same digest (1:1) is a rename."""
    changes: dict[str, FileChange] = {}
    for path, digest in current.items():
        if path not in baseline:
            changes[path] = FileChange(path, ChangeStatus.ADDED, None, digest)
        elif baseline[path] == digest:
            changes[path] = FileChange(path, ChangeStatus.UNCHANGED, digest, digest)
        else:
            changes[path] = FileChange(path, ChangeStatus.MODIFIED, baseline[path], digest)
    for path, digest in baseline.items():
        if path not in current:
            changes[path] = FileChange(path, ChangeStatus.DELETED, digest, None)

    deleted_by_hash: dict[str, list[str]] = defaultdict(list)
    added_by_hash: dict[str, list[str]] = defaultdict(list)
    for c in changes.values():
        if c.status is ChangeStatus.DELETED and c.expected:
            deleted_by_hash[c.expected].append(c.path)
        elif c.status is ChangeStatus.ADDED and c.actual:
            added_by_hash[c.actual].append(c.path)
    for digest, old_paths in deleted_by_hash.items():
        new_paths = added_by_hash.get(digest, [])
        if len(old_paths) == 1 and len(new_paths) == 1:  # only unambiguous renames
            old, new = old_paths[0], new_paths[0]
            del changes[old]
            changes[new] = FileChange(new, ChangeStatus.RENAMED, digest, digest, old)

    return sorted(changes.values(), key=lambda c: c.path)


def scan_directory(
    root: Path,
    algorithm: str,
    baseline: dict[str, str] | None = None,
    exclude: Iterable[str] = (),
    follow_symlinks: bool = False,
    chunk_size: int | str = DEFAULT_CHUNK_SIZE,
    skip: Iterable[Path] = (),
) -> ScanResult:
    """Scan root. With a baseline, classify changes; without one, return an inventory."""
    alg = get_algorithm(algorithm)
    current = snapshot(root, alg.name, exclude, follow_symlinks, chunk_size, skip)
    if baseline is None:
        changes = [
            FileChange(p, ChangeStatus.UNCHANGED, None, d) for p, d in sorted(current.items())
        ]
        return ScanResult(str(root), alg.name, changes, has_baseline=False)
    return ScanResult(str(root), alg.name, compare(baseline, current), has_baseline=True)
