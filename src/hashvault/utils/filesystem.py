"""Deterministic, exclusion-aware directory walking."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterable, Iterator
from pathlib import Path

from hashvault.errors import FileError

DEFAULT_EXCLUDES = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".DS_Store",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
)


def is_excluded(rel_posix: str, patterns: Iterable[str]) -> bool:
    """Match patterns against any path component, or the full relative path if they contain '/'."""
    parts = rel_posix.split("/")
    for raw in patterns:
        pat = raw.rstrip("/")
        if not pat:
            continue
        if "/" in pat:
            if fnmatch.fnmatchcase(rel_posix, pat.removeprefix("./")):
                return True
        elif any(fnmatch.fnmatchcase(part, pat) for part in parts):
            return True
    return False


def walk_files(
    root: Path,
    exclude: Iterable[str] = (),
    follow_symlinks: bool = False,
    skip: Iterable[Path] = (),
) -> Iterator[tuple[str, Path]]:
    """Yield (posix_relative_path, absolute_path) for regular files, sorted, excluded pruned.

    Symlinks are ignored unless follow_symlinks is set. Directory symlink loops are avoided.
    """
    if not root.exists():
        raise FileError(f"directory not found: {root}")
    if not root.is_dir():
        raise FileError(f"not a directory: {root}")
    patterns = tuple(exclude)
    skip_set = {p.resolve() for p in skip}
    seen_dirs: set[Path] = set()

    def on_error(exc: OSError) -> None:
        raise FileError(f"cannot read {exc.filename}: {exc.strerror or exc}") from exc

    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks, onerror=on_error):
        base = Path(dirpath)
        if follow_symlinks:
            real = base.resolve()
            if real in seen_dirs:
                dirnames[:] = []
                continue
            seen_dirs.add(real)
        rel_dir = base.relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = sorted(
            d
            for d in dirnames
            if not is_excluded(prefix + d, patterns)
            and (follow_symlinks or not (base / d).is_symlink())
        )
        for name in sorted(filenames):
            rel = prefix + name
            full = base / name
            if is_excluded(rel, patterns):
                continue
            if not follow_symlinks and full.is_symlink():
                continue
            if not full.is_file() or full.resolve() in skip_set:
                continue
            yield rel, full
