"""Configuration loading from hashvault.toml (optional) merged with CLI flags."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hashvault.algorithms import DEFAULT_ALGORITHM, get_algorithm
from hashvault.core.hasher import DEFAULT_CHUNK_SIZE, parse_size
from hashvault.errors import FileError, UsageError
from hashvault.utils.filesystem import DEFAULT_EXCLUDES

CONFIG_FILENAME = "hashvault.toml"


@dataclass
class Settings:
    algorithm: str = DEFAULT_ALGORITHM
    chunk_size: int = DEFAULT_CHUNK_SIZE
    follow_symlinks: bool = False
    use_default_excludes: bool = True
    exclude: list[str] = field(default_factory=list)

    def effective_excludes(self, extra: list[str] | None = None) -> tuple[str, ...]:
        base = list(DEFAULT_EXCLUDES) if self.use_default_excludes else []
        merged = base + self.exclude + (extra or [])
        return tuple(dict.fromkeys(merged))  # de-duplicate, keep order


def load_settings(path: Path | None = None) -> Settings:
    """Load settings. An explicit path must exist; the default ./hashvault.toml is optional."""
    explicit = path is not None
    cfg = path or Path(CONFIG_FILENAME)
    if not cfg.is_file():
        if explicit:
            raise FileError(f"config file not found: {cfg}")
        return Settings()
    try:
        data = tomllib.loads(cfg.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError) as exc:
        raise UsageError(f"invalid config file {cfg}: {exc}") from exc

    s = Settings()
    if "algorithm" in data:
        s.algorithm = get_algorithm(_expect(data["algorithm"], str, "algorithm")).name
    if "chunk_size" in data:
        s.chunk_size = parse_size(_expect(data["chunk_size"], (int, str), "chunk_size"))
    if "follow_symlinks" in data:
        s.follow_symlinks = _expect(data["follow_symlinks"], bool, "follow_symlinks")
    scan = data.get("scan", {})
    if not isinstance(scan, dict):
        raise UsageError("config: [scan] must be a table")
    if "exclude" in scan:
        items = _expect(scan["exclude"], list, "scan.exclude")
        if not all(isinstance(i, str) for i in items):
            raise UsageError("config: scan.exclude must be a list of strings")
        s.exclude = list(items)
    if "use_default_excludes" in scan:
        s.use_default_excludes = _expect(scan["use_default_excludes"], bool, "use_default_excludes")
    return s


def _expect(value: Any, types: type | tuple[type, ...], name: str) -> Any:
    # bool is an int subclass; reject it where a number/string is wanted
    if isinstance(value, bool) and types is not bool:
        raise UsageError(f"config: {name} has the wrong type")
    if not isinstance(value, types):
        raise UsageError(f"config: {name} has the wrong type")
    return value
