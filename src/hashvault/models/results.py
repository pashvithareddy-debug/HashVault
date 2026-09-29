"""Structured result types shared by the core services, CLI and JSON output."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChangeStatus(str, Enum):
    UNCHANGED = "unchanged"
    MODIFIED = "modified"
    ADDED = "added"
    DELETED = "deleted"
    RENAMED = "renamed"


@dataclass(frozen=True)
class HashResult:
    path: str
    algorithm: str
    digest: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "algorithm": self.algorithm,
            "digest": self.digest,
            "size": self.size,
        }


@dataclass(frozen=True)
class VerificationResult:
    path: str
    algorithm: str
    expected: str
    computed: str
    verified: bool
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "verified" if self.verified else "failed",
            "path": self.path,
            "algorithm": self.algorithm,
            "expected": self.expected,
            "computed": self.computed,
            "size": self.size,
        }


@dataclass(frozen=True)
class FileChange:
    path: str
    status: ChangeStatus
    expected: str | None = None  # digest in the baseline
    actual: str | None = None  # digest on disk now
    previous_path: str | None = None  # set for RENAMED

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "path": self.path,
            "status": self.status.value,
            "expected": self.expected,
            "actual": self.actual,
        }
        if self.previous_path is not None:
            d["previous_path"] = self.previous_path
        return d


@dataclass(frozen=True)
class Manifest:
    algorithm: str
    files: dict[str, str]  # POSIX relative path -> hex digest
    created_at: str
    version: str = "1.0"
    exclude: tuple[str, ...] = ()
    follow_symlinks: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "follow_symlinks": self.follow_symlinks,
            "exclude": list(self.exclude),
            "files": dict(sorted(self.files.items())),
        }


@dataclass(frozen=True)
class SignatureResult:
    manifest: str
    signature_file: str
    valid: bool
    key_id: str  # fingerprint of the public key used for verification
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "status": "signature_valid" if self.valid else "signature_invalid",
            "manifest": self.manifest,
            "signature_file": self.signature_file,
            "key_id": self.key_id,
        }
        if self.reason:
            d["reason"] = self.reason
        return d


@dataclass
class ScanResult:
    root: str
    algorithm: str
    changes: list[FileChange] = field(default_factory=list)
    has_baseline: bool = True

    @property
    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in ChangeStatus}
        for c in self.changes:
            counts[c.status.value] += 1
        return counts

    @property
    def clean(self) -> bool:
        return all(c.status is ChangeStatus.UNCHANGED for c in self.changes)

    @property
    def status(self) -> str:
        if not self.has_baseline:
            return "inventory"
        return "clean" if self.clean else "changes_detected"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "root": self.root,
            "algorithm": self.algorithm,
            "summary": self.summary,
            "files": [c.to_dict() for c in self.changes],
        }
