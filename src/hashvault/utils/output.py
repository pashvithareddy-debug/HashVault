"""Human-readable and JSON rendering."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, TextIO

from hashvault.algorithms import get_algorithm
from hashvault.models import ChangeStatus, HashResult, ScanResult, VerificationResult

RULE = "─" * 44
_COLORS = {"green": "32", "red": "31", "yellow": "33", "cyan": "36", "dim": "2", "bold": "1"}

_SYMBOL = {
    ChangeStatus.UNCHANGED: ("✓", "green"),
    ChangeStatus.MODIFIED: ("✗", "red"),
    ChangeStatus.ADDED: ("+", "cyan"),
    ChangeStatus.DELETED: ("-", "yellow"),
    ChangeStatus.RENAMED: ("→", "cyan"),
}


def use_color(stream: TextIO, disabled: bool = False) -> bool:
    return not disabled and "NO_COLOR" not in os.environ and stream.isatty()


def paint(text: str, color: str, enabled: bool) -> str:
    return f"\033[{_COLORS[color]}m{text}\033[0m" if enabled else text


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    raise AssertionError("unreachable")


def render_hash(results: list[HashResult], verbose: bool) -> str:
    lines: list[str] = []
    for r in results:
        if verbose:
            alg = get_algorithm(r.algorithm)
            lines += [
                f"File      : {r.path}",
                f"Algorithm : {alg.display}",
                f"Size      : {human_size(r.size)}",
                f"Digest    : {r.digest}",
                "",
            ]
        else:
            lines.append(f"{r.digest}  {r.path}")
    return "\n".join(lines).rstrip("\n")


def render_verification(r: VerificationResult, color: bool) -> str:
    alg = get_algorithm(r.algorithm)
    if r.verified:
        status, integrity = paint("✓ VERIFIED", "green", color), "INTACT"
    else:
        status, integrity = paint("✗ FAILED", "red", color), paint("COMPROMISED", "red", color)
    return "\n".join(
        [
            "HashVault Verification",
            RULE,
            f"File       : {r.path}",
            f"Algorithm  : {alg.display}",
            f"Expected   : {r.expected}",
            f"Computed   : {r.computed}",
            "",
            f"Status     : {status}",
            f"Integrity  : {integrity}",
        ]
    )


def render_scan(result: ScanResult, verbose: bool, color: bool) -> str:
    title = "HASHVAULT INTEGRITY SCAN" if result.has_baseline else "HASHVAULT INVENTORY"
    lines = [title, RULE]
    for c in result.changes:
        if c.status is ChangeStatus.UNCHANGED and result.has_baseline and not verbose:
            continue
        sym, col = _SYMBOL[c.status]
        label = paint(sym, col, color)
        if not result.has_baseline:
            lines.append(f"{c.actual}  {c.path}")
        elif c.status is ChangeStatus.RENAMED:
            lines.append(f"{label} {c.previous_path} → {c.path}")
        elif c.status is ChangeStatus.UNCHANGED:
            lines.append(f"{label} {c.path}")
        else:
            lines.append(f"{label} {c.path}  ({c.status.value})")
    if len(lines) == 2:
        lines.append("(no differences to list)" if result.has_baseline else "(no files found)")
    s = result.summary
    lines.append(RULE)
    if result.has_baseline:
        lines += [
            f"Modified  : {s['modified']}",
            f"Added     : {s['added']}",
            f"Deleted   : {s['deleted']}",
            f"Renamed   : {s['renamed']}",
            f"Unchanged : {s['unchanged']}",
            "",
        ]
        if result.clean:
            lines.append("STATUS: " + paint("CLEAN — no changes detected", "green", color))
        else:
            lines.append("STATUS: " + paint("CHANGES DETECTED", "red", color))
    else:
        lines.append(f"{s['unchanged']} files hashed ({get_algorithm(result.algorithm).display}).")
        lines.append("No baseline found; run 'hashvault manifest create' to create one.")
    return "\n".join(lines)


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)
