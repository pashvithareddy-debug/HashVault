"""Command-line interface. Thin layer: parse args, call core services, render results."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from hashvault import __version__
from hashvault.algorithms import Algorithm, available_algorithms, get_algorithm
from hashvault.config import Settings, load_settings
from hashvault.core.hasher import hash_file, parse_size
from hashvault.core.manifest import (
    DEFAULT_MANIFEST_NAME,
    create_manifest,
    load_manifest,
    write_manifest,
)
from hashvault.core.scanner import scan_directory
from hashvault.core.verifier import verify_file
from hashvault.errors import (
    EXIT_MISMATCH,
    EXIT_OK,
    HashVaultError,
    UsageError,
)
from hashvault.models import ScanResult
from hashvault.utils import output

log = logging.getLogger("hashvault")


def _common_options() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("output options")
    g.add_argument("--json", action="store_true", help="machine-readable JSON output")
    g.add_argument("-v", "--verbose", action="store_true", help="more detail")
    g.add_argument("-q", "--quiet", action="store_true", help="no output; rely on the exit code")
    g.add_argument("--no-color", action="store_true", help="disable colored output")
    g.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        help="diagnostic log level on stderr (default: warning)",
    )
    g.add_argument("--config", type=Path, help="path to a config file (default: ./hashvault.toml)")
    return p


def _hash_options() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    names = ", ".join(a.name for a in available_algorithms())
    p.add_argument("-a", "--algorithm", help=f"hash algorithm ({names}); default sha256")
    p.add_argument("--chunk-size", help="read size, e.g. 64KB or 1MB (default 1MB)")
    return p


def _scan_options() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="glob to skip (repeatable), matched per path component",
    )
    p.add_argument("--follow-symlinks", action="store_true", help="follow symbolic links")
    return p


def build_parser() -> argparse.ArgumentParser:
    common, hashing, scanning = _common_options(), _hash_options(), _scan_options()
    parser = argparse.ArgumentParser(
        prog="hashvault",
        description="HashVault — file integrity security CLI.",
        epilog="Exit codes: 0 ok, 1 integrity mismatch, 2 usage error, "
        "3 file error, 4 manifest error.",
    )
    parser.add_argument("--version", action="version", version=f"hashvault {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>", required=True)

    p = sub.add_parser(
        "hash", aliases=["generate"], parents=[common, hashing], help="generate cryptographic hash"
    )
    p.add_argument("files", nargs="+", type=Path, metavar="FILE")

    p = sub.add_parser("verify", parents=[common, hashing], help="verify a file against a hash")
    p.add_argument("file", type=Path)
    p.add_argument("hash", help="expected hex digest (optionally prefixed, e.g. sha256:ab12...)")

    p = sub.add_parser(
        "scan", parents=[common, hashing, scanning], help="scan a directory for changes"
    )
    p.add_argument("directory", type=Path)
    p.add_argument(
        "--baseline",
        type=Path,
        help=f"manifest to compare against (default: <directory>/{DEFAULT_MANIFEST_NAME} if present)",
    )

    p = sub.add_parser("manifest", help="create or verify integrity manifests")
    msub = p.add_subparsers(dest="manifest_command", metavar="<action>", required=True)
    mc = msub.add_parser(
        "create", parents=[common, hashing, scanning], help="create a baseline manifest"
    )
    mc.add_argument("directory", type=Path)
    mc.add_argument(
        "-o", "--output", type=Path, help=f"output file (default: <directory>/{DEFAULT_MANIFEST_NAME})"
    )
    mc.add_argument("--force", action="store_true", help="overwrite an existing manifest")
    mv = msub.add_parser(
        "verify", parents=[common, scanning], help="verify a directory against a manifest"
    )
    mv.add_argument("manifest", type=Path)
    mv.add_argument("--root", type=Path, help="directory to check (default: manifest's directory)")

    sub.add_parser("config", parents=[common], help="show the effective configuration")
    sub.add_parser("version", parents=[common], help="show version information")
    return parser


def _setup_logging(args: argparse.Namespace) -> None:
    level = args.log_level or ("info" if args.verbose else "warning")
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
        force=True,
    )


def _warn_legacy(alg: Algorithm, args: argparse.Namespace) -> None:
    if alg.legacy and not args.quiet:
        output.eprint(
            f"warning: {alg.display} is not recommended for security-sensitive integrity checks"
        )


def _emit(args: argparse.Namespace, data: object, text: str) -> None:
    if args.json:
        print(output.dump_json(data))
    elif not args.quiet:
        print(text)


def _algorithm(args: argparse.Namespace, settings: Settings, fallback: str | None = None) -> Algorithm:
    alg = get_algorithm(getattr(args, "algorithm", None) or fallback or settings.algorithm)
    _warn_legacy(alg, args)
    return alg


def _chunk(args: argparse.Namespace, settings: Settings) -> int:
    value = getattr(args, "chunk_size", None)
    return parse_size(value) if value else settings.chunk_size


def _cmd_hash(args: argparse.Namespace, settings: Settings) -> int:
    alg, chunk = _algorithm(args, settings), _chunk(args, settings)
    results = [hash_file(f, alg.name, chunk) for f in args.files]
    _emit(
        args,
        {"results": [r.to_dict() for r in results]},
        output.render_hash(results, args.verbose),
    )
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace, settings: Settings) -> int:
    alg, chunk = _algorithm(args, settings), _chunk(args, settings)
    result = verify_file(args.file, args.hash, alg.name, chunk)
    color = output.use_color(sys.stdout, args.no_color)
    _emit(args, result.to_dict(), output.render_verification(result, color))
    return EXIT_OK if result.verified else EXIT_MISMATCH


def _report_scan(args: argparse.Namespace, result: ScanResult) -> int:
    color = output.use_color(sys.stdout, args.no_color)
    _emit(args, result.to_dict(), output.render_scan(result, args.verbose, color))
    return EXIT_OK if result.clean else EXIT_MISMATCH


def _scan_against(
    args: argparse.Namespace, settings: Settings, root: Path, baseline_path: Path | None
) -> int:
    chunk = _chunk(args, settings)
    if baseline_path is None:
        alg = _algorithm(args, settings)
        excludes = settings.effective_excludes(args.exclude)
        follow = args.follow_symlinks or settings.follow_symlinks
        result = scan_directory(root, alg.name, None, excludes, follow, chunk)
        return _report_scan(args, result)

    manifest = load_manifest(baseline_path)
    requested = getattr(args, "algorithm", None)
    if requested and get_algorithm(requested).name != manifest.algorithm:
        raise UsageError(
            f"manifest uses {manifest.algorithm}; cannot compare with --algorithm {requested}"
        )
    alg = get_algorithm(manifest.algorithm)
    _warn_legacy(alg, args)
    # Rules recorded in the manifest apply; CLI --exclude can only add to them.
    excludes = tuple(dict.fromkeys([*manifest.exclude, *args.exclude]))
    follow = manifest.follow_symlinks or args.follow_symlinks
    log.info("comparing %s against %s", root, baseline_path)
    result = scan_directory(
        root, alg.name, manifest.files, excludes, follow, chunk, skip=[baseline_path]
    )
    return _report_scan(args, result)


def _cmd_scan(args: argparse.Namespace, settings: Settings) -> int:
    baseline = args.baseline
    if baseline is None:
        default = args.directory / DEFAULT_MANIFEST_NAME
        baseline = default if default.is_file() else None
    return _scan_against(args, settings, args.directory, baseline)


def _cmd_manifest_create(args: argparse.Namespace, settings: Settings) -> int:
    alg, chunk = _algorithm(args, settings), _chunk(args, settings)
    out = args.output or args.directory / DEFAULT_MANIFEST_NAME
    excludes = settings.effective_excludes(args.exclude)
    follow = args.follow_symlinks or settings.follow_symlinks
    manifest = create_manifest(args.directory, alg.name, excludes, follow, chunk, skip=[out])
    write_manifest(manifest, out, overwrite=args.force)
    data = {
        "status": "created",
        "manifest": str(out),
        "algorithm": alg.name,
        "file_count": len(manifest.files),
    }
    _emit(args, data, f"Manifest written: {out} ({len(manifest.files)} files, {alg.display})")
    return EXIT_OK


def _cmd_manifest_verify(args: argparse.Namespace, settings: Settings) -> int:
    root = args.root or args.manifest.resolve().parent
    return _scan_against(args, settings, root, args.manifest)


def _cmd_config(args: argparse.Namespace, settings: Settings) -> int:
    data = {
        "algorithm": settings.algorithm,
        "chunk_size": settings.chunk_size,
        "follow_symlinks": settings.follow_symlinks,
        "exclude": list(settings.effective_excludes()),
    }
    text = "\n".join(f"{k:16}: {v}" for k, v in data.items())
    _emit(args, data, text)
    return EXIT_OK


def _cmd_version(args: argparse.Namespace, settings: Settings) -> int:
    _emit(args, {"version": __version__}, f"hashvault {__version__}")
    return EXIT_OK


def _dispatch(args: argparse.Namespace, settings: Settings) -> int:
    if args.command in ("hash", "generate"):
        return _cmd_hash(args, settings)
    if args.command == "manifest":
        handler = {"create": _cmd_manifest_create, "verify": _cmd_manifest_verify}
        return handler[args.manifest_command](args, settings)
    handlers = {
        "verify": _cmd_verify,
        "scan": _cmd_scan,
        "config": _cmd_config,
        "version": _cmd_version,
    }
    return handlers[args.command](args, settings)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits with 2 on bad usage, 0 on --help/--version
        return int(exc.code) if isinstance(exc.code, int) else 2
    _setup_logging(args)
    try:
        settings = load_settings(args.config)
        return _dispatch(args, settings)
    except HashVaultError as exc:
        if args.json:
            print(
                output.dump_json(
                    {"status": "error", "error": str(exc), "exit_code": exc.exit_code}
                )
            )
        else:
            output.eprint(f"error: {exc}")
        return exc.exit_code
    except BrokenPipeError:  # e.g. `hashvault scan . --json | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 141
    except KeyboardInterrupt:
        output.eprint("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
