# 🔐 HashVault

[![CI](https://github.com/pashvithareddy-debug/HashVault/actions/workflows/ci.yml/badge.svg)](https://github.com/pashvithareddy-debug/HashVault/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A security-focused file-integrity verification and monitoring CLI, written in Python with **zero runtime dependencies**.
HashVault uses cryptographic hashes to detect files that were **modified, added, deleted or renamed** since a trusted baseline.

```console
$ hashvault scan ./project -v
HASHVAULT INTEGRITY SCAN
────────────────────────────────────────────
✓ README.md
✗ config/settings.json  (modified)
- src/auth.py  (deleted)
+ src/logger.py  (added)
✓ src/main.py
────────────────────────────────────────────
Modified  : 1
Added     : 1
Deleted   : 1
Renamed   : 0
Unchanged : 2

STATUS: CHANGES DETECTED
```

## Features
- **Algorithms:** SHA-256 (default), SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s. MD5/SHA-1 are available but warned as legacy.
- **Streaming hashing:** fixed-size chunks (`--chunk-size 64KB`), so memory use is bounded by the chunk size, not the file size.
- **Verification:** constant-time comparison; strict validation of the expected digest.
- **Directory scanning:** recursive, sorted, deterministic; classifies files as unchanged / modified / added / deleted / renamed.
- **Manifests:** `manifest create` / `manifest verify` baselines with atomic writes and path-traversal protection.
- **CI-friendly:** `--json`, `--quiet`, and meaningful exit codes.
- **Config & exclusions:** `hashvault.toml`, `--exclude`, sensible defaults (`.git`, `.venv`, `__pycache__`, `node_modules`, ...).

## Install
```bash
git clone https://github.com/pashvithareddy-debug/HashVault && cd HashVault
pip install -e .          # provides the `hashvault` command; or run: python -m hashvault
```
Requires Python 3.11+.

## Quick start
```bash
hashvault hash report.pdf                         # SHA-256, sha256sum-style output
hashvault hash report.pdf -a blake2b -v           # pick an algorithm, verbose output
hashvault hash big.iso --chunk-size 4MB

hashvault verify report.pdf <expected-hash>       # exit 0 verified, 1 mismatch
hashvault verify report.pdf sha512:<hash>         # algorithm prefix is accepted

hashvault manifest create ./project               # writes ./project/hashvault.manifest.json
hashvault scan ./project                          # compares against that manifest
hashvault manifest verify ./project/hashvault.manifest.json
hashvault scan ./project --json                   # machine-readable
```
`scan` without a baseline prints an inventory of digests. The legacy `generate` command is kept as an alias of `hash`.

## CLI reference
| Command | Purpose |
|---|---|
| `hash FILE...` | Generate digests (`-a`, `--chunk-size`) |
| `verify FILE HASH` | Check a file against an expected digest |
| `scan DIR` | Compare a directory to a manifest (`--baseline`, `--exclude`, `--follow-symlinks`) |
| `manifest create DIR` | Create a baseline (`-o`, `--force`, `-a`, `--exclude`) |
| `manifest verify MANIFEST` | Verify (`--root` if the manifest is stored elsewhere) |
| `config` / `version` | Show effective settings / version |

Common options: `--json`, `-v/--verbose`, `-q/--quiet`, `--no-color`, `--log-level`, `--config`.

### Exit codes
| Code | Meaning |
|---|---|
| 0 | Success / verified / no changes |
| 1 | Integrity mismatch or changes detected |
| 2 | Usage error (bad algorithm, malformed hash, bad config) |
| 3 | File or directory error |
| 4 | Manifest error (missing, corrupt, unsafe) |

Example CI step: `hashvault manifest verify release/hashvault.manifest.json || exit 1`

### JSON output
```json
{
  "status": "changes_detected",
  "algorithm": "sha256",
  "summary": {"unchanged": 3, "modified": 1, "added": 1, "deleted": 1, "renamed": 0},
  "files": [{"path": "config/settings.json", "status": "modified", "expected": "…", "actual": "…"}]
}
```

## Configuration
See [`examples/hashvault.toml`](examples/hashvault.toml). HashVault reads `./hashvault.toml` if present; command-line flags override it.

## Security model
Hashing detects change; it does not provide confidentiality or authentication. **A manifest stored beside the files it protects
can be replaced by an attacker who can write there.** Store it elsewhere or record its digest independently.
Details, algorithm guidance and hardening notes: [docs/security-model.md](docs/security-model.md) and [SECURITY.md](SECURITY.md).

## Development
```bash
pip install -e ".[dev]"
pytest --cov              # or: PYTHONPATH=src python -m unittest discover -s tests -t .
ruff check . && ruff format --check . && mypy
python benchmarks/benchmark_hashing.py --size-mb 100
```
Architecture and design decisions: [docs/architecture.md](docs/architecture.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

## Project layout
```
src/hashvault/  cli.py  config.py  errors.py
                core/        hasher.py verifier.py scanner.py manifest.py
                algorithms/  registry.py
                models/      results.py
                utils/       filesystem.py output.py
tests/          unit/  integration/
benchmarks/  docs/  examples/  .github/workflows/
```

## Roadmap
Not yet implemented: digitally signed manifests (public-key verification), verification history, continuous monitoring / watch mode.

## License
MIT — see [LICENSE](LICENSE).
