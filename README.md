<div align="center">

# 🔐 HashVault

**Security-focused file integrity verification & monitoring CLI**

Detect modified, added, deleted and renamed files — and prove your baseline wasn't forged with Ed25519-signed manifests.
Pure-Python core with **zero runtime dependencies**.

[![CI](https://github.com/pashvithareddy-debug/HashVault/actions/workflows/ci.yml/badge.svg)](https://github.com/pashvithareddy-debug/HashVault/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Dependencies](https://img.shields.io/badge/runtime%20deps-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

```console
$ hashvault manifest verify baseline.json --root project --public-key vault.pub
HASHVAULT INTEGRITY SCAN
────────────────────────────────────────────
✗ config/settings.json  (modified)
- old_config.json  (deleted)
+ src/logger.py  (added)
✗ src/mod3.py  (modified)
────────────────────────────────────────────
Modified  : 2
Added     : 1
Deleted   : 1
Renamed   : 0
Unchanged : 8

STATUS: CHANGES DETECTED
```

## Why HashVault?
Checksums tell you whether a file changed. They don't tell you whether you can trust the list of checksums.
If an attacker can edit a file *and* regenerate the manifest, an unsigned check passes. HashVault treats that as a first-class
threat and documents it:

```console
$ hashvault manifest verify baseline.json --root project            # unsigned: forged baseline passes
STATUS: CLEAN — no changes detected

$ hashvault manifest verify baseline.json --root project --public-key vault.pub   # signed: forgery caught
HashVault Manifest Signature
────────────────────────────────────────────
Manifest   : keys/baseline.json
Signature  : keys/baseline.json.sig
Key ID     : 19be8cd29d5c402f…

Status     : ✗ INVALID
Reason     : signature does not match the manifest contents
Trust      : DO NOT TRUST this manifest
```

## Features
| | |
|---|---|
| **Hashing** | SHA-256 (default), SHA-512, SHA3-256/512, BLAKE2b/2s; MD5/SHA-1 as warned legacy options |
| **Streaming** | Fixed-size chunks (`--chunk-size`); ~1 MiB peak memory whether the file is 1 KB or 100 GB |
| **Verify** | Constant-time comparison, strict digest validation, `sha256:<hex>` prefixes |
| **Scan** | Recursive, deterministic; unchanged / modified / added / deleted / renamed |
| **Manifests** | Atomic writes, strict validation, path-traversal protection, records its own scan rules |
| **Signing** | Ed25519 detached signatures over the manifest's exact bytes (`pip install "hashvault[signing]"`) |
| **Automation** | `--json`, `--quiet`, exit codes 0–4, `hashvault.toml`, exclusion globs |
| **UX** | Colored output, live progress on large scans (TTY only), clear error messages |
| **Hardening** | Never follows symlinks by default, never opens paths named in a manifest, detects files changing mid-hash |

## Install
```bash
pip install hashvault                 # once published to PyPI; requires Python 3.11+
pip install "hashvault[signing]"      # adds Ed25519 signing
# from source:
git clone https://github.com/pashvithareddy-debug/HashVault && cd HashVault && pip install -e ".[dev]"
```

## Quick start
```bash
hashvault hash report.pdf -a blake2b                 # digest (sha256sum-style output)
hashvault verify report.pdf <expected-hash>          # exit 0 verified / 1 mismatch

hashvault manifest create ./project                  # baseline → ./project/hashvault.manifest.json
hashvault scan ./project                             # compare current state to the baseline
hashvault scan ./project --json                      # machine-readable
```

### Signed workflow (recommended)
```bash
hashvault keygen vault                               # vault.key (private, 0600) + vault.pub
hashvault manifest create ./project -o baseline.json
hashvault manifest sign baseline.json --key vault.key            # writes baseline.json.sig
# ...store vault.key offline; distribute vault.pub out-of-band...
hashvault manifest verify baseline.json --root ./project --public-key vault.pub
```

## Architecture
```
                 ┌──────────────────────── cli.py ────────────────────────┐
                 │ argparse · config merge · exit codes · JSON / text out  │
                 └───────┬─────────────┬──────────────┬──────────────┬─────┘
                         ▼             ▼              ▼              ▼
                    hasher.py     verifier.py    scanner.py     manifest.py ──► signing.py
                  (streaming)   (const-time)   (snapshot +     (validate,     (Ed25519, optional)
                                                classify)       atomic write)
                         └─────────────┴──────┬───────┴──────────────┘
                                              ▼
                     algorithms/registry · models/results · utils/filesystem
```
Core services never print or exit; only the CLI does. Details: [docs/architecture.md](docs/architecture.md).

## Exit codes
| Code | Meaning |
|---|---|
| 0 | Success / verified / no changes / signature valid |
| 1 | Integrity mismatch, changes detected, or invalid signature |
| 2 | Usage error (bad algorithm, malformed hash, bad config, missing optional dependency) |
| 3 | File or directory error (missing, unreadable, changed while hashing) |
| 4 | Manifest or signature-file error (missing, corrupt, unsafe) |

CI example: `hashvault manifest verify baseline.json --root . --public-key vault.pub || exit 1`

## CLI reference
| Command | Purpose |
|---|---|
| `hash FILE...` | Generate digests (`-a`, `--chunk-size`) |
| `verify FILE HASH` | Check a file against an expected digest |
| `scan DIR` | Compare a directory to a manifest (`--baseline`, `--exclude`, `--follow-symlinks`, `--public-key`) |
| `manifest create DIR` | Create a baseline (`-o`, `--force`, `-a`, `--exclude`) |
| `manifest verify MANIFEST` | Verify a tree (`--root`, `--public-key`, `--signature`) |
| `manifest sign MANIFEST` | Sign with an Ed25519 key (`--key`, `-o`, `--force`) |
| `manifest verify-signature MANIFEST` | Check only the signature (`--public-key`) |
| `keygen PREFIX` | Generate an Ed25519 key pair |
| `config` / `version` | Show effective settings / version |

Common options: `--json`, `-v/--verbose`, `-q/--quiet`, `--no-color`, `--log-level`, `--config`.
Configuration lives in `./hashvault.toml` (see [`examples/hashvault.toml`](examples/hashvault.toml)); flags override it.

## Performance
Measured on a 1-vCPU Xeon VM, 200 MB file, best of 3 ([full results & method](docs/benchmarks.md)):

| Algorithm | MB/s | Peak Python memory |
|---|---:|---:|
| sha256 | 1089 | ~1 MiB |
| sha512 | 519 | ~1 MiB |
| blake2b | 540 | ~1 MiB |
| sha3-256 | 370 | ~1 MiB |

Reproduce on your machine: `python benchmarks/benchmark_hashing.py --size-mb 200`.

## Security model
Hashing detects change; it does not provide confidentiality. An unsigned manifest stored beside the files it protects can be
replaced by an attacker — sign it, keep the private key elsewhere, and distribute the public key out-of-band. Known limits
(no key revocation/rotation, replay of an old signed baseline, unencrypted private keys) are listed in
[docs/security-model.md](docs/security-model.md). Reporting: [SECURITY.md](SECURITY.md).

## Testing
138 tests (`pytest`, or `python -m unittest discover -s tests -t .` with `PYTHONPATH=src`):
- **Unit:** algorithms, chunked hashing (digest identical for any chunk size), verifier, scanner classification, manifests, config, signing, progress.
- **Hardening:** symlink attacks, hostile manifests (traversal, deep nesting, bad UTF-8), permission failures, concurrent writers, >2 GiB files, bounded memory.
- **End-to-end:** real subprocess runs of hash → verify → manifest → tamper → detect, signed and unsigned, including the forged-manifest attack.

Some permission tests skip when run as root. CI runs Ubuntu, macOS and Windows on Python 3.11–3.13, plus a job with no optional dependencies.

## Development
```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest --cov
```
See [CONTRIBUTING.md](CONTRIBUTING.md). Releases: push a `vX.Y.Z` tag; the workflow checks the tag against the package version, runs tests, builds, creates a GitHub Release and publishes to PyPI via trusted publishing.

## Roadmap
Not yet built: key rotation/revocation, encrypted private keys, verification history, watch mode.

## License
MIT — see [LICENSE](LICENSE).
