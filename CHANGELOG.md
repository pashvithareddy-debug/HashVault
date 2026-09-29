# Changelog

## [3.0.0]
### Added
- **Signed manifests (Ed25519):** `keygen`, `manifest sign`, `manifest verify-signature`, and
  `--public-key` on `manifest verify` / `scan`. Optional extra: `pip install "hashvault[signing]"`.
- Progress indicator for large scans (terminal only; silent with `--json`, `--quiet`, pipes).
- Detection of files that change while being hashed (reported as an error instead of a bogus digest).
- Security-hardening tests: symlink attacks, hostile manifests, permission failures, concurrent writers,
  malformed config, >2 GiB files, bounded memory.
- End-to-end subprocess tests of the full hash → verify → manifest → tamper → detect workflow, signed and unsigned.
- Release workflow: tag/version check, `twine check`, GitHub Release, PyPI trusted publishing.
- Measured benchmark results in `docs/benchmarks.md`.

### Changed
- The manifest and its `.sig` file are never reported as added files in scans.
- `load_manifest` is split into `read_manifest_bytes` + `parse_manifest` so signatures cover the exact bytes parsed.

## [2.0.0]
### Added
- Package layout (`src/hashvault`) with `python -m hashvault` and `hashvault` console script.
- Algorithms: SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s; MD5/SHA-1 as warned legacy options.
- Streaming hashing with configurable `--chunk-size`.
- `verify` with constant-time comparison, `algo:` prefixes and digest-format validation.
- `scan`: recursive scanning with added / modified / deleted / renamed classification.
- `manifest create|verify` with strict validation, atomic writes and path-traversal protection.
- `--json`, `--verbose`, `--quiet`, `--log-level`, `--no-color`; exit codes 0–4.
- `hashvault.toml` configuration and exclusion rules.
- Tests, benchmarks, CI, security documentation.

### Changed
- `generate` is now `hash` (`generate` remains as an alias).
- `verify` now exits non-zero on mismatch or missing file (v1 always exited 0).

## [1.0.0]
- SHA-256 `generate` and `verify` in a single script.
