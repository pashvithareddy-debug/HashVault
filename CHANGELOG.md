# Changelog

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
