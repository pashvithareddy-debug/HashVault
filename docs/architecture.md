# Architecture

```
CLI (cli.py)               argparse, config merge, exit codes, error rendering
  │
  ├── utils/output.py      text + JSON rendering
  ├── config.py            hashvault.toml → Settings
  ▼
Core services (core/)
  ├── hasher.py            streaming file hashing, chunk-size parsing
  ├── verifier.py          digest validation + constant-time comparison
  ├── scanner.py           snapshot(), compare() change classification, scan_directory()
  ├── manifest.py          create / write (atomic) / read bytes / parse (strictly validated)
  └── signing.py           optional Ed25519 keygen, detached sign/verify (lazy-imports cryptography)
  │
  ├── algorithms/registry  supported algorithms, legacy flags
  ├── models/results.py    dataclasses: HashResult, VerificationResult, FileChange, ScanResult, Manifest
  └── utils/filesystem.py  deterministic walk, exclusion matching, symlink policy
```

## Design decisions
- **Standard library only.** A security tool with no runtime dependencies has no supply chain to audit.
- **Core never prints or exits.** Services return dataclasses or raise `HashVaultError` subclasses;
  only `cli.py` decides output and exit codes. This keeps the core testable and reusable as a library.
- **Errors map to exit codes:** `UsageError`→2, `FileError`→3, `ManifestError`→4; a mismatch returns 1.
- **Manifests record their own scan rules** (algorithm, excludes, symlink policy) so `verify` reproduces
  the original scan. CLI `--exclude` can add exclusions on verify but not remove recorded ones.
- **Deterministic output:** directories and files are walked in sorted order and manifests are written
  with sorted keys, so identical trees produce identical manifests (apart from `created_at`).
- **Optional dependency, isolated.** `cryptography` is imported lazily inside `signing.py` only; without it every
  other command works and signing commands fail with an install hint.
- **Verify-then-parse on the same bytes.** The manifest is read once; the signature is checked over those bytes
  and the same bytes are parsed, so there is no check/use race.
- **`scan` vs `manifest verify`:** both share one code path. `scan DIR` uses `DIR/hashvault.manifest.json`
  if present (or `--baseline`); with no baseline it prints an inventory.

## Manifest format (v1.0)
```json
{
  "version": "1.0",
  "algorithm": "sha256",
  "created_at": "2026-01-01T00:00:00+00:00",
  "follow_symlinks": false,
  "exclude": [".git", "__pycache__"],
  "files": { "README.md": "<hex digest>" }
}
```
