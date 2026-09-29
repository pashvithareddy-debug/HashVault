# Security model

## What HashVault provides
- **Integrity verification:** a file matches a digest you obtained from a source you trust.
- **Change detection:** modified, added, deleted and renamed files relative to a baseline manifest.
- **Fingerprinting:** a stable identifier for file content.

## What it does not provide
- **Confidentiality:** hashing is not encryption; digests reveal nothing useful about content but files stay readable.
- **Authentication:** a digest says *what* the content is, not *who* produced it.
- **Protection of the baseline:** see below.

## The key limitation: the manifest is only as trustworthy as its storage
If an attacker can modify a file **and** the manifest that describes it, they can make the
tampered files verify cleanly. A local manifest is therefore a tamper-*evidence* aid against
accidents, bit rot and unsophisticated changes, not a security boundary on its own.

Mitigations available today:
- Store the manifest **outside** the monitored tree (`manifest create -o /safe/place/m.json`,
  then `manifest verify m.json --root DIR`), ideally on read-only or separate media.
- Record the manifest's own digest somewhere independent (a ticket, a signed commit, a printout)
  and check it with `hashvault verify`.
- Keep the manifest in version control with signed commits.

Not implemented (possible future work): digitally signed manifests with public-key verification.

## Algorithm choices
| Algorithm | Status |
|---|---|
| SHA-256, SHA-512 | Recommended. SHA-256 is the default. |
| SHA3-256, SHA3-512 | Recommended; different construction (Keccak) from SHA-2. |
| BLAKE2b, BLAKE2s | Recommended; fast. |
| SHA-1, MD5 | **Legacy.** Practical collision attacks exist, so an attacker can craft two different files with the same digest. Provided only for compatibility; HashVault warns when they are used. |

Collision resistance matters here because an attacker who can produce a colliding file could
substitute it without changing the digest.

## Implementation notes
- Digest comparison uses a constant-time comparison (`hmac.compare_digest`).
- Manifests are validated strictly on load: version, algorithm, digest length/format, and
  **path safety** (absolute paths and `..` components are rejected, so a hostile manifest
  cannot direct HashVault outside the scanned root).
- Manifests are written atomically (temp file + rename) and never overwritten without `--force`.
- Symbolic links are not followed unless requested, and link loops are detected when they are.
- Files are read in fixed-size chunks; memory use is bounded by the chunk size, not file size.
- Rename detection only reports an unambiguous 1:1 match of a deleted and an added file with the
  same digest. Ambiguous cases are shown as added + deleted.
- A file changing *while it is being hashed* yields a digest of whatever bytes were read; scan
  quiescent data for meaningful results.
