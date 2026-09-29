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

- **Sign the manifest** (v3, below). This is the mitigation that actually removes the trust problem.

## Signed manifests (Ed25519)
```bash
hashvault keygen vault                                   # vault.key (private, 0600) + vault.pub
hashvault manifest create ./project
hashvault manifest sign ./project/hashvault.manifest.json --key vault.key
hashvault manifest verify ./project/hashvault.manifest.json --public-key vault.pub
```
An attacker who edits files **and** regenerates the manifest cannot produce a valid signature without the
private key, so `--public-key` verification fails (exit 1) even though the unsigned check would pass.

Design and limits:
- The signature covers the manifest's **exact bytes** (detached `.sig` file); there is no canonical-JSON
  step to get wrong. HashVault reads the manifest once and verifies and parses those same bytes, so the
  file cannot be swapped between check and use.
- Only the `signature` field is trusted. `key_id` and `manifest_sha256` in the `.sig` file are hints; a forged
  `key_id` cannot make an invalid signature verify (tested).
- Trust ultimately rests on **how you obtain the public key**. Distribute it out-of-band (not next to the
  manifest). If an attacker can replace the public key you verify with, signing gives no protection.
- Private keys are unencrypted PEM files created with mode 0600; HashVault warns if permissions are looser.
  Keep the key off the machine being monitored, ideally offline or in a hardware token/secret store.
- Signing needs the optional extra: `pip install "hashvault[signing]"` (uses the `cryptography` package).
  The core tool stays dependency-free.
- No key revocation, rotation policy or timestamping. A validly signed but *old* manifest will verify (replay
  of a stale baseline). Compare `created_at` or re-sign on a schedule if that matters to you.

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
- A file that changes *while it is being hashed* (size or mtime differs before/after the read) is reported
  as an error (exit 3) instead of producing a digest of a state that never existed on disk.
  Changes that preserve both size and mtime within one read cannot be detected this way.
- Hashing follows the *current* state of the path: the scanner never opens paths named in a manifest, so a
  hostile manifest or a symlink cannot make HashVault read files outside the scanned root.
