# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/pashvithareddy-debug/HashVault/security/advisories/new)
for this repository. Include the command, input and HashVault version that reproduce the problem.

## Supported versions

Only the latest release receives fixes.

## Scope and limits

HashVault detects *accidental or unauthorized change* by comparing cryptographic digests.
It does not provide confidentiality or authentication. In particular, a manifest stored next
to the files it describes can be replaced by an attacker who can write there. See
[docs/security-model.md](docs/security-model.md) for the full threat model.
