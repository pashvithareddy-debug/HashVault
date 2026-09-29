"""Ed25519 detached signatures for manifests.

Requires the optional dependency:  pip install "hashvault[signing]"
The signature covers the manifest's exact bytes, so there is no canonicalization to get wrong.
Fields in the .sig file other than `signature` are informational and are *not* trusted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

from hashvault.errors import FileError, ManifestError, UsageError
from hashvault.models import SignatureResult

log = logging.getLogger(__name__)

SIGNATURE_VERSION = "1.0"
SIGNATURE_ALGORITHM = "ed25519"
SIGNATURE_SUFFIX = ".sig"


def signature_path_for(manifest: Path) -> Path:
    return manifest.with_name(manifest.name + SIGNATURE_SUFFIX)


def _crypto() -> tuple[Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise UsageError(
            "signing needs the 'cryptography' package: pip install 'hashvault[signing]'"
        ) from exc
    return ed25519, serialization, InvalidSignature


def key_id(public_key: Any) -> str:
    """SHA-256 fingerprint of the raw public key (hex)."""
    _, serialization, _ = _crypto()
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def generate_keypair(prefix: Path, force: bool = False) -> tuple[Path, Path, str]:
    """Write PREFIX.key (private, mode 0600) and PREFIX.pub. Returns (private, public, key_id)."""
    ed25519, serialization, _ = _crypto()
    priv_path = prefix.with_name(prefix.name + ".key")
    pub_path = prefix.with_name(prefix.name + ".pub")
    if not force:
        for p in (priv_path, pub_path):
            if p.exists():
                raise UsageError(f"{p} already exists (use --force to overwrite)")
    private = ed25519.Ed25519PrivateKey.generate()
    priv_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        priv_path.unlink(missing_ok=True)  # O_EXCL below then guarantees fresh 0600 permissions
        fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(priv_pem)
        pub_path.write_bytes(pub_pem)
    except OSError as exc:
        raise FileError(f"cannot write key files: {exc.strerror or exc}") from exc
    return priv_path, pub_path, key_id(private.public_key())


def _read_key_file(path: Path, what: str) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        raise FileError(f"{what} not found: {path}") from None
    except OSError as exc:
        raise FileError(f"cannot read {what} {path}: {exc.strerror or exc}") from exc


def load_private_key(path: Path) -> Any:
    ed25519, serialization, _ = _crypto()
    data = _read_key_file(path, "private key")
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        log.warning("private key %s is accessible by other users; run: chmod 600 %s", path, path)
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise UsageError(f"invalid private key {path}: {exc}") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise UsageError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path) -> Any:
    ed25519, serialization, _ = _crypto()
    data = _read_key_file(path, "public key")
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise UsageError(f"invalid public key {path}: {exc}") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise UsageError(f"{path} is not an Ed25519 public key")
    return key


def sign_bytes(data: bytes, private_key: Any) -> dict[str, Any]:
    """Return the signature document for `data`."""
    return {
        "version": SIGNATURE_VERSION,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id(private_key.public_key()),
        "manifest_sha256": hashlib.sha256(data).hexdigest(),
        "signature": base64.b64encode(private_key.sign(data)).decode("ascii"),
    }


def write_signature(doc: dict[str, Any], path: Path, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        raise ManifestError(f"{path} already exists (use --force to overwrite)")
    try:
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot write signature {path}: {exc.strerror or exc}") from exc


def load_signature(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ManifestError(f"signature file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise ManifestError(f"cannot read signature {path}: {exc}") from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"signature {path} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise ManifestError("signature file must be a JSON object")
    if doc.get("version") != SIGNATURE_VERSION:
        raise ManifestError(f"unsupported signature version: {doc.get('version')!r}")
    if doc.get("algorithm") != SIGNATURE_ALGORITHM:
        raise ManifestError(f"unsupported signature algorithm: {doc.get('algorithm')!r}")
    if not isinstance(doc.get("signature"), str):
        raise ManifestError("signature file has no 'signature' field")
    return doc


def verify_bytes(
    data: bytes, doc: dict[str, Any], public_key: Any, manifest: str = "", sig_file: str = ""
) -> SignatureResult:
    _, _, invalid_signature = _crypto()
    kid = key_id(public_key)
    try:
        sig = base64.b64decode(doc["signature"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ManifestError("signature is not valid base64") from exc
    try:
        public_key.verify(sig, data)
    except invalid_signature:
        reason = (
            "manifest was signed by a different key"
            if doc.get("key_id") not in (None, kid)
            else "signature does not match the manifest contents"
        )
        return SignatureResult(manifest, sig_file, False, kid, reason)
    return SignatureResult(manifest, sig_file, True, kid)
