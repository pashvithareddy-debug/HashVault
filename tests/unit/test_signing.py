import base64
import json
import os
import sys
import unittest
from importlib.util import find_spec
from unittest import mock

from hashvault.core.manifest import create_manifest, write_manifest
from hashvault.errors import FileError, ManifestError, UsageError
from tests.helpers import TempDirTestCase

HAVE_CRYPTO = find_spec("cryptography") is not None


@unittest.skipUnless(HAVE_CRYPTO, "needs the optional 'cryptography' package")
class SigningTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        from hashvault.core import signing

        self.s = signing
        self.priv, self.pub, self.kid = signing.generate_keypair(self.tmp / "k")
        self.data = b'{"version": "1.0"}'

    def sign(self, data=None, priv=None):
        return self.s.sign_bytes(data or self.data, self.s.load_private_key(priv or self.priv))

    def verify(self, doc, data=None, pub=None):
        return self.s.verify_bytes(data or self.data, doc, self.s.load_public_key(pub or self.pub))

    def test_roundtrip(self):
        r = self.verify(self.sign())
        self.assertTrue(r.valid)
        self.assertEqual(r.key_id, self.kid)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_private_key_is_owner_only(self):
        self.assertEqual(self.priv.stat().st_mode & 0o777, 0o600)

    def test_keygen_refuses_overwrite(self):
        with self.assertRaises(UsageError):
            self.s.generate_keypair(self.tmp / "k")
        self.s.generate_keypair(self.tmp / "k", force=True)

    def test_tampered_manifest_is_invalid(self):
        doc = self.sign()
        r = self.verify(doc, data=self.data + b" ")
        self.assertFalse(r.valid)
        self.assertIn("does not match", r.reason)

    def test_wrong_key_is_invalid(self):
        _, other_pub, _ = self.s.generate_keypair(self.tmp / "other")
        r = self.verify(self.sign(), pub=other_pub)
        self.assertFalse(r.valid)
        self.assertIn("different key", r.reason)

    def test_forged_key_id_cannot_make_signature_valid(self):
        _, other_pub, other_kid = self.s.generate_keypair(self.tmp / "other")
        doc = self.sign()
        doc["key_id"] = other_kid
        self.assertFalse(self.verify(doc, pub=other_pub).valid)

    def test_signature_from_another_manifest_is_invalid(self):
        doc = self.sign(b"manifest A")
        self.assertFalse(self.verify(doc, data=b"manifest B").valid)

    def test_corrupted_signature_bytes_invalid(self):
        doc = self.sign()
        raw = bytearray(base64.b64decode(doc["signature"]))
        raw[0] ^= 0xFF
        doc["signature"] = base64.b64encode(bytes(raw)).decode()
        self.assertFalse(self.verify(doc).valid)

        doc["signature"] = base64.b64encode(bytes(raw)[:10]).decode()
        self.assertFalse(self.verify(doc).valid)

    def test_bad_base64_is_manifest_error(self):
        doc = self.sign()
        doc["signature"] = "***not base64***"
        with self.assertRaises(ManifestError):
            self.verify(doc)

    def test_malformed_signature_files(self):
        cases = [
            "{bad",
            "[]",
            json.dumps({"version": "9"}),
            json.dumps(
                {
                    "version": "1.0",
                    "algorithm": "rsa",
                    "signature": "x",
                }
            ),
            json.dumps(
                {
                    "version": "1.0",
                    "algorithm": "ed25519",
                }
            ),
        ]

        for body in cases:
            with self.assertRaises(ManifestError, msg=body):
                self.s.load_signature(self.write("s.sig", body))

        with self.assertRaises(ManifestError):
            self.s.load_signature(self.tmp / "missing.sig")

    def test_key_loading_errors(self):
        with self.assertRaises(FileError):
            self.s.load_private_key(self.tmp / "nope.key")

        with self.assertRaises(UsageError):
            self.s.load_private_key(self.write("junk.key", "not a pem"))

        with self.assertRaises(UsageError):
            self.s.load_private_key(self.pub)

        with self.assertRaises(UsageError):
            self.s.load_public_key(self.priv)

    def test_non_ed25519_keys_rejected(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(65537, 2048)

        pem = rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        with self.assertRaises(UsageError):
            self.s.load_private_key(self.write("rsa.key", pem))

        pub = rsa_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with self.assertRaises(UsageError):
            self.s.load_public_key(self.write("rsa.pub", pub))

    def test_real_manifest_signed_and_tampered(self):
        self.write("d/a.txt", "a")

        out = self.tmp / "d" / "m.json"

        write_manifest(
            create_manifest(
                self.tmp / "d",
                "sha256",
                skip=[out],
            ),
            out,
        )

        raw = out.read_bytes()
        doc = self.sign(raw)

        self.assertTrue(self.verify(doc, data=raw).valid)
        self.assertFalse(
            self.verify(
                doc,
                data=raw.replace(b"sha256", b"sha512"),
            ).valid
        )

    def test_missing_cryptography_gives_clear_error(self):
        with (
            mock.patch.dict(
                sys.modules,
                {"cryptography.exceptions": None},
            ),
            self.assertRaises(UsageError) as ctx,
        ):
            self.s.load_public_key(self.pub)

        self.assertIn("hashvault[signing]", str(ctx.exception))
