import hashlib
import os
import unittest

from hashvault.core.hasher import hash_file, parse_size
from hashvault.errors import FileError, UsageError
from tests.helpers import TempDirTestCase


class ParseSizeTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(parse_size("4096"), 4096)
        self.assertEqual(parse_size("64KB"), 64 * 1024)
        self.assertEqual(parse_size("1mb"), 1024**2)
        self.assertEqual(parse_size(" 2 GiB "), 2 * 1024**3)
        self.assertEqual(parse_size(512), 512)

    def test_invalid(self):
        for bad in ("", "abc", "1XB", "-1", "0", 0, "1.5MB"):
            with self.assertRaises(UsageError, msg=repr(bad)):
                parse_size(bad)


class HashFileTests(TempDirTestCase):
    def test_empty_file(self):
        p = self.write("empty")
        r = hash_file(p)
        self.assertEqual(r.digest, hashlib.sha256(b"").hexdigest())
        self.assertEqual(r.size, 0)

    def test_text_and_binary(self):
        text = self.write("t.txt", "hello world\n")
        binary = self.write("b.bin", bytes(range(256)) * 10)
        self.assertEqual(hash_file(text).digest, hashlib.sha256(b"hello world\n").hexdigest())
        self.assertEqual(
            hash_file(binary, "sha512").digest, hashlib.sha512(bytes(range(256)) * 10).hexdigest()
        )

    def test_chunk_size_does_not_change_digest(self):
        data = os.urandom(100_003)  # deliberately not a multiple of any chunk size
        p = self.write("d", data)
        expected = hashlib.sha256(data).hexdigest()
        for chunk in (1, 7, 1024, 4096, 1024**2):
            self.assertEqual(hash_file(p, chunk_size=chunk).digest, expected, chunk)

    def test_all_algorithms_match_hashlib(self):
        data = b"integrity" * 1000
        p = self.write("d", data)
        for name, lib in [("sha3-256", "sha3_256"), ("blake2b", "blake2b"), ("blake2s", "blake2s")]:
            self.assertEqual(hash_file(p, name).digest, hashlib.new(lib, data).hexdigest())

    def test_one_byte_change_changes_digest(self):
        a = self.write("a", b"A" * 1000)
        b = self.write("b", b"A" * 999 + b"B")
        self.assertNotEqual(hash_file(a).digest, hash_file(b).digest)

    def test_same_content_same_digest(self):
        a = self.write("a", b"same")
        b = self.write("sub/b", b"same")
        self.assertEqual(hash_file(a).digest, hash_file(b).digest)

    def test_missing_file(self):
        with self.assertRaises(FileError):
            hash_file(self.tmp / "nope")

    def test_directory_is_rejected(self):
        with self.assertRaises(FileError):
            hash_file(self.tmp)

    @unittest.skipIf(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), "needs POSIX non-root"
    )
    def test_permission_denied(self):
        p = self.write("secret", b"x")
        p.chmod(0)
        self.addCleanup(p.chmod, 0o600)
        with self.assertRaises(FileError):
            hash_file(p)

    def test_invalid_algorithm(self):
        p = self.write("a", b"x")
        with self.assertRaises(UsageError):
            hash_file(p, "nope")
