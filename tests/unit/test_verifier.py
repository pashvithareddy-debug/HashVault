from hashvault.core.verifier import verify_file
from hashvault.errors import FileError, UsageError
from tests.helpers import TempDirTestCase, sha256


class VerifierTests(TempDirTestCase):
    def test_match(self):
        p = self.write("f", b"data")
        r = verify_file(p, sha256(b"data"))
        self.assertTrue(r.verified)
        self.assertEqual(r.expected, r.computed)

    def test_mismatch(self):
        p = self.write("f", b"data")
        r = verify_file(p, sha256(b"other"))
        self.assertFalse(r.verified)
        self.assertNotEqual(r.expected, r.computed)

    def test_case_and_whitespace_insensitive(self):
        p = self.write("f", b"data")
        self.assertTrue(verify_file(p, "  " + sha256(b"data").upper() + "\n").verified)

    def test_algorithm_prefix(self):
        p = self.write("f", b"data")
        self.assertTrue(verify_file(p, "sha256:" + sha256(b"data")).verified)
        with self.assertRaises(UsageError):
            verify_file(p, "sha512:" + sha256(b"data"))

    def test_invalid_hash_strings(self):
        p = self.write("f", b"data")
        for bad in ("", "xyz", "abc123", "g" * 64, sha256(b"data")[:-1]):
            with self.assertRaises(UsageError, msg=repr(bad)):
                verify_file(p, bad)

    def test_wrong_length_for_algorithm(self):
        p = self.write("f", b"data")
        with self.assertRaises(UsageError):
            verify_file(p, sha256(b"data"), algorithm="sha512")

    def test_missing_file(self):
        with self.assertRaises(FileError):
            verify_file(self.tmp / "nope", sha256(b""))
